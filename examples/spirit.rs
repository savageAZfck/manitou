use manitou::{brain_record, generate_signing_key, record_signed, verify, ProvenanceLog, Verification};
use std::fs;

fn main() {
    let dir = std::env::temp_dir().join(format!("manitou-example-{}", std::process::id()));
    fs::create_dir_all(dir.join("model")).unwrap();
    fs::write(dir.join("model/config.json"), b"{\"hidden\":4096}").unwrap();
    fs::write(dir.join("model/w0.safetensors"), vec![0xAB; 4096]).unwrap();

    let key = generate_signing_key();

    // Record the spirit at first sighting.
    let manifest = record_signed(&dir.join("model"), "qwen/test-7b", &key).unwrap();
    println!("manifest: {} files, fingerprint {}", manifest.files.len(), &manifest.fingerprint()[..16]);
    println!("signature valid: {}", manifest.verify_signature(&key.verifying_key()));

    // Log the brain swap.
    let log = ProvenanceLog::new(dir.join("provenance.jsonl"));
    let mut rec = brain_record("qwen/test-7b", "main", "local_dir", manifest.files.values().map(|f| f.size).sum());
    rec.weights_manifest_sha256 = Some(manifest.fingerprint());
    rec.policy_hash = Some("policyabc".into());
    let anchor = log.record_load(rec, Some(&key)).unwrap();
    println!("brain_manifest anchored: {}", &anchor[..16]);

    // Later — is it still the same spirit?
    println!("verify: {:?}", verify(&dir.join("model"), &manifest));

    // Someone swaps a weight file.
    fs::write(dir.join("model/w0.safetensors"), vec![0xCD; 4096]).unwrap();
    match verify(&dir.join("model"), &manifest) {
        Verification::Drifted(d) => println!("drift detected — changed: {:?}", d.changed),
        other => println!("unexpected: {other:?}"),
    }

    fs::remove_dir_all(&dir).ok();
}
