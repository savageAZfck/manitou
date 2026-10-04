use manitou::{
    brain_record, generate_signing_key, record_signed, verify, ProvenanceLog, Verification,
};
use std::fs;
use std::path::PathBuf;

fn model_dir(tag: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("manitou-{tag}-{}", std::process::id()));
    let _ = fs::remove_dir_all(&dir);
    fs::create_dir_all(dir.join("layers")).unwrap();
    fs::write(dir.join("config.json"), b"{\"hidden\":4096}").unwrap();
    fs::write(dir.join("layers/w0.safetensors"), vec![0xAB; 1024]).unwrap();
    fs::write(dir.join(".hidden"), b"skip me").unwrap();
    dir
}

#[test]
fn manifest_inventories_weights() {
    let dir = model_dir("inv");
    let m = manitou::record(&dir, "qwen/test-7b").unwrap();
    assert_eq!(m.files.len(), 2, "dotfiles skipped");
    assert!(m.files.contains_key("config.json"));
    assert!(m.files.contains_key("layers/w0.safetensors"));
    assert_eq!(m.fingerprint().len(), 64);
    fs::remove_dir_all(&dir).ok();
}

#[test]
fn canonical_message_is_deterministic() {
    let dir = model_dir("canon");
    let m1 = manitou::record(&dir, "qwen/test").unwrap();
    let m2 = manitou::record(&dir, "qwen/test").unwrap();
    let strip = |s: String| s.lines().skip(3).collect::<Vec<_>>().join("\n");
    // File-entry section identical (recorded_at differs between calls).
    assert_eq!(strip(m1.canonical_message()), strip(m2.canonical_message()));
    fs::remove_dir_all(&dir).ok();
}

#[test]
fn verify_detects_drift() {
    let dir = model_dir("drift");
    let m = manitou::record(&dir, "qwen/test").unwrap();
    assert_eq!(verify(&dir, &m), Verification::Verified);

    // Tamper: change a weight file.
    fs::write(dir.join("layers/w0.safetensors"), vec![0xCD; 1024]).unwrap();
    match verify(&dir, &m) {
        Verification::Drifted(d) => {
            assert_eq!(d.changed, vec!["layers/w0.safetensors"]);
        }
        _ => panic!("expected drift"),
    }

    // Remove a file + add one.
    fs::remove_file(dir.join("layers/w0.safetensors")).unwrap();
    fs::write(dir.join("extra.bin"), b"x").unwrap();
    match verify(&dir, &m) {
        Verification::Drifted(d) => {
            assert_eq!(d.added, vec!["extra.bin"]);
            assert_eq!(d.missing, vec!["layers/w0.safetensors"]);
        }
        _ => panic!("expected drift"),
    }
    fs::remove_dir_all(&dir).ok();
}

#[test]
fn signed_manifest_verifies() {
    let dir = model_dir("sig");
    let key = generate_signing_key();
    let m = record_signed(&dir, "qwen/test", &key).unwrap();
    assert!(m.verify_signature(&key.verifying_key()));

    // A tampered manifest signature fails.
    let mut m2 = m.clone();
    m2.repo_id = "evil/model".into();
    assert!(!m2.verify_signature(&key.verifying_key()));
    fs::remove_dir_all(&dir).ok();
}

#[test]
fn provenance_log_anchors_records() {
    let dir = std::env::temp_dir().join(format!("manitou-log-{}", std::process::id()));
    let _ = fs::remove_dir_all(&dir);
    let log = ProvenanceLog::new(dir.join("provenance.jsonl"));
    let key = generate_signing_key();

    let mut rec = brain_record("qwen/7b", "main", "hf_cache", 4_000_000_000);
    rec.policy_hash = Some("abc123".into());
    let hash = log.record_load(rec, Some(&key)).unwrap();
    assert_eq!(hash.len(), 64);

    let recs = log.records();
    assert_eq!(recs.len(), 1);
    assert!(recs[0].signed);
    assert!(recs[0].verify_signature(&key.verifying_key()));
    assert_eq!(recs[0].policy_hash.as_deref(), Some("abc123"));
    fs::remove_dir_all(&dir).ok();
}
