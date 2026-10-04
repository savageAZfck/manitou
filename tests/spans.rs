use ed25519_dalek::Signer;
use manitou::{brain_record, generate_signing_key, span_record, ProvenanceLog, SpanRecord};

fn tmpdir(name: &str) -> std::path::PathBuf {
    let dir = std::env::temp_dir().join(format!("manitou-test-{name}"));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

#[test]
fn signed_span_verifies() {
    let key = generate_signing_key();
    let dir = tmpdir("span-sign");
    let log = ProvenanceLog::new(dir.join("provenance.jsonl"));

    let mut span = span_record(
        "qwen2.5-coder-7b",
        "rev-abc",
        b"the prompt",
        b"the answer",
        0,
        42,
    );
    span.weights_manifest_sha256 = Some("ff".repeat(32));
    span.policy_hash = Some("aa".repeat(32));

    let hash = log.record_span(span.clone(), Some(&key)).unwrap();
    assert_eq!(hash.len(), 64);

    let stored = log.spans().pop().unwrap();
    assert!(stored.signed);
    assert!(stored.verify_signature(&key.verifying_key()));
    assert!(stored.covers_output(b"the answer"));
    assert!(stored.covers_prompt(b"the prompt"));
}

#[test]
fn tampered_span_fails() {
    let key = generate_signing_key();
    let mut span = span_record("m", "r", b"p", b"o", 0, 10);
    let sig = key.sign(&span.signing_body());
    span.signature = Some(hex::encode(sig.to_bytes()));
    span.signed = true;

    // Flip the output hash — the signature must not follow.
    span.output_sha256 = "00".repeat(32);
    assert!(!span.verify_signature(&key.verifying_key()));
}

#[test]
fn wrong_key_fails() {
    let key = generate_signing_key();
    let other = generate_signing_key();
    let mut span = span_record("m", "r", b"p", b"o", 0, 1);
    let sig = key.sign(&span.signing_body());
    span.signature = Some(hex::encode(sig.to_bytes()));
    assert!(!span.verify_signature(&other.verifying_key()));
}

#[test]
fn spans_and_manifests_interleave() {
    let key = generate_signing_key();
    let dir = tmpdir("span-mix");
    let log = ProvenanceLog::new(dir.join("provenance.jsonl"));

    log.record_load(
        brain_record("qwen-7b", "r1", "local_dir", 4_000_000_000),
        Some(&key),
    )
    .unwrap();
    log.record_span(span_record("qwen-7b", "r1", b"p1", b"o1", 0, 5), Some(&key))
        .unwrap();
    log.record_span(span_record("qwen-7b", "r1", b"p2", b"o2", 0, 8), Some(&key))
        .unwrap();
    log.record_load(
        brain_record("qwen3-4b", "r9", "hf_cache", 2_000_000_000),
        Some(&key),
    )
    .unwrap();

    assert_eq!(log.records().len(), 2); // brain manifests only
    assert_eq!(log.spans().len(), 2); // output spans only
}

#[test]
fn unsigned_span_is_unsigned() {
    let dir = tmpdir("span-unsigned");
    let log = ProvenanceLog::new(dir.join("provenance.jsonl"));
    log.record_span(span_record("m", "r", b"p", b"o", 0, 3), None)
        .unwrap();
    let span: SpanRecord = log.spans().pop().unwrap();
    assert!(!span.signed);
    assert_eq!(span.signature, None);
}
