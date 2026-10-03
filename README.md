# manitou

Weight provenance. Named for the **manitou** — the spirit inhabiting a thing. Which manitou was in the body when the words came out?

Extracted from Bad Apple's provenance organ — every brain load/swap writes a signed `brain_manifest` record whose SHA-256 anchors into the audit chain.

## Two layers

- **`Manifest`** — per-file inventory of a model's weights: every non-hidden file → size, mtime, SHA-256. The canonical message is deterministic, so the signature you verify is over the same bytes that were recorded.
- **`BrainRecord` / `ProvenanceLog`** — append-only `provenance.jsonl`; each load pins model_id, revision, source, model_bytes, the dream adapter present, the policy hash in force, and the weights manifest fingerprint. Each record's SHA-256 is returned so the caller anchors it into an audit chain — the artifact can't be silently rewritten.

## The question it answers

*"Prove which mind said that."* — which weights, from where, under which policy, signed at load time, verified offline.

## Usage

```rust
use manitou::{record_signed, verify, generate_signing_key, Verification};

let key = generate_signing_key();
let manifest = record_signed(&model_dir, "qwen/test-7b", &key)?;
assert!(manifest.verify_signature(&key.verifying_key()));

// Later — is the brain still the same brain?
match verify(&model_dir, &manifest) {
    Verification::Verified => println!("same weights"),
    Verification::Drifted(d) => println!("changed: {:?} added: {:?} missing: {:?}", d.changed, d.added, d.missing),
    Verification::Unverifiable(e) => eprintln!("{e}"),
}
```

And the brain-manifest record per load:

```rust
let rec = manitou::brain_record("qwen/7b", "main", "hf_cache", 4_000_000_000);
let anchor = log.record_load(rec, Some(&key))?; // sha256 → drop into the audit ledger
```

## License

MIT
