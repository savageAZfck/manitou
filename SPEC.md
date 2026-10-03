# manitou specification

Weight provenance: file manifests, brain_manifest records, drift
verification.

## File manifest

`record(root, repo_id)` inventories every non-hidden regular file under
`root` recursively: `relative → {size, mtime, sha256}` (dotfiles,
`desktop.ini`, `Thumbs.db` skipped; streaming 64 KiB reads).

`canonical_message()` — the deterministic signed body:

```
repo_id
local_path
recorded_at            (9-decimal seconds)
<rel>:<size>:<mtime9>:<sha256>   (sorted by rel, one per line)
```

`fingerprint()` — SHA-256 over the file-entry lines alone; this is the
`weights_manifest_sha256` pinned into brain records.

## Drift verification

`verify(root, manifest)` recomputes the inventory and returns
`Verified` or `Drifted{added, missing, changed}` — added = on disk not
in manifest; missing = in manifest not on disk; changed = sha256
differs. Mtime/size are not drift conditions; content is.

## Brain records

`BrainRecord` fields: `ts`, `kind="brain_manifest"`, `model_id`,
`revision`, `source`, `model_bytes`, optional `directory`,
`dream_adapter`, `policy_hash`, `weights_manifest_sha256`, signature
fields. `ProvenanceLog::record_load` appends the canonical JSON line
and returns the line's SHA-256 — the anchor for an audit chain.

Signing: Ed25519 over `signing_body()` (all fields minus
`signature`, `signature_scheme`, `public_key`, `signed`).

## Invariants

- The fingerprint covers content, not names — a renamed-but-identical
  file set produces a different manifest, not the same one.
- `verified` means *byte-identical content* — mtime/size drift alone
  doesn't register.
- Every record-load returns its anchor hash; nothing enters the log
  unsigned when a signer is configured.

## Non-goals

- manitou doesn't load or choose weights — it records which ones
  served.
- It doesn't trust the directory — `record`/`verify` hash whatever is
  there; path safety is the caller's.
