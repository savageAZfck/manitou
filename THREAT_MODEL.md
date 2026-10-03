# Threat model

manitou proves which weights served. It assumes the model directory
and the provenance log are within a filesystem trust boundary, and the
threat is silent substitution: weights swapped, patched, or poisoned
without the record knowing.

## What it defends against

- **Silent weight substitution.** `verify` recomputes every file's
  SHA-256 — a single flipped bit lands in `changed`.
- **Manifest forgery.** Signed manifests verify against the canonical
  message; editing repo_id, path, or any file entry breaks the
  signature.
- **Record rewriting.** Each provenance line's SHA-256 anchors into an
  external audit chain — rewriting the log breaks the anchor match.
- **Attribution gaps.** The brain_manifest record binds weights +
  policy hash + adapter presence *at load time* — post-hoc "the model
  must have been different" is checkable, not arguable.

## What it does not defend against

- **First-record trust.** A manifest recorded over already-poisoned
  weights faithfully proves the poison — provenance starts at first
  sighting, so record at download/first-load, not after.
- **Runtime patching.** Weights modified in RAM after load aren't on
  disk — the manifest covers files, not memory. Pair with `flight_tape`
  for behavioral drift.
- **Key compromise.** Signed records are only as strong as the signing
  key — keep it in a hardware boundary where possible.
- **Directory-level substitution between record and verify.** If an
  attacker replaces the whole tree and re-records, both manifest and
  files "agree" — the audit-chain anchor is what makes the new record
  visible.

## Design posture

Prove the spirit in the body, at load time, with content hashes —
then let the audit chain say whether the story changed.
