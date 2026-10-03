# Security policy

## Reporting

Open a private security advisory on the GitHub repository, or email the
maintainer (see `Cargo.toml` authors). Do not file public issues for
provenance-bypass findings — e.g. a file layout that evades `verify`
or a signature that validates over a mutated record.

## Scope

In scope:

- `verify` missing a content change (hashing bugs, skipped file
  classes that should be covered).
- Canonical-message non-determinism (same manifest, different signed
  bytes).
- Signature validation over a body different from what was written.
- `record_load` returning an anchor hash that doesn't match the line
  actually written.

Out of scope:

- Poisoned-at-first-sighting weights — manifests prove *continuity*,
  not *origin*; verify upstream sources separately.
- The model directory itself — path safety and symlink handling are
  the integrator's boundary.
- Signing-key custody — hardware keys are the caller's choice; the
  crate signs with what it's given.

## Guidance

- Record the manifest at download/first-load, not on demand — the
  first record is the baseline everything compares against.
- Anchor every `record_load` hash into a hash-chained ledger so the
  provenance log itself can't be rewritten without detection.
- Re-verify before consequential use: a verified manifest from
  yesterday doesn't cover last night's disk.
