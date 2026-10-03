//! manitou — weight provenance.
//!
//! Named for the manitou — the spirit inhabiting a thing. Which manitou
//! was in the body when the words came out? This crate answers it:
//! per-file SHA-256 manifests of a model's weights, signed
//! `brain_manifest` records on every load/swap, and drift verification
//! that recomputes the files and reports what changed.
//!
//! Extracted from Bad Apple's provenance organ: every successful brain
//! load or swap appends a signed record whose SHA-256 anchors into the
//! audit chain — the artifact cannot be silently rewritten.

use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use serde::{Deserialize, Serialize};
use serde_json;
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::fs;
use std::io::{self, Read, Write};
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

// ───────────────────────── file manifest ────────────────────────────

/// One file in the weight inventory.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FileEntry {
    pub size: u64,
    /// Seconds since epoch (0 when unavailable).
    pub mtime: f64,
    pub sha256: String,
}

/// A signed inventory of one model's files.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Manifest {
    pub repo_id: String,
    pub local_path: String,
    /// Seconds since epoch (fractional, printed with 9 decimals in the
    /// canonical message).
    pub recorded_at: f64,
    /// relative path → entry.
    pub files: BTreeMap<String, FileEntry>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub signature: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub public_key: Option<String>,
}

impl Manifest {
    /// The canonical, deterministic message a signer signs — the exact
    /// bytes recomputed at verify time:
    /// `repo_id\nlocal_path\nrecorded_at\nfile:size:mtime:sha256…`
    pub fn canonical_message(&self) -> String {
        let mut lines = vec![
            self.repo_id.clone(),
            self.local_path.clone(),
            format!("{:.9}", self.recorded_at),
        ];
        for (key, e) in &self.files {
            lines.push(format!("{key}:{}:{:.9}:{}", e.size, e.mtime, e.sha256));
        }
        lines.join("\n")
    }

    /// Fingerprint of the file inventory alone — the
    /// `weights_manifest_sha256` pinned into brain_manifest records.
    pub fn fingerprint(&self) -> String {
        let mut lines: Vec<String> = Vec::new();
        for (key, e) in &self.files {
            lines.push(format!("{key}:{}:{:.9}:{}", e.size, e.mtime, e.sha256));
        }
        hex::encode(Sha256::digest(lines.join("\n").as_bytes()))
    }

    /// Verify the signature over `canonical_message`.
    pub fn verify_signature(&self, key: &VerifyingKey) -> bool {
        let Some(sig_hex) = &self.signature else { return false };
        let Ok(bytes) = hex::decode(sig_hex) else { return false };
        let Ok(arr) = <[u8; 64]>::try_from(bytes.as_slice()) else {
            return false;
        };
        key.verify_strict(self.canonical_message().as_bytes(), &Signature::from_bytes(&arr))
            .is_ok()
    }
}

/// Hash a file, streaming. Skips dotfiles and directories.
pub fn sha256_file(path: &Path) -> io::Result<String> {
    let mut f = fs::File::open(path)?;
    let mut hasher = Sha256::new();
    let mut buf = [0u8; 1 << 16];
    loop {
        let n = f.read(&mut buf)?;
        if n == 0 {
            break;
        }
        hasher.update(&buf[..n]);
    }
    Ok(hex::encode(hasher.finalize()))
}

/// Inventory a model directory: every non-hidden file → size, mtime,
/// SHA-256. Returns a `Manifest` (unsigned — sign with
/// [`Manifest::canonical_message`] + the caller's signer, or
/// [`record_signed`]).
pub fn record(root: &Path, repo_id: &str) -> io::Result<Manifest> {
    let mut files = BTreeMap::new();
    collect(root, root, &mut files)?;
    Ok(Manifest {
        repo_id: repo_id.to_string(),
        local_path: root.display().to_string(),
        recorded_at: now_f64(),
        files,
        signature: None,
        public_key: None,
    })
}

/// Record + sign with an Ed25519 key.
pub fn record_signed(root: &Path, repo_id: &str, key: &SigningKey) -> io::Result<Manifest> {
    let mut m = record(root, repo_id)?;
    let sig = key.sign(m.canonical_message().as_bytes());
    m.signature = Some(hex::encode(sig.to_bytes()));
    m.public_key = Some(hex::encode(key.verifying_key().to_bytes()));
    Ok(m)
}

fn collect(root: &Path, dir: &Path, files: &mut BTreeMap<String, FileEntry>) -> io::Result<()> {
    for entry in fs::read_dir(dir)? {
        let entry = entry?;
        let path = entry.path();
        let name = entry.file_name().to_string_lossy().to_string();
        if name.starts_with('.') || name == "desktop.ini" || name == "Thumbs.db" {
            continue;
        }
        if path.is_dir() {
            collect(root, &path, files)?;
            continue;
        }
        let meta = entry.metadata()?;
        let mtime = meta
            .modified()
            .ok()
            .and_then(|t| t.duration_since(UNIX_EPOCH).ok())
            .map(|d| d.as_secs_f64())
            .unwrap_or(0.0);
        let rel = path
            .strip_prefix(root)
            .unwrap_or(&path)
            .display()
            .to_string();
        files.insert(
            rel,
            FileEntry {
                size: meta.len(),
                mtime,
                sha256: sha256_file(&path)?,
            },
        );
    }
    Ok(())
}

// ──────────────────────── drift verification ────────────────────────

/// What drifted between a recorded manifest and the files on disk.
#[derive(Debug, Default, Clone, PartialEq)]
pub struct Drift {
    /// Paths added since recording.
    pub added: Vec<String>,
    /// Paths present at recording, now gone.
    pub missing: Vec<String>,
    /// Paths whose sha256 changed.
    pub changed: Vec<String>,
}

/// Whether the files still match the manifest.
#[derive(Debug, Clone, PartialEq)]
pub enum Verification {
    Verified,
    Drifted(Drift),
    /// The manifest could not be read/compared.
    Unverifiable(String),
}

/// Recompute the files under `root` and compare to `manifest`.
pub fn verify(root: &Path, manifest: &Manifest) -> Verification {
    let mut current = BTreeMap::new();
    if let Err(e) = collect(root, root, &mut current) {
        return Verification::Unverifiable(format!("cannot inventory: {e}"));
    }
    let mut drift = Drift::default();
    for rel in current.keys() {
        if !manifest.files.contains_key(rel) {
            drift.added.push(rel.clone());
        }
    }
    for (rel, e) in &manifest.files {
        match current.get(rel) {
            None => drift.missing.push(rel.clone()),
            Some(cur) if cur.sha256 != e.sha256 => drift.changed.push(rel.clone()),
            _ => {}
        }
    }
    if drift.added.is_empty() && drift.missing.is_empty() && drift.changed.is_empty() {
        Verification::Verified
    } else {
        Verification::Drifted(drift)
    }
}

// ──────────────────────── brain_manifest records ────────────────────

/// The record appended on every brain load/swap: which weights, from
/// where, how large, which adapter was present, which policy governed.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BrainRecord {
    pub ts: u64,
    pub kind: String,
    pub model_id: String,
    pub revision: String,
    /// `local_dir` | `hf_cache` | free-form.
    pub source: String,
    pub model_bytes: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub directory: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub dream_adapter: Option<String>,
    /// The policy hash in force at load time (wintercount).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub policy_hash: Option<String>,
    /// Fingerprint of the serving weights' file manifest.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub weights_manifest_sha256: Option<String>,
    #[serde(default)]
    pub signed: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub signature: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub signature_scheme: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub public_key: Option<String>,
}

impl BrainRecord {
    /// Canonical body for signing — everything but signature fields.
    pub fn signing_body(&self) -> Vec<u8> {
        let mut v = serde_json::to_value(self).unwrap_or_default();
        if let Some(m) = v.as_object_mut() {
            m.remove("signature");
            m.remove("signature_scheme");
            m.remove("public_key");
            m.remove("signed");
        }
        serde_json::to_vec(&v).unwrap_or_default()
    }

    /// Verify the Ed25519 signature.
    pub fn verify_signature(&self, key: &VerifyingKey) -> bool {
        let Some(sig_hex) = &self.signature else { return false };
        let Ok(bytes) = hex::decode(sig_hex) else { return false };
        let Ok(arr) = <[u8; 64]>::try_from(bytes.as_slice()) else {
            return false;
        };
        key.verify_strict(&self.signing_body(), &Signature::from_bytes(&arr))
            .is_ok()
    }
}

/// The append-only provenance log (`provenance.jsonl`). Every line is a
/// `brain_manifest` record; each record's SHA-256 is returned so the
/// caller can anchor it into an audit chain.
pub struct ProvenanceLog {
    pub path: PathBuf,
}

impl ProvenanceLog {
    pub fn new(path: PathBuf) -> Self {
        Self { path }
    }

    /// Append a record, optionally signing it first. Returns the
    /// SHA-256 of the exact line written — the anchor to drop into an
    /// audit ledger as a `model_provenance` event.
    pub fn record_load(&self, mut record: BrainRecord, signer: Option<&SigningKey>) -> io::Result<String> {
        if let Some(key) = signer {
            let sig = key.sign(&record.signing_body());
            record.signature = Some(hex::encode(sig.to_bytes()));
            record.signature_scheme = Some("ed25519".to_string());
            record.public_key = Some(hex::encode(key.verifying_key().to_bytes()));
            record.signed = true;
        }
        let mut line = serde_json::to_vec(&record)?;
        let hash = hex::encode(Sha256::digest(&line));
        if let Some(dir) = self.path.parent() {
            fs::create_dir_all(dir)?;
        }
        let mut f = fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(&self.path)?;
        line.push(b'\n');
        f.write_all(&line)?;
        Ok(hash)
    }

    /// All records in the log, in order.
    pub fn records(&self) -> Vec<BrainRecord> {
        let Ok(text) = fs::read_to_string(&self.path) else {
            return Vec::new();
        };
        text.lines()
            .filter_map(|l| serde_json::from_str(l).ok())
            .collect()
    }
}

/// A fresh `BrainRecord` skeleton for a load/swap.
pub fn brain_record(model_id: &str, revision: &str, source: &str, model_bytes: u64) -> BrainRecord {
    BrainRecord {
        ts: now(),
        kind: "brain_manifest".to_string(),
        model_id: model_id.to_string(),
        revision: revision.to_string(),
        source: source.to_string(),
        model_bytes,
        directory: None,
        dream_adapter: None,
        policy_hash: None,
        weights_manifest_sha256: None,
        signed: false,
        signature: None,
        signature_scheme: None,
        public_key: None,
    }
}

/// Generate a random Ed25519 signing key.
pub fn generate_signing_key() -> SigningKey {
    let mut secret = [0u8; 32];
    rand::RngCore::fill_bytes(&mut rand::rngs::OsRng, &mut secret);
    SigningKey::from_bytes(&secret)
}

fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

fn now_f64() -> f64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs_f64())
        .unwrap_or(0.0)
}
