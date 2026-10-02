//! Explicit user actions only. Ciphertexts use AEAD; restores never overwrite.
use crate::{QuarantineEntry, Threat, storage};
use anyhow::{Context, Result, ensure};
use chacha20poly1305::{
    ChaCha20Poly1305, KeyInit, Nonce,
    aead::{Aead, Payload},
};
use chrono::Utc;
use rand::{RngCore, rngs::OsRng};
use sha2::{Digest, Sha256};
use std::{
    fs,
    io::{Read, Write},
    path::{Path, PathBuf},
};
use uuid::Uuid;
use zeroize::Zeroizing;

pub struct Quarantine {
    root: PathBuf,
    key: Zeroizing<Vec<u8>>,
}

impl Quarantine {
    pub fn open(data: &Path) -> Result<Self> {
        let root = data.join("quarantine");
        storage::private_dir(&root)?;
        let root = root.canonicalize()?;
        let key_path = root.join("key.bin");
        if !key_path.exists() {
            ensure!(
                !fs::read_dir(&root)?.any(|entry| entry.is_ok_and(|e| e
                    .path()
                    .extension()
                    .is_some_and(|ext| ext == "agq" || ext == "json"))),
                "Quarantine key is missing while backups exist; restore the original key, do not generate a new one"
            );
            let mut key = Zeroizing::new(vec![0u8; 32]);
            OsRng.fill_bytes(&mut key);
            storage::atomic_write(&key_path, &key)?;
        }
        let mut key = Zeroizing::new(Vec::new());
        storage::open_regular(&key_path)?
            .take(33)
            .read_to_end(&mut key)?;
        ensure!(
            key.len() == 32,
            "Invalid quarantine key; do not delete the key to repair it"
        );
        Ok(Self { root, key })
    }

    pub fn list(&self) -> Result<Vec<QuarantineEntry>> {
        let mut records = vec![];
        for entry in fs::read_dir(&self.root)? {
            let path = entry?.path();
            if path.extension().is_some_and(|s| s == "json") {
                records.push(storage::read_json::<QuarantineEntry>(&path)?);
            }
        }
        records.sort_by_key(|e| std::cmp::Reverse(e.quarantined_at));
        Ok(records)
    }

    pub fn contain(&self, threat: &Threat, max_bytes: u64) -> Result<QuarantineEntry> {
        ensure!(self.list()?.len() < 1024, "Quarantine entry limit reached");
        ensure!(
            !self.record(threat.id).exists() && !self.blob(threat.id).exists(),
            "A backup already exists for this detection; review it before retrying"
        );
        let occupied = fs::read_dir(&self.root)?.try_fold(0u64, |total, entry| -> Result<u64> {
            let entry = entry?;
            Ok(total.saturating_add(
                if entry.path().extension().is_some_and(|ext| ext == "agq") {
                    entry.metadata()?.len()
                } else {
                    0
                },
            ))
        })?;
        ensure!(
            occupied.saturating_add(threat.size).saturating_add(28) <= 2 * 1024 * 1024 * 1024,
            "Quarantine 2 GiB content quota reached; review existing backups"
        );
        ensure!(
            !fs::symlink_metadata(&threat.path)?.file_type().is_symlink(),
            "Source is now a symlink; review the changed path"
        );
        let source = threat.path.canonicalize()?;
        ensure!(
            !source.starts_with(&self.root),
            "Cannot quarantine vault files"
        );
        let bytes = read_checked(&source, max_bytes, &threat.sha256)?;
        let mut nonce = [0u8; 12];
        OsRng.fill_bytes(&mut nonce);
        let cipher = ChaCha20Poly1305::new_from_slice(&self.key)
            .map_err(|_| anyhow::anyhow!("Invalid key"))?;
        let aad = format!("{}:{}", threat.id, threat.sha256);
        let ciphertext = cipher
            .encrypt(
                Nonce::from_slice(&nonce),
                Payload {
                    msg: &bytes,
                    aad: aad.as_bytes(),
                },
            )
            .map_err(|_| anyhow::anyhow!("Quarantine encryption failed"))?;
        let mut blob = nonce.to_vec();
        blob.extend(ciphertext);
        storage::atomic_write(&self.blob(threat.id), &blob)?;
        // Stage on the source volume to avoid a cross-device rename. The private
        // directory is recorded before moving so interrupted actions are recoverable.
        let holding = source
            .parent()
            .context("Source has no parent")?
            .join(format!(".ferxium-hold-{}", threat.id));
        storage::private_dir(&holding)?;
        let staged = holding.join("sample.hold");
        let mut record = QuarantineEntry {
            id: threat.id,
            threat: threat.clone(),
            quarantined_at: Utc::now(),
            source_removed: false,
            staging_path: Some(staged.clone()),
            restored_at: None,
        };
        storage::write_json(&self.record(threat.id), &record)?;
        // No deletion occurs until the *moved* object is rehashed. Never run this
        // same-user prototype as a privileged broker for lower-trust clients.
        if let Err(error) = fs::rename(&source, &staged) {
            record.staging_path = None;
            storage::write_json(&self.record(threat.id), &record)?;
            let _ = fs::remove_dir(&holding);
            return Err(error).context(
                "Encrypted backup saved, but source could not be moved; it is not isolated",
            );
        }
        if let Err(error) = read_checked(&staged, max_bytes, &threat.sha256) {
            // Hard-link creates the destination atomically and cannot overwrite
            // a replacement at the original path. Preserve staged data on failure.
            if fs::hard_link(&staged, &source).is_ok() {
                let _ = fs::remove_file(&staged);
                let _ = fs::remove_dir(&holding);
                record.staging_path = None;
            }
            storage::write_json(&self.record(threat.id), &record)?;
            return Err(error)
                .context("Source changed since detection; retained safely, review staging_path");
        }
        fs::remove_file(&staged)
            .context("Encrypted backup saved; staged source remains, review staging_path")?;
        let _ = fs::remove_dir(&holding);
        record.source_removed = true;
        record.staging_path = None;
        record.threat.status = "quarantined".into();
        storage::write_json(&self.record(threat.id), &record)?;
        Ok(record)
    }

    pub fn restore(&self, id: Uuid, destination: &Path) -> Result<()> {
        let mut record: QuarantineEntry = storage::read_json(&self.record(id))?;
        ensure!(
            record.staging_path.is_none(),
            "Resolve interrupted staging before restoration"
        );
        ensure!(
            destination.is_absolute(),
            "Restore destination must be absolute"
        );
        let parent = destination
            .parent()
            .context("Missing destination parent")?
            .canonicalize()?;
        ensure!(
            !parent.starts_with(self.root.parent().context("Missing state root")?),
            "Cannot restore into application state"
        );
        let filename = destination.file_name().context("Missing filename")?;
        #[cfg(windows)]
        {
            let name = filename.to_string_lossy();
            ensure!(
                !name.contains([':', '<', '>', '"', '|', '?', '*']) && !name.ends_with(['.', ' ']),
                "Restore filename contains an unsafe Windows path component"
            );
            let stem = name
                .split('.')
                .next()
                .unwrap_or_default()
                .to_ascii_uppercase();
            ensure!(
                ![
                    "CON", "PRN", "AUX", "NUL", "COM1", "COM2", "COM3", "COM4", "COM5", "COM6",
                    "COM7", "COM8", "COM9", "LPT1", "LPT2", "LPT3", "LPT4", "LPT5", "LPT6", "LPT7",
                    "LPT8", "LPT9"
                ]
                .contains(&stem.as_str()),
                "Restore destination is a reserved Windows device name"
            );
        }
        let target = parent.join(filename);
        let mut blob = Vec::new();
        storage::open_regular(&self.blob(id))?
            .take(256 * 1024 * 1024 + 29)
            .read_to_end(&mut blob)?;
        ensure!(
            blob.len() >= 28 && blob.len() <= 256 * 1024 * 1024 + 28,
            "Invalid ciphertext size"
        );
        let cipher = ChaCha20Poly1305::new_from_slice(&self.key)
            .map_err(|_| anyhow::anyhow!("Invalid key"))?;
        let aad = format!("{}:{}", id, record.threat.sha256);
        let bytes = Zeroizing::new(
            cipher
                .decrypt(
                    Nonce::from_slice(&blob[..12]),
                    Payload {
                        msg: &blob[12..],
                        aad: aad.as_bytes(),
                    },
                )
                .map_err(|_| anyhow::anyhow!("Quarantine integrity verification failed"))?,
        );
        ensure!(
            hex::encode(Sha256::digest(&bytes)) == record.threat.sha256,
            "Restored hash mismatch"
        );
        let mut options = fs::OpenOptions::new();
        options.create_new(true).write(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        let mut file = options
            .open(&target)
            .context("Restore never overwrites an existing file")?;
        if let Err(error) = file.write_all(&bytes).and_then(|_| file.sync_all()) {
            drop(file);
            let _ = fs::remove_file(&target);
            return Err(error.into());
        }
        record.restored_at = Some(Utc::now());
        storage::write_json(&self.record(id), &record)?;
        // Keep ciphertext as recovery backup until explicitly deleted.
        Ok(())
    }

    pub fn delete(&self, id: Uuid) -> Result<()> {
        let record: QuarantineEntry = storage::read_json(&self.record(id))?;
        ensure!(
            record.staging_path.is_none(),
            "Resolve interrupted staging before deleting the backup"
        );
        if self.blob(id).exists() {
            fs::remove_file(self.blob(id))?;
        }
        fs::remove_file(self.record(id))?;
        Ok(())
    }
    fn record(&self, id: Uuid) -> PathBuf {
        self.root.join(format!("{id}.json"))
    }
    fn blob(&self, id: Uuid) -> PathBuf {
        self.root.join(format!("{id}.agq"))
    }
}

fn read_checked(path: &Path, limit: u64, expected: &str) -> Result<Zeroizing<Vec<u8>>> {
    let mut bytes = Zeroizing::new(Vec::new());
    storage::open_regular(path)?
        .take(limit + 1)
        .read_to_end(&mut bytes)?;
    ensure!(bytes.len() as u64 <= limit, "File exceeds quarantine limit");
    ensure!(
        hex::encode(Sha256::digest(&bytes)) == expected,
        "File changed since detection"
    );
    Ok(bytes)
}
