use crate::{
    Config, FileOutcome, Finding, ScanKind, ScanRequest, Severity, Threat, config::valid_hash,
    storage::open_regular, yara_engine::YaraEngine,
};
use anyhow::{Result, ensure};
use chrono::{DateTime, Utc};
use md5::Md5;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    collections::HashMap,
    io::Read,
    path::{Path, PathBuf},
};
use uuid::Uuid;

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HashSignature {
    pub sha256: String,
    pub name: String,
    pub severity: Severity,
    pub description: String,
}

/// Legacy threat-intelligence identifier. Never use MD5 for trust, allowlisting,
/// update authentication, or quarantine integrity; those retain SHA-256/Ed25519.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Md5Signature {
    pub md5: String,
    pub name: String,
    pub severity: Severity,
    pub description: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SignatureDatabase {
    pub version: u64,
    pub published_at: DateTime<Utc>,
    pub signatures: Vec<HashSignature>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub md5_signatures: Vec<Md5Signature>,
}

impl SignatureDatabase {
    pub fn parse(bytes: &[u8]) -> Result<Self> {
        ensure!(
            bytes.len() <= 4 * 1024 * 1024,
            "Signature database too large"
        );
        let database: Self = serde_json::from_slice(bytes)?;
        ensure!(
            database.version > 0
                && database.signatures.len() + database.md5_signatures.len() <= 20_000,
            "Invalid database version or size"
        );
        for sig in &database.signatures {
            ensure!(
                valid_hash(&sig.sha256)
                    && !sig.name.is_empty()
                    && sig.name.len() <= 200
                    && sig.description.len() <= 2000,
                "Invalid signature"
            );
        }
        let mut seen = std::collections::HashSet::new();
        for sig in &database.md5_signatures {
            ensure!(
                sig.md5.len() == 32
                    && sig
                        .md5
                        .bytes()
                        .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
                    && seen.insert(&sig.md5)
                    && !sig.name.is_empty()
                    && sig.name.len() <= 200
                    && sig.description.len() <= 2000,
                "Invalid or duplicate legacy MD5 signature"
            );
        }
        Ok(database)
    }
}

pub struct Scanner {
    signatures: HashMap<String, HashSignature>,
    md5_signatures: HashMap<String, Md5Signature>,
    pub version: u64,
    yara: YaraEngine,
}

#[derive(Debug)]
pub struct FileChanged;

impl std::fmt::Display for FileChanged {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("File changed while it was being scanned")
    }
}

impl std::error::Error for FileChanged {}

fn verify_read(
    path: &Path,
    file: &std::fs::File,
    before: &std::fs::Metadata,
    identity: (u64, u64),
    bytes_len: u64,
) -> Result<()> {
    let after = file.metadata()?;
    // Reopen using no-follow checks before attaching a verdict to this pathname.
    let current = open_regular(path)?;
    let current_metadata = current.metadata()?;
    if bytes_len != before.len()
        || after.len() != before.len()
        || after.modified().ok() != before.modified().ok()
        || crate::storage::file_identity(&current)? != identity
        || current_metadata.len() != after.len()
        || current_metadata.modified().ok() != after.modified().ok()
    {
        return Err(FileChanged.into());
    }
    Ok(())
}

impl Scanner {
    pub fn new(database: SignatureDatabase, rules: &str) -> Result<Self> {
        Ok(Self {
            version: database.version,
            signatures: database
                .signatures
                .into_iter()
                .map(|s| (s.sha256.clone(), s))
                .collect(),
            md5_signatures: database
                .md5_signatures
                .into_iter()
                .map(|s| (s.md5.clone(), s))
                .collect(),
            yara: YaraEngine::new(rules)?,
        })
    }
    pub fn bundled() -> Result<Self> {
        Self::new(
            SignatureDatabase::parse(crate::BUNDLED_DATABASE.as_bytes())?,
            crate::BUNDLED_RULES,
        )
    }
    pub fn yara_enabled(&self) -> bool {
        self.yara.enabled()
    }

    pub fn scan_file(&self, path: &Path, config: &Config) -> Result<FileOutcome> {
        if config.excludes(path) {
            return Ok(FileOutcome::Skipped {
                reason: "Excluded path".into(),
            });
        }
        let mut file = open_regular(path)?;
        let before = file.metadata()?;
        let identity = crate::storage::file_identity(&file)?;
        if before.len() > config.max_file_bytes {
            return Ok(FileOutcome::Skipped {
                reason: "File exceeds configured limit".into(),
            });
        }
        let mut bytes = Vec::new();
        (&mut file)
            .take(config.max_file_bytes + 1)
            .read_to_end(&mut bytes)?;
        if bytes.len() as u64 > config.max_file_bytes {
            return Ok(FileOutcome::Skipped {
                reason: "File grew beyond limit".into(),
            });
        }
        verify_read(path, &file, &before, identity, bytes.len() as u64)?;
        let hash = hex::encode(Sha256::digest(&bytes));
        if config.allowed_hashes.contains(&hash) {
            return Ok(FileOutcome::Skipped {
                reason: "Allowed SHA-256".into(),
            });
        }
        let mut findings = vec![];
        if let Some(sig) = self.signatures.get(&hash) {
            findings.push(Finding {
                name: sig.name.clone(),
                method: "sha256".into(),
                severity: sig.severity,
                explanation: sig.description.clone(),
            });
        }
        // Hash the same bounded snapshot as SHA-256 and YARA. MD5 is only an
        // exact legacy IOC lookup; a finding is still identified by SHA-256.
        if !self.md5_signatures.is_empty()
            && let Some(sig) = self.md5_signatures.get(&hex::encode(Md5::digest(&bytes)))
        {
            findings.push(Finding {
                name: sig.name.clone(),
                method: "md5_ioc".into(),
                severity: sig.severity,
                explanation: sig.description.clone(),
            });
        }
        if matches_eicar(&bytes) && findings.is_empty() {
            findings.push(Finding {
                name: "EICAR-Test-File".into(),
                method: "test_signature".into(),
                severity: Severity::High,
                explanation: "Harmless antivirus test string; not real malware.".into(),
            });
        }
        findings.extend(self.yara.scan(&bytes)?);
        if config.heuristics_enabled {
            findings.extend(heuristics(path, &bytes));
        }
        if findings.is_empty() {
            Ok(FileOutcome::Clean {
                sha256: hash,
                size: bytes.len() as u64,
            })
        } else {
            Ok(FileOutcome::Detected {
                threat: Threat {
                    id: Uuid::new_v4(),
                    path: path.to_path_buf(),
                    sha256: hash,
                    size: bytes.len() as u64,
                    detected_at: Utc::now(),
                    findings,
                    status: "pending".into(),
                },
            })
        }
    }
}

fn matches_eicar(bytes: &[u8]) -> bool {
    // Keep the harmless test string out of the scanner's own on-disk image.
    // Compare against encoded bytes directly; black_box prevents release LTO
    // from folding the XOR back into an embedded plaintext signature.
    const ENCODED: &[u8] = &[
        253, 144, 234, 132, 245, 128, 229, 228, 245, 254, 145, 249, 245, 255, 253, 144, 145, 141,
        245, 251, 140, 146, 230, 230, 140, 146, 216, 129, 224, 236, 230, 228, 247, 136, 246, 241,
        228, 235, 225, 228, 247, 225, 136, 228, 235, 241, 236, 243, 236, 247, 240, 246, 136, 241,
        224, 246, 241, 136, 227, 236, 233, 224, 132, 129, 237, 142, 237, 143,
    ];
    let key = std::hint::black_box(0xa5u8);
    bytes.windows(ENCODED.len()).any(|window| {
        window
            .iter()
            .zip(ENCODED)
            .all(|(&actual, &encoded)| actual ^ key == encoded)
    })
}

fn heuristics(path: &Path, bytes: &[u8]) -> Vec<Finding> {
    let extension = path
        .extension()
        .and_then(|s| s.to_str())
        .unwrap_or_default()
        .to_ascii_lowercase();
    if !["ps1", "bat", "cmd", "vbs", "js", "sh"].contains(&extension.as_str())
        || bytes.len() > 1024 * 1024
    {
        return vec![];
    }
    let text = String::from_utf8_lossy(bytes).to_ascii_lowercase();
    let download = text.contains("downloadstring") || text.contains("invoke-webrequest");
    let execute = text.contains("invoke-expression") || text.contains("iex ");
    if download
        && execute
        && (text.contains("-encodedcommand")
            || text.contains("frombase64string")
            || text.contains("-executionpolicy bypass"))
    {
        vec![Finding { name: "Suspicious.Script.DownloadExecute".into(), method: "heuristic".into(), severity: Severity::Medium, explanation: "Script combines network download, dynamic execution, and obfuscation/bypass. This is a review signal, not proof of malware.".into() }]
    } else {
        vec![]
    }
}

pub fn scan_roots(request: &ScanRequest) -> Result<Vec<PathBuf>> {
    let roots = match request.kind {
        ScanKind::Custom => {
            ensure!(
                !request.paths.is_empty() && request.paths.len() <= 32,
                "Select 1–32 absolute paths"
            );
            request.paths.clone()
        }
        ScanKind::Full => {
            #[cfg(windows)]
            {
                sysinfo::Disks::new_with_refreshed_list()
                    .iter()
                    .map(|d| d.mount_point().to_path_buf())
                    .collect()
            }
            #[cfg(not(windows))]
            {
                vec![PathBuf::from("/")]
            }
        }
        ScanKind::Quick => quick_roots(),
    };
    let mut unique = vec![];
    for root in roots {
        ensure!(root.is_absolute(), "Scan paths must be absolute");
        ensure!(
            !std::fs::symlink_metadata(&root)?.file_type().is_symlink(),
            "Symlink roots are not allowed"
        );
        let p = root.canonicalize()?;
        if !unique.iter().any(|r: &PathBuf| p.starts_with(r)) {
            unique.retain(|r| !r.starts_with(&p));
            unique.push(p);
        }
    }
    ensure!(!unique.is_empty(), "No accessible scan locations");
    Ok(unique)
}

pub fn quick_roots() -> Vec<PathBuf> {
    let mut paths = vec![];
    if let Some(user) = directories::UserDirs::new() {
        let h = user.home_dir();
        paths.extend([h.join("Downloads"), h.join("Desktop")]);
        #[cfg(windows)]
        paths.extend([
            h.join("AppData/Roaming/Microsoft/Windows/Start Menu/Programs/Startup"),
            h.join("AppData/Local/Google/Chrome/User Data/Default/Extensions"),
            h.join("AppData/Roaming/Mozilla/Firefox/Profiles"),
        ]);
        #[cfg(target_os = "linux")]
        paths.extend([
            h.join(".config/autostart"),
            h.join(".config/google-chrome/Default/Extensions"),
            h.join(".mozilla/firefox"),
        ]);
        #[cfg(target_os = "macos")]
        paths.extend([
            h.join("Library/LaunchAgents"),
            h.join("Library/Application Support/Google/Chrome/Default/Extensions"),
            h.join("Library/Application Support/Firefox/Profiles"),
        ]);
    }
    #[cfg(windows)]
    {
        if let Some(w) = std::env::var_os("WINDIR") {
            paths.push(PathBuf::from(w).join("Temp"));
        }
    }
    #[cfg(not(windows))]
    paths.extend([PathBuf::from("/tmp"), PathBuf::from("/etc/cron.d")]);
    // Scan running executable files, not process address spaces. Memory scanning
    // needs a separate least-privilege platform adapter and is not claimed here.
    let mut system = sysinfo::System::new();
    system.refresh_processes(sysinfo::ProcessesToUpdate::All, true);
    paths.extend(
        system
            .processes()
            .values()
            .filter_map(|p| p.exe().map(Path::to_path_buf)),
    );
    paths.into_iter().filter(|p| p.exists()).collect()
}

#[cfg(test)]
mod eicar_tests {
    #[test]
    fn read_guard_rejects_a_same_size_replacement_and_an_in_place_change() {
        use super::*;
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("inert.txt");
        std::fs::write(&path, b"abc").unwrap();
        let file = open_regular(&path).unwrap();
        let before = file.metadata().unwrap();
        let identity = crate::storage::file_identity(&file).unwrap();
        verify_read(&path, &file, &before, identity, 3).unwrap();
        std::fs::rename(&path, dir.path().join("original.txt")).unwrap();
        std::fs::write(&path, b"abc").unwrap();
        assert!(
            verify_read(&path, &file, &before, identity, 3)
                .unwrap_err()
                .downcast_ref::<FileChanged>()
                .is_some()
        );
        let file = open_regular(&path).unwrap();
        let before = file.metadata().unwrap();
        let identity = crate::storage::file_identity(&file).unwrap();
        std::fs::write(&path, b"abcdef").unwrap();
        assert!(
            verify_read(&path, &file, &before, identity, 3)
                .unwrap_err()
                .downcast_ref::<FileChanged>()
                .is_some()
        );
    }

    #[test]
    fn encoded_matcher_accepts_eicar_and_newlines_but_rejects_near_misses() {
        // Test bytes directly: an installed AV may intercept harmless EICAR
        // files before this scanner can read them. Do not disable host protection.
        let marker = [
            b"X5O!P%@AP[4\\PZX54(P^)7CC)7}".as_slice(),
            b"$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*",
        ]
        .concat();
        for suffix in [b"".as_slice(), b"\n", b"\r\n"] {
            assert!(super::matches_eicar(&[marker.as_slice(), suffix].concat()));
        }
        let mut near_miss = marker;
        near_miss[0] ^= 1;
        assert!(!super::matches_eicar(&near_miss));
        assert!(!super::matches_eicar(b"ordinary file contents"));
    }
}
