use anyhow::{Result, ensure};
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct Config {
    pub protection_enabled: bool,
    pub watch_paths: Vec<PathBuf>,
    pub exclusions: Vec<PathBuf>,
    pub allowed_hashes: Vec<String>,
    pub max_file_bytes: u64,
    pub heuristics_enabled: bool,
    pub scan_interval_hours: Option<u32>,
    pub update_interval_hours: Option<u32>,
    pub update_manifest_url: Option<String>,
    pub update_public_key: Option<String>,
    // Hash-only lookup is intentionally an extension point, never an implicit upload.
    pub cloud_lookup_enabled: bool,
}

impl Default for Config {
    fn default() -> Self {
        let home = directories::UserDirs::new().map(|u| u.home_dir().to_path_buf());
        let watch_paths = home
            .into_iter()
            .flat_map(|h| [h.join("Downloads"), h.join("Desktop")])
            .filter(|p| p.is_dir())
            .collect();
        Self {
            protection_enabled: true,
            watch_paths,
            exclusions: vec![],
            allowed_hashes: vec![],
            max_file_bytes: 64 * 1024 * 1024,
            heuristics_enabled: true,
            scan_interval_hours: None,
            update_interval_hours: None,
            update_manifest_url: None,
            update_public_key: None,
            cloud_lookup_enabled: false,
        }
    }
}

impl Config {
    pub fn validate(&self) -> Result<()> {
        ensure!(
            (1024..=256 * 1024 * 1024).contains(&self.max_file_bytes),
            "File limit must be 1 KiB–256 MiB"
        );
        ensure!(
            self.watch_paths.len() <= 32 && self.exclusions.len() <= 128,
            "Too many paths"
        );
        ensure!(
            self.allowed_hashes.len() <= 10_000,
            "Too many whitelist entries"
        );
        for p in self.watch_paths.iter().chain(&self.exclusions) {
            ensure!(p.is_absolute(), "Paths must be absolute");
            ensure!(p.exists(), "Path does not exist: {}", p.display());
            ensure!(
                !p.components().any(|c| c == std::path::Component::ParentDir),
                "Parent traversal is not allowed"
            );
            ensure!(
                !std::fs::symlink_metadata(p)?.file_type().is_symlink(),
                "Symlink roots are not allowed"
            );
        }
        for hash in &self.allowed_hashes {
            ensure!(valid_hash(hash), "Invalid SHA-256 hash");
        }
        for hours in [self.scan_interval_hours, self.update_interval_hours]
            .into_iter()
            .flatten()
        {
            ensure!(
                (1..=24 * 365).contains(&hours),
                "Schedule interval must be 1–8760 hours"
            );
        }
        ensure!(
            !self.cloud_lookup_enabled,
            "No cloud provider is configured in this release"
        );
        ensure!(
            self.update_manifest_url.is_some() == self.update_public_key.is_some(),
            "Update URL and trusted key must be configured together"
        );
        if let Some(url) = &self.update_manifest_url {
            ensure!(url.starts_with("https://"), "Updates require HTTPS");
            ensure!(
                hex::decode(self.update_public_key.as_deref().unwrap_or_default())?.len() == 32,
                "Ed25519 public key must contain 32 bytes"
            );
        }
        Ok(())
    }

    pub fn excludes(&self, path: &Path) -> bool {
        let path = normalize_path(path);
        self.exclusions
            .iter()
            .any(|p| path.starts_with(normalize_path(p)))
    }
}

pub fn valid_hash(hash: &str) -> bool {
    hash.len() == 64
        && hash
            .bytes()
            .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase())
}

/// Normalize through the nearest existing ancestor, including temporarily
/// missing files during renames and Windows extended path prefixes.
pub fn normalize_path(path: &Path) -> PathBuf {
    for ancestor in path.ancestors() {
        if let Ok(base) = ancestor.canonicalize() {
            return base.join(
                path.strip_prefix(ancestor)
                    .unwrap_or_else(|_| Path::new("")),
            );
        }
    }
    path.to_path_buf()
}
