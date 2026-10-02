use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::path::PathBuf;
use uuid::Uuid;

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum Severity {
    Low,
    Medium,
    High,
    Critical,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Finding {
    pub name: String,
    pub method: String,
    pub severity: Severity,
    pub explanation: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Threat {
    pub id: Uuid,
    pub path: PathBuf,
    pub sha256: String,
    pub size: u64,
    pub detected_at: DateTime<Utc>,
    pub findings: Vec<Finding>,
    pub status: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "outcome", rename_all = "snake_case")]
pub enum FileOutcome {
    Clean { sha256: String, size: u64 },
    Detected { threat: Threat },
    Skipped { reason: String },
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ScanKind {
    Quick,
    Full,
    Custom,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanRequest {
    pub kind: ScanKind,
    #[serde(default)]
    pub paths: Vec<PathBuf>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanProgress {
    pub id: Uuid,
    pub kind: ScanKind,
    pub state: String,
    pub scanned: u64,
    pub total_files: Option<u64>,
    pub skipped: u64,
    pub errors: u64,
    pub threats: u64,
    pub current_path: Option<PathBuf>,
    pub started_at: DateTime<Utc>,
    pub finished_at: Option<DateTime<Utc>>,
    pub elapsed_seconds: u64,
    /// Enumeration is streamed. No invented percentage or ETA before a total is known.
    pub estimated_remaining_seconds: Option<u64>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Activity {
    pub at: DateTime<Utc>,
    pub level: String,
    pub message: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct QuarantineEntry {
    pub id: Uuid,
    pub threat: Threat,
    pub quarantined_at: DateTime<Utc>,
    /// Failed removal is explicit; encrypted backup alone is not isolation.
    pub source_removed: bool,
    pub staging_path: Option<PathBuf>,
    pub restored_at: Option<DateTime<Utc>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServiceStatus {
    pub version: String,
    pub protection_enabled: bool,
    pub watcher_active: bool,
    pub watched_roots: Vec<PathBuf>,
    pub dropped_events: u64,
    pub yara_enabled: bool,
    pub signature_version: u64,
    pub scanned_total: u64,
    pub process_count: usize,
    pub network_received: u64,
    pub network_transmitted: u64,
    pub established_connections: Option<usize>,
    pub scan: Option<ScanProgress>,
    pub threats: Vec<Threat>,
    pub quarantine: Vec<QuarantineEntry>,
    pub history: Vec<ScanProgress>,
    pub activity: Vec<Activity>,
    pub config: crate::Config,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Discovery {
    pub port: u16,
    pub token: String,
    pub pid: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "action", rename_all = "snake_case")]
pub enum Action {
    StartScan { request: ScanRequest },
    PauseScan,
    ResumeScan,
    CancelScan,
    SetProtection { enabled: bool },
    SaveConfig { config: crate::Config },
    Quarantine { id: Uuid },
    Restore { id: Uuid, destination: PathBuf },
    DeleteQuarantine { id: Uuid },
    Allow { id: Uuid },
    UpdateSignatures,
}
