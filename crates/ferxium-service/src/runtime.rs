use anyhow::{Context, Result, ensure};
use chrono::Utc;
use ferxium_core::{
    quarantine::Quarantine,
    scanner::{SignatureDatabase, scan_roots},
    storage,
    updater::{self, SignedEnvelope},
    *,
};
use serde::{Deserialize, Serialize};
use std::{
    collections::HashSet,
    path::{Path, PathBuf},
    sync::{
        Arc, Mutex, RwLock,
        atomic::{AtomicBool, AtomicU8, AtomicU64, Ordering},
    },
    time::{Duration, Instant},
};
use tokio::sync::mpsc;
use uuid::Uuid;
use walkdir::WalkDir;

#[derive(Default, Serialize, Deserialize)]
struct Saved {
    threats: Vec<Threat>,
    history: Vec<ScanProgress>,
    scanned_total: u64,
}
struct Runtime {
    config: Config,
    saved: Saved,
    scan: Option<ScanProgress>,
    control: Option<Arc<AtomicU8>>,
    activity: Vec<Activity>,
    watcher_active: bool,
    watcher_error: Option<String>,
    monitoring: MonitoringStatus,
    watched_roots: Vec<PathBuf>,
    process_count: usize,
    network_received: u64,
    network_transmitted: u64,
    established_connections: Option<usize>,
}
pub struct App {
    pub(crate) data: PathBuf,
    state: Mutex<Runtime>,
    engine: RwLock<Arc<Scanner>>,
    vault: Mutex<Quarantine>,
    pub actions: tokio::sync::Mutex<()>,
    pub signals: Arc<realtime::WatchSignals>,
    pub shutdown: AtomicBool,
    pub(crate) revision: AtomicU64,
}

impl App {
    pub fn load(data: PathBuf) -> Result<Self> {
        let data = data.canonicalize()?;
        let config_path = data.join("config.json");
        let config: Config = if config_path.exists() {
            storage::read_json(&config_path)?
        } else {
            Config::default()
        };
        config.validate()?;
        let signatures_path = data.join("signatures.signed.json");
        let database = if signatures_path.exists() {
            let signed: SignedEnvelope = storage::read_json(&signatures_path)?;
            updater::verify(
                &signed,
                config
                    .update_public_key
                    .as_deref()
                    .context("Cached signatures require the configured trusted key")?,
                0,
            )?
        } else {
            SignatureDatabase::parse(BUNDLED_DATABASE.as_bytes())?
        };
        let saved = if data.join("state.json").exists() {
            storage::read_json(&data.join("state.json"))?
        } else {
            Saved::default()
        };
        let vault = Quarantine::open(&data)?;
        Ok(Self {
            engine: RwLock::new(Arc::new(Scanner::new(database, BUNDLED_RULES)?)),
            vault: Mutex::new(vault),
            state: Mutex::new(Runtime {
                config,
                saved,
                scan: None,
                control: None,
                activity: vec![],
                watcher_active: false,
                watcher_error: None,
                monitoring: MonitoringStatus::default(),
                watched_roots: vec![],
                process_count: 0,
                network_received: 0,
                network_transmitted: 0,
                established_connections: None,
            }),
            data,
            actions: tokio::sync::Mutex::new(()),
            signals: Arc::new(realtime::WatchSignals::default()),
            shutdown: AtomicBool::new(false),
            revision: AtomicU64::new(0),
        })
    }

    pub fn event(&self, level: &str, message: &str) {
        let mut state = self.state.lock().unwrap();
        state.activity.insert(
            0,
            Activity {
                at: Utc::now(),
                level: level.into(),
                message: message.into(),
            },
        );
        state.activity.truncate(100);
    }
    pub fn persist(&self) -> Result<()> {
        let state = self.state.lock().unwrap();
        storage::write_json(&self.data.join("state.json"), &state.saved)
    }
    pub fn snapshot(&self) -> Result<ServiceStatus> {
        // Keep lock order consistent: never hold state while acquiring vault.
        let quarantine = self.vault.lock().unwrap().list()?;
        let engine = self.engine.read().unwrap();
        let state = self.state.lock().unwrap();
        Ok(ServiceStatus {
            version: env!("CARGO_PKG_VERSION").into(),
            protection_enabled: state.config.protection_enabled,
            watcher_active: state.watcher_active,
            watched_roots: state.watched_roots.clone(),
            dropped_events: self.signals.dropped_events.load(Ordering::Relaxed),
            monitoring: state.monitoring.clone(),
            yara_enabled: engine.yara_enabled(),
            signature_version: engine.version,
            scanned_total: state.saved.scanned_total,
            process_count: state.process_count,
            network_received: state.network_received,
            network_transmitted: state.network_transmitted,
            established_connections: state.established_connections,
            scan: state.scan.clone(),
            threats: state.saved.threats.clone(),
            quarantine,
            history: state.saved.history.clone(),
            activity: state.activity.clone(),
            config: state.config.clone(),
        })
    }
    pub fn scan_active(&self) -> bool {
        self.state.lock().unwrap().control.is_some()
    }
    pub fn cancel_active(&self) {
        if let Some(control) = &self.state.lock().unwrap().control {
            control.store(2, Ordering::Release);
        }
    }

    fn control(&self, value: u8) -> Result<()> {
        let state = self.state.lock().unwrap();
        state
            .control
            .as_ref()
            .context("No active scan")?
            .store(value, Ordering::Release);
        Ok(())
    }

    pub async fn apply(self: &Arc<Self>, action: Action) -> Result<()> {
        match action {
            Action::StartScan { request } => {
                self.start_scan(request)?;
            }
            Action::PauseScan => self.control(1)?,
            Action::ResumeScan => self.control(0)?,
            Action::CancelScan => self.control(2)?,
            Action::SetProtection { enabled } => {
                let mut config = self.state.lock().unwrap().config.clone();
                config.protection_enabled = enabled;
                self.save_config(config)?;
                self.event(
                    "info",
                    if enabled {
                        "File monitoring enabled."
                    } else {
                        "File monitoring paused by you."
                    },
                );
            }
            Action::SaveConfig { config } => self.save_config(config)?,
            Action::Allow { id } => {
                let mut state = self.state.lock().unwrap();
                let threat = state
                    .saved
                    .threats
                    .iter_mut()
                    .find(|t| t.id == id)
                    .context("Unknown threat")?;
                let hash = threat.sha256.clone();
                let mut config = state.config.clone();
                if !config.allowed_hashes.contains(&hash) {
                    config.allowed_hashes.push(hash);
                }
                drop(state);
                self.save_config(config)?;
                self.set_threat_status(id, "allowed")?;
                self.event("info", "File hash added to your local whitelist.");
            }
            Action::Quarantine { id } => {
                let threat = self
                    .state
                    .lock()
                    .unwrap()
                    .saved
                    .threats
                    .iter()
                    .find(|t| t.id == id && t.status == "pending")
                    .cloned()
                    .context("Unknown or already handled threat")?;
                let limit = self.state.lock().unwrap().config.max_file_bytes;
                let app = self.clone();
                tokio::task::spawn_blocking(move || {
                    app.vault.lock().unwrap().contain(&threat, limit)
                })
                .await??;
                self.set_threat_status(id, "quarantined")?;
                self.event(
                    "warning",
                    "Detected file encrypted in quarantine and removed from its original location.",
                );
            }
            Action::Restore { id, destination } => {
                let app = self.clone();
                tokio::task::spawn_blocking(move || {
                    app.vault.lock().unwrap().restore(id, &destination)
                })
                .await??;
                self.set_threat_status(id, "restored")?;
                self.event(
                    "warning",
                    "Quarantined file restored at your request. It may be detected again.",
                );
            }
            Action::DeleteQuarantine { id } => {
                let app = self.clone();
                tokio::task::spawn_blocking(move || app.vault.lock().unwrap().delete(id)).await??;
                self.set_threat_status(id, "deleted")?;
                self.event("info", "Quarantine backup permanently deleted.");
            }
            Action::UpdateSignatures => self.update().await?,
        }
        Ok(())
    }

    fn save_config(&self, config: Config) -> Result<()> {
        config.validate()?;
        ensure!(
            !config
                .watch_paths
                .iter()
                .any(|p| p.canonicalize().is_ok_and(|p| p.starts_with(&self.data))),
            "Cannot watch application state"
        );
        let state = self.state.lock().unwrap();
        ensure!(
            !self.data.join("signatures.signed.json").exists()
                || config.update_public_key == state.config.update_public_key,
            "Trusted key rotation requires an explicit cache migration; see release documentation"
        );
        drop(state);
        storage::write_json(&self.data.join("config.json"), &config)?;
        self.state.lock().unwrap().config = config;
        self.revision.fetch_add(1, Ordering::Release);
        Ok(())
    }
    fn set_threat_status(&self, id: Uuid, status: &str) -> Result<()> {
        let mut state = self.state.lock().unwrap();
        if let Some(threat) = state.saved.threats.iter_mut().find(|t| t.id == id) {
            threat.status = status.into();
        }
        drop(state);
        self.persist()
    }

    async fn update(self: &Arc<Self>) -> Result<()> {
        let config = self.state.lock().unwrap().config.clone();
        let version = self.engine.read().unwrap().version;
        let (envelope, database) = updater::fetch(&config, version).await?;
        let engine = Scanner::new(database, BUNDLED_RULES)?;
        updater::install(&self.data.join("signatures.signed.json"), &envelope)?;
        *self.engine.write().unwrap() = Arc::new(engine);
        self.signals.request_recovery();
        self.event("info", "Verified signature update installed. Active scans keep their original database snapshot.");
        Ok(())
    }

    pub fn start_scan(self: &Arc<Self>, request: ScanRequest) -> Result<Uuid> {
        ensure!(
            !self.shutdown.load(Ordering::Acquire),
            "Service is shutting down"
        );
        let roots = scan_roots(&request)?;
        let control = Arc::new(AtomicU8::new(0));
        let mut state = self.state.lock().unwrap();
        ensure!(state.control.is_none(), "A scan is already running");
        let progress = ScanProgress {
            id: Uuid::new_v4(),
            kind: request.kind,
            state: "enumerating".into(),
            scanned: 0,
            total_files: None,
            skipped: 0,
            errors: 0,
            threats: 0,
            current_path: None,
            started_at: Utc::now(),
            finished_at: None,
            elapsed_seconds: 0,
            estimated_remaining_seconds: None,
        };
        let id = progress.id;
        state.scan = Some(progress.clone());
        state.control = Some(control.clone());
        let config = state.config.clone();
        drop(state);
        let app = self.clone();
        let engine = self.engine.read().unwrap().clone();
        self.event(
            "info",
            "Scan started. Files will never be executed or uploaded.",
        );
        tokio::task::spawn_blocking(move || app.run_scan(roots, config, engine, control, progress));
        Ok(id)
    }

    fn run_scan(
        &self,
        roots: Vec<PathBuf>,
        config: Config,
        engine: Arc<Scanner>,
        control: Arc<AtomicU8>,
        mut progress: ScanProgress,
    ) {
        let started = Instant::now();
        let mut last_publish = Instant::now();
        let mut total = 0;
        for root in &roots {
            for entry in self.walk(root, &config) {
                if !self.wait_control(&control, &mut progress) {
                    break;
                }
                if let Ok(entry) = entry
                    && entry.file_type().is_file()
                {
                    total += 1;
                }
                if last_publish.elapsed() >= Duration::from_millis(200) {
                    self.publish(&mut progress, started);
                    last_publish = Instant::now();
                }
            }
            if control.load(Ordering::Acquire) == 2 {
                break;
            }
        }
        progress.total_files = Some(total);
        progress.state = "running".into();
        let scan_started = Instant::now();
        'roots: for root in &roots {
            for entry in self.walk(root, &config) {
                if !self.wait_control(&control, &mut progress) {
                    break 'roots;
                }
                match entry {
                    Ok(entry) if entry.file_type().is_file() => {
                        progress.current_path = Some(entry.path().to_path_buf());
                        match engine.scan_file(entry.path(), &config) {
                            Ok(FileOutcome::Skipped { .. }) => progress.skipped += 1,
                            Ok(outcome) => {
                                progress.scanned += 1;
                                // A scan counts every detected file, even when
                                // history already has the same pending threat.
                                if matches!(&outcome, FileOutcome::Detected { .. }) {
                                    progress.threats += 1;
                                }
                                self.record_outcome(outcome);
                            }
                            Err(_) => progress.errors += 1,
                        }
                    }
                    Err(_) => progress.errors += 1,
                    _ => {}
                }
                let processed = progress.scanned + progress.skipped;
                if processed > 0 {
                    progress.estimated_remaining_seconds = Some(
                        (total.saturating_sub(processed) as f64
                            * scan_started.elapsed().as_secs_f64()
                            / processed as f64) as u64,
                    );
                }
                if last_publish.elapsed() >= Duration::from_millis(200) {
                    self.publish(&mut progress, started);
                    last_publish = Instant::now();
                }
            }
        }
        progress.state = if control.load(Ordering::Acquire) == 2 {
            "cancelled"
        } else {
            "completed"
        }
        .into();
        progress.finished_at = Some(Utc::now());
        progress.current_path = None;
        progress.estimated_remaining_seconds = None;
        self.publish(&mut progress, started);
        let mut state = self.state.lock().unwrap();
        state.saved.history.insert(0, progress.clone());
        state.saved.history.truncate(100);
        state.control = None;
        drop(state);
        if let Err(error) = self.persist() {
            self.event("error", &format!("Unable to save scan report: {error}"));
        }
        self.event(
            "info",
            &format!(
                "Scan {}: {} checked, {} skipped, {} errors, {} findings.",
                progress.state,
                progress.scanned,
                progress.skipped,
                progress.errors,
                progress.threats
            ),
        );
    }

    pub(crate) fn walk<'a>(
        &'a self,
        root: &'a Path,
        config: &'a Config,
    ) -> impl Iterator<Item = walkdir::Result<walkdir::DirEntry>> + 'a {
        WalkDir::new(root)
            .follow_links(false)
            .max_open(32)
            .into_iter()
            .filter_entry(move |entry| {
                let p = entry.path();
                !p.starts_with(&self.data)
                    && !config.excludes(p)
                    && !p.file_name().is_some_and(|n| {
                        let name = n.to_string_lossy();
                        name.starts_with(".ferxium-hold-") || name.starts_with(".aegisguard-hold-")
                    })
                    && !["/proc", "/sys", "/dev", "/run"]
                        .iter()
                        .any(|r| p.starts_with(r))
            })
    }

    fn wait_control(&self, control: &AtomicU8, progress: &mut ScanProgress) -> bool {
        while control.load(Ordering::Acquire) == 1 {
            progress.state = "paused".into();
            self.state.lock().unwrap().scan = Some(progress.clone());
            std::thread::sleep(Duration::from_millis(100));
            if self.shutdown.load(Ordering::Acquire) {
                return false;
            }
        }
        if progress.state == "paused" {
            progress.state = if progress.total_files.is_some() {
                "running"
            } else {
                "enumerating"
            }
            .into();
        }
        control.load(Ordering::Acquire) != 2 && !self.shutdown.load(Ordering::Acquire)
    }
    fn publish(&self, progress: &mut ScanProgress, started: Instant) {
        progress.elapsed_seconds = started.elapsed().as_secs();
        self.state.lock().unwrap().scan = Some(progress.clone());
    }
    pub(crate) fn record_outcome(&self, outcome: FileOutcome) -> bool {
        // Native events, reconciliation and manual scans may use different
        // aliases for one path (Windows verbatim prefixes, macOS /var).
        // Normalize only for comparison: preserve the original report path and
        // never turn this into permission to follow a symlink or delete a file.
        let canonical = match &outcome {
            FileOutcome::Detected { threat } => threat.path.canonicalize().ok(),
            _ => None,
        };
        let mut state = self.state.lock().unwrap();
        state.saved.scanned_total += 1;
        if let FileOutcome::Detected { threat } = outcome
            && !state.saved.threats.iter().any(|t| {
                t.sha256 == threat.sha256
                    && t.status == "pending"
                    && (t.path == threat.path
                        || canonical.as_ref().is_some_and(|path| {
                            storage::open_regular(&t.path).is_ok()
                                && t.path.canonicalize().is_ok_and(|old| old == *path)
                        }))
            })
        {
            state.saved.threats.insert(0, threat);
            state.saved.threats.truncate(500);
            drop(state);
            self.event(
                "warning",
                "Potential threat detected. Review its report before taking action.",
            );
            return true;
        }
        false
    }

    pub(crate) fn monitor_snapshot(&self) -> (Config, Arc<Scanner>, bool, Option<String>, u64) {
        let engine = self.engine.read().unwrap().clone();
        let state = self.state.lock().unwrap();
        (
            state.config.clone(),
            engine,
            state.watcher_active,
            state.watcher_error.clone(),
            self.revision.load(Ordering::Acquire),
        )
    }

    pub(crate) fn publish_monitoring(&self, status: MonitoringStatus) {
        self.state.lock().unwrap().monitoring = status;
    }
}

pub fn spawn_background(
    app: Arc<App>,
    tx: mpsc::Sender<PathBuf>,
    rx: mpsc::Receiver<PathBuf>,
) -> tokio::task::JoinHandle<()> {
    let watcher_app = app.clone();
    let process_tx = tx.clone();
    tokio::task::spawn_blocking(move || {
        let mut revision = u64::MAX;
        let mut watcher = None;
        let mut registered_roots = Vec::<PathBuf>::new();
        let mut partial = false;
        let mut watcher_errors = 0;
        let mut retry_at = Instant::now();
        let mut retry_delay = Duration::from_millis(500);
        let mut system = sysinfo::System::new();
        // Establish a baseline instead of queueing every running executable at
        // startup. That flood can delay file events; Quick Scan covers existing
        // processes. Later snapshots still detect new PID/start-time identities.
        let mut known: Option<HashSet<(sysinfo::Pid, u64)>> = None;
        let mut networks = sysinfo::Networks::new_with_refreshed_list();
        let mut tick = 0u64;
        while !watcher_app.shutdown.load(Ordering::Acquire) {
            let current = watcher_app.revision.load(Ordering::Acquire);
            let errors = watcher_app.signals.watcher_errors.load(Ordering::Acquire);
            let configured = watcher_app.state.lock().unwrap().config.clone();
            let missing_root = watcher.is_some() && registered_roots.iter().any(|p| !p.exists());
            if current != revision || errors != watcher_errors || missing_root {
                watcher = None;
                registered_roots.clear();
                retry_at = Instant::now();
                retry_delay = Duration::from_millis(500);
                watcher_errors = errors;
                revision = current;
                watcher_app.signals.request_recovery();
            }
            if (watcher.is_none() || partial)
                && configured.protection_enabled
                && !configured.watch_paths.is_empty()
                && Instant::now() >= retry_at
            {
                let config = configured.clone();
                match realtime::register(
                    &config.watch_paths,
                    tx.clone(),
                    watcher_app.signals.clone(),
                ) {
                    Ok(registration) => {
                        partial = !registration.errors.is_empty();
                        registered_roots = registration.active_roots;
                        watcher = if registered_roots.is_empty() {
                            None
                        } else {
                            Some(registration.watcher)
                        };
                        watcher_app.state.lock().unwrap().watcher_error = if partial {
                            Some(format!("Some watched folders are unavailable; retrying automatically: {}", registration.errors.join("; ")).chars().take(500).collect())
                        } else {
                            None
                        };
                        if partial {
                            retry_at = Instant::now() + retry_delay;
                            retry_delay = (retry_delay * 2).min(Duration::from_secs(30));
                        } else {
                            retry_delay = Duration::from_millis(500);
                        }
                        watcher_app.signals.request_recovery();
                        watcher_app.event("info", "Native file monitoring registered; checking watched folders for missed changes.");
                    }
                    Err(error) => {
                        partial = true;
                        let message =
                            format!("File watcher unavailable; retrying automatically: {error}");
                        watcher_app.state.lock().unwrap().watcher_error =
                            Some(message.chars().take(500).collect());
                        watcher_app.event("warning", "A watched folder is unavailable. File monitoring will retry automatically.");
                        retry_at = Instant::now() + retry_delay;
                        retry_delay = (retry_delay * 2).min(Duration::from_secs(30));
                    }
                }
            }
            {
                let mut state = watcher_app.state.lock().unwrap();
                state.watcher_active = watcher.is_some();
                state.watched_roots = if watcher.is_some() {
                    registered_roots.clone()
                } else {
                    vec![]
                };
            }
            if tick.is_multiple_of(10) {
                system.refresh_processes(sysinfo::ProcessesToUpdate::All, true);
                let mut next = HashSet::new();
                let enabled = watcher_app.state.lock().unwrap().config.protection_enabled;
                for (pid, process) in system.processes() {
                    let identity = (*pid, process.start_time());
                    next.insert(identity);
                    if enabled
                        && known
                            .as_ref()
                            .is_some_and(|known| !known.contains(&identity))
                        && let Some(path) = process.exe()
                        && process_tx.try_send(path.to_path_buf()).is_err()
                    {
                        watcher_app.signals.record_drop();
                    }
                }
                known = Some(next);
                networks.refresh(true);
                // Socket metadata stays local; ordinary connections are not
                // treated as malicious. Failures are represented as unavailable.
                let connections = netstat2::get_sockets_info(netstat2::AddressFamilyFlags::IPV4 | netstat2::AddressFamilyFlags::IPV6, netstat2::ProtocolFlags::TCP)
                    .ok().map(|sockets| sockets.into_iter().filter(|socket| matches!(&socket.protocol_socket_info, netstat2::ProtocolSocketInfo::Tcp(tcp) if tcp.state == netstat2::TcpState::Established)).count());
                let mut state = watcher_app.state.lock().unwrap();
                state.process_count = system.processes().len();
                state.network_received = networks.values().map(|n| n.total_received()).sum();
                state.network_transmitted = networks.values().map(|n| n.total_transmitted()).sum();
                state.established_connections = connections;
            }
            tick += 1;
            std::thread::sleep(Duration::from_millis(500));
        }
        drop(watcher);
    });
    let monitor = crate::monitor::spawn(app.clone(), rx);
    tokio::spawn(async move {
        let mut tick = tokio::time::interval(Duration::from_secs(60));
        let mut last_scan = Instant::now();
        let mut last_update = Instant::now();
        loop {
            tick.tick().await;
            if app.shutdown.load(Ordering::Acquire) {
                break;
            }
            let config = app.state.lock().unwrap().config.clone();
            let _guard = app.actions.lock().await;
            if config
                .scan_interval_hours
                .is_some_and(|h| last_scan.elapsed().as_secs() >= u64::from(h) * 3600)
                && !app.scan_active()
            {
                if let Err(error) = app.start_scan(ScanRequest {
                    kind: ScanKind::Quick,
                    paths: vec![],
                }) {
                    app.event("error", &format!("Scheduled scan failed: {error}"));
                }
                last_scan = Instant::now();
            }
            if config
                .update_interval_hours
                .is_some_and(|h| last_update.elapsed().as_secs() >= u64::from(h) * 3600)
            {
                if let Err(error) = app.update().await {
                    app.event(
                        "error",
                        &format!("Scheduled signature update failed: {error}"),
                    );
                }
                last_update = Instant::now();
            }
        }
    });
    monitor
}

#[cfg(test)]
mod tests {
    use super::*;
    use ferxium_core::scanner::Md5Signature;

    #[test]
    fn path_aliases_keep_one_pending_id_but_distinct_hardlinks_keep_reports() {
        let (dir, app, watched) = monitoring_fixture();
        let file = watched.join("inert-alias.txt");
        std::fs::write(&file, b"abc").unwrap();
        let alias = dir.path().join("watched/../watched/inert-alias.txt");
        let engine = app.engine.read().unwrap().clone();
        assert!(app.record_outcome(engine.scan_file(&alias, &Config::default()).unwrap()));
        let id = app.snapshot().unwrap().threats[0].id;
        assert!(!app.record_outcome(engine.scan_file(&file, &Config::default()).unwrap()));
        assert_eq!(app.snapshot().unwrap().threats.len(), 1);
        assert_eq!(app.snapshot().unwrap().threats[0].id, id);
        // Quarantining one hardlink does not remove another name: retain both.
        let other = watched.join("inert-hardlink.txt");
        std::fs::hard_link(&file, &other).unwrap();
        assert!(app.record_outcome(engine.scan_file(&other, &Config::default()).unwrap()));
        assert_eq!(app.snapshot().unwrap().threats.len(), 2);
    }

    fn monitoring_fixture() -> (tempfile::TempDir, Arc<App>, PathBuf) {
        let dir = tempfile::tempdir().unwrap();
        let data = dir.path().join("state");
        let watched = dir.path().join("watched");
        storage::private_dir(&data).unwrap();
        std::fs::create_dir(&watched).unwrap();
        let watched = watched.canonicalize().unwrap();
        let config = Config {
            watch_paths: vec![watched.clone()],
            ..Config::default()
        };
        storage::write_json(&data.join("config.json"), &config).unwrap();
        let app = Arc::new(App::load(data).unwrap());
        *app.engine.write().unwrap() = Arc::new(
            Scanner::new(
                SignatureDatabase {
                    version: 1,
                    published_at: Utc::now(),
                    signatures: vec![],
                    md5_signatures: vec![Md5Signature {
                        md5: "900150983cd24fb0d6963f7d28e17f72".into(),
                        name: "Harmless.RecoveryFixture".into(),
                        severity: Severity::Low,
                        description: "Inert abc bytes used to check recovery".into(),
                    }],
                },
                BUNDLED_RULES,
            )
            .unwrap(),
        );
        // Deliberately omit a native watcher to inject lost delivery. Native
        // backends are exercised independently by core and packaged smoke tests.
        app.state.lock().unwrap().watcher_active = true;
        (dir, app, watched)
    }

    async fn until_status(app: &App, predicate: impl Fn(&ServiceStatus) -> bool) -> ServiceStatus {
        tokio::time::timeout(Duration::from_secs(25), async {
            loop {
                let status = app.snapshot().unwrap();
                assert!(status.monitoring.workers_active <= 3);
                assert!(status.monitoring.queue_depth <= 4097);
                if predicate(&status) {
                    return status;
                }
                tokio::time::sleep(Duration::from_millis(20)).await;
            }
        })
        .await
        .unwrap_or_else(|_| {
            let status = app.snapshot().unwrap();
            panic!("Monitoring did not reach the expected state: {:?}, threats={}, scanned={}, generation={}", status.monitoring, status.threats.len(), status.scanned_total, app.signals.recovery_generation.load(Ordering::Acquire));
        })
    }

    #[tokio::test]
    async fn overflow_recovery_finds_a_file_with_no_delivered_event_after_a_large_burst() {
        let (_dir, app, watched) = monitoring_fixture();
        let (tx, rx) = mpsc::channel(1);
        let monitor = crate::monitor::spawn(app.clone(), rx);
        until_status(&app, |s| {
            matches!(s.monitoring.health, MonitoringHealth::Healthy)
        })
        .await;
        let signals = app.signals.clone();
        let _sender = tokio::task::spawn_blocking(move || {
            for index in 0..2048 {
                let file = watched.join(format!("benign-{index:04}.txt"));
                std::fs::write(&file, b"ordinary fixture").unwrap();
                if tx.try_send(file).is_err() {
                    signals.record_drop();
                }
            }
            // This path is never delivered to the queue. Recovery must find it.
            std::fs::write(watched.join("missed-inert-fixture.txt"), b"abc").unwrap();
            signals.record_drop();
            // Keep the sender alive until recovery settles.
            tx
        })
        .await
        .unwrap();
        let status = until_status(&app, |s| {
            s.threats
                .iter()
                .any(|t| t.path.ends_with("missed-inert-fixture.txt"))
                && matches!(s.monitoring.health, MonitoringHealth::Healthy)
                && s.monitoring.queue_depth == 0
                && s.monitoring.workers_active == 0
        })
        .await;
        assert!(status.dropped_events > 0);
        assert!(status.monitoring.recovery_count >= 2);
        assert!(status.scanned_total >= 2049);
        assert_eq!(status.threats.len(), 1);
        app.shutdown.store(true, Ordering::Release);
        monitor.await.unwrap();
    }

    #[cfg(windows)]
    #[tokio::test]
    async fn locked_file_is_retried_and_detected_after_the_writer_releases_it() {
        use std::{io::Write, os::windows::fs::OpenOptionsExt};
        let (_dir, app, watched) = monitoring_fixture();
        let (tx, rx) = mpsc::channel(1);
        let monitor = crate::monitor::spawn(app.clone(), rx);
        until_status(&app, |s| {
            matches!(s.monitoring.health, MonitoringHealth::Healthy)
        })
        .await;
        let path = watched.join("locked-inert-fixture.txt");
        let mut writer = std::fs::OpenOptions::new()
            .create_new(true)
            .write(true)
            .share_mode(0)
            .open(&path)
            .unwrap();
        writer.write_all(b"abc").unwrap();
        tx.send(path).await.unwrap();
        until_status(&app, |s| s.monitoring.retry_count > 0).await;
        drop(writer);
        let status = until_status(&app, |s| !s.threats.is_empty()).await;
        assert_eq!(status.threats.len(), 1);
        assert_eq!(status.monitoring.scan_failures, 0);
        app.shutdown.store(true, Ordering::Release);
        monitor.await.unwrap();
    }

    #[tokio::test]
    async fn repeat_scans_count_detections_without_duplicate_history() {
        let dir = tempfile::tempdir().unwrap();
        let data = dir.path().join("state");
        storage::private_dir(&data).unwrap();
        let file = dir.path().join("inert.txt");
        std::fs::write(&file, b"abc").unwrap();
        let file = file.canonicalize().unwrap();
        let app = Arc::new(App::load(data).unwrap());
        let engine = Arc::new(
            Scanner::new(
                SignatureDatabase {
                    version: 1,
                    published_at: Utc::now(),
                    signatures: vec![],
                    md5_signatures: vec![Md5Signature {
                        md5: "900150983cd24fb0d6963f7d28e17f72".into(),
                        name: "Harmless.CounterFixture".into(),
                        severity: Severity::Low,
                        description: "Inert known-file regression fixture".into(),
                    }],
                },
                BUNDLED_RULES,
            )
            .unwrap(),
        );
        assert!(app.record_outcome(engine.scan_file(&file, &Config::default()).unwrap()));
        *app.engine.write().unwrap() = engine;
        for _ in 0..2 {
            let id = app
                .start_scan(ScanRequest {
                    kind: ScanKind::Custom,
                    paths: vec![file.clone()],
                })
                .unwrap();
            tokio::time::timeout(Duration::from_secs(5), async {
                loop {
                    let snapshot = app.snapshot().unwrap();
                    if let Some(scan) = snapshot.scan
                        && scan.id == id
                        && scan.state == "completed"
                    {
                        assert_eq!(scan.scanned, 1);
                        assert_eq!(scan.threats, 1);
                        assert_eq!(scan.errors, 0);
                        assert_eq!(snapshot.threats.len(), 1);
                        break;
                    }
                    tokio::time::sleep(Duration::from_millis(20)).await;
                }
            })
            .await
            .unwrap();
        }
    }
}
