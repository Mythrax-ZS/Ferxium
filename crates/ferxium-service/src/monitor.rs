//! Bounded foreground scans and a separately reserved reconciliation worker.
//! Event collection never waits for file I/O or YARA. All verdicts remain
//! after-change observations; this module does not authorize execution.
use crate::runtime::App;
use ferxium_core::{Config, MonitoringHealth, MonitoringStatus, Scanner, config};
use std::{
    collections::{HashMap, HashSet},
    path::{Path, PathBuf},
    sync::{Arc, atomic::Ordering},
    time::{Duration, Instant},
};
use tokio::{sync::mpsc, task::JoinSet};

const CAPACITY: usize = 4096;
const FOREGROUND_WORKERS: usize = 2;
const QUIET: Duration = Duration::from_millis(600);
const MAX_WAIT: Duration = Duration::from_secs(5);
const MAX_RETRIES: u8 = 3;
const SWEEP_INTERVAL: Duration = Duration::from_secs(30 * 60);
const RECOVERY_BACKOFF: Duration = Duration::from_secs(30);

#[derive(Clone)]
struct Pending {
    first: Instant,
    last: Instant,
    not_before: Instant,
    retries: u8,
}

impl Pending {
    fn new(now: Instant) -> Self {
        Self {
            first: now,
            last: now,
            not_before: now,
            retries: 0,
        }
    }

    fn ready(&self, now: Instant) -> bool {
        now >= self.not_before
            && (now.duration_since(self.last) >= QUIET
                || now.duration_since(self.first) >= MAX_WAIT)
    }
}

fn enqueue(pending: &mut HashMap<PathBuf, Pending>, path: PathBuf, now: Instant) -> bool {
    if let Some(work) = pending.get_mut(&path) {
        work.last = now;
        return true;
    }
    if pending.len() == CAPACITY {
        return false;
    }
    pending.insert(path, Pending::new(now));
    true
}

fn urgent(path: &Path) -> bool {
    path.extension().and_then(|s| s.to_str()).is_none_or(|s| {
        [
            "exe", "dll", "com", "scr", "ps1", "bat", "cmd", "vbs", "js", "sh", "py",
        ]
        .iter()
        .any(|extension| s.eq_ignore_ascii_case(extension))
    })
}

fn next_path(
    pending: &HashMap<PathBuf, Pending>,
    inflight: &HashSet<PathBuf>,
    now: Instant,
) -> Option<PathBuf> {
    pending
        .iter()
        .filter(|(path, work)| !inflight.contains(*path) && work.ready(now))
        .min_by_key(|(path, work)| {
            let rank = if now.duration_since(work.first) >= MAX_WAIT {
                0
            } else if urgent(path) {
                1
            } else {
                2
            };
            (rank, work.first)
        })
        .map(|(path, _)| path.clone())
}

enum Attempt {
    Done,
    Retry(String),
    Failed(String),
    Obsolete,
}

fn retryable(error: &anyhow::Error) -> bool {
    error
        .downcast_ref::<ferxium_core::scanner::FileChanged>()
        .is_some()
        || error.chain().any(|cause| {
            cause.downcast_ref::<std::io::Error>().is_some_and(|io| {
                matches!(
                    io.kind(),
                    std::io::ErrorKind::PermissionDenied
                        | std::io::ErrorKind::WouldBlock
                        | std::io::ErrorKind::Interrupted
                        | std::io::ErrorKind::UnexpectedEof
                        | std::io::ErrorKind::TimedOut
                ) || matches!(io.raw_os_error(), Some(32 | 33)) && cfg!(windows)
            })
        })
}

fn current(app: &App, revision: u64) -> bool {
    !app.shutdown.load(Ordering::Acquire) && app.revision.load(Ordering::Acquire) == revision
}

fn scan_once(app: &App, path: &Path, config: &Config, engine: &Scanner, revision: u64) -> Attempt {
    if !current(app, revision) {
        return Attempt::Obsolete;
    }
    if config.excludes(path) || config::normalize_path(path).starts_with(&app.data) {
        return Attempt::Done;
    }
    match std::fs::symlink_metadata(path) {
        Ok(metadata) if metadata.file_type().is_symlink() || !metadata.is_file() => {
            return Attempt::Done;
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Attempt::Done,
        Err(error) => return Attempt::Retry(error.to_string()),
        _ => {}
    }
    match engine.scan_file(path, config) {
        Ok(outcome) => {
            if !current(app, revision) {
                return Attempt::Obsolete;
            }
            if app.record_outcome(outcome)
                && let Err(error) = app.persist()
            {
                return Attempt::Failed(format!("Unable to persist detection: {error}"));
            }
            Attempt::Done
        }
        Err(error)
            if error.chain().any(|cause| {
                cause
                    .downcast_ref::<std::io::Error>()
                    .is_some_and(|io| io.kind() == std::io::ErrorKind::NotFound)
            }) =>
        {
            Attempt::Done
        }
        Err(error) if retryable(&error) => Attempt::Retry(error.to_string()),
        Err(error) => Attempt::Failed(error.to_string()),
    }
}

struct Job {
    path: PathBuf,
    pending: Pending,
    attempt: Attempt,
    revision: u64,
}

#[derive(Default)]
struct Recovery {
    generation: u64,
    revision: u64,
    errors: u64,
    retries: u64,
    last_error: Option<String>,
    obsolete: bool,
    failure_generation: u64,
}

fn recover(
    app: Arc<App>,
    config: Config,
    engine: Arc<Scanner>,
    revision: u64,
    generation: u64,
    failed: Vec<PathBuf>,
    failure_generation: u64,
) -> Recovery {
    let mut report = Recovery {
        generation,
        revision,
        failure_generation,
        ..Recovery::default()
    };
    fn check(
        app: &App,
        path: &Path,
        config: &Config,
        engine: &Scanner,
        report: &mut Recovery,
    ) -> bool {
        let revision = report.revision;
        for attempt in 0..=MAX_RETRIES {
            match scan_once(app, path, config, engine, revision) {
                Attempt::Done => return true,
                Attempt::Obsolete => {
                    report.obsolete = true;
                    return false;
                }
                Attempt::Retry(_) if attempt < MAX_RETRIES => {
                    report.retries += 1;
                    // Check cancellation during backoff, not only between files.
                    for _ in 0..(5 * (1 << attempt)) {
                        if !current(app, revision) {
                            report.obsolete = true;
                            return false;
                        }
                        std::thread::sleep(Duration::from_millis(50));
                    }
                }
                Attempt::Retry(error) | Attempt::Failed(error) => {
                    report.errors += 1;
                    report.last_error = Some(error.chars().take(300).collect());
                    return true;
                }
            }
        }
        true
    }
    for root in &config.watch_paths {
        for entry in app.walk(root, &config) {
            if !current(&app, revision) {
                report.obsolete = true;
                return report;
            }
            match entry {
                Ok(entry) if entry.file_type().is_file() => {
                    if !check(&app, entry.path(), &config, &engine, &mut report) {
                        return report;
                    }
                }
                Err(error) => {
                    // Walk errors count as incomplete coverage; never report a
                    // successful recovery just because unreadable entries vanish.
                    app.event(
                        "warning",
                        "A reconciliation folder could not be read. Recovery will retry.",
                    );
                    report.errors += 1;
                    report.last_error = Some(error.to_string().chars().take(300).collect());
                }
                _ => {}
            }
        }
    }
    for path in &failed {
        if !check(&app, path, &config, &engine, &mut report) {
            return report;
        }
    }
    report
}

pub fn spawn(app: Arc<App>, mut rx: mpsc::Receiver<PathBuf>) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        let mut pending = HashMap::new();
        let mut inflight = HashSet::new();
        let mut failed = HashSet::new();
        let mut jobs = JoinSet::<Job>::new();
        let mut recovery = None::<tokio::task::JoinHandle<Recovery>>;
        let mut recovered_generation = 0;
        let mut attempted_generation = 0;
        let mut config_revision = u64::MAX;
        let mut needs_recovery = false;
        let mut failure_generation = 0;
        let mut next_recovery = Instant::now();
        let mut last_sweep = Instant::now();
        let mut status = MonitoringStatus::default();
        let mut tick = tokio::time::interval(Duration::from_millis(100));
        tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        loop {
            let mut completion = tokio::select! {
                path = rx.recv() => {
                    let Some(path) = path else { break; };
                    if !enqueue(&mut pending, path, Instant::now()) { app.signals.record_drop(); }
                    continue;
                },
                result = jobs.join_next(), if !jobs.is_empty() => result,
                _ = tick.tick() => None,
            };
            if app.shutdown.load(Ordering::Acquire) {
                break;
            }
            let (config, engine, watcher_active, watcher_error, revision) = app.monitor_snapshot();
            let now = Instant::now();
            if revision != config_revision {
                pending.clear();
                failed.clear();
                status.last_error = None;
                needs_recovery = true;
                next_recovery = now;
                config_revision = revision;
            }
            while let Some(result) = completion.take().or_else(|| jobs.try_join_next()) {
                match result {
                    Ok(Job {
                        path,
                        pending: mut work,
                        attempt,
                        revision: job_revision,
                    }) => {
                        inflight.remove(&path);
                        if job_revision != revision {
                            continue;
                        }
                        match attempt {
                            Attempt::Done => {
                                failed.remove(&path);
                            }
                            Attempt::Retry(_)
                                if work.retries < MAX_RETRIES && config.protection_enabled =>
                            {
                                status.retry_count += 1;
                                work.not_before =
                                    now + Duration::from_millis(250 * (1 << work.retries));
                                work.retries += 1;
                                if let Some(newer) = pending.get_mut(&path) {
                                    newer.retries = work.retries;
                                    newer.not_before = work.not_before;
                                } else if pending.len() < CAPACITY {
                                    pending.insert(path, work);
                                } else {
                                    app.signals.record_drop();
                                }
                            }
                            Attempt::Retry(error) | Attempt::Failed(error) => {
                                status.scan_failures += 1;
                                failure_generation += 1;
                                status.last_error = Some(error.chars().take(300).collect());
                                if failed.len() < CAPACITY {
                                    failed.insert(path);
                                }
                                needs_recovery = true;
                            }
                            Attempt::Obsolete => {}
                        }
                    }
                    Err(_) => {
                        inflight.clear();
                        status.last_error = Some(
                            "A scan worker stopped unexpectedly; reconciling watched files.".into(),
                        );
                        app.signals.record_drop();
                        needs_recovery = true;
                    }
                }
            }
            if recovery.as_ref().is_some_and(|task| task.is_finished()) {
                match recovery.take().unwrap().await {
                    Ok(report) if !report.obsolete && report.revision == revision => {
                        status.retry_count += report.retries;
                        status.scan_failures += report.errors;
                        if report.errors == 0 {
                            recovered_generation = report.generation;
                            needs_recovery = failure_generation != report.failure_generation;
                            if !needs_recovery {
                                failed.clear();
                                status.last_error = None;
                            }
                            status.recovery_count += 1;
                            status.last_recovery_at = Some(chrono::Utc::now());
                            app.event("info", "Watched-folder reconciliation finished. Missed-event recovery is complete for this pass.");
                        } else {
                            status.last_error = report.last_error;
                            needs_recovery = true;
                        }
                    }
                    Ok(_) => {
                        needs_recovery = true;
                    }
                    Err(_) => {
                        status.last_error = Some(
                            "Reconciliation worker stopped unexpectedly; retrying automatically."
                                .into(),
                        );
                        needs_recovery = true;
                    }
                }
                next_recovery = if needs_recovery {
                    now + RECOVERY_BACKOFF
                } else {
                    now
                };
            }
            if config.protection_enabled {
                if last_sweep.elapsed() >= SWEEP_INTERVAL {
                    app.signals.request_recovery();
                    last_sweep = now;
                }
                for _ in 0..64 {
                    if jobs.len() >= FOREGROUND_WORKERS {
                        break;
                    }
                    let Some(path) = next_path(&pending, &inflight, now) else {
                        break;
                    };
                    let work = pending.remove(&path).unwrap();
                    if config.excludes(&path)
                        || config::normalize_path(&path).starts_with(&app.data)
                    {
                        continue;
                    }
                    if std::fs::symlink_metadata(&path)
                        .is_ok_and(|m| m.is_dir() && !m.file_type().is_symlink())
                    {
                        // A moved-in folder may have no individual child
                        // notifications. Reconcile its contents safely.
                        app.signals.request_recovery();
                        continue;
                    }
                    inflight.insert(path.clone());
                    let job_app = app.clone();
                    let job_config = config.clone();
                    let job_engine = engine.clone();
                    jobs.spawn_blocking(move || {
                        let attempt =
                            std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                                scan_once(&job_app, &path, &job_config, &job_engine, revision)
                            }))
                            .unwrap_or_else(|_| {
                                Attempt::Failed(
                                    "Scan worker panicked; file needs another check.".into(),
                                )
                            });
                        Job {
                            path,
                            pending: work,
                            attempt,
                            revision,
                        }
                    });
                }
                let generation = app.signals.recovery_generation.load(Ordering::Acquire);
                if generation != attempted_generation {
                    next_recovery = now;
                }
                if recovery.is_none()
                    && watcher_active
                    && (needs_recovery || generation != recovered_generation)
                    && now >= next_recovery
                {
                    attempted_generation = generation;
                    let recovery_app = app.clone();
                    let failures = failed.iter().cloned().collect();
                    recovery = Some(tokio::task::spawn_blocking(move || {
                        recover(
                            recovery_app,
                            config.clone(),
                            engine,
                            revision,
                            generation,
                            failures,
                            failure_generation,
                        )
                    }));
                }
            } else {
                pending.clear();
            }
            status.queue_depth = pending.len() + rx.len();
            status.workers_active = jobs.len() + usize::from(recovery.is_some());
            status.oldest_event_age_ms = pending
                .values()
                .map(|p| now.duration_since(p.first).as_millis() as u64)
                .max()
                .unwrap_or(0);
            status.recovery_in_progress = recovery.is_some();
            let (enabled, _, active, _, _) = app.monitor_snapshot();
            status.health = if !enabled.protection_enabled {
                MonitoringHealth::Disabled
            } else if !active
                || watcher_error.is_some()
                || status.last_error.is_some()
                || status.oldest_event_age_ms > 10_000
            {
                MonitoringHealth::Degraded
            } else if recovery.is_some()
                || needs_recovery
                || app.signals.recovery_generation.load(Ordering::Acquire) != recovered_generation
            {
                MonitoringHealth::Recovering
            } else {
                MonitoringHealth::Healthy
            };
            if watcher_error.is_some() {
                status.last_error = watcher_error;
            }
            app.publish_monitoring(status.clone());
        }
        rx.close();
        // Blocking scans cooperatively observe shutdown/config revisions. Wait
        // for started work before publishing the final disabled status.
        while jobs.join_next().await.is_some() {}
        if let Some(task) = recovery {
            let _ = task.await;
        }
        status.health = MonitoringHealth::Disabled;
        status.workers_active = 0;
        status.queue_depth = 0;
        status.recovery_in_progress = false;
        app.publish_monitoring(status);
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn continuous_changes_have_a_deadline_and_retries_respect_backoff() {
        let start = Instant::now();
        let mut pending = HashMap::new();
        let path = PathBuf::from("inert.exe");
        for elapsed in [0, 100, 400, 1000, 4990] {
            assert!(enqueue(
                &mut pending,
                path.clone(),
                start + Duration::from_millis(elapsed)
            ));
        }
        assert!(next_path(&pending, &HashSet::new(), start + MAX_WAIT).is_some());
        pending.get_mut(&path).unwrap().not_before = start + Duration::from_secs(7);
        assert!(next_path(&pending, &HashSet::new(), start + MAX_WAIT).is_none());
    }

    #[test]
    fn priority_never_starves_older_work_and_duplicate_paths_do_not_grow_the_queue() {
        let start = Instant::now();
        let normal = PathBuf::from("inert.txt");
        let executable = PathBuf::from("inert.exe");
        let mut pending = HashMap::new();
        enqueue(&mut pending, normal.clone(), start);
        enqueue(
            &mut pending,
            executable.clone(),
            start + Duration::from_millis(100),
        );
        assert_eq!(
            next_path(&pending, &HashSet::new(), start + Duration::from_secs(1)),
            Some(executable)
        );
        assert_eq!(
            next_path(&pending, &HashSet::new(), start + MAX_WAIT),
            Some(normal.clone())
        );
        for _ in 0..1000 {
            enqueue(&mut pending, normal.clone(), start + Duration::from_secs(6));
        }
        assert_eq!(pending.len(), 2);
    }
}
