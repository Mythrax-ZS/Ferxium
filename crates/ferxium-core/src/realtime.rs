//! Native notify backends: inotify, ReadDirectoryChangesW, FSEvents.
//! These are after-write notifications, not a kernel on-access execution gate.
use anyhow::Result;
use notify::{Event, EventKind, RecommendedWatcher, RecursiveMode, Watcher};
use std::{
    path::PathBuf,
    sync::{
        Arc,
        atomic::{AtomicU64, Ordering},
    },
};
use tokio::sync::mpsc;

/// Recovery requests have their own atomic generation: a full event queue
/// must never swallow the instruction to reconcile missed filesystem changes.
#[derive(Default)]
pub struct WatchSignals {
    pub dropped_events: AtomicU64,
    pub recovery_generation: AtomicU64,
    pub watcher_errors: AtomicU64,
}

impl WatchSignals {
    pub fn request_recovery(&self) {
        self.recovery_generation.fetch_add(1, Ordering::AcqRel);
    }

    pub fn record_drop(&self) {
        self.dropped_events.fetch_add(1, Ordering::Relaxed);
        self.request_recovery();
    }

    pub fn watcher_failed(&self) {
        self.watcher_errors.fetch_add(1, Ordering::AcqRel);
        self.record_drop();
    }
}

fn deliver(event: notify::Result<Event>, tx: &mpsc::Sender<PathBuf>, signals: &WatchSignals) {
    match event {
        Ok(event) => {
            // Rescan can arrive as EventKind::Other/Any, without a file path.
            // Check it before filtering ordinary create/modify notifications.
            if event.need_rescan() {
                signals.record_drop();
            }
            if matches!(
                event.kind,
                EventKind::Create(_) | EventKind::Modify(_) | EventKind::Any
            ) {
                for path in event.paths {
                    if tx.try_send(path).is_err() {
                        signals.record_drop();
                    }
                }
            }
        }
        Err(_) => signals.watcher_failed(),
    }
}

pub fn watch(
    paths: &[PathBuf],
    tx: mpsc::Sender<PathBuf>,
    signals: Arc<WatchSignals>,
) -> Result<RecommendedWatcher> {
    let registration = register(paths, tx, signals)?;
    anyhow::ensure!(
        registration.errors.is_empty(),
        "{}",
        registration.errors.join("; ")
    );
    Ok(registration.watcher)
}

pub struct Registration {
    pub watcher: RecommendedWatcher,
    pub active_roots: Vec<PathBuf>,
    pub errors: Vec<String>,
}

/// Keep accessible roots registered even when another root is unavailable.
pub fn register(
    paths: &[PathBuf],
    tx: mpsc::Sender<PathBuf>,
    signals: Arc<WatchSignals>,
) -> Result<Registration> {
    // Resolve aliases before registration, including macOS /var -> /private/var.
    let mut roots = Vec::new();
    let mut errors = Vec::new();
    for path in paths {
        match std::fs::symlink_metadata(path) {
            Ok(metadata) if metadata.file_type().is_symlink() => {
                errors.push("A configured watch root became a symlink".into());
                continue;
            }
            _ => {}
        }
        match path.canonicalize() {
            Ok(root) if !roots.contains(&root) => roots.push(root),
            Ok(_) => {}
            Err(error) => errors.push(error.to_string()),
        }
    }
    let callback_roots = roots.clone();
    let mut watcher = notify::recommended_watcher(move |event: notify::Result<Event>| {
        if let Ok(event) = &event
            && matches!(
                event.kind,
                EventKind::Remove(_) | EventKind::Modify(notify::event::ModifyKind::Name(_))
            )
            && event.paths.iter().any(|path| callback_roots.contains(path))
        {
            // A deleted/replaced root needs a new registration even when a new
            // directory appears at the same spelling before the next poll.
            signals.watcher_failed();
        }
        deliver(event, &tx, &signals);
    })?;
    let mut active_roots = Vec::new();
    for root in roots {
        match watcher.watch(&root, RecursiveMode::Recursive) {
            Ok(()) => active_roots.push(root),
            Err(error) => errors.push(error.to_string()),
        }
    }
    Ok(Registration {
        watcher,
        active_roots,
        errors,
    })
}

/// Platform extension boundary: Windows ETW/minifilter, Linux fanotify/eBPF,
/// macOS Endpoint Security require OS entitlements and separate threat review.
pub trait ExecutionMonitor: Send {
    fn start(&mut self, events: mpsc::Sender<PathBuf>) -> Result<()>;
    fn stop(&mut self) -> Result<()>;
}

#[cfg(test)]
mod tests {
    use super::*;
    use notify::event::Flag;

    #[test]
    fn pathless_rescan_and_full_queue_preserve_a_recovery_request() {
        let (tx, mut rx) = mpsc::channel(1);
        let signals = WatchSignals::default();
        deliver(
            Ok(Event::new(EventKind::Other).set_flag(Flag::Rescan)),
            &tx,
            &signals,
        );
        assert_eq!(signals.recovery_generation.load(Ordering::Acquire), 1);
        let path = PathBuf::from("inert-fixture.txt");
        for _ in 0..2 {
            deliver(
                Ok(Event::new(EventKind::Any).add_path(path.clone())),
                &tx,
                &signals,
            );
        }
        assert_eq!(rx.try_recv().unwrap(), path);
        assert_eq!(signals.recovery_generation.load(Ordering::Acquire), 2);
        deliver(
            Err(notify::Error::generic("synthetic watcher failure")),
            &tx,
            &signals,
        );
        assert_eq!(signals.watcher_errors.load(Ordering::Acquire), 1);
        assert_eq!(signals.recovery_generation.load(Ordering::Acquire), 3);
    }
}
