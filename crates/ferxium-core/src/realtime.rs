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

pub fn watch(
    paths: &[PathBuf],
    tx: mpsc::Sender<PathBuf>,
    dropped: Arc<AtomicU64>,
) -> Result<RecommendedWatcher> {
    let mut watcher =
        notify::recommended_watcher(move |event: notify::Result<Event>| match event {
            Ok(event) if matches!(event.kind, EventKind::Create(_) | EventKind::Modify(_)) => {
                for path in event.paths {
                    if tx.try_send(path).is_err() {
                        dropped.fetch_add(1, Ordering::Relaxed);
                    }
                }
            }
            Err(_) => {
                dropped.fetch_add(1, Ordering::Relaxed);
            }
            _ => {}
        })?;
    for path in paths {
        watcher.watch(path, RecursiveMode::Recursive)?;
    }
    Ok(watcher)
}

/// Platform extension boundary: Windows ETW/minifilter, Linux fanotify/eBPF,
/// macOS Endpoint Security require OS entitlements and separate threat review.
pub trait ExecutionMonitor: Send {
    fn start(&mut self, events: mpsc::Sender<PathBuf>) -> Result<()>;
    fn stop(&mut self) -> Result<()>;
}
