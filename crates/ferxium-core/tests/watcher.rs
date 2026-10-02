use ferxium_core::realtime;
use std::sync::{Arc, atomic::AtomicU64};

#[tokio::test]
async fn native_watcher_reports_a_created_benign_file() {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path().canonicalize().unwrap();
    let (tx, mut rx) = tokio::sync::mpsc::channel(16);
    let _watcher =
        realtime::watch(std::slice::from_ref(&root), tx, Arc::new(AtomicU64::new(0))).unwrap();
    let file = root.join("benign-monitoring-fixture.txt");
    std::fs::write(&file, b"Harmless watcher test").unwrap();
    let seen = tokio::time::timeout(std::time::Duration::from_secs(10), async {
        while let Some(path) = rx.recv().await {
            if path.file_name() == file.file_name() {
                return true;
            }
        }
        false
    })
    .await
    .unwrap();
    assert!(seen);
}
