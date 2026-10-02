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

#[cfg(unix)]
#[tokio::test]
async fn native_watcher_resolves_a_symlink_in_the_parent_path() {
    let dir = tempfile::tempdir().unwrap();
    let real = dir.path().join("real");
    let inner = real.join("watched");
    std::fs::create_dir_all(&inner).unwrap();
    let alias = dir.path().join("alias");
    std::os::unix::fs::symlink(&real, &alias).unwrap();
    let root = alias.join("watched"); // The root itself is not a symlink.
    let (tx, mut rx) = tokio::sync::mpsc::channel(16);
    let _watcher = realtime::watch(&[root], tx, Arc::new(AtomicU64::new(0))).unwrap();
    let file = inner.join("benign-aliased-fixture.txt");
    std::fs::write(&file, b"Harmless canonical watch-path regression").unwrap();
    tokio::time::timeout(std::time::Duration::from_secs(10), async {
        while let Some(path) = rx.recv().await {
            if path.file_name() == file.file_name() {
                return;
            }
        }
        panic!("Watcher closed before reporting the fixture");
    })
    .await
    .unwrap();
}
