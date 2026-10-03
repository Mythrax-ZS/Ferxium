use ferxium_core::realtime;
use std::sync::Arc;

#[tokio::test]
async fn unavailable_root_does_not_disable_an_accessible_root() {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path().canonicalize().unwrap();
    let (tx, mut rx) = tokio::sync::mpsc::channel(16);
    let registration = realtime::register(
        &[root.clone(), root.join("missing")],
        tx,
        Arc::new(realtime::WatchSignals::default()),
    )
    .unwrap();
    assert_eq!(registration.active_roots, vec![root.clone()]);
    assert_eq!(registration.errors.len(), 1);
    std::fs::write(root.join("benign-partial-root.txt"), b"ordinary fixture").unwrap();
    tokio::time::timeout(std::time::Duration::from_secs(10), async {
        while let Some(path) = rx.recv().await {
            if path.ends_with("benign-partial-root.txt") {
                return;
            }
        }
        panic!("Accessible root lost its watcher");
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn native_watcher_reports_a_created_benign_file() {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path().canonicalize().unwrap();
    let (tx, mut rx) = tokio::sync::mpsc::channel(16);
    let _watcher = realtime::watch(
        std::slice::from_ref(&root),
        tx,
        Arc::new(realtime::WatchSignals::default()),
    )
    .unwrap();
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
    let _watcher =
        realtime::watch(&[root], tx, Arc::new(realtime::WatchSignals::default())).unwrap();
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
