//! Current-user watchdog. Launch only this executable, never a path supplied by
//! IPC. Only owned Child handles can be terminated; discovery PIDs are not used
//! as authority to kill a process. Intentional clean stops are not restarted.
use anyhow::{Context, Result, bail};
use chrono::Utc;
use ferxium_core::{Discovery, SupervisionStatus, storage};
use std::{
    path::{Path, PathBuf},
    process::{Child, Command, Stdio},
    time::{Duration, Instant},
};
use uuid::Uuid;

const TICK: Duration = Duration::from_millis(250);
const STABLE: Duration = Duration::from_secs(60);

// A failed state write or unexpected supervisor error must not orphan a worker.
// This handle can only contain a process spawned by this supervisor.
struct OwnedWorker(Child);
impl std::ops::Deref for OwnedWorker {
    type Target = Child;
    fn deref(&self) -> &Child {
        &self.0
    }
}
impl std::ops::DerefMut for OwnedWorker {
    fn deref_mut(&mut self) -> &mut Child {
        &mut self.0
    }
}
impl Drop for OwnedWorker {
    fn drop(&mut self) {
        if !matches!(self.0.try_wait(), Ok(Some(_))) {
            let _ = self.0.kill();
            let _ = self.0.wait();
        }
    }
}

fn publish(data: &Path, status: &SupervisionStatus) {
    if let Err(error) = storage::write_json(&data.join("supervisor.json"), status) {
        // Keep supervising through temporary storage failures. A stale heartbeat
        // makes the desktop display recovery as unavailable rather than healthy.
        tracing::warn!(%error, "Could not persist restart monitor heartbeat");
    }
}

fn contended(error: &std::io::Error) -> bool {
    error.kind() == std::io::ErrorKind::WouldBlock
        || error.raw_os_error() == fs2::lock_contended_error().raw_os_error()
}

fn backoff(failures: u32) -> Duration {
    Duration::from_secs(1u64 << failures.saturating_sub(1).min(5)).min(Duration::from_secs(30))
}

fn available(path: &Path) -> Result<bool> {
    let file = storage::lock_file(path)?;
    match fs2::FileExt::try_lock_exclusive(&file) {
        Ok(()) => Ok(true), // dropping the local handle releases our probe
        Err(error) if contended(&error) => Ok(false),
        Err(error) => Err(error.into()),
    }
}

fn spawn(data: &Path, port: u16) -> Result<OwnedWorker> {
    let mut command = Command::new(std::env::current_exe()?);
    command
        .arg("--data-dir")
        .arg(data)
        .arg("--port")
        .arg(port.to_string())
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null());
    #[cfg(windows)]
    {
        use std::os::windows::process::CommandExt;
        command.creation_flags(0x08000000); // CREATE_NO_WINDOW
    }
    Ok(OwnedWorker(command.spawn()?))
}

async fn request_shutdown(data: &Path) -> Result<()> {
    let discovery: Discovery = storage::read_json(&data.join("service.json"))?;
    reqwest::Client::builder()
        .no_proxy()
        .redirect(reqwest::redirect::Policy::none())
        .timeout(Duration::from_secs(2))
        .build()?
        .post(format!("http://127.0.0.1:{}/v1/shutdown", discovery.port))
        .bearer_auth(discovery.token)
        .send()
        .await?
        .error_for_status()?;
    Ok(())
}

pub async fn stop(data: &Path) -> Result<()> {
    if !available(&data.join("supervisor.lock"))? {
        let status: SupervisionStatus = storage::read_json(&data.join("supervisor.json"))?;
        storage::write_json(&data.join("supervisor-stop.json"), &status.id)?;
    }
    if !available(&data.join("service.lock"))? {
        let _ = request_shutdown(data).await; // the owning supervisor also requests it
    }
    let deadline = Instant::now() + Duration::from_secs(15);
    loop {
        if available(&data.join("supervisor.lock"))? && available(&data.join("service.lock"))? {
            println!("FerXium protection service stopped.");
            return Ok(());
        }
        if Instant::now() >= deadline {
            bail!("Service did not stop; inspect the running worker before updating");
        }
        tokio::time::sleep(TICK).await;
    }
}

pub async fn run(data: PathBuf, port: u16) -> Result<()> {
    let lock = storage::lock_file(&data.join("supervisor.lock"))?;
    match fs2::FileExt::try_lock_exclusive(&lock) {
        Ok(()) => {}
        Err(error) if contended(&error) => return Ok(()),
        Err(error) => return Err(error.into()),
    }
    let mut status = SupervisionStatus {
        id: Uuid::new_v4(),
        pid: std::process::id(),
        worker_pid: None,
        state: "starting".into(),
        restart_count: 0,
        last_error: None,
        updated_at: Utc::now(),
    };
    storage::write_json(&data.join("supervisor.json"), &status)?;
    let mut child: Option<OwnedWorker> = None;
    let mut started = Instant::now();
    let mut next_spawn = Instant::now();
    let mut failures = 0u32;
    let mut last_publish = Instant::now();
    let signal = crate::shutdown_signal();
    tokio::pin!(signal);
    loop {
        let requested = storage::read_json::<Uuid>(&data.join("supervisor-stop.json"))
            .is_ok_and(|id| id == status.id);
        let interrupted = if requested {
            true
        } else {
            tokio::select! { _ = &mut signal => true, _ = tokio::time::sleep(TICK) => false }
        };
        if interrupted {
            status.state = "stopping".into();
            status.updated_at = Utc::now();
            publish(&data, &status);
            let _ = request_shutdown(&data).await;
            if let Some(mut owned) = child.take() {
                let deadline = Instant::now() + Duration::from_secs(10);
                while owned.try_wait()?.is_none() {
                    if Instant::now() >= deadline {
                        owned.kill().context("Could not stop owned worker")?;
                        owned.wait()?;
                        break;
                    }
                    tokio::time::sleep(TICK).await;
                }
            }
            break;
        }
        if let Some(owned) = child.as_mut() {
            if let Some(exit) = owned.try_wait()? {
                child = None;
                status.worker_pid = None;
                if exit.success() {
                    break;
                }
                failures = if started.elapsed() >= STABLE {
                    1
                } else {
                    failures.saturating_add(1)
                };
                status.restart_count += 1;
                status.last_error = Some(format!(
                    "Worker exited abnormally ({exit}); restart scheduled."
                ));
                status.state = "restarting".into();
                next_spawn = Instant::now() + backoff(failures);
            }
        } else if Instant::now() >= next_spawn {
            // Existing foreground/older workers keep their lock. Wait for release;
            // never replace or terminate a process merely because its PID is in JSON.
            if available(&data.join("service.lock"))? {
                match spawn(&data, port) {
                    Ok(owned) => {
                        status.worker_pid = Some(owned.id());
                        status.state = "running".into();
                        child = Some(owned);
                        started = Instant::now();
                    }
                    Err(error) => {
                        failures = failures.saturating_add(1);
                        status.restart_count += 1;
                        status.last_error = Some(
                            format!("Unable to start worker: {error}")
                                .chars()
                                .take(240)
                                .collect(),
                        );
                        status.state = "restarting".into();
                        next_spawn = Instant::now() + backoff(failures);
                    }
                }
            } else {
                status.state = "waiting_for_existing_worker".into();
            }
        }
        if last_publish.elapsed() >= Duration::from_secs(1) {
            status.updated_at = Utc::now();
            publish(&data, &status);
            last_publish = Instant::now();
        }
    }
    status.state = "stopped".into();
    status.worker_pid = None;
    status.updated_at = Utc::now();
    storage::write_json(&data.join("supervisor.json"), &status)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn restart_delay_is_bounded_and_repeated_failures_back_off() {
        assert_eq!(backoff(1), Duration::from_secs(1));
        assert_eq!(backoff(2), Duration::from_secs(2));
        assert_eq!(backoff(3), Duration::from_secs(4));
        assert_eq!(backoff(u32::MAX), Duration::from_secs(30));
    }
    #[test]
    fn probe_does_not_claim_a_lock_held_by_another_handle() {
        let root = tempfile::tempdir().unwrap();
        let path = root.path().join("worker.lock");
        let owned = storage::lock_file(&path).unwrap();
        fs2::FileExt::try_lock_exclusive(&owned).unwrap();
        assert!(!available(&path).unwrap());
        drop(owned);
        assert!(available(&path).unwrap());
    }
}
