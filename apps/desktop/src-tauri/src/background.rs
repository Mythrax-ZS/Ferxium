//! Native polling survives a hidden/throttled webview. The webview cannot supply
//! notification text, launch paths or startup arguments; it changes booleans only.
use ferxium_core::{Discovery, ServiceStatus, SupervisionStatus, Threat, storage};
use serde::{Deserialize, Serialize};
use std::{collections::HashSet, path::PathBuf, sync::Mutex, time::Duration};
use tauri::{Emitter, Manager};
use tauri_plugin_autostart::ManagerExt;
use tauri_plugin_notification::NotificationExt;

#[derive(Clone, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
struct Preferences {
    notifications_enabled: bool,
}
impl Default for Preferences {
    fn default() -> Self {
        Self {
            notifications_enabled: true,
        }
    }
}

#[derive(Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Ledger {
    seen: Vec<uuid::Uuid>,
}

pub struct DesktopAgent {
    pub data: PathBuf,
    pub isolated: bool,
    client: reqwest::Client,
    preferences: Mutex<Preferences>,
    status: Mutex<Option<ServiceStatus>>,
    ledger: Mutex<Ledger>,
    last_notification_error: Mutex<Option<String>>,
    refresh_lock: tokio::sync::Mutex<()>,
}

#[derive(Serialize)]
pub struct DesktopPreferences {
    notifications_enabled: bool,
    start_at_login: bool,
    startup_available: bool,
    supervisor_running: bool,
    restart_count: u64,
    supervisor_state: String,
    last_notification_error: Option<String>,
}

#[derive(Deserialize)]
#[serde(tag = "setting", rename_all = "snake_case", deny_unknown_fields)]
pub enum PreferenceChange {
    Notifications { enabled: bool },
    StartAtLogin { enabled: bool },
}

impl DesktopAgent {
    pub fn load(data: PathBuf, isolated: bool) -> Result<Self, Box<dyn std::error::Error>> {
        storage::private_dir(&data)?;
        let preferences = load_or_default::<Preferences>(&data.join("desktop.json"))?;
        let ledger = load_or_default::<Ledger>(&data.join("notification-state.json"))?;
        if ledger.seen.len() > 1024 {
            return Err("Notification ledger is invalid; retain a backup before repair".into());
        }
        Ok(Self {
            data,
            isolated,
            preferences: Mutex::new(preferences),
            ledger: Mutex::new(ledger),
            client: reqwest::Client::builder()
                .no_proxy()
                .redirect(reqwest::redirect::Policy::none())
                .timeout(Duration::from_secs(2))
                .build()?,
            status: Mutex::new(None),
            last_notification_error: Mutex::new(None),
            refresh_lock: tokio::sync::Mutex::new(()),
        })
    }

    pub fn snapshot(&self) -> Result<ServiceStatus, String> {
        self.status.lock().unwrap().clone()
            .ok_or_else(|| "Protection service is connecting or offline. Check the restart monitor in Settings.".into())
    }

    pub async fn refresh(&self) -> Result<(), String> {
        // Serialize poll/action refreshes so an older response cannot replace a
        // newer snapshot after a user changes protection or reviews a finding.
        let _refresh = self.refresh_lock.lock().await;
        let result = async {
            let discovery: Discovery = storage::read_json(&self.data.join("service.json"))
                .map_err(|_| "Protection service is offline.".to_string())?;
            let response = self
                .client
                .get(format!("http://127.0.0.1:{}/v1/status", discovery.port))
                .bearer_auth(discovery.token)
                .send()
                .await
                .map_err(|_| "Cannot reach protection service.".to_string())?
                .error_for_status()
                .map_err(|_| "Protection service rejected status request.".to_string())?;
            // Service retention is bounded, but also cap an impersonated same-user
            // endpoint rather than buffering an unbounded response in the desktop.
            let mut response = response;
            let mut bytes = Vec::new();
            while let Some(chunk) = response
                .chunk()
                .await
                .map_err(|_| "Cannot read service status.".to_string())?
            {
                if bytes.len() + chunk.len() > 5 * 1024 * 1024 {
                    return Err("Service status exceeds size limit.".into());
                }
                bytes.extend_from_slice(&chunk);
            }
            serde_json::from_slice::<ServiceStatus>(&bytes)
                .map_err(|_| "Invalid service status.".to_string())
        }
        .await;
        let mut cached = self.status.lock().unwrap();
        match result {
            Ok(status) => {
                *cached = Some(status);
                Ok(())
            }
            Err(error) => {
                *cached = None;
                Err(error)
            }
        }
    }

    fn notify(&self, app: &tauri::AppHandle) {
        let Ok(status) = self.snapshot() else { return };
        let mut ledger = self.ledger.lock().unwrap();
        let new = unseen(&ledger.seen, &status.threats);
        if new.is_empty() {
            return;
        }
        let body = alert_body(&new);
        let enabled = self.preferences.lock().unwrap().notifications_enabled;
        if enabled {
            if let Err(error) = app
                .notification()
                .builder()
                .title("FerXium: potential threat detected")
                .body(&body)
                .show()
            {
                *self.last_notification_error.lock().unwrap() = Some(error.to_string());
                return;
            }
            *self.last_notification_error.lock().unwrap() = None;
            let _ = app.emit("threat-alert", &body);
        }
        // Keep only the IDs the service retains, including reviewed findings.
        // Repeat scans reuse pending IDs. Disabled alerts do not accumulate a flood.
        ledger.seen = status.threats.iter().map(|t| t.id).take(1024).collect();
        if let Err(error) =
            storage::write_json(&self.data.join("notification-state.json"), &*ledger)
        {
            *self.last_notification_error.lock().unwrap() =
                Some(format!("Could not save notification history: {error}"));
        }
    }
}

fn load_or_default<T: serde::de::DeserializeOwned + Default>(
    path: &std::path::Path,
) -> Result<T, Box<dyn std::error::Error>> {
    match std::fs::symlink_metadata(path) {
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(T::default()),
        Err(error) => Err(error.into()),
        Ok(_) => Ok(storage::read_json(path)?),
    }
}

fn unseen<'a>(seen: &[uuid::Uuid], threats: &'a [Threat]) -> Vec<&'a Threat> {
    let seen: HashSet<_> = seen.iter().copied().collect();
    threats
        .iter()
        .filter(|t| t.status == "pending" && !seen.contains(&t.id))
        .collect()
}

fn safe_text(value: &str, limit: usize) -> String {
    value
        .chars()
        .filter(|c| {
            !c.is_control() && !matches!(c, '\u{202a}'..='\u{202e}' | '\u{2066}'..='\u{2069}')
        })
        .take(limit)
        .collect()
}

fn alert_body(threats: &[&Threat]) -> String {
    if threats.len() > 1 {
        return format!(
            "{} new findings need review. Open FerXium to inspect or quarantine them.",
            threats.len()
        );
    }
    let threat = threats[0];
    let file = threat
        .path
        .file_name()
        .unwrap_or_default()
        .to_string_lossy();
    let name = threat
        .findings
        .first()
        .map(|f| f.name.as_str())
        .unwrap_or("Suspicious file");
    format!(
        "{} · {}. Open FerXium to review this finding.",
        safe_text(&file, 80),
        safe_text(name, 80)
    )
}

pub fn start(app: tauri::AppHandle) {
    tauri::async_runtime::spawn(async move {
        loop {
            let agent = app.state::<DesktopAgent>();
            let _ = agent.refresh().await;
            agent.notify(&app);
            tokio::time::sleep(Duration::from_millis(500)).await;
        }
    });
}

#[tauri::command]
pub fn desktop_preferences(
    app: tauri::AppHandle,
    agent: tauri::State<'_, DesktopAgent>,
) -> Result<DesktopPreferences, String> {
    let supervisor =
        storage::read_json::<SupervisionStatus>(&agent.data.join("supervisor.json")).ok();
    let running = supervisor.as_ref().is_some_and(|s| {
        s.state != "stopped" && (chrono::Utc::now() - s.updated_at).num_seconds().abs() <= 5
    });
    Ok(DesktopPreferences {
        notifications_enabled: agent.preferences.lock().unwrap().notifications_enabled,
        start_at_login: app.autolaunch().is_enabled().map_err(|e| e.to_string())?,
        startup_available: !cfg!(debug_assertions) && !agent.isolated,
        supervisor_running: running,
        restart_count: supervisor.as_ref().map_or(0, |s| s.restart_count),
        supervisor_state: supervisor.map_or_else(|| "unavailable".into(), |s| s.state),
        last_notification_error: agent.last_notification_error.lock().unwrap().clone(),
    })
}

#[tauri::command]
pub fn set_desktop_preference(
    app: tauri::AppHandle,
    agent: tauri::State<'_, DesktopAgent>,
    change: PreferenceChange,
) -> Result<(), String> {
    ferxium_core::privilege::require_regular_user().map_err(|e| e.to_string())?;
    match change {
        PreferenceChange::Notifications { enabled } => {
            let preferences = Preferences {
                notifications_enabled: enabled,
            };
            storage::write_json(&agent.data.join("desktop.json"), &preferences)
                .map_err(|e| e.to_string())?;
            *agent.preferences.lock().unwrap() = preferences;
        }
        PreferenceChange::StartAtLogin { enabled } => {
            if cfg!(debug_assertions) || agent.isolated {
                return Err("Start at login is available in installed release builds with normal application state.".into());
            }
            if enabled {
                app.autolaunch().enable()
            } else {
                app.autolaunch().disable()
            }
            .map_err(|e| e.to_string())?;
        }
    }
    Ok(())
}

#[tauri::command]
pub fn test_notification(
    app: tauri::AppHandle,
    agent: tauri::State<'_, DesktopAgent>,
) -> Result<(), String> {
    if !agent.preferences.lock().unwrap().notifications_enabled {
        return Err("Turn on threat notifications first.".into());
    }
    app.notification().builder().title("FerXium notification test")
        .body("Native notifications are configured. Threat alerts can appear while FerXium is in the tray.")
        .show().map_err(|e| e.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use ferxium_core::{Finding, Severity};
    fn threat() -> Threat {
        Threat {
            id: uuid::Uuid::new_v4(),
            path: PathBuf::from("private-folder/harmless.txt"),
            sha256: "a".repeat(64),
            size: 3,
            detected_at: chrono::Utc::now(),
            status: "pending".into(),
            findings: vec![Finding {
                name: "Inert test fixture".into(),
                method: "sha256".into(),
                severity: Severity::High,
                explanation: "Harmless unit test".into(),
            }],
        }
    }
    #[test]
    fn notification_selection_deduplicates_and_skips_reviewed_findings() {
        let first = threat();
        let mut reviewed = threat();
        reviewed.status = "allowed".into();
        let second = threat();
        let list = vec![first.clone(), reviewed, second];
        let fresh = unseen(&[first.id], &list);
        assert_eq!(fresh.len(), 1);
        assert_eq!(fresh[0].id, list[2].id);
        assert_eq!(
            unseen(&list.iter().map(|t| t.id).collect::<Vec<_>>(), &list).len(),
            0
        );
    }
    #[test]
    fn toast_omits_full_paths_and_controls_and_batches_a_burst() {
        let one = threat();
        let two = threat();
        assert!(!alert_body(&[&one]).contains("private-folder"));
        assert!(alert_body(&[&one, &two]).contains("2 new findings"));
        assert_eq!(safe_text("x\n\u{202e}yz", 2), "xy");
    }
}
