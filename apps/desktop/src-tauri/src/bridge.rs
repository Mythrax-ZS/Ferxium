//! The bearer token stays in Rust; it is never returned to the webview.
use crate::background::DesktopAgent;
use ferxium_core::{Action, Discovery, ServiceStatus, storage};

async fn request(
    method: reqwest::Method,
    action: Option<Action>,
    data: &std::path::Path,
) -> Result<reqwest::Response, String> {
    let discovery: Discovery = storage::read_json(&data.join("service.json")).map_err(|_| {
        "Protection service is offline. Start ferxium-service as your normal user.".to_string()
    })?;
    let client = reqwest::Client::builder()
        .no_proxy()
        .redirect(reqwest::redirect::Policy::none())
        .timeout(std::time::Duration::from_secs(40))
        .build()
        .map_err(|e| e.to_string())?;
    let endpoint = if action.is_some() { "action" } else { "status" };
    let mut request = client
        .request(
            method,
            format!("http://127.0.0.1:{}/v1/{endpoint}", discovery.port),
        )
        .bearer_auth(discovery.token);
    if let Some(action) = action {
        request = request.json(&action);
    }
    let response = request
        .send()
        .await
        .map_err(|_| "Cannot reach the local protection service.".to_string())?;
    if !response.status().is_success() {
        return Err(response
            .text()
            .await
            .unwrap_or_else(|_| "Service request failed".into()));
    }
    Ok(response)
}

#[tauri::command]
pub fn service_status(agent: tauri::State<'_, DesktopAgent>) -> Result<ServiceStatus, String> {
    agent.snapshot()
}

pub async fn send_action(data: &std::path::Path, action: Action) -> Result<(), String> {
    request(reqwest::Method::POST, Some(action), data).await?;
    Ok(())
}

#[tauri::command]
pub async fn service_action(
    agent: tauri::State<'_, DesktopAgent>,
    action: Action,
) -> Result<(), String> {
    send_action(&agent.data, action).await?;
    agent.refresh().await
}
