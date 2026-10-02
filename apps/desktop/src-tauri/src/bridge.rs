//! The bearer token stays in Rust; it is never returned to the webview.
use ferxium_core::{Action, Discovery, ServiceStatus, storage};

async fn request(
    method: reqwest::Method,
    action: Option<Action>,
) -> Result<reqwest::Response, String> {
    let discovery: Discovery = storage::read_json(
        &storage::data_dir()
            .map_err(|e| e.to_string())?
            .join("service.json"),
    )
    .map_err(|_| {
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
pub async fn service_status() -> Result<ServiceStatus, String> {
    request(reqwest::Method::GET, None)
        .await?
        .json()
        .await
        .map_err(|e| e.to_string())
}

pub async fn send_action(action: Action) -> Result<(), String> {
    request(reqwest::Method::POST, Some(action)).await?;
    Ok(())
}

#[tauri::command]
pub async fn service_action(action: Action) -> Result<(), String> {
    send_action(action).await
}
