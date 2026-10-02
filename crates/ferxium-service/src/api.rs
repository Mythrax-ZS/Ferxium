use crate::runtime::App;
use axum::{
    Json, Router,
    extract::{DefaultBodyLimit, State},
    http::{HeaderMap, StatusCode},
    middleware::{self, Next},
    response::{IntoResponse, Response},
    routing::{get, post},
};
use ferxium_core::{Action, ServiceStatus};
use std::sync::Arc;
use subtle::ConstantTimeEq;

#[derive(Clone)]
struct ApiState {
    app: Arc<App>,
    token: Arc<String>,
}

pub fn router(app: Arc<App>, token: String) -> Router {
    let state = ApiState {
        app,
        token: Arc::new(token),
    };
    Router::new()
        .route("/v1/status", get(status))
        .route("/v1/action", post(action))
        .layer(DefaultBodyLimit::max(64 * 1024))
        .layer(middleware::from_fn_with_state(state.clone(), authenticate))
        .with_state(state)
}

async fn authenticate(
    State(state): State<ApiState>,
    headers: HeaderMap,
    request: axum::extract::Request,
    next: Next,
) -> Response {
    // Browsers do not get CORS access. Reject Origin outright; only the Rust
    // bridge and CLI may authenticate. No query-string or cookie authentication.
    if headers.contains_key("origin") {
        return (StatusCode::FORBIDDEN, "Browser access denied").into_response();
    }
    let Some(token) = headers
        .get("authorization")
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Bearer "))
    else {
        return (StatusCode::UNAUTHORIZED, "Authentication required").into_response();
    };
    if !bool::from(token.as_bytes().ct_eq(state.token.as_bytes())) {
        return (StatusCode::UNAUTHORIZED, "Invalid authentication").into_response();
    }
    next.run(request).await
}

async fn status(
    State(state): State<ApiState>,
) -> Result<Json<ServiceStatus>, (StatusCode, String)> {
    tokio::task::spawn_blocking(move || state.app.snapshot())
        .await
        .map_err(internal)?
        .map(Json)
        .map_err(internal)
}

async fn action(
    State(state): State<ApiState>,
    Json(action): Json<Action>,
) -> Result<Json<serde_json::Value>, (StatusCode, String)> {
    let app = state.app;
    let _guard = app.actions.lock().await;
    app.apply(action)
        .await
        .map_err(|e| (StatusCode::BAD_REQUEST, e.to_string()))?;
    Ok(Json(serde_json::json!({ "ok": true })))
}

fn internal(error: impl std::fmt::Display) -> (StatusCode, String) {
    (StatusCode::INTERNAL_SERVER_ERROR, error.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::{body::Body, http::Request};
    use tower::ServiceExt;

    #[tokio::test]
    async fn all_routes_require_authentication_and_reject_browser_origins() {
        let dir = tempfile::tempdir().unwrap();
        let app = Arc::new(App::load(dir.path().to_path_buf()).unwrap());
        let router = router(app, "test-token".into());
        for route in ["/v1/status", "/v1/action"] {
            let response = router
                .clone()
                .oneshot(Request::builder().uri(route).body(Body::empty()).unwrap())
                .await
                .unwrap();
            assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
        }
        let wrong = Request::builder()
            .uri("/v1/status")
            .header("authorization", "Bearer wrong")
            .body(Body::empty())
            .unwrap();
        assert_eq!(
            router.clone().oneshot(wrong).await.unwrap().status(),
            StatusCode::UNAUTHORIZED
        );
        let browser = Request::builder()
            .uri("/v1/status")
            .header("authorization", "Bearer test-token")
            .header("origin", "https://untrusted.example")
            .body(Body::empty())
            .unwrap();
        assert_eq!(
            router.clone().oneshot(browser).await.unwrap().status(),
            StatusCode::FORBIDDEN
        );
        let valid = Request::builder()
            .uri("/v1/status")
            .header("authorization", "Bearer test-token")
            .body(Body::empty())
            .unwrap();
        assert_eq!(
            router.oneshot(valid).await.unwrap().status(),
            StatusCode::OK
        );
    }

    #[tokio::test]
    async fn action_size_limit_and_config_validation_are_enforced() {
        let dir = tempfile::tempdir().unwrap();
        let app = Arc::new(App::load(dir.path().to_path_buf()).unwrap());
        let router = router(app, "test-token".into());
        let oversized = Request::builder()
            .method("POST")
            .uri("/v1/action")
            .header("authorization", "Bearer test-token")
            .header("content-type", "application/json")
            .body(Body::from(vec![b' '; 65 * 1024]))
            .unwrap();
        assert_eq!(
            router.clone().oneshot(oversized).await.unwrap().status(),
            StatusCode::PAYLOAD_TOO_LARGE
        );
        let invalid = Request::builder()
            .method("POST")
            .uri("/v1/action")
            .header("authorization", "Bearer test-token")
            .header("content-type", "application/json")
            .body(Body::from(
                r#"{"action":"start_scan","request":{"kind":"custom","paths":[]}}"#,
            ))
            .unwrap();
        assert_eq!(
            router.oneshot(invalid).await.unwrap().status(),
            StatusCode::BAD_REQUEST
        );
    }
}
