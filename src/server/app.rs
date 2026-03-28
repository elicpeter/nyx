use crate::server::jobs::JobManager;
use crate::server::progress::TimingBreakdown;
use crate::server::routes;
use crate::server::security::LocalServerSecurity;
use crate::utils::config::Config;
use axum::Router;
use r2d2::Pool;
use r2d2_sqlite::SqliteConnectionManager;
use std::path::PathBuf;
use std::sync::{Arc, RwLock};
use tokio::sync::broadcast;

/// Events broadcast over SSE to connected clients.
#[derive(Debug, Clone, serde::Serialize)]
#[serde(tag = "type", content = "data")]
pub enum ServerEvent {
    ScanStarted {
        job_id: String,
    },
    ScanCompleted {
        job_id: String,
    },
    ScanFailed {
        job_id: String,
        error: String,
    },
    ScanProgress {
        job_id: String,
        stage: String,
        files_discovered: u64,
        files_parsed: u64,
        files_analyzed: u64,
        files_skipped: u64,
        batches_total: u64,
        batches_completed: u64,
        current_file: String,
        elapsed_ms: u64,
        timing: TimingBreakdown,
    },
    ConfigChanged,
}

/// Shared application state accessible to all route handlers.
#[derive(Clone)]
pub struct AppState {
    pub scan_root: PathBuf,
    pub config_dir: PathBuf,
    pub database_dir: PathBuf,
    pub security: Arc<LocalServerSecurity>,
    pub config: Arc<RwLock<Config>>,
    pub job_manager: Arc<JobManager>,
    pub event_tx: broadcast::Sender<ServerEvent>,
    pub db_pool: Option<Arc<Pool<SqliteConnectionManager>>>,
}

/// Build the main axum router with all API routes and static asset fallback.
pub fn build_router(state: AppState) -> Router {
    use axum::middleware;
    use tower_http::compression::CompressionLayer;

    let security = Arc::clone(&state.security);
    Router::new()
        .nest("/api", routes::api_routes())
        .fallback(crate::server::assets::static_handler)
        .layer(middleware::from_fn_with_state(
            security,
            crate::server::security::guard_requests,
        ))
        .layer(CompressionLayer::new())
        .with_state(state)
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::body::{Body, to_bytes};
    use axum::http::{Request, StatusCode};
    #[cfg(unix)]
    use std::os::unix::fs::symlink;
    use tower::util::ServiceExt;

    fn test_state(scan_root: PathBuf, port: u16) -> AppState {
        let (event_tx, _) = broadcast::channel(8);
        AppState {
            scan_root: scan_root.clone(),
            config_dir: scan_root.clone(),
            database_dir: scan_root.clone(),
            security: LocalServerSecurity::new(port),
            config: Arc::new(RwLock::new(Config::default())),
            job_manager: Arc::new(JobManager::new(4, 8 * 1024 * 1024)),
            event_tx,
            db_pool: None,
        }
    }

    async fn session_token(state: &AppState) -> String {
        let response = build_router(state.clone())
            .oneshot(
                Request::builder()
                    .uri("/api/session")
                    .header("host", "localhost:9700")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let body = to_bytes(response.into_body(), 64 * 1024).await.unwrap();
        let payload: serde_json::Value = serde_json::from_slice(&body).unwrap();
        payload["csrf_token"].as_str().unwrap().to_string()
    }

    #[tokio::test]
    async fn rejects_bad_host_headers() {
        let dir = tempfile::tempdir().unwrap();
        let app = build_router(test_state(dir.path().to_path_buf(), 9700));

        let response = app
            .oneshot(
                Request::builder()
                    .uri("/api/health")
                    .header("host", "evil.example:9700")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn blocks_mutations_without_csrf_token() {
        let dir = tempfile::tempdir().unwrap();
        let app = build_router(test_state(dir.path().to_path_buf(), 9700));

        let response = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/api/scans")
                    .header("host", "localhost:9700")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::FORBIDDEN);
    }

    #[tokio::test]
    async fn blocks_cross_origin_mutations_even_with_csrf_token() {
        let dir = tempfile::tempdir().unwrap();
        let state = test_state(dir.path().to_path_buf(), 9700);
        let token = session_token(&state).await;
        let app = build_router(state);

        let response = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/api/scans")
                    .header("host", "localhost:9700")
                    .header("origin", "http://evil.example:9700")
                    .header("x-nyx-csrf", token)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::FORBIDDEN);
    }

    #[tokio::test]
    async fn rejects_traversal_in_file_route() {
        let dir = tempfile::tempdir().unwrap();
        let app = build_router(test_state(dir.path().to_path_buf(), 9700));

        let response = app
            .oneshot(
                Request::builder()
                    .uri("/api/files?path=..%2Fsecret.txt")
                    .header("host", "localhost:9700")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::FORBIDDEN);
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn explorer_tree_skips_symlink_escapes() {
        let dir = tempfile::tempdir().unwrap();
        let outside = tempfile::tempdir().unwrap();
        let outside_file = outside.path().join("secret.rs");
        std::fs::write(&outside_file, "fn leaked() {}").unwrap();
        symlink(&outside_file, dir.path().join("escape.rs")).unwrap();

        let response = build_router(test_state(dir.path().to_path_buf(), 9700))
            .oneshot(
                Request::builder()
                    .uri("/api/explorer/tree")
                    .header("host", "localhost:9700")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);
        let body = to_bytes(response.into_body(), 64 * 1024).await.unwrap();
        let payload: serde_json::Value = serde_json::from_slice(&body).unwrap();
        let entries = payload.as_array().unwrap();
        assert!(entries.iter().all(|entry| entry["name"] != "escape.rs"));
    }
}
