use crate::server::jobs::JobManager;
use crate::server::routes;
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
        current_file: String,
        elapsed_ms: u64,
    },
    ConfigChanged,
}

/// Shared application state accessible to all route handlers.
#[derive(Clone)]
pub struct AppState {
    pub scan_root: PathBuf,
    pub config_dir: PathBuf,
    pub database_dir: PathBuf,
    pub config: Arc<RwLock<Config>>,
    pub job_manager: Arc<JobManager>,
    pub event_tx: broadcast::Sender<ServerEvent>,
    pub db_pool: Option<Arc<Pool<SqliteConnectionManager>>>,
}

/// Build the main axum router with all API routes and static asset fallback.
pub fn build_router(state: AppState) -> Router {
    use tower_http::compression::CompressionLayer;

    Router::new()
        .nest("/api", routes::api_routes())
        .fallback(crate::server::assets::static_handler)
        .layer(CompressionLayer::new())
        .with_state(state)
}
