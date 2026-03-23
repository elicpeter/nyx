use crate::server::routes;
use crate::server::jobs::JobManager;
use crate::utils::config::Config;
use axum::Router;
use std::path::PathBuf;
use std::sync::{Arc, RwLock};
use tokio::sync::broadcast;

/// Events broadcast over SSE to connected clients.
#[derive(Debug, Clone, serde::Serialize)]
#[serde(tag = "type", content = "data")]
pub enum ServerEvent {
    ScanStarted { job_id: String },
    ScanCompleted { job_id: String },
    ScanFailed { job_id: String, error: String },
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
