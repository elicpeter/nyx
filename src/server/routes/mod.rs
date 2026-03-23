pub mod config;
pub mod events;
pub mod findings;
pub mod health;
pub mod scans;

use crate::server::app::AppState;
use axum::Router;

/// Build all API routes under /api.
pub fn api_routes() -> Router<AppState> {
    Router::new()
        .merge(health::routes())
        .merge(findings::routes())
        .merge(scans::routes())
        .merge(config::routes())
        .merge(events::routes())
}
