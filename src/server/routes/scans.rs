use crate::server::app::AppState;
use crate::server::models::ScanView;
use axum::extract::State;
use axum::http::StatusCode;
use axum::routing::{get, post};
use axum::{Json, Router};

pub fn routes() -> Router<AppState> {
    Router::new()
        .route("/scans", post(start_scan).get(list_scans))
        .route("/scans/active", get(active_scan))
        .route("/scans/{id}", get(get_scan))
}

async fn start_scan(
    State(state): State<AppState>,
) -> Result<(StatusCode, Json<serde_json::Value>), (StatusCode, Json<serde_json::Value>)> {
    let scan_root = state.scan_root.clone();

    let config = state.config.read().unwrap().clone();
    let event_tx = state.event_tx.clone();

    match state.job_manager.start_scan(scan_root, config, event_tx) {
        Ok(job_id) => Ok((
            StatusCode::ACCEPTED,
            Json(serde_json::json!({ "job_id": job_id })),
        )),
        Err(msg) => Err((
            StatusCode::CONFLICT,
            Json(serde_json::json!({ "error": msg })),
        )),
    }
}

async fn list_scans(State(state): State<AppState>) -> Json<Vec<ScanView>> {
    let jobs = state.job_manager.list_jobs();
    Json(jobs.iter().map(job_to_view).collect())
}

async fn active_scan(
    State(state): State<AppState>,
) -> Result<Json<ScanView>, StatusCode> {
    let job = state.job_manager.active_job().ok_or(StatusCode::NOT_FOUND)?;
    Ok(Json(job_to_view(&job)))
}

async fn get_scan(
    State(state): State<AppState>,
    axum::extract::Path(id): axum::extract::Path<String>,
) -> Result<Json<ScanView>, StatusCode> {
    let job = state.job_manager.get_job(&id).ok_or(StatusCode::NOT_FOUND)?;
    Ok(Json(job_to_view(&job)))
}

fn job_to_view(job: &crate::server::jobs::ScanJob) -> ScanView {
    ScanView {
        id: job.id.clone(),
        status: format!("{:?}", job.status).to_ascii_lowercase(),
        scan_root: job.scan_root.display().to_string(),
        started_at: job.started_at.map(|t| t.to_rfc3339()),
        finished_at: job.finished_at.map(|t| t.to_rfc3339()),
        duration_secs: job.duration_secs,
        finding_count: job.findings.as_ref().map(|f| f.len()),
        error: job.error.clone(),
    }
}
