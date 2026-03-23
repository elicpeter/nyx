use crate::commands::scan::Diag;
use crate::database::index::{Indexer, ScanRecord};
use crate::server::app::AppState;
use crate::server::models::{
    self, FindingView, ScanView,
};
use crate::server::scan_log::ScanLogEntry;
use crate::server::progress::ScanMetricsSnapshot;
use axum::extract::{Query, State};
use axum::http::StatusCode;
use axum::routing::{get, post};
use axum::{Json, Router};
use std::collections::HashSet;

pub fn routes() -> Router<AppState> {
    Router::new()
        .route("/scans", post(start_scan).get(list_scans))
        .route("/scans/active", get(active_scan))
        .route("/scans/{id}", get(get_scan))
        .route("/scans/{id}/findings", get(get_scan_findings))
        .route("/scans/{id}/logs", get(get_scan_logs))
        .route("/scans/{id}/metrics", get(get_scan_metrics))
}

#[derive(serde::Deserialize, Default)]
struct StartScanRequest {
    scan_root: Option<String>,
    #[allow(dead_code)]
    languages: Option<Vec<String>>,
    #[allow(dead_code)]
    include_paths: Option<Vec<String>>,
    #[allow(dead_code)]
    exclude_paths: Option<Vec<String>>,
}

async fn start_scan(
    State(state): State<AppState>,
    body: Option<Json<StartScanRequest>>,
) -> Result<(StatusCode, Json<serde_json::Value>), (StatusCode, Json<serde_json::Value>)> {
    let req = body.map(|b| b.0).unwrap_or_default();

    let scan_root = if let Some(ref root) = req.scan_root {
        std::path::PathBuf::from(root)
    } else {
        state.scan_root.clone()
    };

    let config = state.config.read().unwrap().clone();
    let event_tx = state.event_tx.clone();
    let db_pool = state.db_pool.clone();

    match state.job_manager.start_scan(scan_root, config, event_tx, db_pool) {
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
    let mut views: Vec<ScanView> = state
        .job_manager
        .list_jobs()
        .iter()
        .map(|j| job_to_view(j))
        .collect();

    // Merge historical scans from DB (deduplicate by ID)
    if let Some(ref pool) = state.db_pool {
        if let Ok(idx) = Indexer::from_pool("_scans", pool) {
            if let Ok(records) = idx.list_scans(100) {
                let in_memory_ids: HashSet<String> =
                    views.iter().map(|v| v.id.clone()).collect();
                for record in records {
                    if !in_memory_ids.contains(&record.id) {
                        views.push(scan_record_to_view(&record));
                    }
                }
            }
        }
    }

    // Sort by started_at descending
    views.sort_by(|a, b| b.started_at.cmp(&a.started_at));

    Json(views)
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
    // Check in-memory first
    if let Some(job) = state.job_manager.get_job(&id) {
        return Ok(Json(job_to_view(&job)));
    }

    // Fall back to DB
    if let Some(ref pool) = state.db_pool {
        if let Ok(idx) = Indexer::from_pool("_scans", pool) {
            if let Ok(Some(record)) = idx.get_scan(&id) {
                let mut view = scan_record_to_view(&record);
                // Load metrics from DB
                if let Ok(Some(metrics)) = idx.get_scan_metrics(&id) {
                    view.metrics = Some(metrics);
                }
                return Ok(Json(view));
            }
        }
    }

    Err(StatusCode::NOT_FOUND)
}

#[derive(serde::Deserialize, Default)]
struct FindingsQuery {
    page: Option<usize>,
    per_page: Option<usize>,
    severity: Option<String>,
    category: Option<String>,
    search: Option<String>,
}

async fn get_scan_findings(
    State(state): State<AppState>,
    axum::extract::Path(id): axum::extract::Path<String>,
    Query(query): Query<FindingsQuery>,
) -> Result<Json<serde_json::Value>, StatusCode> {
    let findings: Vec<Diag> = if let Some(job) = state.job_manager.get_job(&id) {
        job.findings.unwrap_or_default()
    } else if let Some(ref pool) = state.db_pool {
        if let Ok(idx) = Indexer::from_pool("_scans", pool) {
            if let Ok(Some(record)) = idx.get_scan(&id) {
                record
                    .findings_json
                    .as_deref()
                    .and_then(|j| serde_json::from_str::<Vec<Diag>>(j).ok())
                    .unwrap_or_default()
            } else {
                return Err(StatusCode::NOT_FOUND);
            }
        } else {
            return Err(StatusCode::INTERNAL_SERVER_ERROR);
        }
    } else {
        return Err(StatusCode::NOT_FOUND);
    };

    // Apply filters
    let mut filtered: Vec<&Diag> = findings.iter().collect();
    if let Some(ref sev) = query.severity {
        filtered.retain(|d| d.severity.as_db_str().eq_ignore_ascii_case(sev));
    }
    if let Some(ref cat) = query.category {
        filtered.retain(|d| d.category.to_string().eq_ignore_ascii_case(cat));
    }
    if let Some(ref search) = query.search {
        let s = search.to_ascii_lowercase();
        filtered.retain(|d| {
            d.path.to_ascii_lowercase().contains(&s)
                || d.id.to_ascii_lowercase().contains(&s)
                || d.message
                    .as_deref()
                    .map(|m| m.to_ascii_lowercase().contains(&s))
                    .unwrap_or(false)
        });
    }

    let total = filtered.len();
    let page = query.page.unwrap_or(1).max(1);
    let per_page = query.per_page.unwrap_or(50).min(200);
    let start = (page - 1) * per_page;

    let scan_root = state.scan_root.clone();
    let page_findings: Vec<FindingView> = filtered
        .into_iter()
        .enumerate()
        .skip(start)
        .take(per_page)
        .map(|(i, d)| models::finding_from_diag_with_context(i, d, &scan_root))
        .collect();

    Ok(Json(serde_json::json!({
        "findings": page_findings,
        "total": total,
        "page": page,
        "per_page": per_page,
    })))
}

#[derive(serde::Deserialize, Default)]
struct LogsQuery {
    level: Option<String>,
}

async fn get_scan_logs(
    State(state): State<AppState>,
    axum::extract::Path(id): axum::extract::Path<String>,
    Query(query): Query<LogsQuery>,
) -> Result<Json<Vec<ScanLogEntry>>, StatusCode> {
    // Check in-memory (running scan)
    if let Some(job) = state.job_manager.get_job(&id) {
        if let Some(ref collector) = job.log_collector {
            let mut logs = collector.snapshot();
            if let Some(ref level) = query.level {
                logs.retain(|l| l.level.to_string().eq_ignore_ascii_case(level));
            }
            return Ok(Json(logs));
        }
    }

    // Fall back to DB
    if let Some(ref pool) = state.db_pool {
        if let Ok(idx) = Indexer::from_pool("_scans", pool) {
            if let Ok(logs) = idx.get_scan_logs(&id, query.level.as_deref()) {
                return Ok(Json(logs));
            }
        }
    }

    Ok(Json(vec![]))
}

async fn get_scan_metrics(
    State(state): State<AppState>,
    axum::extract::Path(id): axum::extract::Path<String>,
) -> Result<Json<ScanMetricsSnapshot>, StatusCode> {
    // Check in-memory (running scan)
    if let Some(job) = state.job_manager.get_job(&id) {
        if let Some(ref metrics) = job.metrics {
            return Ok(Json(metrics.snapshot()));
        }
    }

    // Fall back to DB
    if let Some(ref pool) = state.db_pool {
        if let Ok(idx) = Indexer::from_pool("_scans", pool) {
            if let Ok(Some(metrics)) = idx.get_scan_metrics(&id) {
                return Ok(Json(metrics));
            }
        }
    }

    Err(StatusCode::NOT_FOUND)
}

fn job_to_view(job: &crate::server::jobs::ScanJob) -> ScanView {
    let (timing, metrics_snap) = if let Some(ref progress) = job.progress {
        let snap = progress.snapshot();
        (Some(snap.timing), job.metrics.as_ref().map(|m| m.snapshot()))
    } else {
        (job.timing.clone(), None)
    };

    ScanView {
        id: job.id.clone(),
        status: format!("{:?}", job.status).to_ascii_lowercase(),
        scan_root: job.scan_root.display().to_string(),
        started_at: job.started_at.map(|t| t.to_rfc3339()),
        finished_at: job.finished_at.map(|t| t.to_rfc3339()),
        duration_secs: job.duration_secs,
        finding_count: job.findings.as_ref().map(|f| f.len()),
        error: job.error.clone(),
        engine_version: job.engine_version.clone(),
        languages: job.languages.clone(),
        files_scanned: job.files_scanned,
        timing,
        metrics: metrics_snap,
    }
}

fn scan_record_to_view(record: &ScanRecord) -> ScanView {
    let timing: Option<crate::server::progress::TimingBreakdown> = record
        .timing_json
        .as_deref()
        .and_then(|j| serde_json::from_str(j).ok());

    let languages: Option<Vec<String>> = record
        .languages
        .as_deref()
        .and_then(|j| serde_json::from_str(j).ok());

    ScanView {
        id: record.id.clone(),
        status: record.status.clone(),
        scan_root: record.scan_root.clone(),
        started_at: record.started_at.clone(),
        finished_at: record.finished_at.clone(),
        duration_secs: record.duration_secs,
        finding_count: record.finding_count.map(|c| c as usize),
        error: record.error.clone(),
        engine_version: record.engine_version.clone(),
        languages,
        files_scanned: record.files_scanned.map(|c| c as u64),
        timing,
        metrics: None,
    }
}
