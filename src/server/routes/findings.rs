use crate::server::app::AppState;
use crate::server::models::{
    collect_filter_values, finding_from_diag, finding_from_diag_with_detail, summarize_findings,
    FilterValues, FindingSummary, FindingView,
};
use axum::extract::{Path, Query, State};
use axum::http::StatusCode;
use axum::routing::get;
use axum::{Json, Router};
use serde::Deserialize;

pub fn routes() -> Router<AppState> {
    Router::new()
        .route("/findings", get(list_findings))
        .route("/findings/summary", get(findings_summary))
        .route("/findings/filters", get(findings_filters))
        .route("/findings/{index}", get(get_finding))
}

#[derive(Debug, Deserialize, Default)]
struct FindingsQuery {
    severity: Option<String>,
    category: Option<String>,
    rule_id: Option<String>,
    path: Option<String>,
    search: Option<String>,
    language: Option<String>,
    confidence: Option<String>,
    status: Option<String>,
    sort_by: Option<String>,
    sort_dir: Option<String>,
    page: Option<usize>,
    per_page: Option<usize>,
}

async fn list_findings(
    State(state): State<AppState>,
    Query(query): Query<FindingsQuery>,
) -> Result<Json<serde_json::Value>, StatusCode> {
    let job = state
        .job_manager
        .get_latest_completed()
        .ok_or(StatusCode::NOT_FOUND)?;

    let findings = job.findings.as_deref().unwrap_or(&[]);

    let mut views: Vec<FindingView> = findings
        .iter()
        .enumerate()
        .map(|(i, d)| finding_from_diag(i, d))
        .collect();

    // Apply filters.
    if let Some(ref sev) = query.severity {
        let sev_upper = sev.to_ascii_uppercase();
        views.retain(|f| f.severity.as_db_str() == sev_upper);
    }
    if let Some(ref cat) = query.category {
        let cat_lower = cat.to_ascii_lowercase();
        views.retain(|f| f.category.to_string().to_ascii_lowercase() == cat_lower);
    }
    if let Some(ref rule) = query.rule_id {
        views.retain(|f| f.rule_id == *rule);
    }
    if let Some(ref path_prefix) = query.path {
        views.retain(|f| f.path.starts_with(path_prefix.as_str()));
    }
    if let Some(ref lang) = query.language {
        let lang_lower = lang.to_ascii_lowercase();
        views.retain(|f| {
            f.language
                .as_ref()
                .is_some_and(|l| l.to_ascii_lowercase() == lang_lower)
        });
    }
    if let Some(ref conf) = query.confidence {
        let conf_lower = conf.to_ascii_lowercase();
        views.retain(|f| {
            f.confidence
                .as_ref()
                .is_some_and(|c| format!("{c:?}").to_ascii_lowercase() == conf_lower)
        });
    }
    if let Some(ref status) = query.status {
        let status_lower = status.to_ascii_lowercase();
        views.retain(|f| f.status.to_ascii_lowercase() == status_lower);
    }
    if let Some(ref search) = query.search {
        let needle = search.to_ascii_lowercase();
        views.retain(|f| {
            f.path.to_ascii_lowercase().contains(&needle)
                || f.rule_id.to_ascii_lowercase().contains(&needle)
                || f.message
                    .as_ref()
                    .is_some_and(|m| m.to_ascii_lowercase().contains(&needle))
        });
    }

    // Sort.
    match query.sort_by.as_deref() {
        Some("severity") => views.sort_by(|a, b| a.severity.cmp(&b.severity)),
        Some("path") | Some("file") => views.sort_by(|a, b| a.path.cmp(&b.path)),
        Some("rule_id") => views.sort_by(|a, b| a.rule_id.cmp(&b.rule_id)),
        Some("score") => views.sort_by(|a, b| {
            b.rank_score
                .unwrap_or(0.0)
                .partial_cmp(&a.rank_score.unwrap_or(0.0))
                .unwrap_or(std::cmp::Ordering::Equal)
        }),
        Some("confidence") => views.sort_by(|a, b| {
            let ca = a.confidence.map(|c| c as u8).unwrap_or(0);
            let cb = b.confidence.map(|c| c as u8).unwrap_or(0);
            ca.cmp(&cb)
        }),
        Some("line") => views.sort_by(|a, b| a.line.cmp(&b.line)),
        Some("language") => views.sort_by(|a, b| {
            a.language
                .as_deref()
                .unwrap_or("")
                .cmp(b.language.as_deref().unwrap_or(""))
        }),
        Some("status") => views.sort_by(|a, b| a.status.cmp(&b.status)),
        Some("category") => {
            views.sort_by(|a, b| a.category.to_string().cmp(&b.category.to_string()))
        }
        _ => {} // default order (by index)
    }
    if query.sort_dir.as_deref() == Some("desc") {
        views.reverse();
    }

    // Paginate.
    let total = views.len();
    let page = query.page.unwrap_or(1).max(1);
    let per_page = query.per_page.unwrap_or(50).clamp(1, 500);
    let start = (page - 1) * per_page;
    let page_views: Vec<_> = views.into_iter().skip(start).take(per_page).collect();

    Ok(Json(serde_json::json!({
        "findings": page_views,
        "total": total,
        "page": page,
        "per_page": per_page,
    })))
}

async fn findings_summary(
    State(state): State<AppState>,
) -> Result<Json<FindingSummary>, StatusCode> {
    let job = state
        .job_manager
        .get_latest_completed()
        .ok_or(StatusCode::NOT_FOUND)?;
    let findings = job.findings.as_deref().unwrap_or(&[]);
    Ok(Json(summarize_findings(findings)))
}

async fn findings_filters(
    State(state): State<AppState>,
) -> Result<Json<FilterValues>, StatusCode> {
    let job = state
        .job_manager
        .get_latest_completed()
        .ok_or(StatusCode::NOT_FOUND)?;
    let findings = job.findings.as_deref().unwrap_or(&[]);
    Ok(Json(collect_filter_values(findings)))
}

async fn get_finding(
    State(state): State<AppState>,
    Path(index): Path<usize>,
) -> Result<Json<FindingView>, StatusCode> {
    let job = state
        .job_manager
        .get_latest_completed()
        .ok_or(StatusCode::NOT_FOUND)?;
    let findings = job.findings.as_deref().unwrap_or(&[]);
    let diag = findings.get(index).ok_or(StatusCode::NOT_FOUND)?;
    Ok(Json(finding_from_diag_with_detail(
        index,
        diag,
        &state.scan_root,
        findings,
    )))
}
