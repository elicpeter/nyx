use crate::server::app::AppState;
use axum::extract::{Query, State};
use axum::http::StatusCode;
use axum::routing::get;
use axum::{Json, Router};
use serde::{Deserialize, Serialize};
use std::fs;

pub fn routes() -> Router<AppState> {
    Router::new().route("/files", get(get_file))
}

#[derive(Debug, Deserialize)]
struct FileQuery {
    path: String,
    start_line: Option<usize>,
    end_line: Option<usize>,
}

#[derive(Debug, Serialize)]
struct FileLine {
    number: usize,
    content: String,
}

#[derive(Debug, Serialize)]
struct FileResponse {
    path: String,
    lines: Vec<FileLine>,
    total_lines: usize,
}

async fn get_file(
    State(state): State<AppState>,
    Query(query): Query<FileQuery>,
) -> Result<Json<FileResponse>, StatusCode> {
    // Belt-and-suspenders: reject paths with ".." segments
    if query.path.contains("..") {
        return Err(StatusCode::FORBIDDEN);
    }

    // Canonicalize and validate the path is within scan_root
    let scan_root = fs::canonicalize(&state.scan_root).map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    let requested = scan_root.join(&query.path);
    let canonical = fs::canonicalize(&requested).map_err(|_| StatusCode::NOT_FOUND)?;

    if !canonical.starts_with(&scan_root) {
        return Err(StatusCode::FORBIDDEN);
    }

    // Max file size guard (5MB)
    let metadata = fs::metadata(&canonical).map_err(|_| StatusCode::NOT_FOUND)?;
    if metadata.len() > 5 * 1024 * 1024 {
        return Err(StatusCode::BAD_REQUEST);
    }

    // Read file (binary files will fail here)
    let content = fs::read_to_string(&canonical).map_err(|_| StatusCode::BAD_REQUEST)?;
    let all_lines: Vec<&str> = content.lines().collect();
    let total_lines = all_lines.len();

    // Apply line range (1-indexed)
    let start = query.start_line.unwrap_or(1).max(1);
    let end = query.end_line.unwrap_or(total_lines).min(total_lines);

    let lines: Vec<FileLine> = if start <= end && start <= total_lines {
        all_lines[start - 1..end]
            .iter()
            .enumerate()
            .map(|(i, l)| FileLine {
                number: start + i,
                content: (*l).to_string(),
            })
            .collect()
    } else {
        vec![]
    };

    Ok(Json(FileResponse {
        path: query.path,
        lines,
        total_lines,
    }))
}
