use crate::server::app::AppState;
use crate::utils::path::{DEFAULT_UI_MAX_FILE_BYTES, RepoPathError, open_repo_text_file};
use axum::extract::{Query, State};
use axum::http::StatusCode;
use axum::routing::get;
use axum::{Json, Router};
use serde::{Deserialize, Serialize};

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
    let opened = open_repo_text_file(&state.scan_root, &query.path, DEFAULT_UI_MAX_FILE_BYTES)
        .map_err(map_path_error)?;
    let content = opened.content;
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
        path: opened.resolved.relative,
        lines,
        total_lines,
    }))
}

fn map_path_error(err: RepoPathError) -> StatusCode {
    match err {
        RepoPathError::InvalidPath | RepoPathError::OutsideRoot => StatusCode::FORBIDDEN,
        RepoPathError::NotFound => StatusCode::NOT_FOUND,
        RepoPathError::TooLarge
        | RepoPathError::InvalidText
        | RepoPathError::NotFile
        | RepoPathError::NotDirectory => StatusCode::BAD_REQUEST,
        RepoPathError::Io => StatusCode::INTERNAL_SERVER_ERROR,
    }
}
