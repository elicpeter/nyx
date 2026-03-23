use axum::extract::Request;
use axum::http::{header, StatusCode};
use axum::response::{Html, IntoResponse, Response};

static INDEX_HTML: &str = include_str!("assets/index.html");
static STYLE_CSS: &str = include_str!("assets/style.css");
static APP_JS: &str = include_str!("assets/app.js");
static FAVICON_SVG: &str = include_str!("assets/favicon.svg");

/// Serve embedded static files or fall back to the SPA shell.
pub async fn static_handler(req: Request) -> Response {
    let path = req.uri().path();

    match path {
        "/style.css" => (
            StatusCode::OK,
            [(header::CONTENT_TYPE, "text/css; charset=utf-8")],
            STYLE_CSS,
        )
            .into_response(),
        "/app.js" => (
            StatusCode::OK,
            [(header::CONTENT_TYPE, "application/javascript; charset=utf-8")],
            APP_JS,
        )
            .into_response(),
        "/favicon.svg" => (
            StatusCode::OK,
            [(header::CONTENT_TYPE, "image/svg+xml")],
            FAVICON_SVG,
        )
            .into_response(),
        // SPA fallback: any non-API path serves index.html.
        _ => Html(INDEX_HTML).into_response(),
    }
}
