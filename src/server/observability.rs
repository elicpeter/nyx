//! Per-request observability: request IDs + structured access logs.
//!
//! Layered above the security guard. Generates a short request id, attaches it
//! as the `X-Request-Id` response header, and emits one INFO record per request
//! with method, path, status, and duration.

use axum::extract::Request;
use axum::http::{HeaderName, HeaderValue};
use axum::middleware::Next;
use axum::response::Response;
use std::time::Instant;
use uuid::Uuid;

const REQUEST_ID_HEADER: HeaderName = HeaderName::from_static("x-request-id");

pub async fn observe(mut request: Request, next: Next) -> Response {
    let request_id = request
        .headers()
        .get(&REQUEST_ID_HEADER)
        .and_then(|v| v.to_str().ok())
        .map(|s| s.to_string())
        .unwrap_or_else(|| Uuid::new_v4().as_simple().to_string()[..12].to_string());

    if let Ok(value) = HeaderValue::from_str(&request_id) {
        request.headers_mut().insert(REQUEST_ID_HEADER, value);
    }

    let method = request.method().clone();
    let path = request
        .uri()
        .path_and_query()
        .map(|p| p.as_str().to_string())
        .unwrap_or_else(|| request.uri().path().to_string());

    let started = Instant::now();
    let mut response = next.run(request).await;
    let elapsed_ms = started.elapsed().as_secs_f64() * 1000.0;
    let status = response.status();

    if let Ok(value) = HeaderValue::from_str(&request_id) {
        response.headers_mut().insert(REQUEST_ID_HEADER, value);
    }

    // Skip noisy SSE channel, long-lived stream pollutes logs.
    if path != "/api/events" {
        if status.is_server_error() {
            tracing::error!(
                request_id = %request_id,
                method = %method,
                path = %path,
                status = status.as_u16(),
                elapsed_ms = format!("{elapsed_ms:.1}"),
                "request"
            );
        } else if status.is_client_error() {
            tracing::warn!(
                request_id = %request_id,
                method = %method,
                path = %path,
                status = status.as_u16(),
                elapsed_ms = format!("{elapsed_ms:.1}"),
                "request"
            );
        } else {
            tracing::info!(
                request_id = %request_id,
                method = %method,
                path = %path,
                status = status.as_u16(),
                elapsed_ms = format!("{elapsed_ms:.1}"),
                "request"
            );
        }
    }

    response
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::Router;
    use axum::body::Body;
    use axum::http::{Request as HttpRequest, StatusCode};
    use axum::middleware;
    use axum::routing::get;
    use tower::util::ServiceExt;

    #[tokio::test]
    async fn adds_request_id_header_when_absent() {
        let app: Router = Router::new()
            .route("/ping", get(|| async { "pong" }))
            .layer(middleware::from_fn(observe));

        let resp = app
            .oneshot(
                HttpRequest::builder()
                    .uri("/ping")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let id = resp
            .headers()
            .get("x-request-id")
            .unwrap()
            .to_str()
            .unwrap();
        assert!(!id.is_empty());
        assert_eq!(id.len(), 12);
    }

    #[tokio::test]
    async fn preserves_caller_supplied_request_id() {
        let app: Router = Router::new()
            .route("/ping", get(|| async { "pong" }))
            .layer(middleware::from_fn(observe));

        let resp = app
            .oneshot(
                HttpRequest::builder()
                    .uri("/ping")
                    .header("x-request-id", "abc-123")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(
            resp.headers()
                .get("x-request-id")
                .unwrap()
                .to_str()
                .unwrap(),
            "abc-123"
        );
    }
}
