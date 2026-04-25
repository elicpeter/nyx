use axum::extract::{Request, State};
use axum::http::header::{HOST, ORIGIN};
use axum::http::{Method, StatusCode};
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};
use std::sync::Arc;
use uuid::Uuid;

const CSRF_HEADER: &str = "x-nyx-csrf";

#[derive(Debug)]
pub struct LocalServerSecurity {
    port: u16,
    csrf_token: String,
}

impl LocalServerSecurity {
    pub fn new(port: u16) -> Arc<Self> {
        Arc::new(Self {
            port,
            csrf_token: Uuid::new_v4().as_simple().to_string(),
        })
    }

    pub fn csrf_token(&self) -> &str {
        &self.csrf_token
    }

    fn host_allowed(&self, authority: &str) -> bool {
        let Some((host, port)) = parse_host_like(authority) else {
            return false;
        };

        matches!(host.as_str(), "localhost" | "127.0.0.1" | "::1")
            && port.is_none_or(|value| value == self.port)
    }

    fn origin_allowed(&self, origin: &str) -> bool {
        let Some(rest) = origin.strip_prefix("http://") else {
            return false;
        };

        let authority = rest.split('/').next().unwrap_or(rest);
        self.host_allowed(authority)
    }
}

pub async fn guard_requests(
    State(security): State<Arc<LocalServerSecurity>>,
    request: Request,
    next: Next,
) -> Response {
    let Some(host) = request
        .headers()
        .get(HOST)
        .and_then(|value| value.to_str().ok())
    else {
        return (StatusCode::BAD_REQUEST, "missing Host header").into_response();
    };
    if !security.host_allowed(host) {
        return (StatusCode::BAD_REQUEST, "invalid Host header").into_response();
    }

    if is_mutating_method(request.method()) {
        if let Some(origin) = request
            .headers()
            .get(ORIGIN)
            .and_then(|value| value.to_str().ok())
            && !security.origin_allowed(origin)
        {
            return (StatusCode::FORBIDDEN, "cross-origin mutation blocked").into_response();
        }

        let Some(token) = request
            .headers()
            .get(CSRF_HEADER)
            .and_then(|value| value.to_str().ok())
        else {
            return (StatusCode::FORBIDDEN, "missing CSRF token").into_response();
        };

        if token != security.csrf_token() {
            return (StatusCode::FORBIDDEN, "invalid CSRF token").into_response();
        }
    }

    next.run(request).await
}

fn is_mutating_method(method: &Method) -> bool {
    matches!(
        *method,
        Method::POST | Method::PUT | Method::PATCH | Method::DELETE
    )
}

fn parse_host_like(value: &str) -> Option<(String, Option<u16>)> {
    if value.is_empty() {
        return None;
    }

    if let Some(rest) = value.strip_prefix('[') {
        let end = rest.find(']')?;
        let host = &rest[..end];
        let port = rest[end + 1..]
            .strip_prefix(':')
            .and_then(|p| p.parse().ok());
        return Some((host.to_ascii_lowercase(), port));
    }

    if value.matches(':').count() == 1 {
        let (host, port) = value.rsplit_once(':')?;
        return Some((host.to_ascii_lowercase(), port.parse().ok()));
    }

    Some((value.to_ascii_lowercase(), None))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn host_check_accepts_loopback_names() {
        let security = LocalServerSecurity::new(9700);
        assert!(security.host_allowed("localhost:9700"));
        assert!(security.host_allowed("127.0.0.1:9700"));
        assert!(security.host_allowed("[::1]:9700"));
    }

    #[test]
    fn host_check_rejects_non_loopback_names() {
        let security = LocalServerSecurity::new(9700);
        assert!(!security.host_allowed("evil.example:9700"));
        assert!(!security.host_allowed("192.168.1.10:9700"));
    }

    #[test]
    fn origin_check_requires_loopback_http_origin() {
        let security = LocalServerSecurity::new(9700);
        assert!(security.origin_allowed("http://localhost:9700"));
        assert!(!security.origin_allowed("https://localhost:9700"));
        assert!(!security.origin_allowed("http://evil.example:9700"));
    }
}
