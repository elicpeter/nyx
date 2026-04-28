//! Unified error type for HTTP route handlers.
//!
//! All routes should return [`ApiResult<T>`] (an alias for `Result<T, ApiError>`).
//! `ApiError` serializes as `{ "error": "<human msg>", "code": "<machine code>",
//! "detail"?: ... }` and carries the HTTP status code through `IntoResponse`.

use axum::Json;
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use serde::Serialize;
use serde_json::Value;

/// Machine-readable error codes. Stable strings the frontend can branch on.
#[derive(Debug, Clone, Copy)]
pub enum ApiCode {
    BadRequest,
    Forbidden,
    NotFound,
    Conflict,
    PayloadTooLarge,
    Unprocessable,
    Internal,
    ServiceUnavailable,
}

impl ApiCode {
    fn as_str(self) -> &'static str {
        match self {
            ApiCode::BadRequest => "bad_request",
            ApiCode::Forbidden => "forbidden",
            ApiCode::NotFound => "not_found",
            ApiCode::Conflict => "conflict",
            ApiCode::PayloadTooLarge => "payload_too_large",
            ApiCode::Unprocessable => "unprocessable",
            ApiCode::Internal => "internal",
            ApiCode::ServiceUnavailable => "service_unavailable",
        }
    }

    fn status(self) -> StatusCode {
        match self {
            ApiCode::BadRequest => StatusCode::BAD_REQUEST,
            ApiCode::Forbidden => StatusCode::FORBIDDEN,
            ApiCode::NotFound => StatusCode::NOT_FOUND,
            ApiCode::Conflict => StatusCode::CONFLICT,
            ApiCode::PayloadTooLarge => StatusCode::PAYLOAD_TOO_LARGE,
            ApiCode::Unprocessable => StatusCode::UNPROCESSABLE_ENTITY,
            ApiCode::Internal => StatusCode::INTERNAL_SERVER_ERROR,
            ApiCode::ServiceUnavailable => StatusCode::SERVICE_UNAVAILABLE,
        }
    }
}

#[derive(Debug)]
pub struct ApiError {
    code: ApiCode,
    message: String,
    detail: Option<Value>,
}

impl ApiError {
    pub fn new(code: ApiCode, message: impl Into<String>) -> Self {
        Self {
            code,
            message: message.into(),
            detail: None,
        }
    }

    pub fn with_detail(mut self, detail: Value) -> Self {
        self.detail = Some(detail);
        self
    }

    pub fn bad_request(msg: impl Into<String>) -> Self {
        Self::new(ApiCode::BadRequest, msg)
    }
    pub fn forbidden(msg: impl Into<String>) -> Self {
        Self::new(ApiCode::Forbidden, msg)
    }
    pub fn not_found(msg: impl Into<String>) -> Self {
        Self::new(ApiCode::NotFound, msg)
    }
    pub fn conflict(msg: impl Into<String>) -> Self {
        Self::new(ApiCode::Conflict, msg)
    }
    pub fn unprocessable(msg: impl Into<String>) -> Self {
        Self::new(ApiCode::Unprocessable, msg)
    }
    pub fn internal(msg: impl Into<String>) -> Self {
        Self::new(ApiCode::Internal, msg)
    }
    pub fn service_unavailable(msg: impl Into<String>) -> Self {
        Self::new(ApiCode::ServiceUnavailable, msg)
    }
}

#[derive(Serialize)]
struct ApiErrorBody<'a> {
    error: &'a str,
    code: &'a str,
    #[serde(skip_serializing_if = "Option::is_none")]
    detail: Option<&'a Value>,
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        let body = ApiErrorBody {
            error: &self.message,
            code: self.code.as_str(),
            detail: self.detail.as_ref(),
        };
        (self.code.status(), Json(serde_json::to_value(&body).unwrap())).into_response()
    }
}

impl From<StatusCode> for ApiError {
    fn from(status: StatusCode) -> Self {
        let code = match status {
            StatusCode::BAD_REQUEST => ApiCode::BadRequest,
            StatusCode::FORBIDDEN => ApiCode::Forbidden,
            StatusCode::NOT_FOUND => ApiCode::NotFound,
            StatusCode::CONFLICT => ApiCode::Conflict,
            StatusCode::PAYLOAD_TOO_LARGE => ApiCode::PayloadTooLarge,
            StatusCode::UNPROCESSABLE_ENTITY => ApiCode::Unprocessable,
            StatusCode::SERVICE_UNAVAILABLE => ApiCode::ServiceUnavailable,
            _ => ApiCode::Internal,
        };
        Self::new(
            code,
            status.canonical_reason().unwrap_or("error").to_string(),
        )
    }
}

impl From<std::io::Error> for ApiError {
    fn from(err: std::io::Error) -> Self {
        Self::internal(err.to_string())
    }
}

impl From<serde_json::Error> for ApiError {
    fn from(err: serde_json::Error) -> Self {
        Self::bad_request(format!("invalid JSON: {err}"))
    }
}

pub type ApiResult<T> = Result<T, ApiError>;

#[cfg(test)]
mod tests {
    use super::*;
    use axum::body::to_bytes;

    #[tokio::test]
    async fn serializes_with_error_code_detail() {
        let err = ApiError::not_found("scan not found").with_detail(serde_json::json!({"id":"x"}));
        let resp = err.into_response();
        assert_eq!(resp.status(), StatusCode::NOT_FOUND);
        let body = to_bytes(resp.into_body(), 8 * 1024).await.unwrap();
        let v: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(v["error"], "scan not found");
        assert_eq!(v["code"], "not_found");
        assert_eq!(v["detail"]["id"], "x");
    }

    #[test]
    fn omits_detail_when_absent() {
        let err = ApiError::bad_request("bad input");
        let body = ApiErrorBody {
            error: &err.message,
            code: err.code.as_str(),
            detail: err.detail.as_ref(),
        };
        let s = serde_json::to_string(&body).unwrap();
        assert!(!s.contains("detail"), "expected no detail key, got {s}");
    }
}
