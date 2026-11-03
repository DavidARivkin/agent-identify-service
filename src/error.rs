use axum::{http::StatusCode, response::{IntoResponse, Response}, Json};
use serde_json::json;

#[derive(Debug, thiserror::Error)]
pub enum AppError {
    #[error("bad request: {0}")] BadRequest(String),
    #[error("unauthorized: {0}")] Unauthorized(String),
    #[error("forbidden: {0}")] Forbidden(String),
    #[error("not found: {0}")] NotFound(String),
    #[error("conflict: {0}")] Conflict(String),
    #[error("too many requests")] TooManyRequests,
    #[error("internal error")] Internal(#[from] anyhow::Error),
    #[error("database error: {0}")] Database(String),
}

impl IntoResponse for AppError {
    fn into_response(self) -> Response {
        let (status, code, message) = match &self {
            AppError::BadRequest(m) => (StatusCode::BAD_REQUEST, "bad_request", m.clone()),
            AppError::Unauthorized(m) => (StatusCode::UNAUTHORIZED, "unauthorized", m.clone()),
            AppError::Forbidden(m) => (StatusCode::FORBIDDEN, "forbidden", m.clone()),
            AppError::NotFound(m) => (StatusCode::NOT_FOUND, "not_found", m.clone()),
            AppError::Conflict(m) => (StatusCode::CONFLICT, "conflict", m.clone()),
            AppError::TooManyRequests => (StatusCode::TOO_MANY_REQUESTS, "too_many_requests", "rate limit exceeded".into()),
            AppError::Database(e) => { tracing::error!(error=%e, "database error"); (StatusCode::INTERNAL_SERVER_ERROR, "internal_error", "internal server error".into()) }
            AppError::Internal(e) => { tracing::error!(error=?e, "internal error"); (StatusCode::INTERNAL_SERVER_ERROR, "internal_error", "internal server error".into()) }
        };
        (status, Json(json!({"error":{"code":code,"message":message}}))).into_response()
    }
}

pub type AppResult<T> = Result<T, AppError>;
