use crate::state::SharedState;
use axum::{extract::State, http::StatusCode, response::IntoResponse, Json};
use serde_json::json;

pub async fn liveness() -> StatusCode { StatusCode::OK }

pub async fn readiness(State(state): State<SharedState>) -> Result<impl IntoResponse, crate::error::AppError> {
    state.db.ping().await.map_err(anyhow::Error::from)?;
    state.revocation.ping().await.map_err(anyhow::Error::from)?;
    let revocation_mode = if state.revocation.is_memory() { "memory" } else { "redis" };
    Ok(Json(json!({
        "status": "ready",
        "database": state.config.database.backend,
        "revocation": revocation_mode,
    })))
}

pub async fn metrics(State(state): State<SharedState>) -> impl IntoResponse {
    state.prometheus.render()
}
