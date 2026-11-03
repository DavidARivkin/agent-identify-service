use crate::audit;
use crate::auth::principal::Principal;
use crate::crypto::signer::SvidClaims;
use crate::db::agents;
use crate::error::{AppError, AppResult};
use crate::metrics;
use crate::state::SharedState;
use axum::{extract::State, Json};
use serde::{Deserialize, Serialize};
use time::{Duration, OffsetDateTime};
use uuid::Uuid;
use validator::Validate;

#[derive(Debug, Deserialize, Validate)]
pub struct IssueSvidRequest {
    pub agent_id: Uuid,
    #[validate(length(min=1,max=32))] pub requested_scopes: Vec<String>,
    #[validate(length(min=1,max=253))] pub audience: String,
    pub ttl_seconds: Option<i64>,
}

#[derive(Debug, Serialize)]
pub struct IssuedSvidResponse {
    pub access_token: String, pub token_type: String,
    pub expires_in: i64, pub spiffe_id: String,
}

pub async fn issue_svid(State(state): State<SharedState>, principal: Principal, Json(req): Json<IssueSvidRequest>) -> AppResult<Json<IssuedSvidResponse>> {
    principal.require_control_plane()?;
    req.validate().map_err(|e| AppError::BadRequest(e.to_string()))?;

    let agent = agents::get_agent(&state.db, req.agent_id).await?
        .ok_or_else(|| AppError::NotFound("agent not found".into()))?;

    if agent.status != "active" { return Err(AppError::Forbidden("agent revoked".into())); }

    for scope in &req.requested_scopes {
        if !agent.allowed_scopes.contains(scope) {
            return Err(AppError::Forbidden(format!("scope not authorized: {scope}")));
        }
    }

    let ttl = req.ttl_seconds.unwrap_or(state.config.crypto.default_svid_ttl_seconds);
    if ttl <= 0 || ttl > state.config.crypto.max_svid_ttl_seconds {
        return Err(AppError::BadRequest("invalid TTL".into()));
    }

    let now = OffsetDateTime::now_utc();
    let claims = SvidClaims {
        iss: state.signer.issuer().to_string(),
        sub: agent.spiffe_id.clone(),
        aud: vec![req.audience.clone()],
        iat: now.unix_timestamp(), nbf: now.unix_timestamp(),
        exp: (now + Duration::seconds(ttl)).unix_timestamp(),
        jti: Uuid::new_v4().to_string(),
        agent_name: agent.agent_name.clone(), owner: agent.owner.clone(),
        scopes: req.requested_scopes.clone(),
    };

    let token = state.signer.sign(&claims).await?;
    audit::record_svid_issued(&state, principal.spiffe_id(), agent.agent_id, &agent.spiffe_id, &req.audience, ttl);
    metrics::record_svid_issued();

    Ok(Json(IssuedSvidResponse {
        access_token: token, token_type: "Bearer".into(),
        expires_in: ttl, spiffe_id: agent.spiffe_id,
    }))
}

pub async fn jwks(State(state): State<SharedState>) -> Json<serde_json::Value> {
    Json(state.signer.public_jwks().clone())
}
