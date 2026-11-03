use crate::audit;
use crate::auth::principal::Principal;
use crate::db::agents;
use crate::error::{AppError, AppResult};
use crate::state::SharedState;
use axum::{extract::{Path, State}, Json};
use serde::{Deserialize, Serialize};
use uuid::Uuid;
use validator::Validate;

#[derive(Debug, Deserialize, Validate)]
pub struct RegisterAgentRequest {
    #[validate(length(min=1,max=128))] pub agent_name: String,
    #[validate(length(min=1,max=128))] pub owner: String,
    #[validate(length(min=1,max=64))] pub allowed_scopes: Vec<String>,
}

#[derive(Debug, Serialize)]
pub struct AgentResponse {
    pub agent_id: Uuid, pub spiffe_id: String, pub agent_name: String,
    pub owner: String, pub allowed_scopes: Vec<String>, pub status: String,
}

impl From<agents::AgentRecord> for AgentResponse {
    fn from(r: agents::AgentRecord) -> Self {
        Self { agent_id:r.agent_id, spiffe_id:r.spiffe_id, agent_name:r.agent_name, owner:r.owner, allowed_scopes:r.allowed_scopes, status:r.status }
    }
}

pub async fn register_agent(State(state): State<SharedState>, principal: Principal, Json(req): Json<RegisterAgentRequest>) -> AppResult<Json<AgentResponse>> {
    principal.require_control_plane()?;
    req.validate().map_err(|e| AppError::BadRequest(e.to_string()))?;

    let id = Uuid::new_v4();
    let spiffe_id = format!("spiffe://{}/ns/agent-platform/agent/{}", state.config.service.trust_domain, id);

    let record = agents::insert_agent(&state.db, id, &spiffe_id, &req.agent_name, &req.owner, &req.allowed_scopes).await?;
    audit::record_agent_registered(&state, principal.spiffe_id(), id, &spiffe_id);
    Ok(Json(record.into()))
}

pub async fn get_agent(State(state): State<SharedState>, Path(agent_id): Path<Uuid>) -> AppResult<Json<AgentResponse>> {
    let record = agents::get_agent(&state.db, agent_id).await?
        .ok_or_else(|| AppError::NotFound("agent not found".into()))?;
    Ok(Json(record.into()))
}

pub async fn revoke_agent(State(state): State<SharedState>, principal: Principal, Path(agent_id): Path<Uuid>) -> AppResult<Json<serde_json::Value>> {
    principal.require_control_plane()?;
    let record = agents::revoke_agent(&state.db, agent_id).await?
        .ok_or_else(|| AppError::NotFound("active agent not found".into()))?;
    audit::record_agent_revoked(&state, principal.spiffe_id(), agent_id, &record.spiffe_id);
    Ok(Json(serde_json::json!({"agent_id":agent_id,"status":"revoked"})))
}

#[derive(Debug, Deserialize, Validate)]
pub struct RevokeSvidRequest {
    #[validate(length(min=1,max=128))] pub jti: String,
    pub expires_at_unix: i64,
}

pub async fn revoke_svid(State(state): State<SharedState>, principal: Principal, Json(req): Json<RevokeSvidRequest>) -> AppResult<Json<serde_json::Value>> {
    principal.require_control_plane()?;
    req.validate().map_err(|e| AppError::BadRequest(e.to_string()))?;

    let now = time::OffsetDateTime::now_utc().unix_timestamp();
    let ttl = req.expires_at_unix.saturating_sub(now);
    if ttl <= 0 || ttl > state.config.crypto.max_svid_ttl_seconds {
        return Err(AppError::BadRequest("invalid expiry".into()));
    }

    let key = format!("{}{}", state.config.redis.revocation_prefix, req.jti);
    state.revocation.set_ex(key, ttl as u64).await
        .map_err(|e| anyhow::anyhow!("revocation failed: {e}"))?;

    audit::record_svid_revoked(&state, principal.spiffe_id(), &req.jti);
    Ok(Json(serde_json::json!({"jti":req.jti,"revoked":true})))
}
