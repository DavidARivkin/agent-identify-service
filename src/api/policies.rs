use crate::audit;
use crate::auth::principal::Principal;
use crate::auth::svid::validate_bearer_svid;
use crate::db::policies;
use crate::error::{AppError, AppResult};
use crate::metrics;
use crate::observability::redact_spiffe_id;
use crate::state::SharedState;
use axum::{extract::State, http::HeaderMap, Json};
use serde::{Deserialize, Serialize};
use validator::Validate;

#[derive(Debug, Deserialize, Validate)]
pub struct CreatePolicyRequest {
    pub spiffe_id: String,
    #[validate(length(min=1,max=253))] pub resource: String,
    #[validate(length(min=1,max=128))] pub action: String,
    pub effect: String,
}

#[derive(Debug, Deserialize, Validate)]
pub struct AuthorizeRequest {
    #[validate(length(min=1,max=253))] pub resource: String,
    #[validate(length(min=1,max=128))] pub action: String,
}

#[derive(Debug, Serialize)]
pub struct AuthorizationResponse { pub allowed: bool, pub spiffe_id: String }

pub async fn create_policy(State(state): State<SharedState>, principal: Principal, Json(req): Json<CreatePolicyRequest>) -> AppResult<Json<serde_json::Value>> {
    principal.require_control_plane()?;
    req.validate().map_err(|e| AppError::BadRequest(e.to_string()))?;

    if !matches!(req.effect.as_str(), "allow"|"deny") {
        return Err(AppError::BadRequest("effect must be allow or deny".into()));
    }

    let prefix = format!("spiffe://{}/", state.config.service.trust_domain);
    if !req.spiffe_id.starts_with(&prefix) { return Err(AppError::BadRequest("untrusted SPIFFE ID".into())); }

    let policy_id = policies::insert_policy(&state.db, &req.spiffe_id, &req.resource, &req.action, &req.effect, principal.spiffe_id()).await?;
    audit::record_policy_created(&state, principal.spiffe_id(), policy_id, &req.spiffe_id);

    Ok(Json(serde_json::json!({"policy_id":policy_id})))
}

pub async fn authorize(State(state): State<SharedState>, headers: HeaderMap, Json(req): Json<AuthorizeRequest>) -> AppResult<Json<AuthorizationResponse>> {
    req.validate().map_err(|e| AppError::BadRequest(e.to_string()))?;

    let svid = validate_bearer_svid(&state, headers.get("authorization").and_then(|v| v.to_str().ok()), "agent-platform").await?;
    let decision = policies::decide(&state.db, &svid.spiffe_id, &req.resource, &req.action).await?;
    let allowed = decision.map(|d| d.effect == "allow").unwrap_or(false);

    let outcome = if allowed { audit::AuditOutcome::Allowed } else { audit::AuditOutcome::Denied };
    audit::record_authorization_decision(&state, &svid.spiffe_id, &req.resource, &req.action, outcome);

    if !allowed {
        metrics::record_authorization_denied();
        tracing::warn!(spiffe_id=%redact_spiffe_id(&svid.spiffe_id), "authorization denied");
        return Err(AppError::Forbidden("policy denied access".into()));
    }

    Ok(Json(AuthorizationResponse { allowed, spiffe_id: svid.spiffe_id }))
}
