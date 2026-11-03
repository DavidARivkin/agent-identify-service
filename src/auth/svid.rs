use crate::db::agents;
use crate::error::{AppError, AppResult};
use crate::state::SharedState;
use jsonwebtoken::{decode, decode_header, jwk::Jwk, Algorithm, DecodingKey, Validation};
use serde::{Deserialize, Serialize};
use time::OffsetDateTime;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SvidClaims {
    pub iss: String, pub sub: String, pub aud: Vec<String>,
    pub exp: i64, pub iat: i64, pub nbf: i64, pub jti: String,
    pub agent_name: String, pub owner: String, pub scopes: Vec<String>,
}

#[derive(Debug, Clone)]
pub struct ValidatedSvid {
    pub spiffe_id: String, pub jti: String, pub agent_name: String,
    pub owner: String, pub scopes: Vec<String>, pub expires_at: OffsetDateTime,
}

pub async fn validate_bearer_svid(state: &SharedState, authorization: Option<&str>, audience: &str) -> AppResult<ValidatedSvid> {
    let token = authorization.and_then(|v| v.strip_prefix("Bearer "))
        .ok_or_else(|| AppError::Unauthorized("missing bearer JWT-SVID".into()))?;

    let header = decode_header(token).map_err(|_| AppError::Unauthorized("malformed JWT".into()))?;
    if header.alg != Algorithm::RS256 { return Err(AppError::Unauthorized("unsupported algorithm".into())); }

    let kid = header.kid.filter(|k| !k.is_empty() && k.len() <= 128)
        .ok_or_else(|| AppError::Unauthorized("missing kid".into()))?;

    let jwks = state.signer.public_jwks();
    let jwk = extract_jwk(&jwks, &kid)?;
    let key = DecodingKey::from_jwk(&jwk).map_err(|_| AppError::Unauthorized("invalid signing key".into()))?;

    let mut validation = Validation::new(Algorithm::RS256);
    validation.set_audience(&[audience]);
    validation.set_issuer(&[state.signer.issuer().to_string()]);
    validation.validate_exp = true;
    validation.validate_aud = true;
    validation.validate_nbf = true;
    validation.leeway = 30;

    let data = decode::<SvidClaims>(token, &key, &validation)
        .map_err(|_| AppError::Unauthorized("invalid JWT-SVID".into()))?;
    let claims = data.claims;

    let prefix = format!("spiffe://{}/", state.config.service.trust_domain);
    if !claims.sub.starts_with(&prefix) { return Err(AppError::Unauthorized("untrusted SPIFFE ID".into())); }
    if claims.scopes.len() > 64 { return Err(AppError::Unauthorized("too many scopes".into())); }

    if is_jti_revoked(state, &claims.jti).await? { return Err(AppError::Unauthorized("SVID revoked".into())); }
    if !agents::is_agent_active(&state.db, &claims.sub).await? { return Err(AppError::Unauthorized("agent revoked".into())); }

    let expires_at = OffsetDateTime::from_unix_timestamp(claims.exp)
        .map_err(|_| AppError::Unauthorized("invalid exp".into()))?;

    Ok(ValidatedSvid {
        spiffe_id: claims.sub, jti: claims.jti, agent_name: claims.agent_name,
        owner: claims.owner, scopes: claims.scopes, expires_at,
    })
}

pub async fn is_jti_revoked(state: &SharedState, jti: &str) -> AppResult<bool> {
    let key = format!("{}{}", state.config.redis.revocation_prefix, jti);
    state.revocation.exists(&key).await
        .map_err(|e| anyhow::anyhow!("revocation lookup failed: {e}").into())
}

fn extract_jwk(jwks: &serde_json::Value, kid: &str) -> AppResult<Jwk> {
    let keys = jwks.get("keys").and_then(|v| v.as_array())
        .ok_or_else(|| AppError::Unauthorized("invalid JWKS".into()))?;
    let key_val = keys.iter().find(|k| k.get("kid").and_then(|v| v.as_str()) == Some(kid))
        .ok_or_else(|| AppError::Unauthorized("unknown signing key".into()))?;
    serde_json::from_value::<Jwk>(key_val.clone())
        .map_err(|_| AppError::Unauthorized("invalid signing key format".into()))
}
