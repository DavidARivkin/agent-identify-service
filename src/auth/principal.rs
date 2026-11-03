use crate::error::{AppError, AppResult};
use async_trait::async_trait;
use axum::{extract::FromRequestParts, http::request::Parts};
use time::OffsetDateTime;

#[derive(Debug, Clone)]
pub enum Principal {
    ControlPlane { spiffe_id: String },
    Agent { spiffe_id: String, agent_name: String, owner: String, scopes: Vec<String>, expires_at: OffsetDateTime },
}

impl Principal {
    pub fn spiffe_id(&self) -> &str {
        match self { Self::ControlPlane { spiffe_id } => spiffe_id, Self::Agent { spiffe_id, .. } => spiffe_id }
    }

    pub fn require_control_plane(&self) -> AppResult<()> {
        match self {
            Self::ControlPlane { .. } => Ok(()),
            Self::Agent { .. } => Err(AppError::Forbidden("control-plane identity required".into())),
        }
    }
}

#[async_trait]
impl<S> FromRequestParts<S> for Principal where S: Send + Sync {
    type Rejection = AppError;
    async fn from_request_parts(parts: &mut Parts, _state: &S) -> Result<Self, Self::Rejection> {
        parts.extensions.get::<Principal>().cloned()
            .ok_or_else(|| AppError::Unauthorized("authenticated principal required".into()))
    }
}
