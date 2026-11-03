use crate::auth::principal::Principal;
use crate::error::AppError;
use crate::state::SharedState;
use axum::{
    extract::{Request, State},
    middleware::Next,
    response::Response,
};

/// Authenticates inbound requests:
/// 1. Extracts `X-Client-Cert-SPIFFE-ID` header (injected by TLS proxy/ingress after mTLS cert verification)
///    or `SSL-Client-Subject-SAN` client certs.
/// 2. If present and listed in `allowed_control_plane_spiffe_ids`, assigns `Principal::ControlPlane`.
/// 3. In development environments only, falls back to `development_identity_spiffe_id` if present.
/// 4. Leaves extension empty for public or unauthenticated routes (e.g., `/healthz`, `/readyz`, `/.well-known/jwks.json`).
pub async fn authenticate(
    State(state): State<SharedState>,
    mut request: Request,
    next: Next,
) -> Result<Response, AppError> {
    // 1. Extract header value first without holding immutable borrow on request
    let spiffe_from_header = request
        .headers()
        .get("x-client-cert-spiffe-id")
        .or_else(|| request.headers().get("ssl-client-subject-san"))
        .and_then(|h| h.to_str().ok().map(|s| s.to_string()));

    if let Some(spiffe_id) = spiffe_from_header {
        if state.config.security.allowed_control_plane_spiffe_ids.iter().any(|allowed| allowed == &spiffe_id) {
            request.extensions_mut().insert(Principal::ControlPlane {
                spiffe_id,
            });
            return Ok(next.run(request).await);
        } else {
            tracing::warn!(spiffe_id = %spiffe_id, "rejected untrusted control-plane SPIFFE ID");
            return Err(AppError::Forbidden("unauthorized client identity".into()));
        }
    }

    // 2. Fallback in development environments
    if state.config.service.environment != "production" {
        if let Some(ref dev_id) = state.config.security.development_identity_spiffe_id {
            request.extensions_mut().insert(Principal::ControlPlane {
                spiffe_id: dev_id.clone(),
            });
        }
    }

    Ok(next.run(request).await)
}
