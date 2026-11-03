pub mod agents; pub mod health; pub mod policies; pub mod svids;

use crate::middleware::{auth, rate_limit, security_headers};
use crate::state::SharedState;
use axum::{middleware, routing::{get, post}, Router};
use std::time::Duration;
use tower_http::{limit::RequestBodyLimitLayer, timeout::TimeoutLayer, trace::TraceLayer};

pub fn router(state: SharedState) -> Router {
    let limiter = rate_limit::RateLimitState::new(
        state.config.security.rate_limit_per_second,
        state.config.security.rate_limit_burst,
    );

    Router::new()
        .route("/healthz", get(health::liveness))
        .route("/readyz", get(health::readiness))
        .route("/metrics", get(health::metrics))
        .route("/.well-known/jwks.json", get(svids::jwks))
        .route("/v1/agents", post(agents::register_agent))
        .route("/v1/agents/:agent_id", get(agents::get_agent))
        .route("/v1/agents/:agent_id/revoke", post(agents::revoke_agent))
        .route("/v1/svids", post(svids::issue_svid))
        .route("/v1/svids/revoke", post(agents::revoke_svid))
        .route("/v1/authorize", post(policies::authorize))
        .route("/v1/policies", post(policies::create_policy))
        .layer(middleware::from_fn_with_state(state.clone(), auth::authenticate))
        .layer(middleware::from_fn_with_state(limiter, rate_limit::rate_limit))
        .layer(middleware::from_fn(security_headers::security_headers))
        .layer(TraceLayer::new_for_http())
        .layer(TimeoutLayer::with_status_code(
            axum::http::StatusCode::REQUEST_TIMEOUT,
            Duration::from_secs(state.config.service.request_timeout_seconds),
        ))
        .layer(RequestBodyLimitLayer::new(state.config.service.max_body_bytes))
        .with_state(state)
}
