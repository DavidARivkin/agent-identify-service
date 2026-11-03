use crate::auth::principal::Principal;
use crate::error::AppError;
use axum::{extract::{Request, State}, http::StatusCode, middleware::Next, response::{IntoResponse, Response}};
use std::{collections::HashMap, sync::{Arc, Mutex}, time::Instant};

#[derive(Clone)]
pub struct RateLimitState {
    buckets: Arc<Mutex<HashMap<String, TokenBucket>>>,
    rate: f64, burst: f64,
}

#[derive(Clone)]
struct TokenBucket { tokens: f64, last: Instant }

impl RateLimitState {
    pub fn new(rate_per_second: u32, burst: u32) -> Self {
        Self { buckets: Arc::new(Mutex::new(HashMap::new())), rate: rate_per_second as f64, burst: burst as f64 }
    }

    fn allow(&self, key: &str) -> bool {
        let now = Instant::now();
        let mut buckets = self.buckets.lock().expect("rate-limit lock poisoned");
        let bucket = buckets.entry(key.to_string()).or_insert(TokenBucket { tokens: self.burst, last: now });
        let elapsed = now.duration_since(bucket.last).as_secs_f64();
        bucket.tokens = (bucket.tokens + elapsed * self.rate).min(self.burst);
        bucket.last = now;
        if bucket.tokens >= 1.0 { bucket.tokens -= 1.0; true } else { false }
    }
}

pub async fn rate_limit(State(state): State<RateLimitState>, request: Request, next: Next) -> Result<Response, AppError> {
    let key = request.extensions().get::<Principal>()
        .map(|p| p.spiffe_id().to_string())
        .unwrap_or_else(|| "unauthenticated".into());

    if !state.allow(&key) {
        return Ok((StatusCode::TOO_MANY_REQUESTS, "rate limit exceeded").into_response());
    }
    Ok(next.run(request).await)
}
