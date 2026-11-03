use axum::{extract::Request, http::header, middleware::Next, response::Response};

pub async fn security_headers(request: Request, next: Next) -> Response {
    let mut response = next.run(request).await;
    let h = response.headers_mut();
    h.insert(header::STRICT_TRANSPORT_SECURITY, header::HeaderValue::from_static("max-age=63072000; includeSubDomains"));
    h.insert(header::X_CONTENT_TYPE_OPTIONS, header::HeaderValue::from_static("nosniff"));
    h.insert(header::X_FRAME_OPTIONS, header::HeaderValue::from_static("DENY"));
    h.insert(header::CACHE_CONTROL, header::HeaderValue::from_static("no-store"));
    h.insert(header::REFERRER_POLICY, header::HeaderValue::from_static("no-referrer"));
    response
}
