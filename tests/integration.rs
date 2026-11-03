use serde_json::json;

#[tokio::test]
async fn authorization_requires_bearer_svid() {
    let base = std::env::var("SERVICE_BASE_URL").unwrap_or_else(|_| "http://localhost:8080".into());
    let response = reqwest::Client::new()
        .post(format!("{base}/v1/authorize"))
        .json(&json!({"resource":"invoices","action":"read"}))
        .send().await.expect("request failed");
    assert_eq!(response.status(), 401);
}
