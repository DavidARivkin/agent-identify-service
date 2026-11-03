use metrics::{counter, histogram};
use metrics_exporter_prometheus::{PrometheusBuilder, PrometheusHandle};

pub fn init_prometheus() -> anyhow::Result<PrometheusHandle> {
    Ok(PrometheusBuilder::new().install_recorder()?)
}

pub fn record_svid_issued() { counter!("agent_identity_svids_issued_total").increment(1); }
pub fn record_authorization_denied() { counter!("agent_identity_authorization_denied_total").increment(1); }
pub fn record_revocation() { counter!("agent_identity_revocations_total").increment(1); }

pub fn record_request(route: &str, method: &str, status: u16, seconds: f64) {
    counter!("http_requests_total","route"=>route.to_string(),"method"=>method.to_string(),"status"=>status.to_string()).increment(1);
    histogram!("http_request_duration_seconds","route"=>route.to_string()).record(seconds);
}
