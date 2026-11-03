use crate::audit::AuditLogger;
use crate::config::Config;
use crate::crypto::signer::Signer;
use crate::db::Database;
use crate::revocation::RevocationStore;
use std::sync::Arc;
use metrics_exporter_prometheus::PrometheusHandle;

pub struct AppState {
    pub config: Arc<Config>,
    pub db: Database,
    pub revocation: RevocationStore,
    pub signer: Arc<dyn Signer>,
    pub audit: AuditLogger,
    pub prometheus: PrometheusHandle,
}

pub type SharedState = Arc<AppState>;
