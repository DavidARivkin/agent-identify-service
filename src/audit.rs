pub use crate::db::audit::AuditOutcome;
use crate::db::audit::write_event;
use crate::db::Database;
use crate::observability::redact_spiffe_id;
use crate::state::SharedState;
use serde_json::json;
use tokio::sync::mpsc;
use uuid::Uuid;

/// Event envelope for background asynchronous audit dispatch
#[derive(Debug, Clone)]
pub struct QueuedAuditEvent {
    pub event_type: String,
    pub actor: Option<String>,
    pub agent_id: Option<Uuid>,
    pub resource: Option<String>,
    pub action: Option<String>,
    pub outcome: AuditOutcome,
    pub request_id: Option<String>,
    pub details: serde_json::Value,
}

/// Async Audit Logger with a bounded background worker queue.
/// Prevents database write latency from degrading HTTP token issuance and request authorization.
#[derive(Clone)]
pub struct AuditLogger {
    tx: mpsc::Sender<QueuedAuditEvent>,
}

impl AuditLogger {
    pub fn new(db: Database, capacity: usize) -> Self {
        let (tx, mut rx) = mpsc::channel::<QueuedAuditEvent>(capacity);

        // Background worker consuming queued audit events
        tokio::spawn(async move {
            while let Some(evt) = rx.recv().await {
                if let Err(e) = write_event(
                    &db,
                    &evt.event_type,
                    evt.actor.as_deref(),
                    evt.agent_id,
                    evt.resource.as_deref(),
                    evt.action.as_deref(),
                    evt.outcome,
                    evt.request_id.as_deref(),
                    evt.details,
                ).await {
                    tracing::error!(error=?e, event=%evt.event_type, "background audit write failed");
                }
            }
        });

        Self { tx }
    }

    pub fn send(&self, event: QueuedAuditEvent) {
        if let Err(e) = self.tx.try_send(event) {
            tracing::warn!(error=?e, "audit event queue full or dropped; falling back to direct warning log");
        }
    }
}

pub fn record_agent_registered(s: &SharedState, actor: &str, id: Uuid, spiffe_id: &str) {
    s.audit.send(QueuedAuditEvent {
        event_type: "agent.registered".into(),
        actor: Some(actor.into()),
        agent_id: Some(id),
        resource: None,
        action: None,
        outcome: AuditOutcome::Success,
        request_id: None,
        details: json!({"spiffe_id": redact_spiffe_id(spiffe_id)}),
    });
}

pub fn record_agent_revoked(s: &SharedState, actor: &str, id: Uuid, spiffe_id: &str) {
    s.audit.send(QueuedAuditEvent {
        event_type: "agent.revoked".into(),
        actor: Some(actor.into()),
        agent_id: Some(id),
        resource: None,
        action: None,
        outcome: AuditOutcome::Success,
        request_id: None,
        details: json!({"spiffe_id": redact_spiffe_id(spiffe_id)}),
    });
}

pub fn record_svid_issued(s: &SharedState, actor: &str, id: Uuid, spiffe_id: &str, audience: &str, ttl: i64) {
    s.audit.send(QueuedAuditEvent {
        event_type: "svid.issued".into(),
        actor: Some(actor.into()),
        agent_id: Some(id),
        resource: None,
        action: None,
        outcome: AuditOutcome::Success,
        request_id: None,
        details: json!({"spiffe_id": redact_spiffe_id(spiffe_id), "audience": audience, "ttl_seconds": ttl}),
    });
}

pub fn record_svid_revoked(s: &SharedState, actor: &str, jti: &str) {
    s.audit.send(QueuedAuditEvent {
        event_type: "svid.revoked".into(),
        actor: Some(actor.into()),
        agent_id: None,
        resource: None,
        action: None,
        outcome: AuditOutcome::Success,
        request_id: None,
        details: json!({"jti": jti}),
    });
}

pub fn record_policy_created(s: &SharedState, actor: &str, policy_id: Uuid, subject: &str) {
    s.audit.send(QueuedAuditEvent {
        event_type: "policy.created".into(),
        actor: Some(actor.into()),
        agent_id: None,
        resource: None,
        action: None,
        outcome: AuditOutcome::Success,
        request_id: None,
        details: json!({"policy_id": policy_id, "subject": redact_spiffe_id(subject)}),
    });
}

pub fn record_authorization_decision(s: &SharedState, spiffe_id: &str, resource: &str, action: &str, outcome: AuditOutcome) {
    s.audit.send(QueuedAuditEvent {
        event_type: "authorization.decision".into(),
        actor: Some(spiffe_id.into()),
        agent_id: None,
        resource: Some(resource.into()),
        action: Some(action.into()),
        outcome,
        request_id: None,
        details: json!({}),
    });
}
