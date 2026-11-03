use serde_json::Value;
use uuid::Uuid;
use crate::db::Database;

#[derive(Debug, Clone, Copy)]
pub enum AuditOutcome { Allowed, Denied, Success, Failure }

impl AuditOutcome {
    pub fn as_str(self) -> &'static str {
        match self { Self::Allowed=>"allowed", Self::Denied=>"denied", Self::Success=>"success", Self::Failure=>"failure" }
    }
}

#[allow(clippy::too_many_arguments)]
pub async fn write_event(
    db: &Database,
    event_type: &str,
    actor: Option<&str>,
    agent_id: Option<Uuid>,
    resource: Option<&str>,
    action: Option<&str>,
    outcome: AuditOutcome,
    request_id: Option<&str>,
    details: Value,
) -> anyhow::Result<()> {
    let details_str = details.to_string();
    match db {
        Database::Postgres(pool) => {
            sqlx::query(
                "INSERT INTO audit_events (event_type,actor_spiffe_id,agent_id,resource,action,outcome,request_id,details)
                 VALUES ($1,$2,$3,$4,$5,$6,$7,$8)"
            ).bind(event_type).bind(actor).bind(agent_id).bind(resource).bind(action)
             .bind(outcome.as_str()).bind(request_id).bind(details)
             .execute(pool).await?;
        }
        Database::Sqlite(pool) => {
            let event_id = Uuid::new_v4().to_string();
            let agent_id_str = agent_id.map(|u| u.to_string());
            sqlx::query(
                "INSERT INTO audit_events (event_id,event_type,actor_spiffe_id,agent_id,resource,action,outcome,request_id,details)
                 VALUES (?,?,?,?,?,?,?,?,?)"
            ).bind(&event_id).bind(event_type).bind(actor).bind(agent_id_str.as_deref())
             .bind(resource).bind(action).bind(outcome.as_str()).bind(request_id).bind(&details_str)
             .execute(pool).await?;
        }
        Database::DuckDb(pool) => {
            let pool = pool.clone();
            let event_type = event_type.to_string();
            let actor = actor.map(|s| s.to_string());
            let agent_id_str = agent_id.map(|u| u.to_string());
            let resource = resource.map(|s| s.to_string());
            let action = action.map(|s| s.to_string());
            let outcome_str = outcome.as_str();
            let request_id = request_id.map(|s| s.to_string());
            tokio::task::spawn_blocking(move || {
                let conn = pool.get()?;
                conn.execute(
                    "INSERT INTO audit_events (event_type,actor_spiffe_id,agent_id,resource,action,outcome,request_id,details)
                     VALUES (?,?,?,?,?,?,?,?)",
                    duckdb::params![
                        event_type,
                        actor.as_deref(),
                        agent_id_str.as_deref(),
                        resource.as_deref(),
                        action.as_deref(),
                        outcome_str,
                        request_id.as_deref(),
                        details_str
                    ],
                )?;
                Ok::<_, anyhow::Error>(())
            }).await??;
        }
    }
    Ok(())
}
