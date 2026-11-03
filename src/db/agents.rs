use serde::{Deserialize, Serialize};
use uuid::Uuid;
use crate::db::Database;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AgentRecord {
    pub agent_id: Uuid,
    pub spiffe_id: String,
    pub agent_name: String,
    pub owner: String,
    pub allowed_scopes: Vec<String>,
    pub status: String,
}

// ── helpers ──────────────────────────────────────────────────────────────────

#[derive(sqlx::FromRow)]
struct PgRow {
    agent_id: Uuid,
    spiffe_id: String,
    agent_name: String,
    owner: String,
    allowed_scopes: Vec<String>,
    status: String,
}

impl From<PgRow> for AgentRecord {
    fn from(r: PgRow) -> Self {
        AgentRecord { agent_id: r.agent_id, spiffe_id: r.spiffe_id, agent_name: r.agent_name, owner: r.owner, allowed_scopes: r.allowed_scopes, status: r.status }
    }
}

#[derive(sqlx::FromRow)]
struct SqliteRow {
    agent_id: String,
    spiffe_id: String,
    agent_name: String,
    owner: String,
    allowed_scopes: String, // JSON text
    status: String,
}

impl From<SqliteRow> for AgentRecord {
    fn from(r: SqliteRow) -> Self {
        let scopes: Vec<String> = serde_json::from_str(&r.allowed_scopes).unwrap_or_default();
        AgentRecord {
            agent_id: Uuid::parse_str(&r.agent_id).unwrap_or_else(|_| Uuid::nil()),
            spiffe_id: r.spiffe_id, agent_name: r.agent_name, owner: r.owner,
            allowed_scopes: scopes, status: r.status,
        }
    }
}

fn duck_row_to_record(row: &duckdb::Row<'_>) -> anyhow::Result<AgentRecord> {
    let scopes_str: String = row.get(4)?;
    let scopes: Vec<String> = serde_json::from_str(&scopes_str).unwrap_or_default();
    Ok(AgentRecord {
        agent_id: Uuid::parse_str(&row.get::<_, String>(0)?).unwrap_or_else(|_| Uuid::nil()),
        spiffe_id: row.get(1)?,
        agent_name: row.get(2)?,
        owner: row.get(3)?,
        allowed_scopes: scopes,
        status: row.get(5)?,
    })
}

// ── public API ────────────────────────────────────────────────────────────────

pub async fn insert_agent(
    db: &Database, agent_id: Uuid, spiffe_id: &str,
    agent_name: &str, owner: &str, scopes: &[String],
) -> anyhow::Result<AgentRecord> {
    let scopes_json = serde_json::to_string(scopes)?;
    match db {
        Database::Postgres(pool) => {
            let r = sqlx::query_as::<_, PgRow>(
                "INSERT INTO agents (agent_id,spiffe_id,agent_name,owner,allowed_scopes,status)
                 VALUES ($1,$2,$3,$4,$5,'active')
                 RETURNING agent_id,spiffe_id,agent_name,owner,allowed_scopes,status",
            ).bind(agent_id).bind(spiffe_id).bind(agent_name).bind(owner).bind(scopes)
             .fetch_one(pool).await?;
            Ok(r.into())
        }
        Database::Sqlite(pool) => {
            let id_str = agent_id.to_string();
            sqlx::query(
                "INSERT INTO agents (agent_id,spiffe_id,agent_name,owner,allowed_scopes,status)
                 VALUES (?,?,?,?,?,'active')",
            ).bind(&id_str).bind(spiffe_id).bind(agent_name).bind(owner).bind(&scopes_json)
             .execute(pool).await?;
            get_agent(db, agent_id).await?
                .ok_or_else(|| anyhow::anyhow!("agent not found after insert"))
        }
        Database::DuckDb(pool) => {
            let pool = pool.clone();
            let id_str = agent_id.to_string();
            let spiffe_id = spiffe_id.to_string();
            let agent_name = agent_name.to_string();
            let owner = owner.to_string();
            tokio::task::spawn_blocking(move || {
                let conn = pool.get()?;
                conn.execute(
                    "INSERT INTO agents (agent_id,spiffe_id,agent_name,owner,allowed_scopes,status)
                     VALUES (?,?,?,?,?,'active')",
                    duckdb::params![id_str, spiffe_id, agent_name, owner, scopes_json],
                )?;
                let mut stmt = conn.prepare(
                    "SELECT agent_id,spiffe_id,agent_name,owner,allowed_scopes,status
                     FROM agents WHERE agent_id=?",
                )?;
                let mut rows = stmt.query(duckdb::params![id_str])?;
                let row = rows.next()?.ok_or(duckdb::Error::QueryReturnedNoRows)?;
                duck_row_to_record(row)
            }).await?
        }
    }
}

pub async fn get_agent(db: &Database, agent_id: Uuid) -> anyhow::Result<Option<AgentRecord>> {
    match db {
        Database::Postgres(pool) => {
            let r = sqlx::query_as::<_, PgRow>(
                "SELECT agent_id,spiffe_id,agent_name,owner,allowed_scopes,status
                 FROM agents WHERE agent_id=$1",
            ).bind(agent_id).fetch_optional(pool).await?;
            Ok(r.map(Into::into))
        }
        Database::Sqlite(pool) => {
            let id_str = agent_id.to_string();
            let r = sqlx::query_as::<_, SqliteRow>(
                "SELECT agent_id,spiffe_id,agent_name,owner,allowed_scopes,status
                 FROM agents WHERE agent_id=?",
            ).bind(&id_str).fetch_optional(pool).await?;
            Ok(r.map(Into::into))
        }
        Database::DuckDb(pool) => {
            let pool = pool.clone();
            let id_str = agent_id.to_string();
            tokio::task::spawn_blocking(move || {
                let conn = pool.get()?;
                let mut stmt = conn.prepare(
                    "SELECT agent_id,spiffe_id,agent_name,owner,allowed_scopes,status
                     FROM agents WHERE agent_id=?",
                )?;
                let mut rows = stmt.query(duckdb::params![id_str])?;
                match rows.next()? {
                    None => Ok(None),
                    Some(row) => duck_row_to_record(row).map(Some),
                }
            }).await?
        }
    }
}

pub async fn revoke_agent(db: &Database, agent_id: Uuid) -> anyhow::Result<Option<AgentRecord>> {
    match db {
        Database::Postgres(pool) => {
            let r = sqlx::query_as::<_, PgRow>(
                "UPDATE agents SET status='revoked',revoked_at=now(),updated_at=now()
                 WHERE agent_id=$1 AND status='active'
                 RETURNING agent_id,spiffe_id,agent_name,owner,allowed_scopes,status",
            ).bind(agent_id).fetch_optional(pool).await?;
            Ok(r.map(Into::into))
        }
        Database::Sqlite(pool) => {
            let id_str = agent_id.to_string();
            let affected = sqlx::query(
                "UPDATE agents SET status='revoked',
                 revoked_at=strftime('%Y-%m-%dT%H:%M:%SZ','now'),
                 updated_at=strftime('%Y-%m-%dT%H:%M:%SZ','now')
                 WHERE agent_id=? AND status='active'",
            ).bind(&id_str).execute(pool).await?.rows_affected();
            if affected == 0 { return Ok(None); }
            get_agent(db, agent_id).await
        }
        Database::DuckDb(pool) => {
            let pool = pool.clone();
            let id_str = agent_id.to_string();
            tokio::task::spawn_blocking(move || {
                let conn = pool.get()?;
                let affected = conn.execute(
                    "UPDATE agents SET status='revoked',revoked_at=now(),updated_at=now()
                     WHERE agent_id=? AND status='active'",
                    duckdb::params![id_str],
                )?;
                if affected == 0 { return Ok(None); }
                let mut stmt = conn.prepare(
                    "SELECT agent_id,spiffe_id,agent_name,owner,allowed_scopes,status
                     FROM agents WHERE agent_id=?",
                )?;
                let mut rows = stmt.query(duckdb::params![id_str])?;
                match rows.next()? {
                    None => Ok(None),
                    Some(row) => duck_row_to_record(row).map(Some),
                }
            }).await?
        }
    }
}

pub async fn is_agent_active(db: &Database, spiffe_id: &str) -> anyhow::Result<bool> {
    match db {
        Database::Postgres(pool) => {
            let row: (bool,) = sqlx::query_as(
                "SELECT EXISTS(SELECT 1 FROM agents WHERE spiffe_id=$1 AND status='active')",
            ).bind(spiffe_id).fetch_one(pool).await?;
            Ok(row.0)
        }
        Database::Sqlite(pool) => {
            let n: i64 = sqlx::query_scalar(
                "SELECT COUNT(*) FROM agents WHERE spiffe_id=? AND status='active'",
            ).bind(spiffe_id).fetch_one(pool).await?;
            Ok(n > 0)
        }
        Database::DuckDb(pool) => {
            let pool = pool.clone();
            let spiffe_id = spiffe_id.to_string();
            tokio::task::spawn_blocking(move || {
                let conn = pool.get()?;
                let mut stmt = conn.prepare(
                    "SELECT COUNT(*) FROM agents WHERE spiffe_id=? AND status='active'",
                )?;
                let mut rows = stmt.query(duckdb::params![spiffe_id])?;
                let n: i64 = rows.next()?.map(|r| r.get(0).unwrap_or(0)).unwrap_or(0);
                Ok::<bool, anyhow::Error>(n > 0)
            }).await?
        }
    }
}
