use uuid::Uuid;
use crate::db::Database;

#[derive(Debug)]
pub struct PolicyDecision { pub effect: String }

pub async fn insert_policy(
    db: &Database,
    spiffe_id: &str, resource: &str, action: &str, effect: &str, created_by: &str,
) -> anyhow::Result<Uuid> {
    match db {
        Database::Postgres(pool) => {
            let row: (Uuid,) = sqlx::query_as(
                "INSERT INTO policies (spiffe_id,resource,action,effect,created_by)
                 VALUES ($1,$2,$3,$4,$5) RETURNING policy_id"
            ).bind(spiffe_id).bind(resource).bind(action).bind(effect).bind(created_by)
             .fetch_one(pool).await?;
            Ok(row.0)
        }
        Database::Sqlite(pool) => {
            let policy_id = Uuid::new_v4();
            let id_str = policy_id.to_string();
            sqlx::query(
                "INSERT INTO policies (policy_id,spiffe_id,resource,action,effect,created_by) VALUES (?,?,?,?,?,?)"
            ).bind(&id_str).bind(spiffe_id).bind(resource).bind(action).bind(effect).bind(created_by)
             .execute(pool).await?;
            Ok(policy_id)
        }
        Database::DuckDb(pool) => {
            let pool = pool.clone();
            let spiffe_id = spiffe_id.to_string();
            let resource = resource.to_string();
            let action = action.to_string();
            let effect = effect.to_string();
            let created_by = created_by.to_string();
            tokio::task::spawn_blocking(move || {
                let conn = pool.get()?;
                // DuckDB supports RETURNING like Postgres
                let mut stmt = conn.prepare(
                    "INSERT INTO policies (spiffe_id,resource,action,effect,created_by)
                     VALUES (?,?,?,?,?) RETURNING policy_id"
                )?;
                let mut rows = stmt.query(duckdb::params![spiffe_id, resource, action, effect, created_by])?;
                let row = rows.next()?.ok_or_else(|| anyhow::anyhow!("no policy_id returned"))?;
                let id_str: String = row.get(0)?;
                Ok::<_, anyhow::Error>(Uuid::parse_str(&id_str).unwrap())
            }).await?
        }
    }
}

pub async fn decide(
    db: &Database,
    spiffe_id: &str, resource: &str, action: &str,
) -> anyhow::Result<Option<PolicyDecision>> {
    // Common SQL that works on Postgres and DuckDB (both support CASE, LIMIT).
    // SQLite uses ? placeholders; PG/DuckDB use $N — we handle both.
    match db {
        Database::Postgres(pool) => {
            #[derive(sqlx::FromRow)]
            struct Row { effect: String }
            let r = sqlx::query_as::<_, Row>(
                "SELECT effect FROM policies
                 WHERE spiffe_id=$1 AND (resource=$2 OR resource='*') AND (action=$3 OR action='*')
                 ORDER BY CASE WHEN resource='*' THEN 1 ELSE 0 END,
                          CASE WHEN action='*'   THEN 1 ELSE 0 END, created_at DESC
                 LIMIT 1"
            ).bind(spiffe_id).bind(resource).bind(action).fetch_optional(pool).await?;
            Ok(r.map(|r| PolicyDecision { effect: r.effect }))
        }
        Database::Sqlite(pool) => {
            let r = sqlx::query_scalar::<_, String>(
                "SELECT effect FROM policies
                 WHERE spiffe_id=? AND (resource=? OR resource='*') AND (action=? OR action='*')
                 ORDER BY CASE WHEN resource='*' THEN 1 ELSE 0 END,
                          CASE WHEN action='*'   THEN 1 ELSE 0 END, created_at DESC
                 LIMIT 1"
            ).bind(spiffe_id).bind(resource).bind(action).fetch_optional(pool).await?;
            Ok(r.map(|effect| PolicyDecision { effect }))
        }
        Database::DuckDb(pool) => {
            let pool = pool.clone();
            let spiffe_id = spiffe_id.to_string();
            let resource = resource.to_string();
            let action = action.to_string();
            tokio::task::spawn_blocking(move || {
                let conn = pool.get()?;
                let mut stmt = conn.prepare(
                    "SELECT effect FROM policies
                     WHERE spiffe_id=? AND (resource=? OR resource='*') AND (action=? OR action='*')
                     ORDER BY CASE WHEN resource='*' THEN 1 ELSE 0 END,
                              CASE WHEN action='*'   THEN 1 ELSE 0 END, created_at DESC
                     LIMIT 1"
                )?;
                let mut rows = stmt.query(duckdb::params![spiffe_id, resource, action])?;
                match rows.next()? {
                    None => Ok(None),
                    Some(row) => Ok(Some(PolicyDecision { effect: row.get(0)? })),
                }
            }).await?
        }
    }
}
