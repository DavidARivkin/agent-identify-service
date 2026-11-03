pub mod agents;
pub mod audit;
pub mod policies;

use anyhow::Context;
use std::sync::Arc;

/// Shared DuckDB connection pool type alias.
type DuckPool = Arc<r2d2::Pool<duckdb::DuckdbConnectionManager>>;

/// A cloneable, backend-agnostic database handle.
///
/// Variants:
/// - `DuckDb`  – embedded DuckDB file (default, no external service)
/// - `Sqlite`  – embedded SQLite via sqlx
/// - `Postgres` – external PostgreSQL via sqlx
#[derive(Clone)]
pub enum Database {
    DuckDb(DuckPool),
    Sqlite(sqlx::SqlitePool),
    Postgres(sqlx::PgPool),
}

impl Database {
    /// Ping the backing store — used by the readiness handler.
    pub async fn ping(&self) -> anyhow::Result<()> {
        match self {
            Database::Postgres(pool) => {
                sqlx::query("SELECT 1").execute(pool).await.context("postgres ping")?;
            }
            Database::Sqlite(pool) => {
                sqlx::query("SELECT 1").execute(pool).await.context("sqlite ping")?;
            }
            Database::DuckDb(pool) => {
                let pool = pool.clone();
                tokio::task::spawn_blocking(move || {
                    let conn = pool.get().context("duckdb pool get")?;
                    conn.execute_batch("SELECT 1").context("duckdb ping")
                })
                .await
                .context("spawn_blocking")?
                .context("duckdb ping")?;
            }
        }
        Ok(())
    }

    /// Open and migrate the database from config values.
    pub async fn connect(backend: &str, url: &str, max_conns: u32, timeout_secs: u64) -> anyhow::Result<Self> {
        match backend {
            "postgres" | "postgresql" => {
                let pool = sqlx::postgres::PgPoolOptions::new()
                    .max_connections(max_conns)
                    .acquire_timeout(std::time::Duration::from_secs(timeout_secs))
                    .connect(url)
                    .await
                    .context("failed to connect to PostgreSQL")?;
                sqlx::migrate!("./migrations/postgres")
                    .run(&pool)
                    .await
                    .context("postgres migrations failed")?;
                Ok(Database::Postgres(pool))
            }
            "sqlite" => {
                let pool = sqlx::sqlite::SqlitePoolOptions::new()
                    .max_connections(max_conns)
                    .acquire_timeout(std::time::Duration::from_secs(timeout_secs))
                    .connect(url)
                    .await
                    .context("failed to open SQLite database")?;
                sqlx::migrate!("./migrations/sqlite")
                    .run(&pool)
                    .await
                    .context("sqlite migrations failed")?;
                Ok(Database::Sqlite(pool))
            }
            "duckdb" => {
                let manager = if url == ":memory:" {
                    duckdb::DuckdbConnectionManager::memory()
                        .context("duckdb in-memory init")?
                } else {
                    duckdb::DuckdbConnectionManager::file(url)
                        .context("duckdb file init")?
                };
                let pool = Arc::new(
                    r2d2::Pool::builder()
                        .max_size(max_conns)
                        .connection_timeout(std::time::Duration::from_secs(timeout_secs))
                        .build(manager)
                        .context("duckdb pool build")?,
                );

                // Run migrations on a blocking thread
                let pool2 = pool.clone();
                tokio::task::spawn_blocking(move || {
                    let conn = pool2.get()?;
                    run_duckdb_migrations(&conn)
                })
                    .await
                    .context("spawn_blocking migration")?
                    .context("duckdb migrations failed")?;

                Ok(Database::DuckDb(pool))
            }
            other => anyhow::bail!("unknown database backend {:?} — use duckdb, sqlite, or postgres", other),
        }
    }
}

fn run_duckdb_migrations(conn: &duckdb::Connection) -> anyhow::Result<()> {
    conn.execute_batch(include_str!("../../migrations/duckdb/0001_create_agents.sql"))
        .context("duckdb migration 0001")?;
    conn.execute_batch(include_str!("../../migrations/duckdb/0002_create_policies.sql"))
        .context("duckdb migration 0002")?;
    conn.execute_batch(include_str!("../../migrations/duckdb/0003_create_audit_events.sql"))
        .context("duckdb migration 0003")?;
    Ok(())
}
