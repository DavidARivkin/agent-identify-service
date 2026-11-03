/// JWT revocation store — either a real Redis connection or an
/// in-process DashMap used when REDIS_URL is not configured.
use std::{collections::HashMap, sync::{Arc, Mutex}, time::{Duration, Instant}};

#[derive(Clone)]
pub enum RevocationStore {
    Redis(redis::aio::ConnectionManager),
    Memory(Arc<Mutex<HashMap<String, Instant>>>),
}

impl RevocationStore {
    pub fn memory() -> Self {
        RevocationStore::Memory(Arc::new(Mutex::new(HashMap::new())))
    }

    pub async fn connect(url: &str) -> anyhow::Result<Self> {
        let mgr = redis::Client::open(url)?
            .get_connection_manager()
            .await
            .map_err(|e| anyhow::anyhow!("failed to connect to Redis: {e}"))?;
        Ok(RevocationStore::Redis(mgr))
    }

    pub async fn set_ex(&self, key: String, ttl_secs: u64) -> anyhow::Result<()> {
        match self {
            RevocationStore::Redis(mgr) => {
                let mut conn = mgr.clone();
                redis::cmd("SET")
                    .arg(&key).arg("1")
                    .arg("EX").arg(ttl_secs)
                    .query_async::<()>(&mut conn).await
                    .map_err(|e| anyhow::anyhow!("redis SET: {e}"))?;
            }
            RevocationStore::Memory(map) => {
                let expires_at = Instant::now() + Duration::from_secs(ttl_secs);
                map.lock().unwrap().insert(key, expires_at);
            }
        }
        Ok(())
    }

    pub async fn exists(&self, key: &str) -> anyhow::Result<bool> {
        match self {
            RevocationStore::Redis(mgr) => {
                let mut conn = mgr.clone();
                let v: Option<String> = redis::cmd("GET")
                    .arg(key)
                    .query_async(&mut conn).await
                    .map_err(|e| anyhow::anyhow!("redis GET: {e}"))?;
                Ok(v.is_some())
            }
            RevocationStore::Memory(map) => {
                let now = Instant::now();
                let map = map.lock().unwrap();
                Ok(map.get(key).map(|exp| *exp > now).unwrap_or(false))
            }
        }
    }

    /// Ping the store — used by the readiness check.
    pub async fn ping(&self) -> anyhow::Result<()> {
        match self {
            RevocationStore::Redis(mgr) => {
                let mut conn = mgr.clone();
                redis::cmd("PING").query_async::<()>(&mut conn).await
                    .map_err(|e| anyhow::anyhow!("redis PING: {e}"))?;
            }
            RevocationStore::Memory(_) => { /* always healthy */ }
        }
        Ok(())
    }

    pub fn is_memory(&self) -> bool {
        matches!(self, RevocationStore::Memory(_))
    }
}

