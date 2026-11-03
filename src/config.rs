use serde::Deserialize;
use std::time::Duration;

#[derive(Debug, Clone, Deserialize)]
pub struct Config {
    pub service: ServiceConfig,
    pub database: DatabaseConfig,
    pub redis: RedisConfig,
    pub crypto: CryptoConfig,
    pub security: SecurityConfig,
}

#[derive(Debug, Clone, Deserialize)]
pub struct ServiceConfig {
    pub bind_address: String,
    pub trust_domain: String,
    pub environment: String,
    pub request_timeout_seconds: u64,
    pub max_body_bytes: usize,
}

#[derive(Debug, Clone, Deserialize)]
pub struct DatabaseConfig {
    /// Which backend to use: "duckdb" (default), "sqlite", or "postgres"
    #[serde(default = "DatabaseConfig::default_backend")]
    pub backend: String,
    /// Connection URL / file path.
    /// - DuckDB / SQLite: file path, e.g. "/app/data/agent_identity.db" or ":memory:"
    /// - Postgres: "postgres://user:pass@host/db"
    pub url: String,
    pub max_connections: u32,
    pub min_connections: u32,
    pub connect_timeout_seconds: u64,
}

impl DatabaseConfig {
    fn default_backend() -> String { "duckdb".into() }
}

#[derive(Debug, Clone, Deserialize)]
pub struct RedisConfig {
    /// Optional Redis URL.  Leave empty or omit REDIS_URL to use the
    /// built-in in-memory revocation store (suitable for single-instance
    /// development deployments).
    #[serde(default)]
    pub url: String,
    pub revocation_prefix: String,
}

#[derive(Debug, Clone, Deserialize)]
pub struct CryptoConfig {
    pub issuer: String,
    pub signing_key_id: String,
    pub default_svid_ttl_seconds: i64,
    pub max_svid_ttl_seconds: i64,
    pub private_key_path: String,
}

#[derive(Debug, Clone, Deserialize)]
pub struct SecurityConfig {
    pub require_mtls: bool,
    pub mtls_ca_cert_path: Option<String>,
    pub mtls_server_cert_path: Option<String>,
    pub mtls_server_key_path: Option<String>,
    pub development_identity_spiffe_id: Option<String>,
    pub allowed_control_plane_spiffe_ids: Vec<String>,
    pub rate_limit_per_second: u32,
    pub rate_limit_burst: u32,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum KeyProvider {
    File { private_key_path: String },
}

impl Config {
    pub fn from_env() -> anyhow::Result<Self> {
        let path = std::env::var("CONFIG_PATH").unwrap_or_else(|_| "config.yaml".into());
        let raw = std::fs::read_to_string(&path)
            .with_context(|| format!("failed to read config: {path}"))?;
        let mut config: Config = serde_yaml::from_str(&raw)
            .with_context(|| format!("invalid config: {path}"))?;
        if let Ok(url) = std::env::var("DATABASE_URL") { config.database.url = url; }
        if let Ok(url) = std::env::var("REDIS_URL") { config.redis.url = url; }
        if let Ok(env) = std::env::var("ENVIRONMENT").or_else(|_| std::env::var("SERVICE_ENVIRONMENT")) {
            config.service.environment = env;
        }
        if let Ok(key_path) = std::env::var("PRIVATE_KEY_PATH").or_else(|_| std::env::var("SIGNING_KEY_PATH")) {
            config.crypto.private_key_path = key_path;
        }
        Ok(config)
    }

    pub fn database_connect_timeout(&self) -> Duration {
        Duration::from_secs(self.database.connect_timeout_seconds)
    }

    pub fn validate(&self) -> anyhow::Result<()> {
        if self.service.trust_domain.trim().is_empty() { anyhow::bail!("trust_domain required"); }
        if self.crypto.issuer.trim().is_empty() { anyhow::bail!("issuer required"); }
        if self.crypto.default_svid_ttl_seconds <= 0 { anyhow::bail!("default TTL must be positive"); }
        if self.crypto.max_svid_ttl_seconds <= 0 || self.crypto.max_svid_ttl_seconds > 900 {
            anyhow::bail!("max SVID TTL must be 1-900 seconds");
        }
        if self.crypto.default_svid_ttl_seconds > self.crypto.max_svid_ttl_seconds {
            anyhow::bail!("default TTL exceeds maximum TTL");
        }
        if self.security.rate_limit_per_second == 0 || self.security.rate_limit_burst == 0 {
            anyhow::bail!("rate limits must be positive");
        }
        if self.service.environment == "production" {
            if !self.security.require_mtls { anyhow::bail!("mTLS required in production"); }
            let missing = [&self.security.mtls_ca_cert_path, &self.security.mtls_server_cert_path, &self.security.mtls_server_key_path]
                .iter().any(|p| p.is_none());
            if missing { anyhow::bail!("mTLS paths required in production"); }
            if self.security.allowed_control_plane_spiffe_ids.is_empty() {
                anyhow::bail!("control-plane SPIFFE IDs required in production");
            }
            if self.security.development_identity_spiffe_id.is_some() {
                anyhow::bail!("development identity must not be set in production");
            }
        }
        Ok(())
    }
}
use anyhow::Context;
