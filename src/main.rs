mod api; mod audit; mod auth; mod config; mod crypto; mod db; mod error; mod metrics; mod middleware; mod observability; mod revocation; mod state;

use crate::config::Config;
use crate::crypto::signer::{FileRsaSigner, Signer};
use crate::db::Database;
use crate::revocation::RevocationStore;
use crate::state::AppState;
use anyhow::Context;
use std::{net::SocketAddr, sync::Arc, time::Duration};
use tokio::signal;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let config = Arc::new(Config::from_env()?);
    config.validate()?;

    tracing_subscriber::fmt().json().with_env_filter(
        tracing_subscriber::EnvFilter::try_from_default_env()
            .unwrap_or_else(|_| "info,agent_identity_service=debug".into()),
    ).init();

    let prometheus = metrics::init_prometheus()?;

    // ── Database ──────────────────────────────────────────────────────────────
    let db = Database::connect(
        &config.database.backend,
        &config.database.url,
        config.database.max_connections,
        config.database.connect_timeout_seconds,
    ).await?;
    tracing::info!(backend = %config.database.backend, "database connected");

    // ── Revocation store (Redis optional) ─────────────────────────────────────
    let revocation = if config.redis.url.is_empty() {
        tracing::warn!("REDIS_URL not set — using in-memory revocation store (single-instance only)");
        RevocationStore::memory()
    } else {
        RevocationStore::connect(&config.redis.url).await
            .context("failed to connect to Redis")?
    };

    // ── Signing key ───────────────────────────────────────────────────────────
    let pem = match std::env::var("SIGNING_KEY_PEM") {
        Ok(val) if !val.trim().is_empty() => val,
        _ => std::fs::read_to_string(&config.crypto.private_key_path)
            .with_context(|| format!("failed to read signing key: {}", config.crypto.private_key_path))?,
    };
    let signer = FileRsaSigner::from_pem(
        config.crypto.signing_key_id.clone(),
        config.crypto.issuer.clone(),
        &pem,
    )?;

    let signer: Arc<dyn Signer> = Arc::new(signer);

    let audit = audit::AuditLogger::new(db.clone(), 10_000);

    let state = Arc::new(AppState {
        config: config.clone(), db, revocation,
        signer, audit, prometheus,
    });

    let app = api::router(state.clone());
    let addr: SocketAddr = config.service.bind_address.parse().context("invalid bind_address")?;

    if config.security.require_mtls {
        let tls = axum_server::tls_rustls::RustlsConfig::from_pem_file(
            config.security.mtls_server_cert_path.clone().unwrap(),
            config.security.mtls_server_key_path.clone().unwrap(),
        ).await.context("failed to load TLS material")?;

        let handle = axum_server::Handle::new();
        let shutdown_handle = handle.clone();

        tokio::spawn(async move {
            shutdown_signal().await;
            shutdown_handle.graceful_shutdown(Some(Duration::from_secs(30)));
        });

        tracing::info!(address=%addr, "starting Agent Identity Service with TLS");
        axum_server::bind_rustls(addr, tls).handle(handle)
            .serve(app.into_make_service()).await.context("TLS server failed")?;
    } else {
        if config.service.environment == "production" {
            anyhow::bail!("mTLS must be enabled in production");
        }
        let listener = tokio::net::TcpListener::bind(addr).await?;
        tracing::warn!(address=%addr, "starting WITHOUT TLS; development only");
        axum::serve(listener, app).with_graceful_shutdown(shutdown_signal()).await?;
    }
    Ok(())
}

async fn shutdown_signal() {
    let ctrl_c = async { signal::ctrl_c().await.expect("Ctrl+C handler failed"); };
    #[cfg(unix)]
    let terminate = async {
        signal::unix::signal(signal::unix::SignalKind::terminate())
            .expect("SIGTERM handler failed").recv().await;
    };
    #[cfg(not(unix))]
    let terminate = std::future::pending::<()>();
    tokio::select! { _ = ctrl_c => {}, _ = terminate => {} }
}
