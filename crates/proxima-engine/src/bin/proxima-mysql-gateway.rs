use proxima_engine::mysql_gateway::run_mysql_gateway;
use proxima_engine::mysql_identity::MysqlIdentityRegistry;

use std::env;
use std::net::SocketAddr;
use std::sync::Arc;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .init();

    let registry_path = env::var("PROXIMA_MYSQL_IDENTITY_REGISTRY")
        .map_err(|_| "PROXIMA_MYSQL_IDENTITY_REGISTRY is required")?;

    let address: SocketAddr = env::var("PROXIMA_MYSQL_LISTEN_ADDR")
        .unwrap_or_else(|_| "127.0.0.1:3307".to_string())
        .parse()?;

    let registry = Arc::new(MysqlIdentityRegistry::load(registry_path)?);

    tracing::info!(
        principals = registry.principal_count(),
        "MySQL identity registry loaded"
    );

    run_mysql_gateway(address, registry).await?;

    Ok(())
}
