use proxima_engine::sqlserver_tds_gateway::{run, SqlServerTdsConfig};
use std::{io, path::PathBuf};

#[tokio::main]
async fn main() -> io::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(std::env::var("RUST_LOG").unwrap_or_else(|_| "info".to_owned()))
        .init();
    rustls::crypto::CryptoProvider::install_default(rustls::crypto::aws_lc_rs::default_provider())
        .map_err(|_| io::Error::other("failed to install AWS-LC TLS crypto provider"))?;
    let path = std::env::var_os("PROXIMA_SQLSERVER_TDS_CONFIG")
        .map(PathBuf::from)
        .ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidInput,
                "PROXIMA_SQLSERVER_TDS_CONFIG is required",
            )
        })?;
    let config = SqlServerTdsConfig::load(&path)?;
    run(config).await
}
