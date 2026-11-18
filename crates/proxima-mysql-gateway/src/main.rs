use proxima_mysql_gateway::{
    listener::{GatewayConfig, MySqlGateway},
    store::EncryptedTenantStore,
    upstream::UpstreamTlsConfig,
};
use std::{env, net::SocketAddr, path::PathBuf, sync::Arc, time::Duration};
use tracing::{error, info};
use tracing_subscriber::EnvFilter;

fn required(name: &str) -> Result<String, String> {
    env::var(name)
        .map(|value| value.trim().to_owned())
        .map_err(|_| format!("required environment variable {name} is missing"))
        .and_then(|value| {
            if value.is_empty() {
                Err(format!("required environment variable {name} is empty"))
            } else {
                Ok(value)
            }
        })
}

fn parse_u64(name: &str, default: u64) -> Result<u64, String> {
    match env::var(name) {
        Ok(value) => value.parse::<u64>()
            .map_err(|_| format!("{name} must be an unsigned integer")),
        Err(_) => Ok(default),
    }
}

fn parse_usize(name: &str, default: usize) -> Result<usize, String> {
    match env::var(name) {
        Ok(value) => value.parse::<usize>()
            .map_err(|_| format!("{name} must be an unsigned integer")),
        Err(_) => Ok(default),
    }
}

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")))
        .with_target(false)
        .init();

    if let Err(error) = run().await {
        error!(%error, "Proxima MySQL gateway stopped");
        std::process::exit(1);
    }
}

async fn run() -> Result<(), String> {
    let listen_addr: SocketAddr = env::var("PROXIMA_MYSQL_LISTEN_ADDR")
        .unwrap_or_else(|_| "127.0.0.1:13306".into())
        .parse()
        .map_err(|_| "PROXIMA_MYSQL_LISTEN_ADDR must be a valid socket address".to_owned())?;

    let upstream_host = required("PROXIMA_MYSQL_UPSTREAM_HOST")?;
    let upstream_port = env::var("PROXIMA_MYSQL_UPSTREAM_PORT")
        .unwrap_or_else(|_| "3306".into())
        .parse::<u16>()
        .map_err(|_| "PROXIMA_MYSQL_UPSTREAM_PORT must be a valid TCP port".to_owned())?;
    let upstream_server_name = required("PROXIMA_MYSQL_UPSTREAM_SERVER_NAME")?;
    let upstream_ca_file = required("PROXIMA_MYSQL_UPSTREAM_CA_FILE")?;
    let client_certificate_file = required("PROXIMA_MYSQL_TLS_CERT_FILE")?;
    let client_private_key_file = required("PROXIMA_MYSQL_TLS_KEY_FILE")?;
    let store_file = PathBuf::from(required("PROXIMA_MYSQL_SECRET_STORE_FILE")?);
    let store_key_file = PathBuf::from(required("PROXIMA_MYSQL_SECRET_STORE_KEY_FILE")?);

    let connect_timeout = Duration::from_millis(parse_u64("PROXIMA_MYSQL_CONNECT_TIMEOUT_MS", 10_000)?);
    let handshake_timeout = Duration::from_millis(parse_u64("PROXIMA_MYSQL_HANDSHAKE_TIMEOUT_MS", 10_000)?);
    let max_connections = parse_usize("PROXIMA_MYSQL_MAX_CONNECTIONS", 256)?;
    let max_packet_size = parse_usize("PROXIMA_MYSQL_MAX_PACKET_SIZE", 16_777_214)?;

    let upstream = UpstreamTlsConfig::from_ca_file(
        upstream_host,
        upstream_port,
        upstream_server_name,
        &upstream_ca_file,
        connect_timeout,
        handshake_timeout,
        max_packet_size,
    ).map_err(|_| "invalid MySQL upstream TLS configuration; check host, port, server name, CA file and limits".to_owned())?;

    let store = Arc::new(
        EncryptedTenantStore::open(store_file, store_key_file)
            .map_err(|error| format!("cannot open encrypted MySQL tenant store: {error}"))?
    );
    let account_directory = store.clone();
    let credential_store = store;

    let config = GatewayConfig {
        listen_addr,
        client_certificate_file,
        client_private_key_file,
        upstream,
        max_connections,
        max_packet_size,
        handshake_timeout,
    };

    let gateway = MySqlGateway::new(
        config,
        account_directory,
        credential_store,
    ).map_err(|_| "invalid MySQL gateway configuration or client TLS certificate".to_owned())?;

    info!(%listen_addr, max_connections, "Proxima MySQL gateway starting; PostgreSQL listener remains separate");
    gateway.run().await.map_err(|error| error.to_string())
}
