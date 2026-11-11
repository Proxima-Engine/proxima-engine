use crate::config::{Config, UpstreamTlsMode};
use rustls::crypto::ring;
use rustls::pki_types::{CertificateDer, PrivateKeyDer, ServerName};
use rustls::{ClientConfig, RootCertStore, ServerConfig};
use std::fs::File;
use std::io::{self, BufReader};
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio_rustls::{
    client::TlsStream as ClientTlsStream, server::TlsStream as ServerTlsStream, TlsAcceptor,
    TlsConnector,
};

pub fn client_acceptor(config: &Config) -> io::Result<Option<TlsAcceptor>> {
    // reqwest and rustls can enable multiple crypto providers through Cargo feature unification.
    // Install an explicit provider before any ServerConfig/ClientConfig builder is created.
    let _ = ring::default_provider().install_default();
    let (Some(cert_path), Some(key_path)) = (&config.tls_cert_file, &config.tls_key_file) else {
        return Ok(None);
    };

    let certs = load_certs(cert_path)?;
    let key = load_private_key(key_path)?;
    let server = ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(certs, key)
        .map_err(|error| {
            io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("invalid TLS certificate/key: {error}"),
            )
        })?;

    Ok(Some(TlsAcceptor::from(Arc::new(server))))
}

pub fn upstream_connector(config: &Config) -> io::Result<Option<TlsConnector>> {
    let _ = ring::default_provider().install_default();
    if config.upstream_tls_mode == UpstreamTlsMode::Disable {
        return Ok(None);
    }

    let ca_path = config.upstream_tls_ca_file.as_ref().ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            "upstream TLS CA file is required",
        )
    })?;

    let mut roots = RootCertStore::empty();
    for cert in load_certs(ca_path)? {
        roots.add(cert).map_err(|error| {
            io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("invalid upstream CA certificate: {error}"),
            )
        })?;
    }

    let client = ClientConfig::builder()
        .with_root_certificates(roots)
        .with_no_client_auth();

    Ok(Some(TlsConnector::from(Arc::new(client))))
}

pub async fn accept_client_tls(
    acceptor: &TlsAcceptor,
    stream: TcpStream,
    timeout_duration: std::time::Duration,
) -> io::Result<ServerTlsStream<TcpStream>> {
    tokio::time::timeout(timeout_duration, acceptor.accept(stream))
        .await
        .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "client TLS handshake timed out"))?
        .map_err(|error| {
            io::Error::new(
                io::ErrorKind::PermissionDenied,
                format!("client TLS handshake failed: {error}"),
            )
        })
}

pub async fn connect_upstream_tls(
    connector: &TlsConnector,
    mut stream: TcpStream,
    server_name: &str,
    timeout_duration: std::time::Duration,
) -> io::Result<ClientTlsStream<TcpStream>> {
    stream.write_all(&8i32.to_be_bytes()).await?;
    stream
        .write_all(&crate::protocol::SSL_REQUEST_CODE.to_be_bytes())
        .await?;

    let mut response = [0u8; 1];
    stream.read_exact(&mut response).await?;
    if response[0] != b'S' {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "PostgreSQL upstream rejected TLS",
        ));
    }

    let name = ServerName::try_from(server_name.to_owned()).map_err(|_| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            "invalid upstream TLS server name",
        )
    })?;

    tokio::time::timeout(timeout_duration, connector.connect(name, stream))
        .await
        .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "upstream TLS handshake timed out"))?
        .map_err(|error| {
            io::Error::new(
                io::ErrorKind::PermissionDenied,
                format!("upstream TLS handshake failed: {error}"),
            )
        })
}

fn load_certs(path: &str) -> io::Result<Vec<CertificateDer<'static>>> {
    let file = File::open(path)?;
    let mut reader = BufReader::new(file);
    rustls_pemfile::certs(&mut reader)
        .collect::<Result<Vec<_>, _>>()
        .map_err(|error| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                format!("failed to parse certificate PEM: {error}"),
            )
        })
}

fn load_private_key(path: &str) -> io::Result<PrivateKeyDer<'static>> {
    let file = File::open(path)?;
    let mut reader = BufReader::new(file);
    rustls_pemfile::private_key(&mut reader)
        .map_err(|error| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                format!("failed to parse private key PEM: {error}"),
            )
        })?
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "no private key found in PEM"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use tempfile::NamedTempFile;

    #[test]
    fn invalid_cert_file_is_rejected() {
        let mut file = NamedTempFile::new().unwrap();
        writeln!(file, "not a certificate").unwrap();
        let mut config = test_config();
        config.tls_cert_file = Some(file.path().to_string_lossy().into_owned());
        config.tls_key_file = Some(file.path().to_string_lossy().into_owned());
        assert!(client_acceptor(&config).is_err());
    }

    fn test_config() -> Config {
        Config {
            listen_addr: "127.0.0.1:6432".parse().unwrap(),
            upstream_addr: "127.0.0.1:5432".into(),
            tenant_signing_key: None,
            tenant_signing_key_previous: None,
            tenant_role_prefix: "proxima_tenant_".into(),
            upstream_connect_timeout: std::time::Duration::from_secs(1),
            max_connections: 10,
            tls_cert_file: None,
            tls_key_file: None,
            tls_handshake_timeout: std::time::Duration::from_secs(1),
            require_client_tls: false,
            upstream_tls_mode: UpstreamTlsMode::Disable,
            upstream_tls_ca_file: None,
            upstream_tls_server_name: None,
            upstream_tls_handshake_timeout: std::time::Duration::from_secs(1),
            dashboard_enabled: false,
            dashboard_listen_addr: "127.0.0.1:9080".parse().unwrap(),
        }
    }
}
