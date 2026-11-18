//! Verified-TLS MySQL 8.4 upstream connector.
//!
//! This module connects only with a tenant-specific runtime account. It
//! validates the upstream greeting, requires verified TLS, performs the
//! caching_sha2_password handshake, and never sends the password outside TLS.
use crate::auth::AuthenticatedTenantSession;
use crate::protocol::{
    validate_client_capabilities, verify_sequence, Packet, ProtocolError, ServerHandshake,
    CLIENT_CONNECT_WITH_DB, CLIENT_PLUGIN_AUTH, CLIENT_PLUGIN_AUTH_LENENC_CLIENT_DATA,
    CLIENT_PROTOCOL_41, CLIENT_SECURE_CONNECTION, CLIENT_SSL, MAX_PACKET_PAYLOAD,
    CLIENT_LONG_PASSWORD, CLIENT_LONG_FLAG, CLIENT_TRANSACTIONS, CLIENT_MULTI_RESULTS,
    CLIENT_PS_MULTI_RESULTS, CLIENT_SESSION_TRACK, CLIENT_DEPRECATE_EOF,
    MIN_HANDSHAKE_PACKET_SIZE,
};
use rustls::pki_types::ServerName;
use rustls::{ClientConfig, RootCertStore};
use sha2::{Digest, Sha256};
use std::fs::File;
use std::io::BufReader;
use std::time::Duration;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::time::timeout;
use tokio_rustls::client::TlsStream;
use tokio_rustls::TlsConnector;
use zeroize::{Zeroize, Zeroizing};

pub struct UpstreamTlsConfig {
    host: String,
    port: u16,
    server_name: ServerName<'static>,
    connector: TlsConnector,
    connect_timeout: Duration,
    handshake_timeout: Duration,
    max_packet_size: usize,
}

impl UpstreamTlsConfig {
    pub fn max_packet_size(&self) -> usize {
        self.max_packet_size
    }

    pub fn from_ca_file(
        host: String,
        port: u16,
        server_name: String,
        ca_file: &str,
        connect_timeout: Duration,
        handshake_timeout: Duration,
        max_packet_size: usize,
    ) -> Result<Self, UpstreamError> {
        if host.is_empty() || port == 0 || connect_timeout.is_zero() || handshake_timeout.is_zero()
            || max_packet_size < MIN_HANDSHAKE_PACKET_SIZE || max_packet_size >= MAX_PACKET_PAYLOAD {
            return Err(UpstreamError::InvalidConfiguration);
        }
        let server_name = ServerName::try_from(server_name)
            .map_err(|_| UpstreamError::InvalidConfiguration)?;

        let file = File::open(ca_file).map_err(|_| UpstreamError::InvalidConfiguration)?;
        let mut reader = BufReader::new(file);
        let certificates = rustls_pemfile::certs(&mut reader)
            .collect::<Result<Vec<_>, _>>()
            .map_err(|_| UpstreamError::InvalidConfiguration)?;
        if certificates.is_empty() {
            return Err(UpstreamError::InvalidConfiguration);
        }

        let mut roots = RootCertStore::empty();
        for certificate in certificates {
            roots.add(certificate).map_err(|_| UpstreamError::InvalidConfiguration)?;
        }

        let _ = rustls::crypto::ring::default_provider().install_default();
        let client_config = ClientConfig::builder()
            .with_root_certificates(roots)
            .with_no_client_auth();

        Ok(Self {
            host,
            port,
            server_name,
            connector: TlsConnector::from(std::sync::Arc::new(client_config)),
            connect_timeout,
            handshake_timeout,
            max_packet_size,
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum UpstreamError {
    InvalidConfiguration,
    ConnectTimeout,
    TlsHandshakeFailed,
    TransportFailed,
    InvalidServerGreeting,
    UnsupportedServerCapabilities,
    UnsupportedAuthenticationPlugin,
    AuthenticationRejected,
    UnexpectedAuthenticationPacket,
    Protocol(ProtocolError),
}
impl std::fmt::Display for UpstreamError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InvalidConfiguration => write!(f, "invalid MySQL upstream TLS configuration"),
            Self::ConnectTimeout => write!(f, "MySQL upstream connection timed out"),
            Self::TlsHandshakeFailed => write!(f, "MySQL upstream TLS verification failed"),
            Self::TransportFailed => write!(f, "MySQL upstream transport failed"),
            Self::InvalidServerGreeting => write!(f, "invalid MySQL upstream server greeting"),
            Self::UnsupportedServerCapabilities => write!(f, "MySQL upstream server lacks required secure protocol capabilities"),
            Self::UnsupportedAuthenticationPlugin => write!(f, "MySQL upstream server requires an unsupported authentication plugin"),
            Self::AuthenticationRejected => write!(f, "MySQL upstream tenant account authentication was rejected"),
            Self::UnexpectedAuthenticationPacket => write!(f, "unexpected MySQL upstream authentication packet"),
            Self::Protocol(error) => write!(f, "MySQL upstream protocol error: {error}"),
        }
    }
}
impl std::error::Error for UpstreamError {}
impl From<ProtocolError> for UpstreamError {
    fn from(value: ProtocolError) -> Self { Self::Protocol(value) }
}

pub async fn connect_upstream(
    config: &UpstreamTlsConfig,
    session: &AuthenticatedTenantSession,
) -> Result<TlsStream<TcpStream>, UpstreamError> {
    validate_session_identity(session)?;
    connect_authenticated(
        config,
        &session.upstream_username,
        &session.upstream_password,
        Some(&session.database_name),
    ).await
}

/// Connect with a trusted MySQL administrative account. This is reserved for
/// the provisioning executor; application sessions must use connect_upstream.
pub async fn connect_admin(
    config: &UpstreamTlsConfig,
    username: &str,
    password: &str,
) -> Result<TlsStream<TcpStream>, UpstreamError> {
    if username.is_empty()
        || username.len() > 32
        || username.bytes().any(|byte| byte == 0 || byte.is_ascii_control())
        || password.is_empty()
        || password.len() > 1024
    {
        return Err(UpstreamError::InvalidConfiguration);
    }
    connect_authenticated(config, username, password, None).await
}

async fn connect_authenticated(
    config: &UpstreamTlsConfig,
    username: &str,
    password: &str,
    database: Option<&str>,
) -> Result<TlsStream<TcpStream>, UpstreamError> {
    let tcp = timeout(
        config.connect_timeout,
        TcpStream::connect((config.host.as_str(), config.port)),
    )
    .await
    .map_err(|_| UpstreamError::ConnectTimeout)?
    .map_err(|_| UpstreamError::TransportFailed)?;

    let mut tcp = tcp;
    let greeting_packet = timeout(
        config.handshake_timeout,
        read_packet(&mut tcp, config.max_packet_size),
    )
    .await
    .map_err(|_| UpstreamError::ConnectTimeout)??;
    verify_sequence(&greeting_packet, 0)?;
    let greeting = ServerHandshake::parse(&greeting_packet.payload)
        .map_err(|_| UpstreamError::InvalidServerGreeting)?;

    if greeting.auth_plugin_name.as_deref() != Some("caching_sha2_password")
        || greeting.auth_plugin_data.len() != 20
    {
        return Err(UpstreamError::UnsupportedAuthenticationPlugin);
    }

    let mut client_flags = CLIENT_LONG_PASSWORD
        | CLIENT_LONG_FLAG
        | CLIENT_PROTOCOL_41
        | CLIENT_SSL
        | CLIENT_TRANSACTIONS
        | CLIENT_SECURE_CONNECTION
        | CLIENT_MULTI_RESULTS
        | CLIENT_PS_MULTI_RESULTS
        | CLIENT_PLUGIN_AUTH
        | CLIENT_PLUGIN_AUTH_LENENC_CLIENT_DATA
        | CLIENT_SESSION_TRACK
        | CLIENT_DEPRECATE_EOF;
    if database.is_some() {
        client_flags |= CLIENT_CONNECT_WITH_DB;
    }
    validate_client_capabilities(client_flags, greeting.capability_flags)
        .map_err(|_| UpstreamError::UnsupportedServerCapabilities)?;

    let ssl_request = Packet {
        sequence: 1,
        payload: build_ssl_request(client_flags),
    };
    write_packet(&mut tcp, &ssl_request, config.max_packet_size).await?;

    let mut upstream = timeout(
        config.handshake_timeout,
        config.connector.connect(config.server_name.clone(), tcp),
    )
    .await
    .map_err(|_| UpstreamError::ConnectTimeout)?
    .map_err(|_| UpstreamError::TlsHandshakeFailed)?;

    let challenge: [u8; 20] = greeting.auth_plugin_data
        .as_slice()
        .try_into()
        .map_err(|_| UpstreamError::InvalidServerGreeting)?;
    let response = build_handshake_response(
        username,
        password,
        database,
        &challenge,
        client_flags,
        config.max_packet_size,
    );
    write_packet(
        &mut upstream,
        &Packet { sequence: 2, payload: response },
        config.max_packet_size,
    )
    .await?;

    let auth_packet = timeout(
        config.handshake_timeout,
        read_packet(&mut upstream, config.max_packet_size),
    )
    .await
    .map_err(|_| UpstreamError::ConnectTimeout)??;
    verify_sequence(&auth_packet, 3)?;

    match auth_packet.payload.as_slice() {
        [0x00, ..] => Ok(upstream),
        [0x01, 0x03] => {
            let ok = timeout(
                config.handshake_timeout,
                read_packet(&mut upstream, config.max_packet_size),
            )
            .await
            .map_err(|_| UpstreamError::ConnectTimeout)??;
            verify_sequence(&ok, 4)?;
            ensure_ok(&ok)?;
            Ok(upstream)
        }
        [0x01, 0x04] => {
            let mut clear_password = password.as_bytes().to_vec();
            clear_password.push(0);
            let mut packet = Packet { sequence: 4, payload: clear_password };
            let write_result = write_packet(
                &mut upstream,
                &packet,
                config.max_packet_size,
            )
            .await;
            packet.payload.zeroize();
            write_result?;
            let ok = timeout(
                config.handshake_timeout,
                read_packet(&mut upstream, config.max_packet_size),
            )
            .await
            .map_err(|_| UpstreamError::ConnectTimeout)??;
            verify_sequence(&ok, 5)?;
            ensure_ok(&ok)?;
            Ok(upstream)
        }
        [0xff, ..] => Err(UpstreamError::AuthenticationRejected),
        _ => Err(UpstreamError::UnexpectedAuthenticationPacket),
    }
}

fn validate_session_identity(session: &AuthenticatedTenantSession) -> Result<(), UpstreamError> {
    let expected_database = format!("ap_t_{}", session.tenant_id.simple());
    let digest = Sha256::digest(session.tenant_id.as_bytes());
    let expected_username = format!("ap_r_{}", &hex::encode(digest)[..27]);
    if session.database_name != expected_database
        || session.upstream_username != expected_username
        || session.upstream_password.len() != 64
        || !session.upstream_password.bytes().all(|byte| byte.is_ascii_hexdigit())
    {
        return Err(UpstreamError::InvalidConfiguration);
    }
    Ok(())
}

fn build_ssl_request(capabilities: u32) -> Vec<u8> {
    let mut payload = Vec::with_capacity(32);
    payload.extend_from_slice(&capabilities.to_le_bytes());
    payload.extend_from_slice(&(MAX_PACKET_PAYLOAD as u32).to_le_bytes());
    payload.push(45);
    payload.extend_from_slice(&[0u8; 23]);
    payload
}

fn build_handshake_response(
    username: &str,
    password: &str,
    database: Option<&str>,
    challenge: &[u8; 20],
    capabilities: u32,
    max_packet_size: usize,
) -> Vec<u8> {
    let auth = caching_sha2_response(password.as_bytes(), challenge);
    let mut payload = Vec::with_capacity(128);
    payload.extend_from_slice(&capabilities.to_le_bytes());
    payload.extend_from_slice(&(max_packet_size as u32).to_le_bytes());
    payload.push(45);
    payload.extend_from_slice(&[0u8; 23]);
    payload.extend_from_slice(username.as_bytes());
    payload.push(0);
    payload.push(auth.len() as u8);
    payload.extend_from_slice(&auth);
    if let Some(database) = database {
        payload.extend_from_slice(database.as_bytes());
        payload.push(0);
    }
    payload.extend_from_slice(b"caching_sha2_password\0");
    payload
}

fn caching_sha2_response(password: &[u8], challenge: &[u8; 20]) -> Vec<u8> {
    let stage_one = Sha256::digest(password);
    let stage_two = Sha256::digest(stage_one);
    let mut material = Vec::with_capacity(52);
    material.extend_from_slice(&stage_two);
    material.extend_from_slice(challenge);
    let mask = Sha256::digest(material);
    stage_one.iter().zip(mask.iter()).map(|(left, right)| left ^ right).collect()
}

pub(crate) async fn read_packet<R: AsyncRead + Unpin>(
    reader: &mut R,
    max_packet_size: usize,
) -> Result<Packet, UpstreamError> {
    let mut header = [0u8; 4];
    reader.read_exact(&mut header).await.map_err(|_| UpstreamError::TransportFailed)?;
    let length = header[0] as usize
        | ((header[1] as usize) << 8)
        | ((header[2] as usize) << 16);
    if length > max_packet_size || length >= MAX_PACKET_PAYLOAD {
        return Err(UpstreamError::Protocol(ProtocolError::PacketTooLarge));
    }
    let mut payload = vec![0u8; length];
    reader.read_exact(&mut payload).await.map_err(|_| UpstreamError::TransportFailed)?;
    Ok(Packet { sequence: header[3], payload })
}

pub(crate) async fn write_packet<W: AsyncWrite + Unpin>(
    writer: &mut W,
    packet: &Packet,
    max_packet_size: usize,
) -> Result<(), UpstreamError> {
    let mut frame = packet.encode(max_packet_size)?;
    let write_result = async {
        writer.write_all(&frame).await.map_err(|_| UpstreamError::TransportFailed)?;
        writer.flush().await.map_err(|_| UpstreamError::TransportFailed)
    }.await;
    frame.zeroize();
    write_result
}

fn ensure_ok(packet: &Packet) -> Result<(), UpstreamError> {
    if packet.payload.first() == Some(&0x00) {
        Ok(())
    } else if packet.payload.first() == Some(&0xff) {
        Err(UpstreamError::AuthenticationRejected)
    } else {
        Err(UpstreamError::UnexpectedAuthenticationPacket)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::auth::AuthenticatedTenantSession;
    use uuid::Uuid;

    #[test]
    fn caching_sha2_response_is_32_bytes_and_challenge_dependent() {
        let challenge_a = [1u8; 20];
        let challenge_b = [2u8; 20];
        let a = caching_sha2_response(b"high-entropy-password", &challenge_a);
        let b = caching_sha2_response(b"high-entropy-password", &challenge_b);
        assert_eq!(a.len(), 32);
        assert_ne!(a, b);
    }

    #[test]
    fn upstream_identity_must_be_derived_from_tenant_uuid() {
        let tenant = Uuid::new_v4();
        let session = AuthenticatedTenantSession {
            tenant_id: tenant,
            database_name: format!("ap_t_{}", tenant.simple()),
            assertion_expires_at: 1_000,
            tenant_assertion: "test-assertion".into(),
            upstream_username: "root".into(),
            upstream_password: "a".repeat(64),
        };
        assert_eq!(validate_session_identity(&session), Err(UpstreamError::InvalidConfiguration));
    }

    #[test]
    fn ssl_request_has_exact_protocol_length() {
        let payload = build_ssl_request(
            CLIENT_PROTOCOL_41 | CLIENT_SSL | CLIENT_SECURE_CONNECTION
        );
        assert_eq!(payload.len(), 32);
        assert!(crate::protocol::is_ssl_request(&payload).unwrap());
    }
}
