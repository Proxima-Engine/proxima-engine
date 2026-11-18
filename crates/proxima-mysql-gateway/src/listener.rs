//! Dedicated MySQL TLS listener and tenant-bound session relay.
//!
//! This listener is separate from the PostgreSQL proxy. It requires TLS from
//! clients, authenticates a gateway account, validates a signed tenant
//! assertion, obtains the tenant's runtime secret, and opens a verified-TLS
//! upstream session before acknowledging the client connection.

use crate::auth::{
    authenticate_and_resolve, TenantAccountDirectory, TenantUpstreamCredentialStore,
};
use crate::protocol::{
    encode_server_handshake, is_ssl_request, server_capabilities, verify_sequence, Command,
    CommandError, Packet, ProtocolError, CLIENT_SSL, MAX_PACKET_PAYLOAD,
    MIN_HANDSHAKE_PACKET_SIZE,
};
use crate::upstream::{
    connect_upstream, read_packet, write_packet, UpstreamError, UpstreamTlsConfig,
};
use crate::tenant::TenantAssertion;
use ring::rand::{SecureRandom, SystemRandom};
use rustls::{ServerConfig, pki_types::PrivateKeyDer};
use std::fs::File;
use std::io::BufReader;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tokio::io::AsyncWriteExt;
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{mpsc, Semaphore};
use tokio::time::timeout;
use tokio_rustls::{client::TlsStream as ClientTlsStream, server::TlsStream as ServerTlsStream, TlsAcceptor};
use zeroize::Zeroizing;

static NEXT_CONNECTION_ID: AtomicU32 = AtomicU32::new(1);

pub struct GatewayConfig {
    pub listen_addr: SocketAddr,
    pub client_certificate_file: String,
    pub client_private_key_file: String,
    pub upstream: UpstreamTlsConfig,
    pub max_connections: usize,
    pub max_packet_size: usize,
    pub handshake_timeout: Duration,
    pub idle_timeout: Duration,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum GatewayError {
    InvalidConfiguration,
    ListenerFailed,
    TransportFailed,
    ClientTlsFailed,
    ClientHandshakeRejected,
    AuthenticationRejected,
    Upstream(UpstreamError),
    Protocol(ProtocolError),
}
impl std::fmt::Display for GatewayError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InvalidConfiguration => write!(f, "invalid MySQL gateway configuration"),
            Self::ListenerFailed => write!(f, "MySQL gateway listener failed"),
            Self::TransportFailed => write!(f, "MySQL gateway transport failed"),
            Self::ClientTlsFailed => write!(f, "MySQL client TLS handshake failed"),
            Self::ClientHandshakeRejected => write!(f, "MySQL client handshake was rejected"),
            Self::AuthenticationRejected => write!(f, "MySQL gateway authentication or tenant authorization failed"),
            Self::Upstream(error) => write!(f, "MySQL upstream connection failed: {error}"),
            Self::Protocol(error) => write!(f, "MySQL gateway protocol error: {error}"),
        }
    }
}
impl std::error::Error for GatewayError {}
impl From<ProtocolError> for GatewayError {
    fn from(value: ProtocolError) -> Self { Self::Protocol(value) }
}

pub struct MySqlGateway {
    config: GatewayConfig,
    client_tls_acceptor: TlsAcceptor,
    account_directory: Arc<dyn TenantAccountDirectory>,
    credential_store: Arc<dyn TenantUpstreamCredentialStore>,
}

impl MySqlGateway {
    pub fn new(
        config: GatewayConfig,
        account_directory: Arc<dyn TenantAccountDirectory>,
        credential_store: Arc<dyn TenantUpstreamCredentialStore>,
    ) -> Result<Self, GatewayError> {
        if config.max_connections == 0
            || config.max_packet_size < MIN_HANDSHAKE_PACKET_SIZE
            || config.max_packet_size >= MAX_PACKET_PAYLOAD
            || config.handshake_timeout.is_zero()
            || config.idle_timeout.is_zero()
            || config.idle_timeout > Duration::from_secs(24 * 60 * 60)
        {
            return Err(GatewayError::InvalidConfiguration);
        }
        let client_tls_acceptor = load_client_tls_acceptor(
            &config.client_certificate_file,
            &config.client_private_key_file,
        )?;
        Ok(Self {
            config,
            client_tls_acceptor,
            account_directory,
            credential_store,
        })
    }

    pub async fn run(self) -> Result<(), GatewayError> {
        let listener = TcpListener::bind(self.config.listen_addr)
            .await
            .map_err(|_| GatewayError::ListenerFailed)?;
        let gateway = Arc::new(self);
        let permits = Arc::new(Semaphore::new(gateway.config.max_connections));

        loop {
            let (stream, _) = listener.accept().await.map_err(|_| GatewayError::ListenerFailed)?;
            let permit = Arc::clone(&permits)
                .acquire_owned()
                .await
                .map_err(|_| GatewayError::ListenerFailed)?;
            let gateway = Arc::clone(&gateway);
            tokio::spawn(async move {
                let _permit = permit;
                if let Err(error) = gateway.handle_client(stream).await {
                    tracing::warn!(error = %error, "MySQL gateway connection closed");
                }
            });
        }
    }

    async fn handle_client(&self, mut tcp: TcpStream) -> Result<(), GatewayError> {
        tcp.set_nodelay(true).map_err(|_| GatewayError::TransportFailed)?;
        let mut challenge = [0u8; 20];
        SystemRandom::new()
            .fill(&mut challenge)
            .map_err(|_| GatewayError::TransportFailed)?;
        let connection_id = NEXT_CONNECTION_ID.fetch_add(1, Ordering::Relaxed);
        let capabilities = server_capabilities(true);
        let greeting = encode_server_handshake(
            connection_id,
            &challenge,
            "Proxima-MySQL-0.1",
            true,
        )?;
        tcp.write_all(&greeting).await.map_err(|_| GatewayError::TransportFailed)?;

        let ssl_request = timeout(
            self.config.handshake_timeout,
            read_packet(&mut tcp, self.config.max_packet_size),
        )
        .await
        .map_err(|_| GatewayError::ClientHandshakeRejected)?
        .map_err(|_| GatewayError::ClientHandshakeRejected)?;
        verify_sequence(&ssl_request, 1)?;
        if !is_ssl_request(&ssl_request.payload)? {
            send_error(
                &mut tcp,
                2,
                1045,
                "28000",
                "TLS is required by the Proxima MySQL gateway",
                self.config.max_packet_size,
            )
            .await?;
            return Err(GatewayError::ClientTlsFailed);
        }
        let requested_flags = u32::from_le_bytes(
            ssl_request.payload[..4]
                .try_into()
                .map_err(|_| GatewayError::ClientHandshakeRejected)?,
        );
        let requested_max_packet_size = u32::from_le_bytes(
            ssl_request.payload[4..8]
                .try_into()
                .map_err(|_| GatewayError::ClientHandshakeRejected)?,
        );
        let requested_character_set = ssl_request.payload[8];
        crate::protocol::validate_client_capabilities(requested_flags, capabilities)?;

        let mut client = timeout(
            self.config.handshake_timeout,
            self.client_tls_acceptor.accept(tcp),
        )
        .await
        .map_err(|_| GatewayError::ClientTlsFailed)?
        .map_err(|_| GatewayError::ClientTlsFailed)?;

        let handshake_packet = timeout(
            self.config.handshake_timeout,
            read_packet(&mut client, self.config.max_packet_size),
        )
        .await
        .map_err(|_| GatewayError::ClientHandshakeRejected)?
        .map_err(|_| GatewayError::ClientHandshakeRejected)?;
        verify_sequence(&handshake_packet, 2)?;
        if handshake_packet.payload.len() < 4 {
            send_error(
                &mut client,
                3,
                1045,
                "28000",
                "Invalid MySQL handshake response",
                self.config.max_packet_size,
            )
            .await?;
            return Err(GatewayError::ClientHandshakeRejected);
        }
        let client_flags = u32::from_le_bytes(
            handshake_packet.payload[..4]
                .try_into()
                .map_err(|_| GatewayError::ClientHandshakeRejected)?,
        );
        if client_flags & CLIENT_SSL == 0 {
            send_error(
                &mut client,
                3,
                1045,
                "28000",
                "TLS is required by the Proxima MySQL gateway",
                self.config.max_packet_size,
            )
            .await?;
            return Err(GatewayError::ClientTlsFailed);
        }
        crate::protocol::validate_client_capabilities(client_flags, capabilities)?;

        let handshake = match crate::protocol::ClientHandshake::parse(
            &handshake_packet.payload,
            1024,
            16 * 1024,
        ) {
            Ok(value) => value,
            Err(_) => {
                send_error(
                    &mut client,
                    3,
                    1045,
                    "28000",
                    "Invalid MySQL handshake response",
                    self.config.max_packet_size,
                )
                .await?;
                return Err(GatewayError::ClientHandshakeRejected);
            }
        };

        if handshake.capability_flags != requested_flags
            || handshake.max_packet_size != requested_max_packet_size
            || handshake.character_set != requested_character_set
        {
            send_error(
                &mut client,
                3,
                1045,
                "28000",
                "MySQL TLS and handshake capabilities do not match",
                self.config.max_packet_size,
            ).await?;
            return Err(GatewayError::ClientHandshakeRejected);
        }

        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|_| GatewayError::TransportFailed)?
            .as_secs();
        let session = match authenticate_and_resolve(
            &handshake,
            &challenge,
            true,
            self.account_directory.as_ref(),
            now,
            self.credential_store.as_ref(),
        ) {
            Ok(session) => session,
            Err(_) => {
                send_error(
                    &mut client,
                    3,
                    1045,
                    "28000",
                    "Invalid MySQL gateway credentials or tenant context",
                    self.config.max_packet_size,
                )
                .await?;
                return Err(GatewayError::AuthenticationRejected);
            }
        };

        let upstream = match connect_upstream(&self.config.upstream, &session).await {
            Ok(upstream) => upstream,
            Err(error) => {
                send_error(
                    &mut client,
                    3,
                    1042,
                    "08S01",
                    "The tenant database is unavailable",
                    self.config.max_packet_size,
                )
                .await?;
                return Err(GatewayError::Upstream(error));
            }
        };

        // caching_sha2_password requires an AuthMoreData fast-auth-success
        // packet before the final OK packet. Preserve the MySQL handshake
        // sequence numbers: greeting=0, SSL request=1, response=2,
        // AuthMoreData=3, OK=4.
        let fast_auth_success = Packet {
            sequence: 3,
            payload: vec![0x01, 0x03],
        };
        write_packet(&mut client, &fast_auth_success, self.config.max_packet_size)
            .await
            .map_err(|_| GatewayError::TransportFailed)?;

        let ok = Packet {
            sequence: 4,
            payload: vec![0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00],
        };
        write_packet(&mut client, &ok, self.config.max_packet_size)
            .await
            .map_err(|_| GatewayError::TransportFailed)?;

        let gateway_username = handshake.username.clone();
        let tenant_id = session.tenant_id;
        let tenant_assertion = Zeroizing::new(session.tenant_assertion.clone());
        let assertion_expires_at = session.assertion_expires_at;
        relay_session(
            client,
            upstream,
            self.config.max_packet_size,
            self.config.idle_timeout,
            Arc::clone(&self.account_directory),
            Arc::clone(&self.credential_store),
            gateway_username,
            tenant_id,
            tenant_assertion,
            assertion_expires_at,
        ).await
    }
}

fn load_client_tls_acceptor(cert_file: &str, key_file: &str) -> Result<TlsAcceptor, GatewayError> {
    let cert_file = File::open(cert_file).map_err(|_| GatewayError::InvalidConfiguration)?;
    let mut cert_reader = BufReader::new(cert_file);
    let certificates = rustls_pemfile::certs(&mut cert_reader)
        .collect::<Result<Vec<_>, _>>()
        .map_err(|_| GatewayError::InvalidConfiguration)?;
    if certificates.is_empty() {
        return Err(GatewayError::InvalidConfiguration);
    }

    let key_file = File::open(key_file).map_err(|_| GatewayError::InvalidConfiguration)?;
    let mut key_reader = BufReader::new(key_file);
    let private_key: PrivateKeyDer<'static> = rustls_pemfile::private_key(&mut key_reader)
        .map_err(|_| GatewayError::InvalidConfiguration)?
        .ok_or(GatewayError::InvalidConfiguration)?;

    let _ = rustls::crypto::ring::default_provider().install_default();
    let server_config = ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(certificates, private_key)
        .map_err(|_| GatewayError::InvalidConfiguration)?;
    Ok(TlsAcceptor::from(Arc::new(server_config)))
}

async fn send_error<W: tokio::io::AsyncWrite + Unpin>(
    writer: &mut W,
    sequence: u8,
    code: u16,
    sql_state: &str,
    message: &str,
    max_packet_size: usize,
) -> Result<(), GatewayError> {
    let mut payload = vec![0xff];
    payload.extend_from_slice(&code.to_le_bytes());
    payload.push(b'#');
    let state = if sql_state.len() == 5 { sql_state } else { "HY000" };
    payload.extend_from_slice(state.as_bytes());
    payload.extend_from_slice(message.as_bytes());
    write_packet(
        writer,
        &Packet { sequence, payload },
        max_packet_size,
    )
    .await
    .map_err(|_| GatewayError::TransportFailed)
}

async fn relay_session(
    client: ServerTlsStream<TcpStream>,
    upstream: ClientTlsStream<TcpStream>,
    max_packet_size: usize,
    idle_timeout: Duration,
    account_directory: Arc<dyn TenantAccountDirectory>,
    credential_store: Arc<dyn TenantUpstreamCredentialStore>,
    gateway_username: String,
    tenant_id: uuid::Uuid,
    tenant_assertion: Zeroizing<String>,
    assertion_expires_at: u64,
) -> Result<(), GatewayError> {
    let (mut client_reader, mut client_writer) = tokio::io::split(client);
    let (mut upstream_reader, mut upstream_writer) = tokio::io::split(upstream);
    let (server_tx, mut server_rx) = mpsc::channel::<Packet>(32);
    let (local_tx, mut local_rx) = mpsc::channel::<Packet>(8);
    let (activity_tx, mut activity_rx) = mpsc::channel::<()>(8);
    let log_gateway_username = gateway_username.clone();

    let server_reader = tokio::spawn(async move {
        loop {
            match read_packet(&mut upstream_reader, max_packet_size).await {
                Ok(packet) => {
                    if server_tx.send(packet).await.is_err() { break; }
                }
                Err(_) => break,
            }
        }
    });

    let client_reader_task = tokio::spawn(async move {
        loop {
            let packet = match read_packet(&mut client_reader, max_packet_size).await {
                Ok(packet) => packet,
                Err(_) => break,
            };
            if activity_tx.send(()).await.is_err() {
                break;
            }
            if verify_sequence(&packet, 0).is_err() {
                let error = command_error_packet(1, "Invalid MySQL command packet sequence");
                let _ = local_tx.send(error).await;
                break;
            }
            match Command::parse(&packet.payload) {
                Ok(Command::Quit) => {
                    let _ = write_packet(&mut upstream_writer, &packet, max_packet_size).await;
                    break;
                }
                Ok(_) => {
                    let now = SystemTime::now()
                        .duration_since(UNIX_EPOCH)
                        .map(|duration| duration.as_secs())
                        .unwrap_or(u64::MAX);
                    if now >= assertion_expires_at {
                        let error = command_error_packet(
                            packet.sequence.wrapping_add(1),
                            "Tenant assertion has expired",
                        );
                        let _ = local_tx.send(error).await;
                        break;
                    }
                    let assertion_valid = session_assertion_is_current(
                        credential_store.as_ref(),
                        &tenant_assertion,
                        tenant_id,
                        assertion_expires_at,
                        now,
                    );
                    if !assertion_valid {
                        let error = command_error_packet(
                            packet.sequence.wrapping_add(1),
                            "Tenant assertion is expired or no longer trusted",
                        );
                        let _ = local_tx.send(error).await;
                        break;
                    }
                    // Re-check the local registry at every command boundary.
                    // The admin CLI updates the encrypted file atomically, so
                    // a revoked account cannot continue issuing new commands
                    // through an already-open client connection.
                    let still_authorized = matches!(
                        account_directory.find_account(&gateway_username),
                        Ok(Some(account)) if account.tenant_id == tenant_id
                    );
                    if !still_authorized {
                        let error = command_error_packet(
                            packet.sequence.wrapping_add(1),
                            "Tenant authorization has been revoked",
                        );
                        let _ = local_tx.send(error).await;
                        break;
                    }
                    if write_packet(&mut upstream_writer, &packet, max_packet_size).await.is_err() {
                        break;
                    }
                }
                Err(CommandError::ForbiddenTenantSwitch(_)) => {
                    let error = command_error_packet(
                        packet.sequence.wrapping_add(1),
                        "Changing database or authentication context is forbidden",
                    );
                    if local_tx.send(error).await.is_err() { break; }
                }
                Err(_) => {
                    let error = command_error_packet(
                        packet.sequence.wrapping_add(1),
                        "Unsupported MySQL command",
                    );
                    let _ = local_tx.send(error).await;
                    break;
                }
            }
        }
    });

    let mut server_closed = false;
    let mut local_closed = false;
    let mut activity_closed = false;
    let idle_sleep = tokio::time::sleep(idle_timeout);
    tokio::pin!(idle_sleep);
    while !(server_closed && local_closed) {
        tokio::select! {
            _ = &mut idle_sleep => {
                tracing::debug!(%tenant_id, gateway_username = %log_gateway_username, "closing idle MySQL tenant session");
                break;
            }
            activity = activity_rx.recv(), if !activity_closed => {
                match activity {
                    Some(()) => idle_sleep.as_mut().reset(tokio::time::Instant::now() + idle_timeout),
                    None => activity_closed = true,
                }
            }
            packet = server_rx.recv(), if !server_closed => {
                match packet {
                    Some(packet) => {
                        idle_sleep.as_mut().reset(tokio::time::Instant::now() + idle_timeout);
                        // Never forward a LOCAL INFILE request to the client.
                        // A malicious or compromised upstream server could
                        // otherwise induce a client driver to upload a local file.
                        if is_local_infile_request(&packet) {
                            let error = command_error_packet(
                                packet.sequence.wrapping_add(1),
                                "LOCAL INFILE is disabled by the Proxima MySQL gateway",
                            );
                            write_packet(&mut client_writer, &error, max_packet_size)
                                .await
                                .map_err(|_| GatewayError::TransportFailed)?;
                            break;
                        }
                        write_packet(&mut client_writer, &packet, max_packet_size)
                            .await
                            .map_err(|_| GatewayError::TransportFailed)?;
                    }
                    None => server_closed = true,
                }
            }
            packet = local_rx.recv(), if !local_closed => {
                match packet {
                    Some(packet) => {
                        idle_sleep.as_mut().reset(tokio::time::Instant::now() + idle_timeout);
                        write_packet(&mut client_writer, &packet, max_packet_size)
                            .await
                            .map_err(|_| GatewayError::TransportFailed)?;
                    }
                    None => local_closed = true,
                }
            }
        }
        if server_closed || local_closed { break; }
    }

    server_reader.abort();
    client_reader_task.abort();
    Ok(())
}

fn session_assertion_is_current<K: TenantAssertionKeyStore + ?Sized>(
    store: &K,
    token: &str,
    tenant_id: uuid::Uuid,
    expected_expiry: u64,
    now: u64,
) -> bool {
    let key = match store.load_assertion_key(tenant_id) {
        Ok(Some(key)) => Zeroizing::new(key),
        _ => return false,
    };
    TenantAssertion::verify(token, &key, now).is_ok_and(|assertion| {
        assertion.tenant_id == tenant_id && assertion.expires_at == expected_expiry
    })
}

fn command_error_packet(sequence: u8, message: &str) -> Packet {
    let mut payload = vec![0xff, 0x14, 0x04, b'#'];
    payload.extend_from_slice(b"42000");
    payload.extend_from_slice(message.as_bytes());
    Packet { sequence, payload }
}

fn is_local_infile_request(packet: &Packet) -> bool {
    packet.payload.first() == Some(&0xfb)
}

#[cfg(test)]
mod tests {
    use super::*;

    struct TestAssertionKeyStore {
        key: Option<Vec<u8>>,
    }

    impl TenantAssertionKeyStore for TestAssertionKeyStore {
        fn load_assertion_key(
            &self,
            _tenant_id: uuid::Uuid,
        ) -> Result<Option<Vec<u8>>, AccountError> {
            Ok(self.key.clone())
        }
    }

    #[test]
    fn active_session_revalidates_assertion_against_current_tenant_key() {
        let tenant_id = uuid::Uuid::new_v4();
        let now = 1_800_000_000u64;
        let expiry = now + 600;
        let original_key = b"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa".to_vec();
        let token = TenantAssertion::issue(tenant_id, expiry, &original_key).unwrap();

        let valid_store = TestAssertionKeyStore { key: Some(original_key.clone()) };
        assert!(session_assertion_is_current(&valid_store, &token, tenant_id, expiry, now));

        let rotated_store = TestAssertionKeyStore {
            key: Some(b"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb".to_vec()),
        };
        assert!(!session_assertion_is_current(&rotated_store, &token, tenant_id, expiry, now));

        let revoked_store = TestAssertionKeyStore { key: None };
        assert!(!session_assertion_is_current(&revoked_store, &token, tenant_id, expiry, now));

        assert!(!session_assertion_is_current(&valid_store, &token, uuid::Uuid::new_v4(), expiry, now));
        assert!(!session_assertion_is_current(&valid_store, &token, tenant_id, expiry + 1, now));
        assert!(!session_assertion_is_current(&valid_store, &token, tenant_id, expiry, expiry));
    }

    #[test]
    fn upstream_local_infile_request_is_identified_and_rejected() {
        let request = Packet { sequence: 7, payload: vec![0xfb, b'/', b't', b'm', b'p'] };
        assert!(is_local_infile_request(&request));

        let ordinary_result = Packet { sequence: 7, payload: vec![0x01, 0x00] };
        assert!(!is_local_infile_request(&ordinary_result));

        let error = command_error_packet(8, "LOCAL INFILE disabled");
        assert_eq!(error.sequence, 8);
        assert_eq!(error.payload.first(), Some(&0xff));
        assert!(String::from_utf8_lossy(&error.payload).contains("LOCAL INFILE disabled"));
    }
}
