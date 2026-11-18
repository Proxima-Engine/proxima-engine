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
};
use crate::upstream::{
    connect_upstream, read_packet, write_packet, UpstreamError, UpstreamTlsConfig,
};
use ring::rand::{SecureRandom, SystemRandom};
use rustls::{ServerConfig, pki_types::PrivateKeyDer};
use std::fs::File;
use std::io::BufReader;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{mpsc, Semaphore};
use tokio::time::timeout;
use tokio_rustls::{client::TlsStream as ClientTlsStream, server::TlsStream as ServerTlsStream, TlsAcceptor};

static NEXT_CONNECTION_ID: AtomicU32 = AtomicU32::new(1);

pub struct GatewayConfig {
    pub listen_addr: SocketAddr,
    pub client_certificate_file: String,
    pub client_private_key_file: String,
    pub upstream: UpstreamTlsConfig,
    pub tenant_assertion_key: Vec<u8>,
    pub max_connections: usize,
    pub max_packet_size: usize,
    pub handshake_timeout: Duration,
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
        if config.tenant_assertion_key.len() < 32
            || config.max_connections == 0
            || config.max_packet_size == 0
            || config.max_packet_size >= MAX_PACKET_PAYLOAD
            || config.handshake_timeout.is_zero()
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

        let ssl_request = read_packet(&mut tcp, self.config.max_packet_size)
            .await
            .map_err(|_| GatewayError::ClientHandshakeRejected)?;
        verify_sequence(&ssl_request, 1)?;
        if !is_ssl_request(&ssl_request.payload) {
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
        crate::protocol::validate_client_capabilities(requested_flags, capabilities)?;

        let mut client = timeout(
            self.config.handshake_timeout,
            self.client_tls_acceptor.accept(tcp),
        )
        .await
        .map_err(|_| GatewayError::ClientTlsFailed)?
        .map_err(|_| GatewayError::ClientTlsFailed)?;

        let handshake_packet = read_packet(&mut client, self.config.max_packet_size)
            .await
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

        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|_| GatewayError::TransportFailed)?
            .as_secs();
        let session = match authenticate_and_resolve(
            &handshake,
            &challenge,
            true,
            self.account_directory.as_ref(),
            &self.config.tenant_assertion_key,
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

        let ok = Packet {
            sequence: 3,
            payload: vec![0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00],
        };
        write_packet(&mut client, &ok, self.config.max_packet_size)
            .await
            .map_err(|_| GatewayError::TransportFailed)?;

        relay_session(client, upstream, self.config.max_packet_size).await
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
) -> Result<(), GatewayError> {
    let (mut client_reader, mut client_writer) = tokio::io::split(client);
    let (mut upstream_reader, mut upstream_writer) = tokio::io::split(upstream);
    let (server_tx, mut server_rx) = mpsc::channel::<Packet>(32);
    let (local_tx, mut local_rx) = mpsc::channel::<Packet>(8);

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
    while !(server_closed && local_closed) {
        tokio::select! {
            packet = server_rx.recv(), if !server_closed => {
                match packet {
                    Some(packet) => {
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

fn command_error_packet(sequence: u8, message: &str) -> Packet {
    let mut payload = vec![0xff, 0x14, 0x04, b'#'];
    payload.extend_from_slice(b"42000");
    payload.extend_from_slice(message.as_bytes());
    Packet { sequence, payload }
}
