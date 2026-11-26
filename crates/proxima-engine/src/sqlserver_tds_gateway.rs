//! SQL Server TDS 7.4 tenant-bound gateway.
//!
//! The gateway terminates client TLS, validates the LOGIN7 principal/database
//! against a node-local assignment registry, then opens a separately verified
//! TLS connection to the assigned SQL Server and forwards the authenticated TDS
//! session. Tenant isolation is enforced by the per-tenant SQL Server login and
//! database permissions provisioned by `sqlserver_tenant`.
use serde::{Deserialize, Serialize};
use std::{
    collections::HashMap,
    fs, io,
    net::SocketAddr,
    path::Path,
    pin::Pin,
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc,
    },
    task::{Context, Poll},
};
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf},
    net::{TcpListener, TcpStream},
};
use tokio_rustls::{
    rustls::{
        self,
        pki_types::{CertificateDer, PrivateKeyDer, ServerName},
    },
    TlsAcceptor, TlsConnector,
};

const MAX_PRELOGIN: usize = 16 * 1024;
const MAX_LOGIN: usize = 1024 * 1024;
const TDS_PRELOGIN: u8 = 0x12;
const TDS_PRELOGIN_RESPONSE: u8 = 0x04;
const TDS_TLS_PACKET: u8 = 0x12;
const TDS_LOGIN7: u8 = 0x10;
const TDS_EOM: u8 = 0x01;
const DEFAULT_MAX_CONNECTIONS: usize = 128;
const HANDSHAKE_TIMEOUT_SECS: u64 = 10;
const UPSTREAM_CONNECT_TIMEOUT_SECS: u64 = 10;

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct SqlServerTdsConfig {
    pub schema_version: u64,
    pub provider_key: String,
    pub listen_addr: String,
    pub upstream_host: String,
    pub upstream_port: u16,
    pub upstream_server_name: String,
    pub upstream_ca_pem: String,
    pub client_cert_pem: String,
    pub client_key_pem: String,
    #[serde(default)]
    pub allow_non_loopback: bool,
    pub tenants: Vec<TdsTenantBinding>,
}
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct TdsTenantBinding {
    pub tenant_id: String,
    pub username: String,
    pub database: String,
}
#[derive(Clone)]
struct Gateway {
    upstream: SocketAddr,
    upstream_name: String,
    connector: TlsConnector,
    acceptor: TlsAcceptor,
    users: std::sync::Arc<HashMap<String, (String, String)>>,
    connection_slots: Arc<tokio::sync::Semaphore>,
}

impl SqlServerTdsConfig {
    pub fn load(path: &Path) -> io::Result<Self> {
        let raw = fs::read(path)?;
        let cfg: Self = serde_json::from_slice(&raw)
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
        cfg.validate()?;
        Ok(cfg)
    }
    pub fn validate(&self) -> io::Result<()> {
        if self.schema_version != 1 || self.provider_key != "sqlserver" {
            return Err(invalid(
                "unsupported SQL Server TDS registry schema/provider",
            ));
        }
        let listen: SocketAddr = self.listen_addr.parse().map_err(invalid)?;
        let operator_non_loopback_opt_in =
            std::env::var("PROXIMA_SQLSERVER_TDS_ALLOW_NON_LOOPBACK")
                .is_ok_and(|value| value.eq_ignore_ascii_case("true"));
        if (!listen.ip().is_loopback()
            && (!self.allow_non_loopback || !operator_non_loopback_opt_in))
            || self.upstream_port == 0
        {
            return Err(invalid(
                "TDS listener must be loopback unless both the signed runtime flag and operator PROXIMA_SQLSERVER_TDS_ALLOW_NON_LOOPBACK=true are present; upstream port must be valid",
            ));
        }
        if self.upstream_host.trim().is_empty() || self.upstream_server_name.trim().is_empty() {
            return Err(invalid(
                "SQL Server upstream host and TLS server name are required",
            ));
        }
        if self.tenants.is_empty() {
            return Err(invalid("SQL Server tenant registry must contain at least one binding"));
        }
        let mut users = std::collections::HashSet::new();
        let mut databases = std::collections::HashSet::new();
        let mut tenant_ids = std::collections::HashSet::new();
        for t in &self.tenants {
            if !valid_sql_identifier(&t.username)
                || !valid_sql_identifier(&t.database)
                || t.tenant_id.is_empty()
                || t.tenant_id.len() > 128
                || !t
                    .tenant_id
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
                || !users.insert(t.username.to_ascii_lowercase())
                || !databases.insert(t.database.to_ascii_lowercase())
                || !tenant_ids.insert(t.tenant_id.clone())
            {
                return Err(invalid(
                    "invalid or duplicate SQL Server tenant login/database mapping",
                ));
            }
        }
        Ok(())
    }
}

fn max_connections_from_env() -> io::Result<usize> {
    let value = std::env::var("PROXIMA_SQLSERVER_TDS_MAX_CONNECTIONS").ok();
    parse_max_connections(value.as_deref())
}

fn parse_max_connections(value: Option<&str>) -> io::Result<usize> {
    let max_connections = value
        .unwrap_or("128")
        .parse::<usize>()
        .map_err(invalid)?;
    if max_connections == 0 {
        return Err(invalid("PROXIMA_SQLSERVER_TDS_MAX_CONNECTIONS must be greater than zero"));
    }
    Ok(max_connections)
}

pub async fn run(config: SqlServerTdsConfig) -> io::Result<()> {
    let _ = tokio_rustls::rustls::crypto::ring::default_provider().install_default();
    config.validate()?;
    let certs = load_certs(&config.client_cert_pem)?;
    let key = load_key(&config.client_key_pem)?;
    let server_cfg = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(certs, key)
        .map_err(invalid)?;
    let acceptor = TlsAcceptor::from(std::sync::Arc::new(server_cfg));
    let mut roots = rustls::RootCertStore::empty();
    for cert in load_certs(&config.upstream_ca_pem)? {
        roots.add(cert).map_err(invalid)?;
    }
    if roots.is_empty() {
        return Err(invalid("SQL Server upstream CA bundle is empty"));
    }
    let client_cfg = rustls::ClientConfig::builder()
        .with_root_certificates(roots)
        .with_no_client_auth();
    let connector = TlsConnector::from(std::sync::Arc::new(client_cfg));
    let upstream =
        match format!("{}:{}", config.upstream_host, config.upstream_port).parse::<SocketAddr>() {
            Ok(address) => address,
            Err(_) => resolve_socket(&config.upstream_host, config.upstream_port)?,
        };
    let mut users = HashMap::new();
    for t in &config.tenants {
        users.insert(
            t.username.to_ascii_lowercase(),
            (t.tenant_id.clone(), t.database.clone()),
        );
    }
    let max_connections = max_connections_from_env()?;
    let gateway = Gateway {
        upstream,
        upstream_name: config.upstream_server_name.clone(),
        connector,
        acceptor,
        users: std::sync::Arc::new(users),
        connection_slots: Arc::new(tokio::sync::Semaphore::new(max_connections)),
    };
    let listener = TcpListener::bind(&config.listen_addr).await?;
    tracing::info!(listen=%config.listen_addr, upstream=%config.upstream_host, tenants=config.tenants.len(), "SQL Server TDS gateway listening");
    loop {
        let (stream, peer) = listener.accept().await?;
        let permit = match gateway.connection_slots.clone().try_acquire_owned() {
            Ok(permit) => permit,
            Err(_) => {
                tracing::warn!(%peer, "TDS connection rejected: connection capacity exhausted");
                drop(stream);
                continue;
            }
        };
        let gw = gateway.clone();
        tokio::spawn(async move {
            let _permit = permit;
            if let Err(e) = gw.handle(stream).await {
                tracing::warn!(%peer, error=%e, "TDS session rejected or terminated");
            }
        });
    }
}

impl Gateway {
    async fn handle(&self, mut client: TcpStream) -> io::Result<()> {
        let (kind, prelogin) = tokio::time::timeout(
            std::time::Duration::from_secs(HANDSHAKE_TIMEOUT_SECS),
            read_tds_message(&mut client, MAX_PRELOGIN),
        )
        .await
        .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "TDS PRELOGIN timed out"))??;
        if kind != TDS_PRELOGIN {
            return Err(invalid("expected TDS PRELOGIN packet"));
        }
        let requested = prelogin_encryption(&prelogin)?;
        if requested == 0x02 {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "client does not support TLS",
            ));
        }
        // The server's initial PRELOGIN table response uses packet type 0x04.
        // TLS handshake records that follow are carried in PRELOGIN (0x12) packets.
        write_tds_message(&mut client, TDS_PRELOGIN_RESPONSE, &build_prelogin(0x01)).await?;
        let (client_transport, client_tls_mode) = TdsTlsIo::new(client);
        let mut client_tls = tokio::time::timeout(
            std::time::Duration::from_secs(HANDSHAKE_TIMEOUT_SECS),
            self.acceptor.accept(client_transport),
        )
        .await
        .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "TDS client TLS handshake timed out"))?
        .map_err(invalid)?;
        client_tls_mode.mark_established();
        let (kind, login) = tokio::time::timeout(
            std::time::Duration::from_secs(HANDSHAKE_TIMEOUT_SECS),
            read_tds_message(&mut client_tls, MAX_LOGIN),
        )
        .await
        .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "TDS LOGIN7 timed out"))??;
        if kind != TDS_LOGIN7 {
            return Err(invalid("expected TDS LOGIN7 packet after TLS negotiation"));
        }
        let (username, database) = parse_login7_identity(&login)?;
        let Some((_tenant, expected_database)) = self.users.get(&username.to_ascii_lowercase())
        else {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "LOGIN7 principal is not assigned to this SQL Server gateway",
            ));
        };
        if !database.is_empty() && !database.eq_ignore_ascii_case(expected_database) {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "LOGIN7 requested a database outside its tenant assignment",
            ));
        }
        let mut upstream = tokio::time::timeout(
            std::time::Duration::from_secs(UPSTREAM_CONNECT_TIMEOUT_SECS),
            TcpStream::connect(self.upstream),
        )
        .await
        .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "SQL Server upstream connect timed out"))??;
        write_tds_message(&mut upstream, TDS_PRELOGIN, &build_prelogin(0x03)).await?;
        let (up_kind, up_prelogin) = tokio::time::timeout(
            std::time::Duration::from_secs(HANDSHAKE_TIMEOUT_SECS),
            read_tds_message(&mut upstream, MAX_PRELOGIN),
        )
        .await
        .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "SQL Server upstream PRELOGIN timed out"))??;
        if up_kind != TDS_PRELOGIN_RESPONSE
            || !matches!(prelogin_encryption(&up_prelogin)?, 0x01 | 0x03)
        {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "SQL Server upstream did not negotiate TLS",
            ));
        }
        let server_name = ServerName::try_from(self.upstream_name.clone()).map_err(invalid)?;
        let (upstream_transport, upstream_tls_mode) = TdsTlsIo::new(upstream);
        let mut upstream_tls = tokio::time::timeout(
            std::time::Duration::from_secs(HANDSHAKE_TIMEOUT_SECS),
            self.connector.connect(server_name, upstream_transport),
        )
        .await
        .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "SQL Server upstream TLS handshake timed out"))?
        .map_err(invalid)?;
        upstream_tls_mode.mark_established();
        write_tds_message(&mut upstream_tls, TDS_LOGIN7, &login).await?;
        // LOGIN7 is forwarded only after the tenant principal and requested database
        // have been checked. SQL Server authenticates the password and enforces the
        // tenant login's database permissions. All subsequent TDS packets stay TLS.
        tokio::io::copy_bidirectional(&mut client_tls, &mut upstream_tls).await?;
        Ok(())
    }
}

/// TDS 7.x TLS transport adapter.
///
/// During the TLS handshake, TLS records are carried as the payload of TDS
/// PRELOGIN (0x12) packets. Once the TLS handshake completes, TDS 7.x full
/// encryption switches to an ordinary TLS byte stream. tokio-rustls therefore
/// needs an adapter that frames/unframes only the handshake phase and then
/// becomes transparent. The transition is shared with the handshake caller.
#[derive(Clone)]
struct TdsTlsMode(Arc<AtomicBool>);

impl TdsTlsMode {
    fn mark_established(&self) {
        self.0.store(true, Ordering::Release);
    }

    fn is_established(&self) -> bool {
        self.0.load(Ordering::Acquire)
    }
}

struct TdsTlsIo<S> {
    inner: S,
    mode: TdsTlsMode,
    header: [u8; 8],
    header_filled: usize,
    payload_remaining: usize,
    write_pending: Vec<u8>,
    write_offset: usize,
}

impl<S> TdsTlsIo<S> {
    fn new(inner: S) -> (Self, TdsTlsMode) {
        let mode = TdsTlsMode(Arc::new(AtomicBool::new(false)));
        (
            Self {
                inner,
                mode: mode.clone(),
                header: [0; 8],
                header_filled: 0,
                payload_remaining: 0,
                write_pending: Vec::new(),
                write_offset: 0,
            },
            mode,
        )
    }
}

impl<S: AsyncRead + AsyncWrite + Unpin> AsyncRead for TdsTlsIo<S> {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        output: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        if output.remaining() == 0 {
            return Poll::Ready(Ok(()));
        }
        if this.mode.is_established() {
            if this.header_filled != 0 || this.payload_remaining != 0 {
                return Poll::Ready(Err(invalid(
                    "TDS TLS framing transition occurred in the middle of a packet",
                )));
            }
            return Pin::new(&mut this.inner).poll_read(cx, output);
        }

        loop {
            if this.payload_remaining > 0 {
                let capacity = this.payload_remaining.min(output.remaining()).min(8192);
                let mut temporary = vec![0u8; capacity];
                let mut payload = ReadBuf::new(&mut temporary);
                match Pin::new(&mut this.inner).poll_read(cx, &mut payload) {
                    Poll::Pending => return Poll::Pending,
                    Poll::Ready(Err(error)) => return Poll::Ready(Err(error)),
                    Poll::Ready(Ok(())) => {
                        let count = payload.filled().len();
                        if count == 0 {
                            return Poll::Ready(Err(io::Error::new(
                                io::ErrorKind::UnexpectedEof,
                                "EOF inside TDS TLS packet payload",
                            )));
                        }
                        output.put_slice(&payload.filled()[..count]);
                        this.payload_remaining -= count;
                        return Poll::Ready(Ok(()));
                    }
                }
            }

            while this.header_filled < this.header.len() {
                let start = this.header_filled;
                let mut header = ReadBuf::new(&mut this.header[start..]);
                match Pin::new(&mut this.inner).poll_read(cx, &mut header) {
                    Poll::Pending => return Poll::Pending,
                    Poll::Ready(Err(error)) => return Poll::Ready(Err(error)),
                    Poll::Ready(Ok(())) => {
                        let count = header.filled().len();
                        if count == 0 {
                            if this.header_filled == 0 {
                                return Poll::Ready(Ok(()));
                            }
                            return Poll::Ready(Err(io::Error::new(
                                io::ErrorKind::UnexpectedEof,
                                "EOF inside TDS TLS packet header",
                            )));
                        }
                        this.header_filled += count;
                    }
                }
            }

            let packet_type = this.header[0];
            let packet_length = u16::from_be_bytes([this.header[2], this.header[3]]) as usize;
            this.header_filled = 0;
            if packet_type != TDS_TLS_PACKET || !(8..=65_535).contains(&packet_length) {
                return Poll::Ready(Err(invalid(
                    "TLS handshake data must be carried in valid TDS PRELOGIN packets",
                )));
            }
            this.payload_remaining = packet_length - 8;
            if this.payload_remaining == 0 {
                continue;
            }
        }
    }
}

impl<S: AsyncRead + AsyncWrite + Unpin> TdsTlsIo<S> {
    fn poll_flush_pending(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        while self.write_offset < self.write_pending.len() {
            match Pin::new(&mut self.inner).poll_write(cx, &self.write_pending[self.write_offset..])
            {
                Poll::Pending => return Poll::Pending,
                Poll::Ready(Err(error)) => return Poll::Ready(Err(error)),
                Poll::Ready(Ok(0)) => {
                    return Poll::Ready(Err(io::Error::new(
                        io::ErrorKind::WriteZero,
                        "failed to write TDS TLS packet",
                    )))
                }
                Poll::Ready(Ok(count)) => self.write_offset += count,
            }
        }
        self.write_pending.clear();
        self.write_offset = 0;
        Poll::Ready(Ok(()))
    }
}

impl<S: AsyncRead + AsyncWrite + Unpin> AsyncWrite for TdsTlsIo<S> {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        input: &[u8],
    ) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        if this.write_offset < this.write_pending.len() {
            match this.poll_flush_pending(cx) {
                Poll::Pending => return Poll::Pending,
                Poll::Ready(Err(error)) => return Poll::Ready(Err(error)),
                Poll::Ready(Ok(())) => {}
            }
        }
        if this.mode.is_established() {
            return Pin::new(&mut this.inner).poll_write(cx, input);
        }
        if input.is_empty() {
            return Poll::Ready(Ok(0));
        }

        const MAX_TLS_PAYLOAD: usize = 32_760;
        let count = input.len().min(MAX_TLS_PAYLOAD);
        let packet_length = (count + 8) as u16;
        this.write_pending.clear();
        this.write_pending.reserve(count + 8);
        this.write_pending.extend_from_slice(&[
            TDS_TLS_PACKET,
            TDS_EOM,
            packet_length.to_be_bytes()[0],
            packet_length.to_be_bytes()[1],
            0,
            0,
            1,
            0,
        ]);
        this.write_pending.extend_from_slice(&input[..count]);
        this.write_offset = 0;
        Poll::Ready(Ok(count))
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        match this.poll_flush_pending(cx) {
            Poll::Pending => return Poll::Pending,
            Poll::Ready(Err(error)) => return Poll::Ready(Err(error)),
            Poll::Ready(Ok(())) => {}
        }
        Pin::new(&mut this.inner).poll_flush(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        match this.poll_flush_pending(cx) {
            Poll::Pending => return Poll::Pending,
            Poll::Ready(Err(error)) => return Poll::Ready(Err(error)),
            Poll::Ready(Ok(())) => {}
        }
        Pin::new(&mut this.inner).poll_shutdown(cx)
    }
}

async fn read_tds_message<R: AsyncRead + Unpin>(
    r: &mut R,
    max: usize,
) -> io::Result<(u8, Vec<u8>)> {
    let mut all = Vec::new();
    let mut packet_type = None;
    loop {
        let mut h = [0u8; 8];
        r.read_exact(&mut h).await?;
        let len = u16::from_be_bytes([h[2], h[3]]) as usize;
        if len < 8 || len > 65535 {
            return Err(invalid("invalid TDS packet length"));
        }
        let kind = h[0];
        if packet_type.replace(kind).is_some_and(|old| old != kind) {
            return Err(invalid("mixed packet types in TDS message"));
        }
        if all.len().saturating_add(len - 8) > max {
            return Err(invalid("TDS message exceeds configured limit"));
        }
        let start = all.len();
        all.resize(start + len - 8, 0);
        r.read_exact(&mut all[start..]).await?;
        if h[1] & TDS_EOM != 0 {
            return Ok((kind, all));
        }
    }
}
async fn write_tds_message<W: AsyncWrite + Unpin>(
    w: &mut W,
    kind: u8,
    payload: &[u8],
) -> io::Result<()> {
    let mut packet_id = 1u8;
    if payload.is_empty() {
        let mut h = [0u8; 8];
        h[0] = kind;
        h[1] = TDS_EOM;
        h[2..4].copy_from_slice(&8u16.to_be_bytes());
        h[6] = packet_id;
        w.write_all(&h).await?;
    } else {
        for (index, chunk) in payload.chunks(32_760).enumerate() {
            let final_packet = (index + 1) * 32_760 >= payload.len();
            let mut h = [0u8; 8];
            h[0] = kind;
            h[1] = if final_packet { TDS_EOM } else { 0 };
            h[2..4].copy_from_slice(&((chunk.len() + 8) as u16).to_be_bytes());
            h[6] = packet_id;
            w.write_all(&h).await?;
            w.write_all(chunk).await?;
            packet_id = packet_id.wrapping_add(1);
        }
    }
    w.flush().await
}
fn prelogin_encryption(p: &[u8]) -> io::Result<u8> {
    let mut i = 0;
    while i < p.len() {
        let token = p[i];
        if token == 0xff {
            break;
        }
        if i + 5 > p.len() {
            return Err(invalid("malformed TDS PRELOGIN option table"));
        }
        let off = u16::from_be_bytes([p[i + 1], p[i + 2]]) as usize;
        let len = u16::from_be_bytes([p[i + 3], p[i + 4]]) as usize;
        if off.checked_add(len).is_none_or(|end| end > p.len()) {
            return Err(invalid("TDS PRELOGIN option outside packet"));
        }
        if token == 0x01 {
            if len != 1 {
                return Err(invalid("invalid TDS encryption option"));
            }
            return Ok(p[off]);
        }
        i += 5;
    }
    Err(invalid("TDS PRELOGIN encryption option is missing"))
}
fn build_prelogin(encryption: u8) -> Vec<u8> {
    // VERSION, ENCRYPTION, THREADID and MARS; offsets are relative to this payload.
    let version = [0x0f, 0x00, 0x00, 0x00, 0x00, 0x00];
    let thread = [0u8; 4];
    let mars = [0u8; 1];
    let mut p = Vec::with_capacity(33);
    p.extend_from_slice(&[
        0x00, 0x00, 0x15, 0x00, 0x06, 0x01, 0x00, 0x1b, 0x00, 0x01, 0x04, 0x00, 0x1c, 0x00, 0x04,
        0x0a, 0x00, 0x20, 0x00, 0x01, 0xff,
    ]);
    p.extend_from_slice(&version);
    p.push(encryption);
    p.extend_from_slice(&thread);
    p.extend_from_slice(&mars);
    p
}
fn parse_login7_identity(p: &[u8]) -> io::Result<(String, String)> {
    if p.len() < 94 {
        return Err(invalid("truncated TDS LOGIN7 payload"));
    }
    let field = |count_off: usize, offset_off: usize| -> io::Result<(usize, usize)> {
        let n = u16::from_le_bytes([p[count_off], p[count_off + 1]]) as usize;
        let o = u16::from_le_bytes([p[offset_off], p[offset_off + 1]]) as usize;
        if o.checked_add(n.saturating_mul(2))
            .is_none_or(|e| e > p.len())
        {
            return Err(invalid("LOGIN7 string field outside packet"));
        }
        Ok((o, n))
    };
    let (uo, un) = field(40, 42)?;
    let (doff, dn) = field(68, 70)?;
    let username = decode_utf16(&p[uo..uo + un * 2])?;
    let database = decode_utf16(&p[doff..doff + dn * 2])?;
    if username.is_empty() {
        return Err(invalid("LOGIN7 username is empty"));
    }
    Ok((username, database))
}
fn decode_utf16(b: &[u8]) -> io::Result<String> {
    let words = b.chunks_exact(2).map(|c| u16::from_le_bytes([c[0], c[1]]));
    String::from_utf16(&words.collect::<Vec<_>>()).map_err(invalid)
}
fn valid_sql_identifier(s: &str) -> bool {
    !s.is_empty()
        && s.len() <= 128
        && s.bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'$' || b == b'#')
}
fn load_certs(path: &str) -> io::Result<Vec<CertificateDer<'static>>> {
    let f = fs::File::open(path)?;
    rustls_pemfile::certs(&mut std::io::BufReader::new(f))
        .collect::<Result<Vec<_>, _>>()
        .map_err(invalid)
}
fn load_key(path: &str) -> io::Result<PrivateKeyDer<'static>> {
    let f = fs::File::open(path)?;
    rustls_pemfile::private_key(&mut std::io::BufReader::new(f))
        .map_err(invalid)?
        .ok_or_else(|| invalid("TLS private key is missing"))
}
fn resolve_socket(host: &str, port: u16) -> io::Result<SocketAddr> {
    use std::net::ToSocketAddrs;
    (host, port)
        .to_socket_addrs()?
        .next()
        .ok_or_else(|| invalid("upstream host did not resolve"))
}
fn invalid(e: impl std::fmt::Display) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidInput, e.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn sqlserver_connection_limit_defaults_and_rejects_unsafe_values() {
        assert_eq!(parse_max_connections(None).unwrap(), DEFAULT_MAX_CONNECTIONS);
        assert!(parse_max_connections(Some("0")).is_err());
        assert_eq!(parse_max_connections(Some("100000")).unwrap(), 100000);
        assert!(parse_max_connections(Some("not-a-number")).is_err());
        assert_eq!(parse_max_connections(Some("64")).unwrap(), 64);
    }

    #[test]
    fn prelogin_advertises_tls() {
        let p = build_prelogin(1);
        assert_eq!(prelogin_encryption(&p).unwrap(), 1);
    }
    #[test]
    fn login7_identity_is_read_from_utf16_fields() {
        let u = "agata_acme_app".encode_utf16().collect::<Vec<_>>();
        let mut p = vec![0u8; 94 + u.len() * 2];
        p[40..42].copy_from_slice(&(u.len() as u16).to_le_bytes());
        p[42..44].copy_from_slice(&94u16.to_le_bytes());
        for (i, w) in u.iter().enumerate() {
            p[94 + i * 2..96 + i * 2].copy_from_slice(&w.to_le_bytes());
        }
        let d = "AGATA_ACME".encode_utf16().collect::<Vec<_>>();
        let o = 94 + u.len() * 2;
        p[68..70].copy_from_slice(&(d.len() as u16).to_le_bytes());
        p[70..72].copy_from_slice(&(o as u16).to_le_bytes());
        p.resize(o + d.len() * 2, 0);
        for (i, w) in d.iter().enumerate() {
            p[o + i * 2..o + i * 2 + 2].copy_from_slice(&w.to_le_bytes());
        }
        let (user, db) = parse_login7_identity(&p).unwrap();
        assert_eq!(user, "agata_acme_app");
        assert_eq!(db, "AGATA_ACME");
    }
    #[test]
    fn sqlserver_registry_accepts_more_than_ten_thousand_tenants() {
        let tenants = (0..10_001)
            .map(|index| TdsTenantBinding {
                tenant_id: format!("tenant-{index}"),
                username: format!("agata_tenant_{index}"),
                database: format!("AGATA_{index}"),
            })
            .collect();
        let config = SqlServerTdsConfig {
            schema_version: 1,
            provider_key: "sqlserver".into(),
            listen_addr: "127.0.0.1:14330".into(),
            upstream_host: "db.example".into(),
            upstream_port: 1433,
            upstream_server_name: "db.example".into(),
            upstream_ca_pem: "ca".into(),
            client_cert_pem: "cert".into(),
            client_key_pem: "key".into(),
            allow_non_loopback: false,
            tenants,
        };
        assert!(config.validate().is_ok());
    }

    #[test]
    fn rejects_duplicate_or_unsafe_principals() {
        let mut c = SqlServerTdsConfig {
            schema_version: 1,
            provider_key: "sqlserver".into(),
            listen_addr: "127.0.0.1:14330".into(),
            upstream_host: "db.example".into(),
            upstream_port: 1433,
            upstream_server_name: "db.example".into(),
            upstream_ca_pem: "ca".into(),
            client_cert_pem: "cert".into(),
            client_key_pem: "key".into(),
            allow_non_loopback: false,
            tenants: vec![TdsTenantBinding {
                tenant_id: "a".into(),
                username: "agata_a".into(),
                database: "AGATA_A".into(),
            }],
        };
        assert!(c.validate().is_ok());
        c.tenants.push(c.tenants[0].clone());
        assert!(c.validate().is_err());
    }

    #[tokio::test]
    async fn tds_tls_transport_unframes_handshake_records_and_frames_writes() {
        let (mut raw_peer, raw_gateway) = tokio::io::duplex(4096);
        let (mut framed, mode) = TdsTlsIo::new(raw_gateway);

        let inbound = b"client-hello";
        let mut packet = vec![TDS_TLS_PACKET, TDS_EOM, 0, 0, 0, 0, 1, 0];
        let length = (inbound.len() + 8) as u16;
        packet[2..4].copy_from_slice(&length.to_be_bytes());
        packet.extend_from_slice(inbound);
        raw_peer.write_all(&packet).await.unwrap();

        let mut received = vec![0u8; inbound.len()];
        framed.read_exact(&mut received).await.unwrap();
        assert_eq!(&received, inbound);

        framed.write_all(b"server-hello").await.unwrap();
        framed.flush().await.unwrap();
        let mut header = [0u8; 8];
        raw_peer.read_exact(&mut header).await.unwrap();
        assert_eq!(header[0], TDS_TLS_PACKET);
        assert_eq!(header[1] & TDS_EOM, TDS_EOM);
        assert_eq!(u16::from_be_bytes([header[2], header[3]]) as usize, 20);
        let mut payload = [0u8; 12];
        raw_peer.read_exact(&mut payload).await.unwrap();
        assert_eq!(&payload, b"server-hello");

        mode.mark_established();
        framed.write_all(b"raw-tls-record").await.unwrap();
        framed.flush().await.unwrap();
        let mut raw = [0u8; 14];
        raw_peer.read_exact(&mut raw).await.unwrap();
        assert_eq!(&raw, b"raw-tls-record");
    }

    #[tokio::test]
    async fn tds_tls_transport_rejects_non_prelogin_handshake_packets() {
        let (mut peer, raw_gateway) = tokio::io::duplex(128);
        let (mut framed, _) = TdsTlsIo::new(raw_gateway);
        peer.write_all(&[TDS_LOGIN7, TDS_EOM, 0, 8, 0, 0, 1, 0])
            .await
            .unwrap();
        let mut byte = [0u8; 1];
        let error = framed.read_exact(&mut byte).await.unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::InvalidInput);
    }

    #[tokio::test]
    async fn tds_tls_adapter_frames_handshake_records_and_unframes_peer_records() {
        use tokio::io::{duplex, AsyncReadExt, AsyncWriteExt};

        let (writer, mut peer) = duplex(1024);
        let (mut adapter, _mode) = TdsTlsIo::new(writer);
        adapter.write_all(b"client-tls-record").await.unwrap();
        adapter.flush().await.unwrap();
        let mut header = [0u8; 8];
        peer.read_exact(&mut header).await.unwrap();
        assert_eq!(header[0], TDS_TLS_PACKET);
        assert_eq!(header[1], TDS_EOM);
        assert_eq!(
            u16::from_be_bytes([header[2], header[3]]) as usize,
            8 + b"client-tls-record".len()
        );
        let mut payload = vec![0u8; b"client-tls-record".len()];
        peer.read_exact(&mut payload).await.unwrap();
        assert_eq!(payload.as_slice(), b"client-tls-record");

        let (mut peer, reader) = duplex(1024);
        let (mut adapter, _mode) = TdsTlsIo::new(reader);
        let payload = b"server-tls-record";
        let mut packet = Vec::with_capacity(8 + payload.len());
        packet.push(TDS_TLS_PACKET);
        packet.push(TDS_EOM);
        packet.extend_from_slice(&((8 + payload.len()) as u16).to_be_bytes());
        packet.extend_from_slice(&[0, 0, 1, 0]);
        packet.extend_from_slice(payload);
        peer.write_all(&packet).await.unwrap();
        let mut received = vec![0u8; payload.len()];
        adapter.read_exact(&mut received).await.unwrap();
        assert_eq!(received.as_slice(), payload);
    }

    #[tokio::test]
    async fn server_prelogin_response_uses_tds_response_packet_type() {
        use tokio::io::{duplex, AsyncReadExt};
        let (mut writer, mut peer) = duplex(128);
        write_tds_message(&mut writer, TDS_PRELOGIN_RESPONSE, &build_prelogin(0x01))
            .await
            .unwrap();
        let mut header = [0u8; 8];
        peer.read_exact(&mut header).await.unwrap();
        assert_eq!(header[0], 0x04);
        assert_eq!(header[1], TDS_EOM);
    }
}
