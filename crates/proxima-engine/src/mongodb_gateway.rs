use crate::mongodb_policy::{MongoSessionRegistry, MongoTenantPolicy};
use mongodb::bson::{self, Bson, Document};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, ServerName};
use rustls::{ClientConfig, RootCertStore, ServerConfig};
use std::collections::HashMap;
use std::fs::File;
use std::io::{self, BufReader};
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::Semaphore;
use tokio_rustls::{TlsAcceptor, TlsConnector};
use tracing::{info, warn};

const OP_MSG: i32 = 2013;
const MAX_MESSAGE_BYTES: usize = 48 * 1024 * 1024;
const MAX_SEQUENCE_DOCUMENTS: usize = 100_000;
const SCRAM_SHA_256: &str = "SCRAM-SHA-256";

trait MongoIo: AsyncRead + AsyncWrite + Unpin + Send {}
impl<T> MongoIo for T where T: AsyncRead + AsyncWrite + Unpin + Send {}
type BoxedMongoIo = Box<dyn MongoIo>;

#[derive(Debug, Clone)]
struct MongoTenantIdentity {
    username: String,
    tenant_id: String,
    database: String,
    auth_source: String,
}

pub struct MongoIdentityRegistry {
    users: HashMap<String, MongoTenantIdentity>,
}

impl MongoIdentityRegistry {
    pub fn load(path: impl AsRef<Path>) -> io::Result<Self> {
        let bytes = std::fs::read(path)?;
        let value: serde_json::Value = serde_json::from_slice(&bytes).map_err(|error| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                format!("invalid MongoDB identity registry JSON: {error}"),
            )
        })?;
        let records = value
            .get("users")
            .and_then(serde_json::Value::as_array)
            .ok_or_else(|| {
                io::Error::new(
                    io::ErrorKind::InvalidData,
                    "MongoDB identity registry must contain a users array",
                )
            })?;
        if records.is_empty() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "MongoDB identity registry cannot be empty",
            ));
        }

        let mut users = HashMap::new();
        let mut tenant_databases: HashMap<String, String> = HashMap::new();
        for (index, record) in records.iter().enumerate() {
            let field = |name: &str| -> io::Result<String> {
                record
                    .get(name)
                    .and_then(serde_json::Value::as_str)
                    .map(str::trim)
                    .filter(|value| !value.is_empty())
                    .map(str::to_owned)
                    .ok_or_else(|| {
                        io::Error::new(
                            io::ErrorKind::InvalidData,
                            format!("users[{index}].{name} is required"),
                        )
                    })
            };
            let username = field("username")?;
            let tenant_id = field("tenant_id")?;
            let database = field("database")?;
            let auth_source = record
                .get("auth_source")
                .and_then(serde_json::Value::as_str)
                .unwrap_or("admin")
                .trim()
                .to_owned();
            if username.len() > 128 || !username.bytes().all(|b| b.is_ascii_graphic()) {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!("users[{index}].username is invalid"),
                ));
            }
            if auth_source != "admin" {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "the initial MongoDB gateway supports admin as the SCRAM authentication source",
                ));
            }
            MongoTenantPolicy::new(tenant_id.clone(), database.clone()).map_err(|error| {
                io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!("users[{index}] has an invalid tenant binding: {error}"),
                )
            })?;
            if let Some(existing) = tenant_databases.get(&tenant_id) {
                if existing != &database {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        format!("tenant {tenant_id} maps to more than one database"),
                    ));
                }
            } else if tenant_databases
                .values()
                .any(|existing| existing == &database)
            {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!("database {database} is assigned to multiple tenants"),
                ));
            } else {
                tenant_databases.insert(tenant_id.clone(), database.clone());
            }
            let identity = MongoTenantIdentity {
                username: username.clone(),
                tenant_id,
                database,
                auth_source,
            };
            if users.insert(username.clone(), identity).is_some() {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!("duplicate MongoDB gateway username: {username}"),
                ));
            }
        }
        Ok(Self { users })
    }

    fn get(&self, username: &str) -> Option<MongoTenantIdentity> {
        self.users.get(username).cloned()
    }

    pub fn principal_count(&self) -> usize {
        self.users.len()
    }
}

struct MongoGatewayConfig {
    listen_addr: String,
    upstream_addr: String,
    upstream_tls: bool,
    upstream_tls_server_name: Option<String>,
    upstream_tls_ca_file: Option<String>,
    max_connections: usize,
}

impl MongoGatewayConfig {
    fn from_env() -> io::Result<Self> {
        let listen_addr = env_required_or("PROXIMA_MONGODB_LISTEN_ADDR", "127.0.0.1:27018")?;
        let upstream_addr = env_required("PROXIMA_MONGODB_UPSTREAM_ADDR")?;
        let upstream_tls = env_bool("PROXIMA_MONGODB_UPSTREAM_TLS", true)?;
        let upstream_tls_server_name = env_optional("PROXIMA_MONGODB_UPSTREAM_TLS_SERVER_NAME");
        let upstream_tls_ca_file = env_optional("PROXIMA_MONGODB_UPSTREAM_TLS_CA_FILE");
        if upstream_tls && (upstream_tls_server_name.is_none() || upstream_tls_ca_file.is_none()) {
            return Err(io::Error::new(io::ErrorKind::InvalidInput, "MongoDB upstream TLS requires PROXIMA_MONGODB_UPSTREAM_TLS_SERVER_NAME and PROXIMA_MONGODB_UPSTREAM_TLS_CA_FILE"));
        }
        let max_connections = env_optional("PROXIMA_MONGODB_MAX_CONNECTIONS")
            .unwrap_or_else(|| "256".to_owned())
            .parse::<usize>()
            .map_err(|error| {
                io::Error::new(
                    io::ErrorKind::InvalidInput,
                    format!("invalid PROXIMA_MONGODB_MAX_CONNECTIONS: {error}"),
                )
            })?;
        if max_connections == 0 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "PROXIMA_MONGODB_MAX_CONNECTIONS must be greater than zero",
            ));
        }
        Ok(Self {
            listen_addr,
            upstream_addr,
            upstream_tls,
            upstream_tls_server_name,
            upstream_tls_ca_file,
            max_connections,
        })
    }
}

pub async fn run_mongodb_gateway() -> io::Result<()> {
    let _ = rustls::crypto::ring::default_provider().install_default();
    let config = MongoGatewayConfig::from_env()?;
    let registry_path = env_required("PROXIMA_MONGODB_IDENTITY_REGISTRY")?;
    let cert_path = env_required("PROXIMA_MONGODB_TLS_CERT_FILE")?;
    let key_path = env_required("PROXIMA_MONGODB_TLS_KEY_FILE")?;
    let registry = Arc::new(MongoIdentityRegistry::load(registry_path)?);
    let acceptor = build_server_tls(&cert_path, &key_path)?;
    let connector = if config.upstream_tls {
        Some(build_client_tls(
            config.upstream_tls_ca_file.as_deref().unwrap(),
        )?)
    } else {
        None
    };
    let listener = TcpListener::bind(&config.listen_addr).await?;
    let permits = Arc::new(Semaphore::new(config.max_connections));
    let sessions = Arc::new(MongoSessionRegistry::default());

    info!(listen = %config.listen_addr, upstream = %config.upstream_addr,
        principals = registry.principal_count(), max_connections = config.max_connections,
        upstream_tls = config.upstream_tls, "Proxima MongoDB wire gateway listening");

    loop {
        let (socket, peer) = listener.accept().await?;
        let permit = match permits.clone().try_acquire_owned() {
            Ok(permit) => permit,
            Err(_) => {
                warn!(%peer, "MongoDB gateway connection limit reached");
                drop(socket);
                continue;
            }
        };
        let acceptor = acceptor.clone();
        let connector = connector.clone();
        let upstream = config.upstream_addr.clone();
        let server_name = config.upstream_tls_server_name.clone();
        let registry = registry.clone();
        let sessions = sessions.clone();
        tokio::spawn(async move {
            let _permit = permit;
            if let Err(error) = handle_connection(
                socket,
                acceptor,
                connector,
                &upstream,
                server_name.as_deref(),
                registry,
                sessions,
            )
            .await
            {
                warn!(%peer, %error, "MongoDB gateway session closed");
            }
        });
    }
}

async fn handle_connection(
    socket: TcpStream,
    acceptor: TlsAcceptor,
    connector: Option<TlsConnector>,
    upstream_addr: &str,
    upstream_server_name: Option<&str>,
    registry: Arc<MongoIdentityRegistry>,
    sessions: Arc<MongoSessionRegistry>,
) -> io::Result<()> {
    let mut client: BoxedMongoIo = Box::new(
        tokio::time::timeout(Duration::from_secs(10), acceptor.accept(socket))
            .await
            .map_err(|_| {
                io::Error::new(
                    io::ErrorKind::TimedOut,
                    "MongoDB client TLS handshake timed out",
                )
            })?
            .map_err(|error| {
                io::Error::new(
                    io::ErrorKind::PermissionDenied,
                    format!("MongoDB client TLS handshake failed: {error}"),
                )
            })?,
    );

    let upstream_socket =
        tokio::time::timeout(Duration::from_secs(10), TcpStream::connect(upstream_addr))
            .await
            .map_err(|_| {
                io::Error::new(
                    io::ErrorKind::TimedOut,
                    "MongoDB upstream connection timed out",
                )
            })??;
    let mut upstream: BoxedMongoIo = if let Some(connector) = connector {
        let server_name = ServerName::try_from(upstream_server_name.unwrap_or_default().to_owned())
            .map_err(|_| {
                io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "invalid MongoDB upstream TLS server name",
                )
            })?;
        Box::new(
            tokio::time::timeout(
                Duration::from_secs(10),
                connector.connect(server_name, upstream_socket),
            )
            .await
            .map_err(|_| {
                io::Error::new(
                    io::ErrorKind::TimedOut,
                    "MongoDB upstream TLS handshake timed out",
                )
            })?
            .map_err(|error| {
                io::Error::new(
                    io::ErrorKind::PermissionDenied,
                    format!("MongoDB upstream TLS handshake failed: {error}"),
                )
            })?,
        )
    } else {
        Box::new(upstream_socket)
    };

    let mut identity: Option<MongoTenantIdentity> = None;
    let mut authenticated = false;

    loop {
        let frame = read_frame(&mut client).await?;
        let mut message = match decode_op_msg(&frame) {
            Ok(message) => message,
            Err(error) => {
                send_command_error(&mut client, request_id(&frame), "admin", &error.to_string())
                    .await?;
                return Err(error);
            }
        };
        let command_name = message.body.keys().next().cloned().unwrap_or_default();

        match command_name.as_str() {
            "hello" | "isMaster" => {
                // Disable wire compression and speculative SCRAM so every later
                // command remains inspectable and authentication follows one path.
                message.body.remove("compression");
                message.body.remove("speculativeAuthenticate");
                write_frame(
                    &mut upstream,
                    &encode_op_msg(message.request_id, 0, &message.body)?,
                )
                .await?;
            }
            "saslStart" => {
                if authenticated || identity.is_some() {
                    send_command_error(
                        &mut client,
                        message.request_id,
                        "admin",
                        "authentication restart is not permitted",
                    )
                    .await?;
                    continue;
                }
                let mechanism = message.body.get_str("mechanism").unwrap_or_default();
                if mechanism != SCRAM_SHA_256 {
                    send_command_error(
                        &mut client,
                        message.request_id,
                        "admin",
                        "only SCRAM-SHA-256 authentication is supported",
                    )
                    .await?;
                    continue;
                }
                let username = match scram_username(&message.body) {
                    Ok(username) => username,
                    Err(error) => {
                        send_command_error(
                            &mut client,
                            message.request_id,
                            "admin",
                            &error.to_string(),
                        )
                        .await?;
                        continue;
                    }
                };
                let Some(principal) = registry.get(&username) else {
                    send_command_error(
                        &mut client,
                        message.request_id,
                        "admin",
                        "unknown MongoDB gateway principal",
                    )
                    .await?;
                    continue;
                };
                if message.body.get_str("$db").unwrap_or_default() != principal.auth_source {
                    send_command_error(
                        &mut client,
                        message.request_id,
                        "admin",
                        "SCRAM authentication source does not match the principal registry",
                    )
                    .await?;
                    continue;
                }
                identity = Some(principal);
                write_frame(&mut upstream, &frame).await?;
            }
            "saslContinue" => {
                if identity.is_none() || authenticated {
                    send_command_error(
                        &mut client,
                        message.request_id,
                        "admin",
                        "unexpected SCRAM continuation",
                    )
                    .await?;
                    continue;
                }
                write_frame(&mut upstream, &frame).await?;
            }
            "ping" => {
                if !authenticated || message.body.get_str("$db").unwrap_or_default() != "admin" {
                    send_command_error(
                        &mut client,
                        message.request_id,
                        "admin",
                        "ping requires an authenticated principal and the admin database",
                    )
                    .await?;
                    continue;
                }
                write_frame(&mut upstream, &frame).await?;
            }
            "endSessions" => {
                let Some(principal) = identity.as_ref() else {
                    send_command_error(
                        &mut client,
                        message.request_id,
                        "admin",
                        "authentication is required",
                    )
                    .await?;
                    continue;
                };
                if !authenticated || message.body.get_str("$db").unwrap_or_default() != "admin" {
                    send_command_error(
                        &mut client,
                        message.request_id,
                        "admin",
                        "endSessions requires an authenticated principal on the admin database",
                    )
                    .await?;
                    continue;
                }
                let end_sessions = match message.body.get_array("endSessions") {
                    Ok(values) if values.len() <= 10_000 => values,
                    _ => {
                        send_command_error(
                            &mut client,
                            message.request_id,
                            "admin",
                            "endSessions must contain at most 10000 logical session identifiers",
                        )
                        .await?;
                        continue;
                    }
                };
                let mut invalid_session = None;
                for value in end_sessions {
                    let Some(lsid) = value.as_document() else {
                        invalid_session = Some(
                            "endSessions contains a non-document session identifier".to_owned(),
                        );
                        break;
                    };
                    if let Err(error) = sessions.release_if_owned(&principal.tenant_id, lsid) {
                        invalid_session = Some(error.to_string());
                        break;
                    }
                }
                if let Some(error) = invalid_session {
                    send_command_error(&mut client, message.request_id, "admin", &error).await?;
                    continue;
                }
                write_frame(&mut upstream, &frame).await?;
            }
            _ => {
                let Some(principal) = identity.as_ref() else {
                    send_command_error(
                        &mut client,
                        message.request_id,
                        "admin",
                        "authentication is required before data commands",
                    )
                    .await?;
                    continue;
                };
                if !authenticated {
                    send_command_error(
                        &mut client,
                        message.request_id,
                        "admin",
                        "SCRAM authentication has not completed",
                    )
                    .await?;
                    continue;
                }
                let mut policy_command = message.body.clone();
                if let Err(error) = merge_sequences(&mut policy_command, &message.sequences) {
                    send_command_error(
                        &mut client,
                        message.request_id,
                        &principal.database,
                        &error.to_string(),
                    )
                    .await?;
                    continue;
                }
                if matches!(policy_command.get_bool("startTransaction"), Ok(true))
                    || matches!(policy_command.get_bool("autocommit"), Ok(false))
                {
                    send_command_error(
                        &mut client,
                        message.request_id,
                        &principal.database,
                        "MongoDB transactions are not supported by this gateway profile",
                    )
                    .await?;
                    continue;
                }
                if let Ok(lsid) = policy_command.get_document("lsid") {
                    if let Err(error) = sessions.bind(&principal.tenant_id, lsid) {
                        send_command_error(
                            &mut client,
                            message.request_id,
                            &principal.database,
                            &error.to_string(),
                        )
                        .await?;
                        continue;
                    }
                    if let Err(error) = sessions.authorize(&principal.tenant_id, lsid) {
                        send_command_error(
                            &mut client,
                            message.request_id,
                            &principal.database,
                            &error.to_string(),
                        )
                        .await?;
                        continue;
                    }
                }
                let policy = MongoTenantPolicy::new(&principal.tenant_id, &principal.database)
                    .map_err(|error| {
                        io::Error::new(io::ErrorKind::InvalidData, error.to_string())
                    })?;
                if let Err(error) = policy.authorize(&policy_command) {
                    send_command_error(
                        &mut client,
                        message.request_id,
                        &principal.database,
                        &error.to_string(),
                    )
                    .await?;
                    continue;
                }
                write_frame(&mut upstream, &frame).await?;
            }
        }

        let response = read_frame(&mut upstream).await?;
        if response.len() < 16 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "truncated MongoDB upstream response",
            ));
        }
        let response_to = i32::from_le_bytes(response[8..12].try_into().unwrap());
        if response_to != message.request_id {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "MongoDB upstream response correlation mismatch",
            ));
        }

        if matches!(command_name.as_str(), "saslStart" | "saslContinue") {
            if let Ok(reply) = decode_op_msg(&response) {
                let ok = match reply.body.get("ok") {
                    Some(Bson::Double(value)) => *value == 1.0,
                    Some(Bson::Int32(value)) => *value == 1,
                    Some(Bson::Int64(value)) => *value == 1,
                    _ => false,
                };
                if ok && matches!(reply.body.get_bool("done"), Ok(true)) {
                    authenticated = true;
                }
            }
        }

        let mut client_response = response;
        if matches!(command_name.as_str(), "hello" | "isMaster") {
            let mut reply = decode_op_msg(&client_response)?;
            let writable_primary = matches!(reply.body.get_bool("isWritablePrimary"), Ok(true))
                || matches!(reply.body.get_bool("ismaster"), Ok(true));
            if !writable_primary {
                send_command_error(
                    &mut client,
                    message.request_id,
                    "admin",
                    "configured MongoDB upstream is not a writable primary or standalone node",
                )
                .await?;
                return Err(io::Error::new(
                    io::ErrorKind::PermissionDenied,
                    "MongoDB upstream is not writable",
                ));
            }
            if matches!(reply.body.get_str("msg"), Ok("isdbgrid")) {
                send_command_error(
                    &mut client,
                    message.request_id,
                    "admin",
                    "sharded MongoDB upstreams are not supported by this gateway profile",
                )
                .await?;
                return Err(io::Error::new(
                    io::ErrorKind::Unsupported,
                    "sharded MongoDB upstream is not supported",
                ));
            }
            for field in [
                "compression",
                "speculativeAuthenticate",
                "hosts",
                "passives",
                "arbiters",
                "primary",
                "setName",
                "setVersion",
                "electionId",
                "topologyVersion",
                "me",
                "msg",
                "serviceId",
                "secondary",
                "arbiterOnly",
                "hidden",
                "passive",
            ] {
                reply.body.remove(field);
            }
            client_response = encode_op_msg(reply.request_id, reply.response_to, &reply.body)?;
        }
        write_frame(&mut client, &client_response).await?;
    }
}

struct MongoMessage {
    request_id: i32,
    response_to: i32,
    body: Document,
    sequences: Vec<(String, Vec<Document>)>,
}

fn request_id(frame: &[u8]) -> i32 {
    if frame.len() >= 8 {
        i32::from_le_bytes(frame[4..8].try_into().unwrap())
    } else {
        0
    }
}

async fn read_frame(stream: &mut BoxedMongoIo) -> io::Result<Vec<u8>> {
    let mut header = [0u8; 4];
    stream.read_exact(&mut header).await?;
    let length = i32::from_le_bytes(header) as usize;
    if !(16..=MAX_MESSAGE_BYTES).contains(&length) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("invalid MongoDB wire message length: {length}"),
        ));
    }
    let mut frame = vec![0u8; length];
    frame[..4].copy_from_slice(&header);
    stream.read_exact(&mut frame[4..]).await?;
    Ok(frame)
}

fn decode_op_msg(frame: &[u8]) -> io::Result<MongoMessage> {
    if frame.len() < 21 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "truncated MongoDB OP_MSG",
        ));
    }
    let length = i32::from_le_bytes(frame[..4].try_into().unwrap()) as usize;
    if length != frame.len() || length > MAX_MESSAGE_BYTES {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "MongoDB OP_MSG length mismatch",
        ));
    }
    let request_id = i32::from_le_bytes(frame[4..8].try_into().unwrap());
    let response_to = i32::from_le_bytes(frame[8..12].try_into().unwrap());
    let opcode = i32::from_le_bytes(frame[12..16].try_into().unwrap());
    if opcode != OP_MSG {
        return Err(io::Error::new(
            io::ErrorKind::Unsupported,
            format!("MongoDB opcode {opcode} is not supported; only OP_MSG is accepted"),
        ));
    }
    let flags = i32::from_le_bytes(frame[16..20].try_into().unwrap());
    if flags != 0 {
        return Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "MongoDB OP_MSG checksums are not supported",
        ));
    }

    let mut offset = 20usize;
    let mut body = None;
    let mut sequences = Vec::new();
    while offset < frame.len() {
        let kind = frame[offset];
        offset += 1;
        match kind {
            0 => {
                let (document, consumed) = read_bson_document(frame, offset, frame.len())?;
                if body.replace(document).is_some() {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "MongoDB OP_MSG contains multiple body sections",
                    ));
                }
                offset = consumed;
            }
            1 => {
                let section_start = offset;
                if offset + 4 > frame.len() {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "truncated MongoDB document sequence",
                    ));
                }
                let section_size =
                    i32::from_le_bytes(frame[offset..offset + 4].try_into().unwrap());
                if section_size < 5 {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "invalid MongoDB document sequence size",
                    ));
                }
                let section_end = section_start
                    .checked_add(section_size as usize)
                    .filter(|end| *end <= frame.len())
                    .ok_or_else(|| {
                        io::Error::new(
                            io::ErrorKind::InvalidData,
                            "MongoDB document sequence exceeds frame",
                        )
                    })?;
                offset += 4;
                let nul = frame[offset..section_end]
                    .iter()
                    .position(|byte| *byte == 0)
                    .ok_or_else(|| {
                        io::Error::new(
                            io::ErrorKind::InvalidData,
                            "MongoDB document sequence identifier is unterminated",
                        )
                    })?;
                let identifier = std::str::from_utf8(&frame[offset..offset + nul])
                    .map_err(|_| {
                        io::Error::new(
                            io::ErrorKind::InvalidData,
                            "MongoDB document sequence identifier is not UTF-8",
                        )
                    })?
                    .to_owned();
                offset += nul + 1;
                let mut documents = Vec::new();
                while offset < section_end {
                    if documents.len() >= MAX_SEQUENCE_DOCUMENTS {
                        return Err(io::Error::new(
                            io::ErrorKind::InvalidData,
                            "MongoDB document sequence exceeds document limit",
                        ));
                    }
                    let (document, consumed) = read_bson_document(frame, offset, section_end)?;
                    documents.push(document);
                    offset = consumed;
                }
                if offset != section_end {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "MongoDB document sequence boundary mismatch",
                    ));
                }
                sequences.push((identifier, documents));
            }
            other => {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!("unknown MongoDB OP_MSG section kind: {other}"),
                ))
            }
        }
    }
    let body = body.ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            "MongoDB OP_MSG is missing its body section",
        )
    })?;
    Ok(MongoMessage {
        request_id,
        response_to,
        body,
        sequences,
    })
}

fn read_bson_document(frame: &[u8], offset: usize, limit: usize) -> io::Result<(Document, usize)> {
    if offset + 4 > limit {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "truncated BSON document length",
        ));
    }
    let length = i32::from_le_bytes(frame[offset..offset + 4].try_into().unwrap()) as usize;
    if length < 5 || offset.checked_add(length).is_none_or(|end| end > limit) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "invalid BSON document length",
        ));
    }
    let end = offset + length;
    let document = bson::from_slice::<Document>(&frame[offset..end]).map_err(|error| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            format!("invalid MongoDB BSON document: {error}"),
        )
    })?;
    Ok((document, end))
}

fn merge_sequences(
    command: &mut Document,
    sequences: &[(String, Vec<Document>)],
) -> io::Result<()> {
    for (identifier, documents) in sequences {
        if !matches!(identifier.as_str(), "documents" | "updates" | "deletes") {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                format!("MongoDB document sequence {identifier} is not admitted"),
            ));
        }
        if command.contains_key(identifier) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("MongoDB command contains duplicate {identifier} payload"),
            ));
        }
        command.insert(
            identifier,
            Bson::Array(documents.iter().cloned().map(Bson::Document).collect()),
        );
    }
    Ok(())
}

fn encode_op_msg(request_id: i32, response_to: i32, body: &Document) -> io::Result<Vec<u8>> {
    let bson = bson::to_vec(body).map_err(|error| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            format!("could not encode MongoDB BSON: {error}"),
        )
    })?;
    let length = 16usize
        .checked_add(4)
        .and_then(|value| value.checked_add(1))
        .and_then(|value| value.checked_add(bson.len()))
        .ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidInput,
                "MongoDB response length overflow",
            )
        })?;
    if length > MAX_MESSAGE_BYTES {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "MongoDB response exceeds maximum wire message size",
        ));
    }
    let mut frame = Vec::with_capacity(length);
    frame.extend_from_slice(&(length as i32).to_le_bytes());
    frame.extend_from_slice(&request_id.to_le_bytes());
    frame.extend_from_slice(&response_to.to_le_bytes());
    frame.extend_from_slice(&OP_MSG.to_le_bytes());
    frame.extend_from_slice(&0i32.to_le_bytes());
    frame.push(0);
    frame.extend_from_slice(&bson);
    Ok(frame)
}

async fn send_command_error(
    stream: &mut BoxedMongoIo,
    request_id: i32,
    database: &str,
    message: &str,
) -> io::Result<()> {
    let mut response = Document::new();
    response.insert("ok", 0.0);
    response.insert("errmsg", message);
    response.insert("code", 13);
    response.insert("codeName", "Unauthorized");
    response.insert("$db", database);
    let frame = encode_op_msg(request_id.wrapping_add(1), request_id, &response)?;
    write_frame(stream, &frame).await
}

async fn write_frame(stream: &mut BoxedMongoIo, frame: &[u8]) -> io::Result<()> {
    stream.write_all(frame).await?;
    stream.flush().await
}

fn scram_username(command: &Document) -> io::Result<String> {
    let payload = match command.get("payload") {
        Some(Bson::Binary(binary)) => &binary.bytes,
        _ => {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "SCRAM saslStart payload must be BSON binary",
            ))
        }
    };
    let payload = std::str::from_utf8(payload).map_err(|_| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            "SCRAM client-first message is not UTF-8",
        )
    })?;
    let attributes = payload.strip_prefix("n,,").ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::PermissionDenied,
            "SCRAM channel binding is not supported by this gateway",
        )
    })?;
    let encoded = attributes
        .split(',')
        .find_map(|attribute| attribute.strip_prefix("n="))
        .ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                "SCRAM client-first message has no username",
            )
        })?;
    let username = encoded.replace("=2C", ",").replace("=3D", "=");
    if username.is_empty() || username.len() > 128 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "SCRAM username is invalid",
        ));
    }
    Ok(username)
}

fn build_server_tls(cert_path: &str, key_path: &str) -> io::Result<TlsAcceptor> {
    let certs = load_certs(cert_path)?;
    let key = load_private_key(key_path)?;
    let config = ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(certs, key)
        .map_err(|error| {
            io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("invalid MongoDB gateway TLS certificate/key: {error}"),
            )
        })?;
    Ok(TlsAcceptor::from(Arc::new(config)))
}

fn build_client_tls(ca_path: &str) -> io::Result<TlsConnector> {
    let mut roots = RootCertStore::empty();
    for certificate in load_certs(ca_path)? {
        roots.add(certificate).map_err(|error| {
            io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("invalid MongoDB upstream CA: {error}"),
            )
        })?;
    }
    let config = ClientConfig::builder()
        .with_root_certificates(roots)
        .with_no_client_auth();
    Ok(TlsConnector::from(Arc::new(config)))
}

fn load_certs(path: &str) -> io::Result<Vec<CertificateDer<'static>>> {
    let file = File::open(path)?;
    rustls_pemfile::certs(&mut BufReader::new(file))
        .collect::<Result<Vec<_>, _>>()
        .map_err(|error| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                format!("invalid certificate PEM: {error}"),
            )
        })
}

fn load_private_key(path: &str) -> io::Result<PrivateKeyDer<'static>> {
    rustls_pemfile::private_key(&mut BufReader::new(File::open(path)?))
        .map_err(|error| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                format!("invalid private key PEM: {error}"),
            )
        })?
        .ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                "MongoDB gateway private key is missing",
            )
        })
}

fn env_required(name: &str) -> io::Result<String> {
    std::env::var(name)
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, format!("{name} is required")))
        .and_then(|value| {
            if value.trim().is_empty() {
                Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    format!("{name} cannot be empty"),
                ))
            } else {
                Ok(value)
            }
        })
}

fn env_required_or(name: &str, default: &str) -> io::Result<String> {
    Ok(std::env::var(name).unwrap_or_else(|_| default.to_owned()))
}

fn env_optional(name: &str) -> Option<String> {
    std::env::var(name)
        .ok()
        .filter(|value| !value.trim().is_empty())
}

fn env_bool(name: &str, default: bool) -> io::Result<bool> {
    match std::env::var(name) {
        Ok(value) => match value.trim().to_ascii_lowercase().as_str() {
            "true" | "1" | "yes" | "on" => Ok(true),
            "false" | "0" | "no" | "off" => Ok(false),
            other => Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("invalid {name}: {other}"),
            )),
        },
        Err(_) => Ok(default),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use mongodb::bson::doc;

    #[test]
    fn op_msg_round_trip_preserves_command_document() {
        let command =
            doc! { "find": "records", "filter": { "active": true }, "$db": "tenant_a_db" };
        let frame = encode_op_msg(7, 0, &command).unwrap();
        let parsed = decode_op_msg(&frame).unwrap();
        assert_eq!(parsed.request_id, 7);
        assert_eq!(parsed.body, command);
    }

    #[test]
    fn hello_reply_removes_upstream_topology_addresses() {
        let mut reply = doc! {
            "ok": 1.0,
            "isWritablePrimary": true,
            "setName": "rs0",
            "hosts": ["mongo-a.internal:27017", "mongo-b.internal:27017"],
            "primary": "mongo-a.internal:27017",
            "topologyVersion": { "counter": 1_i64 }
        };
        for field in [
            "hosts",
            "passives",
            "arbiters",
            "primary",
            "setName",
            "setVersion",
            "electionId",
            "topologyVersion",
            "me",
            "msg",
            "serviceId",
        ] {
            reply.remove(field);
        }
        assert!(reply.get("hosts").is_none());
        assert!(reply.get("setName").is_none());
        assert_eq!(reply.get_bool("isWritablePrimary").unwrap(), true);
    }

    #[test]
    fn rejects_non_op_msg_and_checksum_flags() {
        let mut frame = encode_op_msg(7, 0, &Document::new()).unwrap();
        frame[12..16].copy_from_slice(&2004i32.to_le_bytes());
        assert!(decode_op_msg(&frame).is_err());

        let mut frame = encode_op_msg(7, 0, &Document::new()).unwrap();
        frame[16..20].copy_from_slice(&1i32.to_le_bytes());
        assert!(decode_op_msg(&frame).is_err());
    }

    #[test]
    fn merges_insert_document_sequences_for_policy_validation() {
        let mut command = doc! { "insert": "records", "$db": "tenant_a_db" };
        merge_sequences(
            &mut command,
            &[("documents".into(), vec![doc! { "secret": "a" }])],
        )
        .unwrap();
        assert_eq!(command.get_array("documents").unwrap().len(), 1);
    }

    #[test]
    fn scram_username_is_decoded_from_client_first_message() {
        let command = doc! {
            "saslStart": 1,
            "mechanism": SCRAM_SHA_256,
            "payload": bson::Binary { subtype: bson::spec::BinarySubtype::Generic, bytes: b"n,,n=tenant=2Ca,r=nonce".to_vec() }
        };
        assert_eq!(scram_username(&command).unwrap(), "tenant,a");
    }
}
