//! Cloud assignment activation for the restricted MongoDB OP_MSG gateway.
//!
//! The runtime provisions one SCRAM-SHA-256 readWrite identity per tenant
//! database, verifies authentication and exact role scope, removes revoked
//! identities, and supervises the node-local gateway.

use crate::{
    mongodb_gateway::MongoIdentityRegistry,
    runtime_activation::{GatewayProcessSpec, RuntimeProcessSupervisor},
    runtime_reconciliation::{self, RuntimePhase, RuntimeRecord},
    sqlserver_runtime::VerifiedBinding,
};
use mongodb::{
    bson::{self, doc, Bson, Document},
    options::{ClientOptions, Credential, Tls, TlsOptions},
    Client,
};
use rustls::{
    pki_types::{CertificateDer, ServerName},
    ClientConfig, RootCertStore,
};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::{
    collections::{HashMap, HashSet},
    fs::{self, File},
    io::{self, BufReader},
    net::SocketAddr,
    path::Path,
    time::Duration,
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpStream,
    time::timeout,
};
use tokio_rustls::{client::TlsStream, TlsConnector};

const OP_MSG: i32 = 2013;
const MAX_MESSAGE_BYTES: usize = 48 * 1024 * 1024;

#[derive(Clone)]
pub struct MongoRuntime {
    supervisor: RuntimeProcessSupervisor,
}

impl MongoRuntime {
    pub fn new() -> Self {
        Self {
            supervisor: RuntimeProcessSupervisor::new(),
        }
    }
    pub async fn is_running(&self, id: &str) -> bool {
        self.supervisor.is_running(id).await
    }
    pub async fn stop(&self, id: &str) -> io::Result<()> {
        self.supervisor.stop(id).await
    }
    pub async fn shutdown(&self) -> io::Result<()> {
        self.supervisor.stop_all().await
    }

    pub async fn activate(
        &self,
        assignment: &Value,
        credentials: &Value,
        executable_dir: &Path,
        private_root: &Path,
        state_path: &Path,
        state: &mut RuntimeRecord,
    ) -> Result<Vec<VerifiedBinding>, Box<dyn std::error::Error + Send + Sync>> {
        let assignment_id = required(assignment, "assignment_id")?;
        if required(assignment, "provider_key")? != "mongodb" {
            return Err(invalid("MongoDB runtime cannot activate another provider").into());
        }
        if required(assignment, "cloud_integration_state")? != "enabled" {
            return Err(invalid("MongoDB assignment is not enabled for live integration").into());
        }
        if required(assignment, "gateway_runtime")? != "proxima-mongodb-gateway" {
            return Err(invalid("assignment does not select the MongoDB OP_MSG gateway").into());
        }
        let runtime = credentials
            .get("gateway_runtime_config")
            .ok_or_else(|| invalid("gateway_runtime_config is required for MongoDB activation"))?;
        if runtime.get("schema_version").and_then(Value::as_u64) != Some(1)
            || runtime.get("provider_key").and_then(Value::as_str) != Some("mongodb")
        {
            return Err(invalid("MongoDB gateway runtime schema/provider mismatch").into());
        }
        let users = runtime
            .get("users")
            .and_then(Value::as_array)
            .ok_or_else(|| invalid("MongoDB runtime users must be an array"))?;
        validate_tenant_coverage(assignment, users)?;
        let bindings = assignment
            .get("tenant_bindings")
            .and_then(Value::as_array)
            .ok_or_else(|| invalid("MongoDB tenant_bindings are required"))?;
        let active_count = bindings
            .iter()
            .filter(|b| b.get("status").and_then(Value::as_str) != Some("revoked"))
            .count();
        if active_count != users.len() {
            return Err(invalid(
                "MongoDB runtime users must exactly cover non-revoked tenant bindings",
            )
            .into());
        }
        let host = assignment
            .pointer("/endpoint/host")
            .and_then(Value::as_str)
            .ok_or_else(|| invalid("MongoDB target host is missing"))?;
        let port = assignment
            .pointer("/endpoint/port")
            .and_then(Value::as_u64)
            .filter(|v| (1..=65535).contains(v))
            .ok_or_else(|| invalid("MongoDB target port is invalid"))? as u16;
        let admin_user = required(credentials, "username")?;
        let admin_password = required(credentials, "password")?;
        let ca_file = runtime
            .get("upstream_tls_ca_file")
            .and_then(Value::as_str)
            .map(str::to_owned)
            .or_else(|| std::env::var("PROXIMA_MONGODB_UPSTREAM_TLS_CA_FILE").ok())
            .ok_or_else(|| invalid("MongoDB upstream TLS CA file is required"))?;
        let admin_client =
            mongo_client(host, port, admin_user, admin_password, "admin", &ca_file).await?;
        let admin_db = admin_client.database("admin");
        let desired_revision = state.desired_revision;
        let credential_revision = state.credential_revision;
        let needs_apply = state.phase != RuntimePhase::Applied
            || state.applied_revision != Some(desired_revision);
        let mut evidence = Vec::with_capacity(bindings.len());
        for binding in bindings {
            let tenant_id = required(binding, "tenant_id")?;
            let username = required(binding, "identity_reference")?;
            let database = required(binding, "namespace")?;
            if binding.get("status").and_then(Value::as_str) == Some("revoked") {
                let result = admin_db.run_command(doc! {"dropUser": username}).await;
                if let Err(error) = result {
                    if !error.to_string().to_ascii_lowercase().contains("not found") {
                        return Err(Box::new(error));
                    }
                }
                evidence.push(mongo_binding_evidence(
                    binding,
                    assignment,
                    "revoked",
                    json!({"username":username,"database":database,"user_dropped":true}),
                )?);
                continue;
            }
            let user = users
                .iter()
                .find(|u| u.get("tenant_id").and_then(Value::as_str) == Some(tenant_id))
                .ok_or_else(|| invalid("MongoDB tenant binding has no runtime user"))?;
            if required(user, "username")? != username
                || required(user, "database")? != database
                || user
                    .get("auth_source")
                    .and_then(Value::as_str)
                    .unwrap_or("admin")
                    != "admin"
            {
                return Err(invalid(
                    "MongoDB username/database/authSource does not match the Cloud tenant binding",
                )
                .into());
            }
            let password = required(user, "password")?;
            if password.len() < 24 || !password.bytes().all(|b| (33..=126).contains(&b)) {
                return Err(invalid(
                    "MongoDB tenant password must contain at least 24 printable ASCII characters",
                )
                .into());
            }
            let users_info = admin_db
                .run_command(doc! {"usersInfo": username, "showCredentials": false})
                .await?;
            let exists = users_info
                .get_array("users")
                .map(|rows| !rows.is_empty())
                .unwrap_or(false);
            let roles = vec![doc! {"role":"readWrite", "db":database}];
            if exists {
                admin_db.run_command(doc! {"updateUser": username, "pwd": password, "roles": roles, "mechanisms":["SCRAM-SHA-256"]}).await?;
            } else {
                admin_db.run_command(doc! {"createUser": username, "pwd": password, "roles": roles, "mechanisms":["SCRAM-SHA-256"]}).await?;
            }
            let verified_info = admin_db
                .run_command(doc! {"usersInfo": username, "showCredentials": false})
                .await?;
            let verified_user = verified_info
                .get_array("users")?
                .first()
                .and_then(Bson::as_document)
                .ok_or_else(|| invalid("MongoDB usersInfo did not return the provisioned user"))?;
            let verified_roles = verified_user.get_array("roles")?;
            if verified_roles.len() != 1
                || verified_roles[0].as_document().is_none_or(|role| {
                    role.get_str("role").ok() != Some("readWrite")
                        || role.get_str("db").ok() != Some(database)
                })
            {
                return Err(invalid(
                    "MongoDB tenant user must have exactly readWrite on its assigned database",
                )
                .into());
            }
            let tenant_client =
                mongo_client(host, port, username, password, "admin", &ca_file).await?;
            tenant_client
                .database(database)
                .run_command(doc! {"ping":1})
                .await?;
            evidence.push(mongo_binding_evidence(binding, assignment, "active", json!({"username":username,"database":database,"roles":[{"role":"readWrite","db":database}],"scram_sha256_authentication_verified":true}))?);
        }

        let listen: SocketAddr = runtime
            .get("listen_addr")
            .and_then(Value::as_str)
            .unwrap_or("127.0.0.1:27018")
            .parse()?;
        let kubernetes_mode =
            std::env::var("PROXIMA_GATEWAY_EXECUTION_MODE").as_deref() == Ok("kubernetes");
        if !kubernetes_mode && !listen.ip().is_loopback() {
            return Err(invalid("local MongoDB gateway must bind to loopback; use Kubernetes execution mode for pod networking").into());
        }
        let upstream_addr = required(runtime, "upstream_addr")?;
        let upstream_name = required(runtime, "upstream_tls_server_name")?;
        let ca_file = runtime
            .get("upstream_tls_ca_file")
            .and_then(Value::as_str)
            .map(str::to_owned)
            .or_else(|| std::env::var("PROXIMA_MONGODB_UPSTREAM_TLS_CA_FILE").ok())
            .ok_or_else(|| invalid("MongoDB upstream TLS CA file is required"))?;
        let cert_file = runtime
            .get("tls_cert_file")
            .and_then(Value::as_str)
            .map(str::to_owned)
            .or_else(|| std::env::var("PROXIMA_MONGODB_TLS_CERT_FILE").ok())
            .ok_or_else(|| invalid("MongoDB gateway TLS certificate is required"))?;
        let key_file = runtime
            .get("tls_key_file")
            .and_then(Value::as_str)
            .map(str::to_owned)
            .or_else(|| std::env::var("PROXIMA_MONGODB_TLS_KEY_FILE").ok())
            .ok_or_else(|| invalid("MongoDB gateway TLS key is required"))?;
        for path in [&ca_file, &cert_file, &key_file] {
            if !Path::new(path).is_file() {
                return Err(invalid("MongoDB gateway TLS file is missing").into());
            }
        }
        if !runtime
            .get("upstream_tls")
            .and_then(Value::as_bool)
            .unwrap_or(true)
        {
            return Err(invalid("Cloud-managed MongoDB activation requires upstream TLS").into());
        }

        if users.is_empty() {
            self.stop(assignment_id).await?;
            if needs_apply {
                state.begin_apply(desired_revision, credential_revision)?;
                runtime_reconciliation::persist(state_path, state)?;
                state.mark_applied(desired_revision, true)?;
                runtime_reconciliation::persist(state_path, state)?;
            }
            return Ok(evidence);
        }
        // The gateway only needs identity/database mappings; never persist the
        // tenant passwords used by the Cloud-side provisioning step.
        let mut registry_value = runtime.clone();
        if let Some(registry_users) = registry_value
            .get_mut("users")
            .and_then(Value::as_array_mut)
        {
            for user in registry_users {
                if let Some(object) = user.as_object_mut() {
                    object.remove("password");
                }
            }
        }
        let registry_json = serde_json::to_vec(&registry_value)?;
        let registry_path = private_root.join("gateway-identities").join(format!(
            "{}.json",
            hex::encode(Sha256::digest(assignment_id.as_bytes()))
        ));
        write_private_file(&registry_path, &registry_json)?;
        let registry = MongoIdentityRegistry::load(&registry_path)?;
        if registry.principal_count() != users.len() {
            return Err(invalid("MongoDB registry principal count mismatch").into());
        }
        if kubernetes_mode {
            probe_upstream_hello(upstream_addr, upstream_name, &ca_file).await?;
            if needs_apply {
                state.begin_apply(desired_revision, credential_revision)?;
                runtime_reconciliation::persist(state_path, state)?;
                state.mark_applied(desired_revision, true)?;
                runtime_reconciliation::persist(state_path, state)?;
            }
            return Ok(evidence);
        }
        if state.phase == RuntimePhase::Applied
            && state.applied_revision == Some(desired_revision)
            && self.is_running(assignment_id).await
        {
            probe_upstream_hello(upstream_addr, upstream_name, &ca_file).await?;
            return Ok(evidence);
        }
        if self.is_running(assignment_id).await {
            self.stop(assignment_id).await?;
        }
        probe_upstream_hello(upstream_addr, upstream_name, &ca_file).await?;
        let binary = executable_dir.join(format!(
            "proxima-mongodb-gateway{}",
            std::env::consts::EXE_SUFFIX
        ));
        if !binary.is_file() {
            return Err(
                invalid("proxima-mongodb-gateway binary is not packaged beside Engine").into(),
            );
        }
        state.begin_apply(desired_revision, credential_revision)?;
        runtime_reconciliation::persist(state_path, state)?;
        let spec = GatewayProcessSpec {
            assignment_id: assignment_id.to_owned(),
            executable: binary.to_string_lossy().into_owned(),
            args: Vec::new(),
            env: vec![
                ("PROXIMA_MONGODB_LISTEN_ADDR".into(), listen.to_string()),
                (
                    "PROXIMA_MONGODB_IDENTITY_REGISTRY".into(),
                    registry_path.to_string_lossy().into_owned(),
                ),
                (
                    "PROXIMA_MONGODB_UPSTREAM_ADDR".into(),
                    upstream_addr.to_owned(),
                ),
                ("PROXIMA_MONGODB_UPSTREAM_TLS".into(), "true".into()),
                (
                    "PROXIMA_MONGODB_UPSTREAM_TLS_SERVER_NAME".into(),
                    upstream_name.to_owned(),
                ),
                (
                    "PROXIMA_MONGODB_UPSTREAM_TLS_CA_FILE".into(),
                    ca_file.to_owned(),
                ),
                ("PROXIMA_MONGODB_TLS_CERT_FILE".into(), cert_file.to_owned()),
                ("PROXIMA_MONGODB_TLS_KEY_FILE".into(), key_file.to_owned()),
                (
                    "PROXIMA_MONGODB_MAX_CONNECTIONS".into(),
                    runtime
                        .get("max_connections")
                        .and_then(Value::as_u64)
                        .unwrap_or(256)
                        .to_string(),
                ),
                (
                    "PROXIMA_MONGODB_MAX_SESSION_BINDINGS".into(),
                    runtime
                        .get("max_session_bindings")
                        .and_then(Value::as_u64)
                        .unwrap_or_else(|| {
                            runtime
                                .get("max_connections")
                                .and_then(Value::as_u64)
                                .unwrap_or(256)
                                .saturating_mul(16)
                        })
                        .to_string(),
                ),
                ("RUST_LOG".into(), "proxima_engine=info".into()),
            ],
            readiness_addr: listen,
            startup_timeout: Duration::from_secs(20),
        };
        if let Err(error) = self.supervisor.start(spec).await {
            state.mark_failed("MONGODB_GATEWAY_START_FAILED")?;
            runtime_reconciliation::persist(state_path, state)?;
            return Err(Box::new(error));
        }
        if let Err(error) = probe_upstream_hello(upstream_addr, upstream_name, &ca_file).await {
            let _ = self.stop(assignment_id).await;
            state.mark_failed("MONGODB_UPSTREAM_HEALTH_FAILED")?;
            runtime_reconciliation::persist(state_path, state)?;
            return Err(error);
        }
        state.mark_applied(desired_revision, true)?;
        runtime_reconciliation::persist(state_path, state)?;
        Ok(evidence)
    }
}
impl Default for MongoRuntime {
    fn default() -> Self {
        Self::new()
    }
}

fn validate_tenant_coverage(assignment: &Value, users: &[Value]) -> io::Result<()> {
    let bindings = assignment
        .get("tenant_bindings")
        .and_then(Value::as_array)
        .ok_or_else(|| invalid("tenant_bindings are required"))?;
    let active: Vec<&Value> = bindings
        .iter()
        .filter(|b| b.get("status").and_then(Value::as_str) != Some("revoked"))
        .collect();
    if active.len() != users.len() {
        return Err(invalid(
            "MongoDB principals must exactly cover non-revoked tenant bindings",
        ));
    }
    let mut expected = HashMap::new();
    for binding in bindings {
        let tenant = required(binding, "tenant_id")?;
        let namespace = required(binding, "namespace")?;
        let identity = required(binding, "identity_reference")?;
        if expected
            .insert(
                tenant.to_owned(),
                (namespace.to_owned(), identity.to_owned()),
            )
            .is_some()
        {
            return Err(invalid("duplicate MongoDB tenant binding"));
        }
        if !matches!(
            required(binding, "status")?,
            "pending" | "provisioning" | "active" | "revoked"
        ) {
            return Err(invalid(
                "MongoDB tenant binding has an unsupported lifecycle status",
            ));
        }
    }
    let mut seen = HashSet::new();
    let mut usernames = HashSet::new();
    for user in users {
        let tenant = required(user, "tenant_id")?;
        let database = required(user, "database")?;
        let username = required(user, "username")?;
        if username.len() > 128 || !username.bytes().all(|b| b.is_ascii_graphic()) {
            return Err(invalid("MongoDB username is invalid"));
        }
        let binding = expected
            .get(tenant)
            .ok_or_else(|| invalid("MongoDB identity references an unknown tenant"))?;
        if binding.0 != database
            || binding.1 != username
            || !active
                .iter()
                .any(|b| b.get("tenant_id").and_then(Value::as_str) == Some(tenant))
            || !seen.insert(tenant.to_owned())
            || !usernames.insert(username.to_owned())
        {
            return Err(invalid("MongoDB identity is duplicated, unassigned or mapped to the wrong database/principal"));
        }
        if user
            .get("auth_source")
            .and_then(Value::as_str)
            .unwrap_or("admin")
            != "admin"
        {
            return Err(invalid(
                "MongoDB gateway currently supports only admin SCRAM authentication source",
            ));
        }
    }
    Ok(())
}

async fn mongo_client(
    host: &str,
    port: u16,
    username: &str,
    password: &str,
    auth_source: &str,
    ca_file: &str,
) -> Result<Client, Box<dyn std::error::Error + Send + Sync>> {
    let uri = format!("mongodb://{host}:{port}/");
    let mut options = ClientOptions::parse(uri).await?;
    options.tls = Some(Tls::Enabled(
        TlsOptions::builder()
            .ca_file_path(std::path::PathBuf::from(ca_file))
            .build(),
    ));
    options.credential = Some(
        Credential::builder()
            .username(username.to_owned())
            .password(password.to_owned())
            .source(auth_source.to_owned())
            .build(),
    );
    Ok(Client::with_options(options)?)
}

fn mongo_binding_evidence(
    binding: &Value,
    assignment: &Value,
    status: &str,
    details: Value,
) -> io::Result<VerifiedBinding> {
    Ok(VerifiedBinding {
        provider_key: "mongodb".into(),
        binding_id: required(binding, "binding_id")?.to_owned(),
        target_id: required(assignment, "database_target_id")?.to_owned(),
        revision: assignment
            .get("config_revision")
            .and_then(Value::as_i64)
            .ok_or_else(|| invalid("MongoDB config revision missing"))?,
        tenant_id: required(binding, "tenant_id")?.to_owned(),
        identity_reference: required(binding, "identity_reference")?.to_owned(),
        database: required(binding, "namespace")?.to_owned(),
        status: status.to_owned(),
        details: if status == "active" {
            let mut verified = details.as_object().cloned().unwrap_or_default();
            verified.insert("identity_verified".into(), Value::Bool(true));
            verified.insert("isolation_verified".into(), Value::Bool(true));
            Value::Object(verified)
        } else {
            details
        },
    })
}

async fn probe_upstream_hello(
    addr: &str,
    server_name: &str,
    ca_file: &str,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let _ = rustls::crypto::ring::default_provider().install_default();
    let mut socket = timeout(Duration::from_secs(10), TcpStream::connect(addr)).await??;
    let connector = TlsConnector::from(std::sync::Arc::new(client_tls(ca_file)?));
    let name = ServerName::try_from(server_name.to_owned())
        .map_err(|error| invalid(&error.to_string()))?;
    let mut stream: TlsStream<TcpStream> =
        timeout(Duration::from_secs(10), connector.connect(name, socket)).await??;
    let command = doc! { "hello": 1, "$db": "admin" };
    let bson = bson::to_vec(&command)?;
    let message_len = 16usize + 4 + 1 + bson.len();
    if message_len > MAX_MESSAGE_BYTES {
        return Err(invalid("MongoDB health probe frame exceeds limit").into());
    }
    let mut frame = Vec::with_capacity(message_len);
    frame.extend_from_slice(&(message_len as i32).to_le_bytes());
    frame.extend_from_slice(&1i32.to_le_bytes());
    frame.extend_from_slice(&0i32.to_le_bytes());
    frame.extend_from_slice(&OP_MSG.to_le_bytes());
    frame.extend_from_slice(&0i32.to_le_bytes());
    frame.push(0);
    frame.extend_from_slice(&bson);
    stream.write_all(&frame).await?;
    stream.flush().await?;
    let mut header = [0u8; 16];
    timeout(Duration::from_secs(10), stream.read_exact(&mut header)).await??;
    let response_len = i32::from_le_bytes(header[0..4].try_into().unwrap()) as usize;
    let opcode = i32::from_le_bytes(header[12..16].try_into().unwrap());
    if response_len < 21 || response_len > MAX_MESSAGE_BYTES || opcode != OP_MSG {
        return Err(invalid("MongoDB upstream returned an invalid OP_MSG health response").into());
    }
    let mut rest = vec![0u8; response_len - 16];
    timeout(Duration::from_secs(10), stream.read_exact(&mut rest)).await??;
    if rest.len() < 5 || rest[4] != 0 {
        return Err(invalid("MongoDB hello response has no body section").into());
    }
    let response: Document = bson::from_slice(&rest[5..])?;
    let ok = response
        .get("ok")
        .and_then(|v| v.as_f64())
        .unwrap_or_else(|| response.get_i32("ok").map(|v| v as f64).unwrap_or(0.0));
    if (ok - 1.0).abs() > f64::EPSILON {
        return Err(invalid("MongoDB upstream hello command failed").into());
    }
    Ok(())
}
fn client_tls(ca: &str) -> io::Result<ClientConfig> {
    let mut roots = RootCertStore::empty();
    let certs = rustls_pemfile::certs(&mut BufReader::new(File::open(ca)?))
        .collect::<Result<Vec<CertificateDer<'static>>, _>>()
        .map_err(|error| invalid(&error.to_string()))?;
    if certs.is_empty() {
        return Err(invalid("MongoDB upstream CA bundle is empty"));
    }
    for cert in certs {
        roots
            .add(cert)
            .map_err(|error| invalid(&error.to_string()))?;
    }
    Ok(ClientConfig::builder()
        .with_root_certificates(roots)
        .with_no_client_auth())
}
fn required<'a>(value: &'a Value, key: &str) -> io::Result<&'a str> {
    value
        .get(key)
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|v| !v.is_empty())
        .ok_or_else(|| invalid(&format!("{key} is missing or empty")))
}
fn invalid(message: &str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message.to_owned())
}
fn write_private_file(path: &Path, bytes: &[u8]) -> io::Result<()> {
    let parent = path
        .parent()
        .ok_or_else(|| invalid("identity path has no parent"))?;
    fs::create_dir_all(parent)?;
    set_private_directory(parent)?;
    let temporary = path.with_extension("json.tmp");
    if temporary.exists() {
        fs::remove_file(&temporary)?;
    }
    fs::write(&temporary, bytes)?;
    set_private_file(&temporary)?;
    if path.exists() {
        fs::remove_file(path)?;
    }
    fs::rename(&temporary, path)?;
    set_private_file(path)
}
#[cfg(unix)]
fn set_private_directory(path: &Path) -> io::Result<()> {
    use std::os::unix::fs::PermissionsExt;
    fs::set_permissions(path, fs::Permissions::from_mode(0o700))
}
#[cfg(unix)]
fn set_private_file(path: &Path) -> io::Result<()> {
    use std::os::unix::fs::PermissionsExt;
    fs::set_permissions(path, fs::Permissions::from_mode(0o600))
}
#[cfg(windows)]
fn set_private_directory(path: &Path) -> io::Result<()> {
    windows_acl(path, true)
}
#[cfg(windows)]
fn set_private_file(path: &Path) -> io::Result<()> {
    windows_acl(path, false)
}
#[cfg(windows)]
fn windows_acl(path: &Path, directory: bool) -> io::Result<()> {
    use std::process::Command;
    let output = Command::new("whoami.exe")
        .args(["/user", "/fo", "csv", "/nh"])
        .output()?;
    if !output.status.success() {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "cannot resolve Windows service SID",
        ));
    }
    let sid = String::from_utf8_lossy(&output.stdout)
        .trim()
        .split(',')
        .nth(1)
        .map(|v| v.trim().trim_matches('"'))
        .filter(|v| v.starts_with("S-1-"))
        .ok_or_else(|| invalid("invalid Windows service SID"))?
        .to_owned();
    let current = if directory {
        format!("*{sid}:(OI)(CI)F")
    } else {
        format!("*{sid}:F")
    };
    let system = if directory {
        "*S-1-5-18:(OI)(CI)F"
    } else {
        "*S-1-5-18:F"
    };
    let admins = if directory {
        "*S-1-5-32-544:(OI)(CI)F"
    } else {
        "*S-1-5-32-544:F"
    };
    for args in [
        vec!["/reset".to_owned()],
        vec!["/inheritance:r".to_owned()],
        vec![
            "/grant:r".to_owned(),
            current,
            system.to_owned(),
            admins.to_owned(),
        ],
    ] {
        let result = Command::new("icacls.exe").arg(path).args(args).output()?;
        if !result.status.success() {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "icacls failed while protecting MongoDB identity registry",
            ));
        }
    }
    Ok(())
}
#[cfg(not(any(unix, windows)))]
fn set_private_directory(_: &Path) -> io::Result<()> {
    Err(io::Error::new(
        io::ErrorKind::Unsupported,
        "secure identity storage unsupported",
    ))
}
#[cfg(not(any(unix, windows)))]
fn set_private_file(_: &Path) -> io::Result<()> {
    Err(io::Error::new(
        io::ErrorKind::Unsupported,
        "secure identity storage unsupported",
    ))
}

#[cfg(test)]
mod tests {
    use super::validate_tenant_coverage;
    use serde_json::json;
    #[test]
    fn mongo_runtime_requires_exact_namespace_coverage() {
        let assignment = json!({"tenant_bindings":[{"tenant_id":"t1","namespace":"db_t1","identity_reference":"user1","status":"active"}]});
        let users = vec![
            json!({"tenant_id":"t1","username":"user1","database":"db_t1","auth_source":"admin"}),
        ];
        assert!(validate_tenant_coverage(&assignment, &users).is_ok());
        let wrong = vec![
            json!({"tenant_id":"t1","username":"user1","database":"db_other","auth_source":"admin"}),
        ];
        assert!(validate_tenant_coverage(&assignment, &wrong).is_err());
    }
}
