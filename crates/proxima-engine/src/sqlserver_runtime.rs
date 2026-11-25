//! Cloud assignment activation for SQL Server's native tenant lifecycle and TDS gateway.
use crate::{
    runtime_activation::{GatewayProcessSpec, RuntimeProcessSupervisor},
    runtime_reconciliation::{self, RuntimePhase, RuntimeRecord},
    sqlserver_tds_gateway::{SqlServerTdsConfig, TdsTenantBinding},
    sqlserver_tenant::{SqlServerExecutor, SqlServerTenant, TiberiusSqlServerExecutor},
};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::{
    collections::{HashMap, HashSet},
    fs, io,
    net::SocketAddr,
    path::{Path, PathBuf},
    time::Duration,
};

#[derive(Clone)]
pub struct SqlServerRuntime {
    supervisor: RuntimeProcessSupervisor,
}

#[derive(Clone, Debug)]
pub struct VerifiedBinding {
    pub provider_key: String,
    pub binding_id: String,
    pub target_id: String,
    pub revision: i64,
    pub tenant_id: String,
    pub identity_reference: String,
    pub database: String,
    pub status: String,
    pub details: serde_json::Value,
}

impl SqlServerRuntime {
    pub fn new() -> Self {
        Self {
            supervisor: RuntimeProcessSupervisor::new(),
        }
    }
    pub async fn stop(&self, assignment_id: &str) -> io::Result<()> {
        self.supervisor.stop(assignment_id).await
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
        if required(assignment, "provider_key")? != "sqlserver"
            || required(assignment, "gateway_runtime")? != "proxima-sqlserver-tds-gateway"
        {
            return Err(
                invalid("SQL Server assignment must select the Proxima TDS gateway").into(),
            );
        }
        if required(assignment, "cloud_integration_state")? != "enabled" {
            return Err(invalid("preview SQL Server assignments cannot be activated").into());
        }
        let runtime = credentials
            .get("gateway_runtime_config")
            .ok_or_else(|| invalid("SQL Server gateway_runtime_config is required"))?;
        if runtime.get("schema_version").and_then(Value::as_u64) != Some(1)
            || runtime.get("provider_key").and_then(Value::as_str) != Some("sqlserver")
        {
            return Err(invalid("SQL Server runtime config schema/provider mismatch").into());
        }
        let users = runtime
            .get("users")
            .and_then(Value::as_array)
            .ok_or_else(|| invalid("SQL Server runtime users must be an array"))?;
        let bindings = assignment
            .get("tenant_bindings")
            .and_then(Value::as_array)
            .ok_or_else(|| invalid("SQL Server tenant_bindings are missing"))?;
        let host = assignment
            .pointer("/endpoint/host")
            .and_then(Value::as_str)
            .filter(|v| !v.is_empty())
            .ok_or_else(|| invalid("SQL Server endpoint host is missing"))?;
        let port = assignment
            .pointer("/endpoint/port")
            .and_then(Value::as_u64)
            .filter(|v| (1..=65535).contains(v))
            .ok_or_else(|| invalid("SQL Server endpoint port is invalid"))?
            as u16;
        let admin_user = required(credentials, "username")?;
        let admin_password = required(credentials, "password")?;
        let ca_path = runtime
            .get("upstream_ca_pem")
            .and_then(Value::as_str)
            .map(PathBuf::from)
            .or_else(|| {
                std::env::var_os("PROXIMA_SQLSERVER_TDS_UPSTREAM_CA_PEM").map(PathBuf::from)
            })
            .ok_or_else(|| invalid("SQL Server upstream CA PEM path is required"))?;
        let cert_path = runtime
            .get("client_cert_pem")
            .and_then(Value::as_str)
            .map(PathBuf::from)
            .or_else(|| {
                std::env::var_os("PROXIMA_SQLSERVER_TDS_CLIENT_CERT_PEM").map(PathBuf::from)
            })
            .ok_or_else(|| invalid("SQL Server gateway client certificate path is required"))?;
        let key_path = runtime
            .get("client_key_pem")
            .and_then(Value::as_str)
            .map(PathBuf::from)
            .or_else(|| std::env::var_os("PROXIMA_SQLSERVER_TDS_CLIENT_KEY_PEM").map(PathBuf::from))
            .ok_or_else(|| invalid("SQL Server gateway private key path is required"))?;
        let ca_bundle = fs::read(&ca_path)?;
        let admin = TiberiusSqlServerExecutor::new(host, port, admin_user, admin_password)?
            .with_ca_bundle(ca_bundle.clone())?;
        let needs_apply = state.phase != RuntimePhase::Applied
            || state.applied_revision != Some(state.desired_revision);

        let mut binding_by_tenant = HashMap::new();
        for binding in bindings {
            let tenant_id = required(binding, "tenant_id")?.to_owned();
            if binding_by_tenant.insert(tenant_id, binding).is_some() {
                return Err(invalid("duplicate SQL Server tenant binding").into());
            }
        }
        let active_binding_count = bindings
            .iter()
            .filter(|b| b.get("status").and_then(Value::as_str) != Some("revoked"))
            .count();
        if active_binding_count != users.len() {
            return Err(invalid(
                "SQL Server runtime users must exactly cover every non-revoked tenant binding",
            )
            .into());
        }
        let mut seen = HashSet::new();
        let mut seen_usernames = HashSet::new();
        let mut tds_tenants = Vec::with_capacity(users.len());
        let mut verified = Vec::with_capacity(bindings.len());
        for binding in bindings
            .iter()
            .filter(|b| b.get("status").and_then(Value::as_str) == Some("revoked"))
        {
            let username = required(binding, "identity_reference")?;
            let database = required(binding, "namespace")?;
            let tenant_key = username
                .strip_prefix("agata_")
                .and_then(|s| s.strip_suffix("_app"))
                .ok_or_else(|| {
                    invalid("revoked SQL Server identity is not a managed Proxima login")
                })?;
            if !database.eq_ignore_ascii_case(&format!("AGATA_{tenant_key}")) {
                return Err(invalid(
                    "revoked SQL Server identity/database mapping is inconsistent",
                )
                .into());
            }
            let revoked = SqlServerTenant::new(tenant_key, "REVOKED-IDENTITY-NOT-USED-0001")?;
            if needs_apply {
                revoked.revoke(&admin).await?;
            }
            verified.push(VerifiedBinding {
                provider_key: "sqlserver".into(),
                binding_id: required(binding, "binding_id")?.to_owned(),
                target_id: required(assignment, "database_target_id")?.to_owned(),
                revision: assignment
                    .get("config_revision")
                    .and_then(Value::as_i64)
                    .ok_or_else(|| invalid("SQL Server config revision is missing"))?,
                tenant_id: required(binding, "tenant_id")?.to_owned(),
                identity_reference: username.to_owned(),
                database: database.to_owned(),
                status: "revoked".into(),
                details: json!({"database":database,"verification":"SQL Server login disabled and revoked"}),
            });
        }
        for user in users {
            let tenant_id = required(user, "tenant_id")?;
            let tenant_key = required(user, "tenant_key")?;
            let username = required(user, "username")?;
            let database = required(user, "database")?;
            let password = required(user, "password")?;
            if !seen.insert(tenant_id.to_owned()) || !seen_usernames.insert(username.to_owned()) {
                return Err(invalid(
                    "duplicate SQL Server runtime tenant identity or login principal",
                )
                .into());
            }
            let binding = binding_by_tenant.get(tenant_id).ok_or_else(|| {
                invalid("SQL Server runtime user does not map to an assigned tenant binding")
            })?;
            let binding_login = required(binding, "identity_reference")?;
            let binding_database = required(binding, "namespace")?;
            if binding_login != username || !binding_database.eq_ignore_ascii_case(database) {
                return Err(invalid(
                    "SQL Server login/database does not match the Cloud tenant binding",
                )
                .into());
            }
            let tenant = SqlServerTenant::new(tenant_key, password)?;
            if tenant.login() != username || !tenant.database().eq_ignore_ascii_case(database) {
                return Err(invalid(
                    "SQL Server tenant key does not produce the assigned login and database",
                )
                .into());
            }
            // Apply/rotate only on a new desired revision. Ready snapshots are
            // redelivered periodically; they verify the existing identity without
            // issuing DDL on every reconciliation poll.
            if needs_apply {
                tenant.provision(&admin).await?;
            } else {
                tenant.verify(&admin).await?;
            }
            let app = TiberiusSqlServerExecutor::new(host, port, username, password)?
                .with_ca_bundle(ca_bundle.clone())?
                .with_database(database)?;
            app.verify_tenant_session(database).await?;
            let binding_id = required(binding, "binding_id")?.to_owned();
            let target_id = required(assignment, "database_target_id")?.to_owned();
            let revision = assignment
                .get("config_revision")
                .and_then(Value::as_i64)
                .ok_or_else(|| invalid("SQL Server config revision is missing"))?;
            verified.push(VerifiedBinding {
                provider_key: "sqlserver".into(),
                binding_id,
                target_id,
                revision,
                tenant_id: tenant_id.to_owned(),
                identity_reference: username.to_owned(),
                database: database.to_owned(),
                status: "active".into(),
                details: json!({"identity_verified":true,"isolation_verified":true,"database":database,"verification":"TDS LOGIN7 principal plus SQL Server session database and non-sysadmin verification"}),
            });
            tds_tenants.push(TdsTenantBinding {
                tenant_id: tenant_id.to_owned(),
                username: username.to_owned(),
                database: database.to_owned(),
            });
        }
        if seen.len() != active_binding_count {
            return Err(invalid("SQL Server runtime omitted an assigned tenant binding").into());
        }
        if users.is_empty() {
            if self.supervisor.is_running(assignment_id).await {
                self.supervisor.stop(assignment_id).await?;
            }
            state.begin_apply(state.desired_revision, state.credential_revision)?;
            runtime_reconciliation::persist(state_path, state)?;
            state.mark_applied(state.desired_revision, true)?;
            runtime_reconciliation::persist(state_path, state)?;
            return Ok(verified);
        }

        let assignment_digest = Sha256::digest(assignment_id.as_bytes());
        let default_port =
            20_000u16 + (u16::from_be_bytes([assignment_digest[0], assignment_digest[1]]) % 30_000);
        let default_listen = format!("127.0.0.1:{default_port}");
        let configured_listen =
            std::env::var("PROXIMA_SQLSERVER_TDS_LISTEN_ADDR").unwrap_or(default_listen);
        let listen_addr = runtime
            .get("listen_addr")
            .and_then(Value::as_str)
            .unwrap_or(&configured_listen)
            .to_owned();
        let listen: SocketAddr = listen_addr.parse()?;
        let allow_non_loopback = runtime
            .get("allow_non_loopback")
            .and_then(Value::as_bool)
            .unwrap_or(false);
        if !listen.ip().is_loopback() {
            let operator_opt_in = std::env::var("PROXIMA_SQLSERVER_TDS_ALLOW_NON_LOOPBACK")
                .is_ok_and(|value| value.eq_ignore_ascii_case("true"));
            if !allow_non_loopback || !operator_opt_in {
                return Err(invalid("non-loopback SQL Server TDS binding requires both the signed runtime allow_non_loopback flag and PROXIMA_SQLSERVER_TDS_ALLOW_NON_LOOPBACK=true").into());
            }
        }
        let client_cert = env_path("PROXIMA_SQLSERVER_TDS_CLIENT_CERT_PEM")?;
        let client_key = env_path("PROXIMA_SQLSERVER_TDS_CLIENT_KEY_PEM")?;
        let upstream_name = runtime
            .get("upstream_server_name")
            .and_then(Value::as_str)
            .unwrap_or(host)
            .to_owned();
        let config = SqlServerTdsConfig {
            schema_version: 1,
            provider_key: "sqlserver".into(),
            listen_addr: listen_addr.clone(),
            upstream_host: host.to_owned(),
            upstream_port: port,
            upstream_server_name: upstream_name,
            upstream_ca_pem: ca_path.to_string_lossy().into_owned(),
            client_cert_pem: client_cert.to_string_lossy().into_owned(),
            client_key_pem: client_key.to_string_lossy().into_owned(),
            allow_non_loopback,
            tenants: tds_tenants,
        };
        config.validate()?;
        let config_dir = private_root.join("sqlserver-tds");
        fs::create_dir_all(&config_dir)?;
        set_private_dir(&config_dir)?;
        let hash = hex::encode(Sha256::digest(assignment_id.as_bytes()));
        let config_path = config_dir.join(format!("{hash}.json"));
        write_private(&config_path, &serde_json::to_vec(&config)?)?;
        if std::env::var("PROXIMA_GATEWAY_EXECUTION_MODE").as_deref() == Ok("kubernetes") {
            if needs_apply {
                state.begin_apply(state.desired_revision, state.credential_revision)?;
                runtime_reconciliation::persist(state_path, state)?;
                state.mark_applied(state.desired_revision, true)?;
                runtime_reconciliation::persist(state_path, state)?;
            }
            return Ok(verified);
        }
        let binary = executable_dir.join(format!(
            "proxima-sqlserver-tds-gateway{}",
            std::env::consts::EXE_SUFFIX
        ));
        if !binary.is_file() {
            return Err(invalid(
                "proxima-sqlserver-tds-gateway binary is not packaged beside the Engine",
            )
            .into());
        }
        if state.phase == RuntimePhase::Applied
            && state.applied_revision == Some(state.desired_revision)
            && self.supervisor.is_running(assignment_id).await
        {
            return Ok(verified);
        }
        if self.supervisor.is_running(assignment_id).await {
            self.supervisor.stop(assignment_id).await?;
        }
        state.begin_apply(state.desired_revision, state.credential_revision)?;
        runtime_reconciliation::persist(state_path, state)?;
        let spec = GatewayProcessSpec {
            assignment_id: assignment_id.to_owned(),
            executable: binary.to_string_lossy().into_owned(),
            args: Vec::new(),
            env: vec![
                (
                    "PROXIMA_SQLSERVER_TDS_CONFIG".into(),
                    config_path.to_string_lossy().into_owned(),
                ),
                ("RUST_LOG".into(), "info".into()),
            ],
            readiness_addr: listen,
            startup_timeout: Duration::from_secs(25),
        };
        if let Err(e) = self.supervisor.start(spec).await {
            state.mark_failed("SQLSERVER_TDS_GATEWAY_START_FAILED")?;
            runtime_reconciliation::persist(state_path, state)?;
            return Err(Box::new(e));
        }
        state.mark_applied(state.desired_revision, true)?;
        runtime_reconciliation::persist(state_path, state)?;
        Ok(verified)
    }
}
impl Default for SqlServerRuntime {
    fn default() -> Self {
        Self::new()
    }
}

fn required<'a>(v: &'a Value, key: &str) -> Result<&'a str, io::Error> {
    v.get(key)
        .and_then(Value::as_str)
        .filter(|s| !s.trim().is_empty())
        .ok_or_else(|| {
            invalid(format!(
                "required SQL Server runtime field is missing: {key}"
            ))
        })
}
fn env_path(name: &str) -> io::Result<PathBuf> {
    std::env::var_os(name)
        .map(PathBuf::from)
        .ok_or_else(|| invalid(format!("{name} must point to a local PEM file")))
}
fn write_private(path: &Path, bytes: &[u8]) -> io::Result<()> {
    let tmp = path.with_extension("json.tmp");
    if tmp.exists() {
        fs::remove_file(&tmp)?;
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        let mut f = fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&tmp)?;
        use std::io::Write;
        f.write_all(bytes)?;
        f.sync_all()?;
    }
    #[cfg(not(unix))]
    {
        fs::write(&tmp, bytes)?;
    }
    if path.exists() {
        fs::remove_file(path)?;
    }
    fs::rename(tmp, path)?;
    Ok(())
}
fn set_private_dir(path: &Path) -> io::Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(path, fs::Permissions::from_mode(0o700))?;
    }
    Ok(())
}
fn invalid(e: impl std::fmt::Display) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidInput, e.to_string())
}
