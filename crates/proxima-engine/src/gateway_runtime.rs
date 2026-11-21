use std::{fs, io, net::SocketAddr, path::{Path, PathBuf}, time::Duration};

use serde_json::Value;
use crate::runtime_activation::GatewayProcessSpec;

pub struct PreparedGateway {
    pub spec: GatewayProcessSpec,
    upstream_url: String,
}

fn invalid(message: impl Into<String>) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message.into())
}

fn required<'a>(value: &'a Value, key: &str) -> io::Result<&'a str> {
    value.get(key).and_then(Value::as_str).map(str::trim)
        .filter(|v| !v.is_empty())
        .ok_or_else(|| invalid(format!("gateway_runtime_config.{key} is required")))
}

fn write_private_json(path: &Path, value: &Value) -> io::Result<()> {
    let parent = path.parent().ok_or_else(|| invalid("gateway identity path has no parent"))?;
    fs::create_dir_all(parent)?;
    let temp = path.with_extension(format!("{}.tmp", std::process::id()));
    let bytes = serde_json::to_vec_pretty(value).map_err(invalid)?;
    #[cfg(unix)]
    {
        use std::{io::Write, os::unix::fs::OpenOptionsExt};
        let mut file = fs::OpenOptions::new().write(true).create_new(true).mode(0o600).open(&temp)?;
        file.write_all(&bytes)?;
        file.sync_all()?;
    }
    #[cfg(not(unix))]
    fs::write(&temp, bytes)?;
    #[cfg(windows)]
    if path.exists() { fs::remove_file(path)?; }
    fs::rename(temp, path)?;
    Ok(())
}

/// Converts the authenticated, decrypted provider-specific runtime payload into
/// a private registry file and a supervised gateway process specification.
/// No credentials are synthesized: every tenant identity must be present in the
/// encrypted Cloud envelope and match the assignment's tenant bindings.
pub fn prepare_mysql(
    assignment: &Value,
    credentials: &Value,
    executable_dir: &Path,
    state_dir: &Path,
) -> io::Result<PreparedGateway> {
    let provider = required(assignment, "provider_key")?;
    if provider != "mysql" && provider != "mariadb" {
        return Err(invalid("this activation path currently supports only MySQL/MariaDB"));
    }
    let runtime = credentials.get("gateway_runtime_config")
        .ok_or_else(|| invalid("encrypted credentials do not include gateway_runtime_config"))?;
    if runtime.get("schema_version").and_then(Value::as_u64) != Some(1)
        || required(runtime, "provider_key")? != provider
    {
        return Err(io::Error::new(io::ErrorKind::PermissionDenied,
            "gateway runtime schema or provider does not match the assignment"));
    }
    let users = runtime.get("users").and_then(Value::as_array)
        .filter(|v| !v.is_empty()).ok_or_else(|| invalid("gateway runtime users must be a non-empty array"))?;
    let bindings = assignment.get("tenant_bindings").and_then(Value::as_array)
        .filter(|v| !v.is_empty()).ok_or_else(|| invalid("at least one tenant binding is required"))?;

    let binding_tenants: std::collections::HashSet<&str> = bindings.iter()
        .filter_map(|b| b.get("tenant_id").and_then(Value::as_str)).collect();
    let user_tenants: std::collections::HashSet<&str> = users.iter()
        .filter_map(|u| u.get("tenant_id").and_then(Value::as_str)).collect();
    if binding_tenants.len() != bindings.len()
        || user_tenants.len() != users.len()
        || user_tenants != binding_tenants
    {
        return Err(io::Error::new(io::ErrorKind::PermissionDenied,
            "MySQL identity registry must map exactly one upstream identity to every assigned tenant"));
    }

    let executable = executable_dir.join(format!("proxima-mysql-gateway{}", std::env::consts::EXE_SUFFIX));
    if !executable.is_file() {
        return Err(io::Error::new(io::ErrorKind::NotFound, "proxima-mysql-gateway is not packaged beside the Engine"));
    }
    let assignment_id = required(assignment, "assignment_id")?;
    if !assignment_id.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-') {
        return Err(invalid("assignment_id contains unsafe path characters"));
    }
    let listen = runtime.get("listen_addr").and_then(Value::as_str).unwrap_or("127.0.0.1:3307");
    let readiness_addr: SocketAddr = listen.parse().map_err(invalid)?;
    if !readiness_addr.ip().is_loopback() {
        return Err(io::Error::new(io::ErrorKind::PermissionDenied, "gateway listener must bind to loopback"));
    }

    // Reuse the gateway's own registry parser before starting a child so malformed
    // credentials or cross-tenant database mappings fail before any listener opens.
    let registry = serde_json::json!({"users": users});
    let registry_bytes = registry.to_string();
    crate::mysql_identity::MysqlIdentityRegistry::from_json(&registry_bytes)
        .map_err(|e| invalid(format!("MySQL provider identity registry rejected: {e}")))?;

    let registry_path: PathBuf = state_dir.join("gateway-identities").join(format!("{assignment_id}.json"));
    write_private_json(&registry_path, &registry)?;
    let upstream_url = required(&users[0], "upstream_url")?.to_owned();
    Ok(PreparedGateway {
        spec: GatewayProcessSpec {
            assignment_id: assignment_id.to_owned(),
            executable: executable.to_string_lossy().into_owned(),
            args: vec![],
            env: vec![
                ("PROXIMA_MYSQL_IDENTITY_REGISTRY".into(), registry_path.to_string_lossy().into_owned()),
                ("PROXIMA_MYSQL_LISTEN_ADDR".into(), listen.into()),
                ("RUST_LOG".into(), "info".into()),
            ],
            readiness_addr,
            startup_timeout: Duration::from_secs(20),
        },
        upstream_url,
    })
}

impl PreparedGateway {
    /// Verifies a real authenticated upstream connection, not just a TCP port.
    pub async fn verify_upstream(&self) -> io::Result<()> {
        let options = mysql_async::Opts::from_url(&self.upstream_url).map_err(invalid)?;
        let mut connection = mysql_async::Conn::new(options).await
            .map_err(|error| invalid(format!("MySQL upstream authentication failed: {error}")))?;
        connection.ping().await
            .map_err(|error| invalid(format!("MySQL upstream ping failed: {error}")))?;
        Ok(())
    }
}


#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn fixture(temp: &Path) -> (Value, Value, PathBuf) {
        let executable_dir = temp.join("bin");
        fs::create_dir_all(&executable_dir).unwrap();
        fs::write(
            executable_dir.join(format!("proxima-mysql-gateway{}", std::env::consts::EXE_SUFFIX)),
            b"test executable placeholder",
        ).unwrap();
        let assignment = json!({
            "assignment_id":"assignment-001",
            "provider_key":"mysql",
            "tenant_bindings":[{"tenant_id":"tenant-a"}]
        });
        let credentials = json!({
            "gateway_runtime_config":{
                "schema_version":1,
                "provider_key":"mysql",
                "users":[{
                    "username":"tenant-a-client",
                    "tenant_id":"tenant-a",
                    "database":"tenant_a",
                    "upstream_url":"mysql://upstream_user:upstream_pass@127.0.0.1:3306/tenant_a",
                    "password_sha1":"0123456789012345678901234567890123456789",
                    "auth_plugin":"mysql_native_password"
                }]
            }
        });
        (assignment, credentials, executable_dir)
    }

    #[test]
    fn rejects_registry_that_does_not_cover_every_binding() {
        let temp = tempfile::tempdir().unwrap();
        let (mut assignment, credentials, executable_dir) = fixture(temp.path());
        assignment["tenant_bindings"] = json!([
            {"tenant_id":"tenant-a"},
            {"tenant_id":"tenant-b"}
        ]);
        let result = prepare_mysql(&assignment, &credentials, &executable_dir, temp.path());
        assert!(matches!(result, Err(ref error) if error.kind() == io::ErrorKind::PermissionDenied));
    }

    #[test]
    fn builds_loopback_gateway_spec_and_private_registry() {
        let temp = tempfile::tempdir().unwrap();
        let (assignment, credentials, executable_dir) = fixture(temp.path());
        let prepared = prepare_mysql(&assignment, &credentials, &executable_dir, temp.path()).unwrap();
        assert_eq!(prepared.spec.readiness_addr, "127.0.0.1:3307".parse().unwrap());
        assert_eq!(prepared.spec.assignment_id, "assignment-001");
        let registry = prepared.spec.env.iter()
            .find(|(key, _)| key == "PROXIMA_MYSQL_IDENTITY_REGISTRY")
            .map(|(_, value)| value).unwrap();
        let value: Value = serde_json::from_slice(&fs::read(registry).unwrap()).unwrap();
        assert_eq!(value["users"][0]["tenant_id"], "tenant-a");
    }
}
