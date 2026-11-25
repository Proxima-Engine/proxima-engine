mod canary_probe;

use bytes::{Buf, BytesMut};
use std::{
    env, fs, io,
    path::{Path, PathBuf},
    sync::Arc,
};

use hmac::Mac;
use proxima_engine::{
    attestation::{AttestationConfig, AttestationLedger, SecurityState, TelemetrySummary},
    break_glass,
    config::{Config, UpstreamTlsMode},
    dashboard,
    metrics::{self, QueryLatencyTracker},
    mongodb_runtime::MongoRuntime,
    mysql_runtime::MysqlRuntime,
    native_provider_runtime::NativeProviderRuntime,
    protocol::SSL_REQUEST_CODE,
    redis_runtime::RedisRuntime,
    runtime_reconciliation::{self, RuntimePhase, RuntimeRecord},
    security_breaker::{BreakerConfig, SecurityBreaker},
    session::{establish, BoxedPgStream},
    sqlserver_runtime::SqlServerRuntime,
    tenant::TenantTokenVerifier,
    tls::{accept_client_tls, client_acceptor, connect_upstream_tls, upstream_connector},
};
use sha2::{Digest, Sha256};
use std::time::Instant;

// The workspace can enable both rustls crypto providers through transitive dependencies.
// Select AWS-LC explicitly before any TLS configuration is constructed.

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::Semaphore;
use tokio::time::timeout;
use tracing::{error, info};

async fn deliver_pending_attestations(
    ledger: &AttestationLedger,
    client: &reqwest::Client,
    url: &str,
    token: &str,
) {
    loop {
        let pending = match ledger.pending_records().await {
            Ok(records) => records,
            Err(error) => {
                error!(%error, "cannot read pending attestations; delivery stopped");
                return;
            }
        };

        let Some(record) = pending.first() else {
            return;
        };
        let value: serde_json::Value = match serde_json::from_str(record) {
            Ok(value) => value,
            Err(error) => {
                error!(%error, "invalid pending attestation JSON; delivery stopped");
                return;
            }
        };

        let Some(hash) = value
            .get("block_hash")
            .and_then(serde_json::Value::as_str)
            .map(str::to_owned)
        else {
            error!("pending attestation has no block hash");
            return;
        };
        let Some(predecessor) = value
            .get("previous_block_hash")
            .and_then(serde_json::Value::as_str)
            .map(str::to_owned)
        else {
            error!(block_hash = %hash, "pending attestation has no predecessor");
            return;
        };

        let mut accepted = false;

        for attempt in 0..5u32 {
            let result = client
                .post(url)
                .bearer_auth(token)
                .header("content-type", "application/json")
                .body(record.clone())
                .send()
                .await;

            match result {
                Ok(response) if response.status().is_success() => {
                    accepted = true;
                }
                Ok(response) if response.status() == reqwest::StatusCode::CONFLICT => {
                    let body = response
                        .json::<serde_json::Value>()
                        .await
                        .unwrap_or_else(|_| serde_json::json!({}));
                    let expected = body
                        .get("expected_previous_block_hash")
                        .and_then(serde_json::Value::as_str)
                        .unwrap_or("");

                    // A matching current hash is consistent with a lost success response.
                    if expected == hash {
                        accepted = true;
                    } else if expected != predecessor {
                        error!(
                            block_hash = %hash,
                            expected_previous_block_hash = %expected,
                            local_previous_block_hash = %predecessor,
                            "unresolved chain conflict; evidence preserved and delivery stopped"
                        );
                        return;
                    } else if attempt < 4 {
                        tokio::time::sleep(std::time::Duration::from_secs(1u64 << attempt)).await;
                        continue;
                    } else {
                        error!(block_hash = %hash, "chain conflict persisted; record remains pending");
                        return;
                    }
                }
                Ok(response)
                    if response.status().is_server_error()
                        || response.status() == reqwest::StatusCode::TOO_MANY_REQUESTS =>
                {
                    let status = response.status();
                    if attempt == 4 {
                        error!(block_hash = %hash, %status, "retry limit reached; record remains pending");
                        return;
                    }
                    tokio::time::sleep(std::time::Duration::from_secs(1u64 << attempt)).await;
                    continue;
                }
                Ok(response) => {
                    error!(block_hash = %hash, status = %response.status(),
                        "permanent rejection; record remains pending and later records are withheld");
                    return;
                }
                Err(error) => {
                    if attempt == 4 {
                        error!(block_hash = %hash, %error, "delivery retries exhausted; record remains pending");
                        return;
                    }
                    tokio::time::sleep(std::time::Duration::from_secs(1u64 << attempt)).await;
                    continue;
                }
            }

            if accepted {
                if let Err(error) = ledger.acknowledge_record(&hash).await {
                    error!(block_hash = %hash, %error,
                        "could not persist delivery acknowledgement; safe redelivery may occur");
                    return;
                }
                info!(block_hash = %hash, "signed attestation delivered and acknowledged");
                break;
            }
        }

        if !accepted {
            return;
        }
    }
}
fn runtime_capability_report_from(
    executable: &std::path::Path,
) -> (Vec<String>, serde_json::Value, Option<String>) {
    let directory = executable.parent();
    let has_gateway = |name: &str| {
        directory.is_some_and(|directory| {
            directory
                .join(format!("{}{}", name, std::env::consts::EXE_SUFFIX))
                .is_file()
        })
    };

    let mysql_gateway = has_gateway("proxima-mysql-gateway");
    let mongodb_gateway = has_gateway("proxima-mongodb-gateway");
    let redis_gateway = has_gateway("proxima-redis-gateway");
    let sqlserver_tds_gateway = has_gateway("proxima-sqlserver-tds-gateway");

    let mut provider_keys = vec!["cockroachdb".to_owned(), "postgresql".to_owned()];
    if mysql_gateway {
        provider_keys.push("mariadb".to_owned());
        provider_keys.push("mysql".to_owned());
    }
    if mongodb_gateway {
        provider_keys.push("mongodb".to_owned());
    }
    if redis_gateway {
        provider_keys.push("redis".to_owned());
    }
    if sqlserver_tds_gateway {
        provider_keys.push("sqlserver".to_owned());
    }
    provider_keys.extend([
        "sqlite".to_owned(),
        "oracle".to_owned(),
        "dynamodb".to_owned(),
        "cassandra".to_owned(),
        "elasticsearch".to_owned(),
    ]);
    provider_keys.sort();

    let capabilities = serde_json::json!({
        "engine_version": env!("CARGO_PKG_VERSION"),
        "protocols": {
            "postgresql_wire": true,
            "mysql_wire": mysql_gateway,
            "mongodb_op_msg": mongodb_gateway,
            "redis_resp2": redis_gateway,
            "sqlserver_tds": sqlserver_tds_gateway
        },
        "native_provider_runtime": {
            "sqlite": true,
            "oracle": true,
            "dynamodb": true,
            "cassandra": true,
            "elasticsearch": true,
            "opensearch_distribution": true
        },
        "gateway_binaries": {
            "proxima-engine": true,
            "proxima-mysql-gateway": mysql_gateway,
            "proxima-mongodb-gateway": mongodb_gateway,
            "proxima-redis-gateway": redis_gateway,
            "proxima-sqlserver-tds-gateway": sqlserver_tds_gateway
        },
        "isolation_profiles": {
            "postgresql": "roles-and-rls",
            "cockroachdb": "roles-and-forced-rls",
            "mysql": if mysql_gateway { "tenant-accounts-and-grants" } else { "unavailable" },
            "mariadb": if mysql_gateway { "tenant-accounts-and-grants" } else { "unavailable" },
            "mongodb": if mongodb_gateway { "database-per-tenant-rbac" } else { "unavailable" },
            "redis": if redis_gateway { "resp2-tenant-key-namespace-and-acl" } else { "unavailable" },
            "sqlserver": if sqlserver_tds_gateway { "tds-login7-tenant-principal-and-database-binding" } else { "unavailable" },
            "sqlite": "private-file-per-tenant",
            "oracle": "schema-owner-per-tenant",
            "dynamodb": "iam-leading-keys-per-tenant",
            "cassandra": "keyspace-and-role-per-tenant",
            "elasticsearch": "native-role-dls-fls-per-tenant"
        }
    });

    let artifact_digest = std::fs::read(executable)
        .ok()
        .map(|bytes| format!("sha256:{}", hex::encode(Sha256::digest(bytes))));
    (provider_keys, capabilities, artifact_digest)
}

fn runtime_capability_report() -> (Vec<String>, serde_json::Value, Option<String>) {
    match std::env::current_exe() {
        Ok(executable) => runtime_capability_report_from(&executable),
        Err(_) => (Vec::new(), serde_json::json!({}), None),
    }
}

#[cfg(test)]
mod runtime_capability_report_tests {
    use super::runtime_capability_report_from;
    use std::{fs, path::PathBuf};

    #[test]
    fn redis_is_advertised_only_when_its_gateway_binary_is_packaged() {
        let directory = std::env::temp_dir().join(format!(
            "proxima-runtime-capabilities-{}",
            std::process::id()
        ));
        let _ = fs::remove_dir_all(&directory);
        fs::create_dir_all(&directory).unwrap();
        let engine = directory.join(format!("proxima-engine{}", std::env::consts::EXE_SUFFIX));
        fs::write(&engine, b"synthetic engine artifact").unwrap();

        let (without_redis, caps_without, digest) = runtime_capability_report_from(&engine);
        assert!(!without_redis.iter().any(|key| key == "redis"));
        assert_eq!(caps_without["protocols"]["redis_resp2"], false);
        assert!(digest
            .as_deref()
            .is_some_and(|value| value.starts_with("sha256:")));

        let redis = directory.join(format!(
            "proxima-redis-gateway{}",
            std::env::consts::EXE_SUFFIX
        ));
        fs::write(&redis, b"synthetic redis gateway artifact").unwrap();
        let (with_redis, caps_with, _) = runtime_capability_report_from(&engine);
        assert!(with_redis.windows(2).all(|pair| pair[0] < pair[1]));
        assert!(with_redis.iter().any(|key| key == "redis"));
        assert_eq!(caps_with["protocols"]["redis_resp2"], true);
        assert_eq!(
            caps_with["isolation_profiles"]["redis"],
            "resp2-tenant-key-namespace-and-acl"
        );
        let _ = fs::remove_dir_all(PathBuf::from(directory));
    }
}

fn sign_node_heartbeat_v2(
    key: &[u8],
    node_id: &str,
    organization_id: &str,
    timestamp: i64,
    version: &str,
    runtime_status: &str,
    provider_keys: &[String],
    capabilities: &serde_json::Value,
    artifact_digest: Option<&str>,
) -> Result<String, hmac::digest::InvalidLength> {
    let canonical = format!(
        "proxima-node-heartbeat-v2\n{}\n{}\n{}\n{}\n{}\n{}\n{}\n{}",
        node_id,
        organization_id,
        timestamp,
        version,
        runtime_status,
        provider_keys.join(","),
        capabilities,
        artifact_digest.unwrap_or("")
    );
    let mut mac = hmac::Hmac::<Sha256>::new_from_slice(key)?;
    mac.update(canonical.as_bytes());
    Ok(hex::encode(mac.finalize().into_bytes()))
}

#[cfg(test)]
fn sign_node_heartbeat(
    key: &[u8],
    node_id: &str,
    organization_id: &str,
    timestamp: i64,
    version: &str,
    runtime_status: &str,
) -> Result<String, hmac::digest::InvalidLength> {
    let canonical = format!(
        "proxima-node-heartbeat-v1\n{}\n{}\n{}\n{}\n{}",
        node_id, organization_id, timestamp, version, runtime_status
    );
    let mut mac = hmac::Hmac::<Sha256>::new_from_slice(key)?;
    mac.update(canonical.as_bytes());
    Ok(hex::encode(mac.finalize().into_bytes()))
}

fn attestation_ingest_url_allowed(url: &str, allow_insecure_http: bool) -> bool {
    let Ok(parsed) = reqwest::Url::parse(url) else {
        return false;
    };
    if parsed.scheme() == "https" {
        return true;
    }
    if parsed.scheme() != "http" {
        return false;
    }

    let host = parsed.host_str().unwrap_or_default();
    let loopback = host == "localhost" || host == "127.0.0.1" || host == "::1";
    loopback || (allow_insecure_http && host == "proxima-control" && parsed.port() == Some(8080))
}

async fn bootstrap_node_identity() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    use std::{
        env, fs,
        path::{Path, PathBuf},
        time::{SystemTime, UNIX_EPOCH},
    };

    fn persist_identity(
        identity_path: &Path,
        identity: &serde_json::Value,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let parent = identity_path.parent().ok_or("Invalid node identity path")?;
        fs::create_dir_all(parent)?;
        let temporary_path = identity_path.with_extension("json.tmp");
        if temporary_path.exists() {
            fs::remove_file(&temporary_path)?;
        }
        let identity_bytes = serde_json::to_vec_pretty(identity)?;
        #[cfg(unix)]
        {
            use std::{io::Write, os::unix::fs::OpenOptionsExt};
            let mut file = fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .mode(0o600)
                .open(&temporary_path)?;
            file.write_all(&identity_bytes)?;
            file.sync_all()?;
        }
        #[cfg(not(unix))]
        fs::write(&temporary_path, &identity_bytes)?;

        #[cfg(windows)]
        if identity_path.exists() {
            fs::remove_file(identity_path)?;
        }
        fs::rename(&temporary_path, identity_path)?;
        Ok(())
    }

    fn apply_identity(
        value: &serde_json::Value,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let node_id = value["node_id"]
            .as_str()
            .ok_or("Identity is missing node_id")?;
        let organization_id = value["organization_id"]
            .as_str()
            .ok_or("Identity is missing organization_id")?;
        let key = value["signing_key"]
            .as_str()
            .ok_or("Identity is missing signing_key")?;

        let decoded = hex::decode(key)?;
        if decoded.len() != 32 {
            return Err("Node signing key must be exactly 32 bytes".into());
        }

        if let Some(tenant_key) = value["tenant_signing_key"].as_str() {
            if hex::decode(tenant_key)?.len() != 32 {
                return Err(
                    "Organization tenant signing key must be exactly 32 bytes (hex encoded)".into(),
                );
            }
            // This is an organization-scoped key derived by the Control Plane.
            // The Control Plane master secret is never sent to the customer node.
            env::set_var("PROXIMA_TENANT_SIGNING_KEY", tenant_key);
        }

        env::set_var("PROXIMA_NODE_ID", node_id);
        env::set_var("PROXIMA_ORGANIZATION_ID", organization_id);
        env::set_var("PROXIMA_NODE_SIGNING_KEY_HEX", key);
        Ok(())
    }

    let identity_path = env::var_os("PROXIMA_NODE_IDENTITY_PATH")
        .map(PathBuf::from)
        .or_else(|| {
            env::var_os("LOCALAPPDATA").map(|base| {
                PathBuf::from(base)
                    .join("AgataProxima")
                    .join("node-identity.json")
            })
        })
        .unwrap_or_else(|| PathBuf::from("data/node-identity.json"));

    if identity_path.is_file() {
        let bytes = fs::read(&identity_path)?;
        let mut identity: serde_json::Value = serde_json::from_slice(&bytes)?;
        // Keep the old verifier secret in process memory only while already-issued
        // one-hour tokens may still exist. Never persist the Control Plane master
        // secret in the customer node identity file.
        let legacy_key = env::var("PROXIMA_TENANT_SIGNING_KEY").ok().or_else(|| {
            env::var("PROXIMA_TENANT_SIGNING_KEY_FILE")
                .ok()
                .and_then(|path| fs::read_to_string(path).ok())
                .map(|value| value.trim().to_owned())
        });
        if let Some(key) = legacy_key.filter(|key| {
            key.len() >= 32 && identity["tenant_signing_key"].as_str() != Some(key.as_str())
        }) {
            env::set_var("PROXIMA_TENANT_SIGNING_KEY_PREVIOUS", key);
        }

        if identity["tenant_signing_key"].as_str().is_none()
            && (env::var("PROXIMA_NODE_HEARTBEAT_URL").is_ok()
                || env::var("PROXIMA_NODE_ENROLLMENT_URL").is_ok())
        {
            // Upgrade an identity created before organization-scoped tenant keys
            // were returned during enrollment. This signed, domain-separated
            // refresh does not require consuming another enrollment token.
            let node_id = identity["node_id"]
                .as_str()
                .ok_or("Identity is missing node_id")?;
            let organization_id = identity["organization_id"]
                .as_str()
                .ok_or("Identity is missing organization_id")?;
            let node_key_hex = identity["signing_key"]
                .as_str()
                .ok_or("Identity is missing signing_key")?;
            let node_key = hex::decode(node_key_hex)?;
            if node_key.len() != 32 {
                return Err("Node signing key must be exactly 32 bytes".into());
            }

            let heartbeat_url = env::var("PROXIMA_NODE_HEARTBEAT_URL")
                .ok()
                .or_else(|| {
                    env::var("PROXIMA_NODE_ENROLLMENT_URL")
                        .ok()
                        .map(|url| url.replace("/api/v1/nodes/enroll", "/api/v1/nodes/heartbeat"))
                })
                .ok_or("Missing PROXIMA_NODE_HEARTBEAT_URL for organization-key refresh")?;
            let timestamp = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs() as i64;
            let version = env!("CARGO_PKG_VERSION");
            let runtime_status = "running";
            let canonical = format!(
                "proxima-node-identity-refresh-v1\n{}\n{}\n{}\n{}\n{}",
                node_id, organization_id, timestamp, version, runtime_status
            );
            let mut mac = hmac::Hmac::<Sha256>::new_from_slice(&node_key)
                .map_err(|_| "Invalid node signing key")?;
            mac.update(canonical.as_bytes());
            let signature = hex::encode(mac.finalize().into_bytes());

            let response = reqwest::Client::new()
                .post(heartbeat_url)
                .json(&serde_json::json!({
                    "node_id": node_id,
                    "timestamp": timestamp,
                    "version": version,
                    "runtime_status": runtime_status,
                    "signature": signature,
                    "include_tenant_signing_key": true
                }))
                .send()
                .await?
                .error_for_status()?;
            let refresh: serde_json::Value = response.json().await?;
            let tenant_key = refresh["tenant_signing_key"]
                .as_str()
                .ok_or("Control Plane identity refresh response is missing tenant_signing_key")?;
            if hex::decode(tenant_key)?.len() != 32 {
                return Err(
                    "Control Plane returned an invalid organization tenant signing key".into(),
                );
            }
            identity["tenant_signing_key"] = serde_json::Value::String(tenant_key.to_owned());
            persist_identity(&identity_path, &identity)?;
        }

        apply_identity(&identity)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&identity_path, fs::Permissions::from_mode(0o600))?;
        }
        return Ok(());
    }

    if env::var("PROXIMA_NODE_SIGNING_KEY_HEX")
        .ok()
        .and_then(|key| hex::decode(key).ok())
        .is_some_and(|key| key.len() == 32)
    {
        return Ok(());
    }

    let url = env::var("PROXIMA_NODE_ENROLLMENT_URL").ok();
    let enrollment_token_file =
        env::var_os("PROXIMA_NODE_ENROLLMENT_TOKEN_FILE").map(PathBuf::from);
    let token = if let Some(path) = enrollment_token_file.as_ref() {
        Some(fs::read_to_string(path)?.trim().to_owned())
    } else {
        env::var("PROXIMA_NODE_ENROLLMENT_TOKEN").ok()
    };
    let node_id = env::var("PROXIMA_NODE_ID").ok();

    if url.is_none() && token.is_none() && node_id.is_none() {
        return Ok(());
    }

    let url = url.ok_or("Missing PROXIMA_NODE_ENROLLMENT_URL")?;
    let token = token.ok_or("Missing PROXIMA_NODE_ENROLLMENT_TOKEN")?;
    let node_id = node_id.ok_or("Missing PROXIMA_NODE_ID")?;

    let response = reqwest::Client::new()
        .post(url)
        .json(&serde_json::json!({
            "node_id": node_id,
            "enrollment_token": token
        }))
        .send()
        .await?
        .error_for_status()?;

    let identity: serde_json::Value = response.json().await?;

    // Validate both credentials before persisting the identity.
    let key = identity["signing_key"]
        .as_str()
        .ok_or("Enrollment response is missing signing_key")?;
    if hex::decode(key)?.len() != 32 {
        return Err("Enrollment returned an invalid signing key".into());
    }
    let tenant_key = identity["tenant_signing_key"]
        .as_str()
        .ok_or("Enrollment response is missing the organization-scoped tenant_signing_key")?;
    if hex::decode(tenant_key)?.len() != 32 {
        return Err("Enrollment returned an invalid organization tenant signing key".into());
    }
    let _ = identity["organization_id"]
        .as_str()
        .ok_or("Enrollment response is missing organization_id")?;
    let _ = identity["node_id"]
        .as_str()
        .ok_or("Enrollment response is missing node_id")?;

    persist_identity(&identity_path, &identity)?;
    apply_identity(&identity)?;
    if enrollment_token_file.is_none() {
        env::remove_var("PROXIMA_NODE_ENROLLMENT_TOKEN");
    }

    eprintln!("Engine node identity loaded successfully.");
    Ok(())
}

fn validate_tenant_bindings(record: &serde_json::Value) -> Result<(), &'static str> {
    let provider = record
        .get("provider_key")
        .and_then(serde_json::Value::as_str)
        .unwrap_or("");
    let bindings = record
        .get("tenant_bindings")
        .and_then(serde_json::Value::as_array)
        .ok_or("tenant database bindings are missing or invalid")?;
    if bindings.len() > 10_000 {
        return Err("tenant database binding count exceeds the supported limit");
    }
    let mut tenant_ids = std::collections::HashSet::new();
    let mut namespaces = std::collections::HashSet::new();
    for binding in bindings {
        let tenant_id = binding
            .get("tenant_id")
            .and_then(serde_json::Value::as_str)
            .filter(|value| !value.is_empty())
            .ok_or("tenant binding has no tenant ID")?;
        let namespace = binding
            .get("namespace")
            .and_then(serde_json::Value::as_str)
            .filter(|value| !value.is_empty())
            .ok_or("tenant binding has no namespace")?;
        let status = binding
            .get("status")
            .and_then(serde_json::Value::as_str)
            .ok_or("tenant binding has no lifecycle status")?;
        let allowed_status = matches!(status, "pending" | "provisioning" | "active");
        if !allowed_status {
            return Err("tenant binding lifecycle status is not deployable");
        }
        if tenant_id.len() > 128
            || namespace.len() > 255
            || !tenant_id.bytes().all(|byte| byte.is_ascii_graphic())
            || !namespace
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-' | b'.'))
            || namespace.contains("..")
        {
            return Err("tenant binding contains an invalid tenant ID or namespace");
        }
        if !tenant_ids.insert(tenant_id) || !namespaces.insert(namespace) {
            return Err("tenant bindings contain duplicate tenant IDs or namespaces");
        }
    }
    Ok(())
}

/// The Engine's native PostgreSQL listener has one upstream, but gateway
/// assignments are independent Kubernetes workloads and therefore each gets
/// its own process. Do not impose the native listener's cardinality on gateways.
fn validate_assignment_runtime_cardinality(
    records: &[serde_json::Value],
) -> Result<(), &'static str> {
    let mut native_engine_assignments = 0usize;
    let mut assignment_ids = std::collections::HashSet::new();
    for record in records {
        let id = record
            .get("assignment_id")
            .and_then(serde_json::Value::as_str)
            .filter(|value| !value.trim().is_empty())
            .ok_or("assignment ID missing")?;
        if id.len() > 128
            || !id
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-' || byte == b'_')
        {
            return Err("assignment ID contains unsafe path characters");
        }
        if !assignment_ids.insert(id) {
            return Err("configuration bundle contains duplicate assignment IDs");
        }
        let runtime = record
            .get("gateway_runtime")
            .and_then(serde_json::Value::as_str)
            .ok_or("gateway runtime is missing")?;
        if runtime == "proxima-engine" {
            native_engine_assignments += 1;
        } else if !matches!(
            runtime,
            "proxima-mysql-gateway"
                | "proxima-mongodb-gateway"
                | "proxima-redis-gateway"
                | "proxima-sqlserver-tds-gateway"
                | "proxima-engine-native-sqlite"
                | "proxima-engine-native-oracle"
                | "proxima-engine-native-dynamodb"
                | "proxima-engine-native-cassandra"
                | "proxima-engine-native-search"
        ) {
            return Err("assigned gateway runtime is not supported");
        }
    }
    if native_engine_assignments > 1 {
        return Err("this Engine node supports one native proxima-engine upstream assignment");
    }
    Ok(())
}

async fn pull_and_stage_database_config_once(
    mysql_runtime: &MysqlRuntime,
    mongo_runtime: &MongoRuntime,
    redis_runtime: &RedisRuntime,
    sqlserver_runtime: &SqlServerRuntime,
    native_runtime: &NativeProviderRuntime,
    verifier: Option<&TenantTokenVerifier>,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    use std::{
        env, fs,
        io::Write,
        path::PathBuf,
        time::{SystemTime, UNIX_EPOCH},
    };
    let node_id = env::var("PROXIMA_NODE_ID")?;
    let organization_id = env::var("PROXIMA_ORGANIZATION_ID")?;
    let signing_key = hex::decode(env::var("PROXIMA_NODE_SIGNING_KEY_HEX")?)?;
    if signing_key.len() != 32 {
        return Err("node signing key must be 32 bytes".into());
    }
    let heartbeat_url = env::var("PROXIMA_NODE_HEARTBEAT_URL")?;
    let pull_url = env::var("PROXIMA_NODE_CONFIG_PULL_URL").unwrap_or_else(|_| {
        heartbeat_url.replace("/api/v1/nodes/heartbeat", "/api/v1/nodes/config/pull")
    });
    let ack_url = env::var("PROXIMA_NODE_CONFIG_ACK_URL").unwrap_or_else(|_| {
        heartbeat_url.replace("/api/v1/nodes/heartbeat", "/api/v1/nodes/config/ack")
    });
    if !pull_url.contains("/api/v1/nodes/config/pull")
        || !ack_url.contains("/api/v1/nodes/config/ack")
    {
        return Err("configure PROXIMA_NODE_CONFIG_PULL_URL and PROXIMA_NODE_CONFIG_ACK_URL or a canonical node heartbeat URL".into());
    }
    if !attestation_ingest_url_allowed(&pull_url, false)
        || !attestation_ingest_url_allowed(&ack_url, false)
    {
        return Err(
            "node configuration endpoints must use HTTPS (or loopback for local development)"
                .into(),
        );
    }

    let timestamp = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs() as i64;
    let nonce = uuid::Uuid::new_v4().to_string();
    let canonical = format!(
        "proxima-node-config-pull-v1\n{}\n{}\n{}\n{}",
        node_id, organization_id, timestamp, nonce
    );
    let mut mac = hmac::Hmac::<Sha256>::new_from_slice(&signing_key)?;
    mac.update(canonical.as_bytes());
    let signature = hex::encode(mac.finalize().into_bytes());
    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(15))
        .build()?;
    let response = client
        .post(&pull_url)
        .json(&serde_json::json!({
            "node_id":node_id,"timestamp":timestamp,"nonce":nonce,"signature":signature
        }))
        .send()
        .await?
        .error_for_status()?;
    let response: serde_json::Value = response.json().await?;
    let bundle = response
        .get("bundle")
        .cloned()
        .ok_or("Control Plane response has no configuration bundle")?;
    let bundle_signature = response
        .get("signature")
        .and_then(serde_json::Value::as_str)
        .ok_or("Control Plane response has no bundle signature")?;
    if bundle.get("node_id").and_then(serde_json::Value::as_str) != Some(node_id.as_str())
        || bundle
            .get("organization_id")
            .and_then(serde_json::Value::as_str)
            != Some(organization_id.as_str())
    {
        return Err("configuration bundle identity does not match this enrolled node".into());
    }
    let bundle_bytes = bundle.to_string();
    let mut verify = hmac::Hmac::<Sha256>::new_from_slice(&signing_key)?;
    verify.update(format!("proxima-node-config-bundle-v1\n{bundle_bytes}").as_bytes());
    verify.verify_slice(&hex::decode(bundle_signature)?)?;

    let mut derive = hmac::Hmac::<Sha256>::new_from_slice(&signing_key)?;
    derive.update(format!("proxima-node-config-envelope-key-v1\n{node_id}").as_bytes());
    let envelope_key = derive.finalize().into_bytes();
    let decryptor = ring::aead::LessSafeKey::new(
        ring::aead::UnboundKey::new(&ring::aead::AES_256_GCM, &envelope_key)
            .map_err(|_| io::Error::other("invalid database configuration envelope key"))?,
    );
    let mut staged = Vec::new();
    // Decrypted provider credentials remain in memory only. They are never
    // copied into the shared routing document or the Kubernetes-readable PVC.
    let mut decrypted_credentials = std::collections::HashMap::new();
    let records = bundle
        .get("assignments")
        .and_then(serde_json::Value::as_array)
        .ok_or("configuration bundle assignments must be an array")?;
    validate_assignment_runtime_cardinality(records)?;
    let executable = env::current_exe()?;
    let executable_dir = executable
        .parent()
        .ok_or("Engine executable directory is unavailable")?;
    for record in records {
        validate_tenant_bindings(record)
            .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))?;
        let provider_key = record
            .get("provider_key")
            .and_then(serde_json::Value::as_str)
            .ok_or("database provider missing")?;
        let sqlite_local = provider_key == "sqlite"
            && record
                .pointer("/endpoint/host")
                .and_then(serde_json::Value::as_str)
                == Some("local")
            && record
                .pointer("/endpoint/port")
                .and_then(serde_json::Value::as_u64)
                == Some(0)
            && record.get("tls_mode").and_then(serde_json::Value::as_str) == Some("local");
        if !sqlite_local
            && record.get("tls_mode").and_then(serde_json::Value::as_str) != Some("verify-full")
        {
            return Err(
                "assigned network database target does not require full upstream TLS verification"
                    .into(),
            );
        }
        let gateway_runtime = record
            .get("gateway_runtime")
            .and_then(serde_json::Value::as_str)
            .ok_or("gateway runtime is missing")?;
        let runtime_available = match gateway_runtime {
            "proxima-engine"
            | "proxima-engine-native-sqlite"
            | "proxima-engine-native-oracle"
            | "proxima-engine-native-dynamodb"
            | "proxima-engine-native-cassandra"
            | "proxima-engine-native-search" => true,
            "proxima-mysql-gateway" => executable_dir
                .join(format!("proxima-mysql-gateway{}", env::consts::EXE_SUFFIX))
                .is_file(),
            "proxima-mongodb-gateway" => executable_dir
                .join(format!(
                    "proxima-mongodb-gateway{}",
                    env::consts::EXE_SUFFIX
                ))
                .is_file(),
            "proxima-redis-gateway" => executable_dir
                .join(format!("proxima-redis-gateway{}", env::consts::EXE_SUFFIX))
                .is_file(),
            "proxima-sqlserver-tds-gateway" => executable_dir
                .join(format!(
                    "proxima-sqlserver-tds-gateway{}",
                    env::consts::EXE_SUFFIX
                ))
                .is_file(),
            "proxima-engine-native-sqlite"
            | "proxima-engine-native-oracle"
            | "proxima-engine-native-dynamodb"
            | "proxima-engine-native-cassandra"
            | "proxima-engine-native-search" => true,
            _ => false,
        };
        if !runtime_available {
            return Err(
                format!("assigned gateway runtime is not packaged: {gateway_runtime}").into(),
            );
        }
        let target_id = record
            .get("database_target_id")
            .and_then(serde_json::Value::as_str)
            .ok_or("database target ID missing")?;
        let config_revision = record
            .get("config_revision")
            .and_then(serde_json::Value::as_i64)
            .ok_or("configuration revision missing")?;
        let credential_revision = record
            .get("credential_revision")
            .and_then(serde_json::Value::as_i64)
            .ok_or("credential revision missing")?;
        let expected_aad =
            format!("{node_id}\n{target_id}\n{config_revision}\n{credential_revision}");
        let envelope = record
            .get("credential_envelope")
            .ok_or("credential envelope missing")?;
        if envelope
            .get("algorithm")
            .and_then(serde_json::Value::as_str)
            != Some("AES-256-GCM")
        {
            return Err("unsupported database credential envelope algorithm".into());
        }
        let ciphertext = hex::decode(
            envelope
                .get("ciphertext")
                .and_then(serde_json::Value::as_str)
                .ok_or("credential envelope ciphertext missing")?,
        )?;
        let nonce_bytes: [u8; 12] = hex::decode(
            envelope
                .get("nonce")
                .and_then(serde_json::Value::as_str)
                .ok_or("credential envelope nonce missing")?,
        )?
        .try_into()
        .map_err(|_| "invalid credential envelope nonce")?;
        let aad = envelope
            .get("aad")
            .and_then(serde_json::Value::as_str)
            .ok_or("credential envelope AAD missing")?;
        if aad != expected_aad {
            return Err("credential envelope associated data does not match the assigned target and revisions".into());
        }
        let mut plaintext = ciphertext;
        let credentials = decryptor
            .open_in_place(
                ring::aead::Nonce::assume_unique_for_key(nonce_bytes),
                ring::aead::Aad::from(aad.as_bytes()),
                &mut plaintext,
            )
            .map_err(|_| io::Error::other("database credential envelope authentication failed"))?;
        let credentials: serde_json::Value = serde_json::from_slice(credentials)?;
        let assignment_id = record
            .get("assignment_id")
            .and_then(serde_json::Value::as_str)
            .ok_or("assignment ID missing")?;
        decrypted_credentials.insert(assignment_id.to_owned(), credentials.clone());
        let credentialless = matches!(provider_key, "sqlite" | "dynamodb");
        let username = credentials
            .get("username")
            .and_then(serde_json::Value::as_str)
            .unwrap_or_default();
        let password = credentials
            .get("password")
            .and_then(serde_json::Value::as_str)
            .unwrap_or_default();
        if (!credentialless && (username.trim().is_empty() || password.is_empty()))
            || username.len() > 128
            || password.len() > 4096
        {
            return Err(
                "database target credentials exceed supported limits or are missing".into(),
            );
        }
        let endpoint = record
            .get("endpoint")
            .ok_or("database target endpoint is missing")?;
        let host = endpoint
            .get("host")
            .and_then(serde_json::Value::as_str)
            .filter(|value| !value.trim().is_empty())
            .ok_or("database target host is missing")?;
        let port = endpoint
            .get("port")
            .and_then(serde_json::Value::as_u64)
            .filter(|value| {
                (1..=65535).contains(value) || (provider_key == "sqlite" && *value == 0)
            })
            .ok_or("database target port is invalid")?;
        let database_name = record
            .get("database_name")
            .and_then(serde_json::Value::as_str)
            .filter(|value| !value.trim().is_empty())
            .ok_or("database target database name is missing")?;
        if host.len() > 255
            || database_name.len() > 255
            || (provider_key == "sqlite" && host != "local")
        {
            return Err("database target endpoint exceeds supported limits".into());
        }
        let mut item = record.clone();
        // The shared desired-state file is consumed by the Kubernetes
        // controller, so persist routing metadata only. Never place decrypted
        // database usernames/passwords on the controller-readable PVC; the
        // authenticated credential envelope is validated above and then dropped.
        item.as_object_mut()
            .ok_or("assignment entry must be an object")?
            .remove("credential_envelope");
        item.as_object_mut().unwrap().remove("credentials");
        staged.push(item);
    }

    let identity_path = env::var_os("PROXIMA_NODE_IDENTITY_PATH")
        .map(PathBuf::from)
        .or_else(|| {
            env::var_os("LOCALAPPDATA").map(|base| {
                PathBuf::from(base)
                    .join("AgataProxima")
                    .join("node-identity.json")
            })
        })
        .unwrap_or_else(|| PathBuf::from("data/node-identity.json"));
    let output_path = env::var_os("PROXIMA_NODE_DATABASE_CONFIG_PATH")
        .map(PathBuf::from)
        .or_else(|| {
            identity_path
                .parent()
                .map(|parent| parent.join("database-targets.json"))
        })
        .unwrap_or_else(|| PathBuf::from("data/database-targets.json"));
    let parent = output_path
        .parent()
        .ok_or("invalid database config output path")?;
    fs::create_dir_all(parent)?;
    let delivery_id = uuid::Uuid::new_v4().to_string();
    let secret_output_path = env::var_os("PROXIMA_NODE_DATABASE_SECRETS_PATH")
        .map(PathBuf::from)
        .unwrap_or_else(|| parent.join("database-target-secrets.json"));
    // Publish the secret manifest first. The routing manifest is atomically
    // replaced last, so the controller never sees a new routing generation
    // without its matching credential Secret material.
    write_gateway_secret_manifest(
        &staged,
        &decrypted_credentials,
        &node_id,
        &delivery_id,
        &secret_output_path,
    )?;
    // An authenticated empty bundle explicitly revokes this node's assignment.
    // Replace the staged document with an empty assignment set so revoked
    // credentials are not left on disk as if they were still current.
    let document = serde_json::json!({
        "schema_version":1,
        "node_id":node_id,
        "organization_id":organization_id,
        "delivery_id":delivery_id,
        "generated_at":bundle.get("generated_at"),
        "assignments":staged
    });
    let temporary = output_path.with_extension("json.tmp");
    if temporary.exists() {
        fs::remove_file(&temporary)?;
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        let mut file = fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&temporary)?;
        std::io::Write::write_all(&mut file, serde_json::to_string_pretty(&document)?.as_bytes())?;
        file.sync_all()?;
    }
    #[cfg(not(unix))]
    fs::write(&temporary, serde_json::to_vec_pretty(&document)?)?;
    #[cfg(windows)]
    if output_path.exists() {
        fs::remove_file(&output_path)?;
    }
    fs::rename(&temporary, &output_path)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&output_path, fs::Permissions::from_mode(0o600))?;
    }

    // Persist each assignment independently. A node may receive multiple
    // target assignments; one shared state file must never silently track only
    // the first assignment in the bundle.
    let state_dir = env::var_os("PROXIMA_NODE_RUNTIME_STATE_DIR")
        .map(PathBuf::from)
        .or_else(|| {
            output_path
                .parent()
                .map(|parent| parent.join("runtime-state"))
        })
        .unwrap_or_else(|| PathBuf::from("data/runtime-state"));
    fs::create_dir_all(&state_dir)?;
    let gateway_status_path = env::var_os("PROXIMA_NODE_GATEWAY_STATUS_PATH")
        .map(PathBuf::from)
        .unwrap_or_else(|| output_path.with_file_name("gateway-runtime-status.json"));
    let kubernetes_gateway_mode =
        env::var("PROXIMA_GATEWAY_EXECUTION_MODE").as_deref() == Ok("kubernetes");
    for record in &staged {
        let assignment_id = record
            .get("assignment_id")
            .and_then(serde_json::Value::as_str)
            .ok_or("assignment ID missing")?;
        let target_id = record
            .get("database_target_id")
            .and_then(serde_json::Value::as_str)
            .ok_or("target ID missing")?;
        let provider = record
            .get("provider_key")
            .and_then(serde_json::Value::as_str)
            .ok_or("provider key missing")?;
        let revision = record
            .get("config_revision")
            .and_then(serde_json::Value::as_u64)
            .ok_or("configuration revision missing")?;
        let credential_revision = record
            .get("credential_revision")
            .and_then(serde_json::Value::as_u64)
            .ok_or("credential revision missing")?;
        let state_key = hex::encode(Sha256::digest(assignment_id.as_bytes()));
        let state_path = state_dir.join(format!("{state_key}.json"));
        // Migrate state files written by the previous release, which used the
        // raw assignment ID as a filename, without losing revision monotonicity.
        let legacy_state_path = state_dir.join(format!("{assignment_id}.json"));
        let existing_state_path = if state_path.exists() {
            Some(state_path.as_path())
        } else if legacy_state_path.exists() {
            Some(legacy_state_path.as_path())
        } else {
            None
        };
        let state = if let Some(existing_path) = existing_state_path {
            let mut current = runtime_reconciliation::load(existing_path)?;
            current.update_desired(
                assignment_id,
                target_id,
                provider,
                revision,
                credential_revision,
            )?;
            current
        } else {
            RuntimeRecord::staged(
                assignment_id.to_owned(),
                target_id.to_owned(),
                provider.to_owned(),
                revision,
                credential_revision,
            )?
        };
        runtime_reconciliation::persist(&state_path, &state)?;
        if legacy_state_path.exists() && legacy_state_path != state_path {
            fs::remove_file(legacy_state_path)?;
        }
        info!(
            assignment_id,
            target_id,
            desired_revision = revision,
            phase = "staged",
            "authenticated database desired state persisted"
        );
    }

    // Activate the supported node-local gateway runtimes from the authenticated
    // bundle. The gateway modules are part of the Engine library and are invoked
    // here rather than merely compiling as unused source files.
    let private_root = env::var_os("PROXIMA_NODE_PRIVATE_ROOT")
        .map(PathBuf::from)
        .or_else(|| {
            identity_path
                .parent()
                .map(|parent| parent.join("runtime-private"))
        })
        .unwrap_or_else(|| PathBuf::from("data/runtime-private"));
    fs::create_dir_all(&private_root)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&private_root, fs::Permissions::from_mode(0o700))?;
    }

    // A signed desired-state bundle is authoritative. Assignments omitted from it
    // are locally revoked: stop their node-local gateway, remove its private
    // identity registry, and durably mark the assignment revoked.
    let active_assignment_ids: std::collections::HashSet<String> = staged
        .iter()
        .filter_map(|record| {
            record
                .get("assignment_id")
                .and_then(serde_json::Value::as_str)
        })
        .map(str::to_owned)
        .collect();
    for entry in fs::read_dir(&state_dir)? {
        let entry = entry?;
        let path = entry.path();
        if path.extension().and_then(|value| value.to_str()) != Some("json") {
            continue;
        }
        let mut prior = match runtime_reconciliation::load(&path) {
            Ok(record) => record,
            Err(error) => {
                tracing::error!(path=%path.display(), %error, "unreadable runtime state blocks safe automatic revocation");
                continue;
            }
        };
        if active_assignment_ids.contains(&prior.assignment_id)
            || prior.phase == RuntimePhase::Revoked
        {
            continue;
        }
        match prior.provider.as_str() {
            "mysql" | "mariadb" => mysql_runtime.stop(&prior.assignment_id).await?,
            "mongodb" => mongo_runtime.stop(&prior.assignment_id).await?,
            "redis" => redis_runtime.stop(&prior.assignment_id).await?,
            "sqlserver" => sqlserver_runtime.stop(&prior.assignment_id).await?,
            _ => {}
        }
        let identity_key = hex::encode(Sha256::digest(prior.assignment_id.as_bytes()));
        let identity_path = private_root
            .join("gateway-identities")
            .join(format!("{identity_key}.json"));
        if identity_path.exists() {
            fs::remove_file(identity_path)?;
        }
        prior.begin_revocation();
        runtime_reconciliation::persist(&path, &prior)?;
        info!(assignment_id=%prior.assignment_id, "omitted Cloud assignment locally revoked");
    }

    let mut provider_binding_evidence: std::collections::HashMap<
        String,
        Vec<proxima_engine::sqlserver_runtime::VerifiedBinding>,
    > = std::collections::HashMap::new();
    let mut gateway_endpoints = std::collections::HashMap::<String, (String, u16)>::new();
    for assignment in &staged {
        let assignment_id = assignment
            .get("assignment_id")
            .and_then(serde_json::Value::as_str)
            .ok_or("assignment ID missing")?;
        let state_key = hex::encode(Sha256::digest(assignment_id.as_bytes()));
        let state_path = state_dir.join(format!("{state_key}.json"));
        let mut state = runtime_reconciliation::load(&state_path)?;
        let Some(credentials) = decrypted_credentials.get(assignment_id) else {
            state.mark_failed("CREDENTIAL_BUNDLE_MISSING")?;
            runtime_reconciliation::persist(&state_path, &state)?;
            continue;
        };
        // Preview integrations are allowed to stage authenticated desired state,
        // but must never start a gateway or acknowledge an applied runtime.
        if assignment
            .get("cloud_integration_state")
            .and_then(serde_json::Value::as_str)
            != Some("enabled")
        {
            continue;
        }
        let activation = match assignment
            .get("gateway_runtime")
            .and_then(serde_json::Value::as_str)
            .unwrap_or("")
        {
            "proxima-mysql-gateway" => {
                mysql_runtime
                    .activate(
                        assignment,
                        credentials,
                        executable_dir,
                        &private_root,
                        &state_path,
                        &mut state,
                    )
                    .await
            }
            "proxima-mongodb-gateway" => {
                mongo_runtime
                    .activate(
                        assignment,
                        credentials,
                        executable_dir,
                        &private_root,
                        &state_path,
                        &mut state,
                    )
                    .await
            }
            "proxima-redis-gateway" => {
                redis_runtime
                    .activate(
                        assignment,
                        credentials,
                        executable_dir,
                        &private_root,
                        &state_path,
                        &mut state,
                    )
                    .await
            }
            "proxima-sqlserver-tds-gateway" => {
                sqlserver_runtime
                    .activate(
                        assignment,
                        credentials,
                        executable_dir,
                        &private_root,
                        &state_path,
                        &mut state,
                    )
                    .await
            }
            "proxima-engine" => {
                native_runtime
                    .activate_postgres(assignment, credentials, &state_path, &mut state)
                    .await
            }
            "proxima-engine-native-sqlite"
            | "proxima-engine-native-oracle"
            | "proxima-engine-native-dynamodb"
            | "proxima-engine-native-cassandra"
            | "proxima-engine-native-search" => {
                native_runtime
                    .activate(
                        assignment,
                        credentials,
                        &private_root,
                        &state_path,
                        &mut state,
                    )
                    .await
            }
            // All supported provider runtimes must be explicit; unknown artifacts
            // are not acknowledged as applied.
            _ => continue,
        };
        match activation {
            Ok(evidence) => {
                let runtime_name = assignment
                    .get("gateway_runtime")
                    .and_then(serde_json::Value::as_str)
                    .unwrap_or_default();
                if kubernetes_gateway_mode
                    && matches!(
                        runtime_name,
                        "proxima-mysql-gateway"
                            | "proxima-mongodb-gateway"
                            | "proxima-redis-gateway"
                            | "proxima-sqlserver-tds-gateway"
                    )
                {
                    let active_tenants = assignment
                        .get("tenant_bindings")
                        .and_then(serde_json::Value::as_array)
                        .map(|bindings| {
                            bindings
                                .iter()
                                .filter(|binding| {
                                    binding.get("status").and_then(serde_json::Value::as_str)
                                        != Some("revoked")
                                })
                                .count()
                        })
                        .unwrap_or(0);
                    match wait_for_kubernetes_gateway_status(
                        &gateway_status_path,
                        &node_id,
                        &delivery_id,
                        assignment_id,
                        i64::try_from(state.desired_revision)?,
                        active_tenants == 0,
                    )
                    .await
                    {
                        Ok(Some((host, port))) => {
                            gateway_endpoints
                                .insert(assignment_id.to_owned(), (host.clone(), port));
                        }
                        Ok(None) => {}
                        Err(error) => {
                            state.mark_failed("KUBERNETES_GATEWAY_NOT_READY")?;
                            runtime_reconciliation::persist(&state_path, &state)?;
                            tracing::error!(assignment_id, %error, "Kubernetes gateway did not become ready; Cloud binding remains pending");
                            continue;
                        }
                    }
                }
                if !evidence.is_empty() {
                    provider_binding_evidence.insert(assignment_id.to_owned(), evidence);
                }
            }
            Err(error) => {
                if state.phase != RuntimePhase::Failed {
                    state.mark_failed("GATEWAY_ACTIVATION_FAILED")?;
                }
                runtime_reconciliation::persist(&state_path, &state)?;
                tracing::error!(assignment_id, %error, "gateway assignment activation failed");
            }
        }
    }

    if let Some(verifier) = verifier {
        let assigned_tenants = provider_binding_evidence
            .values()
            .flatten()
            .filter(|evidence| {
                matches!(evidence.provider_key.as_str(), "postgresql" | "cockroachdb")
                    && evidence.status == "active"
            })
            .map(|evidence| evidence.tenant_id.clone())
            .collect::<std::collections::HashSet<_>>();
        verifier.set_allowed_tenants(Some(assigned_tenants));
    }

    for record in records {
        let assignment_id = record
            .get("assignment_id")
            .and_then(serde_json::Value::as_str)
            .ok_or("assignment ID missing")?;
        let target_id = record
            .get("database_target_id")
            .and_then(serde_json::Value::as_str)
            .ok_or("target ID missing")?;
        let revision = record
            .get("config_revision")
            .and_then(serde_json::Value::as_i64)
            .ok_or("config revision missing")?;
        let state_key = hex::encode(Sha256::digest(assignment_id.as_bytes()));
        let state_path = state_dir.join(format!("{state_key}.json"));
        let state = runtime_reconciliation::load(&state_path)?;
        let (status, healthy, error_code) = match state.phase {
            RuntimePhase::Applied
                if state.runtime_health_passed
                    && state.applied_revision == Some(state.desired_revision) =>
            {
                ("applied", true, None)
            }
            RuntimePhase::Failed => (
                "failed",
                false,
                Some(
                    state
                        .last_error_code
                        .unwrap_or_else(|| "RUNTIME_APPLY_FAILED".to_owned()),
                ),
            ),
            _ => ("staged", false, None),
        };
        let endpoint = gateway_endpoints.get(assignment_id);
        let runtime_endpoint = endpoint.map(|(host, _)| host.as_str());
        let runtime_port = endpoint.map(|(_, port)| *port);
        let health_label = if healthy { "healthy" } else { "unhealthy" };
        let ack_timestamp = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs() as i64;
        let ack_nonce = uuid::Uuid::new_v4().to_string();
        let ack_canonical = format!(
            "proxima-node-config-ack-v1\n{}\n{}\n{}\n{}\n{}\n{}\n{}\n{}\n{}\n{}\n{}\n{}",
            node_id,
            organization_id,
            ack_nonce,
            assignment_id,
            target_id,
            revision,
            ack_timestamp,
            status,
            health_label,
            error_code.as_deref().unwrap_or(""),
            runtime_endpoint.unwrap_or(""),
            runtime_port
                .map(|port| port.to_string())
                .unwrap_or_default()
        );
        let mut ack_mac = hmac::Hmac::<Sha256>::new_from_slice(&signing_key)?;
        ack_mac.update(ack_canonical.as_bytes());
        let ack_signature = hex::encode(ack_mac.finalize().into_bytes());
        client
            .post(&ack_url)
            .json(&serde_json::json!({
                "node_id":node_id,"nonce":ack_nonce,"assignment_id":assignment_id,
                "database_target_id":target_id,"config_revision":revision,
                "timestamp":ack_timestamp,"status":status,"runtime_health_passed":healthy,
                "runtime_endpoint":runtime_endpoint,"runtime_port":runtime_port,
                "error_code":error_code,"signature":ack_signature
            }))
            .send()
            .await?
            .error_for_status()?;

        // Tenant activation is reported only after the target-level acknowledgement
        // has been accepted and the SQL Server login/database isolation checks passed.
        if status == "applied" {
            if let Some(evidence_items) = provider_binding_evidence.get(assignment_id) {
                let node_uuid = uuid::Uuid::parse_str(&node_id)?;
                let org_uuid = uuid::Uuid::parse_str(&organization_id)?;
                let base_url = heartbeat_url
                    .strip_suffix("/api/v1/nodes/heartbeat")
                    .ok_or("node heartbeat URL is not canonical")?;
                for evidence in evidence_items {
                    let active = evidence.status == "active";
                    let details = serde_json::json!({
                        "provider_key":evidence.provider_key,
                        "identity_reference":evidence.identity_reference,
                        "identity_verified":active,
                        "isolation_verified":active,
                        "operation_id":uuid::Uuid::new_v4().to_string(),
                        "observed_at_unix":SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs(),
                        "details":evidence.details
                    });
                    let report_status = if active { "active" } else { "revoked" };
                    if let Err(error) = proxima_engine::tenant_binding_coordinator::report(
                        &client,
                        base_url,
                        node_uuid,
                        org_uuid,
                        &signing_key,
                        uuid::Uuid::parse_str(&evidence.binding_id)?,
                        uuid::Uuid::parse_str(&evidence.target_id)?,
                        evidence.revision,
                        report_status,
                        details,
                        None,
                    )
                    .await
                    {
                        tracing::error!(provider=%evidence.provider_key, binding_id=%evidence.binding_id, %error, "tenant provider evidence delivery failed; Cloud binding remains pending for retry");
                    }
                }
            }
        }
    }
    info!(assignments=records.len(),path=%output_path.display(),"authenticated database configuration reconciled on node");
    Ok(())
}

fn write_gateway_secret_manifest(
    assignments: &[serde_json::Value],
    decrypted_credentials: &std::collections::HashMap<String, serde_json::Value>,
    node_id: &str,
    delivery_id: &str,
    output_path: &Path,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    use base64::Engine as _;
    let mut secret_assignments = Vec::new();
    for assignment in assignments {
        let assignment_id = assignment
            .get("assignment_id")
            .and_then(serde_json::Value::as_str)
            .ok_or("assignment ID missing")?;
        let runtime_name = assignment
            .get("gateway_runtime")
            .and_then(serde_json::Value::as_str)
            .unwrap_or_default();
        if !matches!(
            runtime_name,
            "proxima-mysql-gateway"
                | "proxima-mongodb-gateway"
                | "proxima-redis-gateway"
                | "proxima-sqlserver-tds-gateway"
        ) {
            continue;
        }
        let credentials = decrypted_credentials
            .get(assignment_id)
            .ok_or("decrypted gateway credentials missing")?;
        let mut runtime = credentials
            .get("gateway_runtime_config")
            .cloned()
            .ok_or("gateway runtime config missing")?;
        let mut files = serde_json::Map::new();
        let mut add_file = |key: &str, source: &str| -> io::Result<()> {
            let bytes = fs::read(source)?;
            files.insert(
                key.to_owned(),
                serde_json::Value::String(base64::engine::general_purpose::STANDARD.encode(bytes)),
            );
            Ok(())
        };
        let secret_config = match runtime_name {
            "proxima-mysql-gateway" => {
                let ca = runtime
                    .get("upstream_tls_ca_file")
                    .and_then(serde_json::Value::as_str)
                    .map(str::to_owned)
                    .or_else(|| env::var("PROXIMA_MYSQL_UPSTREAM_TLS_CA_FILE").ok())
                    .ok_or("MySQL upstream TLS CA file missing")?;
                let cert = runtime
                    .get("tls_cert_file")
                    .and_then(serde_json::Value::as_str)
                    .map(str::to_owned)
                    .or_else(|| env::var("PROXIMA_MYSQL_TLS_CERT_FILE").ok())
                    .ok_or("MySQL gateway TLS certificate missing")?;
                let key = runtime
                    .get("tls_key_file")
                    .and_then(serde_json::Value::as_str)
                    .map(str::to_owned)
                    .or_else(|| env::var("PROXIMA_MYSQL_TLS_KEY_FILE").ok())
                    .ok_or("MySQL gateway TLS key missing")?;
                add_file("ca.crt", &ca)?;
                add_file("tls.crt", &cert)?;
                add_file("tls.key", &key)?;
                runtime["upstream_tls_ca_file"] =
                    serde_json::Value::String("/var/run/proxima/ca.crt".into());
                runtime["tls_cert_file"] =
                    serde_json::Value::String("/var/run/proxima/tls.crt".into());
                runtime["tls_key_file"] =
                    serde_json::Value::String("/var/run/proxima/tls.key".into());
                serde_json::json!({"kind":"mysql","runtime_config":runtime})
            }
            "proxima-mongodb-gateway" => {
                let ca = runtime
                    .get("upstream_tls_ca_file")
                    .and_then(serde_json::Value::as_str)
                    .map(str::to_owned)
                    .or_else(|| env::var("PROXIMA_MONGODB_UPSTREAM_TLS_CA_FILE").ok())
                    .ok_or("MongoDB upstream TLS CA file missing")?;
                let cert = runtime
                    .get("tls_cert_file")
                    .and_then(serde_json::Value::as_str)
                    .map(str::to_owned)
                    .or_else(|| env::var("PROXIMA_MONGODB_TLS_CERT_FILE").ok())
                    .ok_or("MongoDB gateway TLS certificate missing")?;
                let key = runtime
                    .get("tls_key_file")
                    .and_then(serde_json::Value::as_str)
                    .map(str::to_owned)
                    .or_else(|| env::var("PROXIMA_MONGODB_TLS_KEY_FILE").ok())
                    .ok_or("MongoDB gateway TLS key missing")?;
                add_file("ca.crt", &ca)?;
                add_file("tls.crt", &cert)?;
                add_file("tls.key", &key)?;
                runtime["upstream_tls_ca_file"] =
                    serde_json::Value::String("/var/run/proxima/ca.crt".into());
                runtime["tls_cert_file"] =
                    serde_json::Value::String("/var/run/proxima/tls.crt".into());
                runtime["tls_key_file"] =
                    serde_json::Value::String("/var/run/proxima/tls.key".into());
                if let Some(users) = runtime
                    .get_mut("users")
                    .and_then(serde_json::Value::as_array_mut)
                {
                    for user in users {
                        if let Some(object) = user.as_object_mut() {
                            object.remove("password");
                        }
                    }
                }
                serde_json::json!({"kind":"mongodb","runtime_config":runtime})
            }
            "proxima-redis-gateway" => {
                let ca = runtime
                    .get("upstream_tls_ca_file")
                    .and_then(serde_json::Value::as_str)
                    .map(str::to_owned)
                    .or_else(|| env::var("PROXIMA_REDIS_UPSTREAM_TLS_CA_FILE").ok())
                    .ok_or("Redis upstream TLS CA file missing")?;
                let cert = runtime
                    .get("tls_cert_file")
                    .and_then(serde_json::Value::as_str)
                    .map(str::to_owned)
                    .or_else(|| env::var("PROXIMA_REDIS_TLS_CERT_FILE").ok())
                    .ok_or("Redis gateway TLS certificate missing")?;
                let key = runtime
                    .get("tls_key_file")
                    .and_then(serde_json::Value::as_str)
                    .map(str::to_owned)
                    .or_else(|| env::var("PROXIMA_REDIS_TLS_KEY_FILE").ok())
                    .ok_or("Redis gateway TLS key missing")?;
                add_file("ca.crt", &ca)?;
                add_file("tls.crt", &cert)?;
                add_file("tls.key", &key)?;
                runtime["upstream_tls_ca_file"] =
                    serde_json::Value::String("/var/run/proxima/ca.crt".into());
                runtime["tls_cert_file"] =
                    serde_json::Value::String("/var/run/proxima/tls.crt".into());
                runtime["tls_key_file"] =
                    serde_json::Value::String("/var/run/proxima/tls.key".into());
                serde_json::json!({"kind":"redis","runtime_config":runtime})
            }
            "proxima-sqlserver-tds-gateway" => {
                let ca = runtime
                    .get("upstream_ca_pem")
                    .and_then(serde_json::Value::as_str)
                    .map(str::to_owned)
                    .or_else(|| env::var("PROXIMA_SQLSERVER_TDS_UPSTREAM_CA_PEM").ok())
                    .ok_or("SQL Server upstream CA PEM path missing")?;
                let cert = runtime
                    .get("client_cert_pem")
                    .and_then(serde_json::Value::as_str)
                    .map(str::to_owned)
                    .or_else(|| env::var("PROXIMA_SQLSERVER_TDS_CLIENT_CERT_PEM").ok())
                    .ok_or("SQL Server gateway certificate path missing")?;
                let key = runtime
                    .get("client_key_pem")
                    .and_then(serde_json::Value::as_str)
                    .map(str::to_owned)
                    .or_else(|| env::var("PROXIMA_SQLSERVER_TDS_CLIENT_KEY_PEM").ok())
                    .ok_or("SQL Server gateway private key path missing")?;
                add_file("upstream-ca.crt", &ca)?;
                add_file("server.crt", &cert)?;
                add_file("server.key", &key)?;
                let host = assignment
                    .pointer("/endpoint/host")
                    .and_then(serde_json::Value::as_str)
                    .ok_or("SQL Server upstream host missing")?;
                let port = assignment
                    .pointer("/endpoint/port")
                    .and_then(serde_json::Value::as_u64)
                    .ok_or("SQL Server upstream port missing")? as u16;
                let users = runtime
                    .get("users")
                    .and_then(serde_json::Value::as_array)
                    .ok_or("SQL Server runtime users missing")?;
                let tenants =
                    users
                        .iter()
                        .map(
                            |user| -> io::Result<
                                proxima_engine::sqlserver_tds_gateway::TdsTenantBinding,
                            > {
                                Ok(proxima_engine::sqlserver_tds_gateway::TdsTenantBinding {
                                    tenant_id: user
                                        .get("tenant_id")
                                        .and_then(serde_json::Value::as_str)
                                        .ok_or_else(|| {
                                            io::Error::other("SQL Server tenant ID missing")
                                        })?
                                        .to_owned(),
                                    username: user
                                        .get("username")
                                        .and_then(serde_json::Value::as_str)
                                        .ok_or_else(|| {
                                            io::Error::other("SQL Server tenant username missing")
                                        })?
                                        .to_owned(),
                                    database: user
                                        .get("database")
                                        .and_then(serde_json::Value::as_str)
                                        .ok_or_else(|| {
                                            io::Error::other("SQL Server tenant database missing")
                                        })?
                                        .to_owned(),
                                })
                            },
                        )
                        .collect::<io::Result<Vec<_>>>()?;
                let config = proxima_engine::sqlserver_tds_gateway::SqlServerTdsConfig {
                    schema_version: 1,
                    provider_key: "sqlserver".into(),
                    listen_addr: "0.0.0.0:14330".into(),
                    upstream_host: host.to_owned(),
                    upstream_port: port,
                    upstream_server_name: runtime
                        .get("upstream_server_name")
                        .and_then(serde_json::Value::as_str)
                        .unwrap_or(host)
                        .to_owned(),
                    upstream_ca_pem: "/var/run/proxima/upstream-ca.crt".into(),
                    client_cert_pem: "/var/run/proxima/server.crt".into(),
                    client_key_pem: "/var/run/proxima/server.key".into(),
                    allow_non_loopback: runtime
                        .get("allow_non_loopback")
                        .and_then(serde_json::Value::as_bool)
                        .unwrap_or_else(|| {
                            env::var("PROXIMA_SQLSERVER_TDS_ALLOW_NON_LOOPBACK").as_deref()
                                == Ok("true")
                        }),
                    tenants,
                };
                serde_json::json!({"kind":"sqlserver","config":config})
            }
            _ => unreachable!(),
        };
        drop(add_file);
        let active_tenant_count = assignment
            .get("tenant_bindings")
            .and_then(serde_json::Value::as_array)
            .map(|bindings| {
                bindings
                    .iter()
                    .filter(|binding| {
                        binding.get("status").and_then(serde_json::Value::as_str) != Some("revoked")
                    })
                    .count()
            })
            .unwrap_or(0);
        let config_revision = assignment
            .get("config_revision")
            .and_then(serde_json::Value::as_i64)
            .ok_or("gateway assignment config_revision missing")?;
        secret_assignments.push(serde_json::json!({
            "assignment_id":assignment_id,
            "config_revision":config_revision,
            "gateway_runtime":runtime_name,
            "active_tenant_count":active_tenant_count,
            "secret_config":secret_config,
            "files":files
        }));
    }
    if let Some(parent) = output_path.parent() {
        fs::create_dir_all(parent)?;
    }
    let document = serde_json::json!({"schema_version":1,"node_id":node_id,"delivery_id":delivery_id,"assignments":secret_assignments});
    let temporary = output_path.with_extension("json.tmp");
    if temporary.exists() {
        fs::remove_file(&temporary)?;
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        let mut file = fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&temporary)?;
        std::io::Write::write_all(&mut file, serde_json::to_string_pretty(&document)?.as_bytes())?;
        file.sync_all()?;
    }
    #[cfg(not(unix))]
    fs::write(&temporary, serde_json::to_vec_pretty(&document)?)?;
    if output_path.exists() {
        fs::remove_file(output_path)?;
    }
    fs::rename(&temporary, output_path)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(output_path, fs::Permissions::from_mode(0o600))?;
    }
    Ok(())
}

async fn wait_for_kubernetes_gateway_status(
    status_path: &Path,
    expected_node_id: &str,
    expected_delivery_id: &str,
    assignment_id: &str,
    revision: i64,
    expect_removed: bool,
) -> Result<Option<(String, u16)>, Box<dyn std::error::Error + Send + Sync>> {
    let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(240);
    loop {
        if let Ok(bytes) = fs::read(status_path) {
            if let Ok(document) = serde_json::from_slice::<serde_json::Value>(&bytes) {
                if document.get("node_id").and_then(serde_json::Value::as_str)
                    != Some(expected_node_id)
                    || document
                        .get("delivery_id")
                        .and_then(serde_json::Value::as_str)
                        != Some(expected_delivery_id)
                {
                    tokio::time::sleep(std::time::Duration::from_secs(2)).await;
                    continue;
                }
                if let Some(entries) = document
                    .get("assignments")
                    .and_then(serde_json::Value::as_array)
                {
                    if let Some(entry) = entries.iter().find(|entry| {
                        entry
                            .get("assignment_id")
                            .and_then(serde_json::Value::as_str)
                            == Some(assignment_id)
                    }) {
                        let observed_revision = entry
                            .get("config_revision")
                            .and_then(serde_json::Value::as_i64);
                        let status = entry.get("status").and_then(serde_json::Value::as_str);
                        if observed_revision == Some(revision)
                            && ((expect_removed && status == Some("removed"))
                                || (!expect_removed && status == Some("ready")))
                        {
                            if expect_removed {
                                return Ok(None);
                            }
                            let host = entry
                                .get("service_dns")
                                .and_then(serde_json::Value::as_str)
                                .ok_or("Kubernetes gateway status has no service DNS name")?;
                            let port = entry
                                .get("port")
                                .and_then(serde_json::Value::as_u64)
                                .filter(|p| (1..=65535).contains(p))
                                .ok_or("Kubernetes gateway status has no valid service port")?
                                as u16;
                            return Ok(Some((host.to_owned(), port)));
                        }
                        if observed_revision == Some(revision) && status == Some("failed") {
                            return Err(format!("Kubernetes gateway reconciliation failed for assignment {assignment_id}").into());
                        }
                    }
                }
            }
        }
        if tokio::time::Instant::now() >= deadline {
            return Err(format!(
                "timed out waiting for Kubernetes gateway readiness for assignment {assignment_id}"
            )
            .into());
        }
        tokio::time::sleep(std::time::Duration::from_secs(2)).await;
    }
}

fn spawn_node_database_config_worker(verifier: Option<TenantTokenVerifier>) {
    tokio::spawn(async move {
        // Keep supervisors alive for the worker lifetime. Recreating them on every
        // poll would lose Child handles and repeatedly spawn gateways on occupied ports.
        let mysql_runtime = MysqlRuntime::new();
        let mongo_runtime = MongoRuntime::new();
        let redis_runtime = RedisRuntime::new();
        let sqlserver_runtime = SqlServerRuntime::new();
        let native_runtime = NativeProviderRuntime;
        let mut interval = tokio::time::interval(std::time::Duration::from_secs(30));
        loop {
            interval.tick().await;
            match pull_and_stage_database_config_once(
                &mysql_runtime,
                &mongo_runtime,
                &redis_runtime,
                &sqlserver_runtime,
                &native_runtime,
                verifier.as_ref(),
            )
            .await
            {
                Ok(()) => {}
                Err(error) => {
                    tracing::warn!(%error,"database configuration pull/stage cycle failed; current gateway configuration is unchanged")
                }
            }
        }
    });
}

#[cfg(test)]
mod assignment_runtime_cardinality_tests {
    use super::validate_assignment_runtime_cardinality;
    use serde_json::json;

    #[test]
    fn accepts_multiple_independent_gateway_assignments() {
        let records = vec![
            json!({"assignment_id":"mysql-a","gateway_runtime":"proxima-mysql-gateway"}),
            json!({"assignment_id":"mysql-b","gateway_runtime":"proxima-mysql-gateway"}),
            json!({"assignment_id":"mongo-a","gateway_runtime":"proxima-mongodb-gateway"}),
            json!({"assignment_id":"redis-a","gateway_runtime":"proxima-redis-gateway"}),
        ];
        assert!(validate_assignment_runtime_cardinality(&records).is_ok());
    }

    #[test]
    fn keeps_native_engine_listener_single_upstream() {
        let records = vec![
            json!({"assignment_id":"pg-a","gateway_runtime":"proxima-engine"}),
            json!({"assignment_id":"pg-b","gateway_runtime":"proxima-engine"}),
        ];
        assert!(validate_assignment_runtime_cardinality(&records).is_err());
    }

    #[test]
    fn rejects_assignment_ids_that_could_escape_runtime_state_directory() {
        let records = vec![json!({
            "assignment_id": "..\\outside",
            "gateway_runtime": "proxima-mysql-gateway"
        })];
        assert!(validate_assignment_runtime_cardinality(&records).is_err());
    }

    #[test]
    fn rejects_duplicate_assignment_ids_and_unknown_runtimes() {
        let duplicate = vec![
            json!({"assignment_id":"same","gateway_runtime":"proxima-mysql-gateway"}),
            json!({"assignment_id":"same","gateway_runtime":"proxima-redis-gateway"}),
        ];
        let unknown = vec![json!({"assignment_id":"x","gateway_runtime":"made-up"})];
        assert!(validate_assignment_runtime_cardinality(&duplicate).is_err());
        assert!(validate_assignment_runtime_cardinality(&unknown).is_err());
    }
}

#[tokio::main]
async fn main() -> io::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            std::env::var("RUST_LOG").unwrap_or_else(|_| "proxima_engine=info".to_string()),
        )
        .init();

    rustls::crypto::CryptoProvider::install_default(rustls::crypto::aws_lc_rs::default_provider())
        .map_err(|_| io::Error::other("failed to install rustls AWS-LC crypto provider"))?;

    // Enrollment must run before configuration is loaded: it supplies the
    // node identity and organization-scoped tenant verification key.
    if let Err(error) = bootstrap_node_identity().await {
        eprintln!("Engine node bootstrap failed: {error}");
        std::process::exit(1);
    }
    let config = Config::from_env()?;
    let config_tenant_role_prefix = config.tenant_role_prefix.clone();

    let verifier = config
        .tenant_signing_key
        .as_deref()
        .map(|key| {
            TenantTokenVerifier::new_with_previous(
                key,
                config.tenant_signing_key_previous.as_deref(),
            )
        })
        .transpose()
        .map_err(|error| io::Error::new(io::ErrorKind::InvalidInput, error.to_string()))?;

    if std::env::var("PROXIMA_NODE_HEARTBEAT_URL").is_ok() {
        spawn_node_database_config_worker(verifier.clone());
    }

    let client_acceptor = client_acceptor(&config)?;
    let upstream_connector = upstream_connector(&config)?;

    if config.require_client_tls && client_acceptor.is_none() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "client TLS is required but no certificate/key is configured",
        ));
    }

    let listener = TcpListener::bind(config.listen_addr).await?;
    let metrics_addr: std::net::SocketAddr = std::env::var("PROXIMA_METRICS_LISTEN_ADDR")
        .unwrap_or_else(|_| "127.0.0.1:9090".to_string())
        .parse()
        .map_err(|error| {
            io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("invalid PROXIMA_METRICS_LISTEN_ADDR: {error}"),
            )
        })?;
    let metrics_listener = TcpListener::bind(metrics_addr).await?;
    tokio::spawn(async move {
        if let Err(error) = metrics::serve_listener(metrics_listener).await {
            error!(%error, "Prometheus metrics listener stopped");
        }
    });
    let breaker = SecurityBreaker::new(BreakerConfig::from_env());
    let allow_insecure_security_http = matches!(
        std::env::var("PROXIMA_TENANT_CANARY_ALLOW_INSECURE_HTTP")
            .unwrap_or_default()
            .trim()
            .to_ascii_lowercase()
            .as_str(),
        "true" | "1" | "yes"
    );
    let security_event_url = std::env::var("PROXIMA_SECURITY_EVENT_INGEST_URL")
        .ok()
        .filter(|url| canary_probe::control_plane_url_allowed(url, allow_insecure_security_http));
    let security_event_token = std::env::var("PROXIMA_SECURITY_EVENT_INGEST_TOKEN")
        .or_else(|_| std::env::var("PROXIMA_ATTESTATION_INGEST_TOKEN"))
        .ok()
        .filter(|token| token.starts_with("aga_"));
    let security_event_client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(5))
        .build()
        .ok();
    if let (Some(url), Some(token), Some(client)) = (
        security_event_url.clone(),
        security_event_token.clone(),
        security_event_client.clone(),
    ) {
        let outbox = break_glass::default_outbox_dir();
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(std::time::Duration::from_secs(10));
            loop {
                interval.tick().await;
                let events = match break_glass::pending_events(&outbox).await {
                    Ok(v) => v,
                    Err(error) => {
                        error!(%error,"cannot read break-glass outbox; events preserved");
                        continue;
                    }
                };
                for (path, event) in events {
                    match client
                        .post(&url)
                        .bearer_auth(&token)
                        .json(&event)
                        .send()
                        .await
                    {
                        Ok(response) if response.status().is_success() => {
                            if let Err(error) = break_glass::acknowledge_event(&path).await {
                                error!(%error,"break-glass event accepted but local acknowledgement failed; safe redelivery may occur");
                                break;
                            }
                        }
                        Ok(response) => {
                            error!(status=%response.status(),"break-glass delivery deferred; event remains queued");
                            break;
                        }
                        Err(error) => {
                            error!(%error,"break-glass delivery deferred; event remains queued");
                            break;
                        }
                    }
                }
            }
        });
    }
    let allow_insecure_attestation_http = matches!(
        std::env::var("PROXIMA_ATTESTATION_ALLOW_INSECURE_HTTP")
            .unwrap_or_default()
            .trim()
            .to_ascii_lowercase()
            .as_str(),
        "true" | "1" | "yes"
    );
    // Report signed liveness independently of the slower hourly attestation ledger.
    // This updates Fleet health without turning enrollment into a health assertion.
    let heartbeat_url = std::env::var("PROXIMA_NODE_HEARTBEAT_URL")
        .ok()
        .filter(|value| !value.trim().is_empty())
        .or_else(|| {
            std::env::var("PROXIMA_NODE_ENROLLMENT_URL")
                .ok()
                .map(|value| value.replace("/api/v1/nodes/enroll", "/api/v1/nodes/heartbeat"))
        })
        .or_else(|| {
            std::env::var("PROXIMA_ATTESTATION_INGEST_URL")
                .ok()
                .map(|value| value.replace("/api/v1/attestations", "/api/v1/nodes/heartbeat"))
        })
        .filter(|url| attestation_ingest_url_allowed(url, allow_insecure_attestation_http));
    let heartbeat_identity = (
        std::env::var("PROXIMA_NODE_ID").ok(),
        std::env::var("PROXIMA_ORGANIZATION_ID").ok(),
        std::env::var("PROXIMA_NODE_SIGNING_KEY_HEX").ok(),
    );
    let (provider_keys, capabilities, artifact_digest) = runtime_capability_report();
    if let (Some(url), (Some(node_id), Some(organization_id), Some(key_hex))) =
        (heartbeat_url, heartbeat_identity)
    {
        let signing_key = hex::decode(&key_hex).ok().filter(|key| key.len() == 32);
        if let Some(signing_key) = signing_key {
            let client = reqwest::Client::builder()
                .redirect(reqwest::redirect::Policy::none())
                .timeout(std::time::Duration::from_secs(8))
                .build();
            if let Ok(client) = client {
                tokio::spawn(async move {
                    let mut interval = tokio::time::interval(std::time::Duration::from_secs(30));
                    loop {
                        interval.tick().await;
                        let timestamp = std::time::SystemTime::now()
                            .duration_since(std::time::UNIX_EPOCH)
                            .map(|value| value.as_secs() as i64)
                            .unwrap_or_default();
                        let version = env!("CARGO_PKG_VERSION").to_string();
                        let runtime_status = "running";
                        let signature = match sign_node_heartbeat_v2(
                            &signing_key,
                            &node_id,
                            &organization_id,
                            timestamp,
                            &version,
                            runtime_status,
                            &provider_keys,
                            &capabilities,
                            artifact_digest.as_deref(),
                        ) {
                            Ok(signature) => signature,
                            Err(_) => {
                                error!("could not initialize node heartbeat signature");
                                continue;
                            }
                        };
                        let payload = serde_json::json!({
                            "node_id": node_id,
                            "timestamp": timestamp,
                            "version": version,
                            "runtime_status": runtime_status,
                            "provider_keys": provider_keys,
                            "capabilities": capabilities,
                            "artifact_digest": artifact_digest,
                            "signature": signature
                        });
                        match client.post(&url).json(&payload).send().await {
                            Ok(response) if response.status().is_success() => {
                                info!(node_id = %node_id, "signed node heartbeat accepted");
                            }
                            Ok(response) => {
                                error!(node_id = %node_id, status = %response.status(), "node heartbeat rejected; retrying on next interval");
                            }
                            Err(error) => {
                                error!(node_id = %node_id, %error, "node heartbeat delivery failed; retrying on next interval");
                            }
                        }
                    }
                });
                info!("signed node heartbeat enabled; interval=30s");
            }
        } else {
            error!("node heartbeat disabled because the enrolled signing key is invalid");
        }
    } else if std::env::var("PROXIMA_NODE_ID").is_ok() {
        error!("node heartbeat is not configured: verify node identity and PROXIMA_NODE_HEARTBEAT_URL or enrollment URL");
    }

    let attestation_config = AttestationConfig::from_env();
    let attestation_signing_ready = attestation_config.signing_key.is_some();
    let attestation_p99 = std::env::var("PROXIMA_ATTESTATION_P99_OVERHEAD_MS")
        .ok()
        .and_then(|value| value.parse::<f64>().ok())
        .filter(|value| value.is_finite() && *value >= 0.0);
    if attestation_signing_ready && attestation_p99.is_some() {
        let ledger = Arc::new(AttestationLedger::new(attestation_config.clone()));
        let engine_config = config.clone();
        let configured_ingest_url = std::env::var("PROXIMA_ATTESTATION_INGEST_URL")
            .ok()
            .filter(|value| !value.trim().is_empty());
        let ingest_url = configured_ingest_url
            .clone()
            .filter(|url| attestation_ingest_url_allowed(url, allow_insecure_attestation_http));
        if configured_ingest_url.is_some() && ingest_url.is_none() {
            error!("attestation ingestion URL must use HTTPS, loopback HTTP, or the explicitly enabled local Docker control-plane URL");
        }
        let ingest_token = std::env::var("PROXIMA_ATTESTATION_INGEST_TOKEN")
            .ok()
            .filter(|value| value.starts_with("aga_"));
        let http_client = reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(10))
            .build()
            .ok();
        if ingest_url.is_some() && (ingest_token.is_none() || http_client.is_none()) {
            error!("attestation ingestion URL is configured but a valid API token or HTTPS client is unavailable");
        }
        tokio::spawn(async move {
            let mut interval = tokio::time::interval_at(
                tokio::time::Instant::now(),
                std::time::Duration::from_secs(3600),
            );
            let mut previous_queries = 0u64;
            let mut previous_tenant_sessions = 0u64;
            let mut previous_violations = 0u64;
            let mut previous_breaker_trips = 0u64;
            loop {
                interval.tick().await;
                let snapshot = metrics::global();
                let current_queries = snapshot.processed_queries();
                let current_tenant_sessions = snapshot.authenticated_tenant_sessions();
                let current_violations = snapshot.blocked_violations();
                let current_breaker_trips = snapshot.breaker_trips();
                let telemetry = TelemetrySummary {
                    total_processed_queries: current_queries.saturating_sub(previous_queries),
                    authenticated_tenant_sessions: current_tenant_sessions
                        .saturating_sub(previous_tenant_sessions),
                    blocked_unauthorized_violations: current_violations
                        .saturating_sub(previous_violations),
                    p99_latency_overhead_ms: attestation_p99.unwrap_or(0.0),
                };
                let state = SecurityState {
                    force_rls_active: std::env::var("PROXIMA_ATTESTATION_FORCE_RLS_ACTIVE")
                        .ok()
                        .as_deref()
                        == Some("true"),
                    tls_termination_enforced: engine_config.require_client_tls
                        && engine_config.tls_cert_file.is_some(),
                    circuit_breaker_tripped: current_breaker_trips > previous_breaker_trips,
                };
                previous_queries = current_queries;
                previous_tenant_sessions = current_tenant_sessions;
                previous_violations = current_violations;
                previous_breaker_trips = current_breaker_trips;
                match ledger.append_hourly(telemetry, state).await {
                    Ok(_) => {
                        if let (Some(url), Some(token), Some(client)) = (
                            ingest_url.as_deref(),
                            ingest_token.as_deref(),
                            http_client.as_ref(),
                        ) {
                            deliver_pending_attestations(&ledger, client, url, token).await;
                        }
                    }
                    Err(error) => {
                        error!(%error, "hourly security attestation could not be written")
                    }
                }
            }
        });
        info!("hourly signed attestation ledger enabled");
    } else {
        info!("hourly signed attestation ledger disabled: set PROXIMA_ATTESTATION_P99_OVERHEAD_MS to a measured non-negative value; the enrolled node signing key is already available");
    }
    let connection_limit = Arc::new(Semaphore::new(config.max_connections));

    if matches!(
        std::env::var("PROXIMA_TENANT_CANARY_ENABLED").as_deref(),
        Ok("true" | "1" | "yes")
    ) {
        if verifier.is_none() {
            error!("tenant canary is enabled but tenant-token enforcement is not configured; no canary runner was started");
        } else {
            let local_probe_addr: std::net::SocketAddr =
                std::env::var("PROXIMA_TENANT_CANARY_LOCAL_LISTEN_ADDR")
                    .unwrap_or_else(|_| "127.0.0.1:16432".to_string())
                    .parse()
                    .map_err(|error| {
                        io::Error::new(
                            io::ErrorKind::InvalidInput,
                            format!("invalid PROXIMA_TENANT_CANARY_LOCAL_LISTEN_ADDR: {error}"),
                        )
                    })?;
            if !local_probe_addr.ip().is_loopback() {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "PROXIMA_TENANT_CANARY_LOCAL_LISTEN_ADDR must bind to a loopback address",
                ));
            }
            let probe_listener = match TcpListener::bind(local_probe_addr).await {
                Ok(listener) => Some(listener),
                Err(error) => {
                    error!(%error, listen = %local_probe_addr, "could not bind loopback tenant-canary listener; continuing without canary probes");
                    None
                }
            };
            if let Some(probe_listener) = probe_listener {
                let probe_upstream = config.upstream_addr.clone();
                let probe_verifier = verifier.clone();
                let probe_role_prefix = config_tenant_role_prefix.clone();
                let probe_connect_timeout = config.upstream_connect_timeout;
                let probe_client_tls_timeout = config.tls_handshake_timeout;
                let probe_upstream_connector = upstream_connector.clone();
                let probe_upstream_tls_timeout = config.upstream_tls_handshake_timeout;
                let probe_upstream_tls_mode = config.upstream_tls_mode;
                let probe_upstream_server_name = config.upstream_tls_server_name.clone();
                let probe_limit = connection_limit.clone();
                tokio::spawn(async move {
                    loop {
                        let (client, peer) = match probe_listener.accept().await {
                            Ok(pair) => pair,
                            Err(error) => {
                                error!(%error, "local tenant-canary listener stopped accepting connections");
                                break;
                            }
                        };
                        metrics::global().connection_accepted();
                        let permit = match probe_limit.clone().try_acquire_owned() {
                            Ok(permit) => permit,
                            Err(_) => {
                                metrics::global().connection_rejected();
                                drop(client);
                                continue;
                            }
                        };
                        let upstream = probe_upstream.clone();
                        let verifier = probe_verifier.clone();
                        let role_prefix = probe_role_prefix.clone();
                        let upstream_connector = probe_upstream_connector.clone();
                        let server_name = probe_upstream_server_name.clone();
                        tokio::spawn(async move {
                            let _permit = permit;
                            if let Err(error) = handle_connection(
                                client,
                                peer,
                                &upstream,
                                verifier.as_ref(),
                                &role_prefix,
                                probe_connect_timeout,
                                None,
                                upstream_connector.as_ref(),
                                probe_client_tls_timeout,
                                probe_upstream_tls_timeout,
                                false,
                                probe_upstream_tls_mode,
                                server_name.as_deref(),
                            )
                            .await
                            {
                                metrics::global().session_failed();
                                error!(%peer, %error, "local tenant-canary connection failed");
                            }
                        });
                    }
                });
                tokio::spawn(async move {
                    canary_probe::run_if_enabled(local_probe_addr).await;
                });
                info!(listen = %local_probe_addr, "loopback-only tenant-canary listener enabled; tenant enforcement and upstream TLS remain active");
            }
        }
    }

    if config.dashboard_enabled {
        let dashboard_addr = config.dashboard_listen_addr;
        tokio::spawn(async move {
            if let Err(error) = dashboard::serve(dashboard_addr).await {
                error!(%error, "dashboard server stopped");
            }
        });
    }

    info!(
        listen = %config.listen_addr,
        upstream = %config.upstream_addr,
        tenant_enforcement = verifier.is_some(),
        client_tls = client_acceptor.is_some(),
        require_client_tls = config.require_client_tls,
        upstream_tls = config.upstream_tls_mode != UpstreamTlsMode::Disable,
        dashboard = config.dashboard_enabled,
        metrics = %metrics_addr,
        security_breaker = breaker_config_enabled(),
        max_connections = config.max_connections,
        "Agata Proxima engine listening"
    );

    loop {
        tokio::select! {
            accept = listener.accept() => {
                let (client, peer) = accept?;
                metrics::global().connection_accepted();
                if breaker.is_blocked(peer.ip()) {
                    metrics::global().connection_rejected();
                    error!(peer = %peer, "connection rejected by security breaker");
                    drop(client);
                    continue;
                }
                let permit = match connection_limit.clone().try_acquire_owned() {
                    Ok(permit) => permit,
                    Err(_) => {
                        metrics::global().connection_rejected();
                        error!(peer = %peer, "connection limit reached");
                        drop(client);
                        continue;
                    }
                };

                let breaker = breaker.clone();
                let security_event_url = security_event_url.clone();
                let security_event_token = security_event_token.clone();
                let security_event_client = security_event_client.clone();
                let upstream = config.upstream_addr.clone();
                let verifier = verifier.clone();
                let tenant_role_prefix = config_tenant_role_prefix.clone();
                let upstream_connect_timeout = config.upstream_connect_timeout;
                let client_acceptor = client_acceptor.clone();
                let upstream_connector = upstream_connector.clone();
                let client_tls_timeout = config.tls_handshake_timeout;
                let upstream_tls_timeout = config.upstream_tls_handshake_timeout;
                let require_client_tls = config.require_client_tls;
                let upstream_tls_mode = config.upstream_tls_mode;
                let upstream_tls_server_name = config.upstream_tls_server_name.clone();

                tokio::spawn(async move {
                    let _permit = permit;
                    if let Err(err) = handle_connection(
                        client,
                        peer,
                        &upstream,
                        verifier.as_ref(),
                        &tenant_role_prefix,
                        upstream_connect_timeout,
                        client_acceptor.as_ref(),
                        upstream_connector.as_ref(),
                        client_tls_timeout,
                        upstream_tls_timeout,
                        require_client_tls,
                        upstream_tls_mode,
                        upstream_tls_server_name.as_deref(),
                    ).await {
                        metrics::global().session_failed();
                        let security_failure = matches!(err.kind(), io::ErrorKind::PermissionDenied | io::ErrorKind::InvalidData);
                        if security_failure {
                            metrics::global().violation_blocked();
                            if breaker.record_violation(peer.ip()) {
                                metrics::global().breaker_tripped();
                                error!(peer = %peer, "security breaker tripped for peer; cooldown enforced");
                                if let (Some(url), Some(token), Some(client)) = (
                                    security_event_url.clone(),
                                    security_event_token.clone(),
                                    security_event_client.clone(),
                                ) {
                                    let node_id = std::env::var("PROXIMA_NODE_ID").unwrap_or_else(|_| "local-node".to_string());
                                    let fingerprint = peer_fingerprint(peer.ip());
                                    tokio::spawn(async move {
                                        send_security_event(client, url, token, node_id, fingerprint).await;
                                    });
                                } else {
                                    error!("security breaker tripped but control-plane event delivery is not configured with an HTTPS endpoint and API token");
                                }
                            }
                        }
                        error!(peer = %peer, error = %err, "connection failed");
                    }
                });
            }
            _ = tokio::signal::ctrl_c() => {
                info!("shutdown signal received");
                break;
            }
        }
    }

    Ok(())
}

#[allow(clippy::too_many_arguments)]
async fn handle_connection(
    mut client: TcpStream,
    peer: std::net::SocketAddr,
    upstream_addr: &str,
    verifier: Option<&TenantTokenVerifier>,
    tenant_role_prefix: &str,
    upstream_connect_timeout: std::time::Duration,
    client_acceptor: Option<&tokio_rustls::TlsAcceptor>,
    upstream_connector: Option<&tokio_rustls::TlsConnector>,
    client_tls_timeout: std::time::Duration,
    upstream_tls_timeout: std::time::Duration,
    require_client_tls: bool,
    upstream_tls_mode: UpstreamTlsMode,
    upstream_tls_server_name: Option<&str>,
) -> io::Result<()> {
    info!(peer = %peer, "client connected");

    let client_is_tls = client_wants_tls(&client).await?;
    let client: BoxedPgStream = if client_is_tls {
        let acceptor = client_acceptor.ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::PermissionDenied,
                "client requested TLS but Proxima TLS termination is disabled",
            )
        })?;
        let mut request = [0u8; 8];
        client.read_exact(&mut request).await?;
        client.write_all(b"S").await?;
        Box::new(accept_client_tls(acceptor, client, client_tls_timeout).await?)
    } else {
        if require_client_tls {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "plaintext PostgreSQL connection rejected because TLS is required",
            ));
        }
        Box::new(client)
    };

    let upstream_tcp = timeout(upstream_connect_timeout, TcpStream::connect(upstream_addr))
        .await
        .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "upstream connection timed out"))??;

    let upstream: BoxedPgStream = if upstream_tls_mode != UpstreamTlsMode::Disable {
        let connector = upstream_connector.ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidInput,
                "upstream TLS connector is not configured",
            )
        })?;
        let server_name = upstream_tls_server_name.ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidInput,
                "upstream TLS server name is required",
            )
        })?;
        let tls = connect_upstream_tls(connector, upstream_tcp, server_name, upstream_tls_timeout)
            .await?;
        Box::new(tls)
    } else {
        Box::new(upstream_tcp)
    };

    let (client, upstream, session) =
        establish(client, upstream, verifier, tenant_role_prefix).await?;

    if let Some(context) = session.tenant_context.as_ref().filter(|c| c.emergency) {
        let node_id = std::env::var("PROXIMA_NODE_ID").unwrap_or_default();
        let nonce_hash = context.emergency_nonce_hash.as_deref().unwrap_or_default();
        if let Err(error) =
            break_glass::record_event(&break_glass::default_outbox_dir(), &node_id, nonce_hash)
                .await
        {
            error!(%error,"emergency session rejected because durable audit could not be written");
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "emergency access requires durable local audit",
            ));
        }
    }
    let session_started_at = Instant::now();
    metrics::global().session_started(session.tenant_context.is_some());
    info!(
        peer = %peer,
        tenant = session
            .tenant_context
            .as_ref()
            .map(|context| context.tenant_id.as_str())
            .unwrap_or("unbound"),
        client_tls = client_is_tls,
        upstream_tls = upstream_tls_mode != UpstreamTlsMode::Disable,
        "PostgreSQL session established"
    );

    let (mut client_reader, mut client_writer) = tokio::io::split(client);
    let (mut upstream_reader, mut upstream_writer) = tokio::io::split(upstream);
    let query_latency = Arc::new(QueryLatencyTracker::default());
    let copy_result = tokio::try_join!(
        copy_frontend_messages(
            &mut client_reader,
            &mut upstream_writer,
            query_latency.clone()
        ),
        copy_backend_messages(&mut upstream_reader, &mut client_writer, query_latency),
    );
    let duration_micros = session_started_at
        .elapsed()
        .as_micros()
        .min(u64::MAX as u128) as u64;
    match copy_result {
        Ok((client_bytes, upstream_bytes)) => {
            metrics::global().session_finished(client_bytes, upstream_bytes, duration_micros);
            info!(
                peer = %peer,
                client_to_database = client_bytes,
                database_to_client = upstream_bytes,
                "connection closed"
            );
            Ok(())
        }
        Err(error) => {
            metrics::global().session_finished(0, 0, duration_micros);
            Err(error)
        }
    }
}

fn peer_fingerprint(peer: std::net::IpAddr) -> String {
    format!("{:x}", Sha256::digest(peer.to_string().as_bytes()))
}

async fn send_security_event(
    client: reqwest::Client,
    url: String,
    token: String,
    node_id: String,
    peer_fingerprint: String,
) {
    let node_id: String = node_id
        .chars()
        .filter(|character| {
            character.is_ascii_alphanumeric() || matches!(character, '-' | '_' | '.')
        })
        .take(128)
        .collect();
    let observed_at = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|duration| duration.as_secs() as i64)
        .unwrap_or_default();
    let body = format!(
        "{{\"node_id\":\"{}\",\"event_type\":\"security.breaker.tripped\",\"severity\":\"critical\",\"peer_fingerprint\":\"{}\",\"reason\":\"Repeated PostgreSQL protocol or tenant-authentication violations\",\"observed_at\":{}}}",
        node_id, peer_fingerprint, observed_at
    );
    match client
        .post(url)
        .bearer_auth(token)
        .header("content-type", "application/json")
        .body(body)
        .send()
        .await
    {
        Ok(response) if response.status().is_success() => {
            info!(status = %response.status(), "security breaker event recorded by control plane");
        }
        Ok(response) => {
            error!(status = %response.status(), "control plane rejected security breaker event")
        }
        Err(error) => error!(%error, "security breaker event delivery failed"),
    }
}

async fn copy_backend_messages<R, W>(
    reader: &mut R,
    writer: &mut W,
    query_latency: Arc<QueryLatencyTracker>,
) -> io::Result<u64>
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    let mut buffer = [0u8; 16 * 1024];
    let mut pending = BytesMut::with_capacity(8 * 1024);
    let mut total = 0u64;
    loop {
        let size = reader.read(&mut buffer).await?;
        if size == 0 {
            writer.shutdown().await?;
            return Ok(total);
        }
        pending.extend_from_slice(&buffer[..size]);
        loop {
            if pending.len() < 5 {
                break;
            }
            let frame_length = i32::from_be_bytes(pending[1..5].try_into().unwrap());
            if frame_length < 4 || frame_length as usize > 16 * 1024 * 1024 {
                pending.clear();
                break;
            }
            let Some(total_length) = (frame_length as usize).checked_add(1) else {
                pending.clear();
                break;
            };
            if pending.len() < total_length {
                break;
            }
            if matches!(pending[0], b'C' | b'I' | b's' | b'E') {
                query_latency.finish_extended();
            } else if pending[0] == b'Z' {
                query_latency.finish_simple();
            }
            pending.advance(total_length);
        }
        if pending.len() > 16 * 1024 * 1024 + 5 {
            pending.clear();
        }
        writer.write_all(&buffer[..size]).await?;
        total = total.saturating_add(size as u64);
    }
}

async fn copy_frontend_messages<R, W>(
    reader: &mut R,
    writer: &mut W,
    query_latency: Arc<QueryLatencyTracker>,
) -> io::Result<u64>
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    let mut buffer = [0u8; 16 * 1024];
    let mut pending = BytesMut::with_capacity(8 * 1024);
    let mut total = 0u64;
    loop {
        let size = reader.read(&mut buffer).await?;
        if size == 0 {
            writer.shutdown().await?;
            return Ok(total);
        }
        pending.extend_from_slice(&buffer[..size]);
        loop {
            if pending.len() < 5 {
                break;
            }
            let frame_length = i32::from_be_bytes(pending[1..5].try_into().unwrap());
            if frame_length < 4 || frame_length as usize > 16 * 1024 * 1024 {
                // Preserve wire behavior: observer failures never mutate or suppress forwarded bytes.
                pending.clear();
                break;
            }
            let Some(total_length) = (frame_length as usize).checked_add(1) else {
                pending.clear();
                break;
            };
            if pending.len() < total_length {
                break;
            }
            if matches!(pending[0], b'Q' | b'E') {
                metrics::global().query_processed();
                query_latency.start(pending[0] == b'Q');
            }
            pending.advance(total_length);
        }
        if pending.len() > 16 * 1024 * 1024 + 5 {
            pending.clear();
        }
        writer.write_all(&buffer[..size]).await?;
        total = total.saturating_add(size as u64);
    }
}

async fn client_wants_tls(client: &TcpStream) -> io::Result<bool> {
    let mut probe = [0u8; 8];
    let n = timeout(std::time::Duration::from_secs(10), async {
        loop {
            let n = client.peek(&mut probe).await?;
            if n >= 8 || n == 0 {
                break Ok::<usize, io::Error>(n);
            }
            tokio::task::yield_now().await;
        }
    })
    .await
    .map_err(|_| {
        io::Error::new(
            io::ErrorKind::TimedOut,
            "waiting for PostgreSQL startup packet timed out",
        )
    })??;

    if n < 8 {
        return Ok(false);
    }

    let length = i32::from_be_bytes(probe[..4].try_into().unwrap());
    let code = i32::from_be_bytes(probe[4..8].try_into().unwrap());
    Ok(length == 8 && code == SSL_REQUEST_CODE)
}

fn breaker_config_enabled() -> bool {
    let mode = std::env::var("PROXIMA_SECURITY_BREAKER")
        .or_else(|_| std::env::var("PROXIMA_SECURITY_CIRCUIT_BREAKER"))
        .unwrap_or_else(|_| "fail-closed".to_string());
    !matches!(
        mode.trim().to_ascii_lowercase().as_str(),
        "off" | "disabled" | "false" | "0"
    )
}

#[cfg(test)]
mod tenant_database_binding_validation_tests {
    use super::validate_tenant_bindings;

    #[test]
    fn accepts_distinct_tenant_namespaces() {
        let record = serde_json::json!({"tenant_bindings":[
            {"tenant_id":"tenant-a","namespace":"tenant_a","status":"active"},
            {"tenant_id":"tenant-b","namespace":"tenant_b","status":"pending"}
        ]});
        assert!(validate_tenant_bindings(&record).is_ok());
    }

    #[test]
    fn rejects_duplicate_tenant_ids_and_namespaces() {
        let duplicate_tenant = serde_json::json!({"tenant_bindings":[
            {"tenant_id":"tenant-a","namespace":"one","status":"active"},
            {"tenant_id":"tenant-a","namespace":"two","status":"active"}
        ]});
        let duplicate_namespace = serde_json::json!({"tenant_bindings":[
            {"tenant_id":"tenant-a","namespace":"shared","status":"active"},
            {"tenant_id":"tenant-b","namespace":"shared","status":"active"}
        ]});
        assert!(validate_tenant_bindings(&duplicate_tenant).is_err());
        assert!(validate_tenant_bindings(&duplicate_namespace).is_err());
    }

    #[test]
    fn rejects_revoked_or_malformed_bindings() {
        let revoked = serde_json::json!({"tenant_bindings":[
            {"tenant_id":"tenant-a","namespace":"one","status":"revoked"}
        ]});
        let malformed = serde_json::json!({"tenant_bindings":[
            {"tenant_id":"tenant-a","namespace":"../escape","status":"active"}
        ]});
        assert!(validate_tenant_bindings(&revoked).is_err());
        assert!(validate_tenant_bindings(&malformed).is_err());
    }
}

#[cfg(test)]
mod attestation_ingest_url_tests {
    use super::attestation_ingest_url_allowed;

    #[test]
    fn accepts_https_without_insecure_opt_in() {
        assert!(attestation_ingest_url_allowed(
            "https://control.example.com/api/v1/attestations",
            false
        ));
    }

    #[test]
    fn accepts_loopback_http_for_local_development() {
        assert!(attestation_ingest_url_allowed(
            "http://127.0.0.1:8080/api/v1/attestations",
            false
        ));
        assert!(attestation_ingest_url_allowed(
            "http://localhost:8080/api/v1/attestations",
            false
        ));
    }

    #[test]
    fn docker_service_http_requires_explicit_opt_in() {
        assert!(!attestation_ingest_url_allowed(
            "http://proxima-control:8080/api/v1/attestations",
            false
        ));
        assert!(attestation_ingest_url_allowed(
            "http://proxima-control:8080/api/v1/attestations",
            true
        ));
    }

    #[test]
    fn rejects_arbitrary_plain_http_even_with_opt_in() {
        assert!(!attestation_ingest_url_allowed(
            "http://attacker.example/api/v1/attestations",
            true
        ));
        assert!(!attestation_ingest_url_allowed(
            "ftp://localhost/file",
            true
        ));
        assert!(!attestation_ingest_url_allowed("not-a-url", true));
    }
}
#[cfg(test)]
mod node_heartbeat_signature_tests {
    use super::{sign_node_heartbeat, sign_node_heartbeat_v2};

    #[test]
    fn heartbeat_signature_is_deterministic_for_the_same_payload() {
        let key = [7u8; 32];
        let first = sign_node_heartbeat(&key, "node-a", "org-a", 1_800_000_000, "0.1.0", "running")
            .unwrap();
        let second =
            sign_node_heartbeat(&key, "node-a", "org-a", 1_800_000_000, "0.1.0", "running")
                .unwrap();
        assert_eq!(first, second);
        assert_eq!(first.len(), 64);
    }

    #[test]
    fn capability_report_is_signed_and_bound_to_node_and_artifact() {
        let key = [9u8; 32];
        let providers = vec!["cockroachdb".to_owned(), "postgresql".to_owned()];
        let capabilities = serde_json::json!({"engine_version":"0.1.0","postgresql_wire":true});
        let signature = sign_node_heartbeat_v2(
            &key,
            "node-a",
            "org-a",
            1_800_000_000,
            "0.1.0",
            "running",
            &providers,
            &capabilities,
            Some("sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"),
        )
        .unwrap();
        let changed = sign_node_heartbeat_v2(
            &key,
            "node-a",
            "org-a",
            1_800_000_000,
            "0.1.0",
            "running",
            &providers,
            &capabilities,
            Some("sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"),
        )
        .unwrap();
        let changed_provider = sign_node_heartbeat_v2(
            &key,
            "node-a",
            "org-a",
            1_800_000_000,
            "0.1.0",
            "running",
            &["cockroachdb".to_owned()],
            &capabilities,
            Some("sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"),
        )
        .unwrap();
        assert_ne!(signature, changed);
        assert_ne!(signature, changed_provider);
    }

    fn heartbeat_signature_changes_when_signed_fields_change() {
        let key = [7u8; 32];
        let baseline =
            sign_node_heartbeat(&key, "node-a", "org-a", 1_800_000_000, "0.1.0", "running")
                .unwrap();
        let other_node =
            sign_node_heartbeat(&key, "node-b", "org-a", 1_800_000_000, "0.1.0", "running")
                .unwrap();
        let other_time =
            sign_node_heartbeat(&key, "node-a", "org-a", 1_800_000_001, "0.1.0", "running")
                .unwrap();
        assert_ne!(baseline, other_node);
        assert_ne!(baseline, other_time);
    }
}
