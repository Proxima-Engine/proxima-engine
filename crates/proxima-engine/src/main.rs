mod canary_probe;

use bytes::{Buf, BytesMut};
use std::io;
use std::sync::Arc;

use hmac::Mac;
use proxima_engine::{
    attestation::{AttestationConfig, AttestationLedger, SecurityState, TelemetrySummary},
    break_glass,
    config::{Config, UpstreamTlsMode},
    dashboard,
    metrics::{self, QueryLatencyTracker},
    protocol::SSL_REQUEST_CODE,
    security_breaker::{BreakerConfig, SecurityBreaker},
    session::{establish, BoxedPgStream},
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
    use std::{env, fs, path::PathBuf};

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

        std::env::set_var("PROXIMA_NODE_ID", node_id);
        std::env::set_var("PROXIMA_ORGANIZATION_ID", organization_id);
        std::env::set_var("PROXIMA_NODE_SIGNING_KEY_HEX", key);
        Ok(())
    }

    if env::var("PROXIMA_NODE_SIGNING_KEY_HEX")
        .ok()
        .and_then(|key| hex::decode(key).ok())
        .is_some_and(|key| key.len() == 32)
    {
        return Ok(());
    }

    if identity_path.is_file() {
        let bytes = fs::read(&identity_path)?;
        let identity: serde_json::Value = serde_json::from_slice(&bytes)?;
        apply_identity(&identity)?;
        return Ok(());
    }

    let url = env::var("PROXIMA_NODE_ENROLLMENT_URL").ok();
    let token = env::var("PROXIMA_NODE_ENROLLMENT_TOKEN").ok();
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

    // Validate the complete identity before persisting it.
    let key = identity["signing_key"]
        .as_str()
        .ok_or("Enrollment response is missing signing_key")?;
    if hex::decode(key)?.len() != 32 {
        return Err("Enrollment returned an invalid signing key".into());
    }
    let _ = identity["organization_id"]
        .as_str()
        .ok_or("Enrollment response is missing organization_id")?;
    let _ = identity["node_id"]
        .as_str()
        .ok_or("Enrollment response is missing node_id")?;

    let parent = identity_path.parent().ok_or("Invalid node identity path")?;
    fs::create_dir_all(parent)?;

    let temporary_path = identity_path.with_extension("json.tmp");
    fs::write(&temporary_path, serde_json::to_vec_pretty(&identity)?)?;
    fs::rename(&temporary_path, &identity_path)?;

    apply_identity(&identity)?;
    env::remove_var("PROXIMA_NODE_ENROLLMENT_TOKEN");

    eprintln!("Engine node identity loaded successfully.");
    Ok(())
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

    let config = Config::from_env()?;
    let config_tenant_role_prefix = config.tenant_role_prefix.clone();

    let verifier = config
        .tenant_signing_key
        .as_deref()
        .map(TenantTokenVerifier::new)
        .transpose()
        .map_err(|error| io::Error::new(io::ErrorKind::InvalidInput, error.to_string()))?;

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
    if let Err(error) = bootstrap_node_identity().await {
        eprintln!("Engine node bootstrap failed: {error}");
        std::process::exit(1);
    }

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
                        let signature = match sign_node_heartbeat(
                            &signing_key,
                            &node_id,
                            &organization_id,
                            timestamp,
                            &version,
                            runtime_status,
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
    use super::sign_node_heartbeat;

    #[test]
    fn heartbeat_signature_is_deterministic_for_the_same_payload() {
        let key = [7u8; 32];
        let first = sign_node_heartbeat(
            &key,
            "node-a",
            "org-a",
            1_800_000_000,
            "0.1.0",
            "running",
        )
        .unwrap();
        let second = sign_node_heartbeat(
            &key,
            "node-a",
            "org-a",
            1_800_000_000,
            "0.1.0",
            "running",
        )
        .unwrap();
        assert_eq!(first, second);
        assert_eq!(first.len(), 64);
    }

    #[test]
    fn heartbeat_signature_changes_when_signed_fields_change() {
        let key = [7u8; 32];
        let baseline = sign_node_heartbeat(
            &key,
            "node-a",
            "org-a",
            1_800_000_000,
            "0.1.0",
            "running",
        )
        .unwrap();
        let other_node = sign_node_heartbeat(
            &key,
            "node-b",
            "org-a",
            1_800_000_000,
            "0.1.0",
            "running",
        )
        .unwrap();
        let other_time = sign_node_heartbeat(
            &key,
            "node-a",
            "org-a",
            1_800_000_001,
            "0.1.0",
            "running",
        )
        .unwrap();
        assert_ne!(baseline, other_node);
        assert_ne!(baseline, other_time);
    }

}
