//! Native Redis ACL and key-pattern discovery adapter.
//! Catalog discovery is TLS-only and always fails closed for tenant admission.

use crate::database_adapter::{
    AdapterError, AdapterFuture, AdapterTarget, CompiledPolicy, DatabaseAdapter,
    DiscoveryRequest, DiscoverySnapshot, DiscoveredResource, DriftReport,
    InspectionRequest, InspectionSnapshot, ResourceInspection,
};
use crate::native_policy_plans::compile_redis_acl;
use crate::security_core::{
    AdapterCapabilities, AdapterDescriptor, AdapterMaturity, DatabaseKind,
    InspectionCompleteness, Operation, ResourceKind, ResourceRef, SecurityFinding,
    SecurityPosture, TenantSecurityPolicy, VerificationReport, SECURITY_MODEL_VERSION,
};
use redis::{aio::MultiplexedConnection, Client};
use serde_json::json;
use sha2::{Digest, Sha256};
use std::time::Duration;

pub struct RedisCatalogAdapter {
    target_id: String,
    database_index: u32,
    connection_uri: String,
}

impl RedisCatalogAdapter {
    pub fn new(target_id: impl Into<String>, database_index: u32, connection_uri: impl Into<String>) -> Result<Self, AdapterError> {
        let target_id = target_id.into();
        let connection_uri = connection_uri.into();
        if target_id.trim().is_empty() || target_id.len() > 256 || target_id.contains('\0')
            || connection_uri.trim().is_empty() || connection_uri.len() > 4096 {
            return Err(error("invalid_redis_target", "A bounded target ID and Redis connection URI are required."));
        }
        if !connection_uri.to_ascii_lowercase().starts_with("rediss://") {
            return Err(error("redis_tls_required", "Redis catalog connections must use rediss:// with certificate and hostname verification."));
        }
        Client::open(connection_uri.as_str())
            .map_err(|_| error("invalid_redis_connection_config", "The Redis TLS connection URI could not be parsed."))?;
        Ok(Self { target_id, database_index, connection_uri })
    }

    fn validate_target(&self, target: &AdapterTarget) -> Result<(), AdapterError> {
        if target.target_id != self.target_id || target.database_name != self.database_index.to_string() {
            return Err(error("redis_target_mismatch", "The request does not match this adapter's registered Redis target and database index."));
        }
        Ok(())
    }

    async fn connect_checked(&self) -> Result<MultiplexedConnection, AdapterError> {
        let client = Client::open(self.connection_uri.as_str())
            .map_err(|_| error("invalid_redis_connection_config", "The Redis TLS connection URI could not be parsed."))?;
        let mut connection = tokio::time::timeout(Duration::from_secs(10), client.get_multiplexed_async_connection())
            .await.map_err(|_| error("redis_connection_timeout", "Redis connection exceeded the ten-second deadline."))?
            .map_err(db_error)?;
        let client_info = redis::cmd("CLIENT").arg("INFO").query_async::<String>(&mut connection).await.map_err(db_error)?;
        let selected_db = client_info.split_whitespace().find_map(|field| field.strip_prefix("db="))
            .and_then(|value| value.parse::<u32>().ok())
            .ok_or_else(|| error("redis_database_identity_unavailable", "Redis CLIENT INFO did not expose a numeric database index."))?;
        if selected_db != self.database_index {
            return Err(error("redis_database_mismatch", "The authenticated Redis connection selected a different logical database."));
        }
        let pong = redis::cmd("PING").query_async::<String>(&mut connection).await.map_err(db_error)?;
        if !pong.eq_ignore_ascii_case("PONG") {
            return Err(error("redis_ping_failed", "Redis did not return PONG for the authenticated connection."));
        }
        Ok(connection)
    }

    async fn discover_inner(&self, request: &DiscoveryRequest) -> Result<DiscoverySnapshot, AdapterError> {
        self.validate_target(&request.target)?;
        if request.namespace.as_ref().is_some_and(|namespace| namespace != &self.database_index.to_string()) {
            return Err(error("invalid_discovery_namespace", "Redis namespace must be the registered logical database index."));
        }
        let mut connection = self.connect_checked().await?;
        let whoami = redis::cmd("ACL").arg("WHOAMI").query_async::<String>(&mut connection).await.map_err(db_error)?;
        let acl_lines = redis::cmd("ACL").arg("LIST").query_async::<Vec<String>>(&mut connection).await.map_err(db_error)?;
        let acl_rule_count = acl_lines.len();
        let acl_inventory_truncated = acl_rule_count > 10_000;
        let acl_digest = digest(&serde_json::to_vec(&acl_lines).map_err(|_| error("redis_acl_serialization_failed", "Could not serialize Redis ACL rules."))?);
        let acl_lines = acl_lines.into_iter().take(10_000).collect::<Vec<_>>();
        let categories = redis::cmd("ACL").arg("CAT").query_async::<Vec<String>>(&mut connection).await.map_err(db_error)?;
        let server_info = redis::cmd("INFO").arg("server").query_async::<String>(&mut connection).await.map_err(db_error)?;
        let keyspace_info = redis::cmd("INFO").arg("keyspace").query_async::<String>(&mut connection).await.map_err(db_error)?;
        let mut resources = Vec::new();
        let mut broad_users = Vec::new();
        let mut resource_inventory_truncated = false;
        'acl_users: for line in &acl_lines {
            let Some((username, tokens)) = parse_acl_line(line) else { continue };
            let patterns = tokens.iter().filter_map(|token| {
                if let Some(pattern) = token.strip_prefix("%R~") {
                    Some((pattern.to_owned(), "read"))
                } else if let Some(pattern) = token.strip_prefix("%W~") {
                    Some((pattern.to_owned(), "write"))
                } else if let Some(pattern) = token.strip_prefix('~') {
                    Some((pattern.to_owned(), "read_write"))
                } else if token == "allkeys" {
                    Some(("*".into(), "read_write"))
                } else {
                    None
                }
            }).collect::<Vec<_>>();
            let command_rules = tokens.iter().filter(|token| token.starts_with('+') || token.starts_with('-')).cloned().collect::<Vec<_>>();
            let channel_rules = tokens.iter().filter(|token| token.starts_with('&')).cloned().collect::<Vec<_>>();
            for (pattern, pattern_mode) in patterns {
                if pattern == "*" || pattern == "**" { broad_users.push(username.to_owned()); }
                resources.push(DiscoveredResource {
                    namespace: Some(self.database_index.to_string()),
                    name: pattern.clone(),
                    kind: ResourceKind::Keyspace,
                    owner: Some(username.to_owned()),
                    attributes: json!({
                        "acl_username": username,
                        "key_pattern": pattern,
                        "key_pattern_mode": pattern_mode,
                        "command_rules": command_rules,
                        "channel_rules": channel_rules,
                        "user_flags": tokens.iter().filter(|token| !token.starts_with('#') && !token.starts_with('>') && !token.starts_with('~') && !token.starts_with('&') && !token.starts_with('%') && !token.starts_with('+') && !token.starts_with('-')).cloned().collect::<Vec<_>>()
                    }),
                });
            }
        }
        let sanitized_acl = acl_lines.iter().map(|line| sanitize_acl_line(line)).collect::<Vec<_>>();
        let target_attributes = json!({
            "database_index": self.database_index,
            "authenticated_acl_user": whoami,
            "server_version": info_field(&server_info, "redis_version").unwrap_or_else(|| "unknown".into()),
            "server_info": server_info,
            "keyspace_info": keyspace_info,
            "acl_users": sanitized_acl,
            "acl_categories": categories,
            "acl_rule_fingerprint": acl_digest,
            "acl_rule_count": acl_rule_count,
            "acl_inventory_truncated": acl_inventory_truncated,
            "resource_inventory_truncated": resource_inventory_truncated,
            "tls_certificate_and_hostname_verification_required": true
        });
        let fingerprint = digest(&serde_json::to_vec(&json!({"database_index":self.database_index,"target":target_attributes,"resources":resources}))
            .map_err(|_| error("fingerprint_serialization_failed", "Could not serialize Redis discovery results."))?);
        let mut findings = vec![SecurityFinding {
            code: "redis_keyspace_inventory_is_acl_scoped".into(),
            resource: None,
            detail: "Discovery inventories ACL key patterns and command rules. It does not enumerate all stored keys or prove every application operation is tenant-bound.".into(),
        }];
        if acl_inventory_truncated || resource_inventory_truncated {
            findings.push(SecurityFinding {
                code: "redis_acl_inventory_truncated".into(),
                resource: None,
                detail: "Redis ACL or key-pattern inventory exceeded the 10,000-user or 50,000-pattern safety bound; the displayed inventory is bounded and cannot be treated as complete.".into(),
            });
        }
        if !broad_users.is_empty() {
            broad_users.sort();
            broad_users.dedup();
            findings.push(SecurityFinding {
                code: "redis_acl_unrestricted_key_pattern".into(),
                resource: None,
                detail: format!("Redis ACL users have unrestricted key access: {}. Replace wildcard access with tenant-specific patterns.", broad_users.join(", ")),
            });
        }
        Ok(DiscoverySnapshot {
            database_kind: DatabaseKind::Redis,
            target: request.target.clone(),
            completeness: InspectionCompleteness::Incomplete,
            target_attributes,
            resources,
            findings,
            fingerprint: Some(fingerprint),
            observed_at: chrono::Utc::now().to_rfc3339(),
        })
    }
}

impl DatabaseAdapter for RedisCatalogAdapter {
    fn descriptor(&self) -> AdapterDescriptor {
        AdapterDescriptor {
            kind: DatabaseKind::Redis,
            name: "Redis ACL adapter",
            maturity: AdapterMaturity::InDevelopment,
            capabilities: AdapterCapabilities { schema_inspection: true, policy_generation: true, drift_detection: true, ..AdapterCapabilities::default() },
            status_note: "TLS-verified ACL users, command rules, key patterns and keyspace metadata are inspected. Runtime tenant binding, keyless-command mediation, semantic probes, controlled ACL deployment and signed admission are not implemented.",
        }
    }

    fn discover<'a>(&'a self, request: &'a DiscoveryRequest) -> AdapterFuture<'a, Result<DiscoverySnapshot, AdapterError>> {
        Box::pin(async move { self.discover_inner(request).await })
    }

    fn inspect<'a>(&'a self, request: &'a InspectionRequest) -> AdapterFuture<'a, Result<InspectionSnapshot, AdapterError>> {
        Box::pin(async move {
            self.validate_target(&request.target)?;
            request.policy.validate().map_err(|_| error("invalid_policy", "The canonical tenant policy failed validation."))?;
            let discovery = self.discover_inner(&DiscoveryRequest { target: request.target.clone(), namespace: None }).await?;
            let mut findings = discovery.findings.clone();
            let mut resources = Vec::with_capacity(request.policy.resources.len());
            let placeholder = concat!("$", "{tenant_id}");
            for protected in &request.policy.resources {
                if !matches!(protected.resource.kind, ResourceKind::Keyspace | ResourceKind::Table) {
                    return Err(error("unsupported_redis_resource_kind", "Redis policies must target a keyspace or logical key collection."));
                }
                if protected.operations.contains(&Operation::Execute) {
                    return Err(error("unsupported_redis_execute_operation", "Redis script and function execution requires a separate native command policy."));
                }
                let Some((prefix, suffix)) = protected.tenant_key.split_once(placeholder) else {
                    return Err(error("redis_tenant_key_pattern_required", "Redis policy key patterns must contain a tenant placeholder."));
                };
                if protected.tenant_key.matches(placeholder).count() != 1 {
                    return Err(error("unsafe_redis_tenant_pattern", "Redis policy key patterns must contain exactly one tenant placeholder."));
                }
                let matching: Vec<_> = discovery.resources.iter().filter(|resource| {
                    resource.name.starts_with(prefix) && resource.name.ends_with(suffix) && resource.owner.is_some()
                }).collect();
                let mut resource_findings = Vec::new();
                if matching.is_empty() {
                    resource_findings.push(finding("redis_tenant_key_pattern_not_registered", &protected.resource, "No Redis ACL user currently exposes a key pattern matching the registered tenant key template."));
                }
                if discovery.resources.iter().any(|resource| resource.name == "*" || resource.name == "**") {
                    resource_findings.push(finding("redis_unrestricted_key_pattern", &protected.resource, "At least one Redis ACL user has unrestricted key access."));
                }
                let needs_read_scope = protected.operations.contains(&Operation::Read);
                let needs_write_scope = protected.operations.iter().any(|operation| matches!(operation, Operation::Create | Operation::Update | Operation::Delete));
                let key_scope_coverage = matching.iter().any(|resource| {
                    let Some(owner) = resource.owner.as_deref() else { return false };
                    let same_user = matching.iter().filter(|other| other.owner.as_deref() == Some(owner));
                    let mut read_scope = false;
                    let mut write_scope = false;
                    for candidate in same_user {
                        match candidate.attributes["key_pattern_mode"].as_str() {
                            Some("read_write") => { read_scope = true; write_scope = true; }
                            Some("read") => read_scope = true,
                            Some("write") => write_scope = true,
                            _ => {}
                        }
                    }
                    (!needs_read_scope || read_scope) && (!needs_write_scope || write_scope)
                });
                if !key_scope_coverage {
                    resource_findings.push(finding("redis_acl_key_scope_incomplete", &protected.resource, "No single ACL user has key-pattern permissions covering every read and write scope required by this policy."));
                }
                let required_commands = required_commands(&protected.operations);
                let explicit_command_coverage = matching.iter().any(|resource| {
                    let rules = resource.attributes["command_rules"].as_array();
                    rules.is_some_and(|rules| {
                        required_commands.iter().all(|command| rules.iter().any(|rule| rule.as_str().is_some_and(|value| value == format!("+{command}"))))
                            && !rules.iter().filter_map(|rule| rule.as_str()).any(|rule| rule.starts_with("-@") || required_commands.iter().any(|command| rule == format!("-{command}").as_str()))
                    })
                });
                if !explicit_command_coverage {
                    resource_findings.push(finding("redis_acl_command_coverage_incomplete", &protected.resource, "No single tenant ACL user explicitly grants every command required by this policy; command categories are not treated as proof of least-privilege coverage."));
                }
                if matching.iter().any(|resource| resource.attributes["command_rules"].as_array().is_some_and(|rules| {
                    rules.iter().filter_map(|rule| rule.as_str()).any(|rule| matches!(rule, "+@all" | "+@write" | "+@admin"))
                })) {
                    resource_findings.push(finding("redis_acl_broad_command_category", &protected.resource, "A matching ACL user grants a broad command category; review and replace category grants with an explicit command allowlist."));
                }
                resource_findings.push(finding("redis_tenant_operation_probe_required", &protected.resource, "ACL inspection cannot prove that scripts, functions, modules and keyless commands respect tenant boundaries."));
                let resource_fingerprint = digest(&serde_json::to_vec(&matching.iter().map(|resource| &resource.attributes).collect::<Vec<_>>())
                    .map_err(|_| error("fingerprint_serialization_failed", "Could not serialize Redis ACL resource metadata."))?);
                findings.extend(resource_findings.clone());
                resources.push(ResourceInspection {
                    resource: protected.clone(),
                    completeness: InspectionCompleteness::Incomplete,
                    posture: SecurityPosture::NeedsAttention,
                    verified_operations: Vec::new(),
                    findings: resource_findings,
                    fingerprint: Some(resource_fingerprint),
                });
            }
            Ok(InspectionSnapshot {
                database_kind: DatabaseKind::Redis,
                target: request.target.clone(),
                completeness: discovery.completeness,
                posture: SecurityPosture::NeedsAttention,
                resources,
                findings,
                fingerprint: discovery.fingerprint,
                observed_at: discovery.observed_at,
            })
        })
    }

    fn compile_policy(&self, policy: &TenantSecurityPolicy) -> Result<CompiledPolicy, AdapterError> { compile_redis_acl(policy) }

    fn verify<'a>(&'a self, policy: &'a TenantSecurityPolicy, snapshot: &'a InspectionSnapshot) -> AdapterFuture<'a, Result<VerificationReport, AdapterError>> {
        Box::pin(async move {
            if snapshot.database_kind != DatabaseKind::Redis || snapshot.target.target_id != self.target_id
                || snapshot.target.database_name != self.database_index.to_string() {
                return Err(error("redis_snapshot_target_mismatch", "The inspection snapshot does not belong to this Redis adapter target."));
            }
            let mut findings = snapshot.findings.clone();
            findings.push(SecurityFinding {
                code: "independent_tenant_probes_required".into(),
                resource: None,
                detail: format!("{} protected keyspaces require own-tenant allow and cross-tenant deny probes across every declared command.", policy.resources.len()),
            });
            findings.push(SecurityFinding {
                code: "redis_runtime_tenant_binding_unavailable".into(),
                resource: None,
                detail: "No trusted Redis protocol gateway binds authenticated tenant identity to the matching ACL user and mediates keyless commands.".into(),
            });
            Ok(VerificationReport { model_version: SECURITY_MODEL_VERSION.into(), posture: SecurityPosture::Blocked, inspection: snapshot.completeness, findings })
        })
    }

    fn detect_drift<'a>(&'a self, target: &'a AdapterTarget, previous_fingerprint: Option<&'a str>) -> AdapterFuture<'a, Result<DriftReport, AdapterError>> {
        Box::pin(async move {
            self.validate_target(target)?;
            if previous_fingerprint.is_some_and(|value| value.len() != 64 || hex::decode(value).map_or(true, |bytes| bytes.len() != 32)) {
                return Err(error("invalid_previous_fingerprint", "The previous fingerprint must be a 32-byte hexadecimal SHA-256 digest."));
            }
            let snapshot = self.discover_inner(&DiscoveryRequest { target: target.clone(), namespace: None }).await?;
            Ok(DriftReport {
                database_kind: DatabaseKind::Redis,
                target: target.clone(),
                detected: previous_fingerprint.is_some_and(|previous| Some(previous) != snapshot.fingerprint.as_deref()),
                completeness: snapshot.completeness,
                previous_fingerprint: previous_fingerprint.map(str::to_owned),
                observed_fingerprint: snapshot.fingerprint,
                findings: snapshot.findings,
                observed_at: snapshot.observed_at,
            })
        })
    }
}

fn required_commands(operations: &[Operation]) -> Vec<&'static str> {
    let mut commands = Vec::new();
    for operation in operations {
        let required: &[&str] = match operation {
            Operation::Read => &["get","mget","exists","ttl","pttl","type","strlen","getrange","hget","hmget","hgetall","hexists","hlen","lrange","llen","lindex","scard","smembers","sismember","zrange","zscore","zcard","xrange","xlen"],
            Operation::Create => &["set","mset","hset","lpush","rpush","sadd","zadd","xadd"],
            Operation::Update => &["set","mset","expire","pexpire","persist","incr","decr","hset","lpush","rpush","sadd","zadd","xadd"],
            Operation::Delete => &["del","unlink","hdel","lpop","rpop","srem","zrem","xdel"],
            Operation::Execute => &[],
        };
        commands.extend_from_slice(required);
    }
    commands.sort_unstable();
    commands.dedup();
    commands
}

fn parse_acl_line(line: &str) -> Option<(&str, Vec<String>)> {
    let mut parts = line.split_whitespace();
    if parts.next()? != "user" { return None; }
    Some((parts.next()?, parts.map(str::to_owned).collect()))
}

fn sanitize_acl_line(line: &str) -> String {
    line.split_whitespace().map(|token| if token.starts_with('#') || token.starts_with('>') {
        "<credential-redacted>"
    } else { token }).collect::<Vec<_>>().join(" ")
}

fn info_field(info: &str, key: &str) -> Option<String> {
    info.lines().find_map(|line| line.strip_prefix(&format!("{key}:")).map(str::to_owned))
}

fn finding(code: &str, resource: &ResourceRef, detail: &str) -> SecurityFinding {
    SecurityFinding { code: code.into(), resource: Some(resource.clone()), detail: detail.into() }
}

fn digest(bytes: &[u8]) -> String {
    let mut hash = Sha256::new();
    hash.update(bytes);
    hex::encode(hash.finalize())
}

fn error(code: &str, detail: &str) -> AdapterError {
    AdapterError { code: code.into(), detail: detail.into(), retryable: false }
}

fn db_error(error: redis::RedisError) -> AdapterError {
    AdapterError {
        code: "redis_catalog_command_failed".into(),
        detail: "The authenticated Redis ACL/catalog command failed; grant the inspection principal the required read-only ACL commands.".into(),
        retryable: error.is_io_error() || error.is_timeout(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn requires_tls_and_validates_target() {
        assert!(RedisCatalogAdapter::new("target", 0, "redis://localhost/0").is_err());
        assert!(RedisCatalogAdapter::new("target", 0, "rediss://localhost/0").is_ok());
        assert!(RedisCatalogAdapter::new("", 0, "rediss://localhost/0").is_err());
    }

    #[test]
    fn parses_acl_key_patterns_and_sanitizes_credentials() {
        let line = "user tenant-a on #secret-hash ~tenant:tenant-a:* +get +set";
        let (username, tokens) = parse_acl_line(line).unwrap();
        assert_eq!(username, "tenant-a");
        assert!(tokens.iter().any(|token| token == "~tenant:tenant-a:*"));
        let sanitized = sanitize_acl_line(line);
        assert!(!sanitized.contains("secret-hash"));
        assert!(sanitized.contains("<credential-redacted>"));
    }

    #[test]
    fn parses_read_only_and_write_only_key_patterns_separately() {
        let (_, read_tokens) = parse_acl_line("user reader on %R~tenant:* +get").unwrap();
        let (_, write_tokens) = parse_acl_line("user writer on %W~tenant:* +set").unwrap();
        assert!(read_tokens.iter().any(|token| token == "%R~tenant:*"));
        assert!(write_tokens.iter().any(|token| token == "%W~tenant:*"));
    }

    #[test]
    fn maps_policy_operations_to_explicit_redis_commands() {
        let commands = required_commands(&[Operation::Read, Operation::Delete]);
        assert!(commands.contains(&"get"));
        assert!(commands.contains(&"del"));
        assert!(!commands.contains(&"set"));
    }

    #[test]
    fn rejects_target_database_index_mismatch_without_connecting() {
        let adapter = RedisCatalogAdapter::new("target", 2, "rediss://localhost/2").unwrap();
        let request = DiscoveryRequest {
            target: AdapterTarget { target_id: "target".into(), database_name: "1".into(), namespace: None },
            namespace: None,
        };
        assert_eq!(adapter.validate_target(&request.target).unwrap_err().code, "redis_target_mismatch");
    }
}
