//! Elasticsearch / OpenSearch native index and security-role discovery.
//!
//! This adapter inspects index mappings/settings and security role/user
//! assignments over verified HTTPS. It does not deploy DLS/FLS policies or
//! claim tenant enforcement; document isolation requires trusted principal
//! binding and independent cross-tenant probes.
use crate::database_adapter::{
    AdapterError, AdapterFuture, AdapterTarget, CompiledPolicy, DatabaseAdapter,
    DiscoveryRequest, DiscoverySnapshot, DiscoveredResource, DriftReport,
    InspectionRequest, InspectionSnapshot, ResourceInspection,
};
use crate::security_core::{
    AdapterCapabilities, AdapterDescriptor, AdapterMaturity, DatabaseKind,
    InspectionCompleteness, Operation, ResourceKind, ResourceRef, SecurityFinding,
    SecurityPosture, TenantSecurityPolicy, VerificationReport, SECURITY_MODEL_VERSION,
};
use reqwest::{header::{HeaderMap, HeaderValue, AUTHORIZATION}, redirect::Policy, Client, Url};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::{str::FromStr, time::Duration};

pub struct ElasticsearchCatalogAdapter {
    target_id: String,
    index_pattern: String,
    endpoint: Url,
    client: Client,
}

impl ElasticsearchCatalogAdapter {
    pub fn new(
        target_id: impl Into<String>,
        index_pattern: impl Into<String>,
        endpoint: impl AsRef<str>,
        authorization: impl AsRef<str>,
    ) -> Result<Self, AdapterError> {
        let target_id = target_id.into();
        let index_pattern = index_pattern.into();
        if target_id.trim().is_empty() || target_id.len() > 256 || target_id.contains('\0')
            || index_pattern.trim().is_empty() || index_pattern.len() > 255
            || index_pattern.contains('\0') || index_pattern.contains('/') || index_pattern.contains('\\')
            || !index_pattern.bytes().all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || matches!(byte, b'-' | b'_' | b'.' | b'*'))
        {
            return Err(error("invalid_elasticsearch_target", "A bounded target ID and index pattern are required."));
        }
        let endpoint = Url::parse(endpoint.as_ref())
            .map_err(|_| error("invalid_elasticsearch_endpoint", "The Elasticsearch endpoint URL could not be parsed."))?;
        if endpoint.scheme() != "https" || endpoint.host_str().is_none()
            || !endpoint.username().is_empty() || endpoint.password().is_some()
            || endpoint.query().is_some() || endpoint.fragment().is_some() || endpoint.path() != "/"
        {
            return Err(error("elasticsearch_tls_required", "Elasticsearch/OpenSearch requires an HTTPS endpoint with no embedded credentials, query parameters or fragment."));
        }
        let auth = authorization.as_ref().trim();
        if !(auth.starts_with("ApiKey ") || auth.starts_with("Bearer ") || auth.starts_with("Basic ")) || auth.len() > 8192 {
            return Err(error("invalid_elasticsearch_auth_header", "Supply an Authorization header using ApiKey, Bearer or Basic authentication."));
        }
        let auth_value = HeaderValue::from_str(auth)
            .map_err(|_| error("invalid_elasticsearch_auth_header", "The Authorization header contains invalid HTTP header bytes."))?;
        let mut headers = HeaderMap::new();
        headers.insert(AUTHORIZATION, auth_value);
        let client = Client::builder()
            .default_headers(headers)
            .connect_timeout(Duration::from_secs(10))
            .timeout(Duration::from_secs(15))
            .redirect(Policy::none())
            .user_agent("Agata-Proxima-Security-Discovery/1")
            .build()
            .map_err(|_| error("elasticsearch_http_client_failed", "The HTTPS discovery client could not be initialized."))?;
        Ok(Self { target_id, index_pattern, endpoint, client })
    }

    fn validate_target(&self, target: &AdapterTarget) -> Result<(), AdapterError> {
        if target.target_id != self.target_id || target.database_name != self.index_pattern {
            return Err(error("elasticsearch_target_mismatch", "The request does not match this registered endpoint and index-pattern target."));
        }
        Ok(())
    }

    fn url_for(&self, segments: &[&str]) -> Result<Url, AdapterError> {
        let mut url = self.endpoint.clone();
        {
            let mut path = url.path_segments_mut()
                .map_err(|_| error("invalid_elasticsearch_endpoint", "The endpoint cannot accept API path segments."))?;
            path.clear();
            for segment in segments { path.push(segment); }
        }
        Ok(url)
    }

    async fn get_json(&self, url: Url) -> Result<Value, AdapterError> {
        let response = self.client.get(url).send().await.map_err(http_error)?;
        if !response.status().is_success() {
            return Err(AdapterError {
                code: "elasticsearch_api_rejected".into(),
                detail: format!("Elasticsearch/OpenSearch API returned HTTP {}.", response.status().as_u16()),
                retryable: response.status().is_server_error() || response.status().as_u16() == 429,
            });
        }
        response.json::<Value>().await.map_err(|_| error("elasticsearch_invalid_json", "The Elasticsearch/OpenSearch API returned invalid JSON."))
    }

    async fn get_optional_json(&self, url: Url) -> Result<Option<Value>, AdapterError> {
        let response = self.client.get(url).send().await.map_err(http_error)?;
        if matches!(response.status().as_u16(), 401 | 403 | 404) { return Ok(None); }
        if !response.status().is_success() {
            return Err(AdapterError {
                code: "elasticsearch_security_api_rejected".into(),
                detail: format!("Elasticsearch/OpenSearch security API returned HTTP {}.", response.status().as_u16()),
                retryable: response.status().is_server_error() || response.status().as_u16() == 429,
            });
        }
        response.json::<Value>().await.map(Some)
            .map_err(|_| error("elasticsearch_invalid_json", "The security API returned invalid JSON."))
    }

    async fn discover_inner(&self, request: &DiscoveryRequest) -> Result<DiscoverySnapshot, AdapterError> {
        self.validate_target(&request.target)?;
        if request.namespace.is_some() {
            return Err(error("elasticsearch_namespace_unsupported", "Use the registered index pattern as the target namespace."));
        }
        let root = self.get_json(self.url_for(&[])?).await?;
        let version = root.pointer("/version/number").and_then(Value::as_str).unwrap_or("unknown").to_owned();
        let tagline = root.get("tagline").and_then(Value::as_str).unwrap_or_default();
        let distribution = root.pointer("/version/distribution").and_then(Value::as_str).unwrap_or_default();
        let is_opensearch = distribution.eq_ignore_ascii_case("opensearch") || tagline.to_ascii_lowercase().contains("opensearch");
        let kind = if is_opensearch {
            DatabaseKind::Elasticsearch
        } else if root.get("version").is_some() {
            DatabaseKind::Elasticsearch
        } else {
            return Err(error("elasticsearch_server_identity_unavailable", "The endpoint did not return a recognized Elasticsearch/OpenSearch root response."));
        };
        let cat_url = self.url_for(&["_cat", "indices"])?;
        let mut cat_url = cat_url;
        cat_url.query_pairs_mut().append_pair("format", "json").append_pair("h", "index,health,status,docs.count,store.size");
        let cat = self.get_json(cat_url).await?;
        let index_rows = cat.as_array().ok_or_else(|| error("elasticsearch_index_inventory_invalid", "The index inventory response was not a JSON array."))?;
        let truncated = index_rows.len() > 10_000;
        let mut resources = Vec::new();
        let mut findings = Vec::new();
        let mut state = Vec::new();
        for row in index_rows.iter().take(10_000) {
            let Some(index) = row.get("index").and_then(Value::as_str) else { continue };
            if !matches_index_pattern(&self.index_pattern, index) { continue; }
            let mapping = self.get_json(self.url_for(&[index, "_mapping"])?).await?;
            let settings = self.get_json(self.url_for(&[index, "_settings"])?).await?;
            let aliases = self.get_optional_json(self.url_for(&[index, "_alias"])?).await?.unwrap_or_else(|| json!({}));
            let mapping_value = mapping.get(index).cloned().unwrap_or_else(|| mapping.clone());
            let settings_value = settings.get(index).cloned().unwrap_or_else(|| settings.clone());
            let aliases_value = aliases.get(index).cloned().unwrap_or_else(|| aliases.clone());
            let attributes = json!({
                "health": row.get("health").cloned().unwrap_or(Value::Null),
                "status": row.get("status").cloned().unwrap_or(Value::Null),
                "document_count": row.get("docs.count").cloned().unwrap_or(Value::Null),
                "store_size": row.get("store.size").cloned().unwrap_or(Value::Null),
                "mapping": mapping_value,
                "settings": settings_value,
                "aliases": aliases_value
            });
            resources.push(DiscoveredResource {
                namespace: None,
                name: index.to_owned(),
                kind: ResourceKind::Collection,
                owner: None,
                attributes: attributes.clone(),
            });
            state.push(json!({ "index": index, "attributes": attributes }));
        }
        if truncated {
            findings.push(SecurityFinding {
                code: "elasticsearch_index_inventory_truncated".into(),
                resource: None,
                detail: "The cluster index inventory exceeded 10,000 entries; discovery is incomplete.".into(),
            });
        }
        let (roles, role_mappings, users, security_api) = if is_opensearch {
            let roles = self.get_optional_json(self.url_for(&["_plugins", "_security", "api", "roles"])?).await?;
            let mappings = self.get_optional_json(self.url_for(&["_plugins", "_security", "api", "rolesmapping"])?).await?;
            let users = self.get_optional_json(self.url_for(&["_plugins", "_security", "api", "internalusers"])?).await?;
            (roles, mappings, users, "opensearch_security_plugin")
        } else {
            let roles = self.get_optional_json(self.url_for(&["_security", "role"])?).await?;
            let users = self.get_optional_json(self.url_for(&["_security", "user"])?).await?;
            (roles, None, users, "elasticsearch_security")
        };
        let security_visible = roles.is_some() && users.is_some()
            && (!is_opensearch || role_mappings.is_some());
        if !security_visible {
            findings.push(SecurityFinding {
                code: "elasticsearch_security_catalog_unavailable".into(),
                resource: None,
                detail: "The authenticated principal could not read the native security role/user catalog. Index discovery alone cannot establish effective document-level privileges.".into(),
            });
        }
        let target_attributes = json!({
            "server_version": version,
            "distribution": if security_api == "opensearch_security_plugin" { "opensearch" } else { "elasticsearch" },
            "security_api": security_api,
            "index_pattern": self.index_pattern,
            "roles": roles.clone().unwrap_or(Value::Null),
            "role_mappings": role_mappings.clone().unwrap_or(Value::Null),
            "users": sanitize_user_catalog(users.clone().unwrap_or(Value::Null)),
            "security_catalog_visible": security_visible
        });
        let fingerprint = digest(&serde_json::to_vec(&json!({ "target": target_attributes, "indices": state }))
            .map_err(|_| error("elasticsearch_fingerprint_failed", "Could not serialize Elasticsearch/OpenSearch catalog state."))?);
        if resources.is_empty() {
            findings.push(SecurityFinding {
                code: "elasticsearch_no_matching_indices".into(),
                resource: None,
                detail: "No visible index matched the registered index pattern. Check the pattern and the inspection principal's index privileges.".into(),
            });
        }
        Ok(DiscoverySnapshot {
            database_kind: kind,
            target: request.target.clone(),
            completeness: if truncated || !security_visible { InspectionCompleteness::Incomplete } else { InspectionCompleteness::Complete },
            target_attributes,
            resources,
            findings,
            fingerprint: Some(fingerprint),
            observed_at: chrono::Utc::now().to_rfc3339(),
        })
    }

    async fn discover_bounded(&self, request: &DiscoveryRequest) -> Result<DiscoverySnapshot, AdapterError> {
        tokio::time::timeout(Duration::from_secs(90), self.discover_inner(request))
            .await
            .map_err(|_| AdapterError {
                code: "elasticsearch_catalog_timeout".into(),
                detail: "Elasticsearch/OpenSearch catalog discovery exceeded the ninety-second operation deadline.".into(),
                retryable: true,
            })?
    }
}

impl DatabaseAdapter for ElasticsearchCatalogAdapter {
    fn descriptor(&self) -> AdapterDescriptor {
        AdapterDescriptor {
            kind: DatabaseKind::Elasticsearch,
            name: "Elasticsearch / OpenSearch catalog adapter",
            maturity: AdapterMaturity::InDevelopment,
            capabilities: AdapterCapabilities { schema_inspection: true, drift_detection: true, ..AdapterCapabilities::default() },
            status_note: "Verified-HTTPS discovery inventories matching indices, mappings, settings, aliases and native security roles/users where visible. DLS/FLS enforcement, trusted tenant-principal binding, policy deployment, independent document probes and runtime admission are not implemented.",
        }
    }

    fn discover<'a>(&'a self, request: &'a DiscoveryRequest) -> AdapterFuture<'a, Result<DiscoverySnapshot, AdapterError>> {
        Box::pin(async move { self.discover_bounded(request).await })
    }

    fn inspect<'a>(&'a self, request: &'a InspectionRequest) -> AdapterFuture<'a, Result<InspectionSnapshot, AdapterError>> {
        Box::pin(async move {
            request.policy.validate().map_err(|_| error("invalid_policy", "The canonical tenant policy failed validation."))?;
            let discovery = self.discover_bounded(&DiscoveryRequest { target: request.target.clone(), namespace: None }).await?;
            let mut findings = discovery.findings.clone();
            let mut inspected = Vec::new();
            for required in &request.policy.resources {
                let resource = discovery.resources.iter().find(|resource| resource.name == required.resource.name
                    && resource.kind == required.resource.kind && required.resource.namespace.is_none());
                let Some(resource) = resource else {
                    findings.push(finding("elasticsearch_required_index_missing", &required.resource, "The protected index was not present in the visible index inventory."));
                    continue;
                };
                let mapping = resource.attributes.get("mapping").cloned().unwrap_or(Value::Null);
                let field_type = mapping_field_type(&mapping, &required.tenant_key);
                let mut resource_findings = Vec::new();
                if field_type.is_none() {
                    resource_findings.push(finding("elasticsearch_tenant_field_missing", &required.resource, "The declared tenant ownership field is absent from the index mapping."));
                }
                if !discovery.target_attributes.get("security_catalog_visible").and_then(Value::as_bool).unwrap_or(false) {
                    resource_findings.push(finding("elasticsearch_security_roles_unavailable", &required.resource, "Native DLS/FLS role state could not be inspected."));
                }
                if field_type.is_some() {
                    resource_findings.push(finding("elasticsearch_dls_probe_required", &required.resource, "A mapped tenant field does not enforce document isolation; verify DLS query predicates and independent positive/negative document probes."));
                }
                findings.extend(resource_findings.iter().cloned());
                inspected.push(ResourceInspection {
                    resource: required.clone(),
                    completeness: discovery.completeness,
                    posture: SecurityPosture::NeedsAttention,
                    verified_operations: Vec::new(),
                    findings: resource_findings,
                    fingerprint: discovery.fingerprint.clone(),
                });
            }
            findings.push(SecurityFinding {
                code: "elasticsearch_runtime_tenant_binding_unavailable".into(),
                resource: None,
                detail: "No trusted gateway currently binds authenticated tenant identity to a dedicated Elasticsearch/OpenSearch principal with verified DLS/FLS restrictions.".into(),
            });
            Ok(InspectionSnapshot {
                database_kind: discovery.database_kind,
                target: discovery.target,
                completeness: discovery.completeness,
                posture: SecurityPosture::NeedsAttention,
                resources: inspected,
                findings,
                fingerprint: discovery.fingerprint,
                observed_at: discovery.observed_at,
            })
        })
    }

    fn compile_policy(&self, _policy: &TenantSecurityPolicy) -> Result<CompiledPolicy, AdapterError> {
        Err(error("elasticsearch_policy_compilation_unavailable", "DLS/FLS policy compilation and controlled role deployment are not implemented; the adapter will not generate unverified role definitions."))
    }

    fn verify<'a>(&'a self, _policy: &'a TenantSecurityPolicy, snapshot: &'a InspectionSnapshot) -> AdapterFuture<'a, Result<VerificationReport, AdapterError>> {
        Box::pin(async move {
            if snapshot.database_kind != DatabaseKind::Elasticsearch || snapshot.target.target_id != self.target_id {
                return Err(error("elasticsearch_snapshot_target_mismatch", "The inspection snapshot belongs to a different Elasticsearch/OpenSearch target."));
            }
            let mut findings = snapshot.findings.clone();
            findings.push(SecurityFinding {
                code: "elasticsearch_semantic_verification_unavailable".into(),
                resource: None,
                detail: "Document isolation has not been proven with distinct authenticated tenant principals and independent cross-tenant document probes.".into(),
            });
            Ok(VerificationReport {
                model_version: SECURITY_MODEL_VERSION.into(),
                posture: SecurityPosture::Blocked,
                inspection: snapshot.completeness,
                findings,
            })
        })
    }

    fn detect_drift<'a>(&'a self, target: &'a AdapterTarget, previous_fingerprint: Option<&'a str>) -> AdapterFuture<'a, Result<DriftReport, AdapterError>> {
        Box::pin(async move {
            self.validate_target(target)?;
            if previous_fingerprint.is_some_and(|value| value.len() != 64 || hex::decode(value).map_or(true, |bytes| bytes.len() != 32)) {
                return Err(error("invalid_previous_fingerprint", "The previous fingerprint must be a 32-byte hexadecimal SHA-256 digest."));
            }
            let snapshot = self.discover_bounded(&DiscoveryRequest { target: target.clone(), namespace: None }).await?;
            let detected = previous_fingerprint.is_some_and(|previous| Some(previous) != snapshot.fingerprint.as_deref());
            Ok(DriftReport {
                database_kind: DatabaseKind::Elasticsearch,
                target: target.clone(),
                detected,
                completeness: snapshot.completeness,
                previous_fingerprint: previous_fingerprint.map(str::to_owned),
                observed_fingerprint: snapshot.fingerprint,
                findings: if detected { vec![SecurityFinding {
                    code: "elasticsearch_catalog_fingerprint_changed".into(),
                    resource: None,
                    detail: "Index mappings, settings, aliases or security-role assignments differ from the previously accepted fingerprint.".into(),
                }] } else { snapshot.findings },
                observed_at: snapshot.observed_at,
            })
        })
    }
}

fn mapping_field_type(mapping: &Value, field: &str) -> Option<String> {
    let mut current = mapping.get("mappings").unwrap_or(mapping);
    for part in field.split('.') {
        current = current.get("properties")?.get(part)?;
    }
    current.get("type").and_then(Value::as_str).map(str::to_owned)
}

fn matches_index_pattern(pattern: &str, value: &str) -> bool {
    let parts = pattern.split('*').collect::<Vec<_>>();
    if parts.len() == 1 { return pattern == value; }
    if !value.starts_with(parts[0]) || !value.ends_with(parts[parts.len()-1]) { return false; }
    let mut offset = parts[0].len();
    for part in parts.iter().skip(1).take(parts.len().saturating_sub(2)) {
        let Some(found) = value[offset..].find(part) else { return false };
        offset += found + part.len();
    }
    offset <= value.len() - parts[parts.len()-1].len()
}

fn sanitize_user_catalog(mut value: Value) -> Value {
    fn strip_secrets(value: &mut Value) {
        match value {
            Value::Object(map) => {
                for key in ["password", "password_hash", "hash", "salt", "api_key", "token"] {
                    map.remove(key);
                }
                for child in map.values_mut() { strip_secrets(child); }
            }
            Value::Array(items) => for child in items { strip_secrets(child); },
            _ => {}
        }
    }
    strip_secrets(&mut value);
    value
}

fn digest(bytes: &[u8]) -> String { hex::encode(Sha256::digest(bytes)) }
fn error(code: &str, detail: &str) -> AdapterError { AdapterError { code: code.into(), detail: detail.into(), retryable: false } }
fn http_error(error: reqwest::Error) -> AdapterError {
    AdapterError { code: "elasticsearch_http_request_failed".into(), detail: "The verified HTTPS request to the search cluster failed.".into(), retryable: error.is_timeout() || error.is_connect() }
}
fn finding(code: &str, resource: &ResourceRef, detail: &str) -> SecurityFinding {
    SecurityFinding { code: code.into(), resource: Some(resource.clone()), detail: detail.into() }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn requires_https_and_non_embedded_credentials() {
        assert!(ElasticsearchCatalogAdapter::new("target", "tenant-*", "http://localhost:9200", "ApiKey x").is_err());
        assert!(ElasticsearchCatalogAdapter::new("target", "tenant-*", "https://user:pass@example.com", "ApiKey x").is_err());
        assert!(ElasticsearchCatalogAdapter::new("target", "tenant-*", "https://search.example.com:9200", "ApiKey x").is_ok());
    }

    #[test]
    fn matches_globbed_index_names_without_regex_interpretation() {
        assert!(matches_index_pattern("tenant-*", "tenant-a"));
        assert!(matches_index_pattern("tenant-*-events", "tenant-a-events"));
        assert!(!matches_index_pattern("tenant-*", "other-a"));
        assert!(!matches_index_pattern("tenant-a", "tenant-ab"));
    }

    #[test]
    fn resolves_nested_mapping_field_types() {
        let mapping = json!({ "mappings": { "properties": { "tenant": { "properties": { "id": { "type": "keyword" } } } } } });
        assert_eq!(mapping_field_type(&mapping, "tenant.id"), Some("keyword".into()));
        assert_eq!(mapping_field_type(&mapping, "missing"), None);
    }

    #[test]
    fn strips_credentials_from_user_catalog() {
        let users = json!({ "alice": { "password": "secret", "roles": ["reader"], "metadata": { "token": "secret" } } });
        let sanitized = sanitize_user_catalog(users);
        assert!(sanitized.pointer("/alice/password").is_none());
        assert!(sanitized.pointer("/alice/metadata/token").is_none());
        assert_eq!(sanitized.pointer("/alice/roles/0").and_then(Value::as_str), Some("reader"));
    }
}
