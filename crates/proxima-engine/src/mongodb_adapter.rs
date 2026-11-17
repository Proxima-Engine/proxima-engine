//! Native MongoDB catalog and authorization discovery.
//!
//! Discovery is performed with the authenticated account's effective
//! connection-status privileges. MongoDB database roles do not by themselves
//! enforce tenant ownership on individual documents; this adapter therefore
//! never converts catalog presence into an isolation allow decision.

use crate::database_adapter::{
    AdapterError, AdapterFuture, AdapterTarget, CompiledPolicy, DatabaseAdapter,
    DiscoveryRequest, DiscoverySnapshot, DiscoveredResource, DriftReport,
    InspectionRequest, InspectionSnapshot, ResourceInspection,
};
use crate::native_policy_plans::compile_mongodb_database_boundary;
use crate::security_core::{
    AdapterCapabilities, AdapterDescriptor, AdapterMaturity, DatabaseKind,
    InspectionCompleteness, ResourceKind, ResourceRef, SecurityFinding,
    SecurityPosture, TenantSecurityPolicy, VerificationReport, SECURITY_MODEL_VERSION,
};
use mongodb::{
    bson::{doc, Bson, Document},
    options::ClientOptions,
    Client,
};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::time::Duration;

pub struct MongoCatalogAdapter {
    target_id: String,
    database_name: String,
    connection_uri: String,
}

impl MongoCatalogAdapter {
    pub fn new(
        target_id: impl Into<String>,
        database_name: impl Into<String>,
        connection_uri: impl Into<String>,
    ) -> Result<Self, AdapterError> {
        let target_id = target_id.into();
        let database_name = database_name.into();
        let connection_uri = connection_uri.into();
        let uri = connection_uri.to_ascii_lowercase();
        if target_id.trim().is_empty() || target_id.len() > 256 || target_id.contains('\0')
            || database_name.trim().is_empty() || database_name.len() > 63 || database_name.contains('\0')
            || connection_uri.trim().is_empty() || connection_uri.len() > 4096
        {
            return Err(error("invalid_mongodb_target", "A bounded target ID, database name and connection URI are required."));
        }
        let parameters: Vec<(&str, &str)> = uri.split_once('?').map(|(_, query)| {
            query.split('&').filter_map(|part| part.split_once('=')).collect()
        }).unwrap_or_default();
        let parameter_is_true = |key: &str| parameters.iter().any(|(name, value)| *name == key && *value == "true");
        let parameter_is_false = |key: &str| parameters.iter().any(|(name, value)| *name == key && *value == "false");
        let tls_enabled = uri.starts_with("mongodb+srv://") || parameter_is_true("tls") || parameter_is_true("ssl");
        let tls_disabled = parameter_is_false("tls") || parameter_is_false("ssl");
        let insecure_tls = parameter_is_true("tlsinsecure")
            || parameter_is_true("tlsallowinvalidcertificates")
            || parameter_is_true("tlsallowinvalidhostnames");
        if !tls_enabled || tls_disabled || insecure_tls {
            return Err(error("mongodb_tls_verification_required", "MongoDB connections must use TLS with certificate and hostname verification; insecure TLS options are forbidden."));
        }
        Ok(Self { target_id, database_name, connection_uri })
    }

    fn validate_target(&self, target: &AdapterTarget) -> Result<(), AdapterError> {
        if target.target_id != self.target_id || target.database_name != self.database_name {
            return Err(error("mongodb_target_mismatch", "The request does not match this adapter's registered database target."));
        }
        Ok(())
    }

    async fn connect_checked(&self) -> Result<Client, AdapterError> {
        let mut options = ClientOptions::parse(&self.connection_uri).await.map_err(db_error)?;
        options.server_selection_timeout = Some(Duration::from_secs(10));
        options.connect_timeout = Some(Duration::from_secs(10));
        let client = Client::with_options(options).map_err(db_error)?;
        // Force authentication and server selection now, rather than treating
        // the driver's lazy Client construction as a successful connection.
        client.database(&self.database_name)
            .run_command(doc! { "ping": 1 })
            .await.map_err(db_error)?;
        Ok(client)
    }

    async fn discover_inner(&self, request: &DiscoveryRequest) -> Result<DiscoverySnapshot, AdapterError> {
        self.validate_target(&request.target)?;
        if request.namespace.as_ref().is_some_and(|namespace| {
            namespace.trim().is_empty() || namespace.len() > 63 || namespace.contains('\0')
                || namespace != &self.database_name
        }) {
            return Err(error("invalid_discovery_namespace", "MongoDB discovery namespace must be the registered database name."));
        }
        let client = self.connect_checked().await?;
        let database = client.database(&self.database_name);
        let connection_status = database.run_command(doc! {
            "connectionStatus": 1,
            "showPrivileges": true
        }).await.map_err(db_error)?;
        let names = database.list_collection_names().await.map_err(db_error)?;
        let mut resources = Vec::with_capacity(names.len());
        for name in names {
            let response = database.run_command(doc! {
                "listCollections": 1,
                "filter": { "name": &name },
                "nameOnly": false,
            }).await.map_err(db_error)?;
            let first_batch = response.get_document("cursor")
                .and_then(|cursor| cursor.get_array("firstBatch"))
                .map_err(|_| error("mongodb_discovery_response_invalid", "MongoDB listCollections returned an invalid cursor response."))?;
            let entry = first_batch.iter().find_map(Bson::as_document)
                .ok_or_else(|| error("mongodb_discovery_resource_disappeared", "A collection disappeared between enumeration and metadata inspection."))?;
            let resource_type = entry.get_str("type").unwrap_or("collection");
            let options = entry.get_document("options").cloned().unwrap_or_default();
            let info = entry.get_document("info").cloned().unwrap_or_default();
            let kind = if resource_type == "view" { ResourceKind::View } else { ResourceKind::Collection };
            let attributes = json!({
                "native_type": resource_type,
                "options": bson_value(&options)?,
                "info": bson_value(&info)?,
                "collection_uuid": info.get("uuid").map(|value| format!("{value:?}")),
                "validator": options.get("validator").map(|value| format!("{value:?}")),
                "view_on": options.get_str("viewOn").ok(),
                "pipeline": options.get_array("pipeline").ok().map(|value| format!("{value:?}"))
            });
            resources.push(DiscoveredResource {
                namespace: Some(self.database_name.clone()),
                name,
                kind,
                owner: None,
                attributes,
            });
        }
        let target_attributes = json!({
            "database": self.database_name,
            "connection_status": bson_value(&connection_status)?,
            "tls_certificate_verification_required": true
        });
        let fingerprint = digest(&serde_json::to_vec(&json!({"target":target_attributes,"resources":resources}))
            .map_err(|_| error("fingerprint_serialization_failed", "Could not serialize MongoDB discovery results."))?);
        Ok(DiscoverySnapshot {
            database_kind: DatabaseKind::MongoDb,
            target: request.target.clone(),
            // listCollections and connectionStatus are scoped to what the
            // authenticated principal is allowed to see.
            completeness: InspectionCompleteness::Incomplete,
            target_attributes,
            resources,
            findings: vec![SecurityFinding {
                code: "mongodb_catalog_visibility_not_proven".into(),
                resource: None,
                detail: "MongoDB collection and privilege visibility is scoped to the authenticated account; a partial inventory cannot certify complete database coverage.".into(),
            }],
            fingerprint: Some(fingerprint),
            observed_at: chrono::Utc::now().to_rfc3339(),
        })
    }
}

impl DatabaseAdapter for MongoCatalogAdapter {
    fn descriptor(&self) -> AdapterDescriptor {
        AdapterDescriptor {
            kind: DatabaseKind::MongoDb,
            name: "MongoDB catalog adapter",
            maturity: AdapterMaturity::InDevelopment,
            capabilities: AdapterCapabilities {
                schema_inspection: true,
                policy_generation: true,
                drift_detection: true,
                ..AdapterCapabilities::default()
            },
            status_note: "TLS-verified collection, validator, view and effective privilege discovery are implemented. MongoDB document ownership enforcement, independent tenant probes, controlled deployment and runtime admission are not implemented.",
        }
    }

    fn discover<'a>(&'a self, request: &'a DiscoveryRequest) -> AdapterFuture<'a, Result<DiscoverySnapshot, AdapterError>> {
        Box::pin(async move { self.discover_inner(request).await })
    }

    fn inspect<'a>(&'a self, request: &'a InspectionRequest) -> AdapterFuture<'a, Result<InspectionSnapshot, AdapterError>> {
        Box::pin(async move {
            self.validate_target(&request.target)?;
            request.policy.validate().map_err(|_| error("invalid_policy", "The canonical tenant policy failed validation."))?;
            let discovery = self.discover_inner(&DiscoveryRequest {
                target: request.target.clone(),
                namespace: None,
            }).await?;
            let mut findings = discovery.findings.clone();
            let mut resources = Vec::with_capacity(request.policy.resources.len());
            for protected in &request.policy.resources {
                let namespace = protected.resource.namespace.as_deref().unwrap_or(&self.database_name);
                if namespace != self.database_name {
                    return Err(error("mongodb_resource_namespace_mismatch", "A MongoDB resource must belong to the registered database target."));
                }
                let found = discovery.resources.iter().find(|resource| {
                    resource.namespace.as_deref() == Some(namespace)
                        && resource.name == protected.resource.name
                        && resource.kind == protected.resource.kind
                });
                let mut resource_findings = Vec::new();
                if found.is_none() {
                    resource_findings.push(finding("protected_resource_not_found", &protected.resource, "The collection or view was not visible in the authenticated database inventory."));
                } else if protected.resource.kind != ResourceKind::Collection {
                    resource_findings.push(finding("unsupported_mongodb_policy_resource", &protected.resource, "The current MongoDB policy compiler manages tenant-isolated database resources, not views."));
                } else {
                    let attrs = &found.unwrap().attributes;
                    let validator = attrs["options"]["validator"].clone();
                    let properties = validator.get("$jsonSchema").and_then(|schema| schema.get("properties"));
                    let tenant_property = properties.and_then(|value| value.get(protected.tenant_key.as_str()));
                    if tenant_property.is_none() {
                        resource_findings.push(finding("tenant_ownership_validator_missing", &protected.resource, "The collection validator does not declare the policy tenant ownership field."));
                    } else if tenant_property.and_then(|property| property.get("bsonType")).is_none() {
                        resource_findings.push(finding("tenant_ownership_type_unconstrained", &protected.resource, "The collection validator does not constrain the BSON type of the tenant ownership field."));
                    }
                    let required = validator.get("$jsonSchema").and_then(|schema| schema.get("required")).and_then(Value::as_array);
                    if !required.is_some_and(|fields| fields.iter().any(|field| field.as_str() == Some(protected.tenant_key.as_str()))) {
                        resource_findings.push(finding("tenant_ownership_not_required", &protected.resource, "The collection validator does not require the tenant ownership field."));
                    }
                    let validation_action = attrs["options"]["validationAction"].as_str().unwrap_or("error");
                    if !validation_action.eq_ignore_ascii_case("error") {
                        resource_findings.push(finding("mongodb_validator_not_rejecting_invalid_documents", &protected.resource, "The collection validationAction is not error, so invalid tenant documents may be accepted."));
                    }
                    let validation_level = attrs["options"]["validationLevel"].as_str().unwrap_or("strict");
                    if !validation_level.eq_ignore_ascii_case("strict") {
                        resource_findings.push(finding("mongodb_validator_not_strict", &protected.resource, "The collection validationLevel is not strict; existing documents may avoid full validation on updates."));
                    }
                }
                resource_findings.push(finding("mongodb_document_isolation_probe_required", &protected.resource, "MongoDB database roles do not automatically enforce tenant ownership for individual documents; independent tenant-scoped document probes are required."));
                findings.extend(resource_findings.clone());
                let resource_fingerprint = if let Some(resource) = found {
                    Some(digest(&serde_json::to_vec(&resource.attributes)
                        .map_err(|_| error("fingerprint_serialization_failed", "Could not serialize MongoDB resource metadata."))?))
                } else {
                    None
                };
                resources.push(ResourceInspection {
                    resource: protected.clone(),
                    completeness: InspectionCompleteness::Incomplete,
                    posture: SecurityPosture::NeedsAttention,
                    verified_operations: Vec::new(),
                    findings: resource_findings,
                    fingerprint: resource_fingerprint,
                });
            }
            Ok(InspectionSnapshot {
                database_kind: DatabaseKind::MongoDb,
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

    fn compile_policy(&self, policy: &TenantSecurityPolicy) -> Result<CompiledPolicy, AdapterError> {
        compile_mongodb_database_boundary(policy)
    }

    fn verify<'a>(&'a self, policy: &'a TenantSecurityPolicy, snapshot: &'a InspectionSnapshot) -> AdapterFuture<'a, Result<VerificationReport, AdapterError>> {
        Box::pin(async move {
            if snapshot.database_kind != DatabaseKind::MongoDb
                || snapshot.target.target_id != self.target_id
                || snapshot.target.database_name != self.database_name {
                return Err(error("mongodb_snapshot_target_mismatch", "The inspection snapshot does not belong to this MongoDB adapter target."));
            }
            let mut findings = snapshot.findings.clone();
            findings.push(SecurityFinding {
                code: "independent_tenant_probes_required".into(),
                resource: None,
                detail: format!("{} protected resources require own-tenant allow and cross-tenant deny document probes using distinct authenticated principals.", policy.resources.len()),
            });
            findings.push(SecurityFinding {
                code: "mongodb_runtime_tenant_binding_unavailable".into(),
                resource: None,
                detail: "No trusted MongoDB protocol gateway currently binds authenticated tenant identity to a native database/user boundary.".into(),
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
                return Err(error("invalid_previous_fingerprint", "The previous catalog fingerprint must be a 32-byte hexadecimal SHA-256 digest."));
            }
            let snapshot = self.discover_inner(&DiscoveryRequest { target: target.clone(), namespace: None }).await?;
            Ok(DriftReport {
                database_kind: DatabaseKind::MongoDb,
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

fn bson_value(document: &Document) -> Result<Value, AdapterError> {
    serde_json::to_value(document).map_err(|_| error("mongodb_catalog_serialization_failed", "Could not serialize MongoDB catalog metadata."))
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

fn db_error(_error: mongodb::error::Error) -> AdapterError {
    AdapterError {
        code: "mongodb_catalog_operation_failed".into(),
        detail: "The authenticated MongoDB catalog operation failed.".into(),
        retryable: true,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn requires_verified_tls_for_mongodb_connections() {
        assert!(MongoCatalogAdapter::new("target", "app", "mongodb://localhost/app").is_err());
        assert!(MongoCatalogAdapter::new("target", "app", "mongodb://localhost/app?tls=false").is_err());
        assert!(MongoCatalogAdapter::new("target", "app", "mongodb://localhost/app?tls=true&tlsInsecure=true").is_err());
        assert!(MongoCatalogAdapter::new("target", "app", "mongodb://localhost/app?tls=true").is_ok());
        assert!(MongoCatalogAdapter::new("target", "app", "mongodb+srv://cluster.example/app").is_ok());
    }

    #[test]
    fn descriptor_exposes_inventory_but_not_document_enforcement() {
        let adapter = MongoCatalogAdapter::new("target", "app", "mongodb://localhost/app?tls=true").unwrap();
        let descriptor = adapter.descriptor();
        assert_eq!(descriptor.maturity, AdapterMaturity::InDevelopment);
        assert!(descriptor.capabilities.schema_inspection);
        assert!(descriptor.capabilities.policy_generation);
        assert!(descriptor.capabilities.drift_detection);
        assert!(!descriptor.capabilities.tenant_identity_enforcement);
        assert!(!descriptor.capabilities.policy_semantic_verification);
        assert!(!descriptor.capabilities.controlled_policy_deployment);
        assert!(!descriptor.capabilities.runtime_fail_closed_admission);
        assert!(!descriptor.capabilities.signed_security_evidence);
    }
}
