//! CockroachDB native catalog discovery adapter.
//!
//! CockroachDB speaks the PostgreSQL wire protocol but has distinct authorization
//! and feature semantics. This module intentionally performs discovery only;
//! it does not reuse PostgreSQL RLS assumptions or claim tenant isolation.
use crate::database_adapter::{
    AdapterError, AdapterFuture, AdapterTarget, CompiledPolicy, DatabaseAdapter,
    DiscoveryRequest, DiscoverySnapshot, DiscoveredResource, DriftReport,
    InspectionRequest, InspectionSnapshot, ResourceInspection,
};
use crate::security_core::{
    AdapterCapabilities, AdapterDescriptor, AdapterMaturity, DatabaseKind,
    InspectionCompleteness, ResourceKind, ResourceRef, SecurityFinding,
    SecurityPosture, TenantSecurityPolicy, VerificationReport, SECURITY_MODEL_VERSION,
};
use serde_json::json;
use sha2::{Digest, Sha256};
use std::sync::Arc;
use tokio_postgres::Client;

pub type CockroachConnector =
    Arc<dyn Fn() -> AdapterFuture<'static, Result<Client, AdapterError>> + Send + Sync>;

pub struct CockroachCatalogAdapter {
    target_id: String,
    database_name: String,
    connect: CockroachConnector,
}

impl CockroachCatalogAdapter {
    pub fn new(
        target_id: impl Into<String>,
        database_name: impl Into<String>,
        connect: CockroachConnector,
    ) -> Result<Self, AdapterError> {
        let target_id = target_id.into();
        let database_name = database_name.into();
        if target_id.trim().is_empty() || target_id.len() > 256 || target_id.contains('\0')
            || database_name.trim().is_empty() || database_name.len() > 63
            || database_name.contains('\0')
        {
            return Err(error("invalid_cockroach_target", "A bounded target ID and database name are required."));
        }
        Ok(Self { target_id, database_name, connect })
    }

    fn validate_target(&self, target: &AdapterTarget) -> Result<(), AdapterError> {
        if target.target_id != self.target_id || target.database_name != self.database_name {
            return Err(error("cockroach_target_mismatch", "The request does not match this registered CockroachDB target."));
        }
        Ok(())
    }

    async fn connect_checked(&self) -> Result<Client, AdapterError> {
        let client = (self.connect)().await?;
        client.batch_execute(
            "SET default_transaction_read_only = on; SET statement_timeout = '10s'; SET search_path = pg_catalog, public"
        ).await.map_err(db_error)?;
        let row = client.query_one(
            "SELECT current_database(), current_user, version()", &[]
        ).await.map_err(db_error)?;
        let database: String = row.get(0);
        let user: String = row.get(1);
        let version: String = row.get(2);
        if database != self.database_name {
            return Err(error("cockroach_database_mismatch", "The authenticated connection reached a different database."));
        }
        if !version.to_ascii_lowercase().contains("cockroach") {
            return Err(error("cockroach_server_identity_mismatch", "The endpoint did not identify itself as CockroachDB."));
        }
        if user.trim().is_empty() {
            return Err(error("cockroach_authenticated_identity_missing", "The server did not expose an authenticated principal."));
        }
        Ok(client)
    }

    async fn discover_inner(&self, request: &DiscoveryRequest) -> Result<DiscoverySnapshot, AdapterError> {
        self.validate_target(&request.target)?;
        if request.namespace.as_ref().is_some_and(|schema| {
            schema.trim().is_empty() || schema.len() > 63 || schema.contains('\0')
        }) {
            return Err(error("invalid_cockroach_namespace", "The requested schema name is empty or exceeds the identifier limit."));
        }
        let client = self.connect_checked().await?;
        let rows = client.query(
            "SELECT table_schema, table_name, table_type FROM information_schema.tables \
             WHERE table_catalog = current_database() \
             AND table_schema NOT IN ('information_schema', 'pg_catalog', 'crdb_internal', 'pg_extension') \
             AND ($1::STRING IS NULL OR table_schema = $1) \
             ORDER BY table_schema, table_name LIMIT 10001",
            &[&request.namespace],
        ).await.map_err(db_error)?;
        let truncated = rows.len() > 10_000;
        let mut resources = Vec::with_capacity(rows.len().min(10_000));
        let mut findings = Vec::new();
        let mut state = Vec::new();
        for row in rows.into_iter().take(10_000) {
            let schema: String = row.get(0);
            let name: String = row.get(1);
            let table_type: String = row.get(2);
            let columns = client.query(
                "SELECT column_name, data_type, is_nullable, column_default \
                 FROM information_schema.columns \
                 WHERE table_catalog=current_database() AND table_schema=$1 AND table_name=$2 \
                 ORDER BY ordinal_position",
                &[&schema, &name],
            ).await.map_err(db_error)?;
            let privileges = client.query(
                "SELECT grantee, privilege_type, is_grantable \
                 FROM information_schema.table_privileges \
                 WHERE table_catalog=current_database() AND table_schema=$1 AND table_name=$2 \
                 ORDER BY grantee, privilege_type",
                &[&schema, &name],
            ).await.map_err(db_error)?;
            let column_state: Vec<_> = columns.iter().map(|column| json!({
                "name": column.get::<_, String>(0),
                "data_type": column.get::<_, String>(1),
                "nullable": column.get::<_, String>(2) == "YES",
                "default": column.get::<_, Option<String>>(3),
            })).collect();
            let privilege_state: Vec<_> = privileges.iter().map(|grant| json!({
                "grantee": grant.get::<_, String>(0),
                "privilege": grant.get::<_, String>(1),
                "grantable": grant.get::<_, String>(2) == "YES",
            })).collect();
            let kind = if table_type.eq_ignore_ascii_case("VIEW") { ResourceKind::View } else { ResourceKind::Table };
            let reference = ResourceRef { namespace: Some(schema.clone()), name: name.clone(), kind };
            if kind == ResourceKind::View {
                findings.push(SecurityFinding {
                    code: "cockroach_view_requires_dependency_review".into(),
                    resource: Some(reference.clone()),
                    detail: "View dependencies and invoker/definer behavior require separate review before tenant protection can be asserted.".into(),
                });
            }
            resources.push(DiscoveredResource {
                namespace: Some(schema.clone()),
                name: name.clone(),
                kind,
                owner: None,
                attributes: json!({
                    "table_type": table_type,
                    "columns": column_state.clone(),
                    "privileges": privilege_state.clone(),
                }),
            });
            state.push(json!({
                "schema": schema, "name": name, "kind": table_type,
                "columns": column_state, "privileges": privilege_state,
            }));
        }
        // This adapter does not yet enumerate database/schema ACLs, role memberships,
        // ownership or effective inherited privileges, so its security inventory is
        // incomplete even when every relation fits within the relation-count bound.
        let completeness = InspectionCompleteness::Incomplete;
        findings.push(SecurityFinding {
            code: "cockroach_security_catalog_scope_incomplete".into(),
            resource: None,
            detail: "Discovery currently captures visible table grants only. Database/schema privileges, role memberships, relation ownership and effective inherited privileges are not yet inventoried.".into(),
        });
        if truncated {
            findings.push(SecurityFinding {
                code: "cockroach_discovery_limit_reached".into(),
                resource: None,
                detail: "The inventory exceeded 10,000 relations; discovery is incomplete and cannot be used as a clean baseline.".into(),
            });
        }
        let server_version: String = client.query_one("SELECT version()", &[]).await.map_err(db_error)?.get(0);
        let fingerprint = digest(&serde_json::to_vec(&json!({
            "server_version": server_version,
            "resources": state
        })).map_err(|_| error("cockroach_fingerprint_failed", "Catalog state could not be serialized."))?);
        let observed_at: String = client.query_one(
            "SELECT to_char(now() AT TIME ZONE 'UTC', 'YYYY-MM-DD\"T\"HH24:MI:SS.US\"Z\"')", &[]
        ).await.map_err(db_error)?.get(0);
        Ok(DiscoverySnapshot {
            database_kind: DatabaseKind::CockroachDb,
            target: request.target.clone(),
            completeness,
            target_attributes: json!({ "server_version": server_version }),
            resources,
            findings,
            fingerprint: Some(fingerprint),
            observed_at,
        })
    }

    async fn discover_bounded(&self, request: &DiscoveryRequest) -> Result<DiscoverySnapshot, AdapterError> {
        tokio::time::timeout(std::time::Duration::from_secs(60), self.discover_inner(request))
            .await
            .map_err(|_| AdapterError {
                code: "cockroach_catalog_timeout".into(),
                detail: "CockroachDB catalog discovery exceeded the sixty-second operation deadline.".into(),
                retryable: true,
            })?
    }

}

impl DatabaseAdapter for CockroachCatalogAdapter {
    fn descriptor(&self) -> AdapterDescriptor {
        AdapterDescriptor {
            kind: DatabaseKind::CockroachDb,
            name: "CockroachDB catalog adapter",
            maturity: AdapterMaturity::InDevelopment,
            capabilities: AdapterCapabilities { schema_inspection: true, drift_detection: true, ..AdapterCapabilities::default() },
            status_note: "TLS-verified PostgreSQL-wire catalog discovery covers non-system tables, views, columns and visible table grants with bounded fingerprints. CockroachDB-native tenant enforcement, policy deployment, independent semantic probes and runtime admission are not implemented; PostgreSQL RLS behavior is not assumed.",
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
                let discovered = discovery.resources.iter().find(|resource| {
                    resource.namespace == required.resource.namespace
                        && resource.name == required.resource.name
                        && resource.kind == required.resource.kind
                });
                let Some(resource) = discovered else {
                    findings.push(SecurityFinding {
                        code: "cockroach_required_resource_missing".into(),
                        resource: Some(required.resource.clone()),
                        detail: "The policy resource was not present in the complete native catalog inventory.".into(),
                    });
                    continue;
                };
                let columns = resource.attributes.get("columns").and_then(|value| value.as_array()).cloned().unwrap_or_default();
                let tenant_column = columns.iter().find(|column| column.get("name").and_then(|value| value.as_str()) == Some(required.tenant_key.as_str()));
                let mut resource_findings = Vec::new();
                if tenant_column.is_none() {
                    resource_findings.push(SecurityFinding {
                        code: "cockroach_tenant_key_missing".into(),
                        resource: Some(required.resource.clone()),
                        detail: "The declared tenant ownership column does not exist in the native table metadata.".into(),
                    });
                } else if tenant_column.and_then(|column| column.get("nullable")).and_then(|value| value.as_bool()) == Some(true) {
                    resource_findings.push(SecurityFinding {
                        code: "cockroach_tenant_key_nullable".into(),
                        resource: Some(required.resource.clone()),
                        detail: "The declared tenant ownership column permits NULL values; rows without a tenant owner cannot be assigned safely.".into(),
                    });
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
                code: "cockroach_native_enforcement_not_implemented".into(),
                resource: None,
                detail: "Catalog discovery does not prove tenant isolation. A CockroachDB-specific authorization model, trusted tenant binding and independent cross-tenant probes are required.".into(),
            });
            Ok(InspectionSnapshot {
                database_kind: DatabaseKind::CockroachDb,
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
        Err(error("cockroach_policy_compilation_unavailable", "CockroachDB policy compilation is disabled until its native authorization semantics and deployment safety are implemented."))
    }

    fn verify<'a>(&'a self, _policy: &'a TenantSecurityPolicy, snapshot: &'a InspectionSnapshot) -> AdapterFuture<'a, Result<VerificationReport, AdapterError>> {
        Box::pin(async move {
            if snapshot.database_kind != DatabaseKind::CockroachDb || snapshot.target.target_id != self.target_id || snapshot.target.database_name != self.database_name {
                return Err(error("cockroach_snapshot_target_mismatch", "The inspection snapshot belongs to a different database target."));
            }
            let mut findings = snapshot.findings.clone();
            findings.push(SecurityFinding {
                code: "cockroach_semantic_verification_unavailable".into(),
                resource: None,
                detail: "CockroachDB isolation has not been proven with independent authenticated positive and cross-tenant negative probes.".into(),
            });
            Ok(VerificationReport { model_version: SECURITY_MODEL_VERSION.into(), posture: SecurityPosture::Blocked, inspection: snapshot.completeness, findings })
        })
    }

    fn detect_drift<'a>(&'a self, target: &'a AdapterTarget, previous_fingerprint: Option<&'a str>) -> AdapterFuture<'a, Result<DriftReport, AdapterError>> {
        Box::pin(async move {
            self.validate_target(target)?;
            if previous_fingerprint.is_some_and(|value| value.len() != 64 || hex::decode(value).map_or(true, |decoded| decoded.len() != 32)) {
                return Err(error("invalid_previous_fingerprint", "The previous fingerprint must be a 32-byte hexadecimal SHA-256 digest."));
            }
            let snapshot = self.discover_bounded(&DiscoveryRequest { target: target.clone(), namespace: None }).await?;
            let detected = previous_fingerprint.is_some_and(|previous| Some(previous) != snapshot.fingerprint.as_deref());
            Ok(DriftReport {
                database_kind: DatabaseKind::CockroachDb,
                target: target.clone(),
                detected,
                completeness: snapshot.completeness,
                previous_fingerprint: previous_fingerprint.map(str::to_owned),
                observed_fingerprint: snapshot.fingerprint,
                findings: if detected { vec![SecurityFinding {
                    code: "cockroach_catalog_fingerprint_changed".into(),
                    resource: None,
                    detail: "CockroachDB schema or table grants differ from the previously accepted catalog fingerprint.".into(),
                }] } else { snapshot.findings },
                observed_at: snapshot.observed_at,
            })
        })
    }
}

fn digest(bytes: &[u8]) -> String { hex::encode(Sha256::digest(bytes)) }
fn error(code: &str, detail: &str) -> AdapterError { AdapterError { code: code.into(), detail: detail.into(), retryable: false } }
fn db_error(error: tokio_postgres::Error) -> AdapterError {
    AdapterError { code: "cockroach_catalog_query_failed".into(), detail: error.to_string(), retryable: error.is_closed() }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_empty_or_unbounded_target_configuration() {
        let connector: CockroachConnector = Arc::new(|| Box::pin(async {
            Err(error("not_connected", "test connector"))
        }));
        assert!(CockroachCatalogAdapter::new("", "app", connector.clone()).is_err());
        assert!(CockroachCatalogAdapter::new("target", "", connector).is_err());
    }

    #[tokio::test]
    async fn rejects_a_different_registered_target_before_connecting() {
        let connector: CockroachConnector = Arc::new(|| Box::pin(async {
            Err(error("connector_must_not_run", "target validation should fail first"))
        }));
        let adapter = CockroachCatalogAdapter::new("target-a", "app", connector).unwrap();
        let request = DiscoveryRequest {
            target: AdapterTarget { target_id: "target-b".into(), database_name: "app".into(), namespace: None },
            namespace: None,
        };
        assert_eq!(adapter.discover(&request).await.unwrap_err().code, "cockroach_target_mismatch");
    }

    #[test]
    fn policy_compilation_is_disabled_until_native_controls_exist() {
        let connector: CockroachConnector = Arc::new(|| Box::pin(async {
            Err(error("not_connected", "test connector"))
        }));
        let adapter = CockroachCatalogAdapter::new("target", "app", connector).unwrap();
        let policy = TenantSecurityPolicy {
            schema_version: SECURITY_MODEL_VERSION.into(),
            policy_id: "policy".into(),
            revision: 1,
            tenant_identity_claim: "tenant_id".into(),
            resources: vec![crate::security_core::ProtectedResource {
                resource: ResourceRef { namespace: Some("public".into()), name: "records".into(), kind: ResourceKind::Table },
                tenant_key: "tenant_id".into(),
                operations: vec![crate::security_core::Operation::Read],
            }],
        };
        assert_eq!(adapter.compile_policy(&policy).unwrap_err().code, "cockroach_policy_compilation_unavailable");
    }

    #[test]
    fn descriptor_claims_discovery_only() {
        let connector: CockroachConnector = Arc::new(|| Box::pin(async {
            Err(error("not_connected", "test connector"))
        }));
        let adapter = CockroachCatalogAdapter::new("target", "app", connector).unwrap();
        let descriptor = adapter.descriptor();
        assert_eq!(descriptor.maturity, AdapterMaturity::InDevelopment);
        assert!(descriptor.capabilities.schema_inspection);
        assert!(descriptor.capabilities.drift_detection);
        assert!(!descriptor.capabilities.tenant_identity_enforcement);
        assert!(!descriptor.capabilities.policy_semantic_verification);
        assert!(!descriptor.capabilities.policy_generation);
        assert!(!descriptor.capabilities.controlled_policy_deployment);
        assert!(!descriptor.capabilities.runtime_fail_closed_admission);
        assert!(!descriptor.capabilities.signed_security_evidence);
    }
}
