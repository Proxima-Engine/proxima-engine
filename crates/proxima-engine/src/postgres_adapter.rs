//! Concrete PostgreSQL catalog adapter for the database-neutral Security Core.
//!
//! This adapter performs authenticated, read-only catalog inspection and emits
//! reviewable RLS policy plans. It deliberately does not report semantic
//! verification or production support: catalog state cannot prove that an
//! arbitrary policy enforces the intended tenant boundary. A separate
//! adversarial verifier and approved deployment executor are required before
//! this adapter can be registered as production-complete.

use crate::database_adapter::{
    AdapterError, AdapterFuture, AdapterTarget, CompiledPolicy, DatabaseAdapter,
    DriftReport, InspectionRequest, InspectionSnapshot, NativePolicyChange,
    ResourceInspection,
};
use crate::security_core::{
    AdapterCapabilities, AdapterDescriptor, AdapterMaturity, DatabaseKind,
    InspectionCompleteness, Operation, ProtectedResource, ResourceKind,
    SecurityFinding, SecurityPosture, TenantSecurityPolicy, VerificationReport,
    SECURITY_MODEL_VERSION,
};
use serde_json::json;
use sha2::{Digest, Sha256};
use std::sync::Arc;
use tokio_postgres::Client;

/// The connector owns credential retrieval, TLS verification, connection
/// timeouts and connection-task supervision. Production callers must inject a
/// connector configured with certificate and hostname verification enabled.
pub type PostgresConnector =
    Arc<dyn Fn() -> AdapterFuture<'static, Result<Client, AdapterError>> + Send + Sync>;

pub struct PostgresCatalogAdapter {
    target_id: String,
    database_name: String,
    connect: PostgresConnector,
}

impl PostgresCatalogAdapter {
    pub fn new(
        target_id: impl Into<String>,
        database_name: impl Into<String>,
        connect: PostgresConnector,
    ) -> Result<Self, AdapterError> {
        let target_id = target_id.into();
        let database_name = database_name.into();
        if target_id.trim().is_empty() || database_name.trim().is_empty()
            || target_id.len() > 256 || database_name.len() > 256
            || target_id.contains('\0') || database_name.contains('\0')
        {
            return Err(error("invalid_postgres_target", "A bounded target ID and database name are required."));
        }
        Ok(Self { target_id, database_name, connect })
    }

    fn validate_target(&self, target: &AdapterTarget) -> Result<(), AdapterError> {
        if target.target_id != self.target_id || target.database_name != self.database_name {
            return Err(error("postgres_target_mismatch", "The requested target does not match this adapter's configured target."));
        }
        Ok(())
    }

    async fn connect_checked(&self) -> Result<Client, AdapterError> {
        let client = (self.connect)().await?;
        let row = client.query_one(
            "SELECT current_database(), current_user, to_char(clock_timestamp() AT TIME ZONE 'UTC', 'YYYY-MM-DD\"T\"HH24:MI:SS.US\"Z\"')",
            &[],
        ).await.map_err(db_error)?;
        let actual_database: String = row.get(0);
        if actual_database != self.database_name {
            return Err(error("postgres_database_mismatch", "The authenticated connection reached a different database."));
        }
        let _authenticated_role: String = row.get(1);
        Ok(client)
    }
}

impl DatabaseAdapter for PostgresCatalogAdapter {
    fn descriptor(&self) -> AdapterDescriptor {
        AdapterDescriptor {
            kind: DatabaseKind::PostgreSql,
            name: "PostgreSQL catalog adapter",
            maturity: AdapterMaturity::InDevelopment,
            capabilities: AdapterCapabilities {
                schema_inspection: true,
                policy_generation: true,
                ..AdapterCapabilities::default()
            },
            status_note: "Concrete read-only catalog inspection and review-only RLS policy generation are implemented. Semantic verification, controlled deployment, drift response and runtime admission are not production-complete.",
        }
    }

    fn inspect<'a>(
        &'a self,
        request: &'a InspectionRequest,
    ) -> AdapterFuture<'a, Result<InspectionSnapshot, AdapterError>> {
        Box::pin(async move {
            self.validate_target(&request.target)?;
            request.policy.validate().map_err(|_| error("invalid_policy", "The canonical tenant policy failed validation."))?;
            let client = self.connect_checked().await?;
            let mut resources = Vec::with_capacity(request.policy.resources.len());
            let mut snapshot_findings = Vec::new();
            let mut fingerprint_rows = Vec::new();
            let mut complete = true;

            for protected in &request.policy.resources {
                if protected.resource.kind != ResourceKind::Table {
                    complete = false;
                    snapshot_findings.push(finding("unsupported_resource_kind", &protected.resource, "The PostgreSQL catalog adapter currently inspects ordinary tables only."));
                    continue;
                }
                let schema = protected.resource.namespace.as_deref().unwrap_or("public");
                let row = client.query_opt(
                    "SELECT c.relrowsecurity, c.relforcerowsecurity, owner.rolsuper, owner.rolbypassrls, (SELECT count(*)::bigint FROM pg_catalog.pg_policies p WHERE p.schemaname=n.nspname AND p.tablename=c.relname), c.relkind::text FROM pg_catalog.pg_class c JOIN pg_catalog.pg_namespace n ON n.oid=c.relnamespace JOIN pg_catalog.pg_roles owner ON owner.oid=c.relowner WHERE n.nspname=$1 AND c.relname=$2 AND c.relkind IN ('r','p')",
                    &[&schema, &protected.resource.name],
                ).await.map_err(db_error)?;

                let Some(row) = row else {
                    complete = false;
                    snapshot_findings.push(finding("protected_resource_not_found", &protected.resource, "The requested relation was not found as a table or partitioned table."));
                    resources.push(ResourceInspection {
                        resource: protected.clone(),
                        completeness: InspectionCompleteness::Incomplete,
                        posture: SecurityPosture::Blocked,
                        verified_operations: Vec::new(),
                        findings: vec![finding("protected_resource_not_found", &protected.resource, "The requested relation was not found.")],
                        fingerprint: None,
                    });
                    continue;
                };

                let rls_enabled: bool = row.get(0);
                let rls_forced: bool = row.get(1);
                let owner_superuser: bool = row.get(2);
                let owner_bypass: bool = row.get(3);
                let policy_count: i64 = row.get(4);
                let relkind: String = row.get(5);
                let mut findings = Vec::new();
                if !rls_enabled { findings.push(finding("rls_disabled", &protected.resource, "Row-level security is disabled.")); }
                if !rls_forced { findings.push(finding("rls_not_forced", &protected.resource, "Table-owner access is not forced through row-level security.")); }
                if owner_superuser || owner_bypass { findings.push(finding("owner_bypasses_rls", &protected.resource, "The relation owner has SUPERUSER or BYPASSRLS.")); }
                if policy_count == 0 { findings.push(finding("no_native_policies", &protected.resource, "No PostgreSQL row-security policies are attached to this relation.")); }
                if relkind == "p" { findings.push(finding("partitioned_relation_requires_child_audit", &protected.resource, "Partitioned tables require independent inspection of every directly addressable child partition.")); }
                // A policy count is not proof of tenant semantics. Never turn
                // catalog presence into verified operations or an allow result.
                findings.push(finding("semantic_verification_required", &protected.resource, "Native policy expressions and cross-tenant allow/deny behavior have not been independently verified."));
                let state = json!({
                    "schema": schema, "table": protected.resource.name, "rls_enabled": rls_enabled,
                    "rls_forced": rls_forced, "owner_superuser": owner_superuser,
                    "owner_bypassrls": owner_bypass, "policy_count": policy_count, "relkind": relkind
                });
                let digest = sha256(&serde_json::to_vec(&state).map_err(|_| error("fingerprint_serialization_failed", "Could not serialize PostgreSQL catalog state."))?);
                fingerprint_rows.push(state);
                resources.push(ResourceInspection {
                    resource: protected.clone(),
                    completeness: InspectionCompleteness::Complete,
                    posture: if rls_enabled && rls_forced && !owner_superuser && !owner_bypass && policy_count > 0 { SecurityPosture::NeedsAttention } else { SecurityPosture::Blocked },
                    verified_operations: Vec::new(),
                    findings,
                    fingerprint: Some(digest),
                });
            }

            let clock = client.query_one("SELECT to_char(clock_timestamp() AT TIME ZONE 'UTC', 'YYYY-MM-DD\"T\"HH24:MI:SS.US\"Z\"')", &[]).await.map_err(db_error)?;
            let observed_at: String = clock.get(0);
            let fingerprint = sha256(&serde_json::to_vec(&fingerprint_rows).map_err(|_| error("fingerprint_serialization_failed", "Could not serialize PostgreSQL catalog state."))?);
            snapshot_findings.push(SecurityFinding {
                code: "semantic_verification_not_performed".into(),
                resource: None,
                detail: "Read-only catalog inspection is not sufficient to authorize tenant traffic. Run independent positive and cross-tenant negative probes.".into(),
            });
            Ok(InspectionSnapshot {
                database_kind: DatabaseKind::PostgreSql,
                target: request.target.clone(),
                completeness: if complete { InspectionCompleteness::Complete } else { InspectionCompleteness::Incomplete },
                posture: SecurityPosture::NeedsAttention,
                resources,
                findings: snapshot_findings,
                fingerprint: Some(fingerprint),
                observed_at,
            })
        })
    }

    fn compile_policy(&self, policy: &TenantSecurityPolicy) -> Result<CompiledPolicy, AdapterError> {
        policy.validate().map_err(|_| error("invalid_policy", "The canonical tenant policy failed validation."))?;
        let mut changes = Vec::with_capacity(policy.resources.len());
        for protected in &policy.resources {
            if protected.resource.kind != ResourceKind::Table {
                return Err(error("unsupported_resource_kind", "PostgreSQL RLS plan generation currently supports table resources only."));
            }
            let schema = protected.resource.namespace.as_deref().unwrap_or("public");
            let relation = format!("{}.{}", quote_ident(schema), quote_ident(&protected.resource.name));
            let tenant_column = quote_ident(&protected.tenant_key);
            let tenant_expression = format!("({tenant_column})::text = current_setting('proxima.tenant_id', true)");
            let mut statements = Vec::new();
            for operation in &protected.operations {
                let command = match operation {
                    Operation::Read => "SELECT",
                    Operation::Create => "INSERT",
                    Operation::Update => "UPDATE",
                    Operation::Delete => "DELETE",
                    Operation::Execute => return Err(error("unsupported_operation", "EXECUTE is not a table-level PostgreSQL RLS operation.")),
                };
                let seed = format!("{}:{}:{}:{}:{:?}", policy.policy_id, policy.revision, schema, protected.resource.name, operation);
                let suffix = &sha256(seed.as_bytes())[..16];
                let policy_name = format!("proxima_{}_{}", safe_name(&policy.policy_id), suffix);
                let statement = match operation {
                    Operation::Read | Operation::Delete => format!("CREATE POLICY {} ON {} AS RESTRICTIVE FOR {} TO PUBLIC USING ({})", quote_ident(&policy_name), relation, command, tenant_expression),
                    Operation::Create => format!("CREATE POLICY {} ON {} AS RESTRICTIVE FOR {} TO PUBLIC WITH CHECK ({})", quote_ident(&policy_name), relation, command, tenant_expression),
                    Operation::Update => format!("CREATE POLICY {} ON {} AS RESTRICTIVE FOR {} TO PUBLIC USING ({}) WITH CHECK ({})", quote_ident(&policy_name), relation, command, tenant_expression, tenant_expression),
                    Operation::Execute => unreachable!(),
                };
                statements.push(statement);
            }
            changes.push(NativePolicyChange {
                resource: protected.clone(),
                action: "review_only_create_restrictive_rls_policies".into(),
                definition: json!({
                    "statements": statements,
                    "preconditions": [
                        "Apply only after independent review and explicit approval.",
                        "Enable and FORCE ROW LEVEL SECURITY on the relation.",
                        "Ensure the application role cannot own the table and has no BYPASSRLS or SUPERUSER membership.",
                        "Set proxima.tenant_id from a cryptographically authenticated tenant context on every transaction.",
                        "Verify every operation with positive own-tenant and negative cross-tenant probes.",
                        "Inspect and protect every directly addressable partition and view."
                    ],
                    "policy_id": policy.policy_id,
                    "revision": policy.revision,
                    "tenant_identity_claim": policy.tenant_identity_claim,
                    "tenant_setting": "proxima.tenant_id",
                    "execution": "not_executed"
                }),
            });
        }
        Ok(CompiledPolicy {
            database_kind: DatabaseKind::PostgreSql,
            policy_id: policy.policy_id.clone(),
            revision: policy.revision,
            changes,
            requires_approval: true,
        })
    }

    fn verify<'a>(
        &'a self,
        _policy: &'a TenantSecurityPolicy,
        snapshot: &'a InspectionSnapshot,
    ) -> AdapterFuture<'a, Result<VerificationReport, AdapterError>> {
        Box::pin(async move {
            let mut findings = snapshot.findings.clone();
            findings.push(SecurityFinding {
                code: "independent_tenant_probes_required".into(),
                resource: None,
                detail: "The adapter does not claim semantic verification until authenticated tenant sessions prove own-tenant access and deny cross-tenant read/write operations.".into(),
            });
            Ok(VerificationReport {
                model_version: SECURITY_MODEL_VERSION.into(),
                posture: SecurityPosture::NeedsAttention,
                inspection: snapshot.completeness,
                findings,
            })
        })
    }

    fn detect_drift<'a>(
        &'a self,
        target: &'a AdapterTarget,
        previous_fingerprint: Option<&'a str>,
    ) -> AdapterFuture<'a, Result<DriftReport, AdapterError>> {
        Box::pin(async move {
            self.validate_target(target)?;
            if previous_fingerprint.is_some_and(|value| value.len() != 64 || !value.bytes().all(|b| b.is_ascii_hexdigit())) {
                return Err(error("invalid_previous_fingerprint", "The previous catalog fingerprint must be a SHA-256 hex digest."));
            }
            let client = self.connect_checked().await?;
            let rows = client.query(
                "SELECT n.nspname, c.relname, c.relrowsecurity, c.relforcerowsecurity, COALESCE((SELECT string_agg(p.polname || ':' || p.polcmd || ':' || p.polpermissive::text, ',' ORDER BY p.polname) FROM pg_catalog.pg_policy p WHERE p.polrelid=c.oid), '') FROM pg_catalog.pg_class c JOIN pg_catalog.pg_namespace n ON n.oid=c.relnamespace WHERE c.relkind IN ('r','p') AND n.nspname NOT IN ('pg_catalog','information_schema') AND n.nspname NOT LIKE 'pg_%' ORDER BY n.nspname,c.relname",
                &[],
            ).await.map_err(db_error)?;
            let state: Vec<serde_json::Value> = rows.into_iter().map(|row| json!({
                "schema": row.get::<_, String>(0), "table": row.get::<_, String>(1),
                "rls_enabled": row.get::<_, bool>(2), "rls_forced": row.get::<_, bool>(3),
                "policies": row.get::<_, String>(4)
            })).collect();
            let fingerprint = sha256(&serde_json::to_vec(&state).map_err(|_| error("fingerprint_serialization_failed", "Could not serialize PostgreSQL catalog state."))?);
            let clock = client.query_one("SELECT to_char(clock_timestamp() AT TIME ZONE 'UTC', 'YYYY-MM-DD\"T\"HH24:MI:SS.US\"Z\"')", &[]).await.map_err(db_error)?;
            let observed_at: String = clock.get(0);
            Ok(DriftReport {
                database_kind: DatabaseKind::PostgreSql,
                target: target.clone(),
                detected: previous_fingerprint.is_some_and(|previous| previous != fingerprint),
                completeness: InspectionCompleteness::Complete,
                previous_fingerprint: previous_fingerprint.map(str::to_owned),
                observed_fingerprint: Some(fingerprint),
                findings: Vec::new(),
                observed_at,
            })
        })
    }
}

fn error(code: &str, detail: &str) -> AdapterError {
    AdapterError { code: code.into(), detail: detail.into(), retryable: false }
}

fn db_error(error: tokio_postgres::Error) -> AdapterError {
    AdapterError { code: "postgres_catalog_query_failed".into(), detail: error.to_string(), retryable: error.is_closed() }
}

fn finding(code: &str, resource: &crate::security_core::ResourceRef, detail: &str) -> SecurityFinding {
    SecurityFinding { code: code.into(), resource: Some(resource.clone()), detail: detail.into() }
}

fn sha256(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}

fn quote_ident(value: &str) -> String {
    format!("\"{}\"", value.replace('"', "\"\""))
}

fn safe_name(value: &str) -> String {
    let normalized: String = value.chars().map(|character| {
        if character.is_ascii_alphanumeric() || character == '_' { character.to_ascii_lowercase() } else { '_' }
    }).take(24).collect();
    if normalized.is_empty() { "policy".into() } else { normalized }
}
