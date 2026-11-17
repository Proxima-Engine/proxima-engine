//! Native MySQL/MariaDB catalog inspection adapter.
//!
//! This adapter discovers schemas, tables, views, routines and grants over a
//! TLS-verified MySQL protocol connection. It deliberately denies admission:
//! MySQL has no PostgreSQL-equivalent row-level security, and a catalog scan
//! cannot prove that a database-per-tenant runtime mapping is enforced.

use crate::database_adapter::{
    AdapterError, AdapterFuture, AdapterTarget, CompiledPolicy, DatabaseAdapter,
    DiscoveryRequest, DiscoverySnapshot, DiscoveredResource, DriftReport,
    InspectionRequest, InspectionSnapshot, ResourceInspection,
};
use crate::native_policy_plans::compile_mysql_database_boundary;
use crate::security_core::{
    AdapterCapabilities, AdapterDescriptor, AdapterMaturity, DatabaseKind,
    InspectionCompleteness, Operation, ResourceKind, ResourceRef, SecurityFinding,
    SecurityPosture, TenantSecurityPolicy, VerificationReport, SECURITY_MODEL_VERSION,
};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use sqlx::{
    mysql::{MySqlConnectOptions, MySqlConnection, MySqlSslMode},
    Connection, Row,
};
use std::str::FromStr;

pub struct MySqlCatalogAdapter {
    target_id: String,
    database_name: String,
    connection_url: String,
    kind: DatabaseKind,
}

impl MySqlCatalogAdapter {
    pub fn new(
        target_id: impl Into<String>,
        database_name: impl Into<String>,
        connection_url: impl Into<String>,
        kind: DatabaseKind,
    ) -> Result<Self, AdapterError> {
        let target_id = target_id.into();
        let database_name = database_name.into();
        let connection_url = connection_url.into();
        if target_id.trim().is_empty() || target_id.len() > 256 || target_id.contains('\0')
            || database_name.trim().is_empty() || database_name.len() > 64 || database_name.contains('\0')
            || connection_url.trim().is_empty() || connection_url.len() > 4096
        {
            return Err(error("invalid_mysql_target", "A bounded target ID, database name and connection URL are required."));
        }
        if !matches!(kind, DatabaseKind::MySql | DatabaseKind::MariaDb) {
            return Err(error("invalid_mysql_adapter_kind", "The MySQL wire adapter only accepts MySQL or MariaDB targets."));
        }
        Ok(Self { target_id, database_name, connection_url, kind })
    }

    fn validate_target(&self, target: &AdapterTarget) -> Result<(), AdapterError> {
        if target.target_id != self.target_id || target.database_name != self.database_name {
            return Err(error("mysql_target_mismatch", "The request does not match this adapter's registered database target."));
        }
        Ok(())
    }

    async fn connect_checked(&self) -> Result<MySqlConnection, AdapterError> {
        let mut options = MySqlConnectOptions::from_str(&self.connection_url)
            .map_err(|_| error("invalid_mysql_connection_config", "The MySQL connection URL could not be parsed."))?;
        options = options.ssl_mode(MySqlSslMode::VerifyIdentity);
        let mut connection = MySqlConnection::connect_with(&options).await.map_err(db_error)?;
        let row = sqlx::query("SELECT DATABASE() AS database_name, CURRENT_USER() AS authenticated_account")
            .fetch_one(&mut connection).await.map_err(db_error)?;
        let database: Option<String> = row.try_get("database_name").map_err(db_error)?;
        let account: String = row.try_get("authenticated_account").map_err(db_error)?;
        if database.as_deref() != Some(self.database_name.as_str()) {
            return Err(error("mysql_database_mismatch", "The authenticated connection reached a different database."));
        }
        if account.trim().is_empty() {
            return Err(error("mysql_identity_unavailable", "The server did not expose an authenticated account identity."));
        }
        // Catalog operations below are SELECT-only. No DDL, DML, role changes,
        // or privilege mutations are performed by this adapter.
        Ok(connection)
    }

    async fn discover_inner(
        &self,
        request: &DiscoveryRequest,
    ) -> Result<DiscoverySnapshot, AdapterError> {
        self.validate_target(&request.target)?;
        if request.namespace.as_ref().is_some_and(|namespace| {
            namespace.trim().is_empty() || namespace.len() > 64 || namespace.contains('\0')
                || namespace != &self.database_name
        }) {
            return Err(error("invalid_discovery_namespace", "MySQL discovery namespace must be the registered database name."));
        }
        let mut connection = self.connect_checked().await?;
        let table_rows = sqlx::query(
            "SELECT TABLE_SCHEMA,TABLE_NAME,TABLE_TYPE,ENGINE,ROW_FORMAT,CREATE_OPTIONS \
             FROM information_schema.TABLES WHERE TABLE_SCHEMA=? ORDER BY TABLE_NAME"
        ).bind(&self.database_name).fetch_all(&mut connection).await.map_err(db_error)?;
        let mut resources = Vec::with_capacity(table_rows.len());
        for row in table_rows {
            let schema: String = row.try_get("TABLE_SCHEMA").map_err(db_error)?;
            let name: String = row.try_get("TABLE_NAME").map_err(db_error)?;
            let table_type: String = row.try_get("TABLE_TYPE").map_err(db_error)?;
            let columns = sqlx::query(
                "SELECT COLUMN_NAME,COLUMN_TYPE,IS_NULLABLE,COLUMN_DEFAULT,EXTRA \
                 FROM information_schema.COLUMNS WHERE TABLE_SCHEMA=? AND TABLE_NAME=? ORDER BY ORDINAL_POSITION"
            ).bind(&schema).bind(&name).fetch_all(&mut connection).await.map_err(db_error)?;
            let privileges = sqlx::query(
                "SELECT GRANTEE,PRIVILEGE_TYPE,IS_GRANTABLE \
                 FROM information_schema.TABLE_PRIVILEGES WHERE TABLE_SCHEMA=? AND TABLE_NAME=? \
                 ORDER BY GRANTEE,PRIVILEGE_TYPE"
            ).bind(&schema).bind(&name).fetch_all(&mut connection).await.map_err(db_error)?;
            let schema_privileges = sqlx::query(
                "SELECT GRANTEE,PRIVILEGE_TYPE,IS_GRANTABLE \
                 FROM information_schema.SCHEMA_PRIVILEGES WHERE TABLE_SCHEMA=? ORDER BY GRANTEE,PRIVILEGE_TYPE"
            ).bind(&schema).fetch_all(&mut connection).await.map_err(db_error)?;
            let kind = if table_type.eq_ignore_ascii_case("VIEW") { ResourceKind::View } else { ResourceKind::Table };
            let attributes = json!({
                "table_type": table_type,
                "engine": row.try_get::<Option<String>,_>("ENGINE").map_err(db_error)?,
                "row_format": row.try_get::<Option<String>,_>("ROW_FORMAT").map_err(db_error)?,
                "create_options": row.try_get::<Option<String>,_>("CREATE_OPTIONS").map_err(db_error)?,
                "columns": columns.iter().map(|column| Ok(json!({
                    "name": column.try_get::<String,_>("COLUMN_NAME").map_err(db_error)?,
                    "type": column.try_get::<String,_>("COLUMN_TYPE").map_err(db_error)?,
                    "nullable": column.try_get::<String,_>("IS_NULLABLE").map_err(db_error)?,
                    "default": column.try_get::<Option<String>,_>("COLUMN_DEFAULT").map_err(db_error)?,
                    "extra": column.try_get::<String,_>("EXTRA").map_err(db_error)?
                }))).collect::<Result<Vec<_>,AdapterError>>()?,
                "table_privileges": privileges.iter().map(|grant| Ok(json!({
                    "grantee": grant.try_get::<String,_>("GRANTEE").map_err(db_error)?,
                    "privilege": grant.try_get::<String,_>("PRIVILEGE_TYPE").map_err(db_error)?,
                    "grantable": grant.try_get::<String,_>("IS_GRANTABLE").map_err(db_error)?
                }))).collect::<Result<Vec<_>,AdapterError>>()?,
                "schema_privileges": schema_privileges.iter().map(|grant| Ok(json!({
                    "grantee": grant.try_get::<String,_>("GRANTEE").map_err(db_error)?,
                    "privilege": grant.try_get::<String,_>("PRIVILEGE_TYPE").map_err(db_error)?,
                    "grantable": grant.try_get::<String,_>("IS_GRANTABLE").map_err(db_error)?
                }))).collect::<Result<Vec<_>,AdapterError>>()?
            });
            resources.push(DiscoveredResource {
                namespace: Some(schema),
                name,
                kind,
                owner: None,
                attributes,
            });
        }
        let routine_rows = sqlx::query(
            "SELECT ROUTINE_SCHEMA,ROUTINE_NAME,ROUTINE_TYPE,DEFINER,SECURITY_TYPE,SQL_DATA_ACCESS \
             FROM information_schema.ROUTINES WHERE ROUTINE_SCHEMA=? ORDER BY ROUTINE_NAME,ROUTINE_TYPE"
        ).bind(&self.database_name).fetch_all(&mut connection).await.map_err(db_error)?;
        for row in routine_rows {
            let routine_type: String = row.try_get("ROUTINE_TYPE").map_err(db_error)?;
            resources.push(DiscoveredResource {
                namespace: Some(row.try_get("ROUTINE_SCHEMA").map_err(db_error)?),
                name: row.try_get("ROUTINE_NAME").map_err(db_error)?,
                kind: if routine_type.eq_ignore_ascii_case("PROCEDURE") { ResourceKind::Procedure } else { ResourceKind::Function },
                owner: Some(row.try_get("DEFINER").map_err(db_error)?),
                attributes: json!({
                    "routine_type": routine_type,
                    "security_type": row.try_get::<String,_>("SECURITY_TYPE").map_err(db_error)?,
                    "sql_data_access": row.try_get::<String,_>("SQL_DATA_ACCESS").map_err(db_error)?
                }),
            });
        }
        let fingerprint = digest(&serde_json::to_vec(&resources)
            .map_err(|_| error("fingerprint_serialization_failed", "Could not serialize MySQL discovery results."))?);
        let observed_at: String = sqlx::query_scalar("SELECT DATE_FORMAT(UTC_TIMESTAMP(6),'%Y-%m-%dT%H:%i:%s.%fZ')")
            .fetch_one(&mut connection).await.map_err(db_error)?;
        Ok(DiscoverySnapshot {
            database_kind: self.kind,
            target: request.target.clone(),
            completeness: InspectionCompleteness::Complete,
            resources,
            findings: Vec::new(),
            fingerprint: Some(fingerprint),
            observed_at,
        })
    }
}

impl DatabaseAdapter for MySqlCatalogAdapter {
    fn descriptor(&self) -> AdapterDescriptor {
        AdapterDescriptor {
            kind: self.kind,
            name: if self.kind == DatabaseKind::MariaDb { "MariaDB catalog adapter" } else { "MySQL catalog adapter" },
            maturity: AdapterMaturity::InDevelopment,
            capabilities: AdapterCapabilities {
                schema_inspection: true,
                policy_generation: true,
                drift_detection: true,
                ..AdapterCapabilities::default()
            },
            status_note: "TLS-verified native catalog discovery and privilege inspection are implemented. Database-per-tenant grant plans are review-only; runtime tenant binding, independent probes, controlled deployment and signed native admission remain unavailable.",
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
            let mut resources = Vec::with_capacity(request.policy.resources.len());
            let mut findings = Vec::new();
            for protected in &request.policy.resources {
                let namespace = protected.resource.namespace.as_deref().unwrap_or(&self.database_name);
                if namespace != self.database_name {
                    return Err(error("mysql_resource_namespace_mismatch", "A MySQL resource must belong to the registered database target."));
                }
                let found = discovery.resources.iter().find(|resource| {
                    resource.namespace.as_deref() == Some(namespace)
                        && resource.name == protected.resource.name
                        && resource.kind == protected.resource.kind
                });
                let Some(found) = found else {
                    resources.push(ResourceInspection {
                        resource: protected.clone(),
                        completeness: InspectionCompleteness::Incomplete,
                        posture: SecurityPosture::Blocked,
                        verified_operations: Vec::new(),
                        findings: vec![finding("protected_resource_not_found", &protected.resource, "The registered resource was not found in information_schema.")],
                        fingerprint: None,
                    });
                    findings.push(finding("protected_resource_not_found", &protected.resource, "The registered resource was not found in information_schema."));
                    continue;
                };
                let mut resource_findings = Vec::new();
                if protected.resource.kind != ResourceKind::Table {
                    resource_findings.push(finding("unsupported_mysql_policy_resource", &protected.resource, "The current database-per-tenant compiler manages tables only."));
                }
                let columns = found.attributes["columns"].as_array().cloned().unwrap_or_default();
                let tenant_column = columns.iter().find(|column| column["name"].as_str() == Some(protected.tenant_key.as_str()));
                match tenant_column {
                    None => resource_findings.push(finding("tenant_ownership_column_missing", &protected.resource, "The policy tenant key does not exist on this table.")),
                    Some(column) if column["nullable"].as_str() != Some("NO") =>
                        resource_findings.push(finding("tenant_ownership_column_nullable", &protected.resource, "The policy tenant key allows NULL values.")),
                    _ => {}
                }
                resource_findings.push(finding("mysql_database_per_tenant_probe_required", &protected.resource, "MySQL has no native row-level security. Separate database grants must be tested with independent tenant principals before isolation can be verified."));
                let resource_fingerprint = digest(&serde_json::to_vec(&found.attributes)
                    .map_err(|_| error("fingerprint_serialization_failed", "Could not serialize MySQL resource inspection."))?);
                findings.extend(resource_findings.clone());
                resources.push(ResourceInspection {
                    resource: protected.clone(),
                    completeness: InspectionCompleteness::Complete,
                    posture: SecurityPosture::NeedsAttention,
                    verified_operations: Vec::new(),
                    findings: resource_findings,
                    fingerprint: Some(resource_fingerprint),
                });
            }
            Ok(InspectionSnapshot {
                database_kind: self.kind,
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
        compile_mysql_database_boundary(policy, self.kind)
    }

    fn verify<'a>(&'a self, policy: &'a TenantSecurityPolicy, snapshot: &'a InspectionSnapshot) -> AdapterFuture<'a, Result<VerificationReport, AdapterError>> {
        Box::pin(async move {
            if snapshot.database_kind != self.kind || snapshot.target.target_id != self.target_id
                || snapshot.target.database_name != self.database_name {
                return Err(error("mysql_snapshot_target_mismatch", "The inspection snapshot does not match this adapter target."));
            }
            let mut findings = snapshot.findings.clone();
            findings.push(SecurityFinding {
                code: "independent_tenant_probes_required".into(),
                resource: None,
                detail: format!("{} policy resources require own-tenant allow and cross-tenant deny probes using distinct database principals.", policy.resources.len()),
            });
            findings.push(SecurityFinding {
                code: "mysql_runtime_principal_binding_unavailable".into(),
                resource: None,
                detail: "No trusted MySQL protocol gateway currently binds authenticated tenant identity to a dedicated native account and database.".into(),
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
                database_kind: self.kind,
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

fn db_error(error: sqlx::Error) -> AdapterError {
    AdapterError {
        code: "mysql_catalog_query_failed".into(),
        detail: "The authenticated MySQL catalog operation failed.".into(),
        retryable: matches!(error, sqlx::Error::PoolTimedOut | sqlx::Error::Io(_) | sqlx::Error::Tls(_)),
    }
}
