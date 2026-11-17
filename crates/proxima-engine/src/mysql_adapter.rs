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
        MySqlConnectOptions::from_str(&connection_url)
            .map_err(|_| error("invalid_mysql_connection_config", "The MySQL connection URL could not be parsed."))?;
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
        let mut connection = tokio::time::timeout(
            std::time::Duration::from_secs(10),
            MySqlConnection::connect_with(&options),
        ).await.map_err(|_| error("mysql_connection_timeout", "The MySQL TLS connection exceeded the ten-second connection deadline."))?
            .map_err(db_error)?;
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
             FROM information_schema.TABLES WHERE TABLE_SCHEMA=? ORDER BY TABLE_NAME LIMIT 10001"
        ).bind(&self.database_name).fetch_all(&mut connection).await.map_err(db_error)?;
        let table_inventory_truncated = table_rows.len() > 10_000;
        let table_rows = table_rows.into_iter().take(10_000).collect::<Vec<_>>();
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
            let column_privileges = sqlx::query(
                "SELECT GRANTEE,COLUMN_NAME,PRIVILEGE_TYPE,IS_GRANTABLE \
                 FROM information_schema.COLUMN_PRIVILEGES WHERE TABLE_SCHEMA=? AND TABLE_NAME=? ORDER BY GRANTEE,COLUMN_NAME,PRIVILEGE_TYPE"
            ).bind(&schema).bind(&name).fetch_all(&mut connection).await.map_err(db_error)?;
            let schema_privileges = sqlx::query(
                "SELECT GRANTEE,PRIVILEGE_TYPE,IS_GRANTABLE \
                 FROM information_schema.SCHEMA_PRIVILEGES WHERE TABLE_SCHEMA=? ORDER BY GRANTEE,PRIVILEGE_TYPE"
            ).bind(&schema).fetch_all(&mut connection).await.map_err(db_error)?;
            let constraints = sqlx::query(
                "SELECT tc.CONSTRAINT_NAME,tc.CONSTRAINT_TYPE,kcu.COLUMN_NAME,kcu.REFERENCED_TABLE_SCHEMA,kcu.REFERENCED_TABLE_NAME,kcu.REFERENCED_COLUMN_NAME \
                 FROM information_schema.TABLE_CONSTRAINTS tc \
                 LEFT JOIN information_schema.KEY_COLUMN_USAGE kcu ON kcu.CONSTRAINT_SCHEMA=tc.CONSTRAINT_SCHEMA AND kcu.TABLE_NAME=tc.TABLE_NAME AND kcu.CONSTRAINT_NAME=tc.CONSTRAINT_NAME \
                 WHERE tc.TABLE_SCHEMA=? AND tc.TABLE_NAME=? ORDER BY tc.CONSTRAINT_NAME,kcu.ORDINAL_POSITION"
            ).bind(&schema).bind(&name).fetch_all(&mut connection).await.map_err(db_error)?;
            let partitions = sqlx::query(
                "SELECT PARTITION_NAME,SUBPARTITION_NAME,PARTITION_METHOD,SUBPARTITION_METHOD,PARTITION_EXPRESSION,SUBPARTITION_EXPRESSION                  FROM information_schema.PARTITIONS WHERE TABLE_SCHEMA=? AND TABLE_NAME=? ORDER BY PARTITION_ORDINAL_POSITION,SUBPARTITION_ORDINAL_POSITION"
            ).bind(&schema).bind(&name).fetch_all(&mut connection).await.map_err(db_error)?;
            let indexes = sqlx::query(
                "SELECT INDEX_NAME,NON_UNIQUE,SEQ_IN_INDEX,COLUMN_NAME,INDEX_TYPE \
                 FROM information_schema.STATISTICS WHERE TABLE_SCHEMA=? AND TABLE_NAME=? ORDER BY INDEX_NAME,SEQ_IN_INDEX"
            ).bind(&schema).bind(&name).fetch_all(&mut connection).await.map_err(db_error)?;
            let triggers = sqlx::query(
                "SELECT TRIGGER_NAME,EVENT_MANIPULATION,ACTION_TIMING,ACTION_STATEMENT,DEFINER,SQL_MODE \
                 FROM information_schema.TRIGGERS WHERE TRIGGER_SCHEMA=? AND EVENT_OBJECT_TABLE=? ORDER BY TRIGGER_NAME"
            ).bind(&schema).bind(&name).fetch_all(&mut connection).await.map_err(db_error)?;
            let kind = if table_type.eq_ignore_ascii_case("VIEW") { ResourceKind::View } else { ResourceKind::Table };
            let view_metadata = if kind == ResourceKind::View {
                let view = sqlx::query(
                    "SELECT VIEW_DEFINITION,CHECK_OPTION,IS_UPDATABLE,DEFINER,SECURITY_TYPE \
                     FROM information_schema.VIEWS WHERE TABLE_SCHEMA=? AND TABLE_NAME=?"
                ).bind(&schema).bind(&name).fetch_optional(&mut connection).await.map_err(db_error)?;
                view.map(|row| Ok(json!({
                    "definition": row.try_get::<Option<String>,_>("VIEW_DEFINITION").map_err(db_error)?,
                    "check_option": row.try_get::<String,_>("CHECK_OPTION").map_err(db_error)?,
                    "is_updatable": row.try_get::<String,_>("IS_UPDATABLE").map_err(db_error)?,
                    "definer": row.try_get::<String,_>("DEFINER").map_err(db_error)?,
                    "security_type": row.try_get::<String,_>("SECURITY_TYPE").map_err(db_error)?
                }))).transpose()?
            } else { None };
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
                "column_privileges": column_privileges.iter().map(|grant| Ok(json!({
                    "grantee": grant.try_get::<String,_>("GRANTEE").map_err(db_error)?,
                    "column": grant.try_get::<String,_>("COLUMN_NAME").map_err(db_error)?,
                    "privilege": grant.try_get::<String,_>("PRIVILEGE_TYPE").map_err(db_error)?,
                    "grantable": grant.try_get::<String,_>("IS_GRANTABLE").map_err(db_error)?
                }))).collect::<Result<Vec<_>,AdapterError>>()?,
                "schema_privileges": schema_privileges.iter().map(|grant| Ok(json!({
                    "grantee": grant.try_get::<String,_>("GRANTEE").map_err(db_error)?,
                    "privilege": grant.try_get::<String,_>("PRIVILEGE_TYPE").map_err(db_error)?,
                    "grantable": grant.try_get::<String,_>("IS_GRANTABLE").map_err(db_error)?
                }))).collect::<Result<Vec<_>,AdapterError>>()?,
                "constraints": constraints.iter().map(|item| Ok(json!({
                    "name": item.try_get::<String,_>("CONSTRAINT_NAME").map_err(db_error)?,
                    "type": item.try_get::<String,_>("CONSTRAINT_TYPE").map_err(db_error)?,
                    "column": item.try_get::<Option<String>,_>("COLUMN_NAME").map_err(db_error)?,
                    "referenced_schema": item.try_get::<Option<String>,_>("REFERENCED_TABLE_SCHEMA").map_err(db_error)?,
                    "referenced_table": item.try_get::<Option<String>,_>("REFERENCED_TABLE_NAME").map_err(db_error)?,
                    "referenced_column": item.try_get::<Option<String>,_>("REFERENCED_COLUMN_NAME").map_err(db_error)?
                }))).collect::<Result<Vec<_>,AdapterError>>()?,
                "partitions": partitions.iter().map(|item| Ok(json!({
                    "partition": item.try_get::<Option<String>,_>("PARTITION_NAME").map_err(db_error)?,
                    "subpartition": item.try_get::<Option<String>,_>("SUBPARTITION_NAME").map_err(db_error)?,
                    "method": item.try_get::<Option<String>,_>("PARTITION_METHOD").map_err(db_error)?,
                    "subpartition_method": item.try_get::<Option<String>,_>("SUBPARTITION_METHOD").map_err(db_error)?,
                    "expression": item.try_get::<Option<String>,_>("PARTITION_EXPRESSION").map_err(db_error)?,
                    "subpartition_expression": item.try_get::<Option<String>,_>("SUBPARTITION_EXPRESSION").map_err(db_error)?
                }))).collect::<Result<Vec<_>,AdapterError>>()?,
                "indexes": indexes.iter().map(|item| Ok(json!({
                    "name": item.try_get::<String,_>("INDEX_NAME").map_err(db_error)?,
                    "non_unique": item.try_get::<i64,_>("NON_UNIQUE").map_err(db_error)?,
                    "sequence": item.try_get::<i64,_>("SEQ_IN_INDEX").map_err(db_error)?,
                    "column": item.try_get::<Option<String>,_>("COLUMN_NAME").map_err(db_error)?,
                    "type": item.try_get::<String,_>("INDEX_TYPE").map_err(db_error)?
                }))).collect::<Result<Vec<_>,AdapterError>>()?,
                "triggers": triggers.iter().map(|item| Ok(json!({
                    "name": item.try_get::<String,_>("TRIGGER_NAME").map_err(db_error)?,
                    "event": item.try_get::<String,_>("EVENT_MANIPULATION").map_err(db_error)?,
                    "timing": item.try_get::<String,_>("ACTION_TIMING").map_err(db_error)?,
                    "statement": item.try_get::<String,_>("ACTION_STATEMENT").map_err(db_error)?,
                    "definer": item.try_get::<String,_>("DEFINER").map_err(db_error)?,
                    "sql_mode": item.try_get::<String,_>("SQL_MODE").map_err(db_error)?
                }))).collect::<Result<Vec<_>,AdapterError>>()?,
                "view": view_metadata
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
            "SELECT ROUTINE_SCHEMA,ROUTINE_NAME,ROUTINE_TYPE,DEFINER,SECURITY_TYPE,SQL_DATA_ACCESS,IS_DETERMINISTIC,SQL_MODE,ROUTINE_DEFINITION \
             FROM information_schema.ROUTINES WHERE ROUTINE_SCHEMA=? ORDER BY ROUTINE_NAME,ROUTINE_TYPE LIMIT 10001"
        ).bind(&self.database_name).fetch_all(&mut connection).await.map_err(db_error)?;
        let routine_inventory_truncated = routine_rows.len() > 10_000;
        let routine_rows = routine_rows.into_iter().take(10_000).collect::<Vec<_>>();
        for row in routine_rows {
            let routine_schema: String = row.try_get("ROUTINE_SCHEMA").map_err(db_error)?;
            let routine_name: String = row.try_get("ROUTINE_NAME").map_err(db_error)?;
            let routine_type: String = row.try_get("ROUTINE_TYPE").map_err(db_error)?;
            let parameters = sqlx::query(
                "SELECT PARAMETER_NAME,ORDINAL_POSITION,PARAMETER_MODE,DATA_TYPE \
                 FROM information_schema.PARAMETERS WHERE SPECIFIC_SCHEMA=? AND SPECIFIC_NAME=? ORDER BY ORDINAL_POSITION"
            ).bind(&routine_schema).bind(&routine_name).fetch_all(&mut connection).await.map_err(db_error)?;
            resources.push(DiscoveredResource {
                namespace: Some(routine_schema),
                name: routine_name,
                kind: if routine_type.eq_ignore_ascii_case("PROCEDURE") { ResourceKind::Procedure } else { ResourceKind::Function },
                owner: Some(row.try_get("DEFINER").map_err(db_error)?),
                attributes: json!({
                    "routine_type": routine_type,
                    "security_type": row.try_get::<String,_>("SECURITY_TYPE").map_err(db_error)?,
                    "sql_data_access": row.try_get::<String,_>("SQL_DATA_ACCESS").map_err(db_error)?,
                    "is_deterministic": row.try_get::<String,_>("IS_DETERMINISTIC").map_err(db_error)?,
                    "sql_mode": row.try_get::<String,_>("SQL_MODE").map_err(db_error)?,
                    "definition": row.try_get::<Option<String>,_>("ROUTINE_DEFINITION").map_err(db_error)?,
                    "parameters": parameters.iter().map(|parameter| Ok(json!({
                        "name": parameter.try_get::<Option<String>,_>("PARAMETER_NAME").map_err(db_error)?,
                        "position": parameter.try_get::<Option<i64>,_>("ORDINAL_POSITION").map_err(db_error)?,
                        "mode": parameter.try_get::<Option<String>,_>("PARAMETER_MODE").map_err(db_error)?,
                        "data_type": parameter.try_get::<Option<String>,_>("DATA_TYPE").map_err(db_error)?
                    }))).collect::<Result<Vec<_>,AdapterError>>()?
                }),
            });
        }
        let target_row = sqlx::query("SELECT DATABASE() AS database_name, CURRENT_USER() AS authenticated_account, VERSION() AS server_version")
            .fetch_one(&mut connection).await.map_err(db_error)?;
        let grants = sqlx::query("SHOW GRANTS FOR CURRENT_USER")
            .fetch_all(&mut connection).await.map_err(db_error)?;
        let account_grant_statements = grants.iter()
            .map(|row| row.try_get::<String,usize>(0).map_err(db_error))
            .collect::<Result<Vec<_>,AdapterError>>()?;
        let elevated_inspection_account = has_elevated_inspection_grants(&account_grant_statements);
        let active_roles_result: Result<Option<String>, sqlx::Error> = sqlx::query_scalar("SELECT CURRENT_ROLE()")
            .fetch_one(&mut connection).await;
        let active_roles_available = active_roles_result.is_ok();
        let active_roles = active_roles_result.ok().flatten();
        let global_privileges = sqlx::query(
            "SELECT PRIVILEGE_TYPE,IS_GRANTABLE FROM information_schema.USER_PRIVILEGES ORDER BY PRIVILEGE_TYPE"
        ).fetch_all(&mut connection).await.map_err(db_error)?;
        let routine_privileges = sqlx::query(
            "SELECT GRANTEE,ROUTINE_SCHEMA,ROUTINE_NAME,ROUTINE_TYPE,PRIVILEGE_TYPE,IS_GRANTABLE \
             FROM information_schema.ROUTINE_PRIVILEGES WHERE ROUTINE_SCHEMA=? ORDER BY ROUTINE_NAME,GRANTEE,PRIVILEGE_TYPE"
        ).bind(&self.database_name).fetch_all(&mut connection).await.map_err(db_error)?;
        let target_attributes = json!({
            "database": target_row.try_get::<Option<String>,_>("database_name").map_err(db_error)?,
            "authenticated_account": target_row.try_get::<String,_>("authenticated_account").map_err(db_error)?,
            "server_version": target_row.try_get::<String,_>("server_version").map_err(db_error)?,
            "authenticated_account_grants": account_grant_statements,
            "active_roles": active_roles,
            "active_roles_available": active_roles_available,
            "global_privileges": global_privileges.iter().map(|grant| Ok(json!({
                "privilege": grant.try_get::<String,_>("PRIVILEGE_TYPE").map_err(db_error)?,
                "grantable": grant.try_get::<String,_>("IS_GRANTABLE").map_err(db_error)?
            }))).collect::<Result<Vec<_>,AdapterError>>()?,
            "inspection_account_has_elevated_privileges": elevated_inspection_account,
            "routine_privileges": routine_privileges.iter().map(|grant| Ok(json!({
                "grantee": grant.try_get::<String,_>("GRANTEE").map_err(db_error)?,
                "routine_schema": grant.try_get::<String,_>("ROUTINE_SCHEMA").map_err(db_error)?,
                "routine": grant.try_get::<String,_>("ROUTINE_NAME").map_err(db_error)?,
                "routine_type": grant.try_get::<String,_>("ROUTINE_TYPE").map_err(db_error)?,
                "privilege": grant.try_get::<String,_>("PRIVILEGE_TYPE").map_err(db_error)?,
                "grantable": grant.try_get::<String,_>("IS_GRANTABLE").map_err(db_error)?
            }))).collect::<Result<Vec<_>,AdapterError>>()?,
            "tls_identity_verification_required": true
        });
        let fingerprint = digest(&serde_json::to_vec(&json!({"target":target_attributes,"resources":resources}))
            .map_err(|_| error("fingerprint_serialization_failed", "Could not serialize MySQL discovery results."))?);
        let observed_at: String = sqlx::query_scalar("SELECT DATE_FORMAT(UTC_TIMESTAMP(6),'%Y-%m-%dT%H:%i:%s.%fZ')")
            .fetch_one(&mut connection).await.map_err(db_error)?;
        Ok(DiscoverySnapshot {
            database_kind: self.kind,
            target: request.target.clone(),
            // information_schema visibility is privilege-filtered. Without a
            // separately attested inventory principal/metadata scope, absence
            // from this result cannot prove that a resource does not exist.
            completeness: InspectionCompleteness::Incomplete,
            target_attributes,
            resources,
            findings: {
                let mut findings = vec![SecurityFinding {
                    code: "mysql_catalog_visibility_not_proven".into(),
                    resource: None,
                    detail: "MySQL/MariaDB information_schema visibility is privilege-filtered; this inventory is limited to objects visible to the authenticated account and cannot certify full database coverage.".into(),
                }];
                if table_inventory_truncated || routine_inventory_truncated {
                    findings.push(SecurityFinding {
                        code: "mysql_catalog_inventory_truncated".into(),
                        resource: None,
                        detail: "The visible catalog exceeded the 10,000-table or 10,000-routine safety bound; discovery is truncated and cannot be treated as a complete inventory.".into(),
                    });
                }
                if elevated_inspection_account {
                    findings.push(SecurityFinding {
                        code: "mysql_inspection_account_overprivileged".into(),
                        resource: None,
                        detail: "The catalog inspection account has broad global or administrative privileges. Use a dedicated least-privilege inspection identity and keep it separate from application tenant principals.".into(),
                    });
                }
                findings
            },
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
            let mut findings = discovery.findings.clone();
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
                if found.kind == ResourceKind::View && found.attributes["view"].is_null() {
                    resource_findings.push(finding("mysql_view_security_metadata_unavailable", &protected.resource, "View security metadata was not visible; definer/invoker behavior cannot be verified."));
                } else if found.kind == ResourceKind::View
                    && found.attributes["view"]["security_type"].as_str().is_some_and(|value| value.eq_ignore_ascii_case("DEFINER")) {
                    resource_findings.push(finding("mysql_definer_view_requires_review", &protected.resource, "This view executes with definer privileges and may expose rows beyond the caller's direct grants."));
                }
                if found.attributes["triggers"].as_array().is_some_and(|triggers| !triggers.is_empty()) {
                    resource_findings.push(finding("mysql_trigger_definer_requires_review", &protected.resource, "Triggers execute in a definer security context; review every trigger body and definer privilege for tenant-boundary bypasses."));
                }
                if found.attributes["security_type"].as_str().is_some_and(|value| value.eq_ignore_ascii_case("DEFINER")) {
                    resource_findings.push(finding("mysql_definer_routine_requires_review", &protected.resource, "This stored routine executes with definer privileges and requires explicit tenant-boundary review."));
                }
                if matches!(protected.resource.kind, ResourceKind::Table | ResourceKind::View) {
                    let columns = found.attributes["columns"].as_array().cloned().unwrap_or_default();
                    let tenant_column = columns.iter().find(|column| column["name"].as_str() == Some(protected.tenant_key.as_str()));
                    match tenant_column {
                        None => resource_findings.push(finding("tenant_ownership_column_missing", &protected.resource, "The policy tenant key does not exist on this table or view.")),
                        Some(column) if column["nullable"].as_str() != Some("NO") =>
                            resource_findings.push(finding("tenant_ownership_column_nullable", &protected.resource, "The policy tenant key allows NULL values.")),
                        _ => {}
                    }
                } else {
                    let parameters = found.attributes["parameters"].as_array().cloned().unwrap_or_default();
                    let tenant_parameter = parameters.iter().find(|parameter| {
                        parameter["name"].as_str() == Some(protected.tenant_key.as_str())
                            && matches!(parameter["mode"].as_str(), Some("IN" | "INOUT"))
                    });
                    if tenant_parameter.is_none() {
                        resource_findings.push(finding("mysql_tenant_identity_parameter_missing", &protected.resource, "The routine does not expose the configured tenant identity as an IN or INOUT parameter."));
                    }
                }
                resource_findings.push(finding("mysql_database_per_tenant_probe_required", &protected.resource, "MySQL has no native row-level security. Separate database grants must be tested with independent tenant principals before isolation can be verified."));
                let resource_fingerprint = digest(&serde_json::to_vec(&found.attributes)
                    .map_err(|_| error("fingerprint_serialization_failed", "Could not serialize MySQL resource inspection."))?);
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

fn has_elevated_inspection_grants(grants: &[String]) -> bool {
    grants.iter().any(|grant| {
        let upper = grant.to_ascii_uppercase();
        upper.contains("ALL PRIVILEGES ON *.*")
            || upper.contains("WITH GRANT OPTION")
            || upper.contains(" SUPER ")
            || upper.contains("SYSTEM_USER")
            || upper.contains("ROLE_ADMIN")
            || upper.contains("CREATE USER")
    })
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn accepts_only_mysql_family_database_kinds() {
        assert!(MySqlCatalogAdapter::new("target", "app", "mysql://localhost/app", DatabaseKind::PostgreSql).is_err());
        assert!(MySqlCatalogAdapter::new("target", "app", "mysql://localhost/app", DatabaseKind::MySql).is_ok());
        assert!(MySqlCatalogAdapter::new("target", "app", "mysql://localhost/app", DatabaseKind::MariaDb).is_ok());
    }

    #[test]
    fn descriptor_exposes_inspection_and_drift_but_not_admission() {
        let adapter = MySqlCatalogAdapter::new("target", "app", "mysql://localhost/app", DatabaseKind::MySql).unwrap();
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

    #[test]
    fn rejects_invalid_connection_urls_before_network_access() {
        assert!(MySqlCatalogAdapter::new("target", "app", "not-a-mysql-url", DatabaseKind::MySql).is_err());
        assert!(MySqlCatalogAdapter::new("target", "app", "postgres://localhost/app", DatabaseKind::MySql).is_err());
    }

    #[test]
    fn identifies_global_and_administrative_inspection_grants() {
        assert!(has_elevated_inspection_grants(&[
            "GRANT SELECT ON app.* TO 'auditor'@'%'".into(),
            "GRANT ALL PRIVILEGES ON *.* TO 'auditor'@'%'".into(),
        ]));
        assert!(has_elevated_inspection_grants(&[
            "GRANT SELECT ON app.* TO 'auditor'@'%' WITH GRANT OPTION".into(),
        ]));
        assert!(!has_elevated_inspection_grants(&[
            "GRANT SELECT, SHOW VIEW ON app.* TO 'auditor'@'%'".into(),
        ]));
    }

    #[tokio::test]
    async fn discovery_rejects_a_different_registered_target_before_connecting() {
        let adapter = MySqlCatalogAdapter::new("target-a", "app", "mysql://localhost/app", DatabaseKind::MySql).unwrap();
        let request = DiscoveryRequest {
            target: AdapterTarget { target_id: "target-b".into(), database_name: "app".into(), namespace: None },
            namespace: None,
        };
        assert_eq!(adapter.discover(&request).await.unwrap_err().code, "mysql_target_mismatch");
    }

    #[tokio::test]
    async fn verification_never_allows_catalog_only_mysql_evidence() {
        use crate::security_core::{ProtectedResource, ResourceRef};
        let adapter = MySqlCatalogAdapter::new("target", "app", "mysql://localhost/app", DatabaseKind::MySql).unwrap();
        let policy = TenantSecurityPolicy {
            schema_version: SECURITY_MODEL_VERSION.into(),
            policy_id: "tenant-policy".into(),
            revision: 1,
            tenant_identity_claim: "tenant_id".into(),
            resources: vec![ProtectedResource {
                resource: ResourceRef { namespace: Some("app".into()), name: "records".into(), kind: ResourceKind::Table },
                tenant_key: "tenant_id".into(),
                operations: vec![Operation::Read],
            }],
        };
        let snapshot = InspectionSnapshot {
            database_kind: DatabaseKind::MySql,
            target: AdapterTarget { target_id: "target".into(), database_name: "app".into(), namespace: None },
            completeness: InspectionCompleteness::Complete,
            posture: SecurityPosture::Verified,
            resources: Vec::new(),
            findings: Vec::new(),
            fingerprint: Some("a".repeat(64)),
            observed_at: "2026-11-17T00:00:00Z".into(),
        };
        let report = adapter.verify(&policy, &snapshot).await.unwrap();
        assert_eq!(report.posture, SecurityPosture::Blocked);
        assert!(!report.findings.is_empty());
    }

    #[test]
    fn rejects_unbounded_or_empty_target_configuration() {
        assert!(MySqlCatalogAdapter::new("", "app", "mysql://localhost/app", DatabaseKind::MySql).is_err());
        assert!(MySqlCatalogAdapter::new("target", &"d".repeat(65), "mysql://localhost/app", DatabaseKind::MySql).is_err());
    }
}
