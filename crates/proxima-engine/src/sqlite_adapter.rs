//! SQLite native schema and filesystem discovery adapter.
//!
//! SQLite has no native users, row-level security or tenant-scoped database
//! principals. This adapter opens the file read-only, inspects schema objects
//! and filesystem permission bits, and never claims tenant isolation.
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
use sqlx::{
    sqlite::{SqliteConnectOptions, SqliteConnection},
    Connection, Row,
};
use std::{path::PathBuf, str::FromStr, time::Duration};

pub struct SqliteCatalogAdapter {
    target_id: String,
    database_path: PathBuf,
    connection_uri: String,
}

impl SqliteCatalogAdapter {
    pub fn new(
        target_id: impl Into<String>,
        database_path: impl Into<PathBuf>,
        connection_uri: impl Into<String>,
    ) -> Result<Self, AdapterError> {
        let target_id = target_id.into();
        let database_path = database_path.into();
        let connection_uri = connection_uri.into();
        if target_id.trim().is_empty() || target_id.len() > 256 || target_id.contains('\0')
            || connection_uri.trim().is_empty() || connection_uri.len() > 4096
            || connection_uri.contains('?') || connection_uri.contains('#')
            || !database_path.is_absolute()
        {
            return Err(error("invalid_sqlite_target", "A bounded target ID, absolute database file path and SQLite connection URI are required."));
        }
        if !connection_uri.to_ascii_lowercase().starts_with("sqlite:") || connection_uri.to_ascii_lowercase().contains(":memory:") {
            return Err(error("sqlite_file_database_required", "SQLite tenant discovery requires a persistent file database; in-memory databases are not accepted."));
        }
        let canonical_path = std::fs::canonicalize(&database_path)
            .map_err(|_| error("sqlite_database_file_unavailable", "The registered SQLite database file does not exist or cannot be canonicalized."))?;
        if !canonical_path.is_file() {
            return Err(error("sqlite_database_path_not_file", "The registered SQLite database path must identify a regular file."));
        }
        SqliteConnectOptions::from_str(&connection_uri)
            .map_err(|_| error("invalid_sqlite_connection_uri", "The SQLite connection URI could not be parsed."))?;
        Ok(Self { target_id, database_path: canonical_path, connection_uri })
    }

    fn validate_target(&self, target: &AdapterTarget) -> Result<(), AdapterError> {
        if target.target_id != self.target_id {
            return Err(error("sqlite_target_mismatch", "The request does not match this registered SQLite target ID."));
        }
        let requested = std::fs::canonicalize(&target.database_name)
            .map_err(|_| error("sqlite_target_path_unavailable", "The requested SQLite database path cannot be canonicalized."))?;
        if requested != self.database_path {
            return Err(error("sqlite_target_mismatch", "The request points to a different SQLite database file."));
        }
        Ok(())
    }

    async fn connect_checked(&self) -> Result<SqliteConnection, AdapterError> {
        let options = SqliteConnectOptions::from_str(&self.connection_uri)
            .map_err(|_| error("invalid_sqlite_connection_uri", "The SQLite connection URI could not be parsed."))?
            .read_only(true)
            .create_if_missing(false)
            .busy_timeout(Duration::from_secs(5))
            .pragma("query_only", "ON")
            .pragma("trusted_schema", "OFF")
            .statement_cache_capacity(32);
        let mut connection = tokio::time::timeout(
            Duration::from_secs(10),
            SqliteConnection::connect_with(&options),
        ).await.map_err(|_| AdapterError {
            code: "sqlite_connection_timeout".into(),
            detail: "Opening the read-only SQLite database exceeded ten seconds.".into(),
            retryable: true,
        })?.map_err(db_error)?;
        let databases = sqlx::query("PRAGMA database_list").fetch_all(&mut connection).await.map_err(db_error)?;
        let mut main_path = None;
        for database in databases {
            let name: String = database.try_get("name").map_err(db_error)?;
            let file: String = database.try_get("file").map_err(db_error)?;
            if name == "main" {
                main_path = Some(file);
            } else if name != "temp" {
                return Err(error("sqlite_attached_database_rejected", "Attached SQLite databases are not accepted because they expand the inspection boundary."));
            }
        }
        let actual_path = main_path.ok_or_else(|| error("sqlite_main_database_missing", "SQLite did not report a main database file."))?;
        let actual_path = std::fs::canonicalize(actual_path)
            .map_err(|_| error("sqlite_database_path_unavailable", "The connected SQLite main database file cannot be canonicalized."))?;
        if actual_path != self.database_path {
            return Err(error("sqlite_database_mismatch", "The authenticated connection opened a different SQLite database file."));
        }
        Ok(connection)
    }

    async fn discover_inner(&self, request: &DiscoveryRequest) -> Result<DiscoverySnapshot, AdapterError> {
        self.validate_target(&request.target)?;
        if request.namespace.is_some() {
            return Err(error("sqlite_namespace_unsupported", "SQLite discovery does not accept a schema namespace; use the main database file."));
        }
        let mut connection = self.connect_checked().await?;
        let schema_rows = sqlx::query(
            "SELECT type,name,tbl_name,sql FROM sqlite_master \
             WHERE type IN ('table','view') AND name NOT GLOB 'sqlite_*' \
             ORDER BY type,name LIMIT 10001"
        ).fetch_all(&mut connection).await.map_err(db_error)?;
        let truncated = schema_rows.len() > 10_000;
        let mut resources = Vec::with_capacity(schema_rows.len().min(10_000));
        let mut state = Vec::new();
        let mut findings = Vec::new();
        for row in schema_rows.into_iter().take(10_000) {
            let object_type: String = row.try_get("type").map_err(db_error)?;
            let name: String = row.try_get("name").map_err(db_error)?;
            let table_name: String = row.try_get("tbl_name").map_err(db_error)?;
            let definition: Option<String> = row.try_get("sql").map_err(db_error)?;
            let kind = if object_type == "view" { ResourceKind::View } else { ResourceKind::Table };
            // SQLite's table-valued PRAGMA functions support both tables and views.
            let columns = sqlx::query("SELECT cid,name,type,[notnull],dflt_value,pk,hidden FROM pragma_table_xinfo(?) ORDER BY cid")
                .bind(&name).fetch_all(&mut connection).await.map_err(db_error)?;
            let indexes = if kind == ResourceKind::Table {
                sqlx::query("SELECT seq,name,[unique],origin,partial FROM pragma_index_list(?) ORDER BY seq")
                    .bind(&name).fetch_all(&mut connection).await.map_err(db_error)?
            } else { Vec::new() };
            let foreign_keys = if kind == ResourceKind::Table {
                sqlx::query("SELECT id,seq,[table],[from],[to],on_update,on_delete,[match] FROM pragma_foreign_key_list(?) ORDER BY id,seq")
                    .bind(&name).fetch_all(&mut connection).await.map_err(db_error)?
            } else { Vec::new() };
            let mut index_state = Vec::new();
            for index in &indexes {
                let index_name: String = index.try_get("name").map_err(db_error)?;
                let index_columns = sqlx::query("SELECT seqno,cid,name,[desc],coll,key FROM pragma_index_xinfo(?) ORDER BY seqno")
                    .bind(&index_name).fetch_all(&mut connection).await.map_err(db_error)?;
                index_state.push(json!({
                    "sequence": index.try_get::<i64,_>("seq").map_err(db_error)?,
                    "name": index_name,
                    "unique": index.try_get::<i64,_>("unique").map_err(db_error)? != 0,
                    "origin": index.try_get::<String,_>("origin").map_err(db_error)?,
                    "partial": index.try_get::<i64,_>("partial").map_err(db_error)? != 0,
                    "columns": index_columns.iter().map(|column| json!({
                        "sequence": column.get::<i64,_>("seqno"),
                        "column_id": column.get::<i64,_>("cid"),
                        "name": column.get::<Option<String>,_>("name"),
                        "descending": column.get::<i64,_>("desc") != 0,
                        "collation": column.get::<Option<String>,_>("coll"),
                        "key_column": column.get::<i64,_>("key") != 0
                    })).collect::<Vec<_>>()
                }));
            }
            let triggers = sqlx::query(
                "SELECT name,sql FROM sqlite_master WHERE type='trigger' AND tbl_name=? ORDER BY name"
            ).bind(&table_name).fetch_all(&mut connection).await.map_err(db_error)?;
            let attributes = json!({
                "sqlite_object_type": object_type,
                "definition": definition,
                "columns": columns.iter().map(|column| json!({
                    "ordinal": column.get::<i64,_>("cid"),
                    "name": column.get::<String,_>("name"),
                    "type": column.get::<String,_>("type"),
                    "not_null": column.get::<i64,_>("notnull") != 0,
                    "default": column.get::<Option<String>,_>("dflt_value"),
                    "primary_key_ordinal": column.get::<i64,_>("pk"),
                    "hidden": column.get::<i64,_>("hidden")
                })).collect::<Vec<_>>(),
                "indexes": index_state,
                "foreign_keys": foreign_keys.iter().map(|foreign_key| json!({
                    "id": foreign_key.get::<i64,_>("id"),
                    "sequence": foreign_key.get::<i64,_>("seq"),
                    "referenced_table": foreign_key.get::<String,_>("table"),
                    "from": foreign_key.get::<String,_>("from"),
                    "to": foreign_key.get::<Option<String>,_>("to"),
                    "on_update": foreign_key.get::<String,_>("on_update"),
                    "on_delete": foreign_key.get::<String,_>("on_delete"),
                    "match": foreign_key.get::<String,_>("match")
                })).collect::<Vec<_>>(),
                "triggers": triggers.iter().map(|trigger| json!({
                    "name": trigger.get::<String,_>("name"),
                    "definition": trigger.get::<Option<String>,_>("sql")
                })).collect::<Vec<_>>()
            });
            let reference = ResourceRef { namespace: None, name: name.clone(), kind };
            if kind == ResourceKind::View {
                findings.push(SecurityFinding {
                    code: "sqlite_view_requires_dependency_review".into(),
                    resource: Some(reference.clone()),
                    detail: "SQLite views do not provide tenant isolation; review their complete dependency graph and application access paths.".into(),
                });
            }
            resources.push(DiscoveredResource {
                namespace: None,
                name: name.clone(),
                kind,
                owner: None,
                attributes: attributes.clone(),
            });
            state.push(json!({ "name": name, "kind": object_type, "attributes": attributes }));
        }
        if truncated {
            findings.push(SecurityFinding {
                code: "sqlite_inventory_truncated".into(),
                resource: None,
                detail: "The SQLite schema exceeded 10,000 tables/views; the inventory is incomplete.".into(),
            });
        }
        let database_list = sqlx::query("PRAGMA database_list").fetch_all(&mut connection).await.map_err(db_error)?;
        let file_row = database_list.iter().find(|row| row.get::<String,_>("name") == "main")
            .ok_or_else(|| error("sqlite_main_database_missing", "SQLite did not report its main database file."))?;
        let file: String = file_row.try_get("file").map_err(db_error)?;
        let file_metadata = std::fs::metadata(&self.database_path)
            .map_err(|_| error("sqlite_file_metadata_unavailable", "The SQLite database file metadata could not be read."))?;
        let parent_metadata = self.database_path.parent().and_then(|path| std::fs::metadata(path).ok());
        let wal_path = PathBuf::from(format!("{}-wal", self.database_path.display()));
        let shm_path = PathBuf::from(format!("{}-shm", self.database_path.display()));
        let wal_metadata = std::fs::metadata(wal_path).ok();
        let shm_metadata = std::fs::metadata(shm_path).ok();
        let filesystem = filesystem_permissions(
            &file_metadata,
            parent_metadata.as_ref(),
            wal_metadata.as_ref(),
            shm_metadata.as_ref(),
        );
        if filesystem.unsafe_permissions {
            findings.push(SecurityFinding {
                code: "sqlite_filesystem_permissions_too_broad".into(),
                resource: None,
                detail: "The database file or containing directory grants group/other access. SQLite tenant isolation depends on OS-level file and directory permissions.".into(),
            });
        }
        if !filesystem.assessed {
            findings.push(SecurityFinding {
                code: "sqlite_filesystem_acl_not_assessed".into(),
                resource: None,
                detail: "This platform does not expose the filesystem ACL detail required to assess tenant-exclusive file access.".into(),
            });
        }
        let pragma_rows = sqlx::query("PRAGMA foreign_keys").fetch_all(&mut connection).await.map_err(db_error)?;
        let foreign_keys_enabled = pragma_rows.first().and_then(|row| row.try_get::<i64,_>(0).ok()).unwrap_or(0) != 0;
        let journal_mode: String = sqlx::query_scalar("PRAGMA journal_mode").fetch_one(&mut connection).await.map_err(db_error)?;
        let user_version: i64 = sqlx::query_scalar("PRAGMA user_version").fetch_one(&mut connection).await.map_err(db_error)?;
        let application_id: i64 = sqlx::query_scalar("PRAGMA application_id").fetch_one(&mut connection).await.map_err(db_error)?;
        let target_attributes = json!({
            "database_file": file,
            "filesystem_permissions": filesystem,
            "inspection_connection_foreign_keys_enabled": foreign_keys_enabled,
            "journal_mode": journal_mode,
            "user_version": user_version,
            "application_id": application_id,
            "read_only_connection": true,
            "query_only": true,
            "inspection_connection_trusted_schema_disabled": true
        });
        let fingerprint = digest(&serde_json::to_vec(&json!({ "target_id": self.target_id, "database_path": self.database_path, "target": target_attributes, "resources": state }))
            .map_err(|_| error("sqlite_fingerprint_failed", "Could not serialize SQLite catalog state."))?);
        Ok(DiscoverySnapshot {
            database_kind: DatabaseKind::Sqlite,
            target: request.target.clone(),
            completeness: if truncated || !filesystem.assessed { InspectionCompleteness::Incomplete } else { InspectionCompleteness::Complete },
            target_attributes,
            resources,
            findings,
            fingerprint: Some(fingerprint),
            observed_at: chrono::Utc::now().to_rfc3339(),
        })
    }

    async fn discover_bounded(&self, request: &DiscoveryRequest) -> Result<DiscoverySnapshot, AdapterError> {
        tokio::time::timeout(Duration::from_secs(60), self.discover_inner(request))
            .await
            .map_err(|_| AdapterError {
                code: "sqlite_catalog_timeout".into(),
                detail: "SQLite schema and filesystem discovery exceeded the sixty-second operation deadline.".into(),
                retryable: true,
            })?
    }
}

impl DatabaseAdapter for SqliteCatalogAdapter {
    fn descriptor(&self) -> AdapterDescriptor {
        AdapterDescriptor {
            kind: DatabaseKind::Sqlite,
            name: "SQLite file-isolation discovery adapter",
            maturity: AdapterMaturity::InDevelopment,
            capabilities: AdapterCapabilities { schema_inspection: true, drift_detection: true, ..AdapterCapabilities::default() },
            status_note: "Read-only SQLite schema discovery fingerprints tables, views, columns, indexes, foreign keys, triggers and filesystem permission metadata. SQLite has no native users or RLS; tenant isolation requires a file-per-tenant design, OS ACL enforcement, trusted file selection and independent access probes. No runtime admission or policy deployment is implemented.",
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
                let resource = discovery.resources.iter().find(|resource| {
                    resource.namespace == required.resource.namespace
                        && resource.name == required.resource.name
                        && resource.kind == required.resource.kind
                });
                let Some(resource) = resource else {
                    findings.push(finding("sqlite_required_resource_missing", &required.resource, "The policy resource is not present in the SQLite schema inventory."));
                    continue;
                };
                let columns = resource.attributes.get("columns").and_then(|value| value.as_array()).cloned().unwrap_or_default();
                let tenant_column = columns.iter().find(|column| column.get("name").and_then(|value| value.as_str()) == Some(required.tenant_key.as_str()));
                let mut resource_findings = Vec::new();
                match tenant_column {
                    None => resource_findings.push(finding("sqlite_tenant_key_missing", &required.resource, "The declared tenant ownership column does not exist.")),
                    Some(column) if column.get("not_null").and_then(|value| value.as_bool()) != Some(true) =>
                        resource_findings.push(finding("sqlite_tenant_key_nullable", &required.resource, "The tenant ownership column must be explicitly NOT NULL.")),
                    _ => {}
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
                code: "sqlite_native_tenant_authorization_unavailable".into(),
                resource: None,
                detail: "SQLite has no native row-level security or per-tenant database users. A trusted file-per-tenant selector and operating-system file/directory isolation must be implemented and independently tested.".into(),
            });
            Ok(InspectionSnapshot {
                database_kind: DatabaseKind::Sqlite,
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
        Err(error("sqlite_policy_compilation_unavailable", "SQLite has no native tenant policy mechanism. Use a reviewed file-per-tenant deployment design with OS-level isolation; the adapter will not generate misleading row-policy SQL."))
    }

    fn verify<'a>(&'a self, _policy: &'a TenantSecurityPolicy, snapshot: &'a InspectionSnapshot) -> AdapterFuture<'a, Result<VerificationReport, AdapterError>> {
        Box::pin(async move {
            if snapshot.database_kind != DatabaseKind::Sqlite {
                return Err(error("sqlite_snapshot_target_mismatch", "The inspection snapshot belongs to a different database kind."));
            }
            self.validate_target(&snapshot.target)?;
            let mut findings = snapshot.findings.clone();
            findings.push(SecurityFinding {
                code: "sqlite_semantic_verification_unavailable".into(),
                resource: None,
                detail: "SQLite file isolation has not been proven through independent tenant identities, OS-level permission checks and cross-tenant file-access probes.".into(),
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
                database_kind: DatabaseKind::Sqlite,
                target: target.clone(),
                detected,
                completeness: snapshot.completeness,
                previous_fingerprint: previous_fingerprint.map(str::to_owned),
                observed_fingerprint: snapshot.fingerprint,
                findings: if detected { vec![SecurityFinding {
                    code: "sqlite_catalog_fingerprint_changed".into(),
                    resource: None,
                    detail: "SQLite schema or filesystem permission metadata differs from the previously accepted fingerprint.".into(),
                }] } else { snapshot.findings },
                observed_at: snapshot.observed_at,
            })
        })
    }
}

#[derive(Clone, Copy, Debug, serde::Serialize)]
struct FilesystemPermissions {
    assessed: bool,
    unsafe_permissions: bool,
    file_mode: Option<u32>,
    parent_mode: Option<u32>,
    wal_mode: Option<u32>,
    shm_mode: Option<u32>,
}

fn filesystem_permissions(
    file: &std::fs::Metadata,
    parent: Option<&std::fs::Metadata>,
    wal: Option<&std::fs::Metadata>,
    shm: Option<&std::fs::Metadata>,
) -> FilesystemPermissions {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let file_mode = file.permissions().mode() & 0o777;
        let parent_mode = parent.map(|metadata| metadata.permissions().mode() & 0o777);
        let wal_mode = wal.map(|metadata| metadata.permissions().mode() & 0o777);
        let shm_mode = shm.map(|metadata| metadata.permissions().mode() & 0o777);
        let sidecar_is_unsafe = wal_mode.into_iter().chain(shm_mode).any(|mode| (mode & 0o077) != 0);
        FilesystemPermissions {
            assessed: true,
            unsafe_permissions: (file_mode & 0o077) != 0
                || parent_mode.map_or(true, |mode| (mode & 0o077) != 0)
                || sidecar_is_unsafe,
            file_mode: Some(file_mode),
            parent_mode,
            wal_mode,
            shm_mode,
        }
    }
    #[cfg(not(unix))]
    {
        let _ = (file, parent, wal, shm);
        FilesystemPermissions {
            assessed: false,
            unsafe_permissions: true,
            file_mode: None,
            parent_mode: None,
            wal_mode: None,
            shm_mode: None,
        }
    }
}

fn digest(bytes: &[u8]) -> String { hex::encode(Sha256::digest(bytes)) }
fn finding(code: &str, resource: &ResourceRef, detail: &str) -> SecurityFinding {
    SecurityFinding { code: code.into(), resource: Some(resource.clone()), detail: detail.into() }
}
fn error(code: &str, detail: &str) -> AdapterError { AdapterError { code: code.into(), detail: detail.into(), retryable: false } }
fn db_error(error: sqlx::Error) -> AdapterError {
    AdapterError {
        code: "sqlite_catalog_query_failed".into(),
        detail: "The read-only SQLite catalog operation failed.".into(),
        retryable: matches!(error, sqlx::Error::PoolTimedOut | sqlx::Error::Io(_)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_memory_databases_and_relative_paths() {
        assert!(SqliteCatalogAdapter::new("target", "/tmp/app.db", "sqlite::memory:").is_err());
        assert!(SqliteCatalogAdapter::new("target", "app.db", "sqlite://app.db").is_err());
    }

    #[test]
    fn descriptor_claims_discovery_only() {
        let file = tempfile::NamedTempFile::new().unwrap();
        let path = file.path().to_path_buf();
        let uri = format!("sqlite://{}", path.display());
        let adapter = SqliteCatalogAdapter::new("target", path, uri).unwrap();
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
