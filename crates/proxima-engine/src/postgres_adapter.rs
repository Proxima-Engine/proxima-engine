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
    DriftReport, DiscoveryRequest, DiscoverySnapshot, DiscoveredResource, InspectionRequest, InspectionSnapshot, NativePolicyChange,
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
    tenant_role_prefix: String,
    connect: PostgresConnector,
}

impl PostgresCatalogAdapter {
    pub fn new(
        target_id: impl Into<String>,
        database_name: impl Into<String>,
        tenant_role_prefix: impl Into<String>,
        connect: PostgresConnector,
    ) -> Result<Self, AdapterError> {
        let target_id = target_id.into();
        let database_name = database_name.into();
        let tenant_role_prefix = tenant_role_prefix.into();
        if target_id.trim().is_empty() || database_name.trim().is_empty()
            || target_id.len() > 256 || database_name.len() > 63
            || target_id.contains('\0') || database_name.contains('\0')
        {
            return Err(error("invalid_postgres_target", "A bounded target ID and database name are required."));
        }
        if tenant_role_prefix.is_empty() || tenant_role_prefix.len() > 27
            || tenant_role_prefix.contains('\0')
            || !tenant_role_prefix.bytes().all(|byte| byte.is_ascii_alphanumeric() || byte == b'_')
            || !tenant_role_prefix.as_bytes().first().is_some_and(|byte| byte.is_ascii_alphabetic() || *byte == b'_')
        {
            return Err(error("invalid_tenant_role_prefix", "The tenant role prefix must be a valid PostgreSQL identifier prefix."));
        }
        Ok(Self { target_id, database_name, tenant_role_prefix, connect })
    }

    fn validate_target(&self, target: &AdapterTarget) -> Result<(), AdapterError> {
        if target.target_id != self.target_id || target.database_name != self.database_name {
            return Err(error("postgres_target_mismatch", "The requested target does not match this adapter's configured target."));
        }
        Ok(())
    }

    async fn connect_checked(&self) -> Result<Client, AdapterError> {
        let client = (self.connect)().await?;
        client.batch_execute("SET default_transaction_read_only = on; SET statement_timeout = '10s'; SET lock_timeout = '2s'; SET search_path = pg_catalog, pg_temp;")
            .await.map_err(db_error)?;
        let row = client.query_one(
            "WITH RECURSIVE effective_roles(role_oid) AS (\
               SELECT oid FROM pg_catalog.pg_roles WHERE rolname=current_user \
               UNION \
               SELECT membership.roleid FROM pg_catalog.pg_auth_members membership \
               JOIN effective_roles inherited ON membership.member=inherited.role_oid \
             ) \
             SELECT current_database(), EXISTS( \
               SELECT 1 FROM effective_roles inherited \
               JOIN pg_catalog.pg_roles role ON role.oid=inherited.role_oid \
               WHERE role.rolsuper OR role.rolbypassrls OR role.rolcreaterole OR role.rolcreatedb OR role.rolreplication \
             )",
            &[],
        ).await.map_err(db_error)?;
        let actual_database: String = row.get(0);
        if actual_database != self.database_name {
            return Err(error("postgres_database_mismatch", "The authenticated connection reached a different database."));
        }
        if row.get::<_, bool>(1) {
            return Err(error("unsafe_inspection_role", "The inspection role or any role it can inherit/set must not be SUPERUSER, BYPASSRLS, CREATEROLE, CREATEDB or REPLICATION."));
        }
        let unsafe_privileges: bool = client.query_one(
            "SELECT has_database_privilege(current_user,current_database(),'CREATE') OR EXISTS (SELECT 1 FROM pg_catalog.pg_namespace n WHERE n.nspname NOT IN ('pg_catalog','information_schema') AND n.nspname NOT LIKE 'pg_%' AND has_schema_privilege(current_user,n.oid,'CREATE')) OR EXISTS (SELECT 1 FROM pg_catalog.pg_class c JOIN pg_catalog.pg_namespace n ON n.oid=c.relnamespace WHERE c.relkind IN ('r','p','v','m') AND n.nspname NOT IN ('pg_catalog','information_schema') AND (has_table_privilege(current_user,c.oid,'INSERT') OR has_table_privilege(current_user,c.oid,'UPDATE') OR has_table_privilege(current_user,c.oid,'DELETE') OR has_table_privilege(current_user,c.oid,'TRUNCATE')))",
            &[],
        ).await.map_err(db_error)?.get(0);
        if unsafe_privileges {
            return Err(error("unsafe_inspection_role", "The inspection role must be read-only and have no database/schema CREATE or table write privileges."));
        }
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
                drift_detection: true,
                ..AdapterCapabilities::default()
            },
            status_note: "Concrete read-only catalog inspection and review-only RLS policy generation are implemented. Semantic verification, controlled deployment, drift response and runtime admission are not production-complete.",
        }
    }

    fn discover<'a>(
        &'a self,
        request: &'a DiscoveryRequest,
    ) -> AdapterFuture<'a, Result<DiscoverySnapshot, AdapterError>> {
        Box::pin(async move {
            self.validate_target(&request.target)?;
            if request.namespace.as_ref().is_some_and(|namespace| {
                namespace.trim().is_empty() || namespace.len() > 63 || namespace.contains('\\0')
            }) {
                return Err(error("invalid_discovery_namespace", "The discovery namespace must be a valid bounded PostgreSQL schema name."));
            }
            let client = self.connect_checked().await?;
            let rows = client.query(
                "SELECT n.nspname, c.relname, CASE WHEN c.relkind IN ('r','p','f') THEN 'table' WHEN c.relkind IN ('v','m') THEN 'view' WHEN c.relkind='S' THEN 'sequence' END AS resource_kind, pg_catalog.pg_get_userbyid(c.relowner), jsonb_build_object('relkind',c.relkind::text,'row_security_enabled',c.relrowsecurity,'row_security_forced',c.relforcerowsecurity,'foreign_table',c.relkind='f','is_partition',c.relispartition,'partition_key',CASE WHEN c.relkind='p' THEN pg_catalog.pg_get_partkeydef(c.oid) ELSE NULL END,'partition_parent',(SELECT parent_namespace.nspname || '.' || parent_relation.relname FROM pg_catalog.pg_inherits inheritance JOIN pg_catalog.pg_class parent_relation ON parent_relation.oid=inheritance.inhparent JOIN pg_catalog.pg_namespace parent_namespace ON parent_namespace.oid=parent_relation.relnamespace WHERE inheritance.inhrelid=c.oid ORDER BY parent_namespace.nspname,parent_relation.relname LIMIT 1),'partition_children',COALESCE((SELECT jsonb_agg(jsonb_build_object('schema',child_namespace.nspname,'name',child_relation.relname,'is_partition',child_relation.relispartition,'partition_bound',pg_catalog.pg_get_expr(child_relation.relpartbound,child_relation.oid),'policy_count',(SELECT count(*) FROM pg_catalog.pg_policy child_policy WHERE child_policy.polrelid=child_relation.oid),'policies',COALESCE((SELECT jsonb_agg(jsonb_build_object('name',child_policy.polname,'command',child_policy.polcmd::text,'permissive',child_policy.polpermissive,'using',pg_catalog.pg_get_expr(child_policy.polqual,child_policy.polrelid),'check',pg_catalog.pg_get_expr(child_policy.polwithcheck,child_policy.polrelid)) ORDER BY child_policy.polname) FROM pg_catalog.pg_policy child_policy WHERE child_policy.polrelid=child_relation.oid),'[]'::jsonb),'row_security_enabled',child_relation.relrowsecurity,'row_security_forced',child_relation.relforcerowsecurity,'acl',COALESCE(child_relation.relacl::text,'<default>')) ORDER BY child_namespace.nspname,child_relation.relname) FROM pg_catalog.pg_inherits inheritance JOIN pg_catalog.pg_class child_relation ON child_relation.oid=inheritance.inhrelid JOIN pg_catalog.pg_namespace child_namespace ON child_namespace.oid=child_relation.relnamespace WHERE inheritance.inhparent=c.oid AND child_relation.relispartition),'[]'::jsonb),'acl',COALESCE(c.relacl::text,'<default>'),'columns',COALESCE((SELECT jsonb_agg(jsonb_build_object('name',a.attname,'type',pg_catalog.format_type(a.atttypid,a.atttypmod),'not_null',a.attnotnull,'default',pg_catalog.pg_get_expr(d.adbin,d.adrelid)) ORDER BY a.attnum) FROM pg_catalog.pg_attribute a LEFT JOIN pg_catalog.pg_attrdef d ON d.adrelid=a.attrelid AND d.adnum=a.attnum WHERE a.attrelid=c.oid AND a.attnum>0 AND NOT a.attisdropped),'[]'::jsonb),'policies',COALESCE((SELECT jsonb_agg(jsonb_build_object('name',p.polname,'command',p.polcmd::text,'permissive',p.polpermissive,'using',pg_catalog.pg_get_expr(p.polqual,p.polrelid),'check',pg_catalog.pg_get_expr(p.polwithcheck,p.polrelid),'roles',p.polroles) ORDER BY p.polname) FROM pg_catalog.pg_policy p WHERE p.polrelid=c.oid),'[]'::jsonb),'constraints',COALESCE((SELECT jsonb_agg(jsonb_build_object('name',constraint_row.conname,'type',constraint_row.contype::text,'validated',constraint_row.convalidated,'definition',pg_catalog.pg_get_constraintdef(constraint_row.oid)) ORDER BY constraint_row.conname) FROM pg_catalog.pg_constraint constraint_row WHERE constraint_row.conrelid=c.oid),'[]'::jsonb),'indexes',COALESCE((SELECT jsonb_agg(jsonb_build_object('name',index_class.relname,'valid',index_row.indisvalid,'ready',index_row.indisready,'definition',pg_catalog.pg_get_indexdef(index_row.indexrelid)) ORDER BY index_class.relname) FROM pg_catalog.pg_index index_row JOIN pg_catalog.pg_class index_class ON index_class.oid=index_row.indexrelid WHERE index_row.indrelid=c.oid),'[]'::jsonb),'triggers',COALESCE((SELECT jsonb_agg(jsonb_build_object('name',trigger_row.tgname,'enabled',trigger_row.tgenabled::text,'definition',pg_catalog.pg_get_triggerdef(trigger_row.oid,true)) ORDER BY trigger_row.tgname) FROM pg_catalog.pg_trigger trigger_row WHERE trigger_row.tgrelid=c.oid AND NOT trigger_row.tgisinternal),'[]'::jsonb),'view_definition',CASE WHEN c.relkind IN ('v','m') THEN pg_catalog.pg_get_viewdef(c.oid,true) ELSE NULL END,'view_options',COALESCE(c.reloptions,'{}'::text[])) AS attributes FROM pg_catalog.pg_class c JOIN pg_catalog.pg_namespace n ON n.oid=c.relnamespace WHERE c.relkind IN ('r','p','f','v','m','S') AND n.nspname NOT IN ('pg_catalog','information_schema') AND n.nspname NOT LIKE 'pg_%' AND ($1::text IS NULL OR n.nspname=$1) UNION ALL SELECT n.nspname, p.proname, CASE WHEN p.prokind='p' THEN 'procedure' ELSE 'function' END, pg_catalog.pg_get_userbyid(p.proowner), jsonb_build_object('security_definer',p.prosecdef,'execute_acl',COALESCE(p.proacl::text,'<default>'),'identity_arguments',pg_catalog.pg_get_function_identity_arguments(p.oid),'configuration',COALESCE(p.proconfig,'{}'::text[]),'definition',pg_catalog.pg_get_functiondef(p.oid),'volatility',p.provolatile::text,'leakproof',p.proleakproof,'parallel_safety',p.proparallel::text) FROM pg_catalog.pg_proc p JOIN pg_catalog.pg_namespace n ON n.oid=p.pronamespace WHERE p.prokind IN ('f','p') AND n.nspname NOT IN ('pg_catalog','information_schema') AND n.nspname NOT LIKE 'pg_%' AND ($1::text IS NULL OR n.nspname=$1) ORDER BY 1,2,3",
                &[&request.namespace],
            ).await.map_err(db_error)?;
            let mut resources = Vec::with_capacity(rows.len());
            for row in rows {
                let kind: String = row.get(2);
                let kind = match kind.as_str() {
                    "table" => ResourceKind::Table,
                    "view" => ResourceKind::View,
                    "sequence" => ResourceKind::Sequence,
                    "procedure" => ResourceKind::Procedure,
                    "function" => ResourceKind::Function,
                    _ => return Err(error("unknown_discovered_resource_kind", "PostgreSQL returned an unsupported resource kind during discovery.")),
                };
                resources.push(DiscoveredResource {
                    namespace: Some(row.get(0)),
                    name: row.get(1),
                    kind,
                    owner: Some(row.get(3)),
                    attributes: row.get(4),
                });
            }
            let clock = client.query_one(
                "SELECT to_char(clock_timestamp() AT TIME ZONE 'UTC', 'YYYY-MM-DD\"T\"HH24:MI:SS.US\"Z\"')",
                &[],
            ).await.map_err(db_error)?;
            let observed_at: String = clock.get(0);
            let target_row = client.query_one(
                "SELECT current_database(), current_user, current_setting('server_version'), current_setting('server_version_num')",
                &[],
            ).await.map_err(db_error)?;
            let roles = client.query(
                "SELECT rolname,rolsuper,rolbypassrls,rolcreaterole,rolcreatedb,rolreplication,rolinherit,rolcanlogin,rolconnlimit FROM pg_catalog.pg_roles ORDER BY rolname",
                &[],
            ).await.map_err(db_error)?;
            let role_memberships = client.query(
                "SELECT member_role.rolname AS member_role,granted_role.rolname AS granted_role,membership.admin_option FROM pg_catalog.pg_auth_members membership JOIN pg_catalog.pg_roles member_role ON member_role.oid=membership.member JOIN pg_catalog.pg_roles granted_role ON granted_role.oid=membership.roleid ORDER BY member_role.rolname,granted_role.rolname",
                &[],
            ).await.map_err(db_error)?;
            let database_privileges = client.query(
                "SELECT database_info.datname,pg_catalog.pg_get_userbyid(database_info.datdba) AS owner,COALESCE(database_info.datacl::text,'<default>') AS acl,database_info.datallowconn,database_info.datistemplate FROM pg_catalog.pg_database database_info ORDER BY database_info.datname",
                &[],
            ).await.map_err(db_error)?;
            let schema_privileges = client.query(
                "SELECT namespace.nspname,pg_catalog.pg_get_userbyid(namespace.nspowner) AS owner,COALESCE(namespace.nspacl::text,'<default>') AS acl FROM pg_catalog.pg_namespace namespace WHERE namespace.nspname NOT IN ('pg_catalog','information_schema') AND namespace.nspname NOT LIKE 'pg_%' ORDER BY namespace.nspname",
                &[],
            ).await.map_err(db_error)?;
            let default_privileges = client.query(
                "SELECT pg_catalog.pg_get_userbyid(default_acl.defaclrole) AS owner_role,COALESCE(namespace.nspname,'') AS schema_name,default_acl.defaclobjtype::text AS object_type,COALESCE(default_acl.defaclacl::text,'<default>') AS acl FROM pg_catalog.pg_default_acl default_acl LEFT JOIN pg_catalog.pg_namespace namespace ON namespace.oid=default_acl.defaclnamespace ORDER BY 1,2,3",
                &[],
            ).await.map_err(db_error)?;
            let target_attributes = json!({
                "database": target_row.get::<_, String>(0),
                "authenticated_role": target_row.get::<_, String>(1),
                "server_version": target_row.get::<_, String>(2),
                "server_version_num": target_row.get::<_, String>(3),
                "inspection_role_is_read_only": true,
                "roles": roles.iter().map(|role| json!({
                    "name": role.get::<_, String>(0),
                    "superuser": role.get::<_, bool>(1),
                    "bypass_rls": role.get::<_, bool>(2),
                    "create_role": role.get::<_, bool>(3),
                    "create_database": role.get::<_, bool>(4),
                    "replication": role.get::<_, bool>(5),
                    "inherit": role.get::<_, bool>(6),
                    "can_login": role.get::<_, bool>(7),
                    "connection_limit": role.get::<_, i32>(8)
                })).collect::<Vec<_>>(),
                "role_memberships": role_memberships.iter().map(|membership| json!({
                    "member_role": membership.get::<_, String>(0),
                    "granted_role": membership.get::<_, String>(1),
                    "admin_option": membership.get::<_, bool>(2)
                })).collect::<Vec<_>>(),
                "database_privileges": database_privileges.iter().map(|database| json!({
                    "database": database.get::<_, String>(0),
                    "owner": database.get::<_, String>(1),
                    "acl": database.get::<_, String>(2),
                    "allow_connections": database.get::<_, bool>(3),
                    "is_template": database.get::<_, bool>(4)
                })).collect::<Vec<_>>(),
                "schema_privileges": schema_privileges.iter().map(|schema| json!({
                    "schema": schema.get::<_, String>(0),
                    "owner": schema.get::<_, String>(1),
                    "acl": schema.get::<_, String>(2)
                })).collect::<Vec<_>>(),
                "default_privileges": default_privileges.iter().map(|default_acl| json!({
                    "owner_role": default_acl.get::<_, String>(0),
                    "schema": default_acl.get::<_, String>(1),
                    "object_type": default_acl.get::<_, String>(2),
                    "acl": default_acl.get::<_, String>(3)
                })).collect::<Vec<_>>()
            });
            let fingerprint = sha256(&serde_json::to_vec(&json!({"target":target_attributes,"resources":resources}))
                .map_err(|_| error("fingerprint_serialization_failed", "Could not serialize discovered PostgreSQL resources."))?);
            Ok(DiscoverySnapshot {
                database_kind: DatabaseKind::PostgreSql,
                target: request.target.clone(),
                completeness: InspectionCompleteness::Complete,
                target_attributes,
                resources,
                findings: Vec::new(),
                fingerprint: Some(fingerprint),
                observed_at,
            })
        })
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
                    "SELECT c.relrowsecurity, c.relforcerowsecurity, (WITH RECURSIVE owner_roles(role_oid) AS (SELECT c.relowner UNION SELECT am.roleid FROM pg_catalog.pg_auth_members am JOIN owner_roles parent ON am.member=parent.role_oid) SELECT EXISTS(SELECT 1 FROM owner_roles roles JOIN pg_catalog.pg_roles inherited ON inherited.oid=roles.role_oid WHERE inherited.rolsuper OR inherited.rolbypassrls)), (SELECT count(*)::bigint FROM pg_catalog.pg_policies p WHERE p.schemaname=n.nspname AND p.tablename=c.relname), c.relkind::text, COALESCE((SELECT string_agg(concat_ws(':',p.polname,p.polcmd,p.polpermissive::text,COALESCE(pg_catalog.pg_get_expr(p.polqual,p.polrelid),''),COALESCE(pg_catalog.pg_get_expr(p.polwithcheck,p.polrelid),''),COALESCE((SELECT string_agg(COALESCE(role_name.rolname,'PUBLIC'),',' ORDER BY COALESCE(role_name.rolname,'PUBLIC')) FROM unnest(p.polroles) policy_role(role_oid) LEFT JOIN pg_catalog.pg_roles role_name ON role_name.oid=policy_role.role_oid),'')), E'\\n' ORDER BY p.polname) FROM pg_catalog.pg_policy p WHERE p.polrelid=c.oid),''), COALESCE(c.relacl::text,'<default>'), pg_catalog.pg_get_userbyid(c.relowner), EXISTS(SELECT 1 FROM aclexplode(COALESCE(c.relacl,acldefault(CASE WHEN c.relkind='S' THEN 'S'::\"char\" ELSE 'r'::\"char\" END,c.relowner))) acl WHERE acl.grantee<>0 AND EXISTS(WITH RECURSIVE granted_roles(role_oid) AS (SELECT acl.grantee UNION SELECT am.roleid FROM pg_catalog.pg_auth_members am JOIN granted_roles parent ON am.member=parent.role_oid) SELECT 1 FROM granted_roles granted JOIN pg_catalog.pg_roles role ON role.oid=granted.role_oid WHERE role.rolsuper OR role.rolbypassrls)), EXISTS(SELECT 1 FROM aclexplode(COALESCE(c.relacl,acldefault(CASE WHEN c.relkind='S' THEN 'S'::\"char\" ELSE 'r'::\"char\" END,c.relowner))) acl WHERE acl.grantee=0 AND acl.privilege_type='SELECT'), EXISTS(SELECT 1 FROM aclexplode(COALESCE(c.relacl,acldefault(CASE WHEN c.relkind='S' THEN 'S'::\"char\" ELSE 'r'::\"char\" END,c.relowner))) acl WHERE acl.grantee=0 AND acl.privilege_type IN ('INSERT','UPDATE','DELETE','TRUNCATE')), EXISTS(SELECT 1 FROM pg_catalog.pg_attribute tenant_column WHERE tenant_column.attrelid=c.oid AND tenant_column.attname::text=$3 AND tenant_column.attnum>0 AND NOT tenant_column.attisdropped), COALESCE((SELECT tenant_column.attnotnull FROM pg_catalog.pg_attribute tenant_column WHERE tenant_column.attrelid=c.oid AND tenant_column.attname::text=$3 AND tenant_column.attnum>0 AND NOT tenant_column.attisdropped),false),COALESCE((SELECT jsonb_agg(jsonb_build_object('schema',child_namespace.nspname,'name',child_relation.relname,'is_partition',child_relation.relispartition,'partition_bound',pg_catalog.pg_get_expr(child_relation.relpartbound,child_relation.oid),'policy_count',(SELECT count(*) FROM pg_catalog.pg_policy child_policy WHERE child_policy.polrelid=child_relation.oid),'policies',COALESCE((SELECT jsonb_agg(jsonb_build_object('name',child_policy.polname,'command',child_policy.polcmd::text,'using',pg_catalog.pg_get_expr(child_policy.polqual,child_policy.polrelid),'check',pg_catalog.pg_get_expr(child_policy.polwithcheck,child_policy.polrelid)) ORDER BY child_policy.polname) FROM pg_catalog.pg_policy child_policy WHERE child_policy.polrelid=child_relation.oid),'[]'::jsonb),'row_security_enabled',child_relation.relrowsecurity,'row_security_forced',child_relation.relforcerowsecurity,'acl',COALESCE(child_relation.relacl::text,'<default>')) ORDER BY child_namespace.nspname,child_relation.relname) FROM pg_catalog.pg_inherits inheritance JOIN pg_catalog.pg_class child_relation ON child_relation.oid=inheritance.inhrelid JOIN pg_catalog.pg_namespace child_namespace ON child_namespace.oid=child_relation.relnamespace WHERE inheritance.inhparent=c.oid AND child_relation.relispartition),'[]'::jsonb) FROM pg_catalog.pg_class c JOIN pg_catalog.pg_namespace n ON n.oid=c.relnamespace WHERE n.nspname=$1 AND c.relname=$2 AND c.relkind IN ('r','p')",
                    &[&schema, &protected.resource.name.as_str(), &protected.tenant_key.as_str()],
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
                let owner_bypasses_rls: bool = row.get(2);
                let policy_count: i64 = row.get(3);
                let relkind: String = row.get(4);
                let policy_definitions: String = row.get(5);
                let relation_acl: String = row.get(6);
                let owner_name: String = row.get(7);
                let bypass_grantee: bool = row.get(8);
                let public_select: bool = row.get(9);
                let public_write: bool = row.get(10);
                let tenant_column_exists: bool = row.get(11);
                let tenant_column_not_null: bool = row.get(12);
                let partition_children: serde_json::Value = row.get(13);
                let unsafe_dependent_views: i64 = client.query_one(
                    "WITH RECURSIVE target_relation(oid) AS (SELECT c.oid FROM pg_catalog.pg_class c JOIN pg_catalog.pg_namespace n ON n.oid=c.relnamespace WHERE n.nspname=$1 AND c.relname=$2), dependent_views(view_oid) AS (SELECT rewrite.ev_class FROM pg_catalog.pg_depend dependency JOIN pg_catalog.pg_rewrite rewrite ON dependency.classid='pg_rewrite'::regclass AND dependency.objid=rewrite.oid CROSS JOIN target_relation target WHERE dependency.refclassid='pg_class'::regclass AND dependency.refobjid=target.oid UNION SELECT rewrite.ev_class FROM pg_catalog.pg_depend dependency JOIN pg_catalog.pg_rewrite rewrite ON dependency.classid='pg_rewrite'::regclass AND dependency.objid=rewrite.oid JOIN dependent_views parent ON dependency.refobjid=parent.view_oid WHERE dependency.refclassid='pg_class'::regclass) SELECT count(*)::bigint FROM dependent_views dependency JOIN pg_catalog.pg_class view_relation ON view_relation.oid=dependency.view_oid JOIN pg_catalog.pg_namespace view_namespace ON view_namespace.oid=view_relation.relnamespace WHERE view_relation.relkind IN ('v','m') AND view_namespace.nspname NOT IN ('pg_catalog','information_schema') AND view_namespace.nspname NOT LIKE 'pg_%' AND (view_relation.relkind='m' OR NOT COALESCE(view_relation.reloptions @> ARRAY['security_invoker=true'],false))",
                    &[&schema, &protected.resource.name.as_str()],
                ).await.map_err(db_error)?.get(0);
                let security_definer_routines: i64 = client.query_one(
                    "SELECT count(*)::bigint FROM pg_catalog.pg_proc routine JOIN pg_catalog.pg_namespace routine_schema ON routine_schema.oid=routine.pronamespace WHERE routine.prosecdef AND routine.prokind IN ('f','p') AND routine_schema.nspname NOT IN ('pg_catalog','information_schema') AND routine_schema.nspname NOT LIKE 'pg_%'",
                    &[],
                ).await.map_err(db_error)?.get(0);

                let mut findings = Vec::new();
                if partition_children.as_array().is_some_and(|children| children.iter().any(|child| child["row_security_enabled"].as_bool() != Some(true))) {
                    findings.push(finding("partition_child_without_rls", &protected.resource, "One or more directly addressable PostgreSQL partitions do not have row-level security enabled; parent-table policies do not protect queries that address a partition directly."));
                }
                if partition_children.as_array().is_some_and(|children| children.iter().any(|child| child["row_security_enabled"].as_bool() == Some(true) && child["row_security_forced"].as_bool() != Some(true))) {
                    findings.push(finding("partition_child_rls_not_forced", &protected.resource, "One or more PostgreSQL partitions have RLS enabled but not forced; table owners may bypass their policies when accessing the partition directly."));
                }
                if partition_children.as_array().is_some_and(|children| children.iter().any(|child| child["row_security_enabled"].as_bool() == Some(true) && child["policy_count"].as_i64().unwrap_or(0) == 0)) {
                    findings.push(finding("partition_child_policy_missing", &protected.resource, "One or more directly addressable PostgreSQL partitions enable RLS but have no local policies; parent policies do not protect direct child access."));
                }
                if partition_children.as_array().is_some_and(|children| children.iter().any(|child| {
                    child["policies"].as_array().is_some_and(|policies| !policies.is_empty() && !policies.iter().all(|policy| {
                        policy["using"].as_str().is_some_and(|expression| expression.contains(protected.tenant_key.as_str()))
                            || policy["check"].as_str().is_some_and(|expression| expression.contains(protected.tenant_key.as_str()))
                    }))
                })) {
                    findings.push(finding("partition_child_tenant_policy_unverified", &protected.resource, "One or more PostgreSQL partition-local policy expressions do not visibly reference the registered tenant key; verify the partition's tenant predicate independently."));
                }
                if unsafe_dependent_views > 0 { findings.push(finding("unsafe_dependent_view", &protected.resource, "A dependent view is not security-invoker or is materialized; it requires separate protection and review.")); }
                if security_definer_routines > 0 { findings.push(finding("security_definer_routine_requires_review", &protected.resource, "Application SECURITY DEFINER routines exist and require explicit privilege and tenant-boundary review.")); }
                if !rls_enabled { findings.push(finding("rls_disabled", &protected.resource, "Row-level security is disabled.")); }
                if !rls_forced { findings.push(finding("rls_not_forced", &protected.resource, "Table-owner access is not forced through row-level security.")); }
                if owner_bypasses_rls { findings.push(finding("owner_bypasses_rls", &protected.resource, "The relation owner or an inherited role has SUPERUSER or BYPASSRLS.")); }
                if bypass_grantee { findings.push(finding("bypass_role_has_table_grant", &protected.resource, "A table grantee or inherited role has SUPERUSER or BYPASSRLS.")); }
                if public_select || public_write { findings.push(finding("public_table_grant", &protected.resource, "PUBLIC has direct SELECT or write privileges on this relation.")); }
                if !tenant_column_exists { findings.push(finding("tenant_ownership_column_missing", &protected.resource, "The policy's tenant ownership column does not exist on this relation.")); }
                else if !tenant_column_not_null { findings.push(finding("tenant_ownership_column_nullable", &protected.resource, "The policy's tenant ownership column permits NULL values.")); }
                if policy_count == 0 { findings.push(finding("no_native_policies", &protected.resource, "No PostgreSQL row-security policies are attached to this relation.")); }
                if relkind == "p" { findings.push(finding("partitioned_relation_requires_child_audit", &protected.resource, "Partitioned tables require independent inspection of every directly addressable child partition.")); }
                // A policy count is not proof of tenant semantics. Never turn
                // catalog presence into verified operations or an allow result.
                findings.push(finding("semantic_verification_required", &protected.resource, "Native policy expressions and cross-tenant allow/deny behavior have not been independently verified."));
                let state = json!({
                    "schema": schema, "table": protected.resource.name, "rls_enabled": rls_enabled,
                    "rls_forced": rls_forced, "owner_bypasses_rls": owner_bypasses_rls,
                    "policy_count": policy_count, "policy_definitions": policy_definitions,
                    "relation_acl": relation_acl, "owner_name": owner_name,
                    "bypass_grantee": bypass_grantee, "public_select": public_select,
                    "public_write": public_write, "tenant_column_exists": tenant_column_exists,
                    "tenant_column_not_null": tenant_column_not_null, "tenant_column": protected.tenant_key,
                    "unsafe_dependent_views": unsafe_dependent_views,
                    "security_definer_routines": security_definer_routines,
                    "relkind": relkind
                });
                let digest = sha256(&serde_json::to_vec(&state).map_err(|_| error("fingerprint_serialization_failed", "Could not serialize PostgreSQL catalog state."))?);
                fingerprint_rows.push(state);
                resources.push(ResourceInspection {
                    resource: protected.clone(),
                    completeness: InspectionCompleteness::Complete,
                    posture: if rls_enabled && rls_forced && !owner_bypasses_rls && policy_count > 0 { SecurityPosture::NeedsAttention } else { SecurityPosture::Blocked },
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
            // The Engine binds tenant identity to a dedicated PostgreSQL login
            // role at startup. Derive the tenant claim from that immutable role
            // identity rather than a session GUC: session GUC state is not safe
            // to rely on behind transaction-pooling proxies.
            let role_prefix = quote_literal(&self.tenant_role_prefix);
            let tenant_expression = format!(
                "pg_catalog.left(current_user, pg_catalog.char_length({role_prefix})) = {role_prefix} AND pg_catalog.replace(({tenant_column})::text, '-', '_') = pg_catalog.substring(current_user FROM pg_catalog.char_length({role_prefix}) + 1)"
            );
            let mut statements = vec![
                format!("ALTER TABLE {relation} ENABLE ROW LEVEL SECURITY"),
                format!("ALTER TABLE {relation} FORCE ROW LEVEL SECURITY"),
            ];
            for operation in &protected.operations {
                let command = match operation {
                    Operation::Read => "SELECT",
                    Operation::Create => "INSERT",
                    Operation::Update => "UPDATE",
                    Operation::Delete => "DELETE",
                    Operation::Execute => return Err(error("unsupported_operation", "EXECUTE is not a table-level PostgreSQL RLS operation.")),
                };
                let seed = format!("{}:{}:{}:{}:{:?}", policy.policy_id, policy.revision, schema, protected.resource.name, operation);
                let digest = sha256(seed.as_bytes());
                let suffix = &digest[..16];
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
                        "Ensure each requested command has a reviewed permissive baseline policy; restrictive policies intersect with permissive policies and otherwise deny all rows.",
                        "Route each authenticated tenant through the Engine's dedicated role prefix plus normalized tenant ID; never share a tenant login role across tenant identities.",
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
            if snapshot.database_kind != DatabaseKind::PostgreSql
                || snapshot.target.target_id != self.target_id
                || snapshot.target.database_name != self.database_name
            {
                return Err(error("postgres_snapshot_target_mismatch", "The verification snapshot does not belong to this PostgreSQL adapter target."));
            }
            _policy.validate().map_err(|_| error("invalid_policy", "The canonical tenant policy failed validation."))?;
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
                "SELECT n.nspname, c.relname, pg_catalog.pg_get_userbyid(c.relowner), c.relrowsecurity, c.relforcerowsecurity, COALESCE((SELECT string_agg(concat_ws(':',p.polname,p.polcmd,p.polpermissive::text,COALESCE(pg_catalog.pg_get_expr(p.polqual,p.polrelid),''),COALESCE(pg_catalog.pg_get_expr(p.polwithcheck,p.polrelid),''),COALESCE((SELECT string_agg(COALESCE(role_name.rolname,'PUBLIC'),',' ORDER BY COALESCE(role_name.rolname,'PUBLIC')) FROM unnest(p.polroles) policy_role(role_oid) LEFT JOIN pg_catalog.pg_roles role_name ON role_name.oid=policy_role.role_oid),'')), E'\\n' ORDER BY p.polname) FROM pg_catalog.pg_policy p WHERE p.polrelid=c.oid), ''), COALESCE(c.relacl::text,'<default>'), EXISTS(SELECT 1 FROM aclexplode(COALESCE(c.relacl,acldefault(CASE WHEN c.relkind='S' THEN 'S'::\"char\" ELSE 'r'::\"char\" END,c.relowner))) acl WHERE acl.grantee<>0 AND EXISTS(WITH RECURSIVE granted_roles(role_oid) AS (SELECT acl.grantee UNION SELECT am.roleid FROM pg_catalog.pg_auth_members am JOIN granted_roles parent ON am.member=parent.role_oid) SELECT 1 FROM granted_roles granted JOIN pg_catalog.pg_roles role ON role.oid=granted.role_oid WHERE role.rolsuper OR role.rolbypassrls)), (WITH RECURSIVE owner_roles(role_oid) AS (SELECT c.relowner UNION SELECT am.roleid FROM pg_catalog.pg_auth_members am JOIN owner_roles parent ON am.member=parent.role_oid) SELECT EXISTS(SELECT 1 FROM owner_roles roles JOIN pg_catalog.pg_roles inherited ON inherited.oid=roles.role_oid WHERE inherited.rolsuper OR inherited.rolbypassrls)) FROM pg_catalog.pg_class c JOIN pg_catalog.pg_namespace n ON n.oid=c.relnamespace WHERE c.relkind IN ('r','p','S') AND n.nspname NOT IN ('pg_catalog','information_schema') AND n.nspname NOT LIKE 'pg_%' ORDER BY n.nspname,c.relname",
                &[],
            ).await.map_err(db_error)?;
            let mut state: Vec<serde_json::Value> = rows.into_iter().map(|row| json!({
                "kind": "relation",
                "schema": row.get::<_, String>(0), "table": row.get::<_, String>(1),
                "owner": row.get::<_, String>(2), "rls_enabled": row.get::<_, bool>(3),
                "rls_forced": row.get::<_, bool>(4), "policies": row.get::<_, String>(5),
                "acl": row.get::<_, String>(6), "bypass_grantee": row.get::<_, bool>(7),
                "owner_bypasses_rls": row.get::<_, bool>(8)
            })).collect();

            // A relation-only fingerprint misses security changes that alter
            // effective access without changing a table's ACL or RLS policy:
            // role attributes, inherited memberships, and persistent role
            // settings can all widen access or disable row security.
            let role_rows = client.query(
                "SELECT r.rolname, r.rolsuper, r.rolbypassrls, r.rolcreaterole, r.rolcreatedb, r.rolreplication, r.rolcanlogin, r.rolinherit, r.rolvaliduntil::text, COALESCE(d.datname, 'ALL_DATABASES'), COALESCE(s.setconfig::text, '') FROM pg_catalog.pg_roles r LEFT JOIN pg_catalog.pg_db_role_setting s ON s.setrole=r.oid LEFT JOIN pg_catalog.pg_database d ON d.oid=s.setdatabase ORDER BY r.rolname, d.datname",
                &[],
            ).await.map_err(db_error)?;
            state.extend(role_rows.into_iter().map(|row| json!({
                "kind": "role",
                "name": row.get::<_, String>(0),
                "superuser": row.get::<_, bool>(1),
                "bypass_rls": row.get::<_, bool>(2),
                "create_role": row.get::<_, bool>(3),
                "create_database": row.get::<_, bool>(4),
                "replication": row.get::<_, bool>(5),
                "can_login": row.get::<_, bool>(6),
                "inherit": row.get::<_, bool>(7),
                "valid_until": row.get::<_, Option<String>>(8),
                "settings_database": row.get::<_, String>(9),
                "settings": row.get::<_, String>(10)
            })));

            let membership_rows = client.query(
                "SELECT granted.rolname, member.rolname, grantor.rolname, membership.admin_option FROM pg_catalog.pg_auth_members membership JOIN pg_catalog.pg_roles granted ON granted.oid=membership.roleid JOIN pg_catalog.pg_roles member ON member.oid=membership.member JOIN pg_catalog.pg_roles grantor ON grantor.oid=membership.grantor ORDER BY granted.rolname, member.rolname, grantor.rolname",
                &[],
            ).await.map_err(db_error)?;
            state.extend(membership_rows.into_iter().map(|row| json!({
                "kind": "role_membership",
                "granted_role": row.get::<_, String>(0),
                "member_role": row.get::<_, String>(1),
                "grantor": row.get::<_, String>(2),
                "admin_option": row.get::<_, bool>(3)
            })));

            let routine_rows = client.query(
                "SELECT n.nspname, p.proname, pg_catalog.pg_get_userbyid(p.proowner), p.prosecdef, COALESCE(array_to_string(p.proconfig, ','), ''), pg_catalog.pg_get_function_identity_arguments(p.oid), pg_catalog.pg_get_functiondef(p.oid), COALESCE(p.proacl::text,'<default>'), p.prokind::text FROM pg_catalog.pg_proc p JOIN pg_catalog.pg_namespace n ON n.oid=p.pronamespace WHERE p.prokind IN ('f','p') AND n.nspname NOT IN ('pg_catalog','information_schema') AND n.nspname NOT LIKE 'pg_%' ORDER BY n.nspname,p.proname,pg_catalog.pg_get_function_identity_arguments(p.oid)",
                &[],
            ).await.map_err(db_error)?;
            state.extend(routine_rows.into_iter().map(|row| json!({
                "kind": "application_routine",
                "schema": row.get::<_, String>(0),
                "name": row.get::<_, String>(1),
                "owner": row.get::<_, String>(2),
                "security_definer": row.get::<_, bool>(3),
                "settings": row.get::<_, String>(4),
                "arguments": row.get::<_, String>(5),
                "definition": row.get::<_, String>(6),
                "acl": row.get::<_, String>(7),
                "routine_kind": row.get::<_, String>(8)
            })));

            let column_rows = client.query(
                "SELECT n.nspname, c.relname, a.attname, pg_catalog.format_type(a.atttypid,a.atttypmod), a.attnotnull, COALESCE(pg_catalog.pg_get_expr(d.adbin,d.adrelid),''), a.attidentity::text, a.attgenerated::text FROM pg_catalog.pg_attribute a JOIN pg_catalog.pg_class c ON c.oid=a.attrelid JOIN pg_catalog.pg_namespace n ON n.oid=c.relnamespace LEFT JOIN pg_catalog.pg_attrdef d ON d.adrelid=a.attrelid AND d.adnum=a.attnum WHERE c.relkind IN ('r','p','v','m') AND a.attnum>0 AND NOT a.attisdropped AND n.nspname NOT IN ('pg_catalog','information_schema') AND n.nspname NOT LIKE 'pg_%' ORDER BY n.nspname,c.relname,a.attnum",
                &[],
            ).await.map_err(db_error)?;
            state.extend(column_rows.into_iter().map(|row| json!({
                "kind": "column",
                "schema": row.get::<_, String>(0),
                "relation": row.get::<_, String>(1),
                "name": row.get::<_, String>(2),
                "data_type": row.get::<_, String>(3),
                "not_null": row.get::<_, bool>(4),
                "default": row.get::<_, String>(5),
                "identity": row.get::<_, String>(6),
                "generated": row.get::<_, String>(7)
            })));

            let constraint_rows = client.query(
                "SELECT n.nspname, c.relname, constraint_row.conname, constraint_row.contype::text, constraint_row.convalidated, constraint_row.condeferrable, constraint_row.condeferred, pg_catalog.pg_get_constraintdef(constraint_row.oid,true) FROM pg_catalog.pg_constraint constraint_row JOIN pg_catalog.pg_class c ON c.oid=constraint_row.conrelid JOIN pg_catalog.pg_namespace n ON n.oid=c.relnamespace WHERE n.nspname NOT IN ('pg_catalog','information_schema') AND n.nspname NOT LIKE 'pg_%' ORDER BY n.nspname,c.relname,constraint_row.conname",
                &[],
            ).await.map_err(db_error)?;
            state.extend(constraint_rows.into_iter().map(|row| json!({
                "kind": "constraint",
                "schema": row.get::<_, String>(0),
                "relation": row.get::<_, String>(1),
                "name": row.get::<_, String>(2),
                "constraint_type": row.get::<_, String>(3),
                "validated": row.get::<_, bool>(4),
                "deferrable": row.get::<_, bool>(5),
                "initially_deferred": row.get::<_, bool>(6),
                "definition": row.get::<_, String>(7)
            })));

            let index_rows = client.query(
                "SELECT n.nspname, table_row.relname, index_row.relname, index_meta.indisunique, index_meta.indisvalid, index_meta.indisready, pg_catalog.pg_get_indexdef(index_meta.indexrelid) FROM pg_catalog.pg_index index_meta JOIN pg_catalog.pg_class table_row ON table_row.oid=index_meta.indrelid JOIN pg_catalog.pg_class index_row ON index_row.oid=index_meta.indexrelid JOIN pg_catalog.pg_namespace n ON n.oid=table_row.relnamespace WHERE n.nspname NOT IN ('pg_catalog','information_schema') AND n.nspname NOT LIKE 'pg_%' ORDER BY n.nspname,table_row.relname,index_row.relname",
                &[],
            ).await.map_err(db_error)?;
            state.extend(index_rows.into_iter().map(|row| json!({
                "kind": "index",
                "schema": row.get::<_, String>(0),
                "relation": row.get::<_, String>(1),
                "name": row.get::<_, String>(2),
                "unique": row.get::<_, bool>(3),
                "valid": row.get::<_, bool>(4),
                "ready": row.get::<_, bool>(5),
                "definition": row.get::<_, String>(6)
            })));

            let trigger_rows = client.query(
                "SELECT n.nspname, c.relname, trigger_row.tgname, trigger_row.tgenabled::text, pg_catalog.pg_get_triggerdef(trigger_row.oid,true) FROM pg_catalog.pg_trigger trigger_row JOIN pg_catalog.pg_class c ON c.oid=trigger_row.tgrelid JOIN pg_catalog.pg_namespace n ON n.oid=c.relnamespace WHERE NOT trigger_row.tgisinternal AND n.nspname NOT IN ('pg_catalog','information_schema') AND n.nspname NOT LIKE 'pg_%' ORDER BY n.nspname,c.relname,trigger_row.tgname",
                &[],
            ).await.map_err(db_error)?;
            state.extend(trigger_rows.into_iter().map(|row| json!({
                "kind": "trigger",
                "schema": row.get::<_, String>(0),
                "relation": row.get::<_, String>(1),
                "name": row.get::<_, String>(2),
                "enabled": row.get::<_, String>(3),
                "definition": row.get::<_, String>(4)
            })));

            let view_rows = client.query(
                "SELECT n.nspname, c.relname, c.relkind::text, pg_catalog.pg_get_userbyid(c.relowner), COALESCE(c.reloptions::text,''), pg_catalog.pg_get_viewdef(c.oid,true), COALESCE(c.relacl::text,'<default>') FROM pg_catalog.pg_class c JOIN pg_catalog.pg_namespace n ON n.oid=c.relnamespace WHERE c.relkind IN ('v','m') AND n.nspname NOT IN ('pg_catalog','information_schema') AND n.nspname NOT LIKE 'pg_%' ORDER BY n.nspname,c.relname",
                &[],
            ).await.map_err(db_error)?;
            state.extend(view_rows.into_iter().map(|row| json!({
                "kind": "view",
                "schema": row.get::<_, String>(0),
                "name": row.get::<_, String>(1),
                "relation_kind": row.get::<_, String>(2),
                "owner": row.get::<_, String>(3),
                "options": row.get::<_, String>(4),
                "definition": row.get::<_, String>(5),
                "acl": row.get::<_, String>(6)
            })));

            let schema_rows = client.query(
                "SELECT n.nspname, pg_catalog.pg_get_userbyid(n.nspowner), COALESCE(n.nspacl::text,'<default>') FROM pg_catalog.pg_namespace n WHERE n.nspname NOT IN ('pg_catalog','information_schema') AND n.nspname NOT LIKE 'pg_%' ORDER BY n.nspname",
                &[],
            ).await.map_err(db_error)?;
            state.extend(schema_rows.into_iter().map(|row| json!({
                "kind": "schema_privilege",
                "schema": row.get::<_, String>(0),
                "owner": row.get::<_, String>(1),
                "acl": row.get::<_, String>(2)
            })));

            let database_rows = client.query(
                "SELECT d.datname, pg_catalog.pg_get_userbyid(d.datdba), COALESCE(d.datacl::text,'<default>'), d.datallowconn, d.datistemplate FROM pg_catalog.pg_database d ORDER BY d.datname",
                &[],
            ).await.map_err(db_error)?;
            state.extend(database_rows.into_iter().map(|row| json!({
                "kind": "database_privilege",
                "database": row.get::<_, String>(0),
                "owner": row.get::<_, String>(1),
                "acl": row.get::<_, String>(2),
                "allow_connections": row.get::<_, bool>(3),
                "is_template": row.get::<_, bool>(4)
            })));

            let default_acl_rows = client.query(
                "SELECT pg_catalog.pg_get_userbyid(default_acl.defaclrole), COALESCE(namespace.nspname,''), default_acl.defaclobjtype::text, COALESCE(default_acl.defaclacl::text,'<default>') FROM pg_catalog.pg_default_acl default_acl LEFT JOIN pg_catalog.pg_namespace namespace ON namespace.oid=default_acl.defaclnamespace ORDER BY 1,2,3",
                &[],
            ).await.map_err(db_error)?;
            state.extend(default_acl_rows.into_iter().map(|row| json!({
                "kind": "default_privilege",
                "owner_role": row.get::<_, String>(0),
                "schema": row.get::<_, String>(1),
                "object_type": row.get::<_, String>(2),
                "acl": row.get::<_, String>(3)
            })));

            let fingerprint = sha256(&serde_json::to_vec(&state).map_err(|_| error("fingerprint_serialization_failed", "Could not serialize PostgreSQL catalog state."))?);
            let clock = client.query_one("SELECT to_char(clock_timestamp() AT TIME ZONE 'UTC', 'YYYY-MM-DD\"T\"HH24:MI:SS.US\"Z\"')", &[]).await.map_err(db_error)?;
            let observed_at: String = clock.get(0);
            let detected = previous_fingerprint.is_some_and(|previous| previous != fingerprint.as_str());
            Ok(DriftReport {
                database_kind: DatabaseKind::PostgreSql,
                target: target.clone(),
                detected,
                completeness: InspectionCompleteness::Complete,
                previous_fingerprint: previous_fingerprint.map(str::to_owned),
                observed_fingerprint: Some(fingerprint),
                findings: if detected {
                    vec![SecurityFinding {
                        code: "native_catalog_fingerprint_changed".into(),
                        resource: None,
                        detail: "The observed PostgreSQL relation, ownership, ACL, or row-security policy definition differs from the accepted fingerprint.".into(),
                    }]
                } else { Vec::new() },
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

fn quote_literal(value: &str) -> String {
    format!("'{}'", value.replace('\'', "''"))
}

fn safe_name(value: &str) -> String {
    let normalized: String = value.chars().map(|character| {
        if character.is_ascii_alphanumeric() || character == '_' { character.to_ascii_lowercase() } else { '_' }
    }).take(24).collect();
    if normalized.is_empty() { "policy".into() } else { normalized }
}


#[cfg(test)]
mod tests {
    use super::*;
    use crate::security_core::{ResourceRef, SECURITY_MODEL_VERSION};

    fn policy() -> TenantSecurityPolicy {
        TenantSecurityPolicy {
            schema_version: SECURITY_MODEL_VERSION.into(),
            policy_id: "tenant_boundary".into(),
            revision: 7,
            tenant_identity_claim: "tenant_id".into(),
            resources: vec![ProtectedResource {
                resource: ResourceRef {
                    namespace: Some("customer data".into()),
                    name: "invoices".into(),
                    kind: ResourceKind::Table,
                },
                tenant_key: "tenant_id".into(),
                operations: vec![Operation::Read, Operation::Create, Operation::Update, Operation::Delete],
            }],
        }
    }

    fn adapter() -> PostgresCatalogAdapter {
        let connector: PostgresConnector = Arc::new(|| Box::pin(async {
            Err(error("test_connector_not_called", "This test exercises compilation only."))
        }));
        PostgresCatalogAdapter::new("test-target", "app_db", "proxima_tenant_", connector).unwrap()
    }

    #[test]
    fn postgres_plan_is_review_only_and_emits_restrictive_operation_policies() {
        let compiled = adapter().compile_policy(&policy()).unwrap();
        assert_eq!(compiled.database_kind, DatabaseKind::PostgreSql);
        assert_eq!(compiled.revision, 7);
        assert!(compiled.requires_approval);
        assert_eq!(compiled.changes.len(), 1);
        let statements = compiled.changes[0].definition["statements"].as_array().unwrap();
        assert_eq!(statements.len(), 6);
        let sql = statements.iter().map(|value| value.as_str().unwrap()).collect::<Vec<_>>().join("\n");
        assert!(sql.contains("AS RESTRICTIVE"));
        assert!(sql.contains("pg_catalog.left(current_user, pg_catalog.char_length('proxima_tenant_')) = 'proxima_tenant_'"));
        assert!(sql.contains("pg_catalog.substring(current_user FROM pg_catalog.char_length('proxima_tenant_') + 1)"));
        assert!(!sql.contains("current_setting"));
        assert!(sql.contains("\"customer data\".\"invoices\""));
        assert!(sql.contains("WITH CHECK"));
        assert_eq!(compiled.changes[0].definition["execution"], "not_executed");
    }

    #[test]
    fn postgres_plan_rejects_execute_and_non_table_resources() {
        let mut invalid = policy();
        invalid.resources[0].operations.push(Operation::Execute);
        assert_eq!(adapter().compile_policy(&invalid).unwrap_err().code, "unsupported_operation");

        let mut invalid = policy();
        invalid.resources[0].resource.kind = ResourceKind::View;
        assert_eq!(adapter().compile_policy(&invalid).unwrap_err().code, "unsupported_resource_kind");
    }


    #[tokio::test]
    async fn catalog_only_verification_never_allows_admission() {
        let adapter = adapter();
        let policy = policy();
        let snapshot = InspectionSnapshot {
            database_kind: DatabaseKind::PostgreSql,
            target: AdapterTarget {
                target_id: "test-target".into(),
                database_name: "app_db".into(),
                namespace: None,
            },
            completeness: InspectionCompleteness::Complete,
            posture: SecurityPosture::Verified,
            resources: Vec::new(),
            findings: Vec::new(),
            fingerprint: Some("a".repeat(64)),
            observed_at: "2026-11-17T00:00:00Z".into(),
        };
        let report = adapter.verify(&policy, &snapshot).await.unwrap();
        assert_eq!(report.access_decision(), crate::security_core::AccessDecision::Deny);
        assert!(report.findings.iter().any(|item| item.code == "independent_tenant_probes_required"));
    }

    #[tokio::test]
    async fn discovery_rejects_a_different_registered_target_before_connecting() {
        let adapter = adapter();
        let request = DiscoveryRequest {
            target: AdapterTarget {
                target_id: "other-target".into(),
                database_name: "app_db".into(),
                namespace: None,
            },
            namespace: None,
        };
        assert_eq!(adapter.discover(&request).await.unwrap_err().code, "postgres_target_mismatch");
    }

    #[tokio::test]
    async fn discovery_rejects_invalid_namespace_before_connecting() {
        let adapter = adapter();
        let request = DiscoveryRequest {
            target: AdapterTarget {
                target_id: "test-target".into(),
                database_name: "app_db".into(),
                namespace: None,
            },
            namespace: Some("x".repeat(64)),
        };
        assert_eq!(adapter.discover(&request).await.unwrap_err().code, "invalid_discovery_namespace");
    }

    #[tokio::test]
    async fn inspection_rejects_a_different_registered_target_before_connecting() {
        let adapter = adapter();
        let request = InspectionRequest {
            target: AdapterTarget {
                target_id: "other-target".into(),
                database_name: "app_db".into(),
                namespace: None,
            },
            policy: policy(),
        };
        let result = adapter.inspect(&request).await;
        assert_eq!(result.unwrap_err().code, "postgres_target_mismatch");
    }

    #[test]
    fn postgres_adapter_does_not_claim_production_support() {
        let descriptor = adapter().descriptor();
        assert_eq!(descriptor.maturity, AdapterMaturity::InDevelopment);
        assert!(!descriptor.capabilities.is_production_complete());
        assert!(!descriptor.capabilities.policy_semantic_verification);
        assert!(!descriptor.capabilities.controlled_policy_deployment);
    }
}
