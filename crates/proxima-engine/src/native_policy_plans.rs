//! Native policy-plan compilers for non-PostgreSQL database families.
//!
//! These functions produce reviewable, non-executable policy plans. They do not
//! connect to customer databases, apply DDL/ACL changes, or prove effective
//! authorization. Runtime adapters must add native inspection, deployment,
//! semantic verification, drift handling, and adversarial acceptance first.

use crate::security_core::{DatabaseKind, Operation, ProtectedResource, ResourceKind, TenantSecurityPolicy};
use crate::database_adapter::{AdapterError, CompiledPolicy, NativePolicyChange};
use serde_json::json;
use sha2::{Digest, Sha256};

fn error(code: &str, detail: &str) -> AdapterError {
    AdapterError { code: code.into(), detail: detail.into(), retryable: false }
}

fn identifier(value: &str, max: usize) -> Result<&str, AdapterError> {
    if value.trim().is_empty() || value.len() > max || value.contains('\0') {
        return Err(error("invalid_identifier", "A native resource identifier is empty, too long, or contains a NUL byte."));
    }
    Ok(value)
}

fn sql_server_ident(value: &str) -> Result<String, AdapterError> {
    identifier(value, 128)?;
    Ok(format!("[{}]", value.replace(']', "]]")))
}

fn mysql_ident(value: &str) -> Result<String, AdapterError> {
    identifier(value, 64)?;
    Ok(format!("\x60{}\x60", value.replace('\x60', "\x60\x60")))
}

fn resource_change(resource: &ProtectedResource, action: &str, definition: serde_json::Value) -> NativePolicyChange {
    NativePolicyChange { resource: resource.clone(), action: action.into(), definition }
}

/// SQL Server uses native Row-Level Security. The generated predicate binds
/// each row to the trusted connection's SESSION_CONTEXT tenant_id value.
pub fn compile_sql_server(policy: &TenantSecurityPolicy) -> Result<CompiledPolicy, AdapterError> {
    policy.validate().map_err(|e| error("invalid_policy", &format!("The shared policy is invalid: {e:?}")))?;
    let mut changes = Vec::new();
    for resource in &policy.resources {
        if resource.resource.kind != ResourceKind::Table {
            return Err(error("unsupported_resource_kind", "SQL Server RLS compilation currently accepts tables only; views, procedures and functions need separate review."));
        }
        let schema = sql_server_ident(resource.resource.namespace.as_deref().unwrap_or("dbo"))?;
        let table = sql_server_ident(&resource.resource.name)?;
        let tenant_key = sql_server_ident(&resource.tenant_key)?;
        if resource.operations.contains(&Operation::Execute) {
            return Err(error("unsupported_operation", "SQL Server table RLS does not compile execute operations; use a separately reviewed module policy."));
        }
        let identity = format!("{}:{}:{}", policy.policy_id, resource.resource.namespace.as_deref().unwrap_or("dbo"), resource.resource.name);
        let digest = Sha256::digest(identity.as_bytes());
        let suffix = hex::encode(&digest[..8]);
        let function_name = format!("{schema}.[proxima_tenant_{suffix}]");
        let policy_name = format!("{schema}.[proxima_policy_{suffix}]");
        let claim = policy.tenant_identity_claim.replace('\'', "''");
        let mut statements = vec![format!(
            "CREATE OR ALTER FUNCTION {function_name}(@row_tenant_key <VERIFIED_COLUMN_TYPE>)\nRETURNS TABLE WITH SCHEMABINDING AS\nRETURN SELECT 1 AS allowed\nWHERE CONVERT(nvarchar(450), @row_tenant_key) = CONVERT(nvarchar(450), SESSION_CONTEXT(N'{claim}'));"
        )];
        if resource.operations.contains(&Operation::Read) {
            statements.push(format!("ADD FILTER PREDICATE {function_name}({tenant_key}) ON {schema}.{table}"));
        }
        if resource.operations.iter().any(|op| matches!(op, Operation::Create | Operation::Update | Operation::Delete)) {
            if resource.operations.contains(&Operation::Create) {
                statements.push(format!("ADD BLOCK PREDICATE {function_name}({tenant_key}) ON {schema}.{table} AFTER INSERT"));
            }
            if resource.operations.contains(&Operation::Update) {
                statements.push(format!("ADD BLOCK PREDICATE {function_name}({tenant_key}) ON {schema}.{table} BEFORE UPDATE"));
                statements.push(format!("ADD BLOCK PREDICATE {function_name}({tenant_key}) ON {schema}.{table} AFTER UPDATE"));
            }
            if resource.operations.contains(&Operation::Delete) {
                statements.push(format!("ADD BLOCK PREDICATE {function_name}({tenant_key}) ON {schema}.{table} BEFORE DELETE"));
            }
        }
        let predicate_lines = statements.iter().skip(1).cloned().collect::<Vec<_>>();
        let create_policy = if predicate_lines.is_empty() {
            String::new()
        } else {
            let schema_name = resource.resource.namespace.as_deref().unwrap_or("dbo");
            let schema_literal = schema_name.replace('\'', "''");
            let policy_short_name = format!("proxima_policy_{suffix}");
            format!(
                "IF NOT EXISTS (SELECT 1 FROM sys.security_policies WHERE name = N'{policy_short_name}' AND schema_id = SCHEMA_ID(N'{schema_literal}'))\nBEGIN\n    CREATE SECURITY POLICY {policy_name}\n        {}\n    WITH (STATE = ON, SCHEMABINDING = ON);\nEND;",
                predicate_lines.join(",\n        ")
            )
        };
        let mut batches = vec![statements[0].clone()];
        if !create_policy.is_empty() { batches.push(create_policy); }
        changes.push(resource_change(resource, "sql_server_create_or_alter_rls", json!({
            "batches": batches,
            "required_session_context": policy.tenant_identity_claim,
            "session_context_must_be_set_by": "trusted_authenticated_application_or_gateway",
            "required_catalog_substitution": { "placeholder": "<VERIFIED_COLUMN_TYPE>", "source": "live_catalog_type_of_the_tenant_key_column" },
            "requires_operator_approval": true,
            "limitations": [
                "The adapter must prove that untrusted clients cannot set or overwrite SESSION_CONTEXT.",
                "The generated function contains a verified-column-type placeholder and is not executable until a live catalog inspector substitutes the exact native type.",
                "Existing security policies require an explicit ALTER SECURITY POLICY revision; the template only creates a missing policy.",
                "SQL Server ownership chaining, elevated principals, module signing and bypass paths require catalog verification."
            ]
        })));
    }
    Ok(CompiledPolicy { database_kind: DatabaseKind::SqlServer, policy_id: policy.policy_id.clone(), revision: policy.revision, changes, requires_approval: true })
}

/// MySQL and MariaDB do not provide PostgreSQL/SQL Server-style native row-level
/// security. This compiler therefore emits a database-per-tenant grant template;
/// it deliberately refuses to pretend that a shared table is row-isolated.
pub fn compile_mysql_database_boundary(policy: &TenantSecurityPolicy, kind: DatabaseKind) -> Result<CompiledPolicy, AdapterError> {
    if !matches!(kind, DatabaseKind::MySql | DatabaseKind::MariaDb) {
        return Err(error("wrong_adapter_kind", "This compiler accepts MySQL or MariaDB only."));
    }
    policy.validate().map_err(|e| error("invalid_policy", &format!("The shared policy is invalid: {e:?}")))?;
    let mut changes = Vec::new();
    for resource in &policy.resources {
        if resource.resource.kind != ResourceKind::Table {
            return Err(error("unsupported_resource_kind", "MySQL-family tenant database templates currently accept tables only."));
        }
        let table = mysql_ident(&resource.resource.name)?;
        let mut grants = Vec::new();
        if resource.operations.contains(&Operation::Read) { grants.push("SELECT"); }
        if resource.operations.contains(&Operation::Create) { grants.push("INSERT"); }
        if resource.operations.contains(&Operation::Update) { grants.push("UPDATE"); }
        if resource.operations.contains(&Operation::Delete) { grants.push("DELETE"); }
        let sql = if grants.is_empty() { return Err(error("empty_privilege_set", "No supported table operations were requested.")); }
            else { format!("GRANT {} ON \x60${{tenant_database}}\x60.{table} TO '${{tenant_principal}}'@'%';", grants.join(", ")) };
        changes.push(resource_change(resource, "mysql_family_per_tenant_database_grant_template", json!({
            "sql_template": [
                "CREATE USER '${tenant_principal}'@'%' IDENTIFIED BY '${secret_manager_generated_password}';",
                sql
            ],
            "required_isolation_model": "one_database_per_tenant",
            "database_placeholder": "${tenant_database}",
            "principal_placeholder": "${tenant_principal}",
            "credential_placeholder": "${secret_manager_generated_password}",
            "shared_table_row_level_isolation": false,
            "limitations": [
                "MySQL and MariaDB have no native row-level security predicate equivalent.",
                "A shared database/table with tenant_id is not protected by this grant template.",
                "The application must resolve tenant identity before selecting a tenant-specific database and credential.",
                "Database/user creation, grants, definer objects, global privileges and administrative accounts still require native inspection and acceptance."
            ]
        })));
    }
    Ok(CompiledPolicy { database_kind: kind, policy_id: policy.policy_id.clone(), revision: policy.revision, changes, requires_approval: true })
}

/// MongoDB authorization is database/collection scoped, not document-tenant
/// scoped. This template is safe only with a database-per-tenant layout.
pub fn compile_mongodb_database_boundary(policy: &TenantSecurityPolicy) -> Result<CompiledPolicy, AdapterError> {
    policy.validate().map_err(|e| error("invalid_policy", &format!("The shared policy is invalid: {e:?}")))?;
    let mut changes = Vec::new();
    for resource in &policy.resources {
        if resource.resource.kind != ResourceKind::Collection {
            return Err(error("unsupported_resource_kind", "MongoDB boundary templates accept collections only."));
        }
        let database = resource.resource.namespace.as_deref().ok_or_else(|| error("tenant_database_required", "MongoDB collection policy requires a database namespace."))?;
        identifier(database, 63)?;
        identifier(&resource.resource.name, 120)?;
        let mut actions = Vec::new();
        if resource.operations.contains(&Operation::Read) { actions.push("find"); }
        if resource.operations.contains(&Operation::Create) { actions.push("insert"); }
        if resource.operations.contains(&Operation::Update) { actions.push("update"); }
        if resource.operations.contains(&Operation::Delete) { actions.push("remove"); }
        if actions.is_empty() { return Err(error("empty_privilege_set", "No supported MongoDB actions were requested.")); }
        changes.push(resource_change(resource, "mongodb_per_tenant_database_role_template", json!({
            "role_template": {
                "role": "proximaTenantRole",
                "db": "${tenant_database}",
                "privileges": [{
                    "resource": {"db": "${tenant_database}", "collection": resource.resource.name},
                    "actions": actions
                }],
                "roles": []
            },
            "required_isolation_model": "one_database_per_tenant",
            "shared_collection_document_level_isolation": false,
            "limitations": [
                "MongoDB RBAC does not enforce arbitrary tenant_id predicates on individual documents.",
                "Shared collections require an independently enforced document-level authorization layer; this role template is not sufficient.",
                "Built-in roles, inherited custom roles, cluster privileges, change streams, views and administrative users require inspection."
            ]
        })));
    }
    Ok(CompiledPolicy { database_kind: DatabaseKind::MongoDb, policy_id: policy.policy_id.clone(), revision: policy.revision, changes, requires_approval: true })
}

/// Redis ACL templates restrict a tenant principal to a tenant-specific key
/// namespace. The key pattern must contain the literal ${tenant_id} placeholder.
pub fn compile_redis_acl(policy: &TenantSecurityPolicy) -> Result<CompiledPolicy, AdapterError> {
    policy.validate().map_err(|e| error("invalid_policy", &format!("The shared policy is invalid: {e:?}")))?;
    let mut changes = Vec::new();
    for resource in &policy.resources {
        let Some((prefix, suffix)) = resource.tenant_key.split_once("${tenant_id}") else {
            return Err(error("redis_tenant_key_pattern_required", "Redis tenant_key must contain exactly one literal ${tenant_id} placeholder, for example tenant:${tenant_id}:*."));
        };
        if resource.tenant_key.matches("${tenant_id}").count() != 1
            || prefix.is_empty()
            || prefix.contains('*')
            || !suffix.starts_with(':')
            || !resource.tenant_key.chars().all(|ch| ch.is_ascii_alphanumeric() || matches!(ch, ':' | '_' | '-' | '*' | '
        let mut commands = Vec::new();
        if resource.operations.contains(&Operation::Read) { commands.push("+@read"); }
        if resource.operations.iter().any(|op| matches!(op, Operation::Create | Operation::Update | Operation::Delete)) { commands.push("+@write"); }
        if commands.is_empty() { return Err(error("empty_privilege_set", "No supported Redis command category was requested.")); }
        let mut acl_template = vec!["reset".to_string(), "on".to_string(), ">${secret_manager_generated_password}".to_string(), format!("~{pattern}")];
        acl_template.extend(commands.iter().map(|value| value.to_string()));
        changes.push(resource_change(resource, "redis_acl_user_template", json!({
            "acl_template": acl_template,
            "username_template": "proxima:${tenant_id}",
            "password_source": "unique_secret_from_secret_manager",
            "transport": "TLS_required_outside_local_development",
            "limitations": [
                "The trusted gateway must authenticate the tenant and select the matching Redis ACL user.",
                "Every key must follow the tenant key pattern; unscoped keys and keyless commands need separate policy review.",
                "Redis ACL categories are broad command groups; production adapters must reduce them to a tested command allowlist.",
                "ACL users, selectors, key patterns, channels, scripts, functions, modules and replication/admin commands require inspection."
            ]
        })));
    }
    Ok(CompiledPolicy { database_kind: DatabaseKind::Redis, policy_id: policy.policy_id.clone(), revision: policy.revision, changes, requires_approval: true })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::security_core::{ResourceRef, SECURITY_MODEL_VERSION};

    fn policy(kind: ResourceKind, tenant_key: &str) -> TenantSecurityPolicy {
        TenantSecurityPolicy {
            schema_version: SECURITY_MODEL_VERSION.into(),
            policy_id: "tenant-boundary".into(),
            revision: 1,
            tenant_identity_claim: "tenant_id".into(),
            resources: vec![ProtectedResource {
                resource: ResourceRef { namespace: Some("app".into()), name: "records".into(), kind },
                tenant_key: tenant_key.into(),
                operations: vec![Operation::Read, Operation::Create, Operation::Update, Operation::Delete],
            }],
        }
    }

    #[test]
    fn sql_server_plan_uses_filter_and_block_predicates() {
        let compiled = compile_sql_server(&policy(ResourceKind::Table, "tenant_id")).unwrap();
        assert_eq!(compiled.database_kind, DatabaseKind::SqlServer);
        let batches = compiled.changes[0].definition["batches"].as_array().unwrap();
        let ddl = batches.iter().filter_map(|batch| batch.as_str()).collect::<Vec<_>>().join("\n");
        assert!(ddl.contains("SESSION_CONTEXT(N'tenant_id')"));
        assert!(ddl.contains("<VERIFIED_COLUMN_TYPE>"));
        assert!(ddl.contains("FILTER PREDICATE"));
        assert!(ddl.contains("AFTER INSERT"));
        assert!(ddl.contains("BEFORE UPDATE"));
        assert!(ddl.contains("BEFORE DELETE"));
        assert_eq!(batches.len(), 2);
    }

    #[test]
    fn mysql_family_template_explicitly_requires_database_per_tenant() {
        let compiled = compile_mysql_database_boundary(&policy(ResourceKind::Table, "tenant_id"), DatabaseKind::MySql).unwrap();
        assert_eq!(compiled.database_kind, DatabaseKind::MySql);
        assert_eq!(compiled.changes[0].definition["required_isolation_model"], "one_database_per_tenant");
        assert_eq!(compiled.changes[0].definition["shared_table_row_level_isolation"], false);
    }

    #[test]
    fn mongodb_template_does_not_claim_document_level_security() {
        let compiled = compile_mongodb_database_boundary(&policy(ResourceKind::Collection, "tenant_id")).unwrap();
        assert_eq!(compiled.changes[0].definition["shared_collection_document_level_isolation"], false);
    }

    #[test]
    fn redis_requires_explicit_tenant_key_pattern() {
        assert!(compile_redis_acl(&policy(ResourceKind::Keyspace, "tenant:${tenant_id}:*")).is_ok());
        assert_eq!(compile_redis_acl(&policy(ResourceKind::Keyspace, "tenant_id")).unwrap_err().code, "redis_tenant_key_pattern_required");
    }
}
 | '{' | '}'))
        {
            return Err(error("unsafe_redis_key_pattern", "Redis tenant key patterns must have a literal non-wildcard prefix, exactly one tenant placeholder, a colon-delimited suffix, and only safe ACL pattern characters."));
        }
        let pattern = resource.tenant_key.clone();
        let mut commands = Vec::new();
        if resource.operations.contains(&Operation::Read) { commands.push("+@read"); }
        if resource.operations.iter().any(|op| matches!(op, Operation::Create | Operation::Update | Operation::Delete)) { commands.push("+@write"); }
        if commands.is_empty() { return Err(error("empty_privilege_set", "No supported Redis command category was requested.")); }
        let mut acl_template = vec!["reset".to_string(), "on".to_string(), ">${secret_manager_generated_password}".to_string(), format!("~{pattern}")];
        acl_template.extend(commands.iter().map(|value| value.to_string()));
        changes.push(resource_change(resource, "redis_acl_user_template", json!({
            "acl_template": acl_template,
            "username_template": "proxima:${tenant_id}",
            "password_source": "unique_secret_from_secret_manager",
            "transport": "TLS_required_outside_local_development",
            "limitations": [
                "The trusted gateway must authenticate the tenant and select the matching Redis ACL user.",
                "Every key must follow the tenant key pattern; unscoped keys and keyless commands need separate policy review.",
                "Redis ACL categories are broad command groups; production adapters must reduce them to a tested command allowlist.",
                "ACL users, selectors, key patterns, channels, scripts, functions, modules and replication/admin commands require inspection."
            ]
        })));
    }
    Ok(CompiledPolicy { database_kind: DatabaseKind::Redis, policy_id: policy.policy_id.clone(), revision: policy.revision, changes, requires_approval: true })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::security_core::{ResourceRef, SECURITY_MODEL_VERSION};

    fn policy(kind: ResourceKind, tenant_key: &str) -> TenantSecurityPolicy {
        TenantSecurityPolicy {
            schema_version: SECURITY_MODEL_VERSION.into(),
            policy_id: "tenant-boundary".into(),
            revision: 1,
            tenant_identity_claim: "tenant_id".into(),
            resources: vec![ProtectedResource {
                resource: ResourceRef { namespace: Some("app".into()), name: "records".into(), kind },
                tenant_key: tenant_key.into(),
                operations: vec![Operation::Read, Operation::Create, Operation::Update, Operation::Delete],
            }],
        }
    }

    #[test]
    fn sql_server_plan_uses_filter_and_block_predicates() {
        let compiled = compile_sql_server(&policy(ResourceKind::Table, "tenant_id")).unwrap();
        assert_eq!(compiled.database_kind, DatabaseKind::SqlServer);
        let batches = compiled.changes[0].definition["batches"].as_array().unwrap();
        let ddl = batches.iter().filter_map(|batch| batch.as_str()).collect::<Vec<_>>().join("\n");
        assert!(ddl.contains("SESSION_CONTEXT(N'tenant_id')"));
        assert!(ddl.contains("FILTER PREDICATE"));
        assert!(ddl.contains("AFTER INSERT"));
        assert!(ddl.contains("BEFORE UPDATE"));
        assert!(ddl.contains("BEFORE DELETE"));
        assert_eq!(batches.len(), 2);
    }

    #[test]
    fn mysql_family_template_explicitly_requires_database_per_tenant() {
        let compiled = compile_mysql_database_boundary(&policy(ResourceKind::Table, "tenant_id"), DatabaseKind::MySql).unwrap();
        assert_eq!(compiled.database_kind, DatabaseKind::MySql);
        assert_eq!(compiled.changes[0].definition["required_isolation_model"], "one_database_per_tenant");
        assert_eq!(compiled.changes[0].definition["shared_table_row_level_isolation"], false);
    }

    #[test]
    fn mongodb_template_does_not_claim_document_level_security() {
        let compiled = compile_mongodb_database_boundary(&policy(ResourceKind::Collection, "tenant_id")).unwrap();
        assert_eq!(compiled.changes[0].definition["shared_collection_document_level_isolation"], false);
    }

    #[test]
    fn redis_requires_explicit_tenant_key_pattern() {
        assert!(compile_redis_acl(&policy(ResourceKind::Keyspace, "tenant:${tenant_id}:*")).is_ok());
        assert_eq!(compile_redis_acl(&policy(ResourceKind::Keyspace, "tenant_id")).unwrap_err().code, "redis_tenant_key_pattern_required");
    }
}
