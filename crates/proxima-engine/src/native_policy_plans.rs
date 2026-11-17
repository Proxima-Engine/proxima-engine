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
        if resource.operations.contains(&Operation::Execute) {
            return Err(error("unsupported_operation", "MySQL table grants do not implement the canonical execute operation; use a separately reviewed routine policy."));
        }
        let table = mysql_ident(&resource.resource.name)?;
        let mut grants = Vec::new();
        if resource.operations.contains(&Operation::Read) { grants.push("SELECT"); }
        if resource.operations.contains(&Operation::Create) { grants.push("INSERT"); }
        if resource.operations.contains(&Operation::Update) { grants.push("UPDATE"); }
        if resource.operations.contains(&Operation::Delete) { grants.push("DELETE"); }
        let sql = if grants.is_empty() { return Err(error("empty_privilege_set", "No supported table operations were requested.")); }
            else { format!("GRANT {} ON \x60${{tenant_database}}\x60.{table} TO '${{tenant_principal}}'@'${{trusted_application_host}}';", grants.join(", ")) };
        changes.push(resource_change(resource, "mysql_family_per_tenant_database_grant_template", json!({
            "sql_template": [
                "CREATE USER IF NOT EXISTS '${tenant_principal}'@'${trusted_application_host}' IDENTIFIED BY '${secret_manager_generated_password}' REQUIRE SSL;",
                sql
            ],
            "required_isolation_model": "one_database_per_tenant",
            "database_placeholder": "${tenant_database}",
            "database_placeholder_requirement": "Resolve from a trusted tenant-to-database registry, validate the native identifier length and character policy, and quote as a MySQL identifier; never interpolate an untrusted tenant string.",
            "principal_placeholder": "${tenant_principal}",
            "principal_placeholder_requirement": "Generate a unique bounded principal name from trusted tenant identity and quote it as a MySQL account component.",
            "credential_placeholder": "${secret_manager_generated_password}",
            "credential_placeholder_requirement": "Generate a unique high-entropy secret in a secret manager; never reuse a shared tenant password. CREATE USER IF NOT EXISTS does not rotate an existing credential; reconcile existing account credentials through a separately approved secret-rotation step.",
            "account_transport_requirement": "The generated account requires SSL; the application connection must also verify the server certificate and hostname.",
            "host_placeholder": "${trusted_application_host}",
            "host_placeholder_requirement": "Replace with the exact trusted application egress host or a narrowly scoped network identity; never use an unrestricted wildcard host.",
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
        if resource.operations.contains(&Operation::Execute) {
            return Err(error("unsupported_operation", "MongoDB command, aggregation, map-reduce and change-stream execution require a separately reviewed command policy."));
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
        let pattern = &resource.tenant_key;
        let Some((prefix, suffix)) = pattern.split_once("${tenant_id}") else {
            return Err(error("redis_tenant_key_pattern_required", "Redis tenant_key must contain exactly one literal ${tenant_id} placeholder, for example tenant:${tenant_id}:*."));
        };
        if pattern.matches("${tenant_id}").count() != 1
            || prefix.is_empty()
            || prefix.contains('*')
            || !suffix.starts_with(':')
            || !pattern.chars().all(|ch| ch.is_ascii_alphanumeric() || matches!(ch, ':' | '_' | '-' | '*' | '$' | '{' | '}'))
        {
            return Err(error("unsafe_redis_key_pattern", "Redis key patterns must be a bounded tenant-prefixed pattern with one tenant placeholder and no whitespace, glob escape, or command syntax."));
        }
        if resource.resource.kind != ResourceKind::Keyspace && resource.resource.kind != ResourceKind::Table {
            return Err(error("unsupported_resource_kind", "Redis policy resources must represent a keyspace or logical key collection."));
        }
        if resource.operations.contains(&Operation::Execute) {
            return Err(error("unsupported_operation", "Redis script/function execution requires a separately reviewed command and key-access policy; it is not represented by the generic execute operation."));
        }
        let mut commands: Vec<&str> = Vec::new();
        if resource.operations.contains(&Operation::Read) {
            commands.extend([
                "+get", "+mget", "+exists", "+ttl", "+pttl", "+type", "+strlen", "+getrange",
                "+hget", "+hmget", "+hgetall", "+hexists", "+hlen", "+lrange", "+llen", "+lindex",
                "+scard", "+smembers", "+sismember", "+zrange", "+zscore", "+zcard", "+xrange", "+xlen"
            ]);
        }
        if resource.operations.contains(&Operation::Create) {
            // Redis writes are frequently upserts. These commands are
            // restricted to the tenant key pattern, but ACLs cannot enforce
            // NX/XX or distinguish creation from replacement.
            commands.extend([
                "+set", "+mset", "+hset", "+lpush", "+rpush", "+sadd",
                "+zadd", "+xadd"
            ]);
        }
        if resource.operations.contains(&Operation::Update) {
            commands.extend([
                "+set", "+mset", "+expire", "+pexpire", "+persist", "+incr",
                "+decr", "+hset", "+lpush", "+rpush", "+sadd", "+zadd", "+xadd"
            ]);
        }
        if resource.operations.contains(&Operation::Delete) {
            commands.extend([
                "+del", "+unlink", "+hdel", "+lpop", "+rpop", "+srem",
                "+zrem", "+xdel"
            ]);
        }
        commands.sort_unstable();
        commands.dedup();
        if commands.is_empty() {
            return Err(error("empty_privilege_set", "No supported Redis command category was requested."));
        }
        let mut acl_template = vec![
            "reset".to_string(),
            "on".to_string(),
            ">${secret_manager_generated_password}".to_string(),
            format!("~{pattern}"),
        ];
        acl_template.extend(commands.iter().map(|value| value.to_string()));
        changes.push(resource_change(resource, "redis_acl_user_template", json!({
            "acl_template": acl_template,
            "username_template": "proxima:${tenant_id}",
            "password_source": "unique_secret_from_secret_manager",
            "transport": "TLS_required_outside_local_development",
            "limitations": [
                "The trusted gateway must authenticate the tenant and select the matching Redis ACL user.",
                "Every key must follow the tenant key pattern; unscoped keys and keyless commands need separate policy review.",
                "This template is a database ACL boundary, not proof of command-level isolation for every Redis module or server version.",
                "Redis ACLs cannot distinguish create-only from update-only semantics for upsert commands such as SET, HSET, SADD and ZADD; an enforcing gateway or application contract must enforce those distinctions.",
                "ACL users, selectors, key patterns, channels, scripts, functions, modules and replication/admin commands require native inspection."
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
        let template = compiled.changes[0].definition["sql_template"].as_array().unwrap()
            .iter().filter_map(|value| value.as_str()).collect::<Vec<_>>().join("\n");
        assert!(template.contains("@'${trusted_application_host}'"));
        assert!(!template.contains("@'%'"));
        assert_eq!(compiled.changes[0].definition["host_placeholder"], "${trusted_application_host}");
    }

    #[test]
    fn mysql_template_rejects_execute_instead_of_silently_dropping_it() {
        let mut requested = policy(ResourceKind::Table, "tenant_id");
        requested.resources[0].operations = vec![Operation::Read, Operation::Execute];
        let error = compile_mysql_database_boundary(&requested, DatabaseKind::MySql).unwrap_err();
        assert_eq!(error.code, "unsupported_operation");
    }

    #[test]
    fn mysql_account_template_is_idempotent_and_requires_tls() {
        let compiled = compile_mysql_database_boundary(&policy(ResourceKind::Table, "tenant_id"), DatabaseKind::MariaDb).unwrap();
        let template = compiled.changes[0].definition["sql_template"].as_array().unwrap()
            .iter().filter_map(|value| value.as_str()).collect::<Vec<_>>().join("\n");
        assert!(template.contains("CREATE USER IF NOT EXISTS"));
        assert!(template.contains("REQUIRE SSL"));
        assert!(template.contains("GRANT SELECT, INSERT, UPDATE, DELETE"));
    }

    #[test]
    fn mongodb_template_does_not_claim_document_level_security() {
        let compiled = compile_mongodb_database_boundary(&policy(ResourceKind::Collection, "tenant_id")).unwrap();
        assert_eq!(compiled.changes[0].definition["shared_collection_document_level_isolation"], false);
    }

    #[test]
    fn mongodb_template_rejects_execute_instead_of_silently_dropping_it() {
        let mut requested = policy(ResourceKind::Collection, "tenant_id");
        requested.resources[0].operations = vec![Operation::Read, Operation::Execute];
        let error = compile_mongodb_database_boundary(&requested).unwrap_err();
        assert_eq!(error.code, "unsupported_operation");
    }

    #[test]
    fn redis_delete_only_policy_does_not_grant_write_or_update_commands() {
        let mut delete_policy = policy(ResourceKind::Keyspace, "tenant:${tenant_id}:*");
        delete_policy.resources[0].operations = vec![Operation::Delete];
        let compiled = compile_redis_acl(&delete_policy).unwrap();
        let acl = compiled.changes[0].definition["acl_template"].as_array().unwrap();
        let commands = acl.iter().filter_map(|value| value.as_str()).collect::<Vec<_>>();
        assert!(commands.contains(&"+del"));
        assert!(commands.contains(&"+unlink"));
        assert!(!commands.contains(&"+set"));
        assert!(!commands.contains(&"+hset"));
        assert!(!commands.contains(&"+incr"));
    }

    #[test]
    fn redis_template_rejects_execute_instead_of_silently_dropping_it() {
        let mut requested = policy(ResourceKind::Keyspace, "tenant:${tenant_id}:*");
        requested.resources[0].operations = vec![Operation::Read, Operation::Execute];
        let error = compile_redis_acl(&requested).unwrap_err();
        assert_eq!(error.code, "unsupported_operation");
    }

    #[test]
    fn redis_create_policy_documents_upsert_semantic_limit() {
        let mut create_policy = policy(ResourceKind::Keyspace, "tenant:${tenant_id}:*");
        create_policy.resources[0].operations = vec![Operation::Create];
        let compiled = compile_redis_acl(&create_policy).unwrap();
        let acl = compiled.changes[0].definition["acl_template"].as_array().unwrap();
        let commands = acl.iter().filter_map(|value| value.as_str()).collect::<Vec<_>>();
        assert!(commands.contains(&"+set"));
        assert!(!commands.contains(&"+del"));
        assert!(compiled.changes[0].definition["limitations"].as_array().unwrap().iter()
            .any(|value| value.as_str().unwrap_or("").contains("cannot distinguish create-only from update-only")));
    }

    #[test]
    fn redis_requires_explicit_tenant_key_pattern_and_uses_a_narrow_allowlist() {
        let compiled = compile_redis_acl(&policy(ResourceKind::Keyspace, "tenant:${tenant_id}:*")).unwrap();
        let acl = compiled.changes[0].definition["acl_template"].as_array().unwrap();
        let acl_text = acl.iter().filter_map(|value| value.as_str()).collect::<Vec<_>>().join(" ");
        assert!(acl_text.contains("+get"));
        assert!(acl_text.contains("+set"));
        assert!(!acl_text.contains("+@all"));
        assert!(!acl_text.contains("+keys"));
        assert!(compile_redis_acl(&policy(ResourceKind::Keyspace, "tenant_id")).is_err());
        assert!(compile_redis_acl(&policy(ResourceKind::Keyspace, "*:${tenant_id}:*")).is_err());
    }
}


/// Oracle Virtual Private Database (VPD) policy compiler.
///
/// Oracle's DBMS_RLS predicate is evaluated inside the database for each
/// statement. Tenant identity is read only from a secure application context;
/// the generated package contains a mandatory trusted-verifier integration
/// point and must not be deployed with that placeholder unresolved.
pub fn compile_oracle_vpd(policy: &TenantSecurityPolicy) -> Result<CompiledPolicy, AdapterError> {
    policy.validate().map_err(|e| error("invalid_policy", &format!("The shared policy is invalid: {e:?}")))?;
    let mut changes = Vec::new();
    for resource in &policy.resources {
        if resource.resource.kind != ResourceKind::Table {
            return Err(error("unsupported_resource_kind", "Oracle VPD compilation currently accepts tables only; views and PL/SQL entry points require separately verified policies."));
        }
        if resource.operations.contains(&Operation::Execute) {
            return Err(error("unsupported_operation", "Oracle table VPD does not authorize PL/SQL execution; package and procedure access require a separate least-privilege grant policy."));
        }
        let owner = identifier(resource.resource.namespace.as_deref().ok_or_else(|| error("oracle_schema_required", "Oracle protected tables must specify their owning schema."))?, 128)?;
        let table = identifier(&resource.resource.name, 128)?;
        let tenant_column = identifier(&resource.tenant_key, 128)?;
        let identity = format!("{}:{}:{}", policy.policy_id, owner.to_ascii_uppercase(), table.to_ascii_uppercase());
        let digest = Sha256::digest(identity.as_bytes());
        let suffix = hex::encode(&digest[..8]).to_ascii_uppercase();
        let package = format!("PROXIMA_CTX_{suffix}");
        let policy_name = format!("PROXIMA_POL_{suffix}");
        let function_name = format!("PROXIMA_VPD_{suffix}");
        let owner_sql = format!("\"{}\"", owner.replace('"', "\"\""));
        let table_sql = format!("\"{}\"", table.replace('"', "\"\""));
        let column_sql = format!("\"{}\"", tenant_column.replace('"', "\"\""));
        let package_sql = format!("{owner_sql}.\"{package}\"");
        let function_sql = format!("{owner_sql}.\"{function_name}\"");
        let predicate = format!("{column_sql} = SYS_CONTEXT('PROXIMA_TENANT_CTX','TENANT_ID')");
        let statement_types = resource.operations.iter().filter_map(|op| match op {
            Operation::Read => Some("SELECT"),
            Operation::Create => Some("INSERT"),
            Operation::Update => Some("UPDATE"),
            Operation::Delete => Some("DELETE"),
            Operation::Execute => None,
        }).collect::<Vec<_>>().join(",");
        let statements = vec![
            format!(
                "CREATE OR REPLACE PACKAGE {package_sql} AUTHID DEFINER AS\n  PROCEDURE SET_TENANT(p_tenant_id IN VARCHAR2, p_signed_context IN CLOB, p_signature IN VARCHAR2);\n  FUNCTION TENANT_PREDICATE(p_schema IN VARCHAR2, p_object IN VARCHAR2) RETURN VARCHAR2;\nEND;"
            ),
            format!(
                "CREATE OR REPLACE PACKAGE BODY {package_sql} AS\n  FUNCTION PROXIMA_TRUSTED_ASSERTION_VERIFY(p_tenant_id IN VARCHAR2, p_signed_context IN CLOB, p_signature IN VARCHAR2) RETURN BOOLEAN IS\n  BEGIN\n    -- Fail closed until the deployment supplies the audited signature verifier.\n    RAISE_APPLICATION_ERROR(-20073, 'Trusted tenant assertion verifier is not configured');\n    RETURN FALSE;\n  END;\n  PROCEDURE SET_TENANT(p_tenant_id IN VARCHAR2, p_signed_context IN CLOB, p_signature IN VARCHAR2) IS\n  BEGIN\n    IF p_tenant_id IS NULL OR LENGTH(p_tenant_id) > 256 THEN RAISE_APPLICATION_ERROR(-20071, 'Invalid tenant identity'); END IF;\n    -- REQUIRED: replace this fail-closed hook with verification of the signed,\n    -- short-lived tenant assertion against a key unavailable to application users.\n    IF NOT PROXIMA_TRUSTED_ASSERTION_VERIFY(p_tenant_id, p_signed_context, p_signature) THEN\n      RAISE_APPLICATION_ERROR(-20072, 'Tenant assertion rejected');\n    END IF;\n    DBMS_SESSION.SET_CONTEXT('PROXIMA_TENANT_CTX','TENANT_ID',p_tenant_id);\n  END;\n  FUNCTION TENANT_PREDICATE(p_schema IN VARCHAR2, p_object IN VARCHAR2) RETURN VARCHAR2 IS\n  BEGIN\n    IF SYS_CONTEXT('PROXIMA_TENANT_CTX','TENANT_ID') IS NULL THEN\n      RETURN '1=0';\n    END IF;\n    RETURN '{predicate}';\n  END;\nEND;"
            ),
            format!("CREATE CONTEXT PROXIMA_TENANT_CTX USING {package_sql};"),
            format!(
                "CREATE OR REPLACE FUNCTION {function_sql}(p_schema IN VARCHAR2, p_object IN VARCHAR2) RETURN VARCHAR2 AUTHID DEFINER IS\nBEGIN\n  IF SYS_CONTEXT('PROXIMA_TENANT_CTX','TENANT_ID') IS NULL THEN RETURN '1=0'; END IF;\n  RETURN '{predicate}';\nEND;"
            ),
            format!(
                "BEGIN\n  DBMS_RLS.ADD_POLICY(\n    object_schema => '{}', object_name => '{}', policy_name => '{}',\n    function_schema => '{}', policy_function => '{}',\n    statement_types => '{}', update_check => TRUE, enable => TRUE,\n    policy_type => DBMS_RLS.DYNAMIC);\nEND;",
                owner.replace('\'', "''"), table.replace('\'', "''"), policy_name,
                owner.replace('\'', "''"), function_name.replace('\'', "''"), statement_types
            )
        ];
        changes.push(resource_change(resource, "oracle_create_vpd_policy_plan", json!({
            "plsql_batches": statements,
            "native_enforcement": "Oracle DBMS_RLS Virtual Private Database",
            "tenant_identity_source": "secure Oracle application context PROXIMA_TENANT_CTX.TENANT_ID",
            "missing_context_behavior": "deny_all_predicate",
            "write_semantics": "DBMS_RLS update_check TRUE enforces tenant predicate on inserted and updated row values",
            "required_trusted_identity_integration": {
                "placeholder": "PROXIMA_TRUSTED_ASSERTION_VERIFY",
                "must_validate": ["signature", "issuer", "audience", "target_id", "tenant_id", "expiry", "nonce_or_replay_window"],
                "key_storage": "database wallet or external secret manager; never application-readable",
                "failure_behavior": "raise error and leave context unset"
            },
            "required_grants": [
                "The deployment principal needs narrowly scoped DBMS_RLS policy administration rights.",
                "The runtime principal must not own protected tables and must not have EXEMPT ACCESS POLICY.",
                "Only the trusted context package may set PROXIMA_TENANT_CTX; revoke direct package/context administration from application principals."
            ],
            "requires_approval": true,
            "limitations": [
                "The trusted assertion verifier is a mandatory implementation dependency; the generated plan is not deployable until it is linked and independently tested.",
                "Oracle VPD is not automatically applied to every access path: inspect SYS-owned objects, definer-rights PL/SQL, synonyms, views, database links and exempt principals.",
                "This plan does not grant table privileges or secure PL/SQL EXECUTE privileges.",
                "The compiler does not execute DDL or certify tenant isolation."
            ]
        })));
    }
    Ok(CompiledPolicy { database_kind: DatabaseKind::Oracle, policy_id: policy.policy_id.clone(), revision: policy.revision, changes, requires_approval: true })
}


#[cfg(test)]
mod oracle_vpd_tests {
    use super::*;

    fn oracle_policy() -> TenantSecurityPolicy {
        TenantSecurityPolicy {
            schema_version: crate::security_core::SECURITY_MODEL_VERSION.into(),
            policy_id: "oracle-tenant-boundary".into(),
            revision: 1,
            tenant_identity_claim: "tenant_id".into(),
            resources: vec![ProtectedResource {
                resource: crate::security_core::ResourceRef {
                    namespace: Some("APP".into()),
                    name: "ORDERS".into(),
                    kind: ResourceKind::Table,
                },
                tenant_key: "TENANT_ID".into(),
                operations: vec![Operation::Read, Operation::Create, Operation::Update, Operation::Delete],
            }],
        }
    }

    #[test]
    fn oracle_compiles_vpd_with_secure_context_and_write_check() {
        let compiled = compile_oracle_vpd(&oracle_policy()).unwrap();
        assert_eq!(compiled.database_kind, DatabaseKind::Oracle);
        assert!(compiled.requires_approval);
        let batches = compiled.changes[0].definition["plsql_batches"].as_array().unwrap();
        let sql = batches.iter().filter_map(|value| value.as_str()).collect::<Vec<_>>().join("\n");
        assert!(sql.contains("DBMS_RLS.ADD_POLICY"));
        assert!(sql.contains("SYS_CONTEXT('PROXIMA_TENANT_CTX','TENANT_ID')"));
        assert!(sql.contains("update_check => TRUE"));
        assert!(sql.contains("RETURN '1=0'"));
        assert!(sql.contains("PROXIMA_TRUSTED_ASSERTION_VERIFY"));
        assert!(sql.contains("statement_types => 'SELECT,INSERT,UPDATE,DELETE'"));
        assert!(!sql.contains("CLIENT_IDENTIFIER"));
    }

    #[test]
    fn oracle_rejects_missing_schema_and_execute_operations() {
        let mut policy = oracle_policy();
        policy.resources[0].resource.namespace = None;
        assert_eq!(compile_oracle_vpd(&policy).unwrap_err().code, "oracle_schema_required");
        let mut policy = oracle_policy();
        policy.resources[0].operations.push(Operation::Execute);
        assert_eq!(compile_oracle_vpd(&policy).unwrap_err().code, "unsupported_operation");
    }
}
