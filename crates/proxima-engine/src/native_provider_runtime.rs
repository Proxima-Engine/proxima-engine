//! Cloud reconciliation for native database authorization providers.
//!
//! These adapters provision native identities and authorization boundaries on
//! the customer database service. They do not pretend that native IAM/SQL/REST
//! authorization is a Proxima wire-protocol gateway.
use crate::{
    cassandra_tenant::{CassandraTenant, ScyllaCassandraExecutor},
    dynamodb_tenant::{AwsSdkDynamoIamAdmin, DynamoTenant},
    oracle_tenant::{OracleExecutor, OracleRsExecutor, OracleTenant},
    runtime_reconciliation::{self, RuntimePhase, RuntimeRecord},
    search_cluster::{SearchClusterClient, SearchProvider, TenantSearchCredential},
    sqlite_tenant::SqliteTenantDatabase,
    sqlserver_runtime::VerifiedBinding,
};
use serde_json::{json, Value};
use std::{
    collections::{HashMap, HashSet},
    fs, io,
    path::{Path, PathBuf},
    time::Duration,
};
use tokio_postgres_rustls::MakeRustlsConnect;
use tokio_rustls::rustls::{ClientConfig, RootCertStore};

#[derive(Clone, Default)]
pub struct NativeProviderRuntime;

impl NativeProviderRuntime {
    /// Reconcile PostgreSQL/CockroachDB against the Engine's single configured
    /// native upstream. The Engine does not silently retarget a running listener:
    /// Cloud assignment must exactly match the node's verify-full upstream.
    pub async fn activate_postgres(
        &self,
        assignment: &Value,
        credentials: &Value,
        state_path: &Path,
        state: &mut RuntimeRecord,
    ) -> Result<Vec<VerifiedBinding>, Box<dyn std::error::Error + Send + Sync>> {
        let provider = required(assignment, "provider_key")?;
        if !matches!(provider, "postgresql" | "cockroachdb")
            || required(assignment, "gateway_runtime")? != "proxima-engine"
            || required(assignment, "cloud_integration_state")? != "enabled"
        {
            return Err(
                invalid("native PostgreSQL assignment provider/runtime/state mismatch").into(),
            );
        }
        if required(assignment, "tls_mode")? != "verify-full"
            || std::env::var("PROXIMA_UPSTREAM_TLS_MODE").as_deref() != Ok("verify-full")
        {
            return Err(invalid(
                "PostgreSQL/CockroachDB Cloud assignments require Engine upstream TLS verify-full",
            )
            .into());
        }
        let host = assignment
            .pointer("/endpoint/host")
            .and_then(Value::as_str)
            .filter(|v| !v.is_empty())
            .ok_or_else(|| invalid("PostgreSQL upstream host is missing"))?;
        let port = assignment
            .pointer("/endpoint/port")
            .and_then(Value::as_u64)
            .filter(|v| (1..=65535).contains(v))
            .ok_or_else(|| invalid("PostgreSQL upstream port is invalid"))?
            as u16;
        let expected_addr = if host.contains(':') && !host.starts_with('[') {
            format!("[{host}]:{port}")
        } else {
            format!("{host}:{port}")
        };
        let configured_addr = std::env::var("PROXIMA_UPSTREAM_ADDR").map_err(|_| {
            invalid(
                "PROXIMA_UPSTREAM_ADDR is required for native PostgreSQL/CockroachDB assignments",
            )
        })?;
        if configured_addr != expected_addr {
            return Err(invalid(format!("Cloud target {expected_addr} does not match this Engine node's configured PROXIMA_UPSTREAM_ADDR {configured_addr}")).into());
        }
        let server_name = std::env::var("PROXIMA_UPSTREAM_TLS_SERVER_NAME")
            .map_err(|_| invalid("PROXIMA_UPSTREAM_TLS_SERVER_NAME is required"))?;
        let runtime = credentials
            .get("gateway_runtime_config")
            .ok_or_else(|| invalid("PostgreSQL gateway_runtime_config is required"))?;
        if runtime.get("schema_version").and_then(Value::as_u64) != Some(1)
            || runtime.get("provider_key").and_then(Value::as_str) != Some(provider)
        {
            return Err(invalid("PostgreSQL runtime schema/provider mismatch").into());
        }
        let expected_server_name = runtime
            .get("upstream_server_name")
            .and_then(Value::as_str)
            .unwrap_or(host);
        if expected_server_name != host || server_name != host {
            return Err(invalid("PostgreSQL/CockroachDB TLS server name must exactly match the signed Cloud endpoint hostname").into());
        }
        let ca_path = runtime
            .get("upstream_tls_ca_file")
            .and_then(Value::as_str)
            .map(PathBuf::from)
            .or_else(|| std::env::var_os("PROXIMA_UPSTREAM_TLS_CA_FILE").map(PathBuf::from))
            .ok_or_else(|| invalid("PostgreSQL upstream CA file is required"))?;
        let cert_file = fs::File::open(&ca_path)?;
        let certs = rustls_pemfile::certs(&mut std::io::BufReader::new(cert_file))
            .collect::<Result<Vec<_>, _>>()?;
        if certs.is_empty() {
            return Err(invalid("PostgreSQL upstream CA bundle is empty").into());
        }
        let mut root_store = RootCertStore::empty();
        for cert in certs {
            root_store.add(cert)?;
        }
        let tls_config = ClientConfig::builder()
            .with_root_certificates(root_store)
            .with_no_client_auth();
        let tls = MakeRustlsConnect::new(tls_config);

        let database = assignment
            .get("database_name")
            .and_then(Value::as_str)
            .filter(|v| !v.is_empty())
            .ok_or_else(|| invalid("PostgreSQL target database name is missing"))?;
        let admin_user = required(credentials, "username")?;
        let admin_password = required(credentials, "password")?;
        let mut pg = tokio_postgres::Config::new();
        pg.host(host)
            .port(port)
            .user(admin_user)
            .password(admin_password)
            .dbname(database)
            .connect_timeout(Duration::from_secs(15));
        let (client, connection) = pg.connect(tls).await?;
        tokio::spawn(async move {
            if let Err(error) = connection.await {
                tracing::warn!(%error, "native PostgreSQL provider verification connection ended");
            }
        });
        client.query_one("SELECT 1", &[]).await?;

        let bindings = assignment
            .get("tenant_bindings")
            .and_then(Value::as_array)
            .ok_or_else(|| invalid("PostgreSQL tenant_bindings are missing"))?;
        let users = runtime
            .get("users")
            .and_then(Value::as_array)
            .ok_or_else(|| invalid("PostgreSQL gateway_runtime_config.users must be an array"))?;
        let active_count = bindings
            .iter()
            .filter(|b| b.get("status").and_then(Value::as_str) != Some("revoked"))
            .count();
        if users.len() != active_count {
            return Err(invalid(
                "PostgreSQL runtime users must exactly cover non-revoked tenant bindings",
            )
            .into());
        }
        let user_ids = users
            .iter()
            .map(|u| required(u, "tenant_id").map(str::to_owned))
            .collect::<io::Result<HashSet<_>>>()?;
        if user_ids.len() != users.len() {
            return Err(invalid("duplicate PostgreSQL runtime tenant IDs").into());
        }
        let prefix = std::env::var("PROXIMA_TENANT_ROLE_PREFIX")
            .unwrap_or_else(|_| "proxima_tenant_".to_owned());
        let target_id = required(assignment, "database_target_id")?;
        let revision = assignment
            .get("config_revision")
            .and_then(Value::as_i64)
            .filter(|v| *v > 0)
            .ok_or_else(|| invalid("PostgreSQL config revision is missing"))?;
        let credential_revision = assignment
            .get("credential_revision")
            .and_then(Value::as_u64)
            .filter(|v| *v > 0)
            .ok_or_else(|| invalid("PostgreSQL credential revision is missing"))?;
        let needs_apply = state.phase != RuntimePhase::Applied
            || state.applied_revision != Some(state.desired_revision);
        let mut evidence = Vec::with_capacity(bindings.len());
        for binding in bindings {
            let tenant_id = required(binding, "tenant_id")?;
            let namespace = required(binding, "namespace")?;
            let expected_role = format!("{}{}", prefix, tenant_id.replace('-', "_"));
            if expected_role.len() > 63 || required(binding, "identity_reference")? != expected_role
            {
                return Err(invalid(
                    "PostgreSQL tenant role does not match the Engine tenant-token role mapping",
                )
                .into());
            }
            let status = binding
                .get("status")
                .and_then(Value::as_str)
                .unwrap_or_default();
            if status == "revoked" {
                let row = client
                    .query_opt(
                        "SELECT rolcanlogin FROM pg_roles WHERE rolname=$1",
                        &[&expected_role],
                    )
                    .await?;
                if let Some(row) = row {
                    let can_login: bool = row.get(0);
                    if can_login && needs_apply {
                        let sql =
                            format!("ALTER ROLE {} NOLOGIN", quote_pg_identifier(&expected_role));
                        client.batch_execute(&sql).await?;
                    } else if can_login {
                        return Err(
                            invalid("revoked PostgreSQL tenant role still has LOGIN").into()
                        );
                    }
                }
                evidence.push(VerifiedBinding {
                    provider_key: provider.to_owned(),
                    binding_id: required(binding, "binding_id")?.to_owned(),
                    target_id: target_id.to_owned(), revision,
                    tenant_id: tenant_id.to_owned(), identity_reference: expected_role,
                    database: namespace.to_owned(), status: "revoked".into(),
                    details: json!({"database":database,"role_login":false,"revocation":"role absent or NOLOGIN verified"}),
                });
                continue;
            }
            if !user_ids.contains(tenant_id) {
                return Err(
                    invalid("PostgreSQL binding has no matching runtime user declaration").into(),
                );
            }
            let role = client
                .query_opt(
                    "SELECT rolsuper, rolbypassrls, rolcanlogin FROM pg_roles WHERE rolname=$1",
                    &[&expected_role],
                )
                .await?
                .ok_or_else(|| {
                    invalid(format!(
                        "PostgreSQL tenant role {expected_role} does not exist"
                    ))
                })?;
            let is_superuser: bool = role.get(0);
            let bypass_rls: bool = role.get(1);
            let can_login: bool = role.get(2);
            if is_superuser || bypass_rls {
                return Err(
                    invalid("PostgreSQL tenant role must be NOSUPERUSER and NOBYPASSRLS").into(),
                );
            }
            if !can_login && needs_apply {
                let sql = format!("ALTER ROLE {} LOGIN", quote_pg_identifier(&expected_role));
                client.batch_execute(&sql).await?;
            } else if !can_login {
                return Err(invalid("PostgreSQL tenant role is not enabled for LOGIN").into());
            }
            let policy_verified: bool = client
                .query_one(
                    "SELECT EXISTS (\
                   SELECT 1 FROM pg_policies p \
                   JOIN pg_class c ON c.relname=p.tablename \
                   JOIN pg_namespace n ON n.nspname=p.schemaname \
                   WHERE p.schemaname=n.nspname AND p.roles::text[] @> ARRAY[$1]::text[] \
                     AND c.relnamespace=n.oid AND c.relrowsecurity AND c.relforcerowsecurity \
                     AND POSITION($2 IN COALESCE(p.qual,'')) > 0 \
                     AND POSITION($2 IN COALESCE(p.with_check,'')) > 0 \
                 )",
                    &[&expected_role, &namespace],
                )
                .await?
                .get(0);
            if !policy_verified {
                return Err(invalid(format!("no forced row-level security policy was verified for tenant role {expected_role} and namespace {namespace}")).into());
            }
            evidence.push(VerifiedBinding {
                provider_key: provider.to_owned(),
                binding_id: required(binding, "binding_id")?.to_owned(),
                target_id: target_id.to_owned(), revision,
                tenant_id: tenant_id.to_owned(), identity_reference: expected_role,
                database: namespace.to_owned(), status: "active".into(),
                details: json!({"identity_verified":true,"isolation_verified":true,"database":database,"role_login":true,"superuser":false,"bypass_rls":false,"forced_rls_policy_verified":true,"upstream_tls":"verify-full"}),
            });
        }
        if evidence.len() != bindings.len() {
            return Err(
                invalid("PostgreSQL runtime did not produce evidence for every binding").into(),
            );
        }
        if needs_apply {
            state.begin_apply(state.desired_revision, credential_revision)?;
            runtime_reconciliation::persist(state_path, state)?;
            state.mark_applied(state.desired_revision, true)?;
            runtime_reconciliation::persist(state_path, state)?;
        }
        Ok(evidence)
    }

    pub async fn activate(
        &self,
        assignment: &Value,
        credentials: &Value,
        private_root: &Path,
        state_path: &Path,
        state: &mut RuntimeRecord,
    ) -> Result<Vec<VerifiedBinding>, Box<dyn std::error::Error + Send + Sync>> {
        let provider = required(assignment, "provider_key")?;
        let runtime_name = required(assignment, "gateway_runtime")?;
        let expected_runtime = match provider {
            "sqlite" => "proxima-engine-native-sqlite",
            "oracle" => "proxima-engine-native-oracle",
            "dynamodb" => "proxima-engine-native-dynamodb",
            "cassandra" => "proxima-engine-native-cassandra",
            "elasticsearch" => "proxima-engine-native-search",
            _ => {
                return Err(
                    invalid("provider is not handled by the native provider runtime").into(),
                )
            }
        };
        if runtime_name != expected_runtime {
            return Err(
                invalid("provider runtime does not match the native provider adapter").into(),
            );
        }
        if required(assignment, "cloud_integration_state")? != "enabled" {
            return Err(invalid("native provider assignment is not enabled in Cloud").into());
        }
        let runtime = credentials
            .get("gateway_runtime_config")
            .ok_or_else(|| invalid("native provider gateway_runtime_config is required"))?;
        if runtime.get("schema_version").and_then(Value::as_u64) != Some(1)
            || runtime.get("provider_key").and_then(Value::as_str) != Some(provider)
        {
            return Err(invalid("native provider runtime schema/provider mismatch").into());
        }
        let users = runtime
            .get("users")
            .and_then(Value::as_array)
            .ok_or_else(|| invalid("native provider runtime users must be an array"))?;
        let bindings = assignment
            .get("tenant_bindings")
            .and_then(Value::as_array)
            .ok_or_else(|| invalid("native provider tenant_bindings are missing"))?;
        let mut binding_by_tenant = HashMap::new();
        for binding in bindings {
            let tenant_id = required(binding, "tenant_id")?.to_owned();
            if binding_by_tenant.insert(tenant_id, binding).is_some() {
                return Err(invalid("duplicate native provider tenant binding").into());
            }
        }
        let active_count = bindings
            .iter()
            .filter(|binding| binding.get("status").and_then(Value::as_str) != Some("revoked"))
            .count();
        if active_count != users.len() {
            return Err(invalid(
                "native provider users must exactly cover all non-revoked tenant bindings",
            )
            .into());
        }

        let assignment_id = required(assignment, "assignment_id")?;
        let target_id = required(assignment, "database_target_id")?;
        let revision = assignment
            .get("config_revision")
            .and_then(Value::as_i64)
            .filter(|value| *value > 0)
            .ok_or_else(|| invalid("native provider configuration revision is missing"))?;
        let credential_revision = assignment
            .get("credential_revision")
            .and_then(Value::as_u64)
            .filter(|value| *value > 0)
            .ok_or_else(|| invalid("native provider credential revision is missing"))?;
        let needs_apply = state.phase != RuntimePhase::Applied
            || state.applied_revision != Some(state.desired_revision);

        let host = assignment
            .pointer("/endpoint/host")
            .and_then(Value::as_str)
            .unwrap_or_default();
        let port = assignment
            .pointer("/endpoint/port")
            .and_then(Value::as_u64)
            .unwrap_or_default();
        let database_name = assignment
            .get("database_name")
            .and_then(Value::as_str)
            .unwrap_or_default();
        let admin_user = credentials
            .get("username")
            .and_then(Value::as_str)
            .unwrap_or_default();
        let admin_password = credentials
            .get("password")
            .and_then(Value::as_str)
            .unwrap_or_default();

        let mut evidence = Vec::with_capacity(bindings.len());
        match provider {
            "sqlite" => {
                let root = std::env::var_os("PROXIMA_SQLITE_TENANT_ROOT")
                    .map(PathBuf::from)
                    .unwrap_or_else(|| private_root.join("sqlite-tenants"));
                fs::create_dir_all(&root)?;
                for binding in bindings
                    .iter()
                    .filter(|b| b.get("status").and_then(Value::as_str) == Some("revoked"))
                {
                    let tenant_key = required(binding, "namespace")?;
                    let marker_dir = root.join("revoked");
                    fs::create_dir_all(&marker_dir)?;
                    write_private(
                        &marker_dir.join(format!("{tenant_key}.revoked")),
                        b"revoked\n",
                    )?;
                    evidence.push(binding_evidence(provider, binding, target_id, revision, "revoked", json!({"storage":"sqlite-file-per-tenant","revocation":"local tenant file marked revoked; retained for explicit retention policy"}))?);
                }
                for user in users {
                    let tenant_id = required(user, "tenant_id")?;
                    let tenant_key = required(user, "tenant_key")?;
                    let binding = binding_by_tenant
                        .get(tenant_id)
                        .ok_or_else(|| invalid("SQLite user has no Cloud tenant binding"))?;
                    let expected_identity = format!("sqlite-file-per-tenant:{tenant_key}");
                    if required(binding, "identity_reference")? != expected_identity
                        || required(binding, "namespace")? != tenant_key
                    {
                        return Err(invalid("SQLite file identity/namespace does not match the Cloud tenant binding").into());
                    }
                    let db = SqliteTenantDatabase::open(&root, tenant_key)?;
                    let path = db.path().to_string_lossy().into_owned();
                    drop(db);
                    let marker = root.join("revoked").join(format!("{tenant_key}.revoked"));
                    if marker.exists() {
                        fs::remove_file(marker)?;
                    }
                    evidence.push(binding_evidence(provider, binding, target_id, revision, "active", json!({"storage":"sqlite-file-per-tenant","file_path":path,"filesystem_boundary_verified":true}))?);
                }
            }
            "oracle" => {
                let service = runtime
                    .get("service_name")
                    .and_then(Value::as_str)
                    .unwrap_or(database_name);
                let executor =
                    OracleRsExecutor::new(host, port as u16, service, admin_user, admin_password)?;
                for binding in bindings
                    .iter()
                    .filter(|b| b.get("status").and_then(Value::as_str) == Some("revoked"))
                {
                    let identity = required(binding, "identity_reference")?;
                    let tenant_key = identity
                        .strip_prefix("PROXIMA_")
                        .and_then(|v| v.strip_suffix("_OWNER"))
                        .ok_or_else(|| {
                            invalid("revoked Oracle identity is not a managed Proxima schema owner")
                        })?;
                    let tenant = OracleTenant::new(tenant_key, "REVOKED-IDENTITY-NOT-USED-0001")?;
                    tenant.revoke(&executor).await?;
                    evidence.push(binding_evidence(provider, binding, target_id, revision, "revoked", json!({"schema_owner":identity,"account_locked":true,"application_privileges_revoked":true}))?);
                }
                let mut seen = HashSet::new();
                for user in users {
                    let tenant_id = required(user, "tenant_id")?;
                    let tenant_key = required(user, "tenant_key")?;
                    let password = required(user, "password")?;
                    if !seen.insert(tenant_id) {
                        return Err(invalid("duplicate Oracle runtime tenant").into());
                    }
                    let binding = binding_by_tenant
                        .get(tenant_id)
                        .ok_or_else(|| invalid("Oracle user has no Cloud tenant binding"))?;
                    let mut tenant = OracleTenant::new(tenant_key, password)?;
                    if required(binding, "identity_reference")? != tenant.username()
                        || required(binding, "namespace")? != tenant.username()
                    {
                        return Err(invalid(
                            "Oracle schema owner does not match the Cloud tenant binding",
                        )
                        .into());
                    }
                    if needs_apply {
                        if executor
                            .user_exists(tenant.username())
                            .await
                            .map_err(io::Error::other)?
                        {
                            tenant.rotate(&executor, password).await?;
                        } else {
                            tenant.provision(&executor).await?;
                        }
                    } else {
                        tenant.verify(&executor).await?;
                    }
                    evidence.push(binding_evidence(provider, binding, target_id, revision, "active", json!({"schema_owner":tenant.username(),"least_privilege_verified":true,"dba_role_denied":true}))?);
                }
            }
            "cassandra" => {
                let ca = runtime
                    .get("upstream_tls_ca_file")
                    .and_then(Value::as_str)
                    .map(PathBuf::from)
                    .or_else(|| std::env::var_os("PROXIMA_CASSANDRA_CA_PEM").map(PathBuf::from))
                    .ok_or_else(|| invalid("Cassandra upstream CA PEM file is required"))?;
                let endpoint = format!("{host}:{port}");
                let executor = ScyllaCassandraExecutor::connect_tls(
                    &endpoint,
                    admin_user,
                    admin_password,
                    &ca,
                )
                .await?;
                let datacenter = runtime
                    .get("datacenter")
                    .and_then(Value::as_str)
                    .ok_or_else(|| invalid("Cassandra datacenter is required"))?;
                let replication_factor = runtime
                    .get("replication_factor")
                    .and_then(Value::as_u64)
                    .filter(|v| (1..=5).contains(v))
                    .ok_or_else(|| {
                        invalid("Cassandra replication_factor must be between 1 and 5")
                    })? as u8;
                for binding in bindings
                    .iter()
                    .filter(|b| b.get("status").and_then(Value::as_str) == Some("revoked"))
                {
                    let role = required(binding, "identity_reference")?;
                    let tenant_key = role
                        .strip_prefix("proxima_")
                        .and_then(|v| v.strip_suffix("_app"))
                        .ok_or_else(|| {
                            invalid("revoked Cassandra identity is not a managed Proxima role")
                        })?;
                    let tenant =
                        CassandraTenant::new(tenant_key, "REVOKED-IDENTITY-NOT-USED-0001")?;
                    tenant.revoke(&executor).await?;
                    evidence.push(binding_evidence(
                        provider,
                        binding,
                        target_id,
                        revision,
                        "revoked",
                        json!({"role":role,"login_disabled":true,"keyspace_grants_revoked":true}),
                    )?);
                }
                for user in users {
                    let tenant_id = required(user, "tenant_id")?;
                    let tenant_key = required(user, "tenant_key")?;
                    let password = required(user, "password")?;
                    let binding = binding_by_tenant
                        .get(tenant_id)
                        .ok_or_else(|| invalid("Cassandra user has no Cloud tenant binding"))?;
                    let tenant = CassandraTenant::new(tenant_key, password)?;
                    if required(binding, "identity_reference")? != tenant.role()
                        || required(binding, "namespace")? != tenant.keyspace()
                    {
                        return Err(invalid(
                            "Cassandra role/keyspace does not match the Cloud tenant binding",
                        )
                        .into());
                    }
                    if needs_apply {
                        tenant
                            .provision(&executor, datacenter, replication_factor)
                            .await?;
                    } else {
                        tenant.verify(&executor).await?;
                    }
                    evidence.push(binding_evidence(provider, binding, target_id, revision, "active", json!({"role":tenant.role(),"keyspace":tenant.keyspace(),"select_modify_only":true}))?);
                }
            }
            "dynamodb" => {
                let table_arn = runtime
                    .get("table_arn")
                    .and_then(Value::as_str)
                    .ok_or_else(|| invalid("DynamoDB table_arn is required"))?;
                let arn_parts = table_arn.split(':').collect::<Vec<_>>();
                if arn_parts.len() < 6 || arn_parts[0] != "arn" || arn_parts[2] != "dynamodb" {
                    return Err(invalid(
                        "DynamoDB table_arn must be a real AWS DynamoDB table ARN",
                    )
                    .into());
                }
                let region = arn_parts[3];
                let dns_suffix = if arn_parts[1] == "aws-cn" {
                    "amazonaws.com.cn"
                } else {
                    "amazonaws.com"
                };
                let expected_host = format!("dynamodb.{region}.{dns_suffix}");
                let configured_region = std::env::var("AWS_REGION")
                    .or_else(|_| std::env::var("AWS_DEFAULT_REGION"))
                    .map_err(|_| {
                        invalid(
                            "AWS_REGION or AWS_DEFAULT_REGION must match the DynamoDB table ARN",
                        )
                    })?;
                if configured_region != region || host != expected_host || port != 443 {
                    return Err(invalid(
                        "DynamoDB endpoint, port and AWS region must match the table ARN region",
                    )
                    .into());
                }
                let admin = AwsSdkDynamoIamAdmin::from_default_credential_chain().await?;
                for binding in bindings
                    .iter()
                    .filter(|b| b.get("status").and_then(Value::as_str) == Some("revoked"))
                {
                    let tenant_id = required(binding, "tenant_id")?;
                    let tenant = DynamoTenant::new(tenant_id, table_arn)?;
                    if required(binding, "identity_reference")? != tenant.role_name() {
                        return Err(invalid(
                            "revoked DynamoDB IAM role does not match the Cloud tenant binding",
                        )
                        .into());
                    }
                    tenant.revoke(&admin).await?;
                    evidence.push(binding_evidence(
                        provider,
                        binding,
                        target_id,
                        revision,
                        "revoked",
                        json!({"iam_role":tenant.role_name(),"role_deleted":true}),
                    )?);
                }
                for user in users {
                    let tenant_id = required(user, "tenant_id")?;
                    let trust = user
                        .get("trust_policy")
                        .cloned()
                        .ok_or_else(|| invalid("DynamoDB tenant trust_policy is required"))?;
                    let binding = binding_by_tenant
                        .get(tenant_id)
                        .ok_or_else(|| invalid("DynamoDB user has no Cloud tenant binding"))?;
                    let tenant = DynamoTenant::new(tenant_id, table_arn)?;
                    if required(binding, "identity_reference")? != tenant.role_name()
                        || required(binding, "namespace")? != tenant_id
                    {
                        return Err(invalid("DynamoDB IAM role/partition namespace does not match the Cloud tenant binding").into());
                    }
                    if needs_apply {
                        tenant.provision(&admin, trust).await?;
                    } else {
                        tenant.verify(&admin).await?;
                    }
                    evidence.push(binding_evidence(provider, binding, target_id, revision, "active", json!({"iam_role":tenant.role_name(),"table_arn":table_arn,"leading_keys_partition_scope_verified":true,"session_duration_seconds":3600}))?);
                }
            }
            "elasticsearch" => {
                let distribution = runtime
                    .get("distribution")
                    .and_then(Value::as_str)
                    .unwrap_or("elasticsearch");
                let search_provider = match distribution {
                    "elasticsearch" => SearchProvider::Elasticsearch,
                    "opensearch" => SearchProvider::OpenSearch,
                    _ => {
                        return Err(invalid(
                            "search distribution must be elasticsearch or opensearch",
                        )
                        .into())
                    }
                };
                let ca_path = runtime
                    .get("upstream_tls_ca_file")
                    .and_then(Value::as_str)
                    .map(PathBuf::from)
                    .or_else(|| {
                        std::env::var_os("PROXIMA_SEARCH_UPSTREAM_CA_PEM").map(PathBuf::from)
                    })
                    .ok_or_else(|| invalid("Search upstream CA PEM file is required"))?;
                let ca = fs::read(ca_path)?;
                let endpoint = format!("https://{host}:{port}");
                let client = SearchClusterClient::connect(
                    search_provider,
                    &endpoint,
                    admin_user,
                    admin_password,
                    Some(&ca),
                )?;
                for binding in bindings
                    .iter()
                    .filter(|b| b.get("status").and_then(Value::as_str) == Some("revoked"))
                {
                    let username = required(binding, "identity_reference")?;
                    let tenant_key = username.strip_prefix("px_").ok_or_else(|| {
                        invalid("revoked search identity is not a managed Proxima user")
                    })?;
                    let role_name = format!("proxima_tenant_{tenant_key}");
                    let credential = TenantSearchCredential::from_value(&json!({
                        "provider":distribution,"tenant_id":tenant_key,"username":username,
                        "role_name":role_name,"password":"REVOKED-IDENTITY-NOT-USED-0001"
                    }))?;
                    client.revoke_tenant(&credential).await?;
                    evidence.push(binding_evidence(provider, binding, target_id, revision, "revoked", json!({"username":username,"role":role_name,"user_role_mapping_revoked":true}))?);
                }
                for user in users {
                    let tenant_id = required(user, "tenant_id")?;
                    let tenant_key = required(user, "tenant_key")?;
                    let password = required(user, "password")?;
                    let binding = binding_by_tenant
                        .get(tenant_id)
                        .ok_or_else(|| invalid("search user has no Cloud tenant binding"))?;
                    let credential = client
                        .provision_tenant_with_password(tenant_key, password)
                        .await?;
                    let expected_namespace = format!("tenant-{tenant_key}");
                    if required(binding, "identity_reference")? != credential.username
                        || required(binding, "namespace")? != expected_namespace
                    {
                        return Err(invalid("search username/index namespace does not match the Cloud tenant binding").into());
                    }
                    client.verify_tenant(&credential).await?;
                    client.verify_tenant_authentication(&credential).await?;
                    evidence.push(binding_evidence(provider, binding, target_id, revision, "active", json!({"distribution":distribution,"username":credential.username,"role":credential.role_name,"index_pattern":format!("tenant-{tenant_key}-*"),"native_role_and_authentication_verified":true}))?);
                }
            }
            _ => unreachable!(),
        }

        if needs_apply {
            state.begin_apply(state.desired_revision, credential_revision)?;
            runtime_reconciliation::persist(state_path, state)?;
            state.mark_applied(state.desired_revision, true)?;
            runtime_reconciliation::persist(state_path, state)?;
        }
        if evidence.len() != bindings.len() {
            return Err(invalid(
                "native provider did not produce evidence for every tenant binding",
            )
            .into());
        }
        let _ = assignment_id;
        Ok(evidence)
    }
}

fn quote_pg_identifier(value: &str) -> String {
    format!("\"{}\"", value.replace('\"', "\"\""))
}

fn binding_evidence(
    provider: &str,
    binding: &Value,
    target_id: &str,
    revision: i64,
    status: &str,
    details: Value,
) -> io::Result<VerifiedBinding> {
    Ok(VerifiedBinding {
        provider_key: provider.to_owned(),
        binding_id: required(binding, "binding_id")?.to_owned(),
        target_id: target_id.to_owned(),
        revision,
        tenant_id: required(binding, "tenant_id")?.to_owned(),
        identity_reference: required(binding, "identity_reference")?.to_owned(),
        database: required(binding, "namespace")?.to_owned(),
        status: status.to_owned(),
        details: if status == "active" {
            let mut verified = details.as_object().cloned().unwrap_or_default();
            verified.insert("identity_verified".into(), Value::Bool(true));
            verified.insert("isolation_verified".into(), Value::Bool(true));
            Value::Object(verified)
        } else {
            details
        },
    })
}

fn required<'a>(value: &'a Value, key: &str) -> io::Result<&'a str> {
    value
        .get(key)
        .and_then(Value::as_str)
        .filter(|v| !v.trim().is_empty())
        .ok_or_else(|| invalid(format!("required native provider field is missing: {key}")))
}

fn required_env_path(name: &str) -> io::Result<PathBuf> {
    std::env::var_os(name)
        .map(PathBuf::from)
        .ok_or_else(|| invalid(format!("{name} must point to a local PEM file")))
}

fn write_private(path: &Path, bytes: &[u8]) -> io::Result<()> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    let temporary = path.with_extension("tmp");
    if temporary.exists() {
        fs::remove_file(&temporary)?;
    }
    #[cfg(unix)]
    {
        use std::io::Write;
        use std::os::unix::fs::OpenOptionsExt;
        let mut file = fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&temporary)?;
        file.write_all(bytes)?;
        file.sync_all()?;
    }
    #[cfg(not(unix))]
    {
        fs::write(&temporary, bytes)?;
    }
    if path.exists() {
        fs::remove_file(path)?;
    }
    fs::rename(temporary, path)
}

fn invalid(error: impl std::fmt::Display) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidInput, error.to_string())
}
