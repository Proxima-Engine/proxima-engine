//! Provider-native provisioning plans for the Phase Two core database lifecycle.
//!
//! Tenant-scoped identity and SQL plans for PostgreSQL, CockroachDB, MySQL and
//! MariaDB. Execution is performed by an Engine-side provider executor; secrets
//! remain in memory and are redacted from Debug output.

use ring::rand::{SecureRandom, SystemRandom};
use serde_json::{json, Value};
use sha1::{Digest, Sha1};
use std::{fmt, fs::File, io::BufReader, path::Path};
use uuid::Uuid;
use tokio_postgres::config::SslMode;
use tokio_postgres_rustls::MakeRustlsConnect;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CoreProvider { PostgreSql, CockroachDb, MySql, MariaDb }

impl CoreProvider {
    pub fn parse(value: &str) -> Result<Self, ProvisioningError> {
        match value {
            "postgresql" | "postgres" => Ok(Self::PostgreSql),
            "cockroachdb" => Ok(Self::CockroachDb),
            "mysql" => Ok(Self::MySql),
            "mariadb" => Ok(Self::MariaDb),
            _ => Err(ProvisioningError::UnsupportedProvider),
        }
    }
    pub fn key(self) -> &'static str {
        match self {
            Self::PostgreSql => "postgresql",
            Self::CockroachDb => "cockroachdb",
            Self::MySql => "mysql",
            Self::MariaDb => "mariadb",
        }
    }
    pub fn is_mysql_family(self) -> bool { matches!(self, Self::MySql | Self::MariaDb) }
}

pub struct Secret(Vec<u8>);
impl Secret {
    pub fn new(value: impl AsRef<[u8]>) -> Self { Self(value.as_ref().to_vec()) }
    pub fn expose(&self) -> Result<&str, ProvisioningError> {
        std::str::from_utf8(&self.0).map_err(|_| ProvisioningError::InvalidSecret)
    }
}
impl Drop for Secret { fn drop(&mut self) { self.0.fill(0); } }
impl fmt::Debug for Secret {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result { f.write_str("Secret([REDACTED])") }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ProvisioningError {
    UnsupportedProvider, InvalidTenantId, InvalidNamespace, InvalidDatabaseName,
    EmptyBindings, DuplicateTenant, DuplicateNamespace, RandomGenerationFailed, InvalidSecret,
    ProviderConnectionFailed, ProviderStatementFailed, ProviderHealthCheckFailed, ProviderIsolationFailed, TlsConfigurationFailed,
}
impl fmt::Display for ProvisioningError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::UnsupportedProvider => "provider is outside the Phase Two core lifecycle",
            Self::InvalidTenantId => "tenant ID must be a UUID",
            Self::InvalidNamespace => "tenant namespace contains unsupported characters",
            Self::InvalidDatabaseName => "database name contains unsupported characters",
            Self::EmptyBindings => "at least one tenant binding is required",
            Self::DuplicateTenant => "tenant bindings contain duplicate tenant IDs",
            Self::DuplicateNamespace => "tenant bindings contain duplicate namespaces",
            Self::RandomGenerationFailed => "cryptographic secret generation failed",
            Self::InvalidSecret => "generated secret is not valid UTF-8",
            Self::ProviderConnectionFailed => "provider connection failed",
            Self::ProviderStatementFailed => "provider provisioning statement failed",
            Self::ProviderHealthCheckFailed => "provisioned tenant identity health check failed",
            Self::ProviderIsolationFailed => "provider tenant isolation verification failed",
            Self::TlsConfigurationFailed => "provider TLS trust configuration failed",
        })
    }
}
impl std::error::Error for ProvisioningError {}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TenantBinding { pub binding_id: Option<String>, pub tenant_id: String, pub namespace: String }

pub struct ProvisioningStatement { pub purpose: &'static str, sql: Secret }
impl ProvisioningStatement {
    pub fn sql(&self) -> Result<&str, ProvisioningError> { self.sql.expose() }
}
impl fmt::Debug for ProvisioningStatement {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ProvisioningStatement").field("purpose", &self.purpose)
            .field("sql", &"[REDACTED]").finish()
    }
}

pub struct TenantIdentity {
    pub binding_id: Option<String>,
    pub tenant_id: String,
    pub namespace: String,
    pub username: String,
    pub database: String,
    pub schema: Option<String>,
    pub client_password: Secret,
    pub upstream_password: Secret,
}
impl fmt::Debug for TenantIdentity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("TenantIdentity")
            .field("tenant_id", &self.tenant_id)
            .field("namespace", &self.namespace)
            .field("username", &self.username)
            .field("database", &self.database)
            .field("schema", &self.schema)
            .field("client_password", &"[REDACTED]")
            .field("upstream_password", &"[REDACTED]").finish()
    }
}

pub struct ProvisioningPlan {
    pub provider: CoreProvider,
    pub identities: Vec<TenantIdentity>,
    pub statements: Vec<ProvisioningStatement>,
}
impl fmt::Debug for ProvisioningPlan {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ProvisioningPlan").field("provider", &self.provider)
            .field("tenant_count", &self.identities.len())
            .field("statement_count", &self.statements.len())
            .field("secrets", &"[REDACTED]").finish()
    }
}

pub struct ProvisioningRequest<'a> {
    pub provider_key: &'a str,
    pub database_name: &'a str,
    pub bindings: &'a [TenantBinding],
}

pub fn build_provisioning_plan(request: ProvisioningRequest<'_>) -> Result<ProvisioningPlan, ProvisioningError> {
    let provider = CoreProvider::parse(request.provider_key)?;
    validate_database_name(request.database_name)?;
    if request.bindings.is_empty() { return Err(ProvisioningError::EmptyBindings); }

    let mut tenant_ids = std::collections::HashSet::new();
    let mut namespaces = std::collections::HashSet::new();
    let mut identities = Vec::with_capacity(request.bindings.len());
    let mut statements = Vec::new();

    for binding in request.bindings {
        let tenant_uuid = Uuid::parse_str(&binding.tenant_id).map_err(|_| ProvisioningError::InvalidTenantId)?;
        validate_namespace(&binding.namespace)?;
        if !tenant_ids.insert(tenant_uuid) { return Err(ProvisioningError::DuplicateTenant); }
        if !namespaces.insert(binding.namespace.to_ascii_lowercase()) { return Err(ProvisioningError::DuplicateNamespace); }

        let username = provider_username(provider, tenant_uuid);
        let client_password = random_hex_secret(32)?;
        let upstream_password = random_hex_secret(32)?;
        let tenant_database = if provider.is_mysql_family() { binding.namespace.clone() } else { request.database_name.to_owned() };
        let schema = if provider.is_mysql_family() { None } else { Some(binding.namespace.clone()) };

        match provider {
            CoreProvider::PostgreSql => {
                let role = pg_identifier(&username);
                let password = sql_literal(upstream_password.expose()?);
                let schema_name = pg_identifier(&binding.namespace);
                let database = pg_identifier(request.database_name);
                statements.push(statement("create_or_rotate_role", format!(
                    "DO $proxima$ BEGIN IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = {}) THEN ALTER ROLE {role} WITH LOGIN PASSWORD {password}; ELSE CREATE ROLE {role} LOGIN PASSWORD {password}; END IF; END $proxima$",
                    sql_literal(&username)
                )));
                statements.push(statement("create_tenant_schema", format!("CREATE SCHEMA IF NOT EXISTS {schema_name} AUTHORIZATION {role}")));
                statements.push(statement("enforce_schema_owner", format!("ALTER SCHEMA {schema_name} OWNER TO {role}")));
                statements.push(statement("grant_database_connect", format!("GRANT CONNECT ON DATABASE {database} TO {role}")));
                statements.push(statement("grant_tenant_schema", format!("GRANT USAGE, CREATE ON SCHEMA {schema_name} TO {role}")));
                statements.push(statement("set_tenant_search_path", format!(
                    "ALTER ROLE {role} IN DATABASE {database} SET search_path TO {schema_name}, pg_catalog"
                )));
            }
            CoreProvider::CockroachDb => {
                let role = pg_identifier(&username);
                let password = sql_literal(upstream_password.expose()?);
                let schema_name = pg_identifier(&binding.namespace);
                let database = pg_identifier(request.database_name);
                statements.push(statement("create_tenant_role", format!("CREATE ROLE IF NOT EXISTS {role}")));
                statements.push(statement("rotate_tenant_role_password", format!("ALTER ROLE {role} WITH PASSWORD = {password}")));
                statements.push(statement("create_tenant_schema", format!("CREATE SCHEMA IF NOT EXISTS {schema_name}")));
                statements.push(statement("grant_tenant_schema", format!("GRANT USAGE, CREATE ON SCHEMA {schema_name} TO {role}")));
                statements.push(statement("set_tenant_search_path", format!(
                    "ALTER ROLE {role} SET search_path = {schema_name}, public"
                )));
            }
            CoreProvider::MySql | CoreProvider::MariaDb => {
                let user = sql_literal(&username);
                let host = sql_literal("%");
                let password = sql_literal(upstream_password.expose()?);
                let database = mysql_identifier(&binding.namespace);
                statements.push(statement("create_tenant_database", format!(
                    "CREATE DATABASE IF NOT EXISTS {database} CHARACTER SET utf8mb4"
                )));
                statements.push(statement("create_tenant_upstream_user", format!(
                    "CREATE USER IF NOT EXISTS {user}@{host} IDENTIFIED BY {password}"
                )));
                statements.push(statement("rotate_tenant_upstream_user", format!(
                    "ALTER USER {user}@{host} IDENTIFIED BY {password}"
                )));
                statements.push(statement("grant_tenant_database", format!(
                    "GRANT SELECT, INSERT, UPDATE, DELETE ON {database}.* TO {user}@{host}"
                )));
            }
        }

        identities.push(TenantIdentity {
            binding_id: binding.binding_id.clone(),
            tenant_id: binding.tenant_id.clone(),
            namespace: binding.namespace.clone(),
            username,
            database: tenant_database,
            schema,
            client_password,
            upstream_password,
        });
    }
    Ok(ProvisioningPlan { provider, identities, statements })
}

pub fn mysql_gateway_runtime_config(
    provider: CoreProvider,
    identities: &[TenantIdentity],
    upstream_host: &str,
    upstream_port: u16,
) -> Result<Value, ProvisioningError> {
    if !provider.is_mysql_family() || upstream_host.trim().is_empty()
        || upstream_host.chars().any(|c| matches!(c, '/' | '@' | ':' | '?' | '#'))
        || upstream_port == 0 {
        return Err(ProvisioningError::UnsupportedProvider);
    }
    let mut users = Vec::with_capacity(identities.len());
    for identity in identities {
        let client_password = identity.client_password.expose()?;
        let upstream_password = identity.upstream_password.expose()?;
        let upstream_url = format!("mysql://{}:{}@{}:{}/{}?require_ssl=true&verify_ca=true&verify_identity=true",
            identity.username, upstream_password, upstream_host, upstream_port, identity.database);
        let mut user = json!({
            "username": identity.username,
            "tenant_id": identity.tenant_id,
            "database": identity.database,
            "upstream_url": upstream_url
        });
        match provider {
            CoreProvider::MySql => {
                let stage1 = sha2::Sha256::digest(client_password.as_bytes());
                let stage2 = sha2::Sha256::digest(stage1);
                user["password_sha256"] = Value::String(hex::encode(stage2));
                user["auth_plugin"] = Value::String("caching_sha2_password".into());
            }
            CoreProvider::MariaDb => {
                user["password_sha1"] = Value::String(hex::encode(Sha1::digest(client_password.as_bytes())));
                user["auth_plugin"] = Value::String("mysql_native_password".into());
            }
            _ => return Err(ProvisioningError::UnsupportedProvider),
        }
        users.push(user);
    }
    Ok(json!({ "schema_version": 1, "provider_key": provider.key(), "users": users }))
}

/// Serialize only the application-facing identity metadata required by Cloud.
/// Upstream passwords and SQL statements are deliberately excluded. MySQL/MariaDB
/// client passwords are returned inside the node-encrypted result envelope.
pub fn provisioning_result_payload(plan: &ProvisioningPlan) -> Result<Value, ProvisioningError> {
    let mut bindings = Vec::with_capacity(plan.identities.len());
    for identity in &plan.identities {
        let mut item = json!({
            "binding_id": identity.binding_id,
            "tenant_id": identity.tenant_id,
            "username": identity.username,
            "database": identity.database,
            "schema": identity.schema
        });
        if plan.provider.is_mysql_family() {
            item["client_password"] = Value::String(identity.client_password.expose()?.to_owned());
        }
        bindings.push(item);
    }
    Ok(json!({
        "schema_version": 1,
        "provider_key": plan.provider.key(),
        "isolation_verified": true,
        "bindings": bindings
    }))
}

pub fn build_rotation_statement(
    provider_key: &str, username: &str, new_password: &Secret,
) -> Result<ProvisioningStatement, ProvisioningError> {
    let provider = CoreProvider::parse(provider_key)?;
    validate_username(provider, username)?;
    let password = sql_literal(new_password.expose()?);
    let sql = match provider {
        CoreProvider::PostgreSql => format!("ALTER ROLE {} WITH LOGIN PASSWORD {password}", pg_identifier(username)),
        CoreProvider::CockroachDb => format!("ALTER ROLE {} WITH PASSWORD = {password}", pg_identifier(username)),
        CoreProvider::MySql | CoreProvider::MariaDb => format!("ALTER USER {}@'%' IDENTIFIED BY {password}", sql_literal(username)),
    };
    Ok(statement("rotate_tenant_credential", sql))
}

pub fn build_revocation_statements(
    provider_key: &str, username: &str, database_name: &str, namespace: &str,
) -> Result<Vec<ProvisioningStatement>, ProvisioningError> {
    let provider = CoreProvider::parse(provider_key)?;
    validate_username(provider, username)?;
    validate_database_name(database_name)?;
    validate_namespace(namespace)?;
    let user = if provider.is_mysql_family() { sql_literal(username) } else { pg_identifier(username) };
    let statements = match provider {
        CoreProvider::PostgreSql => vec![
            statement("disable_tenant_login", format!("ALTER ROLE {user} NOLOGIN")),
            statement("revoke_database_connect", format!("REVOKE CONNECT ON DATABASE {} FROM {user}", pg_identifier(database_name))),
            statement("revoke_schema_privileges", format!("REVOKE ALL PRIVILEGES ON SCHEMA {} FROM {user}", pg_identifier(namespace))),
        ],
        CoreProvider::CockroachDb => vec![
            statement("disable_tenant_login", format!("ALTER ROLE {user} NOLOGIN")),
            statement("revoke_schema_privileges", format!("REVOKE ALL PRIVILEGES ON SCHEMA {} FROM {user}", pg_identifier(namespace))),
        ],
        CoreProvider::MySql | CoreProvider::MariaDb => vec![
            statement("revoke_tenant_privileges", format!("REVOKE ALL PRIVILEGES, GRANT OPTION FROM {user}@'%'")),
            statement("lock_tenant_login", format!("ALTER USER {user}@'%' ACCOUNT LOCK")),
        ],
    };
    Ok(statements)
}

fn statement(purpose: &'static str, sql: String) -> ProvisioningStatement {
    ProvisioningStatement { purpose, sql: Secret::new(sql) }
}
fn random_hex_secret(bytes: usize) -> Result<Secret, ProvisioningError> {
    let mut raw = vec![0u8; bytes];
    SystemRandom::new().fill(&mut raw).map_err(|_| ProvisioningError::RandomGenerationFailed)?;
    let mut encoded = vec![0u8; bytes * 2];
    hex::encode_to_slice(&raw, &mut encoded).map_err(|_| ProvisioningError::RandomGenerationFailed)?;
    raw.fill(0);
    Ok(Secret(encoded))
}
fn provider_username(provider: CoreProvider, tenant_id: Uuid) -> String {
    let compact = tenant_id.simple().to_string();
    match provider {
        CoreProvider::PostgreSql | CoreProvider::CockroachDb =>
            format!("proxima_tenant_{}", tenant_id.to_string().replace('-', "_")),
        CoreProvider::MySql | CoreProvider::MariaDb => format!("prox_t_{}", &compact[..20]),
    }
}
fn validate_namespace(value: &str) -> Result<(), ProvisioningError> {
    if value.is_empty() || value.len() > 63 || !value.as_bytes()[0].is_ascii_alphabetic()
        || !value.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_') {
        return Err(ProvisioningError::InvalidNamespace);
    }
    Ok(())
}
fn validate_database_name(value: &str) -> Result<(), ProvisioningError> {
    if value.is_empty() || value.len() > 63 || !value.as_bytes()[0].is_ascii_alphabetic()
        || !value.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_') {
        return Err(ProvisioningError::InvalidDatabaseName);
    }
    Ok(())
}
fn validate_username(provider: CoreProvider, value: &str) -> Result<(), ProvisioningError> {
    if value.is_empty() || value.len() > if provider.is_mysql_family() { 32 } else { 63 }
        || !value.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_') {
        return Err(ProvisioningError::InvalidTenantId);
    }
    Ok(())
}
fn pg_identifier(value: &str) -> String { format!("\"{}\"", value.replace('"', "\"\"")) }
fn mysql_identifier(value: &str) -> String {
    let doubled = String::from_iter([char::from(96), char::from(96)]);
    format!("{}{}{}", char::from(96), value.replace(char::from(96), &doubled), char::from(96))
}
fn sql_literal(value: &str) -> String { format!("'{}'", value.replace('\'', "''")) }


pub struct ProvisioningTarget<'a> {
    pub host: &'a str,
    pub port: u16,
    pub database_name: &'a str,
    pub admin_username: &'a str,
    pub admin_password: &'a Secret,
    /// PEM bundle containing the provider's trusted root CA. Required for the
    /// PostgreSQL-wire providers; MySQL-family connections use verified system roots.
    pub tls_ca_file: &'a Path,
}

/// Execute a prepared plan against the assigned database. Provisioning is
/// idempotent; every generated tenant identity is then tested with a real login
/// and a database/schema identity check before the caller can acknowledge success.
pub async fn apply_provisioning_plan(
    plan: &ProvisioningPlan,
    target: &ProvisioningTarget<'_>,
) -> Result<(), ProvisioningError> {
    if target.port == 0 || target.host.trim().is_empty()
        || validate_database_name(target.database_name).is_err()
        || target.admin_username.trim().is_empty()
        || target.admin_password.expose().is_err()
    {
        return Err(ProvisioningError::ProviderConnectionFailed);
    }

    match plan.provider {
        CoreProvider::PostgreSql | CoreProvider::CockroachDb => {
            let tls = postgres_tls_connector(target.tls_ca_file)?;
            let mut admin = tokio_postgres::Config::new();
            admin.host(target.host)
                .port(target.port)
                .user(target.admin_username)
                .password(target.admin_password.expose()?)
                .dbname(target.database_name)
                .ssl_mode(SslMode::VerifyFull);
            let (client, connection) = admin.connect(tls.clone()).await
                .map_err(|_| ProvisioningError::ProviderConnectionFailed)?;
            tokio::spawn(async move { let _ = connection.await; });

            for statement in &plan.statements {
                client.batch_execute(statement.sql()?).await
                    .map_err(|_| ProvisioningError::ProviderStatementFailed)?;
            }
            for identity in &plan.identities {
                let schema = pg_identifier(identity.schema.as_deref().ok_or(ProvisioningError::ProviderStatementFailed)?);
                let role = pg_identifier(&identity.username);
                client.batch_execute(&format!(
                    "CREATE TABLE IF NOT EXISTS {schema}.__proxima_isolation_probe (id integer PRIMARY KEY); INSERT INTO {schema}.__proxima_isolation_probe(id) VALUES (1) ON CONFLICT DO NOTHING; GRANT SELECT ON TABLE {schema}.__proxima_isolation_probe TO {role}"
                )).await.map_err(|_| ProvisioningError::ProviderStatementFailed)?;
            }

            let isolation_checks = async {
                for identity in &plan.identities {
                    let mut tenant = tokio_postgres::Config::new();
                    tenant.host(target.host)
                        .port(target.port)
                        .user(&identity.username)
                        .password(identity.upstream_password.expose()?)
                        .dbname(target.database_name)
                        .ssl_mode(SslMode::VerifyFull);
                    let (tenant_client, tenant_connection) = tenant.connect(tls.clone()).await
                        .map_err(|_| ProvisioningError::ProviderHealthCheckFailed)?;
                    tokio::spawn(async move { let _ = tenant_connection.await; });
                    let row = tenant_client.query_one("SELECT current_user, current_schema()", &[]).await
                        .map_err(|_| ProvisioningError::ProviderHealthCheckFailed)?;
                    let actual_user: String = row.get(0);
                    let actual_schema: Option<String> = row.get(1);
                    if actual_user != identity.username || actual_schema.as_deref() != identity.schema.as_deref() {
                        return Err(ProvisioningError::ProviderHealthCheckFailed);
                    }
                    let own_schema = pg_identifier(identity.schema.as_deref().ok_or(ProvisioningError::ProviderHealthCheckFailed)?);
                    tenant_client.query_one(&format!("SELECT id FROM {own_schema}.__proxima_isolation_probe LIMIT 1"), &[]).await
                        .map_err(|_| ProvisioningError::ProviderHealthCheckFailed)?;
                    for other in plan.identities.iter().filter(|other| other.tenant_id != identity.tenant_id) {
                        let other_schema = pg_identifier(other.schema.as_deref().ok_or(ProvisioningError::ProviderIsolationFailed)?);
                        if tenant_client.query_opt(&format!("SELECT id FROM {other_schema}.__proxima_isolation_probe LIMIT 1"), &[]).await.is_ok() {
                            return Err(ProvisioningError::ProviderIsolationFailed);
                        }
                    }
                }
                Ok::<(), ProvisioningError>(())
            }.await;
            for identity in &plan.identities {
                if let Some(schema) = identity.schema.as_deref() {
                    let schema = pg_identifier(schema);
                    client.batch_execute(&format!("DROP TABLE IF EXISTS {schema}.__proxima_isolation_probe"))
                        .await.map_err(|_| ProvisioningError::ProviderStatementFailed)?;
                }
            }
            isolation_checks?;
        }
        CoreProvider::MySql | CoreProvider::MariaDb => {
            use mysql_async::prelude::Queryable;
            let admin_opts = mysql_options(
                target.host, target.port, target.admin_username,
                target.admin_password.expose()?, target.database_name,
            );
            let mut admin = mysql_async::Conn::new(admin_opts).await
                .map_err(|_| ProvisioningError::ProviderConnectionFailed)?;
            for statement in &plan.statements {
                admin.query_drop(statement.sql()?).await
                    .map_err(|_| ProvisioningError::ProviderStatementFailed)?;
            }
            for identity in &plan.identities {
                let database = mysql_identifier(&identity.database);
                admin.query_drop(format!(
                    "CREATE TABLE IF NOT EXISTS {database}.__proxima_isolation_probe (id integer PRIMARY KEY)"
                )).await.map_err(|_| ProvisioningError::ProviderStatementFailed)?;
                admin.query_drop(format!(
                    "INSERT IGNORE INTO {database}.__proxima_isolation_probe(id) VALUES (1)"
                )).await.map_err(|_| ProvisioningError::ProviderStatementFailed)?;
            }

            let isolation_checks = async {
                for identity in &plan.identities {
                    let opts = mysql_options(
                        target.host, target.port, &identity.username,
                        identity.upstream_password.expose()?, &identity.database,
                    );
                    let mut tenant = mysql_async::Conn::new(opts).await
                        .map_err(|_| ProvisioningError::ProviderHealthCheckFailed)?;
                    let selected: Option<String> = tenant.query_first("SELECT DATABASE()").await
                        .map_err(|_| ProvisioningError::ProviderHealthCheckFailed)?;
                    if selected.as_deref() != Some(identity.database.as_str()) {
                        return Err(ProvisioningError::ProviderHealthCheckFailed);
                    }
                    let own_database = mysql_identifier(&identity.database);
                    let own_probe = format!("SELECT id FROM {own_database}.__proxima_isolation_probe LIMIT 1");
                    let own_row: Option<i32> = tenant.query_first(own_probe).await
                        .map_err(|_| ProvisioningError::ProviderHealthCheckFailed)?;
                    if own_row != Some(1) { return Err(ProvisioningError::ProviderHealthCheckFailed); }
                    for other in plan.identities.iter().filter(|other| other.tenant_id != identity.tenant_id) {
                        let other_database = mysql_identifier(&other.database);
                        let cross_query = format!("SELECT id FROM {other_database}.__proxima_isolation_probe LIMIT 1");
                        if tenant.query_first::<i32, _>(cross_query).await.is_ok() {
                            return Err(ProvisioningError::ProviderIsolationFailed);
                        }
                    }
                }
                Ok::<(), ProvisioningError>(())
            }.await;

            for identity in &plan.identities {
                let database = mysql_identifier(&identity.database);
                admin.query_drop(format!("DROP TABLE IF EXISTS {database}.__proxima_isolation_probe"))
                    .await.map_err(|_| ProvisioningError::ProviderStatementFailed)?;
            }
            isolation_checks?;
        }
    }
    Ok(())
}

fn postgres_tls_connector(ca_file: &Path) -> Result<MakeRustlsConnect, ProvisioningError> {
    let file = File::open(ca_file).map_err(|_| ProvisioningError::TlsConfigurationFailed)?;
    let mut reader = BufReader::new(file);
    let certificates = rustls_pemfile::certs(&mut reader)
        .collect::<Result<Vec<_>, _>>()
        .map_err(|_| ProvisioningError::TlsConfigurationFailed)?;
    if certificates.is_empty() {
        return Err(ProvisioningError::TlsConfigurationFailed);
    }
    let mut roots = rustls::RootCertStore::empty();
    for certificate in certificates {
        roots.add(certificate).map_err(|_| ProvisioningError::TlsConfigurationFailed)?;
    }
    let config = rustls::ClientConfig::builder()
        .with_root_certificates(roots)
        .with_no_client_auth();
    Ok(MakeRustlsConnect::new(config))
}

fn mysql_options(
    host: &str, port: u16, username: &str, password: &str, database: &str,
) -> mysql_async::OptsBuilder {
    mysql_async::OptsBuilder::default()
        .ip_or_hostname(host.to_owned())
        .tcp_port(port)
        .user(Some(username.to_owned()))
        .pass(Some(password.to_owned()))
        .db_name(Some(database.to_owned()))
        // SslOpts defaults to certificate and hostname verification. No insecure
        // skip-validation option is enabled for customer database connections.
        .ssl_opts(mysql_async::SslOpts::default())
}

#[cfg(test)]
mod tests {
    use super::*;
    fn binding(tenant: &str, namespace: &str) -> TenantBinding {
        TenantBinding { binding_id: None, tenant_id: tenant.into(), namespace: namespace.into() }
    }

    #[test]
    fn plans_postgres_role_schema_and_search_path_per_tenant() {
        let bindings = vec![
            binding("00000000-0000-4000-8000-000000000001", "tenant_a"),
            binding("00000000-0000-4000-8000-000000000002", "tenant_b"),
        ];
        let plan = build_provisioning_plan(ProvisioningRequest {
            provider_key: "postgresql", database_name: "app", bindings: &bindings,
        }).unwrap();
        assert_eq!(plan.provider, CoreProvider::PostgreSql);
        assert_eq!(plan.identities.len(), 2);
        assert!(plan.statements.iter().any(|s| s.sql().unwrap().contains("CREATE SCHEMA IF NOT EXISTS")));
        assert!(plan.statements.iter().any(|s| s.sql().unwrap().contains("search_path")));
        assert_ne!(plan.identities[0].username, plan.identities[1].username);
    }

    #[test]
    fn plans_cockroach_native_role_and_schema_grants() {
        let bindings = vec![binding("00000000-0000-4000-8000-000000000001", "tenant_a")];
        let plan = build_provisioning_plan(ProvisioningRequest {
            provider_key: "cockroachdb", database_name: "app", bindings: &bindings,
        }).unwrap();
        assert!(plan.statements.iter().any(|s| s.sql().unwrap().contains("CREATE ROLE IF NOT EXISTS")));
        assert!(plan.statements.iter().any(|s| s.sql().unwrap().contains("GRANT CONNECT ON DATABASE")));
    }

    #[test]
    fn plans_mysql_and_mariadb_with_separate_tenant_databases_and_least_privilege() {
        for provider in ["mysql", "mariadb"] {
            let bindings = vec![
                binding("00000000-0000-4000-8000-000000000001", "tenant_a"),
                binding("00000000-0000-4000-8000-000000000002", "tenant_b"),
            ];
            let plan = build_provisioning_plan(ProvisioningRequest {
                provider_key: provider, database_name: "admin", bindings: &bindings,
            }).unwrap();
            assert_eq!(plan.identities[0].database, "tenant_a");
            assert_eq!(plan.identities[1].database, "tenant_b");
            assert!(plan.statements.iter().any(|s| s.sql().unwrap().contains("GRANT SELECT, INSERT, UPDATE, DELETE")));
            assert!(!plan.statements.iter().any(|s| s.sql().unwrap().contains("GRANT ALL")));
            let runtime = mysql_gateway_runtime_config(plan.provider, &plan.identities, "db.example.com", 3306).unwrap();
            assert_eq!(runtime["users"].as_array().unwrap().len(), 2);
            assert_eq!(runtime["provider_key"], provider);
            if provider == "mysql" {
                assert_eq!(runtime["users"][0]["auth_plugin"], "caching_sha2_password");
                assert!(runtime["users"][0].get("password_sha256").is_some());
                assert!(runtime["users"][0].get("password_sha1").is_none());
            } else {
                assert_eq!(runtime["users"][0]["auth_plugin"], "mysql_native_password");
                assert!(runtime["users"][0].get("password_sha1").is_some());
                assert!(runtime["users"][0].get("password_sha256").is_none());
            }
        }
    }

    #[test]
    fn rejects_invalid_and_duplicate_bindings() {
        let invalid = vec![binding("../tenant", "tenant_a")];
        assert_eq!(
            build_provisioning_plan(ProvisioningRequest {
                provider_key: "mysql", database_name: "admin", bindings: &invalid,
            }).unwrap_err(),
            ProvisioningError::InvalidTenantId
        );
        let duplicate = vec![
            binding("00000000-0000-4000-8000-000000000001", "tenant_a"),
            binding("00000000-0000-4000-8000-000000000001", "tenant_b"),
        ];
        assert_eq!(
            build_provisioning_plan(ProvisioningRequest {
                provider_key: "postgresql", database_name: "app", bindings: &duplicate,
            }).unwrap_err(),
            ProvisioningError::DuplicateTenant
        );
    }

    #[test]
    fn revocation_preserves_tenant_data_and_disables_access() {
        let pg = build_revocation_statements(
            "postgresql", "proxima_tenant_00000000_0000_4000_8000_000000000001", "app", "tenant_a",
        ).unwrap();
        assert!(pg.iter().any(|s| s.sql().unwrap().contains("NOLOGIN")));
        assert!(!pg.iter().any(|s| s.sql().unwrap().contains("DROP SCHEMA")));
        let mysql = build_revocation_statements("mysql", "prox_t_00000000000040008000", "admin", "tenant_a").unwrap();
        assert!(mysql.iter().any(|s| s.sql().unwrap().contains("ACCOUNT LOCK")));
        assert!(mysql.iter().any(|s| s.sql().unwrap().contains("REVOKE ALL PRIVILEGES")));
    }

    #[test]
    fn secret_debug_is_redacted() {
        let secret = Secret::new("do-not-print-this");
        assert!(!format!("{secret:?}").contains("do-not-print-this"));
    }
}
