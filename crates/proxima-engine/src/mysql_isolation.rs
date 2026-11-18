//! MySQL tenant isolation primitives.
//!
//! MySQL has no PostgreSQL-style row-level security. The supported isolation
//! model built here is database-per-tenant with separate runtime and migration
//! accounts. MySQL grants are the enforcement boundary; this module does not
//! claim shared-table row filtering.
use sha2::{Digest, Sha256};
use std::fmt;
use std::net::IpAddr;
use ring::rand::{SecureRandom, SystemRandom};
use uuid::Uuid;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MySqlIsolationError {
    InvalidHost,
    InvalidPassword,
    RandomSourceUnavailable,
}

impl fmt::Display for MySqlIsolationError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidHost => write!(f, "MySQL account host must be a literal hostname or IP; wildcards are not allowed"),
            Self::InvalidPassword => write!(f, "MySQL provisioning passwords must be 64 hexadecimal characters"),
            Self::RandomSourceUnavailable => write!(f, "operating-system random source is unavailable"),
        }
    }
}
impl std::error::Error for MySqlIsolationError {}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MySqlTenantIdentity {
    pub tenant_id: Uuid,
    pub database_name: String,
    pub runtime_username: String,
    pub migration_username: String,
}

impl MySqlTenantIdentity {
    pub fn for_tenant(tenant_id: Uuid) -> Self {
        let compact = tenant_id.simple().to_string();
        let digest = Sha256::digest(tenant_id.as_bytes());
        let suffix = hex::encode(digest);
        Self {
            tenant_id,
            database_name: format!("ap_t_{compact}"),
            runtime_username: format!("ap_r_{}", &suffix[..27]),
            migration_username: format!("ap_m_{}", &suffix[..27]),
        }
    }
}

/// Contains SQL with credential material. Never Debug-print, log, or persist it
/// in source control. Execute only over TLS using a dedicated provisioning
/// account. MySQL DDL can implicitly commit; callers need compensating cleanup.
pub struct MySqlProvisioningPlan {
    identity: MySqlTenantIdentity,
    account_host: String,
    statements: Vec<String>,
}

impl MySqlProvisioningPlan {
    pub fn identity(&self) -> &MySqlTenantIdentity {
        &self.identity
    }
    pub fn statements(&self) -> &[String] {
        &self.statements
    }
    pub fn account_host(&self) -> &str {
        &self.account_host
    }
}
impl fmt::Debug for MySqlProvisioningPlan {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("MySqlProvisioningPlan")
            .field("identity", &self.identity)
            .field("account_host", &self.account_host)
            .field("statement_count", &self.statements.len())
            .field("credentials", &"[REDACTED]")
            .finish()
    }
}


/// Generate a 256-bit random MySQL account password using the operating
/// system random source used by UUID v4. The returned value is 64 hex chars,
/// matching the provisioning-plan validation contract.
pub fn generate_mysql_password() -> Result<String, MySqlIsolationError> {
    let mut bytes = [0u8; 32];
    SystemRandom::new()
        .fill(&mut bytes)
        .map_err(|_| MySqlIsolationError::RandomSourceUnavailable)?;
    Ok(hex::encode(bytes))
}

pub fn build_provisioning_plan(
    tenant_id: Uuid,
    account_host: &str,
    runtime_password: &str,
    migration_password: &str,
) -> Result<MySqlProvisioningPlan, MySqlIsolationError> {
    validate_host(account_host)?;
    validate_password(runtime_password)?;
    validate_password(migration_password)?;
    if runtime_password == migration_password {
        return Err(MySqlIsolationError::InvalidPassword);
    }
    let identity = MySqlTenantIdentity::for_tenant(tenant_id);
    let database = quote_identifier(&identity.database_name);
    let runtime_user = quote_account(&identity.runtime_username, account_host);
    let migration_user = quote_account(&identity.migration_username, account_host);
    let statements = vec![
        format!("CREATE DATABASE {database} CHARACTER SET utf8mb4 COLLATE utf8mb4_0900_ai_ci"),
        format!("CREATE USER {runtime_user} IDENTIFIED BY '{runtime_password}' REQUIRE SSL"),
        format!("CREATE USER {migration_user} IDENTIFIED BY '{migration_password}' REQUIRE SSL"),
        format!("GRANT SELECT, INSERT, UPDATE, DELETE ON {database}.* TO {runtime_user}"),
        format!("GRANT SELECT, INSERT, UPDATE, DELETE, CREATE, ALTER, INDEX, DROP, REFERENCES, CREATE VIEW, SHOW VIEW, TRIGGER, EVENT, CREATE ROUTINE, ALTER ROUTINE, EXECUTE ON {database}.* TO {migration_user}"),
    ];
    Ok(MySqlProvisioningPlan { identity, account_host: account_host.to_owned(), statements })
}

pub fn build_password_rotation(
    identity: &MySqlTenantIdentity,
    account_host: &str,
    runtime_password: &str,
    migration_password: &str,
) -> Result<Vec<String>, MySqlIsolationError> {
    validate_host(account_host)?;
    validate_password(runtime_password)?;
    validate_password(migration_password)?;
    if runtime_password == migration_password {
        return Err(MySqlIsolationError::InvalidPassword);
    }
    Ok(vec![
        format!("ALTER USER {} IDENTIFIED BY '{}' REQUIRE SSL", quote_account(&identity.runtime_username, account_host), runtime_password),
        format!("ALTER USER {} IDENTIFIED BY '{}' REQUIRE SSL", quote_account(&identity.migration_username, account_host), migration_password),
    ])
}

/// Locks both tenant accounts and removes grants. It never drops customer data.
pub fn build_revocation(
    identity: &MySqlTenantIdentity,
    account_host: &str,
) -> Result<Vec<String>, MySqlIsolationError> {
    validate_host(account_host)?;
    let runtime_user = quote_account(&identity.runtime_username, account_host);
    let migration_user = quote_account(&identity.migration_username, account_host);
    Ok(vec![
        format!("ALTER USER {runtime_user} ACCOUNT LOCK"),
        format!("ALTER USER {migration_user} ACCOUNT LOCK"),
        format!("REVOKE ALL PRIVILEGES, GRANT OPTION FROM {runtime_user}"),
        format!("REVOKE ALL PRIVILEGES, GRANT OPTION FROM {migration_user}"),
    ])
}

fn validate_host(host: &str) -> Result<(), MySqlIsolationError> {
    if host == "localhost" || host.parse::<IpAddr>().is_ok() {
        return Ok(());
    }
    if host.is_empty() || host.len() > 253 || !host.is_ascii() {
        return Err(MySqlIsolationError::InvalidHost);
    }
    let valid_dns = host.split('.').all(|label| {
        !label.is_empty()
            && label.len() <= 63
            && label.as_bytes().first().is_some_and(u8::is_ascii_alphanumeric)
            && label.as_bytes().last().is_some_and(u8::is_ascii_alphanumeric)
            && label.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-')
    });
    if !valid_dns {
        return Err(MySqlIsolationError::InvalidHost);
    }
    Ok(())
}
fn validate_password(password: &str) -> Result<(), MySqlIsolationError> {
    if password.len() != 64 || !password.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Err(MySqlIsolationError::InvalidPassword);
    }
    Ok(())
}
fn quote_identifier(identifier: &str) -> String {
    let tick = 96 as char;
    format!("{tick}{}{tick}", identifier.replace(tick, &format!("{tick}{tick}")))
}
fn quote_account(username: &str, host: &str) -> String {
    format!("'{username}'@'{host}'")
}

#[cfg(test)]
mod tests {
    use super::*;
    const PASSWORD_A: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    const PASSWORD_B: &str = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";


    #[test]
    fn generated_passwords_are_distinct_and_meet_entropy_format() {
        let first = generate_mysql_password().unwrap();
        let second = generate_mysql_password().unwrap();
        assert_eq!(first.len(), 64);
        assert!(first.bytes().all(|byte| byte.is_ascii_hexdigit()));
        assert_ne!(first, second);
    }

    #[test]
    fn tenant_accounts_are_distinct_and_fit_mysql_limits() {
        let a = MySqlTenantIdentity::for_tenant(Uuid::parse_str("aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa").unwrap());
        let b = MySqlTenantIdentity::for_tenant(Uuid::parse_str("bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb").unwrap());
        assert_ne!(a.database_name, b.database_name);
        assert_ne!(a.runtime_username, b.runtime_username);
        assert_ne!(a.migration_username, b.migration_username);
        assert!(a.database_name.len() <= 64);
        assert!(a.runtime_username.len() <= 32);
        assert!(a.migration_username.len() <= 32);
        assert_ne!(a.runtime_username, a.migration_username);
    }

    #[test]
    fn provisioning_grants_are_database_scoped_and_accounts_are_separate() {
        let tenant = Uuid::parse_str("aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa").unwrap();
        let plan = build_provisioning_plan(tenant, "10.0.0.12", PASSWORD_A, PASSWORD_B).unwrap();
        assert_eq!(plan.statements().len(), 5);
        let sql = plan.statements().join("\n");
        assert!(sql.contains("GRANT SELECT, INSERT, UPDATE, DELETE ON"));
        assert!(!sql.contains("GRANT EXECUTE"));
        assert!(!sql.contains("GRANT SHOW VIEW"));
        assert!(sql.contains(" TO 'ap_r_"));
        assert!(sql.contains(" TO 'ap_m_"));
        assert!(!sql.contains("ON *.*"));
        assert!(!sql.contains("WITH GRANT OPTION"));
        assert!(!sql.contains("IF NOT EXISTS"));
        assert!(sql.contains("REQUIRE SSL"));
    }

    #[test]
    fn wildcard_and_injected_account_hosts_are_rejected() {
        assert_eq!(build_provisioning_plan(Uuid::new_v4(), "%", PASSWORD_A, PASSWORD_B).unwrap_err(), MySqlIsolationError::InvalidHost);
        assert_eq!(build_provisioning_plan(Uuid::new_v4(), "localhost' OR 1=1 --", PASSWORD_A, PASSWORD_B).unwrap_err(), MySqlIsolationError::InvalidHost);
    }

    #[test]
    fn weak_or_non_hex_passwords_are_rejected() {
        assert_eq!(build_provisioning_plan(Uuid::new_v4(), "localhost", "password", PASSWORD_B).unwrap_err(), MySqlIsolationError::InvalidPassword);
        assert_eq!(build_provisioning_plan(Uuid::new_v4(), "localhost", PASSWORD_A, PASSWORD_A).unwrap_err(), MySqlIsolationError::InvalidPassword);
    }

    #[test]
    fn revocation_locks_accounts_without_dropping_customer_database() {
        let tenant = MySqlTenantIdentity::for_tenant(Uuid::new_v4());
        let sql = build_revocation(&tenant, "localhost").unwrap().join("\n");
        assert!(sql.contains("ACCOUNT LOCK"));
        assert!(sql.contains("REVOKE ALL PRIVILEGES"));
        assert!(!sql.contains("DROP DATABASE"));
        assert!(!sql.contains("DROP USER"));
    }

    #[test]
    fn rotation_changes_only_credentials_for_the_tenant_accounts() {
        let tenant = MySqlTenantIdentity::for_tenant(Uuid::new_v4());
        let sql = build_password_rotation(&tenant, "localhost", PASSWORD_A, PASSWORD_B).unwrap();
        assert_eq!(sql.len(), 2);
        assert!(sql.iter().all(|statement| statement.starts_with("ALTER USER")));
    }
}
