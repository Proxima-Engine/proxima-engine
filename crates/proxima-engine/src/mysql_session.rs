use crate::mysql_identity::TenantPrincipal;
use std::sync::OnceLock;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MysqlSessionIdentityError {
    NotAuthenticated,
    AlreadyBound,
    DatabaseSwitchDenied,
}

impl std::fmt::Display for MysqlSessionIdentityError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NotAuthenticated => write!(f, "MySQL session is not authenticated"),
            Self::AlreadyBound => write!(f, "MySQL session identity is already bound"),
            Self::DatabaseSwitchDenied => {
                write!(f, "database selection is not authorized for this tenant")
            }
        }
    }
}

impl std::error::Error for MysqlSessionIdentityError {}

/// Immutable tenant identity for one client connection.
///
/// A connection may be bound once after successful authentication.
/// It cannot be rebound to another tenant.
pub struct MysqlConnectionIdentity {
    principal: OnceLock<TenantPrincipal>,
}

impl MysqlConnectionIdentity {
    pub fn new() -> Self {
        Self {
            principal: OnceLock::new(),
        }
    }

    pub fn bind_authenticated(
        &self,
        principal: TenantPrincipal,
    ) -> Result<(), MysqlSessionIdentityError> {
        self.principal
            .set(principal)
            .map_err(|_| MysqlSessionIdentityError::AlreadyBound)
    }

    pub fn principal(&self) -> Result<&TenantPrincipal, MysqlSessionIdentityError> {
        self.principal
            .get()
            .ok_or(MysqlSessionIdentityError::NotAuthenticated)
    }

    /// Enforces the database assigned to this authenticated principal.
    pub fn authorize_database(
        &self,
        requested_database: &str,
    ) -> Result<(), MysqlSessionIdentityError> {
        let principal = self.principal()?;

        if requested_database != principal.database {
            return Err(MysqlSessionIdentityError::DatabaseSwitchDenied);
        }

        Ok(())
    }

    pub fn is_authenticated(&self) -> bool {
        self.principal.get().is_some()
    }
}

impl Default for MysqlConnectionIdentity {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn principal(tenant: &str, database: &str) -> TenantPrincipal {
        TenantPrincipal {
            username: format!("{tenant}_user"),
            tenant_id: tenant.to_string(),
            database: database.to_string(),
            upstream_url: "mysql://user:secret@127.0.0.1:3306/db".to_string(),
            upstream_tls_ca_file: None,
            auth_plugin: "mysql_native_password",
            password_sha1: Some([0; 20]),
            password_sha256: None,
        }
    }

    #[test]
    fn rejects_access_before_authentication() {
        let identity = MysqlConnectionIdentity::new();

        assert_eq!(
            identity.authorize_database("tenant_a_db"),
            Err(MysqlSessionIdentityError::NotAuthenticated)
        );
    }

    #[test]
    fn binds_authenticated_tenant_once() {
        let identity = MysqlConnectionIdentity::new();

        identity
            .bind_authenticated(principal("tenant_a", "tenant_a_db"))
            .unwrap();

        assert_eq!(identity.principal().unwrap().tenant_id, "tenant_a");
        assert!(identity.is_authenticated());
    }

    #[test]
    fn rejects_identity_rebinding() {
        let identity = MysqlConnectionIdentity::new();

        identity
            .bind_authenticated(principal("tenant_a", "tenant_a_db"))
            .unwrap();

        assert_eq!(
            identity.bind_authenticated(principal("tenant_b", "tenant_b_db")),
            Err(MysqlSessionIdentityError::AlreadyBound)
        );

        assert_eq!(identity.principal().unwrap().tenant_id, "tenant_a");
    }

    #[test]
    fn permits_only_assigned_database() {
        let identity = MysqlConnectionIdentity::new();

        identity
            .bind_authenticated(principal("tenant_a", "tenant_a_db"))
            .unwrap();

        assert!(identity.authorize_database("tenant_a_db").is_ok());

        assert_eq!(
            identity.authorize_database("tenant_b_db"),
            Err(MysqlSessionIdentityError::DatabaseSwitchDenied)
        );
    }

    #[test]
    fn principal_debug_redacts_upstream_credentials() {
        let identity = MysqlConnectionIdentity::new();

        identity
            .bind_authenticated(principal("tenant_a", "tenant_a_db"))
            .unwrap();

        let debug = format!("{:?}", identity.principal().unwrap());

        assert!(!debug.contains("secret"));
        assert!(debug.contains("[REDACTED]"));
    }
}
