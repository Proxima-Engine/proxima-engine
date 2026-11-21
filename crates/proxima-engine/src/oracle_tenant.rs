pub struct OracleTenant {
    tenant_id: String,
    username: String,
    password: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum OracleTenantError {
    InvalidTenantId,
    WeakPassword,
}
impl std::fmt::Display for OracleTenantError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InvalidTenantId => write!(f, "invalid Oracle tenant identifier"),
            Self::WeakPassword => write!(
                f,
                "Oracle tenant password must contain at least 24 characters"
            ),
        }
    }
}
impl std::error::Error for OracleTenantError {}

/// Oracle schema-per-tenant profile. Each tenant uses a dedicated database
/// user as its schema owner; provisioning SQL runs only on a trusted admin session.
impl OracleTenant {
    pub fn new(tenant_id: &str, password: &str) -> Result<Self, OracleTenantError> {
        if tenant_id.is_empty()
            || tenant_id.len() > 24
            || !tenant_id
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'_')
        {
            return Err(OracleTenantError::InvalidTenantId);
        }
        if password.len() < 24 || !password.bytes().all(|b| (33..=126).contains(&b)) {
            return Err(OracleTenantError::WeakPassword);
        }
        let tenant_id = tenant_id.to_ascii_uppercase();
        Ok(Self {
            username: format!("PROXIMA_{}_OWNER", tenant_id),
            tenant_id,
            password: password.to_owned(),
        })
    }
    pub fn tenant_id(&self) -> &str {
        &self.tenant_id
    }
    pub fn username(&self) -> &str {
        &self.username
    }
    pub fn connect_user(&self) -> &str {
        &self.username
    }

    /// Statements create a schema owner with bounded tablespace quota and no
    /// elevated roles or cross-schema ANY privileges.
    pub fn provisioning_sql(&self) -> Vec<String> {
        let password = self.password.replace('"', "\"\"");
        vec![
            format!("CREATE USER {} IDENTIFIED BY \"{}\" DEFAULT TABLESPACE USERS TEMPORARY TABLESPACE TEMP QUOTA 100M ON USERS", self.username, password),
            format!("GRANT CREATE SESSION, CREATE TABLE, CREATE SEQUENCE, CREATE VIEW, CREATE PROCEDURE, CREATE TRIGGER TO {}", self.username),
            format!("ALTER USER {} DEFAULT ROLE NONE", self.username),
        ]
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn generates_dedicated_schema_principal_and_limited_grants() {
        let t = OracleTenant::new("customer_01", "a-long-random-test-password").unwrap();
        assert_eq!(t.username(), "PROXIMA_CUSTOMER_01_OWNER");
        let sql = t.provisioning_sql().join("\n");
        assert!(sql.contains("GRANT CREATE SESSION, CREATE TABLE"));
        assert!(!sql.contains("DBA"));
        assert!(!sql.contains("ANY TABLE"));
        assert!(sql.contains("DEFAULT ROLE NONE"));
    }
    #[test]
    fn rejects_identifier_injection_and_weak_password() {
        assert!(matches!(
            OracleTenant::new("A; DROP USER X", "a-long-random-test-password"),
            Err(OracleTenantError::InvalidTenantId)
        ));
        assert!(matches!(
            OracleTenant::new("tenant", "short"),
            Err(OracleTenantError::WeakPassword)
        ));
    }
    #[test]
    fn escapes_quoted_password_characters() {
        let t = OracleTenant::new("tenant", "a-long-random-password-with-\"-quote").unwrap();
        assert!(t.provisioning_sql()[0].contains("\"\""));
    }
}
