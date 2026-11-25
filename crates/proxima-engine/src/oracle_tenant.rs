use async_trait::async_trait;

pub struct OracleTenant {
    tenant_id: String,
    username: String,
    password: String,
}
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum OracleTenantError {
    InvalidTenantId,
    WeakPassword,
    Provider(String),
}
impl std::fmt::Display for OracleTenantError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InvalidTenantId => write!(f, "invalid Oracle tenant identifier"),
            Self::WeakPassword => write!(
                f,
                "Oracle tenant password must contain at least 24 printable ASCII characters"
            ),
            Self::Provider(e) => write!(f, "Oracle operation failed: {e}"),
        }
    }
}
impl std::error::Error for OracleTenantError {}
/// Oracle schema-per-tenant lifecycle. Run only through a separately
/// authenticated administrative connection with narrowly scoped privileges.
impl OracleTenant {
    pub fn new(id: &str, password: &str) -> Result<Self, OracleTenantError> {
        if id.is_empty()
            || id.len() > 24
            || !id.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_')
        {
            return Err(OracleTenantError::InvalidTenantId);
        }
        validate_password(password)?;
        let id = id.to_ascii_uppercase();
        Ok(Self {
            username: format!("PROXIMA_{}_OWNER", id),
            tenant_id: id,
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
    pub fn provisioning_sql(&self) -> Vec<String> {
        vec![format!("CREATE USER {} IDENTIFIED BY \"{}\" DEFAULT TABLESPACE USERS TEMPORARY TABLESPACE TEMP QUOTA 100M ON USERS",self.username,esc_oracle(&self.password)),format!("GRANT CREATE SESSION, CREATE TABLE, CREATE SEQUENCE, CREATE VIEW, CREATE PROCEDURE, CREATE TRIGGER TO {}",self.username),format!("ALTER USER {} DEFAULT ROLE NONE",self.username)]
    }
    pub async fn provision<E: OracleExecutor>(&self, exec: &E) -> Result<(), OracleTenantError> {
        if !exec.user_exists(&self.username).await.map_err(provider)? {
            exec.execute(&self.provisioning_sql()[0])
                .await
                .map_err(provider)?;
        }
        for sql in self.provisioning_sql().into_iter().skip(1) {
            exec.execute(&sql).await.map_err(provider)?;
        }
        self.verify(exec).await
    }
    pub async fn verify<E: OracleExecutor>(&self, exec: &E) -> Result<(), OracleTenantError> {
        if !exec.user_exists(&self.username).await.map_err(provider)? {
            return Err(provider("tenant schema owner does not exist"));
        }
        if exec
            .account_locked(&self.username)
            .await
            .map_err(provider)?
        {
            return Err(provider("tenant schema owner is locked"));
        }
        for p in [
            "CREATE SESSION",
            "CREATE TABLE",
            "CREATE SEQUENCE",
            "CREATE VIEW",
            "CREATE PROCEDURE",
            "CREATE TRIGGER",
        ] {
            if !exec
                .has_system_privilege(&self.username, p)
                .await
                .map_err(provider)?
            {
                return Err(provider(format!("required privilege missing: {p}")));
            }
        }
        if exec
            .has_dangerous_role(&self.username)
            .await
            .map_err(provider)?
        {
            return Err(provider("tenant owner has an elevated role"));
        }
        Ok(())
    }
    pub async fn rotate<E: OracleExecutor>(
        &mut self,
        exec: &E,
        new_password: &str,
    ) -> Result<(), OracleTenantError> {
        validate_password(new_password)?;
        exec.execute(&format!(
            "ALTER USER {} IDENTIFIED BY \"{}\"",
            self.username,
            esc_oracle(new_password)
        ))
        .await
        .map_err(provider)?;
        self.password = new_password.to_owned();
        self.verify(exec).await
    }
    /// Non-destructive revocation: lock account and revoke its application privileges.
    pub async fn revoke<E: OracleExecutor>(&self, exec: &E) -> Result<(), OracleTenantError> {
        exec.execute(&format!("ALTER USER {} ACCOUNT LOCK", self.username))
            .await
            .map_err(provider)?;
        for p in [
            "CREATE SESSION",
            "CREATE TABLE",
            "CREATE SEQUENCE",
            "CREATE VIEW",
            "CREATE PROCEDURE",
            "CREATE TRIGGER",
        ] {
            exec.execute(&format!("REVOKE {} FROM {}", p, self.username))
                .await
                .map_err(provider)?;
        }
        Ok(())
    }
    /// Destructive offboarding. Removes the schema and all tenant-owned objects.
    pub async fn destroy<E: OracleExecutor>(&self, exec: &E) -> Result<(), OracleTenantError> {
        exec.execute(&format!("DROP USER {} CASCADE", self.username))
            .await
            .map_err(provider)
    }
}
#[async_trait]
pub trait OracleExecutor: Send + Sync {
    async fn execute(&self, sql: &str) -> Result<(), String>;
    async fn user_exists(&self, user: &str) -> Result<bool, String>;
    async fn account_locked(&self, user: &str) -> Result<bool, String>;
    async fn has_system_privilege(&self, user: &str, privilege: &str) -> Result<bool, String>;
    async fn has_dangerous_role(&self, user: &str) -> Result<bool, String>;
}
fn provider(e: impl ToString) -> OracleTenantError {
    OracleTenantError::Provider(e.to_string())
}
fn validate_password(p: &str) -> Result<(), OracleTenantError> {
    if p.len() < 24 || !p.bytes().all(|b| (33..=126).contains(&b)) {
        Err(OracleTenantError::WeakPassword)
    } else {
        Ok(())
    }
}
fn esc_oracle(p: &str) -> String {
    p.replace('"', "\"\"")
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn generates_limited_schema_owner() {
        let t = OracleTenant::new("customer_01", "a-long-random-test-password").unwrap();
        let s = t.provisioning_sql().join("\n");
        assert!(s.contains("GRANT CREATE SESSION, CREATE TABLE"));
        assert!(s.contains("DEFAULT ROLE NONE"));
        assert!(!s.contains("DBA"));
        assert!(!s.contains("ANY TABLE"));
    }
    #[test]
    fn rejects_bad_identifiers_and_passwords() {
        assert!(OracleTenant::new("A; DROP USER X", "a-long-random-test-password").is_err());
        assert!(OracleTenant::new("tenant", "short").is_err());
    }
}

/// Concrete Oracle administrative executor backed by the pure-Rust TNS driver.
/// TLS is enabled for every connection; no plaintext Oracle administration path
/// is exposed by this adapter.
#[derive(Clone)]
pub struct OracleRsExecutor {
    host: String,
    port: u16,
    service: String,
    username: String,
    password: String,
    wallet: Option<(String, Option<String>)>,
}

impl OracleRsExecutor {
    pub fn new(
        host: &str,
        port: u16,
        service: &str,
        username: &str,
        password: &str,
    ) -> Result<Self, OracleTenantError> {
        if host.trim().is_empty()
            || host.len() > 255
            || port == 0
            || service.trim().is_empty()
            || service.len() > 128
            || username.trim().is_empty()
            || username.len() > 128
            || password.is_empty()
            || password.len() > 4096
        {
            return Err(OracleTenantError::Provider(
                "invalid Oracle TLS connection configuration".into(),
            ));
        }
        Ok(Self {
            host: host.to_owned(),
            port,
            service: service.to_owned(),
            username: username.to_owned(),
            password: password.to_owned(),
            wallet: None,
        })
    }

    pub fn with_wallet(
        mut self,
        wallet_path: &str,
        wallet_password: Option<&str>,
    ) -> Result<Self, OracleTenantError> {
        if wallet_path.trim().is_empty() || wallet_path.len() > 1024 {
            return Err(OracleTenantError::Provider(
                "invalid Oracle wallet path".into(),
            ));
        }
        self.wallet = Some((wallet_path.to_owned(), wallet_password.map(str::to_owned)));
        Ok(self)
    }

    async fn connect(&self) -> Result<oracle_rs::Connection, String> {
        let config = oracle_rs::Config::new(
            &self.host,
            self.port,
            &self.service,
            &self.username,
            &self.password,
        );
        let config = if let Some((wallet, wallet_password)) = &self.wallet {
            config
                .with_wallet(wallet, wallet_password.as_deref())
                .map_err(|e| e.to_string())?
        } else {
            config.with_tls().map_err(|e| e.to_string())?
        };
        oracle_rs::Connection::connect_with_config(config)
            .await
            .map_err(|e| e.to_string())
    }
}

#[async_trait]
impl OracleExecutor for OracleRsExecutor {
    async fn execute(&self, sql: &str) -> Result<(), String> {
        let connection = self.connect().await?;
        connection
            .execute(sql, &[])
            .await
            .map(|_| ())
            .map_err(|e| e.to_string())
    }

    async fn user_exists(&self, user: &str) -> Result<bool, String> {
        let connection = self.connect().await?;
        let result = connection
            .query(
                "SELECT username FROM all_users WHERE username = :1",
                &[oracle_rs::Value::String(user.to_owned())],
            )
            .await
            .map_err(|e| e.to_string())?;
        Ok(!result.rows.is_empty())
    }

    async fn account_locked(&self, user: &str) -> Result<bool, String> {
        let connection = self.connect().await?;
        let result = connection
            .query(
                "SELECT account_status FROM dba_users WHERE username = :1",
                &[oracle_rs::Value::String(user.to_owned())],
            )
            .await
            .map_err(|e| e.to_string())?;
        let Some(row) = result.rows.first() else {
            return Ok(true);
        };
        let status = row.get_string(0).unwrap_or("");
        Ok(status != "OPEN")
    }

    async fn has_system_privilege(&self, user: &str, privilege: &str) -> Result<bool, String> {
        let connection = self.connect().await?;
        let result = connection
            .query(
                "SELECT privilege FROM dba_sys_privs WHERE grantee = :1 AND privilege = :2",
                &[
                    oracle_rs::Value::String(user.to_owned()),
                    oracle_rs::Value::String(privilege.to_owned()),
                ],
            )
            .await
            .map_err(|e| e.to_string())?;
        Ok(!result.rows.is_empty())
    }

    async fn has_dangerous_role(&self, user: &str) -> Result<bool, String> {
        let connection = self.connect().await?;
        let role_result = connection.query(
            "SELECT granted_role FROM dba_role_privs WHERE grantee = :1 AND granted_role IN ('DBA','PDB_DBA','RESOURCE','IMP_FULL_DATABASE','EXP_FULL_DATABASE','DATAPUMP_IMP_FULL_DATABASE','DATAPUMP_EXP_FULL_DATABASE','SCHEDULER_ADMIN','SELECT_CATALOG_ROLE','EXECUTE_CATALOG_ROLE')",
            &[oracle_rs::Value::String(user.to_owned())],
        ).await.map_err(|e| e.to_string())?;
        if !role_result.rows.is_empty() {
            return Ok(true);
        }
        let privilege_result = connection.query(
            "SELECT privilege FROM dba_sys_privs WHERE grantee = :1 AND privilege IN ('ALTER SYSTEM','CREATE USER','DROP USER','GRANT ANY PRIVILEGE','GRANT ANY ROLE','BECOME USER','EXEMPT ACCESS POLICY','UNLIMITED TABLESPACE','SELECT ANY DICTIONARY','SELECT ANY TABLE','INSERT ANY TABLE','UPDATE ANY TABLE','DELETE ANY TABLE','CREATE ANY TABLE','ALTER ANY TABLE','DROP ANY TABLE','CREATE ANY PROCEDURE','ALTER ANY PROCEDURE','DROP ANY PROCEDURE')",
            &[oracle_rs::Value::String(user.to_owned())],
        ).await.map_err(|e| e.to_string())?;
        Ok(!privilege_result.rows.is_empty())
    }
}
