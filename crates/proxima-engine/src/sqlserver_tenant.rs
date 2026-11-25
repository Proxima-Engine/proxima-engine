use async_trait::async_trait;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SqlServerTenantError {
    InvalidTenantId,
    WeakPassword,
    Provider(String),
}
impl std::fmt::Display for SqlServerTenantError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InvalidTenantId => write!(f, "invalid SQL Server tenant identifier"),
            Self::WeakPassword => write!(
                f,
                "SQL Server tenant password must contain at least 24 printable ASCII characters"
            ),
            Self::Provider(error) => write!(f, "SQL Server operation failed: {error}"),
        }
    }
}
impl std::error::Error for SqlServerTenantError {}

/// SQL Server database-per-tenant identity. The application login is mapped to
/// exactly one database and receives data-reader/data-writer membership only.
pub struct SqlServerTenant {
    tenant_id: String,
    database: String,
    login: String,
    password: String,
}

impl SqlServerTenant {
    pub fn new(tenant_id: &str, password: &str) -> Result<Self, SqlServerTenantError> {
        if tenant_id.is_empty()
            || tenant_id.len() > 32
            || !tenant_id
                .bytes()
                .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'_')
        {
            return Err(SqlServerTenantError::InvalidTenantId);
        }
        validate_password(password)?;
        Ok(Self {
            tenant_id: tenant_id.to_owned(),
            database: format!("AGATA_{tenant_id}"),
            login: format!("agata_{tenant_id}_app"),
            password: password.to_owned(),
        })
    }

    pub fn database(&self) -> &str {
        &self.database
    }
    pub fn login(&self) -> &str {
        &self.login
    }

    pub async fn provision<E: SqlServerExecutor>(
        &self,
        executor: &E,
    ) -> Result<(), SqlServerTenantError> {
        if !executor
            .database_exists(&self.database)
            .await
            .map_err(provider)?
        {
            executor
                .execute(&format!(
                    "CREATE DATABASE {}",
                    quote_identifier(&self.database)
                ))
                .await
                .map_err(provider)?;
        }
        if !executor.login_exists(&self.login).await.map_err(provider)? {
            executor
                .execute(&format!(
                "CREATE LOGIN {} WITH PASSWORD = N'{}', CHECK_POLICY = ON, CHECK_EXPIRATION = OFF",
                quote_identifier(&self.login), escape_literal(&self.password)
            ))
                .await
                .map_err(provider)?;
        } else {
            // The node is authorized by the signed desired-state revision to
            // rotate any previously disabled/revoked login before reactivation.
            executor
                .execute(&format!(
                "ALTER LOGIN {} WITH PASSWORD = N'{}', CHECK_POLICY = ON, CHECK_EXPIRATION = OFF",
                quote_identifier(&self.login), escape_literal(&self.password)
            ))
                .await
                .map_err(provider)?;
        }
        executor
            .execute(&format!(
                "ALTER LOGIN {} WITH DEFAULT_DATABASE = {}",
                quote_identifier(&self.login),
                quote_identifier(&self.database)
            ))
            .await
            .map_err(provider)?;
        executor
            .execute(&format!(
                "DENY VIEW ANY DATABASE TO {}",
                quote_identifier(&self.login)
            ))
            .await
            .map_err(provider)?;
        executor
            .execute(&format!(
                "ALTER DATABASE {} SET TRUSTWORTHY OFF",
                quote_identifier(&self.database)
            ))
            .await
            .map_err(provider)?;
        executor
            .execute(&format!(
                "ALTER DATABASE {} SET DB_CHAINING OFF",
                quote_identifier(&self.database)
            ))
            .await
            .map_err(provider)?;
        if !executor
            .user_mapped(&self.database, &self.login)
            .await
            .map_err(provider)?
        {
            executor
                .execute(&format!(
                    "USE {}; CREATE USER {} FOR LOGIN {}",
                    quote_identifier(&self.database),
                    quote_identifier(&self.login),
                    quote_identifier(&self.login)
                ))
                .await
                .map_err(provider)?;
        }
        for role in ["db_datareader", "db_datawriter"] {
            if !executor
                .database_role_member(&self.database, &self.login, role)
                .await
                .map_err(provider)?
            {
                executor
                    .execute(&format!(
                        "USE {}; ALTER ROLE {} ADD MEMBER {}",
                        quote_identifier(&self.database),
                        quote_identifier(role),
                        quote_identifier(&self.login)
                    ))
                    .await
                    .map_err(provider)?;
            }
        }
        executor
            .execute(&format!(
                "ALTER LOGIN {} ENABLE",
                quote_identifier(&self.login)
            ))
            .await
            .map_err(provider)?;
        self.verify(executor).await
    }

    pub async fn verify<E: SqlServerExecutor>(
        &self,
        executor: &E,
    ) -> Result<(), SqlServerTenantError> {
        if !executor
            .database_exists(&self.database)
            .await
            .map_err(provider)?
            || !executor.login_exists(&self.login).await.map_err(provider)?
            || !executor
                .login_enabled(&self.login)
                .await
                .map_err(provider)?
            || !executor
                .user_mapped(&self.database, &self.login)
                .await
                .map_err(provider)?
            || !executor
                .database_option_disabled(&self.database, "is_trustworthy_on")
                .await
                .map_err(provider)?
            || !executor
                .database_option_disabled(&self.database, "is_db_chaining_on")
                .await
                .map_err(provider)?
        {
            return Err(provider(
                "SQL Server tenant database, login, mapping, or isolation option is invalid",
            ));
        }
        for role in ["db_datareader", "db_datawriter"] {
            if !executor
                .database_role_member(&self.database, &self.login, role)
                .await
                .map_err(provider)?
            {
                return Err(provider(format!(
                    "required database role is missing: {role}"
                )));
            }
        }
        for role in [
            "db_owner",
            "db_ddladmin",
            "db_securityadmin",
            "db_accessadmin",
            "db_backupoperator",
            "sysadmin",
            "serveradmin",
            "securityadmin",
            "dbcreator",
            "bulkadmin",
            "processadmin",
            "setupadmin",
            "diskadmin",
        ] {
            if executor
                .has_elevated_role(&self.database, &self.login, role)
                .await
                .map_err(provider)?
            {
                return Err(provider(format!("tenant login has elevated role: {role}")));
            }
        }
        Ok(())
    }

    pub async fn rotate<E: SqlServerExecutor>(
        &mut self,
        executor: &E,
        new_password: &str,
    ) -> Result<(), SqlServerTenantError> {
        validate_password(new_password)?;
        executor
            .execute(&format!(
                "ALTER LOGIN {} WITH PASSWORD = N'{}', CHECK_POLICY = ON, CHECK_EXPIRATION = OFF",
                quote_identifier(&self.login),
                escape_literal(new_password)
            ))
            .await
            .map_err(provider)?;
        self.password = new_password.to_owned();
        self.verify(executor).await
    }

    /// Immediate login disable; the tenant database and data are retained.
    pub async fn revoke<E: SqlServerExecutor>(
        &self,
        executor: &E,
    ) -> Result<(), SqlServerTenantError> {
        executor
            .execute(&format!(
                "ALTER LOGIN {} DISABLE",
                quote_identifier(&self.login)
            ))
            .await
            .map_err(provider)
    }

    /// Destructive offboarding. Invoke only after an explicit data-retention decision.
    pub async fn destroy<E: SqlServerExecutor>(
        &self,
        executor: &E,
    ) -> Result<(), SqlServerTenantError> {
        executor.execute(&format!(
            "USE master; IF DB_ID(N'{db}') IS NOT NULL BEGIN ALTER DATABASE {dbq} SET SINGLE_USER WITH ROLLBACK IMMEDIATE; DROP DATABASE {dbq}; END; IF SUSER_ID(N'{login}') IS NOT NULL DROP LOGIN {loginq};",
            db=self.database, dbq=quote_identifier(&self.database), login=self.login, loginq=quote_identifier(&self.login)
        )).await.map_err(provider)
    }
}

#[async_trait]
pub trait SqlServerExecutor: Send + Sync {
    async fn execute(&self, sql: &str) -> Result<(), String>;
    async fn database_exists(&self, database: &str) -> Result<bool, String>;
    async fn login_exists(&self, login: &str) -> Result<bool, String>;
    async fn login_enabled(&self, login: &str) -> Result<bool, String>;
    async fn user_mapped(&self, database: &str, login: &str) -> Result<bool, String>;
    async fn database_option_disabled(&self, database: &str, option: &str) -> Result<bool, String>;
    async fn database_role_member(
        &self,
        database: &str,
        login: &str,
        role: &str,
    ) -> Result<bool, String>;
    async fn has_elevated_role(
        &self,
        database: &str,
        login: &str,
        role: &str,
    ) -> Result<bool, String>;
}

fn provider(error: impl ToString) -> SqlServerTenantError {
    SqlServerTenantError::Provider(error.to_string())
}
fn validate_password(password: &str) -> Result<(), SqlServerTenantError> {
    if password.len() < 24 || !password.bytes().all(|b| (33..=126).contains(&b)) {
        Err(SqlServerTenantError::WeakPassword)
    } else {
        Ok(())
    }
}
fn quote_identifier(value: &str) -> String {
    format!("[{}]", value.replace(']', "]]"))
}
fn escape_literal(value: &str) -> String {
    value.replace('\'', "''")
}

/// Tiberius-backed SQL Server executor. TLS certificate validation is enabled;
/// a private CA bundle can be supplied without disabling hostname verification.
#[derive(Clone)]
pub struct TiberiusSqlServerExecutor {
    host: String,
    port: u16,
    username: String,
    password: String,
    ca_bundle: Option<Vec<u8>>,
    database: Option<String>,
}

impl TiberiusSqlServerExecutor {
    pub fn new(
        host: &str,
        port: u16,
        username: &str,
        password: &str,
    ) -> Result<Self, SqlServerTenantError> {
        if host.trim().is_empty()
            || host.len() > 255
            || port == 0
            || username.trim().is_empty()
            || password.is_empty()
        {
            return Err(provider("invalid SQL Server TLS connection configuration"));
        }
        Ok(Self {
            host: host.to_owned(),
            port,
            username: username.to_owned(),
            password: password.to_owned(),
            ca_bundle: None,
            database: None,
        })
    }

    pub fn with_database(mut self, database: &str) -> Result<Self, SqlServerTenantError> {
        if database.trim().is_empty()
            || database.len() > 128
            || !database
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'$' || b == b'#')
        {
            return Err(provider("invalid SQL Server tenant database name"));
        }
        self.database = Some(database.to_owned());
        Ok(self)
    }

    pub fn with_ca_bundle(mut self, pem_or_der: Vec<u8>) -> Result<Self, SqlServerTenantError> {
        if pem_or_der.is_empty() || pem_or_der.len() > 1024 * 1024 {
            return Err(provider("invalid SQL Server CA bundle"));
        }
        self.ca_bundle = Some(pem_or_der);
        Ok(self)
    }

    async fn connect(
        &self,
    ) -> Result<tiberius::Client<tokio_util::compat::Compat<tokio::net::TcpStream>>, String> {
        use tokio_util::compat::TokioAsyncWriteCompatExt;
        let mut config = tiberius::Config::new();
        config.host(&self.host);
        config.port(self.port);
        config.database(self.database.as_deref().unwrap_or("master"));
        config.authentication(tiberius::AuthMethod::sql_server(
            &self.username,
            &self.password,
        ));
        config.encryption(tiberius::EncryptionLevel::Required);
        config.application_name("Agata Proxima Control Plane");
        if let Some(bundle) = &self.ca_bundle {
            config.trust_cert_ca_bundle(bundle.clone());
        }
        let address = config.get_addr();
        let tcp = tokio::net::TcpStream::connect(address.as_str())
            .await
            .map_err(|e| e.to_string())?;
        tcp.set_nodelay(true).map_err(|e| e.to_string())?;
        tiberius::Client::connect(config, tcp.compat_write())
            .await
            .map_err(|e| e.to_string())
    }

    /// Authenticate as the tenant application principal and verify that SQL Server
    /// selected exactly the assigned database and did not grant server-admin access.
    pub async fn verify_tenant_session(
        &self,
        expected_database: &str,
    ) -> Result<(), SqlServerTenantError> {
        let mut client = self.connect().await.map_err(provider)?;
        let row = client.simple_query(
            "SELECT DB_NAME() AS database_name, SUSER_SNAME() AS login_name, IS_SRVROLEMEMBER('sysadmin') AS is_sysadmin"
        ).await.map_err(provider)?.into_row().await.map_err(provider)?
            .ok_or_else(|| provider("SQL Server tenant verification returned no row"))?;
        let database = row.get::<&str, _>(0).unwrap_or_default();
        let login = row.get::<&str, _>(1).unwrap_or_default();
        let sysadmin = row.get::<i32, _>(2).unwrap_or(1);
        if !database.eq_ignore_ascii_case(expected_database)
            || !login.eq_ignore_ascii_case(&self.username)
            || sysadmin != 0
        {
            return Err(provider("tenant login did not resolve to its assigned database and least-privilege server identity"));
        }
        Ok(())
    }

    async fn scalar_count(&self, sql: &str) -> Result<i32, String> {
        let mut client = self.connect().await?;
        let row = client
            .simple_query(sql)
            .await
            .map_err(|e| e.to_string())?
            .into_row()
            .await
            .map_err(|e| e.to_string())?
            .ok_or_else(|| "SQL Server verification query returned no row".to_owned())?;
        row.get::<i32, _>(0)
            .ok_or_else(|| "SQL Server verification query returned a null count".to_owned())
    }
}

#[async_trait]
impl SqlServerExecutor for TiberiusSqlServerExecutor {
    async fn execute(&self, sql: &str) -> Result<(), String> {
        let mut client = self.connect().await?;
        let query = client.simple_query(sql).await.map_err(|e| e.to_string())?;

        let _results = query.into_results().await.map_err(|e| e.to_string())?;

        Ok(())
    }

    async fn database_exists(&self, database: &str) -> Result<bool, String> {
        Ok(self
            .scalar_count(&format!(
                "SELECT COUNT(*) FROM sys.databases WHERE name = N'{}'",
                escape_literal(database)
            ))
            .await?
            == 1)
    }

    async fn login_exists(&self, login: &str) -> Result<bool, String> {
        Ok(self.scalar_count(&format!("SELECT COUNT(*) FROM sys.server_principals WHERE name = N'{}' AND type_desc = 'SQL_LOGIN'", escape_literal(login))).await? == 1)
    }

    async fn login_enabled(&self, login: &str) -> Result<bool, String> {
        Ok(self
            .scalar_count(&format!(
                "SELECT COUNT(*) FROM sys.sql_logins WHERE name = N'{}' AND is_disabled = 0",
                escape_literal(login)
            ))
            .await?
            == 1)
    }

    async fn user_mapped(&self, database: &str, login: &str) -> Result<bool, String> {
        let sql = format!("SELECT COUNT(*) FROM {}.sys.database_principals WHERE name = N'{}' AND sid = SUSER_SID(N'{}')", quote_identifier(database), escape_literal(login), escape_literal(login));
        Ok(self.scalar_count(&sql).await? == 1)
    }

    async fn database_option_disabled(&self, database: &str, option: &str) -> Result<bool, String> {
        if !matches!(option, "is_trustworthy_on" | "is_db_chaining_on") {
            return Err("unsupported SQL Server database option".into());
        }
        Ok(self
            .scalar_count(&format!(
                "SELECT COUNT(*) FROM sys.databases WHERE name = N'{}' AND {} = 0",
                escape_literal(database),
                option
            ))
            .await?
            == 1)
    }

    async fn database_role_member(
        &self,
        database: &str,
        login: &str,
        role: &str,
    ) -> Result<bool, String> {
        if !matches!(role, "db_datareader" | "db_datawriter") {
            return Err("unsupported SQL Server application role".into());
        }
        let sql = format!("SELECT COUNT(*) FROM {}.sys.database_role_members drm JOIN {}.sys.database_principals r ON r.principal_id = drm.role_principal_id JOIN {}.sys.database_principals u ON u.principal_id = drm.member_principal_id WHERE r.name = N'{}' AND u.name = N'{}'", quote_identifier(database), quote_identifier(database), quote_identifier(database), role, escape_literal(login));
        Ok(self.scalar_count(&sql).await? == 1)
    }

    async fn has_elevated_role(
        &self,
        database: &str,
        login: &str,
        role: &str,
    ) -> Result<bool, String> {
        let database_roles = [
            "db_owner",
            "db_ddladmin",
            "db_securityadmin",
            "db_accessadmin",
            "db_backupoperator",
        ];
        let server_roles = [
            "sysadmin",
            "serveradmin",
            "securityadmin",
            "dbcreator",
            "bulkadmin",
            "processadmin",
            "setupadmin",
            "diskadmin",
        ];
        if database_roles.contains(&role) {
            let sql = format!("SELECT COUNT(*) FROM {}.sys.database_role_members drm JOIN {}.sys.database_principals r ON r.principal_id = drm.role_principal_id JOIN {}.sys.database_principals u ON u.principal_id = drm.member_principal_id WHERE r.name = N'{}' AND u.name = N'{}'", quote_identifier(database), quote_identifier(database), quote_identifier(database), role, escape_literal(login));
            return Ok(self.scalar_count(&sql).await? > 0);
        }
        if server_roles.contains(&role) {
            let sql = format!("SELECT COUNT(*) FROM sys.server_role_members drm JOIN sys.server_principals r ON r.principal_id = drm.role_principal_id JOIN sys.server_principals u ON u.principal_id = drm.member_principal_id WHERE r.name = N'{}' AND u.name = N'{}'", role, escape_literal(login));
            return Ok(self.scalar_count(&sql).await? > 0);
        }
        Err("unsupported SQL Server elevated role".into())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn builds_database_per_tenant_identity_without_elevated_roles() {
        let tenant =
            SqlServerTenant::new("customer_01", "a-long-random-sql-server-secret").unwrap();
        assert_eq!(tenant.database(), "AGATA_customer_01");
        assert_eq!(tenant.login(), "agata_customer_01_app");
    }

    #[test]
    fn rejects_injected_tenant_identifiers_and_weak_passwords() {
        assert!(SqlServerTenant::new(
            "x]; DROP DATABASE master;--",
            "a-long-random-sql-server-secret"
        )
        .is_err());
        assert!(SqlServerTenant::new("tenant_a", "short").is_err());
    }
}
