use async_trait::async_trait;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CassandraTenantError {
    InvalidTenantId,
    WeakPassword,
    InvalidReplicationFactor,
    InvalidDatacenter,
    Provider(String),
}
impl std::fmt::Display for CassandraTenantError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InvalidTenantId => write!(f, "invalid Cassandra tenant identifier"),
            Self::WeakPassword => write!(
                f,
                "Cassandra tenant password must contain at least 24 printable ASCII characters"
            ),
            Self::InvalidReplicationFactor => {
                write!(f, "Cassandra replication factor must be between 1 and 5")
            }
            Self::InvalidDatacenter => write!(f, "invalid Cassandra datacenter identifier"),
            Self::Provider(e) => write!(f, "Cassandra operation failed: {e}"),
        }
    }
}
impl std::error::Error for CassandraTenantError {}

/// Keyspace-per-tenant identity and executable lifecycle operations.
pub struct CassandraTenant {
    tenant_id: String,
    keyspace: String,
    role: String,
    password: String,
}
impl CassandraTenant {
    pub fn new(tenant_id: &str, password: &str) -> Result<Self, CassandraTenantError> {
        if tenant_id.is_empty()
            || tenant_id.len() > 32
            || !tenant_id
                .bytes()
                .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'_')
        {
            return Err(CassandraTenantError::InvalidTenantId);
        }
        validate_password(password)?;
        let id = tenant_id.to_owned();
        Ok(Self {
            tenant_id: id.clone(),
            keyspace: format!("proxima_{id}"),
            role: format!("proxima_{id}_app"),
            password: password.to_owned(),
        })
    }
    pub fn tenant_id(&self) -> &str {
        &self.tenant_id
    }
    pub fn keyspace(&self) -> &str {
        &self.keyspace
    }
    pub fn role(&self) -> &str {
        &self.role
    }
    pub fn provisioning_cql(&self, dc: &str, rf: u8) -> Result<Vec<String>, CassandraTenantError> {
        validate_topology(dc, rf)?;
        Ok(vec![
            format!("CREATE KEYSPACE IF NOT EXISTS {} WITH replication = {{'class': 'NetworkTopologyStrategy', '{}': {}}} AND durable_writes = true", self.keyspace, dc, rf),
            format!("CREATE ROLE IF NOT EXISTS {} WITH PASSWORD = '{}' AND LOGIN = true", self.role, esc_cql(&self.password)),
            format!("ALTER ROLE {} WITH PASSWORD = '{}' AND LOGIN = true", self.role, esc_cql(&self.password)),
            format!("GRANT SELECT ON KEYSPACE {} TO {}", self.keyspace, self.role),
            format!("GRANT MODIFY ON KEYSPACE {} TO {}", self.keyspace, self.role),
        ])
    }
    pub async fn provision<E: CassandraExecutor>(
        &self,
        exec: &E,
        dc: &str,
        rf: u8,
    ) -> Result<(), CassandraTenantError> {
        for cql in self.provisioning_cql(dc, rf)? {
            exec.execute(&cql).await.map_err(provider)?;
        }
        self.verify(exec).await
    }
    pub async fn verify<E: CassandraExecutor>(&self, exec: &E) -> Result<(), CassandraTenantError> {
        let ks = exec
            .exists(
                "SELECT keyspace_name FROM system_schema.keyspaces WHERE keyspace_name = ?",
                &self.keyspace,
            )
            .await
            .map_err(provider)?;
        let role = exec
            .exists(
                "SELECT role FROM system_auth.roles WHERE role = ?",
                &self.role,
            )
            .await
            .map_err(provider)?;
        let select = exec
            .has_grant(&self.role, &format!("KEYSPACE {}", self.keyspace), "SELECT")
            .await
            .map_err(provider)?;
        let modify = exec
            .has_grant(&self.role, &format!("KEYSPACE {}", self.keyspace), "MODIFY")
            .await
            .map_err(provider)?;
        if !(ks && role && select && modify) {
            return Err(provider(
                "keyspace, login role, or required grants are missing",
            ));
        }
        Ok(())
    }
    pub async fn rotate<E: CassandraExecutor>(
        &mut self,
        exec: &E,
        new_password: &str,
    ) -> Result<(), CassandraTenantError> {
        validate_password(new_password)?;
        exec.execute(&format!(
            "ALTER ROLE {} WITH PASSWORD = '{}'",
            self.role,
            esc_cql(new_password)
        ))
        .await
        .map_err(provider)?;
        self.password = new_password.to_owned();
        self.verify(exec).await
    }
    /// Revocation removes the login principal first. Keyspace data is retained by default.
    pub async fn revoke<E: CassandraExecutor>(&self, exec: &E) -> Result<(), CassandraTenantError> {
        exec.execute(&format!("ALTER ROLE {} WITH LOGIN = false", self.role))
            .await
            .map_err(provider)?;
        exec.execute(&format!(
            "REVOKE SELECT ON KEYSPACE {} FROM {}",
            self.keyspace, self.role
        ))
        .await
        .map_err(provider)?;
        exec.execute(&format!(
            "REVOKE MODIFY ON KEYSPACE {} FROM {}",
            self.keyspace, self.role
        ))
        .await
        .map_err(provider)?;
        Ok(())
    }
    /// Destructive tenant offboarding; call only after an explicit data-retention decision.
    pub async fn destroy<E: CassandraExecutor>(
        &self,
        exec: &E,
    ) -> Result<(), CassandraTenantError> {
        self.revoke(exec).await?;
        exec.execute(&format!("DROP ROLE {}", self.role))
            .await
            .map_err(provider)?;
        exec.execute(&format!("DROP KEYSPACE {}", self.keyspace))
            .await
            .map_err(provider)
    }
}
#[async_trait]
pub trait CassandraExecutor: Send + Sync {
    async fn execute(&self, cql: &str) -> Result<(), String>;
    async fn exists(&self, cql: &str, value: &str) -> Result<bool, String>;
    async fn has_grant(&self, role: &str, resource: &str, permission: &str)
        -> Result<bool, String>;
}
fn provider(e: impl ToString) -> CassandraTenantError {
    CassandraTenantError::Provider(e.to_string())
}
fn esc_cql(s: &str) -> String {
    s.replace('\'', "''")
}
fn validate_password(p: &str) -> Result<(), CassandraTenantError> {
    if p.len() < 24 || !p.bytes().all(|b| (33..=126).contains(&b)) {
        Err(CassandraTenantError::WeakPassword)
    } else {
        Ok(())
    }
}
fn validate_topology(dc: &str, rf: u8) -> Result<(), CassandraTenantError> {
    if dc.is_empty() || dc.len() > 48 || !dc.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_')
    {
        return Err(CassandraTenantError::InvalidDatacenter);
    }
    if !(1..=5).contains(&rf) {
        return Err(CassandraTenantError::InvalidReplicationFactor);
    }
    Ok(())
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn generates_restricted_cql() {
        let t = CassandraTenant::new("customer_01", "a-long-random-cassandra-secret").unwrap();
        let s = t.provisioning_cql("dc1", 3).unwrap().join("\n");
        assert!(s.contains("NetworkTopologyStrategy"));
        assert!(s.contains("GRANT SELECT"));
        assert!(!s.contains("GRANT ALL"));
    }
    #[test]
    fn rejects_injection_and_weak_password() {
        assert!(CassandraTenant::new("bad;drop", "a-long-random-cassandra-secret").is_err());
        assert!(CassandraTenant::new("tenant", "short").is_err());
    }
}

/// Concrete authenticated CQL executor backed by the production Scylla Rust
/// driver (compatible with Apache Cassandra). TLS peer verification is mandatory.
#[derive(Clone)]
pub struct ScyllaCassandraExecutor {
    session: std::sync::Arc<scylla::client::session::Session>,
}

impl ScyllaCassandraExecutor {
    pub async fn connect_tls(
        endpoint: &str,
        username: &str,
        password: &str,
        ca_pem_path: impl AsRef<std::path::Path>,
    ) -> Result<Self, CassandraTenantError> {
        use rustls::{ClientConfig, RootCertStore};
        use std::{fs::File, io::BufReader, sync::Arc};

        if username.trim().is_empty() || password.is_empty() || !endpoint.contains(':') {
            return Err(CassandraTenantError::Provider(
                "invalid CQL endpoint or administrative credentials".into(),
            ));
        }
        let mut roots = RootCertStore::empty();
        let certs = rustls_pemfile::certs(&mut BufReader::new(
            File::open(ca_pem_path).map_err(provider)?,
        ))
        .collect::<Result<Vec<_>, _>>()
        .map_err(provider)?;
        if certs.is_empty() {
            return Err(CassandraTenantError::Provider(
                "Cassandra CA bundle contains no certificates".into(),
            ));
        }
        for cert in certs {
            roots.add(cert).map_err(provider)?;
        }
        let tls = Arc::new(
            ClientConfig::builder()
                .with_root_certificates(roots)
                .with_no_client_auth(),
        );
        let session = scylla::client::session_builder::SessionBuilder::new()
            .known_node(endpoint)
            .user(username, password)
            .tls_context(Some(tls))
            .build()
            .await
            .map_err(provider)?;
        Ok(Self {
            session: Arc::new(session),
        })
    }

    async fn prepared_exists(&self, cql: &str, values: (&str,)) -> Result<bool, String> {
        let prepared = self.session.prepare(cql).await.map_err(|e| e.to_string())?;
        let result = self
            .session
            .execute_unpaged(&prepared, values)
            .await
            .map_err(|e| e.to_string())?;
        let rows = result.into_rows_result().map_err(|e| e.to_string())?;
        let mut decoded = rows.rows::<(String,)>().map_err(|e| e.to_string())?;
        match decoded.next() {
            Some(Ok(_)) => Ok(true),
            Some(Err(error)) => Err(error.to_string()),
            None => Ok(false),
        }
    }
}

#[async_trait]
impl CassandraExecutor for ScyllaCassandraExecutor {
    async fn execute(&self, cql: &str) -> Result<(), String> {
        self.session
            .query_unpaged(cql, &[])
            .await
            .map(|_| ())
            .map_err(|e| e.to_string())
    }

    async fn exists(&self, cql: &str, value: &str) -> Result<bool, String> {
        self.prepared_exists(cql, (value,)).await
    }

    async fn has_grant(
        &self,
        role: &str,
        resource: &str,
        permission: &str,
    ) -> Result<bool, String> {
        let keyspace = resource
            .strip_prefix("KEYSPACE ")
            .ok_or_else(|| "unsupported Cassandra permission resource".to_owned())?;
        if keyspace.is_empty()
            || !keyspace
                .bytes()
                .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'_')
        {
            return Err("invalid Cassandra keyspace permission resource".into());
        }
        let prepared = self.session.prepare(
            "SELECT permissions FROM system_auth.role_permissions WHERE role = ? AND resource = ?"
        ).await.map_err(|e| e.to_string())?;
        let result = self
            .session
            .execute_unpaged(&prepared, (role, format!("data/{keyspace}")))
            .await
            .map_err(|e| e.to_string())?;
        let rows = result.into_rows_result().map_err(|e| e.to_string())?;
        let mut decoded = rows
            .rows::<(std::collections::HashSet<String>,)>()
            .map_err(|e| e.to_string())?;
        while let Some(row) = decoded.next() {
            let (permissions,) = row.map_err(|e| e.to_string())?;
            if permissions
                .iter()
                .any(|value| value.eq_ignore_ascii_case(permission))
            {
                return Ok(true);
            }
        }
        Ok(false)
    }
}
