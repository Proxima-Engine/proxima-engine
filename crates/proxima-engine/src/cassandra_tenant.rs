#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CassandraTenantError {
    InvalidTenantId,
    WeakPassword,
    InvalidReplicationFactor,
    InvalidDatacenter,
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
        }
    }
}
impl std::error::Error for CassandraTenantError {}

/// Cassandra keyspace-per-tenant profile. Provisioning statements must run
/// through a separately authenticated administrative session.
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
        if password.len() < 24 || !password.bytes().all(|b| (33..=126).contains(&b)) {
            return Err(CassandraTenantError::WeakPassword);
        }
        let id = tenant_id.to_ascii_lowercase();
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
    /// Generates a dedicated keyspace, login role, and data-only grants.
    pub fn provisioning_cql(
        &self,
        datacenter: &str,
        replication_factor: u8,
    ) -> Result<Vec<String>, CassandraTenantError> {
        if datacenter.is_empty()
            || datacenter.len() > 48
            || !datacenter
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'_')
        {
            return Err(CassandraTenantError::InvalidDatacenter);
        }
        if !(1..=5).contains(&replication_factor) {
            return Err(CassandraTenantError::InvalidReplicationFactor);
        }
        let password = self.password.replace('\'', "''");
        Ok(vec![
            format!("CREATE KEYSPACE IF NOT EXISTS {} WITH replication = {{'class': 'NetworkTopologyStrategy', '{}': {}}} AND durable_writes = true", self.keyspace, datacenter, replication_factor),
            format!("CREATE ROLE IF NOT EXISTS {} WITH PASSWORD = '{}' AND LOGIN = true", self.role, password),
            format!("GRANT SELECT ON KEYSPACE {} TO {}", self.keyspace, self.role),
            format!("GRANT MODIFY ON KEYSPACE {} TO {}", self.keyspace, self.role),
        ])
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn provisions_separate_keyspace_and_restricted_role() {
        let t = CassandraTenant::new("customer_01", "a-long-random-cassandra-secret").unwrap();
        assert_eq!(t.keyspace(), "proxima_customer_01");
        assert_eq!(t.role(), "proxima_customer_01_app");
        let cql = t.provisioning_cql("datacenter1", 3).unwrap().join("\n");
        assert!(cql.contains("NetworkTopologyStrategy"));
        assert!(cql.contains("GRANT SELECT ON KEYSPACE proxima_customer_01"));
        assert!(cql.contains("GRANT MODIFY ON KEYSPACE proxima_customer_01"));
        assert!(!cql.contains("AUTHORIZE"));
        assert!(!cql.contains("GRANT ALL"));
    }
    #[test]
    fn escapes_password_and_rejects_identifier_injection() {
        let t = CassandraTenant::new("tenant_a", "a-long-random-password-with-'quote").unwrap();
        assert!(t.provisioning_cql("dc1", 1).unwrap()[1].contains("''"));
        assert!(matches!(
            CassandraTenant::new("a; DROP KEYSPACE x", "a-long-random-cassandra-secret"),
            Err(CassandraTenantError::InvalidTenantId)
        ));
        assert!(matches!(
            CassandraTenant::new("Customer_01", "a-long-random-cassandra-secret"),
            Err(CassandraTenantError::InvalidTenantId)
        ));
    }
    #[test]
    fn rejects_weak_secrets_and_invalid_topology() {
        assert!(matches!(
            CassandraTenant::new("tenant", "short"),
            Err(CassandraTenantError::WeakPassword)
        ));
        let t = CassandraTenant::new("tenant", "a-long-random-cassandra-secret").unwrap();
        assert!(matches!(
            t.provisioning_cql("dc1", 0),
            Err(CassandraTenantError::InvalidReplicationFactor)
        ));
        assert!(matches!(
            t.provisioning_cql("dc-1;DROP", 1),
            Err(CassandraTenantError::InvalidDatacenter)
        ));
    }
}
