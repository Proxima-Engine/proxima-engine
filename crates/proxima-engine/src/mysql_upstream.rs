use mysql_async::prelude::Queryable;
use mysql_async::{Conn, Pool};

/// A dedicated upstream MySQL connection pool.
///
/// Construct one instance per authenticated tenant principal.
/// Never share a pool between principals with different upstream credentials.
pub struct MysqlUpstream {
    pool: Pool,
}

impl MysqlUpstream {
    /// Creates a pool from a MySQL connection URL.
    pub fn from_url(url: &str) -> Result<Self, mysql_async::Error> {
        let pool = Pool::from_url(url)?;
        Ok(Self { pool })
    }

    /// Acquires a real upstream connection.
    pub async fn get_connection(&self) -> Result<Conn, mysql_async::Error> {
        self.pool.get_conn().await
    }

    /// Executes a statement against the configured upstream.
    ///
    /// Admission and tenant authorization must happen before this method
    /// is called by the gateway.
    pub async fn execute(&self, sql: &str) -> Result<u64, mysql_async::Error> {
        let mut connection = self.pool.get_conn().await?;
        connection.query_drop(sql).await?;
        Ok(connection.affected_rows())
    }

    /// Disconnects the pool and waits for active connections to finish.
    pub async fn disconnect(self) -> Result<(), mysql_async::Error> {
        self.pool.disconnect().await
    }
}
