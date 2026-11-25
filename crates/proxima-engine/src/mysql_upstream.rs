use mysql_async::prelude::Queryable;
use mysql_async::{Conn, Opts, OptsBuilder, Pool, SslOpts};
use std::path::Path;

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

    /// Creates a pool with an explicit upstream CA bundle while retaining
    /// mysql_async's default certificate and hostname verification.
    pub fn from_url_with_ca(url: &str, ca_file: Option<&Path>) -> Result<Self, mysql_async::Error> {
        let opts = Opts::from_url(url)?;
        let pool = if let Some(ca_file) = ca_file {
            Pool::new(OptsBuilder::from_opts(opts).ssl_opts(Some(
                SslOpts::default().with_root_certs(vec![ca_file.to_path_buf().into()]),
            )))
        } else {
            Pool::new(opts)
        };
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
