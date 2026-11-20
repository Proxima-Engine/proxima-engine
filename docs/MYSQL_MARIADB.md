# Database gateway guides

The MySQL-compatible gateway executable supports two separately documented upstream targets. The protocol listener and gateway binary are shared; upstream server setup, compatibility versions and integration test suites are independent.

- **[MySQL gateway](MYSQL.md)** — MySQL upstream setup, client authentication, tenant database provisioning, MySQL 8.0 CI target and MySQL integration test.
- **[MariaDB gateway](MARIADB.md)** — MariaDB upstream setup, client authentication, tenant database provisioning, MariaDB 11.4 CI target and MariaDB integration test.
- [Shared MySQL protocol authentication](MYSQL_GATEWAY_AUTH.md).
- [Database gateway architecture and hosted Cloud boundary](CLOUD_CONTROL_PLANE.md).
