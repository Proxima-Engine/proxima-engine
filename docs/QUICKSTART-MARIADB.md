# MariaDB quickstart

This runs the MySQL-compatible tenant gateway against MariaDB 11.4.

## 1. Clone and build

```bash
git clone https://github.com/Proxima-Engine/proxima-engine.git
cd proxima-engine
cargo build --locked --release -p proxima-engine --bin proxima-mysql-gateway
```

## 2. Start MariaDB 11.4

```bash
docker run -d --name proxima-mariadb -e MARIADB_ROOT_PASSWORD=proxima-mariadb-local -p 127.0.0.1:3308:3306 mariadb:11.4
docker exec proxima-mariadb healthcheck.sh --connect --innodb_initialized
```

## 3. Provision tenant identities

Follow [MariaDB gateway guide](MARIADB.md) to create separate tenant databases and restricted upstream users, generate client verifiers and write `secrets/mysql-identities.json`. Keep the identity registry private and exclude it from Git.

## 4. Start and connect

```bash
export PROXIMA_MYSQL_IDENTITY_REGISTRY=./secrets/mysql-identities.json
export PROXIMA_MYSQL_LISTEN_ADDR=127.0.0.1:3307
RUST_LOG=info ./target/release/proxima-mysql-gateway

In another terminal, wait for the gateway TCP listener:

\`\`\`bash
nc -z 127.0.0.1 3307
\`\`\`
```

Connect Tenant A using `mysql --protocol=TCP -h 127.0.0.1 -P 3307 -u tenant_a_app -p tenant_a`, then repeat with Tenant B. Run the MariaDB integration suite against the disposable service:

\`\`\`bash
cargo test -p proxima-engine --test mariadb_gateway_integration -- --ignored
\`\`\`

Verify tenant-local CRUD, cross-tenant denial and database-switch denial.

## 5. Stop

```bash
docker rm -f proxima-mariadb
```

**Next:** [Complete MariaDB guide](MARIADB.md) · [Configuration](CONFIGURATION.md) · [Security](SECURITY.md)
