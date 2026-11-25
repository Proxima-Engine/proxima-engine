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
```

In another terminal, confirm the gateway is listening and connect Tenant A:

```bash
nc -z 127.0.0.1 3307
mysql --protocol=TCP -h 127.0.0.1 -P 3307 -u tenant_a_app -p tenant_a
```

Repeat with Tenant B. Run the MariaDB integration suite against the disposable service:

```bash
cargo test -p proxima-engine --test mariadb_gateway_integration -- --ignored
```

Verify tenant-local CRUD, cross-tenant denial and database-switch denial.

## 5. Stop

```bash
docker rm -f proxima-mariadb
```

**Next:** [Complete MariaDB guide](MARIADB.md) · [Configuration](CONFIGURATION.md) · [Security](SECURITY.md)


## 3A. Understand the identity registry

The MySQL-compatible gateway maps each client username to one immutable tenant ID and MariaDB database. The registry contains the upstream connection URL and a one-way client password verifier; it must not contain client plaintext passwords. Keep the file private, set restrictive filesystem permissions and exclude it from Git.

Use separate upstream MariaDB accounts for each tenant. Grant only required data operations on that tenant's database. Do not grant global privileges, system-schema access, account administration or server administration. The selected database must match the registry mapping.

## 3B. Validate the connection path

The gateway is a separate process from the PostgreSQL Engine listener. Keep the local listener on loopback during development. For remote MariaDB services, configure verified TLS and private networking. Applications continue using their existing MySQL-compatible driver and connect to the gateway address.

## 3C. Acceptance checklist

- Each tenant's valid client identity maps to its assigned MariaDB database.
- Invalid credentials and unknown users are rejected.
- Cross-tenant reads and writes are denied.
- Database-switch attempts are rejected.
- Upstream accounts cannot access the other tenant's database.
- TLS and registry permissions are checked before production.

See [MariaDB gateway guide](MARIADB.md) for the full registry format, password verifier generation, SQL provisioning, Windows commands and integration verification.


## Windows PowerShell: clone and build

Open PowerShell in the folder where you keep source repositories. Install Git, the stable Rust toolchain and Cargo first. For gateway providers, Docker Desktop is also required for the disposable database service used by the acceptance test.

```powershell
git clone https://github.com/Proxima-Engine/proxima-engine.git
Set-Location .\proxima-engine
cargo build --locked --release -p proxima-engine --bin proxima-mysql-gateway
if ($LASTEXITCODE -ne 0) { throw "Proxima build failed" }
```

Run the command from the repository root. If you already cloned the repository, use `Set-Location` to enter the extracted `proxima-engine` directory instead of cloning a second copy. Keep generated credentials, certificates and local environment files outside Git.

## Configuration review before starting

Before launching this provider, verify all of the following against the full provider guide:

1. The provider endpoint, port and distribution/version identify the intended disposable or customer database.
2. Tenant IDs are resolved by the trusted application backend and are not accepted as authorization claims from a browser.
3. Each tenant has its own database/schema/keyspace/index namespace or IAM identity, as applicable to this provider.
4. Provisioning credentials are separate from tenant application credentials and are not stored in the client registry as plaintext.
5. Certificate authorities, server names and client certificates are configured for every network TLS leg.
6. Listener exposure is limited to the application network. Keep local tests on loopback.
7. Registry files and private keys have restrictive permissions and are excluded from source control.

## Runtime diagnostics

Start the provider process in a dedicated terminal and keep its logs visible while connecting a test client. Confirm the process is listening on the configured address before running application queries. If the client cannot connect, check the process output, port binding, upstream reachability and the database service's readiness before changing tenant policy.

If authentication fails, compare the client principal and tenant mapping with the registry or native provider identity. If a certificate error occurs, validate the configured CA and server name; do not disable certificate verification to make the connection succeed. If a cross-tenant test succeeds unexpectedly, stop the test and review the provider-native grants, namespace mapping and trusted tenant-resolution path before continuing.

## Production handover checklist

- Repeat the acceptance suite against a disposable instance matching the intended provider version.
- Record the exact provider version, Engine release, configuration revision and test result.
- Test allowed tenant operations and denied cross-tenant reads and writes.
- Verify backup/restore and credential rotation for the provider's isolation model.
- Move secrets into the deployment secret manager and enable verified TLS.
- Restrict network access to the Engine and database endpoints.
- Monitor Engine health, provider errors, rejected sessions and credential lifecycle.
- Use the linked complete provider guide for deployment-specific settings and operational procedures.
