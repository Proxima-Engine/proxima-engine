# MySQL quickstart

This runs the dedicated MySQL protocol gateway against a disposable MySQL 8 service.

## 1. Clone and build

```bash
git clone https://github.com/Proxima-Engine/proxima-engine.git
cd proxima-engine
cargo build --locked --release -p proxima-engine --bin proxima-mysql-gateway
```

## 2. Start MySQL 8

```bash
docker run -d --name proxima-mysql -e MYSQL_ROOT_PASSWORD=proxima-mysql-local -p 127.0.0.1:3306:3306 mysql:8
docker exec proxima-mysql mysqladmin ping -uroot -pproxima-mysql-local --silent
```

## 3. Provision two tenants

Follow [MySQL gateway guide](MYSQL.md) to create separate tenant databases, restricted upstream accounts, client password verifiers and `secrets/mysql-identities.json`. Do not use a shared administrator identity for application traffic.

## 4. Start and connect

```bash
export PROXIMA_MYSQL_IDENTITY_REGISTRY=./secrets/mysql-identities.json
export PROXIMA_MYSQL_LISTEN_ADDR=127.0.0.1:3307
RUST_LOG=info ./target/release/proxima-mysql-gateway
```

In another terminal, confirm the gateway is listening:

```bash
nc -z 127.0.0.1 3307
mysql --protocol=TCP -h 127.0.0.1 -P 3307 -u tenant_a_app -p tenant_a
```

Repeat with Tenant B. Confirm each identity cannot access the other database. Use verified TLS and private networking before connecting remote upstreams.

## 5. Verify and stop

Run the two-tenant MySQL gateway acceptance suite:

```bash
bash scripts/test-mysql-gateways-ci.sh
```

Remove the local server with `docker rm -f proxima-mysql`.

**Next:** [Complete MySQL guide](MYSQL.md) · [Configuration](CONFIGURATION.md) · [Security](SECURITY.md)


## 3A. Understand the identity registry

The gateway registry maps each client-facing username to one immutable tenant ID, one database, an upstream URL, an authentication plugin and a one-way client password verifier. It stores no client plaintext password. Keep the registry in a private directory with restrictive filesystem permissions and exclude it from Git. Do not reuse an upstream database password as the client-facing password.

Use separate upstream accounts for Tenant A and Tenant B. Grant only the required database-level data operations. Do not grant global privileges, system-schema access, user administration or server administration. The requested database must exactly match the registry entry.

## 3B. Validate the connection path

The MySQL gateway is a separate executable from the PostgreSQL listener. Confirm the gateway process is listening on the configured address before connecting. The application keeps its MySQL driver and points it at the gateway. Keep the listener on loopback for local testing; use private networking and verified TLS for remote upstreams.

## 3C. Acceptance checklist

- Valid tenant credentials authenticate and map to the expected database.
- Invalid client passwords and unknown usernames are rejected.
- Tenant A cannot select or modify Tenant B's database.
- Database switching cannot escape the assigned tenant database.
- Upstream credentials are least-privilege and isolated per tenant.
- TLS and registry file permissions are verified before production.

See [MySQL gateway guide](MYSQL.md) for the complete registry schema, verifier generation, PowerShell commands, gateway configuration and integration verification.


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
