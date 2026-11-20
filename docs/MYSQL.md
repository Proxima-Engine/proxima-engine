# MySQL gateway

This guide configures Proxima's MySQL-compatible protocol gateway against a MySQL upstream server. The gateway uses the MySQL client wire protocol and the dedicated proxima-mysql-gateway executable. The product guide is named MySQL. The repository's current CI compatibility target is MySQL Server 8.0; the version is recorded as a test target, not as the product name.

The gateway is a separate executable from the PostgreSQL Engine listener. It authenticates each client, binds the session to one immutable tenant principal, opens a dedicated upstream connection and validates the selected database before accepting the client session.

## 1. Requirements

- Git and stable Rust/Cargo
- MySQL server (the CI integration target is MySQL 8.0)
- MySQL-compatible client utilities (mysql and mysqladmin)
- Python 3 for generating password verifiers
- A private directory for the identity registry and upstream credentials

The gateway does not install or provision the MySQL server.

## 2. Clone and build

~~~bash
git clone https://github.com/Proxima-Engine/proxima-engine.git
cd proxima-engine
cargo build --release -p proxima-engine --bin proxima-mysql-gateway
~~~

PowerShell:

~~~powershell
git clone https://github.com/Proxima-Engine/proxima-engine.git
Set-Location .\proxima-engine
cargo build --release -p proxima-engine --bin proxima-mysql-gateway
~~~

## 3. Start a disposable MySQL server

For a disposable local server matching the repository's current CI target, start MySQL 8.0 in Docker:

~~~bash
docker run -d --name proxima-mysql \
  -e MYSQL_ROOT_PASSWORD=proxima-mysql-local \
  -p 127.0.0.1:3306:3306 \
  mysql:8.0
~~~

Wait until the server is ready:

~~~bash
docker exec proxima-mysql mysqladmin ping -uroot -pproxima-mysql-local --silent
~~~

Confirm the upstream server identity before creating tenant fixtures:

~~~bash
docker exec proxima-mysql mysql -uroot -pproxima-mysql-local -e "SELECT VERSION(), @@version_comment;"
~~~

Use a disposable database only. The next section creates two separate tenant databases and dedicated least-privilege upstream users. Remove the local server when finished:

~~~bash
docker rm -f proxima-mysql
~~~

## 4. Provision tenant databases and upstream accounts

Create one database and one restricted upstream account per tenant:

~~~sql
CREATE DATABASE tenant_a;
CREATE DATABASE tenant_b;

CREATE USER 'tenant_a_gateway'@'%' IDENTIFIED BY 'REPLACE_WITH_TENANT_A_SECRET';
CREATE USER 'tenant_b_gateway'@'%' IDENTIFIED BY 'REPLACE_WITH_TENANT_B_SECRET';

GRANT SELECT, INSERT, UPDATE, DELETE ON tenant_a.* TO 'tenant_a_gateway'@'%';
GRANT SELECT, INSERT, UPDATE, DELETE ON tenant_b.* TO 'tenant_b_gateway'@'%';
FLUSH PRIVILEGES;
~~~

Create the application's tables in each tenant database. Do not grant either tenant account access to the other tenant database, system schemas, global privileges, user administration or server administration. Avoid global wildcard grants.

The database selected by the live upstream connection must exactly match the database field in the registry entry.

## 5. Generate client password verifiers

The registry stores a one-way verifier, not the client's plaintext password. For new principals use caching_sha2_password and password_sha256, the hexadecimal encoding of SHA256(SHA256(password)).

Bash:

~~~bash
python3 - <<'PY'
import hashlib
import os
password = os.environ["PROXIMA_CLIENT_PASSWORD"].encode()
print(hashlib.sha256(hashlib.sha256(password).digest()).hexdigest())
PY
~~~

PowerShell:

~~~powershell
$env:PROXIMA_CLIENT_PASSWORD = "REPLACE_WITH_A_LONG_RANDOM_CLIENT_SECRET"
python -c "import hashlib,os; p=os.environ['PROXIMA_CLIENT_PASSWORD'].encode(); print(hashlib.sha256(hashlib.sha256(p).digest()).hexdigest())"
Remove-Item Env:PROXIMA_CLIENT_PASSWORD
~~~

Use a unique client password for each principal. Do not reuse the upstream database password as the client-facing password.

For legacy compatibility, the registry accepts mysql_native_password with password_sha1 containing hexadecimal SHA1(password). Use caching_sha2_password for new clients.

## 6. Create the identity registry

Create a private directory and registry file. Replace all placeholders with actual tenant identifiers, database names, client verifiers and upstream credentials:

~~~bash
mkdir -p secrets
chmod 700 secrets
cat > secrets/mysql-identities.json <<'JSON'
{
  "users": [
    {
      "username": "tenant_a_app",
      "tenant_id": "tenant-a",
      "database": "tenant_a",
      "upstream_url": "mysql://tenant_a_gateway:REPLACE_WITH_UPSTREAM_SECRET@127.0.0.1:3306/tenant_a",
      "auth_plugin": "caching_sha2_password",
      "password_sha256": "REPLACE_WITH_64_HEX_CHARACTER_VERIFIER"
    },
    {
      "username": "tenant_b_app",
      "tenant_id": "tenant-b",
      "database": "tenant_b",
      "upstream_url": "mysql://tenant_b_gateway:REPLACE_WITH_UPSTREAM_SECRET@127.0.0.1:3306/tenant_b",
      "auth_plugin": "caching_sha2_password",
      "password_sha256": "REPLACE_WITH_64_HEX_CHARACTER_VERIFIER"
    }
  ]
}
JSON
chmod 600 secrets/mysql-identities.json
~~~

| Field | Meaning |
|---|---|
| username | Client-facing database username |
| tenant_id | Immutable tenant identifier attached to the session |
| database | The only database assigned to this tenant principal |
| upstream_url | Tenant-specific upstream URL and database credential |
| auth_plugin | caching_sha2_password or mysql_native_password |
| password_sha256 | SHA256(SHA256(password)) verifier |
| password_sha1 | SHA1(password) verifier for legacy authentication |

Each principal must contain exactly one verifier. The authentication plugin must match its verifier. Duplicate usernames, invalid database names, malformed URLs and database mismatches are rejected when the registry loads.

Add secrets/ to .gitignore. Never commit this file or expose its contents in logs.

## 7. Start the gateway

The default listener is 127.0.0.1:3307:

~~~bash
export PROXIMA_MYSQL_IDENTITY_REGISTRY=./secrets/mysql-identities.json
export PROXIMA_MYSQL_LISTEN_ADDR=127.0.0.1:3307
RUST_LOG=info cargo run --release -p proxima-engine --bin proxima-mysql-gateway
~~~

PowerShell:

~~~powershell
$env:PROXIMA_MYSQL_IDENTITY_REGISTRY = ".\secrets\mysql-identities.json"
$env:PROXIMA_MYSQL_LISTEN_ADDR = "127.0.0.1:3307"
$env:RUST_LOG = "info"
cargo run --release -p proxima-engine --bin proxima-mysql-gateway
~~~

Keep the listener on loopback or a private network protected by firewall rules. Do not expose it directly to the public internet.

## 8. Connect clients

Use the client-facing credentials from the registry. The gateway selects the upstream credentials from the authenticated principal:

~~~bash
mysql --protocol=TCP -h 127.0.0.1 -P 3307 -u tenant_a_app -p tenant_a
~~~

Run a tenant query:

~~~sql
SELECT DATABASE();
SELECT id, value FROM records ORDER BY id;
~~~

Tenant B uses its own client identity:

~~~bash
mysql --protocol=TCP -h 127.0.0.1 -P 3307 -u tenant_b_app -p tenant_b
~~~

Use a MySQL client that supports the configured authentication plugin. The upstream URL must point to the MySQL instance and assigned tenant database.

## 9. Enforced controls

- Client authentication uses the registry verifier and configured MySQL authentication plugin.
- An authenticated principal is bound once to the client session and cannot be rebound.
- The tenant's dedicated upstream connection is established before authentication succeeds.
- The live upstream SELECT DATABASE() result must match the registry database.
- Database switching and cross-database qualified relations are denied.
- SQL admission parses one statement and permits SELECT, INSERT, UPDATE and DELETE.
- Multi-statements, DDL, unsupported statement classes, system-schema references, SELECT INTO and selected privileged/resource-intensive functions are rejected.
- Prepared statements are admitted and covered by integration tests.
- Concurrent connections are bounded; upstream connection and query operations have deadlines.
- Non-loopback upstream URLs must require verified TLS with require_ssl=true.

SQL admission supplements database grants; it does not replace them. Keep upstream accounts least-privileged and isolated by tenant. Remote upstream TLS must validate the server certificate.

## 10. Integration verification

The MySQL-specific ignored integration test is crates/proxima-engine/tests/mysql_gateway_integration.rs. CI provisions mysql:8.0 on port 3306.

The CI runner provisions a disposable MySQL 8.0 service, creates two tenant databases and restricted upstream accounts, generates client verifiers, starts the gateway and runs the MySQL integration suite.

The tests verify correct authentication, rejection of incorrect caching SHA-2 credentials, tenant-local reads, denial of cross-tenant reads and writes, denial of database switching, persistent session binding after denied operations, and prepared SELECT/INSERT statements.

To run a test manually, first provision the disposable fixtures and start the gateway with the exact ports and registry expected by the test runner. Then execute:

~~~bash
cargo test -p proxima-engine --test mysql_gateway_integration -- --ignored --test-threads=1
~~~

These tests are ignored by default because they require live database services and a running gateway. The CI script is the reproducible reference for the fixture and process lifecycle.

## 11. Troubleshooting

| Symptom | Check |
|---|---|
| Gateway exits | Confirm PROXIMA_MYSQL_IDENTITY_REGISTRY points to readable, valid JSON. |
| Registry rejected | Each principal needs exactly one verifier and a matching authentication plugin. |
| Client authentication fails | Check username, client password, plugin and verifier generation. |
| Upstream authentication fails | Check the tenant-specific upstream username/password and server account host rule. |
| Database identity mismatch | The database field and database in upstream_url must be identical. |
| Remote upstream rejected | Configure verified TLS and require_ssl=true in the URL options. |
| Cross-database SQL rejected | Use unqualified table names in the assigned database. |
| Query rejected | The current admission policy permits one parsed SELECT, INSERT, UPDATE or DELETE statement. |
| Port unavailable | Set PROXIMA_MYSQL_LISTEN_ADDR to an unused private address and port. |

## Related references

- [Repository README](../README.md)
- [MySQL client authentication](MYSQL_GATEWAY_AUTH.md)
- [Security architecture](SECURITY.md)
- [Configuration](CONFIGURATION.md)
- [Deployment](DEPLOYMENT.md)
- [Verification](VERIFICATION.md)
- [GitHub Actions](https://github.com/Proxima-Engine/proxima-engine/actions)
- [MySQL gateway source](../crates/proxima-engine/src/mysql_gateway.rs)
- [MySQL integration test](../crates/proxima-engine/tests/mysql_gateway_integration.rs)



## CI compatibility target

The repository CI workflow currently provisions mysql:8.0. The integration suite validates tenant-local reads, cross-tenant read/write denial, database-switch denial, prepared statements and invalid-password rejection against that service. This is the tested CI target; rerun the suite before claiming compatibility with additional server versions.
