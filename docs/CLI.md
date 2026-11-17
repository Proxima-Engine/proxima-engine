# Agata CLI for Proxima Engine

The public Engine repository includes a Python 3.10+ command-line tool implemented with the Python standard library. It bootstraps local development identity, creates signed tenant test tokens, checks local diagnostics, and reports Engine status.

Run commands from the repository root:

```bash
python scripts/agata.py --help
python scripts/agata.py init
python scripts/agata.py token --tenant tenant_a --ttl 300
python scripts/agata.py doctor
python scripts/agata.py status
```

On Windows PowerShell, use the same commands with `python`. On Unix-like systems, `python3` may be the configured interpreter.

## Commands

The Rust Policy Guard binary also exposes the adapter maturity catalog:

```bash
cargo run -p proxima-engine --bin proxima-policy-guard -- adapters
```

The `adapters` command prints the versioned Proxima Security Core catalog. PostgreSQL, MySQL/MariaDB, Microsoft SQL Server, MongoDB, Redis, CockroachDB, SQLite and Elasticsearch/OpenSearch are marked `in_development` with only their implemented discovery/compiler capabilities. Oracle, DynamoDB, Cassandra and VAULTDB remain `planned`. An in-development entry is not a supported database integration.

The PostgreSQL `discover-postgres` command enumerates non-system tables, partitioned tables, foreign tables, views, materialized views, sequences, functions and procedures. It captures ownership, columns/defaults, RLS flags, native policies, constraints, indexes, triggers, view definitions/options and routine security/execute ACL metadata. It requires the registered target ID/database name and a TLS-verified, read-only inspection role through `PROXIMA_POSTGRES_ADAPTER_DATABASE_URL`, `PROXIMA_POSTGRES_ADAPTER_TARGET_ID`, `PROXIMA_POSTGRES_ADAPTER_DATABASE_NAME` and `PROXIMA_TENANT_ROLE_PREFIX`.

Run a full database discovery or scope it to one schema:

```bash
cargo run -p proxima-engine --bin proxima-policy-guard -- discover-postgres
cargo run -p proxima-engine --bin proxima-policy-guard -- discover-postgres public
```

Discovery returns an inventory and fingerprint; it does not infer tenant keys, verify tenant isolation, or authorize traffic.

The PostgreSQL `audit` command is a catalog posture inspection, not a semantic policy verifier. Its JSON deliberately reports `security_posture: unknown` and `access_decision: deny`, even when it finds no catalog findings. A zero exit code means the inspection completed without catalog findings; it does not certify tenant isolation.


Validate a database-neutral policy document against the shared contract without connecting to a database:

```bash
cargo run -p proxima-engine --bin proxima-policy-guard -- validate-policy ./policy.json
```

The command checks the versioned envelope, explicit resources, tenant ownership keys and unique operations. It does not prove that any database adapter has enforced the policy.

Generate reviewable PostgreSQL policy SQL from an explicit JSON specification:

```bash
cargo run -p proxima-engine --bin proxima-policy-guard -- generate ./policy.json > policy.sql
```

Each tenant role must match one shared Engine prefix plus the normalized tenant ID. For example, `tenant-a` maps to `proxima_tenant_tenant_a` when `PROXIMA_TENANT_ROLE_PREFIX=proxima_tenant_`. The generated SQL prints the required prefix and performs transactional preflight checks; the CLI never connects to a database or executes the generated DDL. Review and apply it through a controlled migration workflow.

Generation refuses partitioned relations, unsafe dependent views, materialized views without separate protection, tenant roles with database/schema `CREATE` privileges, and unsafe role defaults. These restrictions are deliberate until the PostgreSQL adapter implements and verifies those paths.


| Command | Purpose |
|---|---|
| `init` | Generate local node identity and tenant-signing credentials in `.proxima-dev/` |
| `token` | Mint a short-lived signed tenant-context token |
| `verify-token` | Validate a token against the configured local signing key |
| `doctor` | Check local Engine endpoints and development prerequisites |
| `status` | Read local Engine status information |

Use `python scripts/agata.py <command> --help` to inspect command-specific arguments.

## Local credential setup

The `init` command creates `.proxima-dev/dev-config.json` and `.proxima-dev/node-identity.json`. It refuses to overwrite existing credentials. Configure the Engine's `PROXIMA_TENANT_SIGNING_KEY` with the literal `tenant_signing_key` value from the generated config.

The `.proxima-dev/` directory contains secrets and is ignored by Git. Keep it local and do not publish its contents.

The CLI operates on local development identity and local Engine endpoints. Hosted node registration and account workflows are managed separately by Agata Proxima Cloud.

## Token handling

`verify-token` accepts a generated token as a positional argument. Shell command-line arguments may appear in process listings, so use this mode with local test credentials only. Keep production tokens in protected process environments and secret stores.

## Verify tenant access

`doctor` and `status` inspect local Engine HTTP endpoints. To test database access boundaries, follow [Tenant isolation](TENANT_ISOLATION.md) with a disposable PostgreSQL database.

Run the CLI unit tests:

```bash
python -m unittest discover -s tests_cli -v
```

For the full Rust and PostgreSQL verification path, see [Verification](VERIFICATION.md).

## Review-only multi-database policy plans

The `compile-plan` command generates a JSON policy plan for the current early non-PostgreSQL compilers. It does not connect to a database or apply changes.

```bash
proxima-policy-guard compile-plan sql_server policy.json
proxima-policy-guard compile-plan mysql policy.json
proxima-policy-guard compile-plan mariadb policy.json
proxima-policy-guard compile-plan mongodb policy.json
proxima-policy-guard compile-plan redis policy.json
```

Redirect output to a file for review, for example `proxima-policy-guard compile-plan sql_server policy.json > sql-server-plan.json`. SQL Server plans contain a `<VERIFIED_COLUMN_TYPE>` placeholder that must be resolved by a future live catalog inspector; do not execute the plan as-is. MySQL/MariaDB and MongoDB templates require one database per tenant. Redis requires a keyspace resource whose `tenant_key` uses a strict tenant-specific pattern such as `tenant:${tenant_id}:*`. These policy-generation templates are review-only. MySQL/MariaDB, MongoDB and Redis also have live native discovery/inspection paths, but none of these adapters currently deploy policies, execute independent semantic probes or provide production runtime admission.


## Native MySQL/MariaDB adapter

The Rust adapter exposes read-only MySQL-protocol discovery and catalog inspection for a registered database target. It requires a `mysql://` connection URL whose server certificate and hostname can be verified; TLS identity verification is mandatory. The adapter reads `information_schema` tables, columns, routines, table privileges and schema privileges, and computes a catalog fingerprint for drift comparison. It deliberately reports catalog visibility as incomplete because MySQL/MariaDB metadata visibility is privilege-filtered.

The adapter can be constructed by an Engine integration with `MySqlCatalogAdapter::new(target_id, database_name, connection_url, DatabaseKind::MySql)` or `DatabaseKind::MariaDb`. It captures table/view columns, constraints, indexes, triggers, view definitions/security mode, routine metadata and routine privileges, as well as authenticated-account grants. It does not apply DDL, create users, switch roles, or authorize traffic. Its existing database-per-tenant plan compiler remains review-only until a trusted protocol gateway binds tenant identity to isolated database principals and independent positive/negative probes prove the boundary.

Use the native discovery commands with the same registered-target variables for either database family:

```bash
PROXIMA_MYSQL_ADAPTER_DATABASE_URL='mysql://...' \
PROXIMA_MYSQL_ADAPTER_TARGET_ID='registered-target-id' \
PROXIMA_MYSQL_ADAPTER_DATABASE_NAME='application_db' \
cargo run -p proxima-engine --bin proxima-policy-guard -- discover-mysql

PROXIMA_MYSQL_ADAPTER_DATABASE_URL='mysql://...' \
PROXIMA_MYSQL_ADAPTER_TARGET_ID='registered-target-id' \
PROXIMA_MYSQL_ADAPTER_DATABASE_NAME='application_db' \
cargo run -p proxima-engine --bin proxima-policy-guard -- discover-mariadb
```

For policy inspection, use `inspect-mysql-policy policy.json` or `inspect-mariadb-policy policy.json`. These commands always retain a deny decision because the adapter has no trusted tenant-to-database runtime principal binding and cannot prove document/row isolation from metadata alone. Keep the connection URL in a protected environment variable; do not place credentials in source control or command history.


## Native MongoDB adapter

The Engine crate exposes `MongoCatalogAdapter` for a registered MongoDB database. Its URI must explicitly enable TLS or use `mongodb+srv://`; insecure certificate/hostname options and explicit TLS disablement are rejected. Discovery records visible collections/views, collection validators/options, view definitions and the authenticated account's effective privileges from `connectionStatus`. The inventory is marked incomplete because MongoDB metadata visibility is privilege-scoped.

The adapter checks whether a collection validator declares and requires the configured tenant ownership field, but this is not a substitute for enforcing document-level authorization. MongoDB database roles do not automatically filter documents by tenant. Independent authenticated tenant probes and a trusted runtime enforcement boundary remain mandatory before admission.

Use the Policy Guard commands to inventory a registered database or inspect a policy:

```bash
PROXIMA_MONGODB_ADAPTER_URI='mongodb+srv://...' \
PROXIMA_MONGODB_ADAPTER_TARGET_ID='registered-target-id' \
PROXIMA_MONGODB_ADAPTER_DATABASE_NAME='application_db' \
cargo run -p proxima-engine --bin proxima-policy-guard -- discover-mongodb

PROXIMA_MONGODB_ADAPTER_URI='mongodb+srv://...' \
PROXIMA_MONGODB_ADAPTER_TARGET_ID='registered-target-id' \
PROXIMA_MONGODB_ADAPTER_DATABASE_NAME='application_db' \
cargo run -p proxima-engine --bin proxima-policy-guard -- inspect-mongodb-policy policy.json
```

Both commands return a deny decision until a native document-level enforcement boundary and independent positive/negative tenant probes exist. The URI must not disable TLS or certificate/hostname verification; keep credentials in a protected environment variable.


## Native Redis ACL adapter

The Rust adapter requires a rediss:// URI and a registered logical database index. It rejects URL fragments, including redis-rs's #insecure fragment that disables TLS certificate verification. It connects with TLS, confirms the selected database using CLIENT INFO, reads the authenticated ACL user, ACL user rules, read-only/write-only/read-write key patterns, command rules, ACL categories, server version and keyspace statistics, and fingerprints the observed ACL state. Policy inspection checks required explicit commands and key-pattern modes, flags broad categories and wildcard access, and still requires independent data-plane probes. Credential hashes and plaintext-style ACL password tokens are redacted from the returned inventory; the raw ACL rules are hashed for drift detection.

```bash
PROXIMA_REDIS_ADAPTER_URI='rediss://...' \\
PROXIMA_REDIS_ADAPTER_TARGET_ID='registered-target-id' \\
PROXIMA_REDIS_ADAPTER_DATABASE_INDEX='0' \\
cargo run -p proxima-engine --bin proxima-policy-guard -- discover-redis

PROXIMA_REDIS_ADAPTER_URI='rediss://...' \\
PROXIMA_REDIS_ADAPTER_TARGET_ID='registered-target-id' \\
PROXIMA_REDIS_ADAPTER_DATABASE_INDEX='0' \\
cargo run -p proxima-engine --bin proxima-policy-guard -- inspect-redis-policy policy.json
```

The inspection principal needs permission to run CLIENT INFO, PING, ACL WHOAMI, ACL LIST, ACL CAT, and INFO. The result remains incomplete and denied: ACL key patterns do not prove that application code consistently uses tenant keys, and keyless commands, scripts, functions and modules need a trusted enforcement layer and adversarial probes. Keep the Redis URI and credentials in a protected environment variable.


## Native Microsoft SQL Server adapter

The SQL Server adapter uses encrypted TDS with certificate verification and SQL username/password authentication. Supply a direct hostname and TCP port; SQL Browser/named-instance discovery and integrated Windows/Kerberos authentication are not enabled. This build rejects integrated Windows/Kerberos authentication, TrustServerCertificate=true and Encrypt=false. It confirms the connected database, and inventories tables/columns, object and column permissions, schema/database permissions, principals, role memberships, RLS security policies/predicates, triggers, views and stored routines. It marks catalog visibility incomplete unless the inspection identity has database VIEW DEFINITION or sysadmin visibility; sysadmin inspection is explicitly flagged.

```powershell
$env:PROXIMA_SQL_SERVER_ADAPTER_CONNECTION_STRING = 'Server=db.example,1433;Database=app;User Id=...;Password=...;Encrypt=True;TrustServerCertificate=False'
$env:PROXIMA_SQL_SERVER_ADAPTER_TARGET_ID = 'registered-target-id'
$env:PROXIMA_SQL_SERVER_ADAPTER_DATABASE_NAME = 'app'
cargo run -p proxima-engine --bin proxima-policy-guard -- discover-sql-server
cargo run -p proxima-engine --bin proxima-policy-guard -- inspect-sql-server-policy policy.json
```

Inspection checks tenant columns and nullability, enabled FILTER/BLOCK predicates for the declared operations, and the referenced predicate-function definition for SESSION_CONTEXT and schema binding. It still denies admission: a database client can set SESSION_CONTEXT unless a trusted application/gateway boundary prevents it, and independent positive/negative tenant probes are required. Keep the connection string in a protected environment variable.

## Native CockroachDB catalog discovery

CockroachDB discovery uses the PostgreSQL wire protocol with TLS certificate verification, but a separate CockroachDB adapter and explicit server-identity check. It inventories non-system tables and views, columns, and table grants from the target database. The inventory is bounded to 10,000 relations and is always marked incomplete because database/schema ACLs, role memberships, ownership and effective inherited privileges are not yet inventoried. It fingerprints the visible catalog for drift comparison.

The adapter does not assume PostgreSQL row-level security semantics and does not generate or deploy policies. Its descriptor exposes schema inspection and drift detection only; verification always denies until CockroachDB-specific tenant authorization, trusted identity binding and independent cross-tenant probes exist.

```bash
PROXIMA_COCKROACH_ADAPTER_DATABASE_URL='postgresql://...' \
PROXIMA_COCKROACH_ADAPTER_TARGET_ID='registered-target-id' \
PROXIMA_COCKROACH_ADAPTER_DATABASE_NAME='application_db' \
cargo run -p proxima-engine --bin proxima-policy-guard -- discover-cockroachdb

# Optional schema-scoped inventory
cargo run -p proxima-engine --bin proxima-policy-guard -- discover-cockroachdb public

# Inspect a canonical policy; verification remains blocked until native enforcement exists
PROXIMA_COCKROACH_ADAPTER_DATABASE_URL='postgresql://...' \
PROXIMA_COCKROACH_ADAPTER_TARGET_ID='registered-target-id' \
PROXIMA_COCKROACH_ADAPTER_DATABASE_NAME='application_db' \
cargo run -p proxima-engine --bin proxima-policy-guard -- inspect-cockroach-policy policy.json
```

The connector uses the same verified root-store configuration as PostgreSQL discovery. Credentials must remain in a protected environment variable; discovery is read-only and does not authorize application traffic.


## Native SQLite file-isolation discovery

The SQLite adapter opens a persistent database file read-only, disables trusted schema execution for the inspection connection, rejects attached databases and verifies that the connected main database resolves to the registered absolute file path. It inventories tables/views, columns, indexes and indexed columns, foreign keys, triggers, schema definitions, journal mode and filesystem permissions for the database file, containing directory and any WAL/SHM sidecars.

SQLite has no native database users or row-level security. The adapter therefore does not generate SQL tenant policies or claim that a tenant key column provides isolation. A real tenant boundary requires a trusted file-per-tenant selector, exclusive OS-level file and directory permissions, and independent cross-tenant file-access probes. Windows ACL inspection is not yet implemented, so Windows discovery remains denied.

```bash
PROXIMA_SQLITE_ADAPTER_DATABASE_PATH='/absolute/path/to/tenant.db' \
PROXIMA_SQLITE_ADAPTER_DATABASE_URI='sqlite:///absolute/path/to/tenant.db' \
PROXIMA_SQLITE_ADAPTER_TARGET_ID='registered-target-id' \
cargo run -p proxima-engine --bin proxima-policy-guard -- discover-sqlite

PROXIMA_SQLITE_ADAPTER_DATABASE_PATH='/absolute/path/to/tenant.db' \
PROXIMA_SQLITE_ADAPTER_DATABASE_URI='sqlite:///absolute/path/to/tenant.db' \
PROXIMA_SQLITE_ADAPTER_TARGET_ID='registered-target-id' \
cargo run -p proxima-engine --bin proxima-policy-guard -- inspect-sqlite-policy policy.json
```

The inspection URI must point to the same file as the absolute registered path. Both commands are read-only; policy inspection returns deny because native tenant authorization and file-selection enforcement are not implemented.


## Native Elasticsearch / OpenSearch discovery

The search-cluster adapter requires HTTPS and an explicit Authorization value supplied separately from the endpoint URL. It disables redirects, applies connection/request deadlines, confirms the root cluster identity, inventories indices matching the registered pattern, and retrieves mappings, settings and aliases. It also reads the authenticated identity and Elasticsearch security roles/users or OpenSearch Security plugin roles, role mappings and internal users when the inspection principal has permission. Policy inspection checks DLS coverage only against roles assigned to the authenticated principal; it does not infer safety from an unrelated tenant role. Discovery remains incomplete because cluster-wide index and security-catalog visibility cannot yet be independently attested. User password/hash/token fields are stripped before evidence serialization.

The adapter is discovery-only. A tenant field in an index mapping does not isolate documents. Native DLS/FLS role definitions, authenticated tenant-principal binding, policy deployment and independent positive/negative document probes are still required.

```bash
PROXIMA_ELASTICSEARCH_ADAPTER_ENDPOINT='https://search.example.com:9200' \
PROXIMA_ELASTICSEARCH_ADAPTER_INDEX_PATTERN='tenant-*' \
PROXIMA_ELASTICSEARCH_ADAPTER_TARGET_ID='registered-target-id' \
PROXIMA_ELASTICSEARCH_ADAPTER_AUTHORIZATION='ApiKey ...' \
cargo run -p proxima-engine --bin proxima-policy-guard -- discover-elasticsearch

PROXIMA_ELASTICSEARCH_ADAPTER_ENDPOINT='https://search.example.com:9200' \
PROXIMA_ELASTICSEARCH_ADAPTER_INDEX_PATTERN='tenant-*' \
PROXIMA_ELASTICSEARCH_ADAPTER_TARGET_ID='registered-target-id' \
PROXIMA_ELASTICSEARCH_ADAPTER_AUTHORIZATION='ApiKey ...' \
cargo run -p proxima-engine --bin proxima-policy-guard -- inspect-elasticsearch-policy policy.json
```

Do not put API keys, bearer tokens or Basic credentials in the endpoint URL, source control or command history. Use a protected environment/secret manager. If the security catalog endpoints return 401/403/404, discovery reports the security inventory as incomplete and policy inspection remains denied.
