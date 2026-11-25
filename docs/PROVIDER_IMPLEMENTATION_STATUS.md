# Proxima Engine — Database Provider Runtime Reference

Proxima Engine includes a supervised runtime path for every database in the Agata Proxima provider catalogue. The Engine receives organization-scoped assignments from Cloud, validates signed configuration, activates the provider runtime, provisions or verifies tenant identities, and reports the applied revision and provider evidence.

## Provider runtime matrix

| Database | Engine runtime | Tenant security boundary | Run provider acceptance |
|---|---|---|---|
| PostgreSQL | Native PostgreSQL wire listener | Signed tenant context, tenant roles and row-level security | `cargo test -p proxima-engine --test postgres_integration -- --ignored` and [PostgreSQL quickstart](QUICKSTART.md) |
| MySQL | `proxima-mysql-gateway` | Authenticated tenant identity and dedicated upstream account/database | `bash scripts/test-mysql-gateways-ci.sh` |
| MariaDB | `proxima-mysql-gateway` | Authenticated tenant identity and MariaDB database grants | `cargo test -p proxima-engine --test mariadb_gateway_integration -- --ignored` |
| CockroachDB | PostgreSQL wire runtime | Signed tenant context, tenant roles and row-level security | `bash scripts/test-cockroachdb-tenant-isolation-ci.sh` |
| MongoDB | `proxima-mongodb-gateway` | SCRAM principal mapped to one tenant database | `bash scripts/test-mongodb-tenant-isolation-ci.sh` |
| Redis | `proxima-redis-gateway` | Tenant key namespace and tenant-specific Redis ACL identity | `bash scripts/test-redis-tenant-gateway-ci.sh` |
| Microsoft SQL Server | `proxima-sqlserver-tds-gateway` | TDS 7.4 LOGIN7 principal, assigned database and least-privilege SQL Server login | `bash scripts/test-sqlserver-tenant-isolation-ci.sh` and `powershell -File scripts/test-sqlserver-tds-gateway.ps1` |
| SQLite | Native embedded runtime | Private database file per tenant, canonical path checks and filesystem permissions | `cargo test -p proxima-engine sqlite_tenant` |
| Oracle Database | Native Oracle runtime | Dedicated schema owner, account lifecycle and least-privilege grants | `bash scripts/test-oracle-tenant-isolation-ci.sh` |
| Amazon DynamoDB | AWS SDK IAM runtime | Exact table ARN and tenant partition-key condition using `dynamodb:LeadingKeys` | `bash scripts/test-dynamodb-leading-keys-aws.sh` |
| Apache Cassandra | Native Cassandra runtime | Keyspace-per-tenant roles and restricted grants | `bash scripts/test-cassandra-tenant-isolation-ci.sh` |
| Elasticsearch / OpenSearch | Native search runtime | Tenant index namespace, provider roles and tenant credentials | `bash scripts/test-elasticsearch-tenant-isolation.sh` and `bash scripts/test-opensearch-tenant-isolation.sh` |

## Cloud-to-Engine lifecycle

1. Register the existing database in **Dashboard → Databases** with its provider, endpoint, environment and protected credentials.
2. Enroll the customer-hosted Engine node and confirm its signed heartbeat.
3. Assign the database target to a node that advertises the provider runtime.
4. Create a tenant binding with the provider-specific namespace and identity reference.
5. Cloud advances the desired configuration revision and delivers signed, encrypted, node-bound configuration.
6. The Engine supervisor dispatches the assignment to the matching gateway or native provider runtime.
7. The runtime activates the listener or provider authorization lifecycle, verifies configured identities and records tenant-binding evidence.
8. The Engine acknowledges the applied revision and runtime state to Cloud. The workspace exposes the target, binding, node and verification state.

## Build and local verification

Run from the repository root:

```bash
cargo fmt --all -- --check
cargo check --workspace --all-targets
cargo test --workspace --all-targets
cargo build --workspace --bins --release
```

Run the provider acceptance command in the matrix against its dedicated disposable service or test account. The scripts create isolated tenant fixtures, exercise tenant-local operations, verify cross-tenant denial and clean up their test resources.

## Runtime configuration

Provider configuration is delivered through the authenticated Cloud assignment. The Engine validates the provider key, runtime name, configuration revision, tenant-binding coverage and required TLS or cloud identity settings before applying it. Gateway registries and provider credentials are written to the Engine's private runtime directory with restrictive file permissions.

- Network gateways use their provider-specific listener, identity registry and verified upstream connection.
- Native providers use the database's schema, role, IAM, keyspace, index or file authorization model.
- Credential rotation advances the desired revision and is reconciled by the assigned Engine.
- Revoked bindings are processed by the matching runtime and represented in applied-state evidence.

## Developer entry points

- [Engine quickstart](QUICKSTART.md)
- [Provider setup guides](README.md#provider-guides)
- [Cloud database API](https://github.com/Agata-Proxima/Agata-proxima/blob/main/docs/cloud-multi-database-api.md)
- [Cloud integration starter kit and JavaScript SDK](https://github.com/Agata-Proxima/Agata-proxima/tree/main/download-kit)
- [Agata CLI](https://agataproxima.com/developers/cli)
