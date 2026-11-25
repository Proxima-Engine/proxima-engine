# Proxima Engine documentation

Use this index to go directly to the task you need to complete.

## Get running

- [Repository README](../README.md) — clone, configure, build and start the Engine.
- [PostgreSQL quickstart](QUICKSTART.md) — local profile, SQL connection and health checks.
- [Customer deployment](DEPLOYMENT.md) — Docker Compose, network access, TLS and persistent data.
- [Node enrollment](NODE_ENROLLMENT.md) — Windows and Linux installation, node identity and secure enrollment.
- [Configuration](CONFIGURATION.md) — environment variables, runtime paths and validation.
- [Operations](OPERATIONS.md) — health, logs, monitoring and recovery.

## Database integrations

| Database | Runtime model | Guide |
|---|---|---|
| PostgreSQL | PostgreSQL wire gateway, tenant roles and RLS | [Guide](POSTGRESQL.md) |
| MySQL | MySQL protocol gateway and tenant identities | [Guide](MYSQL.md) |
| MariaDB | MySQL-compatible gateway and MariaDB tenant controls | [Guide](MARIADB.md) |
| CockroachDB | PostgreSQL wire compatibility and native tenant roles/RLS | [Guide](COCKROACHDB_COMPATIBILITY.md) |
| MongoDB | OP_MSG gateway, SCRAM-SHA-256 and database-per-tenant binding | [Guide](MONGODB_TENANT_ISOLATION.md) |
| Redis | RESP2 TLS gateway, key namespace enforcement and Redis ACLs | [Guide](REDIS_TENANT_GATEWAY.md) |
| Microsoft SQL Server | TDS 7.4 gateway, LOGIN7 assignment and verified upstream TLS | [Guide](SQLSERVER_NATIVE_TENANCY.md) |
| SQLite | Embedded database file per tenant | [Guide](SQLITE_TENANCY.md) |
| Oracle Database | Schema-per-tenant native provider | [Guide](ORACLE_TENANCY.md) |
| Amazon DynamoDB | IAM tenant partition-key policy | [Guide](DYNAMODB_TENANCY.md) |
| Apache Cassandra | Keyspace-per-tenant roles and grants | [Guide](CASSANDRA_TENANCY.md) |
| Elasticsearch / OpenSearch | Native role and tenant index authorization | [Guide](ELASTICSEARCH_TENANCY.md) |

## Architecture and security

- [Architecture](ARCHITECTURE.md)
- [Tenant isolation](TENANT_ISOLATION.md)
- [Security architecture](SECURITY.md)
- [Cloud-to-Engine runtime lifecycle](CLOUD_ENGINE_RUNTIME_LIFECYCLE.md)
- [Node enrollment and trust](NODE_ENROLLMENT.md)
- [Gateway authentication](MYSQL_GATEWAY_AUTH.md)

## Build applications

- [PostgreSQL driver integration](INTEGRATIONS.md) — Node.js, Python, Rust and psql examples.
- [Engine CLI](CLI.md) — node bootstrap, token and diagnostic commands.
- [Customer deployment executor](CUSTOMER_DEPLOYMENT_EXECUTOR.md)
- [Cloud API client, CLI and starter kit](https://agataproxima.com/developers/downloads)

## Test and verify

- [Provider verification commands](VERIFICATION.md)
- [Database production verification](DATABASE_PRODUCTION_VERIFICATION.md)
- [Engineering validation case study](ENGINEERING_CASE_STUDY.md)
- [Security demo](DEVELOPER_SECURITY_DEMO.md)

## Operate

- [API, health and metrics](API.md)
- [Operations runbook](OPERATIONS.md)
- [Container deployment](DEPLOYMENT.md)
- [Kubernetes gateway chart](../deploy/kubernetes/helm/proxima-gateways/README.md)

## Project resources

- [Agata Proxima](https://agataproxima.com)
- [Engine repository](https://github.com/Proxima-Engine/proxima-engine)
- [Cloud repository](https://github.com/Agata-Proxima/Agata-proxima)
- [Issues](https://github.com/Proxima-Engine/proxima-engine/issues)
- [Actions](https://github.com/Proxima-Engine/proxima-engine/actions)
