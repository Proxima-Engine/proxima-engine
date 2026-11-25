# Proxima Engine documentation

Use this index to go directly to the task you need to complete.

## Get running

- [Repository README](../README.md) — clone, configure, build and start the Engine.
- [PostgreSQL quickstart](QUICKSTART.md) — local PostgreSQL, SQL query, health and metrics.
- [MySQL quickstart](QUICKSTART-MYSQL.md)
- [MariaDB quickstart](QUICKSTART-MARIADB.md)
- [CockroachDB quickstart](QUICKSTART-COCKROACHDB.md)
- [MongoDB quickstart](QUICKSTART-MONGODB.md)
- [Redis quickstart](QUICKSTART-REDIS.md)
- [Microsoft SQL Server quickstart](QUICKSTART-SQLSERVER.md)
- [SQLite quickstart](QUICKSTART-SQLITE.md)
- [Oracle Database quickstart](QUICKSTART-ORACLE.md)
- [Amazon DynamoDB quickstart](QUICKSTART-DYNAMODB.md)
- [Apache Cassandra quickstart](QUICKSTART-CASSANDRA.md)
- [Elasticsearch / OpenSearch quickstart](QUICKSTART-ELASTICSEARCH.md)
- [Customer deployment](DEPLOYMENT.md) — Docker Compose, network access, TLS and persistent data.
- [Node enrollment](NODE_ENROLLMENT.md) — Windows and Linux installation, node identity and secure enrollment.
- [Configuration](CONFIGURATION.md) — environment variables, runtime paths and validation.
- [Operations](OPERATIONS.md) — health, logs, monitoring and recovery.

## Database integration guides

| Database | Runtime model | Full guide |
|---|---|---|
| PostgreSQL | PostgreSQL wire gateway, tenant roles and RLS | [PostgreSQL](POSTGRESQL.md) |
| MySQL | MySQL protocol gateway and tenant identities | [MySQL](MYSQL.md) |
| MariaDB | MySQL-compatible gateway and MariaDB tenant controls | [MariaDB](MARIADB.md) |
| CockroachDB | PostgreSQL wire compatibility and native tenant roles/RLS | [CockroachDB](COCKROACHDB_COMPATIBILITY.md) |
| MongoDB | OP_MSG gateway, SCRAM-SHA-256 and database-per-tenant binding | [MongoDB](MONGODB_TENANT_ISOLATION.md) |
| Redis | RESP2 TLS gateway, key namespace enforcement and Redis ACLs | [Redis](REDIS_TENANT_GATEWAY.md) |
| Microsoft SQL Server | TDS 7.4 gateway, LOGIN7 assignment and verified upstream TLS | [SQL Server](SQLSERVER_NATIVE_TENANCY.md) |
| SQLite | Embedded database file per tenant | [SQLite](SQLITE_TENANCY.md) |
| Oracle Database | Schema-per-tenant native provider | [Oracle](ORACLE_TENANCY.md) |
| Amazon DynamoDB | IAM tenant partition-key policy | [DynamoDB](DYNAMODB_TENANCY.md) |
| Apache Cassandra | Keyspace-per-tenant roles and grants | [Cassandra](CASSANDRA_TENANCY.md) |
| Elasticsearch / OpenSearch | Native role and tenant index authorization | [Elasticsearch / OpenSearch](ELASTICSEARCH_TENANCY.md) |

## Architecture and security

- [Multi-database architecture](ARCHITECTURE.md)
- [Tenant isolation](TENANT_ISOLATION.md)
- [Security architecture](SECURITY.md)
- [Cloud-to-Engine runtime lifecycle](CLOUD_ENGINE_RUNTIME_LIFECYCLE.md)
- [Node enrollment and trust](NODE_ENROLLMENT.md)
- [Gateway authentication](MYSQL_GATEWAY_AUTH.md)

## Build applications and tooling

- [PostgreSQL driver integration](INTEGRATIONS.md) — Node.js, Python, Rust and psql examples.
- [Engine CLI](CLI.md) — local node bootstrap, token and diagnostic commands.
- [Customer deployment executor](CUSTOMER_DEPLOYMENT_EXECUTOR.md)
- [Cloud SDK, CLI and downloads](https://agataproxima.com/developers/downloads) — public installation packages and guides.
- [Provider runtime and acceptance reference](PROVIDER_RUNTIME_REFERENCE.md) — provider runtime behavior and verification commands.

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
- [Issues](https://github.com/Proxima-Engine/proxima-engine/issues)
- [Actions](https://github.com/Proxima-Engine/proxima-engine/actions)
