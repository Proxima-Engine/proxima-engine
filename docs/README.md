# Proxima Engine documentation

- [Cloud-to-Engine runtime reconciliation](CLOUD_ENGINE_RUNTIME_LIFECYCLE.md)

The Proxima Engine documentation covers the Rust data plane, database protocol gateways, tenant identity, security controls, deployment and integration verification.

## Start here

- **[Repository README](../README.md)** — product scope, database gateway matrix, architecture, clone instructions and quickstarts.
- **[PostgreSQL documentation hub](POSTGRESQL.md)** — complete reference-database guide and navigation for setup, tenant isolation, drivers, deployment and evidence.
- **[PostgreSQL quickstart](QUICKSTART.md)** — launch PostgreSQL and Proxima Engine, run SQL and inspect health and metrics.
- **[MySQL documentation](MYSQL.md)** — provision MySQL tenant databases, configure client verifiers, connect clients and run the MySQL 8.0 integration suite.
- **[MariaDB documentation](MARIADB.md)** — provision MariaDB tenant databases, configure client identities, connect clients and run the MariaDB 11.4 integration suite.
- **[CockroachDB compatibility](COCKROACHDB_COMPATIBILITY.md)** — CockroachDB 25.2+ using the PostgreSQL wire gateway, native RLS, tenant roles and transaction retry behavior.
- **[MongoDB tenant isolation](MONGODB_TENANT_ISOLATION.md)** — restricted MongoDB 8 OP_MSG gateway, SCRAM-SHA-256, TLS, tenant database binding, opt-in customer Compose profile and feature limitations.
- [SQL Server native tenant isolation](SQLSERVER_NATIVE_TENANCY.md) — dedicated database and least-privilege login per tenant; explicitly not a TDS proxy.
- [Redis tenant gateway](REDIS_TENANT_GATEWAY.md) — restricted RESP2 TLS gateway, client identity binding, key namespace enforcement and Redis ACL configuration.
- [SQLite tenant isolation](SQLITE_TENANCY.md) — embedded database-file-per-tenant storage, path safety and operating-system permissions.
- [Oracle tenant isolation](ORACLE_TENANCY.md) — dedicated schema owners, bounded quota and least-privilege provisioning.
- [DynamoDB tenant isolation](DYNAMODB_TENANCY.md) — AWS-native IAM `LeadingKeys` policy construction with exact table ARN validation; real AWS IAM acceptance is separate.
- [Cassandra tenant isolation](CASSANDRA_TENANCY.md) — native keyspace-per-tenant authentication and least-privilege role provisioning.
- [Elasticsearch and OpenSearch tenant isolation](ELASTICSEARCH_TENANCY.md) — native roles, index namespaces, DLS/FLS constraints and separate distribution acceptance.
- [SQL Server and Redis implementation plan](SQLSERVER_REDIS_IMPLEMENTATION_PLAN.md) — protocol feasibility decisions, security boundaries and acceptance criteria.
- [Database production verification system](DATABASE_PRODUCTION_VERIFICATION.md) — target one-command real-database test runner, per-database acceptance suites, evidence reporting and production-confidence levels.
- [Shared MySQL protocol authentication](MYSQL_GATEWAY_AUTH.md) — verifier formats and authentication behavior.
- [Architecture](ARCHITECTURE.md) — request lifecycle, tenant identity, role routing and system boundaries.
- [Tenant isolation](TENANT_ISOLATION.md) — tenant roles, RLS, signed context and positive/negative access tests.
- [Engineering case study](ENGINEERING_CASE_STUDY.md) — PgBouncer, RLS, 1,000-identity, signed-token and recovery validation.
- [Developer security walkthrough](DEVELOPER_SECURITY_DEMO.md) — reproduce tenant-access scenarios and review recorded evidence.
- [Local developer mode](LOCAL_DEVELOPMENT.md) — local node identity and signed test tokens.
- [Engine CLI](CLI.md) — bootstrap, token generation, diagnostics and local status commands.

## Database integrations and native security profiles

| Database | Guide | Implementation |
|---|---|---|
| PostgreSQL | [Documentation hub](POSTGRESQL.md), [quickstart](QUICKSTART.md), [tenant isolation](TENANT_ISOLATION.md), [driver integrations](INTEGRATIONS.md) | PostgreSQL wire-protocol Engine |
| MySQL | [Dedicated guide](MYSQL.md), [authentication](MYSQL_GATEWAY_AUTH.md) | proxima-mysql-gateway; MySQL 8.0 integration suite in CI |
| MariaDB | [Dedicated guide](MARIADB.md), [authentication](MYSQL_GATEWAY_AUTH.md) | MySQL-compatible client protocol gateway |
| CockroachDB 25.2+ | [Compatibility profile](COCKROACHDB_COMPATIBILITY.md) | PostgreSQL wire gateway with CockroachDB-native forced RLS and tenant-role acceptance test |
| MongoDB 8 | [Restricted gateway guide](MONGODB_TENANT_ISOLATION.md) | Separate OP_MSG gateway; SCRAM-SHA-256, TLS, database-per-tenant isolation; restricted preview, not full feature parity |
| SQL Server | [Native tenant isolation](SQLSERVER_NATIVE_TENANCY.md) | Native database-per-tenant profile with dedicated SQL login; no Proxima TDS proxy or shared-database RLS gateway |
| Redis | [Tenant gateway](REDIS_TENANT_GATEWAY.md) | Restricted RESP2 TLS gateway with immutable tenant sessions, namespace rewriting and upstream Redis ACL users; limited command compatibility |
| SQLite | [Tenant isolation](SQLITE_TENANCY.md) | Native embedded storage; separate SQLite file per tenant with path and filesystem protections |
| Oracle Database | [Tenant isolation](ORACLE_TENANCY.md) | Native schema-per-tenant profile with dedicated users and least-privilege grants |
| Amazon DynamoDB | [Tenant isolation](DYNAMODB_TENANCY.md) | AWS-native IAM `dynamodb:LeadingKeys`; not a Proxima protocol gateway |
| Apache Cassandra | [Tenant isolation](CASSANDRA_TENANCY.md) | Native keyspace-per-tenant roles and grants; not a CQL proxy |
| Elasticsearch / OpenSearch | [Tenant isolation](ELASTICSEARCH_TENANCY.md) | Native role/index authorization; DLS/FLS only where distribution/version/license supports it; separate adapters and acceptance required |

## Developer tools

- [Engine local-development CLI](CLI.md) — Python 3.10+ tool for local node identity, signed tenant test tokens, diagnostics and local Engine status. This is not the downloadable Cloud API CLI.
- [Cloud API CLI download](https://agataproxima.com/developers/cli) — separate Node.js 22+ read-only CLI for authenticated Cloud API health, identity and resource listings.
- [Integration starter kit](https://agataproxima.com/developers/downloads) — server-side JavaScript API client, Node example, CLI smoke scripts, webhook receiver, Supabase/Firebase examples, GitHub Actions/Vercel templates, Terraform check example and ChatGPT/MCP server example. The JavaScript client is bundled source, not a published npm SDK; the Terraform sample is not a dedicated provider.

## Integrate and operate

- [Configuration](CONFIGURATION.md) — environment variables, defaults and validation.
- [API, health and metrics](API.md) — PostgreSQL endpoint, local HTTP routes and Prometheus metrics.
- [Driver integration recipes](INTEGRATIONS.md) — psql, Node.js, Python and Rust.
- [Node identity and enrollment](NODE_ENROLLMENT.md) — node identity persistence and enrollment contract.
- [Container deployment](DEPLOYMENT.md) — image build, networking, TLS, persistence and deployment checklist.
- [Operations](OPERATIONS.md) — health checks, logs, monitoring, restart and recovery.
- [Verification](VERIFICATION.md) — automated tests, PostgreSQL, MySQL, MariaDB, CockroachDB, MongoDB, Redis, SQL Server and Cassandra acceptance checks; DynamoDB and Elasticsearch/OpenSearch helper tests remain distinct from live-provider acceptance, Docker image build, PgBouncer isolation and evidence verification.
- [Unified database verification target](DATABASE_PRODUCTION_VERIFICATION.md) — design for real-server tests across every supported database and consolidated JSON/Markdown evidence.
- [Engineering validation evidence](../evidence/engineering-validation-2026-11-09.md) — recorded validation outputs.

## Multi-database Cloud architecture

- [Database gateways in Agata Proxima Cloud](CLOUD_CONTROL_PLANE.md) — current PostgreSQL-oriented hosted contract, the current local MySQL/MariaDB Engine boundary, and the staged architecture for engine-aware database targets, gateway nodes, tenant bindings, policies, deployment and verification.

## Security and hosted product

- [Security architecture](SECURITY.md) — implemented controls and required runtime configuration.
- [MySQL gateway authentication](MYSQL_GATEWAY_AUTH.md) — caching SHA-2 and legacy native password verifier formats.
- [Hosted Cloud control plane](CLOUD_CONTROL_PLANE.md) — hosted organization workflows and Engine boundary.
- [Plans and billing](BILLING.md) — hosted plans, checkout, subscription and billing.
- [Support](SUPPORT.md) — contact routes, diagnostics and issue reporting.

## Contribute and project policies

- [Contributing](../CONTRIBUTING.md)
- [Security policy](../SECURITY.md)
- [Code of Conduct](../CODE_OF_CONDUCT.md)
- [Copyright and brand](../COPYRIGHT.md)
- [MIT License](../LICENSE)
- [Open-source scope](OPEN_SOURCE_SCOPE.md)

## External project resources

- [Agata Proxima website](https://agataproxima.com)
- [GitHub repository](https://github.com/Proxima-Engine/proxima-engine)
- [GitHub Actions](https://github.com/Proxima-Engine/proxima-engine/actions)
- [GitHub issues](https://github.com/Proxima-Engine/proxima-engine/issues)
- [GitHub pull requests](https://github.com/Proxima-Engine/proxima-engine/pulls)
- [GitHub releases](https://github.com/Proxima-Engine/proxima-engine/releases)
- [Discord community](https://discord.gg/xsYSuDMzg)

## Product boundary

Proxima Engine is independently buildable and testable. A compatible control plane can issue node-enrollment credentials and receive optional signed evidence. The hosted Agata Proxima Cloud application is separate; its private management source and hosted account workflows are not part of this repository.

## Customer installation packages

- [Registered-node installation guide](NODE_ENROLLMENT.md) — Windows PowerShell and Linux Bash installer, downloads, enrollment credentials, Docker networking, health verification and lifecycle operations.
- [Customer deployment executor](CUSTOMER_DEPLOYMENT_EXECUTOR.md) — signed deployment webhooks, executor credentials, approved releases, rollback and customer-managed operations.
- [Windows customer installer](../install-customer.ps1)
- [Linux customer installer](../install-customer.sh)
- [Customer Compose definition](../compose.customer.yaml)
