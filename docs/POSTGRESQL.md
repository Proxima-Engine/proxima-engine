# PostgreSQL documentation

PostgreSQL is the reference database integration for Proxima Engine. This guide is the entry point to the complete PostgreSQL implementation, from a disposable local stack through tenant-role provisioning, signed tenant context, Row-Level Security, PgBouncer transaction pooling, application drivers, deployment and verification.

The PostgreSQL listener speaks the PostgreSQL wire protocol. Existing PostgreSQL clients and drivers connect to the Engine endpoint; the Engine validates tenant context and selects the tenant-specific upstream PostgreSQL role. PostgreSQL grants and Row-Level Security remain the database-native authorization layer.

## Start with the complete quickstart

1. [Clone the repository and launch the PostgreSQL + PgBouncer + Proxima Engine stack](QUICKSTART.md).
2. [Create tenant roles, configure signed tenant context and enable Row-Level Security](TENANT_ISOLATION.md).
3. [Connect an existing application using psql, Node.js, Python or Rust](INTEGRATIONS.md).
4. [Review the architecture and request lifecycle](ARCHITECTURE.md).
5. [Configure production networking, TLS, persistence and deployment](DEPLOYMENT.md).
6. [Run the verification workflow and inspect the recorded evidence](VERIFICATION.md).

## PostgreSQL implementation guides

| Guide | What it covers |
|---|---|
| [Quickstart](QUICKSTART.md) | Docker Compose, PostgreSQL, PgBouncer, Engine startup, SQL query, health checks, metrics and troubleshooting |
| [Tenant isolation](TENANT_ISOLATION.md) | Tenant roles, grants, signed context, RLS policies, positive and negative access tests |
| [Architecture](ARCHITECTURE.md) | PostgreSQL wire protocol, authentication, session lifecycle, role routing, pooling and module map |
| [Driver integrations](INTEGRATIONS.md) | psql, Node.js, Python Psycopg and Rust tokio-postgres |
| [Configuration](CONFIGURATION.md) | Listener, upstream, TLS, tenant signing, node identity and operational environment variables |
| [API and metrics](API.md) | PostgreSQL connection endpoint, health/status routes and Prometheus metrics |
| [Deployment](DEPLOYMENT.md) | Container build, network topology, TLS, persistence and deployment acceptance |
| [Operations](OPERATIONS.md) | Logs, health, metrics, restart, recovery and troubleshooting |
| [Security](SECURITY.md) | Implemented controls, threat boundaries and production configuration |
| [Verification](VERIFICATION.md) | Rust tests, PostgreSQL integration, two-tenant acceptance, PgBouncer and evidence review |

## PostgreSQL engineering demonstration and evidence

The original [Zero-Trust Tenant Isolation in Action demonstration](https://github.com/user-attachments/assets/bca488eb-829c-4672-bbe9-b25878e5401c) remains the primary recorded walkthrough.

- [Engineering case study](ENGINEERING_CASE_STUDY.md) — PgBouncer transaction pooling, deliberate RLS misconfiguration, 1,000 tenant identities, signed-token validation and Engine recovery.
- [Developer security walkthrough](DEVELOPER_SECURITY_DEMO.md) — reproduce positive and negative tenant-access scenarios.
- [PgBouncer transaction-pooling evidence](../evidence/pgbouncer-transaction-pooling.txt).
- [Recorded engineering validation](../evidence/engineering-validation-2026-11-09.md).

## PostgreSQL security model

PostgreSQL isolation uses multiple controls that must be configured together:

- The trusted application backend authenticates the caller and authorizes organization/tenant membership.
- The backend issues a short-lived signed tenant token.
- Proxima Engine validates token format, tenant identity, expiry and HMAC signature when enforcement is enabled.
- The Engine maps the verified tenant to its dedicated upstream PostgreSQL role.
- PostgreSQL grants restrict the role's object privileges.
- Row-Level Security restricts which tenant rows the role can read or modify.
- Connection pools preserve tenant identity; a physical connection is never retargeted from one tenant to another.

A successful health check is not proof of tenant isolation. Run the real PostgreSQL acceptance tests and verify both permitted tenant-local operations and denied cross-tenant reads/writes.

## Relationship to other database guides

MySQL and MariaDB have independent guides and integration suites. They use the MySQL-compatible listener and do not use PostgreSQL roles or PostgreSQL Row-Level Security. Start at [MySQL](MYSQL.md) or [MariaDB](MARIADB.md) for their respective setup and verification paths.
