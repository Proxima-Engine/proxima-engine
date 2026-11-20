<p align="center">
  <img src="frontend/src/assets/agata-proxima-orbit.svg" alt="Agata Proxima orbit logo" width="112">
</p>

<h1 align="center">Agata Proxima · Proxima Engine</h1>
<p align="center"><strong>Database protocol gateways and tenant isolation enforced at the connection boundary.</strong></p>
<p align="center">
  <a href="https://github.com/Proxima-Engine/proxima-engine/actions/workflows/ci.yml"><img alt="Rust CI" src="https://github.com/Proxima-Engine/proxima-engine/actions/workflows/ci.yml/badge.svg?branch=main"></a>
  <a href="LICENSE"><img alt="MIT License" src="https://img.shields.io/badge/license-MIT-blue.svg"></a>
</p>
<p align="center"><a href="https://agataproxima.com">Website</a> · <a href="docs/README.md">Documentation</a> · <a href="https://github.com/Proxima-Engine/proxima-engine/issues">Issues</a> · <a href="https://discord.gg/xsYSuDMzg">Discord</a></p>

## Watch the PostgreSQL engineering demonstration

The original PostgreSQL walkthrough is part of the project documentation and remains available. It demonstrates tenant-bound PostgreSQL sessions, PgBouncer transaction pooling, deliberate RLS misconfiguration tests, signed-token validation, and recovery.

**[Watch the PostgreSQL tenant-isolation demonstration](https://github.com/user-attachments/assets/bca488eb-829c-4672-bbe9-b25878e5401c)** · [Read the engineering case study](docs/ENGINEERING_CASE_STUDY.md) · [Review recorded validation evidence](evidence/engineering-validation-2026-11-09.md)



Proxima Engine is the open-source Rust data plane in Agata Proxima. It provides protocol-aware database gateways, immutable tenant-to-session binding, upstream identity validation, conservative SQL admission, connection controls and repeatable integration tests. It places tenant enforcement between an application and its database—not inside application conventions alone.

## Database gateway status

| Database | Implementation | Verification |
|---|---|---|
| PostgreSQL | PostgreSQL wire-protocol Engine | PostgreSQL integration and tenant-isolation tests; PgBouncer transaction-pooling evidence |
| MySQL 8 | MySQL-compatible protocol gateway | Real MySQL 8 integration test in CI: tenant separation, prepared statements and invalid-password rejection |
| MariaDB | Same MySQL-compatible protocol gateway | Real MariaDB integration test in CI: tenant separation, prepared statements and invalid-password rejection |
| MongoDB | Separate development workstream | Policy and RBAC foundations; not part of the supported gateway matrix |

MySQL 8 and MariaDB are independently exercised by the integration workflow. The MySQL gateway has its own listener, identity registry and tenant-specific upstream connection path; it is not enabled by the PostgreSQL Compose profile.

**Scope:** PostgreSQL and MySQL-compatible gateways are separate protocol implementations. Their configuration, authentication, database controls and integration tests are database-specific. One database's test results do not verify another database.

## Architecture

~~~mermaid
flowchart LR
  A["Application"] -->|"native database protocol"| G["Proxima gateway"]
  G --> I["Client authentication"]
  I --> T["Immutable tenant session"]
  T --> P["Protocol and SQL admission"]
  P --> U["Tenant-specific upstream credentials"]
  U --> D[("PostgreSQL / MySQL / MariaDB")]
  D --> R["Database-native grants"]
  G --> M["Metrics and operational signals"]
~~~

Database-native privileges remain mandatory. Each tenant must use a dedicated least-privilege upstream identity. SQL admission narrows accepted operations; it does not replace database authorization.

## Quickstart: clone and run PostgreSQL

### Requirements
- Git
- Docker Desktop with Docker Compose v2, or Docker Engine and the Compose plugin
- curl for health checks
- Optional: stable Rust/Cargo and psql

### 1. Clone

~~~bash
git clone https://github.com/Proxima-Engine/proxima-engine.git
cd proxima-engine
~~~

### 2. Start the local stack

~~~bash
docker compose -f compose.dev.yaml up --build -d
~~~

The development profile starts PostgreSQL, PgBouncer in transaction-pooling mode and Proxima Engine. Published ports bind to host loopback:

| Service | Host address | Purpose |
|---|---|---|
| PostgreSQL gateway | 127.0.0.1:6432 | Application connections |
| Status dashboard | 127.0.0.1:9080 | Local status |
| Health and Prometheus metrics | 127.0.0.1:9090 | Health and metrics |
| PostgreSQL | 127.0.0.1:5432 | Development database |
| PgBouncer | 127.0.0.1:16432 | Transaction-pooling path |

### 3. Verify health and query through Proxima

~~~bash
curl -fsS http://127.0.0.1:9090/healthz
curl -fsS http://127.0.0.1:9080/api/status
docker compose -f compose.dev.yaml exec postgres psql "host=engine port=6432 dbname=appdb user=proxima password=local-only-change-me sslmode=disable" -c "SELECT current_user, current_database();"
~~~

PowerShell:

~~~powershell
Invoke-RestMethod http://127.0.0.1:9090/healthz
Invoke-RestMethod http://127.0.0.1:9080/api/status
~~~

The local credentials are disposable development credentials. Replace them before using any non-disposable environment.

### 4. Inspect metrics and stop

~~~bash
curl -fsS http://127.0.0.1:9090/metrics
docker compose -f compose.dev.yaml down
~~~

Delete local database data only when intended:

~~~bash
docker compose -f compose.dev.yaml down -v
~~~

Continue with [Tenant isolation](docs/TENANT_ISOLATION.md) for tenant roles, signed context, PostgreSQL grants and Row-Level Security.

## MySQL 8 and MariaDB gateway

The MySQL-compatible gateway is a separate executable. Its default listener is 127.0.0.1:3307. It loads client identities from a JSON registry. Each authenticated client is bound to one immutable tenant principal and one dedicated upstream connection. Before accepting the session, the gateway validates that the live upstream database matches the registry assignment.

~~~mermaid
flowchart TD
  C["MySQL or MariaDB client"] --> L["Proxima MySQL listener"]
  L --> A["Authenticate client"]
  A --> B["Resolve tenant principal"]
  B --> S["Bind immutable session"]
  S --> Q["SQL AST admission"]
  Q --> U["Tenant-specific upstream"]
  U --> DB[("MySQL 8 or MariaDB")]
~~~

The initial admission policy accepts one parsed statement at a time: SELECT, INSERT, UPDATE or DELETE. It rejects unsupported statements, multi-statements, database switching, cross-database qualified relations, system-schema references and selected privileged or resource-intensive functions. Database grants remain the authorization boundary.

Build and start the gateway:

~~~bash
cargo build --release -p proxima-engine --bin proxima-mysql-gateway
export PROXIMA_MYSQL_IDENTITY_REGISTRY=./secrets/mysql-identities.json
export PROXIMA_MYSQL_LISTEN_ADDR=127.0.0.1:3307
RUST_LOG=info ./target/release/proxima-mysql-gateway
~~~

PowerShell:

~~~powershell
cargo build --release -p proxima-engine --bin proxima-mysql-gateway
$env:PROXIMA_MYSQL_IDENTITY_REGISTRY = ".\secrets\mysql-identities.json"
$env:PROXIMA_MYSQL_LISTEN_ADDR = "127.0.0.1:3307"
$env:RUST_LOG = "info"
.\target\release\proxima-mysql-gateway.exe
~~~

The registry contains client password verifiers and tenant-specific upstream URLs. Keep it outside version control, restrict file permissions and inject it through a secret-management process. Never commit it or package it into a public image.

Follow the complete [MySQL 8 and MariaDB gateway guide](docs/MYSQL_MARIADB.md) for database provisioning, verifier generation, least-privilege grants, registry configuration, client connection examples, TLS and integration verification.

## Security model

- **Immutable tenant binding:** each authenticated client session is bound once to its configured tenant principal.
- **Separate upstream identities:** every tenant uses its own upstream database account and selected database.
- **Live upstream validation:** the selected database is checked against the registry before authentication succeeds.
- **Client authentication:** caching_sha2_password with a double-SHA-256 verifier; legacy mysql_native_password with a SHA-1 verifier.
- **Constant-time verifier comparison:** fixed-size verifier bytes are compared without early-exit byte comparison.
- **Fail-closed SQL admission:** malformed, multi-statement, unsupported and prohibited SQL is rejected before upstream execution.
- **Bounded resources:** connection limits and upstream connection/query deadlines.
- **Remote TLS requirement:** non-loopback MySQL upstreams must use verified TLS.
- **Database-native authorization:** provision least-privilege grants for each tenant. Never share privileged upstream accounts.

Read [Security](docs/SECURITY.md), [MySQL authentication](docs/MYSQL_GATEWAY_AUTH.md) and [Deployment](docs/DEPLOYMENT.md) before connecting sensitive workloads.

## Build and verify

~~~bash
cargo fmt --all -- --check
cargo check --workspace --all-targets
cargo test --workspace --all-targets
cargo clippy --workspace --all-targets --all-features -- -D warnings
~~~

The real MySQL 8 and MariaDB integration suites require disposable database services, client utilities, fixtures and a running gateway. GitHub Actions provisions those dependencies and runs both suites. The ignored test targets are:

~~~bash
cargo test -p proxima-engine --test mysql_gateway_integration -- --ignored --test-threads=1
cargo test -p proxima-engine --test mariadb_gateway_integration -- --ignored --test-threads=1
~~~

See [MySQL and MariaDB integration verification](docs/MYSQL_MARIADB.md#integration-verification) for the required fixture lifecycle.

## Repository map

| Path | Responsibility |
|---|---|
| crates/proxima-engine/src/ | Rust engine, protocol gateways, identity, policy and session logic |
| crates/proxima-engine/src/bin/ | Standalone gateway executables |
| crates/proxima-engine/tests/ | Real-database integration tests |
| dashboard/ | Local Engine dashboard |
| compose.dev.yaml | Disposable PostgreSQL development stack |
| scripts/ | Integration and CI helpers |
| docs/ | Architecture, configuration, deployment, security and database guides |
| vendor/opensrv-mysql/ | Vendored MySQL protocol implementation and license notices |

## Contribute

1. Create a focused feature branch.
2. Add tests for both permitted and denied behavior.
3. Run formatting, compilation, unit tests and the relevant real-database integration suite.
4. Update the relevant documentation and configuration examples.
5. Open a pull request with database versions, environment details and test results.

Use [GitHub Issues](https://github.com/Proxima-Engine/proxima-engine/issues) for reproducible defects and feature requests. Report vulnerabilities through [SECURITY.md](SECURITY.md), not a public issue.

## Project links

- [Agata Proxima website](https://agataproxima.com)
- [Source code](https://github.com/Proxima-Engine/proxima-engine)
- [CI workflows](https://github.com/Proxima-Engine/proxima-engine/actions)
- [Issues](https://github.com/Proxima-Engine/proxima-engine/issues)
- [Pull requests](https://github.com/Proxima-Engine/proxima-engine/pulls)
- [Releases](https://github.com/Proxima-Engine/proxima-engine/releases)
- [Discord](https://discord.gg/xsYSuDMzg)

## License

Proxima Engine is distributed under the [MIT License](LICENSE) for the source and materials covered by that license. Hosted services, private control-plane source and reserved brand assets are separate; see [Copyright and brand](COPYRIGHT.md).
