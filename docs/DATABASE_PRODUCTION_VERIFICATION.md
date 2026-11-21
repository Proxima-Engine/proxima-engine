# Database Production Verification System

## Purpose

Provide one repeatable, terminal-driven verification entry point for every supported Proxima database integration. The runner must use disposable database services and real client traffic through the Proxima gateway. It must not point at production customer databases or use production credentials.

A consolidated run is a test orchestrator, not a universal certification. Each adapter retains a database-specific acceptance suite and version-specific support declaration.

## Operator experience

The intended interface is:

    ./scripts/verify-all-databases.sh
    ./scripts/verify-all-databases.sh --database postgres
    ./scripts/verify-all-databases.sh --database mysql
    ./scripts/verify-all-databases.sh --database mariadb
    ./scripts/verify-all-databases.sh --database cockroach
    ./scripts/verify-all-databases.sh --database mongodb
    ./scripts/verify-all-databases.sh --database sqlserver
    ./scripts/verify-all-databases.sh --database redis
    ./scripts/verify-all-databases.sh --database redis --no-start
    ./scripts/verify-all-databases.sh --keep

The exact flags may change during implementation, but the one-command and per-database workflows are required.

## Execution stages

1. Validate Docker/Compose, required client binaries, free ports, disk space, and required environment configuration.
2. Create an isolated Compose project name and disposable volumes/network. Never reuse a developer's default database volumes.
3. Start only the selected services, or all supported services for the complete run.
4. Wait for real database readiness using each vendor's native health command, not a fixed sleep.
5. Record exact database image tags, server versions, Engine commit SHA, Rust toolchain, OS, and test configuration.
6. Provision two or more tenant identities with least-privilege upstream principals and independent canary data.
7. Start the matching Proxima gateway and wait for its health/readiness signal.
8. Run positive tests, cross-tenant negative tests, authentication failures, protocol malformed-input tests, lifecycle tests, concurrency tests, and database-native policy checks.
9. Capture test stdout/stderr, gateway logs, database logs, image digests, timing, and exit codes. Redact credentials and tenant data.
10. Generate machine-readable JSON plus a human-readable Markdown summary.
11. Tear down the isolated Compose project and volumes by default. Preserve them only when explicitly requested.

## Database-specific suites

| Database | Real service | Required acceptance coverage |
|---|---|---|
| PostgreSQL | Supported pinned PostgreSQL image | Signed tenant context, role routing, RLS, cross-tenant read/write denial, pooling, token expiry and recovery |
| CockroachDB | Supported pinned CockroachDB 25.2 image | PostgreSQL wire compatibility, tenant roles, forced RLS, transaction retry and isolation |
| MySQL | Supported pinned MySQL 8 image | Identity registry, dedicated upstream accounts, database binding, prepared statements and cross-tenant denial |
| MariaDB | Supported pinned MariaDB 11.4 image | Separate MariaDB compatibility run, auth behavior, prepared statements and cross-tenant denial |
| MongoDB | Supported pinned MongoDB 8 image | SCRAM, TLS, OP_MSG command allowlist, database-per-tenant isolation, unsupported-command rejection |
| SQL Server | Supported pinned SQL Server Linux image | TDS/TLS/login compatibility, tenant principals, RLS, cross-tenant denial, prepared/RPC/transaction scope and session isolation |
| Redis | Supported pinned Redis image with ACL support | RESP framing, tenant key namespace, native ACLs, multi-key validation, command deny-list, pipelining and session binding |
| SQLite | Bundled SQLite library and isolated temporary filesystem root | Separate tenant database files, tenant-ID validation, path traversal and symlink rejection, owner-only permissions, WAL and independent tenant data |
| Oracle Database | Disposable Oracle Free 23 container | Dedicated schema owners, tenant-local DDL and CRUD, cross-schema read denial, no DBA role activation, and restricted grants |
| DynamoDB | Real AWS account and isolated test table | IAM `dynamodb:LeadingKeys` for exact tenant partition keys; run `scripts/test-dynamodb-leading-keys-aws.sh` to verify own-partition success, cross-tenant GetItem/Query denial and Scan denial; DynamoDB Local is not sufficient IAM evidence |
| Apache Cassandra | Pinned disposable Cassandra cluster with authentication enabled | Separate keyspace and login role per tenant, SELECT/MODIFY-only privileges, cross-keyspace denial, credential rotation/revocation and TLS; execute generated CQL through a separate admin session |
| Elasticsearch | Pinned Elasticsearch cluster with the exact security feature entitlement | Dedicated index namespace, role and API key per tenant; DLS/FLS where supported; test aliases, data streams, bulk, reindex, aggregations and forbidden cluster privileges |
| OpenSearch | Pinned OpenSearch cluster with Security plugin enabled | Separate Security-plugin role/backend-role path; index namespace, DLS/FLS where supported; run `scripts/test-opensearch-tenant-isolation.sh` and independently test aliases, data streams, bulk, reindex, aggregations and forbidden cluster privileges |

The runner must clearly distinguish PASS, FAIL, SKIP, and NOT_IMPLEMENTED. A not-yet-implemented database must never be silently counted as a pass.

## Isolation attack cases

Every gateway suite should attempt at least:
- Tenant A reading, writing, deleting, or enumerating Tenant B's data.
- Tenant B performing the symmetric attack.
- Cross-tenant multi-object operations and alternate command/query forms.
- Database/keyspace switching or identity rebinding after authentication.
- Invalid, missing, revoked, expired, malformed, and replayed credentials where applicable.
- Prepared statements, stored procedures, scripts, transactions, pipelines, or other alternate execution paths within the declared support boundary.
- Malformed, oversized, fragmented, and pipelined protocol frames.
- Reconnect, timeout, cancellation, pool reuse, gateway restart, and concurrent-client races.
- Attempts to use administrative or introspection features to bypass tenant boundaries.

Each negative test must assert both that the request is denied and that the denied request did not mutate or disclose another tenant's data.

## Evidence report schema

The JSON report should include:
- Run ID and UTC timestamps.
- Repository commit SHA and dirty/clean source state.
- OS, architecture, Docker/Compose and Rust versions.
- Database image tags, digests, and server version strings.
- Gateway binary/version and configuration profile (secrets omitted).
- Per-suite and per-case status, duration, and failure reason.
- Positive and negative test counts.
- Service health transitions and exit codes.
- Artifact paths for redacted logs and test output.
- Explicit exclusions, unsupported features, skipped checks, and known limitations.

The Markdown report should summarize the same facts and link to the detailed logs. Reports must not contain passwords, bearer tokens, connection strings with credentials, raw customer data, or secret registry contents.

## CI policy

- Keep a single orchestrated workflow entry point, but separate jobs or matrix entries may run databases in parallel where resource limits allow.
- Pin database image major/minor versions deliberately; do not silently float production verification on latest.
- Use ephemeral service containers and unique test credentials.
- Run the full database matrix on pull requests affecting gateway, policy, identity, deployment, or shared protocol code, and on scheduled main-branch verification.
- Preserve the existing PostgreSQL, CockroachDB, MySQL, MariaDB, MongoDB and PgBouncer checks.
- Add SQL Server, Redis, Cassandra, DynamoDB, Elasticsearch and OpenSearch to the matrix only after their provider-specific real-service suites exist; do not count helper-only checks as provider acceptance.
- Fail CI if a database marked implemented has no acceptance suite, or if an expected suite is skipped.
- Keep build-only and mock-only tests separate from real-server acceptance results.

## Production confidence levels

The report should classify evidence rather than emit an unqualified production-ready label:

- Build verified: compiles and packages.
- Protocol verified: supported client protocol paths pass real-client tests.
- Isolation verified: adversarial tenant boundary tests pass against a real database.
- Operationally verified: TLS, limits, timeouts, concurrency, recovery, and observability checks pass.
- Release candidate verified: all required checks pass for the documented database versions and deployment profile.
- Production deployed/observed: a real deployment has operational monitoring, incident procedures, upgrade/rollback evidence, and a defined support window.

A local or CI run can establish the first five levels within its tested scope. It cannot by itself prove that every possible customer workload or production topology is safe.

## Current implementation state

This document specifies the target verification system. The unified all-database runner remains a separate follow-up. Per-database scripts and CI checks are authoritative. DynamoDB AWS IAM and Elasticsearch/OpenSearch cluster acceptance are external provider gates until their live-service suites and provisioning executors are implemented. SQLite isolation is exercised by the Rust unit suite; Oracle isolation is exercised against a disposable Oracle Free 23 instance by scripts/test-oracle-tenant-isolation-ci.sh. A green run establishes only the documented profile and tested version, not universal production certification.
