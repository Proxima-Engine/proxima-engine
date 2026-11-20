# SQL Server and Redis integration contract

## Purpose and current status

This document defines the security boundary and verification scope for the SQL Server and Redis integrations. The integrations are intentionally different: SQL Server uses its native database and principal permissions, while Redis uses a protocol-aware RESP2 gateway and tenant key namespaces.

The implementation is in a review branch and is not production-certified until the full Rust CI workflow, real-server acceptance suites, and packaged-image checks pass. The README labels both integrations as preview.

## SQL Server: native database-per-tenant profile

### Architectural decision

SQL Server speaks TDS. The Rust protocol ecosystem reviewed for this implementation did not provide a maintained, production-ready TDS server that Proxima could safely embed. Tiberius is a client, while protocol parsers and mock servers are not production TDS servers. Proxima therefore does not claim to implement a SQL Server TDS proxy.

The supported preview profile is native SQL Server database-per-tenant isolation:

- Every tenant receives a dedicated SQL Server database and dedicated SQL login.
- The login's default database is its tenant database.
- The tenant login receives only SELECT, INSERT, UPDATE, and DELETE on the tenant's application schema.
- Tenant logins receive no server roles, db_owner, db_datareader, db_datawriter, schema ownership, or login-management permissions.
- VIEW ANY DATABASE and ALTER ANY LOGIN are denied to tenant logins.
- TRUSTWORTHY and cross-database ownership chaining remain disabled.
- Application connection pools are partitioned by tenant credential. A physical connection is never reused across tenant credentials.
- Applications do not add tenant IDs to SQL statements; the tenant-specific credential selects the database boundary.

The database and login provisioning identity is trusted infrastructure. Credential issuance and rotation must be performed by a trusted provisioning service and secrets manager. SQL Server TLS certificate validation is required for application connections.

This profile does not provide a Proxima TDS listener, Proxima gateway-side identity routing, shared-database RLS enforcement, or Proxima protocol telemetry. Customers requiring any of those capabilities need a separately designed and validated TDS gateway. Do not present this native profile as a wire-protocol proxy.

### Real-server verification

The SQL Server 2022 CI fixture provisions two isolated databases and two least-privilege logins. Its shell runner verifies per-tenant CRUD, cross-database read denial, database-switch denial, schema-creation denial, impersonation denial, and invalid credentials.

- Provisioning fixture: scripts/sqlserver-provision-two-tenants.sql
- Acceptance runner: scripts/test-sqlserver-tenant-isolation-ci.sh
- Customer deployment guide: docs/SQLSERVER_NATIVE_TENANCY.md

The fixture drops and recreates only its named CI databases and logins. It is for disposable test instances, not production provisioning.

## Redis: restricted RESP2 tenant gateway

### Architecture

The Redis integration is a dedicated gateway with a separate binary, listener, configuration namespace, identity registry, and upstream connection per authenticated client session.

1. Client connects using TLS.
2. Client authenticates with AUTH against the protected Proxima identity registry.
3. The gateway binds the connection to one immutable tenant principal.
4. The gateway derives an opaque tenant prefix from the trusted tenant identifier.
5. Every supported key-bearing command is parsed and every key argument is rewritten into that tenant namespace.
6. The gateway opens an upstream TLS connection, validates the upstream certificate, and authenticates as the tenant's dedicated Redis ACL user.
7. The upstream ACL independently restricts that user to the tenant key pattern and explicitly granted commands.

Logical Redis database numbers are not a tenant security boundary. Client-supplied prefixes are not trusted. Repeated AUTH, tenant switching, unknown commands, unsupported protocol frames, and malformed requests fail closed.

### Protocol and command surface

The initial implementation supports RESP2 arrays of bulk strings and a restricted allowlist of common string, hash, list, set, sorted-set, expiry, selected stream, and multi-key commands. The command key positions are encoded in redis_protocol.rs. The gateway handles PING, QUIT, and the narrow CLIENT SETINFO metadata handshake locally.

RESP3, inline commands, transactions, Lua/functions, Pub/Sub, blocking commands, cluster administration, keyspace scans, server administration, and unknown commands are not supported. Do not add a command without validating all key positions, including optional and variadic arguments, against the Redis command specification and adding negative tests.

The client identity registry stores a SHA-256 verifier for a high-entropy client password and the tenant's upstream ACL username/password. The registry is loaded at process startup; credential rotation requires updating the protected secret and restarting the gateway. Each tenant must map to a unique upstream Redis ACL user. Upstream TLS is mandatory and certificate validation is enabled.

### Real-server verification

The Redis 7.4 CI fixture creates a disposable TLS-enabled Redis server, provisions two upstream ACL users with separate tenant key patterns, and starts the Proxima gateway with two client identities. It verifies overlapping key names, MGET/MSET rewriting, BITOP key rewriting, attempts to inject another tenant's raw prefix, denied FLUSHALL, and invalid credentials.

- Protocol policy and framing: crates/proxima-engine/src/redis_protocol.rs
- Gateway runtime: crates/proxima-engine/src/redis_gateway.rs
- Binary: crates/proxima-engine/src/bin/proxima-redis-gateway.rs
- Acceptance runner: scripts/test-redis-tenant-gateway-ci.sh
- Customer deployment guide: docs/REDIS_TENANT_GATEWAY.md
- Customer Compose profile: redis in compose.customer.yaml

The Redis gateway is a restricted preview, not a drop-in replacement for an unrestricted Redis endpoint. Validate client-library startup commands and workload command requirements against the documented allowlist before adoption.

## Build, packaging, and CI requirements

The branch adds the Redis binary to the release Docker image and an opt-in customer Compose profile. CI is configured to:

- Compile and test the full Rust engine.
- Build the Redis gateway binary.
- Run SQL Server 2022 native database-per-tenant acceptance tests.
- Run Redis 7.4 TLS gateway acceptance tests.
- Preserve PostgreSQL, MySQL 8, MariaDB 11.4, CockroachDB 25.2, MongoDB 8, PgBouncer, installer, and packaged-image checks.

Do not merge this branch unless the current PR's complete CI run passes. A cancelled, queued, or partially completed workflow is not a passing result. If either new acceptance suite fails, correct the implementation and rerun the complete workflow.

## Production-readiness boundary

Passing CI establishes only the tested versions, protocol features, command surface, TLS setup, and deployment topology. It does not certify every SQL Server edition, Redis client library, cluster topology, or customer workload. The SQL Server native profile and Redis RESP2 gateway must remain separately described in product documentation so customers understand which component enforces tenant identity.
