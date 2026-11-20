# SQL Server and Redis Tenant Gateway Implementation Plan

## Objective

Add SQL Server and Redis as two independent Proxima Engine integrations. They must share the product's tenant-isolation contract and verification standards, but must not share protocol assumptions or enforcement code.

This document is an implementation contract, not a claim that either integration is already implemented or production-certified.

## Existing baseline to preserve

The current main branch has passing CI coverage for PostgreSQL, CockroachDB 25.2, MySQL 8, MariaDB, and the restricted MongoDB 8 gateway. Work on this branch must preserve those paths and must not change billing, hosted control-plane behavior, or existing customer defaults.

## Integration A: Microsoft SQL Server

### Security and protocol model

SQL Server speaks Tabular Data Stream (TDS), not PostgreSQL wire protocol. It has its own PRELOGIN negotiation, TLS transition, LOGIN7 authentication, packet framing, SQL batches, RPC calls, prepared statements, and session semantics. A PostgreSQL or MySQL gateway cannot be reused as a SQL Server listener.

**Decision:** do not implement or advertise a Proxima TDS gateway with the currently available Rust server-side ecosystem. The SQL Server deliverable is a native database-per-tenant security profile: each tenant receives a dedicated SQL Server database and least-privilege SQL login, with the login's default database set to that tenant database. This removes tenant predicates from application SQL and makes SQL Server's native database permissions the enforcement boundary. It is not a Proxima protocol gateway, does not provide gateway-side identity binding or shared-database RLS, and must be positioned separately from the gateway integrations.

SQL Server's native security remains authoritative:
- Tenant-specific SQL principals and database permissions.
- Row-Level Security (RLS) predicates for shared tables where row isolation is required.
- SESSION_CONTEXT only when set by a trusted, non-spoofable connection bootstrap path; applications must not be allowed to overwrite the trusted tenant key.
- Deny cross-tenant reads, writes, schema changes, impersonation, and privilege escalation.
- Do not treat a client-supplied tenant ID or arbitrary SESSION_CONTEXT value as proof of identity.

### TDS gateway feasibility outcome

1. Evaluate the TDS protocol and Rust ecosystem for a maintained, production-usable server-side implementation. The Rust Tiberius project describes itself as a native SQL Server client, so it must not be mistaken for a TDS server. Microsoft’s mssql-rs project and the tds_protocol crate are protocol-layer candidates to audit; the existence of packet/token parsing or a mock TDS server does not itself establish production server support.
2. Prove PRELOGIN/TLS negotiation, LOGIN7 parsing, authentication failure handling, packet framing, and clean disconnect behavior in a minimal protocol spike.
3. Decide whether the gateway will terminate client TLS and re-encrypt upstream TLS. Certificate validation must be enabled for upstream SQL Server connections. No plaintext credentials or TLS downgrade.
4. Define the supported TDS version, SQL Server edition/version, authentication mode, and explicitly unsupported protocol features before exposing a customer endpoint.
5. If a safe TDS server cannot be implemented with a maintainable dependency and adequate test coverage, stop and document a native SQL Server enforcement integration as a separate, explicitly scoped alternative. Do not ship an incomplete or falsely advertised TDS gateway.

Protocol research starting points: [Microsoft mssql-rs](https://github.com/microsoft/mssql-rs), [tds-protocol crate](https://docs.rs/tds-protocol/latest/tds_protocol/), and [Tiberius](https://github.com/tiberius-rs/tiberius). These are client/protocol-layer candidates, not a declaration that a ready-made server gateway exists. The implementation must not proceed to a customer-facing TDS listener until a complete server-side design has been proven with real SQL Server clients and TLS.

### Minimum SQL Server acceptance matrix

- Two independent tenants, each with its own login/principal and test data.
- Tenant A can read and write only Tenant A data; Tenant B can read and write only Tenant B data.
- Cross-tenant SELECT, INSERT, UPDATE, DELETE, schema access, database switching, impersonation, and unauthorized stored procedure execution are denied.
- Invalid credentials, unknown identities, disabled principals, expired/revoked identity records, malformed TDS packets, and TLS verification failures are rejected.
- Prepared statements, parameterized queries, RPC execution, transactions, rollback, and connection reset behavior are tested within the declared compatibility scope.
- A connection cannot change tenant after authentication; pooled/reused connections cannot leak identity or session state.
- RLS is tested directly against SQL Server with adversarial policies and least-privilege grants; gateway checks are not the only isolation layer.
- Resource limits, timeouts, cancellation, concurrent sessions, and gateway restart/recovery are measured.

## Integration B: Redis

### Security and protocol model

Redis uses RESP2/RESP3 and a command-oriented data model. Tenant isolation must be based on authenticated identity and an enforced key namespace, backed by Redis ACLs. Logical database numbers alone are not a tenant-security boundary. The official RESP specification documents binary-safe framing, pipelining, and RESP3; Redis command key specifications are the authoritative starting point for command key extraction. Redis ACLs constrain both commands and key patterns, but key patterns do not restrict keyless administrative commands, so the gateway must also maintain an explicit command policy.

The target design is a dedicated RESP gateway:
- Authenticate the client against a protected identity registry or supported Redis ACL identity.
- Bind the connection to one immutable tenant principal.
- Derive the tenant key namespace inside the gateway; never trust a client-provided tenant prefix.
- Rewrite/validate every key-bearing command and every key in multi-key commands.
- Use a dedicated upstream Redis ACL user per tenant with the narrowest possible command and key-pattern permissions.
- Deny commands whose semantics cannot be safely inspected or scoped until they have explicit, tested support.

### Initial restricted command surface

Support must be explicit and versioned. Start with common string, hash, list, set, sorted-set, and expiry operations only after command metadata and key positions are validated. Multi-key commands must prove every key belongs to the same tenant. Keyless administrative commands are denied by default.

The first release should deny or tightly gate:
- CONFIG, ACL, MODULE, SHUTDOWN, FLUSHALL, FLUSHDB, DEBUG, REPLICAOF/SLAVEOF, MIGRATE, RESTORE, and other administrative commands.
- EVAL/EVALSHA and Functions until script key declarations and runtime key access are proven tenant-safe.
- MONITOR, arbitrary Pub/Sub, client tracking, replication, cluster administration, and commands that expose server-wide metadata.
- Transactions until MULTI/EXEC/DISCARD state is bound to the same authenticated tenant and all queued commands are validated before execution.
- Commands with dynamic/ambiguous key positions until covered by a tested command specification.

Protocol and security references: [Redis RESP specification](https://redis.io/docs/latest/develop/reference/protocol-spec/), [Redis ACL documentation](https://redis.io/docs/latest/operate/oss_and_stack/management/security/acl/), and [command key specifications](https://redis.io/docs/latest/develop/reference/key-specs/).

### Minimum Redis acceptance matrix

- Two independent tenants with overlapping logical key names; each sees only its own namespace.
- Cross-tenant GET/SET/DEL and cross-tenant multi-key operations are denied.
- Validate all supported command key positions, including variadic and optional-key forms.
- Unknown commands, malformed RESP frames, oversized frames, unsupported RESP3 attributes/push messages, and denied administrative commands fail closed.
- Test authentication failure, identity revocation, immutable session binding, connection reuse, pipelining, timeout, cancellation, and concurrent clients.
- Test transactions only if explicitly supported; queued commands cannot escape the tenant namespace.
- Validate ACL key patterns and command categories against the actual Redis server version.
- Test persistence/restart and reconnect behavior without cross-tenant state leakage.

## Shared implementation contracts

Both gateways must:
- Have separate binaries, modules, configuration namespaces, listeners, health reporting, and integration suites.
- Default to loopback-only binds; require explicit configuration for externally reachable listeners.
- Require TLS for production client and upstream connections, with certificate verification.
- Keep credentials in protected files or secret providers; never log passwords, tokens, or raw authentication packets.
- Enforce immutable per-connection tenant identity and least-privilege upstream credentials.
- Fail closed on unknown commands, unsupported protocol features, malformed input, and ambiguous identity.
- Apply connection caps, read/write limits, idle and query timeouts, cancellation, and graceful shutdown.
- Emit structured, tenant-safe audit events without leaking SQL values, Redis values, or secrets.
- Document driver compatibility, protocol limitations, deployment, rotation, and recovery.

## Delivery sequence

1. **SQL Server protocol feasibility spike**: protocol/TLS/authentication proof, dependency review, threat model, and explicit support boundary. No production gateway claim until this passes.
2. **SQL Server native security fixture**: provision two tenants, principals, RLS policies, grants, and adversarial SQL tests against a real SQL Server container.
3. **SQL Server gateway implementation**: only after the feasibility gate; add binary, config, listener, identity registry, upstream TLS, integration suite, docs, and CI.
4. **Redis command model and threat model**: command metadata table, RESP framing/parser tests, key extraction and namespace rewriting, explicit deny list.
5. **Redis gateway implementation**: binary, ACL provisioning, identity binding, RESP2 baseline then RESP3 only where supported, integration tests, docs, and CI.
6. **Unified verification harness**: one terminal entry point to start disposable services, wait for health, run all six database suites, collect logs and emit JSON/Markdown evidence. Also support per-database selection.
7. **Mainline acceptance**: all existing database suites plus SQL Server and Redis pass in the same clean CI run; image packaging and customer install checks pass; docs accurately describe limitations.

## Definition of done

A database is not marked complete merely because the crate compiles or unit tests pass. Completion requires a real server integration test, adversarial two-tenant isolation tests, authentication and protocol negative tests, resource/lifecycle tests, repeatable local terminal execution, CI execution, packaged runtime verification, and accurate customer documentation.

Production readiness is evidence-based and scoped to the tested database versions, protocol features, TLS/authentication modes, deployment topologies, and workload envelope. A green CI run is necessary but is not a blanket certification of every possible customer environment.
