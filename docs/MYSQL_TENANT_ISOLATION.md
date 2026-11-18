# MySQL tenant isolation design

## Status

This branch now contains an independent `proxima-mysql-gateway` crate with a TLS listener API, bounded classic-protocol framing, handshake parsing, TLS-upgrade handling, command classification, TLS-only `caching_sha2_password` gateway-account verification, signed tenant assertion validation, server-derived database routing, verified-TLS upstream authentication, a tenant-bound packet relay, and a journaled provisioning-executor interface. The listener is a library API and is **not yet wired into the Engine executable or customer Docker deployment**. Durable account/secret-store adapters and the Control Plane workflow are not implemented. No real MySQL integration test has run yet, so this remains experimental.

## Security model

MySQL does not provide PostgreSQL-style row-level security. Proxima will not emulate RLS by rewriting arbitrary SQL. The initial supported model is **one database per tenant**, with separate database accounts:

- Runtime account: SELECT, INSERT, UPDATE and DELETE only, scoped to that tenant database. Routine execution and schema inspection are not granted by default.
- Migration account: schema-management privileges scoped to that same tenant database only.
- Neither account receives global privileges, GRANT OPTION, user/role administration, FILE, SUPER, SYSTEM_USER, or cross-database grants.
- Both accounts require TLS.
- Account host matching is exact. Wildcard host patterns are rejected by the plan builder.
- Revocation locks accounts and removes grants; it does not delete customer data.
- Password rotation changes only the two tenant-specific accounts.

A database-per-tenant privilege boundary is stronger and easier to reason about than shared-table filtering, but it is not row-level security. Shared-table multi-tenant schemas are explicitly unsupported by this initial model.

## Implemented building blocks

- `crates/proxima-mysql-gateway/src/protocol.rs`: bounded packet framing, server greeting encoding, client/server handshake parsing, TLS-upgrade request detection, and rejection of commands that can change database or authentication context.
- `crates/proxima-mysql-gateway/src/auth.rs`: TLS-required `caching_sha2_password` gateway-account verification against a stored double-SHA256 verifier, high-entropy one-time gateway credential generation, and interfaces for account lookup and tenant-specific upstream credentials. Password and credential debug output is redacted.
- `crates/proxima-mysql-gateway/src/tenant.rs`: HMAC-SHA256 tenant assertion verification, one-hour maximum lifetime, tenant/account match, and deterministic database routing. Client-selected database names are rejected.
- `crates/proxima-mysql-gateway/src/upstream.rs`: verified-CA TLS connection to MySQL 8.4, server capability validation, and tenant-specific `caching_sha2_password` upstream authentication.
- `crates/proxima-mysql-gateway/src/listener.rs`: separate TLS listener API, client authentication/authorization, upstream connection establishment, and packet relay. It blocks COM_INIT_DB, COM_CHANGE_USER and COM_RESET_CONNECTION.
- `crates/proxima-mysql-gateway/src/isolation.rs`: deterministic database/account naming and scoped provisioning, rotation and revocation SQL plans.

These functions are deliberately separate from the PostgreSQL proxy session code. They still require a real TLS/network state machine and integration tests before they can enforce traffic.

## Required runtime architecture

The target request path is:

1. The application connects to the dedicated MySQL gateway endpoint over TLS, authenticates with its tenant-scoped gateway account using `caching_sha2_password`, and supplies a short-lived signed tenant assertion in the `_proxima_tenant_assertion` connection attribute.
2. The gateway validates signature, expiry, organization and tenant binding. Client-supplied database names and tenant IDs are never authoritative.
3. The gateway resolves the tenant through a trusted local registry and obtains that tenant's runtime credential from protected secret storage.
4. The gateway retrieves the tenant's runtime credential from protected secret storage and opens a tenant-specific MySQL session over verified TLS. It never connects as root or as the provisioning account for application traffic.
5. The upstream MySQL server enforces database-level privileges independently of gateway checks.
6. The gateway rejects missing, malformed, expired, revoked or mismatched tenant context before forwarding application traffic.
7. The control plane records provisioning, rotation, revocation and verification events without recording passwords or customer query results.

The gateway must not share or retarget authenticated upstream sessions between tenants. A connection is permanently bound to one tenant for its lifetime. The upstream MySQL endpoint must be private and unreachable from untrusted application networks, otherwise clients could bypass the gateway.

## Important MySQL-specific constraints

- Definer-security views, routines and triggers can execute with the definer's privileges. Their definers must be tenant-scoped accounts with no global privileges.
- Runtime credentials must not have DDL or account-management privileges.
- Migration credentials are separate and must never be used for ordinary application requests.
- MySQL DDL may implicitly commit. Provisioning therefore needs an explicit compensating-action journal and safe retry semantics; it must not assume a transaction can roll back all DDL.
- Existing customer databases cannot be silently adopted. Adoption requires a separate inspection and privilege-reconciliation workflow.
- Shared-table tenant isolation, arbitrary query rewriting, cross-database queries, replication administration and privileged support access are not part of the first release.

## Implementation gates

1. **Identity and DDL planning** — deterministic names, exact host validation, separate runtime/migration accounts, scoped grants, rotation and revocation plans. Initial primitives are present.
2. **Provisioning executor** — TLS-only administrative connection, safe execution, idempotency journal, compensation and no secret logging. Not implemented.
3. **Tenant registry and credential storage** — signed tenant identity mapped to a protected credential record; no client-controlled routing. Interfaces and assertion checks are present; durable adapters are not implemented.
4. **MySQL protocol gateway** — supported handshake/authentication plugins, TLS termination, bounded packet parsing, command handling and prepared-statement lifecycle. A library listener and packet relay are present, but executable wiring, protocol compatibility testing, multi-packet handling and full prepared-statement lifecycle verification remain.
5. **Control-plane integration** — connection registration, tenant provisioning, credential rotation/revocation, health and audit APIs. The control plane's PostgreSQL SQLx dependency remains PostgreSQL-only.
6. **Verification** — real MySQL 8.4 tests for cross-database denial, DML, DDL separation, definer objects, prepared statements, transactions, connection reuse, token expiry/replay, revocation, TLS and engine restart.
7. **Customer documentation** — supported topology, prerequisites, grants, migration workflow, failure behavior and explicit non-support for shared-table row filtering.

## Release rule

MySQL is not advertised as supported until every gate passes against a real MySQL server. A successful connection or a generated SQL plan is not proof of tenant isolation.
