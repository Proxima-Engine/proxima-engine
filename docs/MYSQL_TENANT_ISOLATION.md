# MySQL tenant isolation design

## Status

This branch introduces the first tested-by-design building block: deterministic tenant database/account identities and a least-privilege SQL provisioning plan. It is **not yet a complete or supported MySQL integration**. The plan generator is not a database driver, protocol gateway, secret store, or control-plane workflow.

## Security model

MySQL does not provide PostgreSQL-style row-level security. Proxima will not emulate RLS by rewriting arbitrary SQL. The initial supported model is **one database per tenant**, with separate database accounts:

- Runtime account: SELECT, INSERT, UPDATE, DELETE, EXECUTE and SHOW VIEW, scoped to that tenant database only.
- Migration account: schema-management privileges scoped to that same tenant database only.
- Neither account receives global privileges, GRANT OPTION, user/role administration, FILE, SUPER, SYSTEM_USER, or cross-database grants.
- Both accounts require TLS.
- Account host matching is exact. Wildcard host patterns are rejected by the plan builder.
- Revocation locks accounts and removes grants; it does not delete customer data.
- Password rotation changes only the two tenant-specific accounts.

A database-per-tenant privilege boundary is stronger and easier to reason about than shared-table filtering, but it is not row-level security. Shared-table multi-tenant schemas are explicitly unsupported by this initial model.

## Required runtime architecture

The target request path is:

1. The application presents a short-lived signed tenant assertion to the Proxima MySQL gateway.
2. The gateway validates signature, expiry, organization and tenant binding. Client-supplied database names and tenant IDs are never authoritative.
3. The gateway resolves the tenant through a trusted local registry and obtains that tenant's runtime credential from protected secret storage.
4. The gateway opens a tenant-specific MySQL session using the runtime account. It never connects as root or as the provisioning account for application traffic.
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

1. **Identity and DDL planning** — deterministic names, exact host validation, separate runtime/migration accounts, scoped grants, rotation and revocation plans.
2. **Provisioning executor** — TLS-only administrative connection, safe execution, idempotency journal, compensation and no secret logging.
3. **Tenant registry and credential storage** — signed tenant identity mapped to a protected credential record; no client-controlled routing.
4. **MySQL protocol gateway** — supported handshake/authentication plugins, TLS termination, bounded packet parsing, command handling and prepared-statement lifecycle. Unsupported protocol commands fail closed.
5. **Control-plane integration** — connection registration, tenant provisioning, credential rotation/revocation, health and audit APIs. The control plane's PostgreSQL SQLx dependency remains PostgreSQL-only.
6. **Verification** — real MySQL 8.4 tests for cross-database denial, DML, DDL separation, definer objects, prepared statements, transactions, connection reuse, token expiry/replay, revocation, TLS and engine restart.
7. **Customer documentation** — supported topology, prerequisites, grants, migration workflow, failure behavior and explicit non-support for shared-table row filtering.

## Release rule

MySQL is not advertised as supported until every gate passes against a real MySQL server. A successful connection or a generated SQL plan is not proof of tenant isolation.
