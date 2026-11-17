# PostgreSQL Security Core adapter

The Engine now contains a concrete PostgreSQL catalog adapter at
`crates/proxima-engine/src/postgres_adapter.rs`. It implements the shared
`DatabaseAdapter` contract for read-only inspection, deterministic catalog
fingerprints, review-only RLS plan generation, and fail-closed verification
reports.

## Compile a policy plan

```sh
cargo run -p proxima-engine --bin proxima-policy-guard -- compile-plan postgresql policy.json
```

Set `PROXIMA_TENANT_ROLE_PREFIX` to the same prefix configured on the Engine,
then run the command. It emits JSON containing SQL statements and explicit
preconditions. It does not connect to PostgreSQL and does not execute DDL. The
generated plan enables and forces RLS, then creates restrictive per-operation
policies that derive the tenant ID from the authenticated PostgreSQL login
role: the role must equal the configured prefix followed by the normalized
tenant ID. This uses the Engine's existing per-tenant role routing and does not
depend on session-level GUC state, which is important when a transaction-pooling
proxy is present.

Before applying a plan, an operator must review the resource mapping, confirm
the tenant column type and semantics, verify that each requested command has a
reviewed permissive baseline policy, reconcile existing policies and grants,
and ensure the Engine's tenant role prefix and tenant-role provisioning contract
match the database's tenant IDs. The plan is not an authorization approval and is not safe to apply
without those preconditions.

## Inspect a live target

Configure:

- `PROXIMA_POSTGRES_ADAPTER_DATABASE_URL`: PostgreSQL connection URL. The
  adapter requires TLS and uses the Engine's trusted root set. Set
  `PROXIMA_POLICY_AUDIT_TLS_CA_FILE` when a private CA is required.
- `PROXIMA_POSTGRES_ADAPTER_TARGET_ID`: stable, non-secret registered target ID.
- `PROXIMA_POSTGRES_ADAPTER_DATABASE_NAME`: expected database name.
- `PROXIMA_TENANT_ROLE_PREFIX`: exact role prefix used by Engine startup
  authentication and tenant role routing.

Then run:

```sh
cargo run -p proxima-engine --bin proxima-policy-guard -- inspect-policy policy.json
```

The adapter configures a read-only session with bounded statement and lock
timeouts. It rejects inspection credentials with elevated role attributes or
database/schema/table write privileges. It checks target identity, relation
existence, RLS enabled/forced state, inherited owner SUPERUSER/BYPASSRLS paths,
policy definitions, policy roles, and relation ACLs. The catalog fingerprint
includes policy expressions and ACL state so policy edits, grant changes, and
RLS toggles change the digest.

The command currently exits with a deny result. This is intentional: catalog
inspection and policy presence cannot prove tenant isolation. The adapter
does not claim semantic verification, approved policy deployment, rollback,
or runtime admission. It does not register as production-supported. Production
admission must remain denied until independent authenticated positive and
cross-tenant negative probes, controlled deployment/rollback, drift response,
and the protocol connection admission path are implemented and accepted.

## Scope boundary

This first concrete adapter supports PostgreSQL table and partitioned-table
catalog inspection and table RLS plan generation. Partitioned relations produce
an explicit finding because directly addressable child partitions require
their own inspection. Views, routines, SECURITY DEFINER behavior, external
authorization, and application-level access paths require separate checks.
