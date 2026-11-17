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

## Runtime admission against Control Plane posture

For a node to enforce the hosted PostgreSQL policy state before accepting a
tenant connection, configure:

- `PROXIMA_NODE_POLICY_STATUS_URL`: the Control Plane endpoint
  `/api/v1/nodes/policy-status` (HTTPS in production).
- `PROXIMA_DATABASE_TARGET_ID`: the UUID of the registered PostgreSQL
  connection in the Control Plane.
- `PROXIMA_POLICY_ADMISSION_REQUIRED=true`: fail Engine startup if the
  admission endpoint or its required node identity is not configured.

When the endpoint is configured, every tenant-bound PostgreSQL startup performs
a signed request bound to the node, registered target, requested database,
verified tenant ID, and Engine role prefix. The Control Plane returns a
node-key-signed decision with a 15-second expiry. The Engine verifies the
signature and every binding before relaying the established session. An
unreachable service, invalid signature, expired response, unknown policy,
unapplied revision, stale schema fingerprint, drift flag, or non-protected
verification denies the connection.

The Control Plane refreshes PostgreSQL catalog fingerprints every 30 seconds.
The admission endpoint denies when the last fingerprint check is older than
90 seconds. Every registration on the target that maps to the requested tenant
must be enabled and have its latest revision applied and verified as protected;
a disabled, unknown, stale or drifted registration denies admission. The
Control Plane also checks that tenant roles have no access to unregistered
application tables. A tenant with no registered protected resources is denied
when admission is enabled.

The Engine rechecks active tenant sessions every five seconds. Decisions are
shared through a bounded five-second per-tenant cache, so multiple sessions
for the same tenant do not each generate a Control Plane request. If posture
becomes unknown, unsafe, stale, or unreachable, the Engine closes affected
sessions instead of allowing them to continue. The PostgreSQL startup
`ReadyForQuery` message is withheld until the first signed admission succeeds,
so a denied connection is never reported as ready to the client.

## Scope boundary

This first concrete adapter supports PostgreSQL table and partitioned-table
catalog inspection and table RLS plan generation. Partitioned relations produce
an explicit finding because directly addressable child partitions require
their own inspection. Views, routines, SECURITY DEFINER behavior, external
authorization, and application-level access paths require separate checks.
