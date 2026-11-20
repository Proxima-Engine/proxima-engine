# CockroachDB compatibility and tenant isolation

## Architecture

CockroachDB speaks the PostgreSQL wire protocol. Proxima reuses its existing PostgreSQL listener, startup authentication broker, tenant-token verifier, upstream TLS validation, and role-binding path. A second wire-protocol implementation would duplicate the PostgreSQL protocol state machine without adding a security boundary.

Set `PROXIMA_UPSTREAM_ADDR` to the CockroachDB SQL endpoint. The client connects to the normal Proxima PostgreSQL listener and supplies a signed Proxima tenant token in the startup parameter `proxima_tenant_token` (or the supported `PGOPTIONS` form). Proxima verifies the token and replaces the requested upstream role with `PROXIMA_TENANT_ROLE_PREFIX` plus the normalized tenant ID.

Use CockroachDB 25.2 or later for native row-level security. Earlier versions do not provide the RLS enforcement required by this shared-table isolation profile.

## Required database controls

Use non-admin tenant roles. Do not connect tenant traffic as `root`, a cluster admin, a table owner, or a role that can bypass row-level security.

For each shared tenant table:

1. Enable row-level security.
2. Force row-level security so table ownership does not silently bypass the policy.
3. Create role-specific `USING` and `WITH CHECK` policies.
4. Grant only the required schema and table privileges.
5. Keep DDL, role management, backup/restore, cluster settings, and other administrative privileges outside tenant roles.

Example policy shape:

```sql
ALTER TABLE app.records ENABLE ROW LEVEL SECURITY;
ALTER TABLE app.records FORCE ROW LEVEL SECURITY;

CREATE POLICY tenant_a_records ON app.records
  TO proxima_tenant_tenant_a
  USING (tenant_id = 'tenant-a')
  WITH CHECK (tenant_id = 'tenant-a');

GRANT USAGE ON SCHEMA app TO proxima_tenant_tenant_a;
GRANT SELECT, INSERT, UPDATE, DELETE ON app.records TO proxima_tenant_tenant_a;
```

Repeat for each tenant role with its own immutable tenant predicate. The policy must cover every tenant-bearing table, including join targets and tables reached through views or functions. Review foreign keys and uniqueness constraints for side channels that can reveal the existence of another tenant's rows.

## Connection configuration

For a secure CockroachDB endpoint, configure the normal Proxima PostgreSQL upstream settings:

```bash
PROXIMA_LISTEN_ADDR=127.0.0.1:6432
PROXIMA_UPSTREAM_ADDR=cockroach.example:26257
PROXIMA_TENANT_ROLE_PREFIX=proxima_tenant_
PROXIMA_UPSTREAM_TLS_MODE=verify-full
PROXIMA_UPSTREAM_TLS_CA_FILE=/etc/proxima/tls/cockroach-ca.pem
PROXIMA_UPSTREAM_TLS_SERVER_NAME=cockroach.example
```

The client still uses a PostgreSQL-compatible driver. Its signed tenant token must be short-lived and issued for the intended tenant. The tenant role's database password or other PostgreSQL authentication material must be valid on the CockroachDB cluster.

## Transaction semantics

CockroachDB uses serializable transactions and can return SQLSTATE `40001` with a transaction-retry error under contention. Proxima must not blindly replay SQL transactions: replay can duplicate application side effects and cannot safely reconstruct arbitrary client transaction state. The proxy forwards CockroachDB's transaction result to the client. Applications must follow CockroachDB's retry protocol and retry the complete transaction when required.

The PostgreSQL-wire compatibility path does not imply full PostgreSQL feature parity. Validate the exact CockroachDB release, SQL features, role grants, TLS mode, transaction retry behavior, and cluster topology used in deployment.

## Verification

`scripts/test-cockroachdb-tenant-isolation-ci.sh` starts a disposable CockroachDB 25.2 node, creates two least-privilege tenant roles and forced RLS policies, starts Proxima against the CockroachDB SQL endpoint, and verifies tenant A/B reads, cross-tenant read filtering, cross-tenant insert/update rejection, and invalid-token rejection.

This test proves the shared PostgreSQL-wire path against a real CockroachDB service. It is not a substitute for testing production multi-node, multi-region, failover, backup, or contention workloads.
