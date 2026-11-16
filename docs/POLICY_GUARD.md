# PostgreSQL RLS posture audit and policy SQL generation

This tool adds an explicit, read-only catalog audit and deterministic SQL generator. It does not replace PostgreSQL, rewrite application queries, or silently apply schema changes.

## Build

    cargo build -p proxima-engine --bin proxima-policy-guard
    cargo test -p proxima-engine --bin proxima-policy-guard

## Audit

Set PROXIMA_POLICY_AUDIT_DATABASE_URL to a dedicated, read-only PostgreSQL inspection connection. Do not use a superuser as the routine audit identity. This initial binary currently connects with tokio-postgres NoTls: use it only against loopback or a trusted private network. Do not send database credentials or traffic over an untrusted network. TLS support for this audit connection is not implemented in this first change.

    export PROXIMA_POLICY_AUDIT_DATABASE_URL='postgresql://AUDIT_USER:...@127.0.0.1:5432/DB?sslmode=disable'
    cargo run -p proxima-engine --bin proxima-policy-guard -- audit

The command emits JSON and exits with status 2 when catalog findings exist. It reports ordinary and partitioned tables visible to the inspection role, RLS enabled/forced state, owner superuser/BYPASSRLS status, PUBLIC SELECT grants, and policy counts. Visibility is limited by the audit role's privileges.

A policy count is not proof of policy correctness. Review role membership, grants, views, functions, SECURITY DEFINER code, dynamic SQL, and application authorization separately. The scanner does not label a database secure based on catalog presence alone.

## Generate policy SQL

Create a reviewed mapping file. Each table must declare its schema, table, tenant key column, policy name, and exact tenant-ID-to-dedicated-PostgreSQL-role mapping.

    {
      "tables": [{
        "schema": "public",
        "table": "orders",
        "tenant_column": "tenant_id",
        "policy_name": "proxima_tenant_isolation",
        "tenants": [
          {"tenant_id": "tenant-a", "role": "proxima_tenant_a"},
          {"tenant_id": "tenant-b", "role": "proxima_tenant_b"}
        ]
      }]
    }

    cargo run -p proxima-engine --bin proxima-policy-guard -- generate policy-spec.json > generated-rls.sql

The generator emits ENABLE ROW LEVEL SECURITY, FORCE ROW LEVEL SECURITY, and a USING/WITH CHECK policy tying each tenant identifier to its dedicated current_user role. It quotes identifiers and literals. It does not trust a client-settable custom GUC as the sole tenant identity. Review the SQL, verify role membership and grants, take a backup, and apply through your migration process. The generator does not execute DDL.

## Security boundaries

- FORCE ROW LEVEL SECURITY does not constrain superusers or roles with BYPASSRLS; remove those capabilities from application roles.
- Table owners, inherited memberships, grants, views, functions, triggers and SECURITY DEFINER routines can change the effective boundary.
- The generated policy is correct only when the supplied tenant column and role mapping match authenticated application identity.
- This is an operator-invoked audit/generator, not a continuous drift monitor. It does not claim complete discovery through views or functions.
- Adversarial cross-tenant read/write tests remain required.
