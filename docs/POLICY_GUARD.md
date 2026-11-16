# PostgreSQL RLS posture audit and tenant-session guard

The Engine Policy Guard provides a read-only PostgreSQL catalog audit and deterministic SQL generator. The Engine runtime also parses tenant-bound PostgreSQL protocol messages and rejects a defined set of commands that could alter the authenticated role or bypass RLS semantics.

This does not replace PostgreSQL, prove arbitrary application authorization, or silently apply schema changes.

## Build and unit tests

    cargo build -p proxima-engine --bin proxima-policy-guard
    cargo test -p proxima-engine --bin proxima-policy-guard
    cargo test -p proxima-engine sql_guard

These commands are intended for local verification. They do not require or trigger GitHub Actions.

## Read-only posture audit

Set PROXIMA_POLICY_AUDIT_DATABASE_URL to a dedicated inspection connection. The command requires TLS and certificate/hostname verification. It uses Mozilla WebPKI roots by default. For a private CA, set PROXIMA_POLICY_AUDIT_TLS_CA_FILE to a PEM file containing the trusted CA certificate(s).

    export PROXIMA_POLICY_AUDIT_DATABASE_URL='postgresql://AUDIT_USER:...@db.example.com:5432/DB?sslmode=require'
    export PROXIMA_POLICY_AUDIT_TLS_CA_FILE='/etc/ssl/customer-postgres-ca.pem'
    cargo run -p proxima-engine --bin proxima-policy-guard -- audit

The audit forces TLS even if the supplied URL requests a weaker SSL mode. It sets a read-only session, a 10-second statement timeout and a 2-second lock timeout. The audit login must not be SUPERUSER or have direct/inherited BYPASSRLS, and must not have INSERT, UPDATE, DELETE or TRUNCATE privileges on application tables.

The JSON report covers ordinary and partitioned tables visible to the audit role, RLS enabled/forced state, table-owner bypass paths, PUBLIC SELECT and write/TRUNCATE grants, inherited BYPASSRLS/SUPERUSER grants, policy counts, multiple permissive policies and SECURITY DEFINER routine presence. The command emits JSON and exits with status 2 when findings exist.

The scanner's catalog visibility is limited by the inspection role. A policy count is not proof of policy correctness. SECURITY DEFINER routines, views, dynamic SQL, application authentication and business authorization require separate review. A clean report is not a security certification.

## Generate reviewed policy SQL

Create a mapping file with the exact schema, table, tenant key and tenant-to-role mapping. The generator accepts 1–100 unique mappings per table, limits PostgreSQL identifiers to 63 bytes, validates role-name syntax, and escapes identifiers and string literals.

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

The generated SQL is wrapped in a transaction and includes a preflight DO block. Before DDL it checks that the table exists, tenant roles exist, mapped roles have no role memberships or RLS-bypass path, the table owner is not a tenant role or RLS-bypass role, no other permissive policy applies, no non-owner TRUNCATE grant exists, no inherited bypass-role grant exists, and no user-defined SECURITY DEFINER routine is present.

The DDL enables and forces RLS and creates a FOR ALL policy with matching USING and WITH CHECK predicates. Each predicate binds the tenant key to current_user. The preflight refuses to overwrite any existing policy with the selected name; inspect and rename or remove a pre-existing policy through a separately reviewed migration before regenerating. The generator does not trust a client-settable custom GUC as the sole tenant identity and does not execute DDL. Review the complete SQL, verify the target mapping, take a backup, and apply through your migration process.

## Runtime tenant-session guard

When the Engine has verified a signed tenant context, it inspects PostgreSQL simple-query and extended-protocol Parse frames. It rejects:

- SET ROLE, SET LOCAL ROLE, RESET ROLE and session-authorization changes.
- Attempts to set row_security to off, false, zero or no.
- set_config calls, preventing a client from changing sensitive session GUCs through a function call.
- DO and CALL procedural entry points pending separate review.
- TRUNCATE, which is not filtered by PostgreSQL RLS.
- The legacy PostgreSQL FunctionCall protocol.
- Startup parameters and options that attempt to override role/session authorization or disable row security.

Rejected operations terminate the tenant-bound upstream session before the complete command is forwarded. This guard is deliberately conservative: applications that rely on DO, CALL, set_config, TRUNCATE or legacy FunctionCall through tenant-bound sessions must use an explicitly reviewed alternative.

The parser/tokenizer is a guard for these specific protocol/session operations, not a complete semantic SQL authorization engine. PostgreSQL privileges and RLS remain authoritative for table access.

## Security boundaries

- FORCE ROW LEVEL SECURITY does not constrain superusers or roles with BYPASSRLS.
- Table owners and inherited memberships can change the effective boundary.
- PostgreSQL RLS does not filter TRUNCATE.
- Other permissive policies combine with OR semantics and can widen access; the generator preflight rejects them.
- SECURITY DEFINER functions and procedures can execute with their owner's privileges; the generator preflight blocks them pending separate review.
- The generated policy is correct only when the supplied tenant column and role mapping match authenticated application identity.
- The CLI audit/generator is operator-invoked, not a continuous drift monitor. Hosted Cloud provides separate database inventory, approved revisions, post-apply verification and drift monitoring.
- Adversarial cross-tenant read/write tests remain required.
