# Multi-database policy-plan compilers

This release adds reviewable native policy-plan generation for SQL Server, MySQL, MariaDB, MongoDB and Redis. These are early adapter-development capabilities, not production database integrations.

The compilers live in `crates/proxima-engine/src/native_policy_plans.rs` and are exposed through `proxima-policy-guard compile-plan <database> <policy.json>`. They accept the shared `proxima.security.v1` policy model and return `CompiledPolicy` values with native, reviewable changes. They do not open database connections, execute DDL, provision credentials, inspect live catalogs, verify effective permissions, detect drift, or admit runtime traffic.

## Current compiler behavior

| Database | Generated native plan | Required security model | Not provided |
|---|---|---|---|
| SQL Server | RLS inline predicate-function template plus filter and block predicate security-policy template | Trusted, authenticated `SESSION_CONTEXT` tenant claim | Session-context bootstrap, catalog inspection, ownership/bypass analysis, deployment, semantic verification, drift and runtime admission |
| MySQL | User and table-grant SQL template | One database and principal per tenant | Native row-level security; shared-table isolation; live privilege inspection |
| MariaDB | User and table-grant SQL template | One database and principal per tenant | Native row-level security; shared-table isolation; live privilege inspection |
| MongoDB | Custom collection-role template | One database per tenant | Document-level filtering inside a shared collection; live role inspection |
| Redis | ACL user/key-pattern template | One ACL user and strict key namespace per tenant | Trusted principal selection, command allowlist, ACL inspection and runtime enforcement |

### SQL Server

The generated RLS predicate compares the configured tenant ownership column with the configured claim in SQL Server `SESSION_CONTEXT`. Read operations generate a filter predicate. Insert, update and delete operations generate corresponding block predicates, including before/after update checks. The function parameter includes a `<VERIFIED_COLUMN_TYPE>` placeholder because the exact native type must come from a live catalog inspection; the output is not executable until that substitution is performed. Function and policy DDL are separate batches, and an existing policy requires an explicit reviewed `ALTER SECURITY POLICY` revision.

This is only safe when the tenant context is set by a trusted authenticated gateway and cannot be set or overwritten by an untrusted client. The compiler cannot prove that condition. The generated function and security policy must be inspected after deployment, and elevated principals, ownership chaining, module signing and bypass paths must be audited.

### MySQL and MariaDB

These systems do not expose native row-level security predicates equivalent to PostgreSQL RLS or SQL Server RLS. The compiler therefore generates a database-per-tenant grant template. It explicitly marks shared-table row-level isolation as false. The generated user and grant statements require a `${trusted_application_host}` placeholder; deployment must replace it with the exact trusted application egress host or a narrowly scoped network identity, never an unrestricted wildcard. A deployment must provision a separate database, principal and secret for each tenant, and route only after authenticating the tenant. A shared table with a `tenant_id` column is not secured by this template.

### MongoDB

MongoDB RBAC controls database and collection privileges; it does not automatically enforce arbitrary tenant predicates on each document. The generated custom-role template is limited to a database-per-tenant design. Shared collections need a separately enforced document-level authorization mechanism and must not be represented as isolated by this role plan.

### Redis

The ACL template binds a tenant-specific principal to a key pattern containing the literal `${tenant_id}` placeholder, for example `tenant:${tenant_id}:*`. The trusted gateway must select the corresponding ACL principal after authenticating the tenant. The template derives a narrower core-command allowlist from the requested operations instead of granting every mutating command. Redis ACLs cannot distinguish create-only from update-only semantics for upsert commands such as `SET`, `HSET`, `SADD` and `ZADD`; a trusted enforcing gateway or application contract must enforce that distinction. Production support still requires inspection of command key specifications, multi-key behavior, keyless commands, scripts, functions, channels, modules and administrative privileges.

## Why these are not yet called supported

A generated policy is not an enforced policy. Before an adapter can be marked supported, it must have all of the following:

1. Authenticated TLS connection handling and least-privilege inspection.
2. Complete resource and native-authorization discovery.
3. Trusted tenant identity to native principal/context binding.
4. Native policy deployment behind exact-revision approval and safe rollback.
5. Semantic positive and negative tests proving cross-tenant reads and writes are denied.
6. Inspection of superuser/admin, owner, inherited-role, global privilege, view, trigger, procedure, script and bypass paths relevant to that database.
7. Drift detection that denies affected access when required controls change.
8. Runtime fail-closed admission tied to the exact verified policy revision.
9. Signed evidence with target identity, policy revision, coverage, test results, timestamp and limitations.
10. Independent adversarial acceptance against supported database versions and topologies.

The Engine catalog therefore marks these five compilers `in_development` and enables only the `policy_generation` capability. All other capabilities remain false. CockroachDB and SQLite now have separate read-only discovery adapters with drift fingerprints; both remain `in_development` and expose no policy-generation, semantic-verification, deployment or runtime-admission capability. Oracle, DynamoDB, Cassandra, Elasticsearch/OpenSearch and VAULTDB remain planned. No database is promoted to production support by the existence of a compiler or catalog entry.
