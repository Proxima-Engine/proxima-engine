# Proxima Security Core implementation audit — 17 November 2026

This is an implementation-state audit, not a security certification. It records what is present in the current development branches and what is still required before production support or merge.

## 1. Multi-database coverage

| Database | Current implementation | Runtime support |
|---|---|---|
| PostgreSQL | Existing signed tenant-token verification, PostgreSQL role binding, Policy Guard CLI, Cloud inventory/registration/reviewed RLS deployment and drift workflow | Existing PostgreSQL path only; full semantic verification and admission gating remain incomplete |
| SQL Server | Review-only native RLS filter/block predicate plan compiler; exact tenant-column type remains a live-catalog placeholder | Not implemented |
| MySQL | Review-only database-per-tenant user/grant SQL template | Not implemented; no native row-level security; shared-table tenant isolation is not provided |
| MariaDB | Review-only database-per-tenant user/grant SQL template | Not implemented; no native row-level security; shared-table tenant isolation is not provided |
| MongoDB | Review-only database-per-tenant custom collection-role template | Not implemented; shared-collection document-level isolation is not provided |
| Redis | Review-only tenant key-pattern ACL template with baseline core-command allowlist | Not implemented; trusted ACL principal selection, live ACL inspection and runtime enforcement are absent |
| CockroachDB, SQLite, Oracle, DynamoDB, Cassandra, Elasticsearch/OpenSearch, VAULTDB | Cataloged as planned | Not implemented |

The CLI command `proxima-policy-guard compile-plan` emits reviewable JSON policy plans for SQL Server, MySQL, MariaDB, MongoDB and Redis. It does not connect to customer databases or execute changes. The catalog exposes only `policy_generation` for those five in-development compilers; no inspection, enforcement, deployment, verification, drift, runtime admission or signed-evidence capability is enabled for them.

## 2. Runtime admission

The common `VerificationReport` decision rule fails closed unless the model version is known, inspection is complete, posture is verified and findings are empty. The new `PolicyEvidenceAuthority` can issue and verify a short-lived admission envelope bound to the policy revision, database target, tenant, signed evidence digest and a maximum 60-second lifetime.

The admission envelope is not yet called by the PostgreSQL connection-startup path. It does not yet have per-connection challenge/replay protection. Other database protocol listeners do not exist. Therefore runtime admission tied to a verified policy posture is not complete.

## 3. Signed evidence

The Engine library can HMAC-sign policy evidence containing model version, policy revision, database kind, target, tenant, posture, inspection completeness, findings, verified operations, fingerprint, timestamp and positive/negative checks. The admission envelope references the exact signed evidence digest.

This is not yet integrated into the existing node-attestation ledger, the hosted Cloud evidence-ingestion API, or persistent evidence storage. Signing keys are library inputs; production secret loading, rotation, key identifiers and operational recovery are still required.

## 4. Verification and adversarial acceptance

Regression tests have been added for policy-plan generation, SQL Server predicate generation, database-per-tenant limitations, Redis key-pattern constraints, evidence tampering, policy/target/tenant binding, stale evidence, expiry and incomplete verification.

No Rust build, Rust test suite, frontend build, live database integration test, protocol test, supply-chain verification or GitHub Actions run was performed in this authoring session. CI was intentionally not triggered. New adapters have not passed independent adversarial acceptance.

## Merge gate

Do not mark the five new database families as supported, do not advertise runtime multi-database enforcement, and do not merge these drafts into `main` until:
- adapter-specific database drivers/listeners and secure TLS connections exist;
- native catalog and privilege inspection is complete;
- exact policy deployment, rollback and drift response are implemented;
- semantic positive and negative isolation tests pass on supported versions/topologies;
- policy evidence is ingested and persisted by Cloud;
- the connection runtime verifies fresh admission envelopes with replay/connection binding;
- owner-run local acceptance and independent adversarial review pass.

The current result is a wider Agata-owned security architecture and five policy-plan compilers—not a completed all-database production security platform.
## 5. Production maturity gate added after this audit

The adapter registry now refuses registration unless an adapter explicitly declares supported maturity and all eight end-to-end capability flags are true: schema inspection, tenant identity enforcement, semantic verification, policy generation, controlled deployment, drift detection, fail-closed runtime admission and signed evidence. The shared capability model exposes the same completeness predicate. Regression tests cover rejection of review-only/partial adapters and acceptance of a complete descriptor.

This is a guard against accidentally advertising or loading an incomplete adapter. It does not implement the missing database drivers, native inspection, deployment, protocol listeners or acceptance tests, and it does not change the maturity of any database in the catalog.

## Follow-on Security Core coordinator work

The Engine branch now includes `security_core_coordinator.rs`, which centralizes adapter-backed policy compilation, native inspection/semantic verification, and drift validation. Compilation rejects unapproved plans, mismatched policy identity/revision/database kind, missing or duplicate protected-resource coverage, altered tenant ownership keys, and incomplete operation coverage. Inspection rejects target/database identity mismatches, missing or malformed SHA-256 fingerprints, incomplete native posture, missing protected resources, ownership-key mismatches, and unverified operations. Drift reports must match the requested target and prior baseline, contain a complete inspection and valid observed fingerprint, and report a drift state consistent with the fingerprint comparison. A first baseline cannot claim drift without a prior trusted fingerprint.

These coordinator paths are orchestration contracts and test-fixture coverage, not a live database adapter. The registry remains empty in production; no database is promoted to `supported`. PostgreSQL native inspection, deployment integration, semantic adversarial verification, durable Cloud evidence ingestion, and protocol-startup admission wiring remain outstanding. No build, unit test, integration test, or CI run has been performed for these follow-on changes.


## 6. Current cross-component boundary — 17 November 2026

The PostgreSQL listener's active admission path consumes the Cloud node-key-signed policy-status response and its per-registration evidence object. The generic Engine `PolicyEvidenceAuthority` format remains a separate library primitive; it is not silently treated as the hosted wire protocol. The PostgreSQL catalog adapter intentionally returns a deny posture until authenticated positive and cross-tenant negative probes exist. The Cloud policy lifecycle currently verifies catalog/revision/role-binding posture, not those independent data-plane probes.

The Cloud registration validator additionally rejects distinct tenant IDs that normalize to one PostgreSQL role and rejects derived role names exceeding PostgreSQL's 63-byte identifier limit. Regression tests were added. The Cloud tenant-role migration was repaired to remove malformed duplicated legacy-collision SQL and now quarantines ambiguous mappings, records drift, and preserves fail-closed behavior.

No Rust/frontend builds, tests, migration execution, live PostgreSQL acceptance, or GitHub Actions were run. These changes are committed to the development branches but remain uncompiled and unvalidated. PostgreSQL remains in development; the five compiler-only databases and all other planned targets remain unsupported.


## 7. PostgreSQL drift fingerprint expansion — 17 November 2026

The concrete Engine PostgreSQL catalog adapter now includes additional native security and schema metadata in its drift fingerprint: database-wide role attributes and validity, database-scoped persistent role settings, role memberships and admin-option state, database and schema ACLs/ownership, default privileges, relation ownership/ACL/RLS/policy definitions, columns and defaults, constraints and validation state, indexes and validity/readiness, non-internal triggers and enabled state, view/materialized-view definitions/options/ACLs, and application routine ownership, SECURITY DEFINER state, settings, arguments, definitions and execute ACLs. Sequence ownership and ACLs are also included.

This closes a material blind spot in the earlier relation-only fingerprint: role grants, inherited membership, persistent settings, routine changes, and schema-object changes can alter effective authorization without changing a table's own RLS policy or ACL. The fingerprint is still a drift signal, not semantic proof. It does not promote PostgreSQL to supported, and independent authenticated positive/negative tenant probes, controlled deployment and full local acceptance remain required.

The SQL changes have been committed but were not compiled or executed against PostgreSQL in this session. Validate catalog-query permissions and compatibility against the supported PostgreSQL major versions before accepting the adapter.


## 8. Policy-plan hardening — 17 November 2026

The MySQL/MariaDB database-per-tenant grant template now requires a trusted application-host placeholder for both account creation and grants instead of creating a principal reachable from the unrestricted wildcard host. Deployment must bind that placeholder to a narrowly scoped trusted egress identity.

The Redis ACL compiler now derives a narrower command allowlist from the requested read/create/update/delete operations rather than granting the same broad mutating command set for every write operation. Regression tests cover delete-only and create-only plans. The generated plan also explicitly states that Redis ACL command permissions cannot distinguish create-only from update-only behavior for upsert commands; that semantic distinction requires an enforcing gateway or application contract and is not claimed as a Redis-native capability.

These are policy-plan safety improvements only. They do not add native MySQL/MariaDB/Redis connections, catalog inspection, deployment, semantic verification, runtime enforcement or drift monitoring. The tests were authored but not executed in this session.


## 9. Signed evidence admission coverage hardening — 17 November 2026

The generic Engine evidence authority now refuses admission unless every declared operation has both a passing own_tenant_allow:<operation> check and a passing cross_tenant_deny:<operation> check. Duplicate check identifiers and duplicate verified operations are rejected, and check identifiers/details are bounded. This prevents a signed payload with one arbitrary passing check from being treated as complete tenant-isolation proof.

The evidence fixture tests now model positive and negative coverage for read, create, update and delete. Regression tests cover missing per-operation negative probes, duplicate check identifiers and duplicate operation declarations. These checks validate the evidence contract; they do not themselves execute database probes. A trusted native verifier must still perform the operations and sign the resulting evidence. Tests were authored but not executed.

The signed evidence payload validator also bounds policy/target/tenant identifiers, finding/check counts, finding and check text, resource identifiers and operation counts, and rejects NUL-bearing values. Regression coverage includes oversized tenant identifiers and finding details.

The read-only PostgreSQL inspection path also checks that each policy-declared tenant ownership column exists on the registered relation and is NOT NULL; missing or nullable tenant keys become explicit findings rather than being inferred from RLS policy presence.

PostgreSQL resource inspection also checks dependent view chains for non-security-invoker views and materialized views, and flags application SECURITY DEFINER routines for explicit review. These are conservative findings; their presence does not automatically prove exploitability, but they prevent a clean isolation posture from being inferred without reviewing those alternate access paths.


## 10. Native PostgreSQL resource discovery — 17 November 2026

The database-neutral adapter contract now exposes `discover` independently of policy inspection, with typed resource inventory, adapter target, completeness, findings, fingerprint and observation time. The PostgreSQL adapter implements read-only discovery of tables, partitioned/foreign tables, views, materialized views, sequences, functions and procedures. It records owners, relation ACL/RLS state, columns/defaults, native policy expressions/roles, constraints, indexes, non-internal triggers, view definitions/options, and routine SECURITY DEFINER/execute ACL metadata. The Policy Guard CLI exposes `discover-postgres [schema]` and always labels the result as inventory only with an explicit deny decision.

Discovery tests cover invalid namespace and target mismatch without opening a database connection. Live catalog discovery and supported-version compatibility remain unexecuted in this session.


## 11. Native MySQL/MariaDB catalog adapter — 17 November 2026

Added a TLS identity-verifying MySQL protocol adapter shared by MySQL and MariaDB. It discovers tables/views and routines, column definitions/defaults/nullability, table/schema grants, constraints and foreign-key references, indexes, triggers and definers, view definitions/check options/security mode, and routine grants; authenticated-account grants are included in target metadata. The Policy Guard exposes `discover-mysql`, `discover-mariadb`, `inspect-mysql-policy` and `inspect-mariadb-policy` commands. Policy inspection checks registered resource presence and tenant-key existence/nullability, while explicitly flagging that native row-level security is unavailable and database-per-tenant grants require independent principal probes. Drift comparison uses discovery fingerprints. The adapter remains in development and does not claim runtime tenant enforcement, semantic verification, controlled deployment or signed admission. Metadata visibility is marked incomplete because information_schema results are privilege-filtered.

Regression tests cover database-kind validation, target bounds and capability maturity. Tests and live TLS/catalog compatibility checks were authored but not executed in this session.


## 12. Native MongoDB discovery and posture adapter — 17 November 2026

Added a MongoDB Rust-driver adapter requiring verified TLS and rejecting insecure TLS URI options. It connects to the registered database, obtains authenticated effective privilege information, enumerates visible collections and views, captures collection options/validators and view metadata, and fingerprints the inventory. Policy inspection checks tenant ownership validator declarations and required fields, but explicitly records that MongoDB database-level roles do not provide document-level tenant filtering. Discovery is marked incomplete where authenticated visibility is privilege-scoped; verification always denies pending independent positive/negative document probes and runtime principal binding. The adapter remains in development.

The adapter now applies bounded server-selection and connect deadlines, and policy inspection checks that tenant ownership has an explicit BSON type, is required, and is protected by strict validation with error action. The Policy Guard exposes `discover-mongodb` and `inspect-mongodb-policy` using explicit target/URI environment variables; both retain deny semantics. Regression tests cover TLS URI enforcement and capability maturity. Driver API compatibility, live MongoDB catalog permissions and tests were not executed in this session.


## 13. Native Redis ACL discovery adapter — 17 November 2026

Added a TLS-only Redis adapter that confirms the selected logical database, reads the authenticated ACL user, ACL user definitions, key patterns, command rules, channels, ACL categories, server version and keyspace statistics, and fingerprints raw ACL state while redacting credential hashes/password tokens from the returned inventory. Discovery flags unrestricted key patterns and remains incomplete because ACL inventory does not enumerate all keys or prove application-level tenant binding. The Policy Guard exposes `discover-redis` and `inspect-redis-policy`; both retain deny semantics. Tests cover TLS URI requirements, ACL credential redaction and target/database mismatch. Runtime protocol mediation, controlled ACL deployment, independent semantic probes, module/script/function coverage and signed admission remain unimplemented. No build, test, or live Redis validation was performed.

Redis inspection now distinguishes read-only, write-only and read/write ACL key patterns, checks that one tenant ACL principal covers the required key scopes, compares explicit command allowlists against the canonical operation set, and flags broad command categories or unrestricted key patterns. Redis `execute` operations are rejected by the compiler and inspector rather than silently omitted.


## 14. Native SQL Server catalog and RLS inspection adapter — 17 November 2026

Added a Tiberius encrypted-TDS adapter that rejects disabled encryption and TrustServerCertificate bypass, confirms the registered database, and discovers tables/columns, indexes, partition schemes/functions/range boundaries, foreign/check/default constraints, object and column grants, schema/database permissions, principals, role membership, database TRUSTWORTHY/cross-database chaining options, RLS policies/predicates, triggers, views and routines. Discovery fingerprints the visible catalog and marks completeness according to database VIEW DEFINITION/sysadmin visibility, flagging sysadmin inspection identities. Policy inspection checks tenant-column existence/nullability, enabled FILTER predicates, AFTER INSERT, BEFORE/AFTER UPDATE and BEFORE DELETE block predicates, and follows the predicate function definition to check SESSION_CONTEXT use and schema binding. The Policy Guard exposes `discover-sql-server` and `inspect-sql-server-policy`; inventory output is bounded to 10,000 tables, views and routines, with truncation explicitly marked incomplete. Runtime SESSION_CONTEXT trust, controlled policy deployment/rollback, independent semantic probes and signed admission remain outstanding. Tiberius API compatibility, TLS chain behavior, SQL Server version compatibility and live catalog tests were not executed.

The PostgreSQL discovery snapshot now also includes database/schema ACLs and ownership, default privileges, role attributes and role memberships, and full application routine definitions alongside relation metadata. The adapter descriptor now advertises its implemented fingerprint drift comparison.

MongoDB discovery now includes collection index definitions in addition to validators, view pipelines, collection options and effective connection privileges; inventory is bounded to 10,000 collections, 10,000 indexes per collection and 100,000 indexes total, with cursor pagination and explicit truncation findings. It flags broad inspection roles/any-resource privileges and uses bounded connect and server-selection timeouts.

PostgreSQL discovery and policy inspection now include declarative partition parent/child relationships, partition keys and bounds, and each child partition's RLS state, FORCE RLS state and local policy expressions. Inspection flags directly addressable partitions without RLS, without local policies, with RLS not forced, or whose local policy expressions do not visibly reference the registered tenant key.

SQL Server discovery also fingerprints partition schemes/functions/range boundaries, and inspection flags RLS predicate functions or table triggers that execute under an explicit EXECUTE AS principal.

MongoDB tenant-field validation now also rejects validators whose BSON type constraint explicitly permits null, rather than treating a merely present bsonType declaration as sufficient.

## CockroachDB discovery adapter added after the initial audit

- Added a separate CockroachDB adapter over the PostgreSQL wire protocol with an injected connector, read-only session settings, server identity validation, database-target binding, bounded discovery, native `information_schema` table/view/column/table-grant inventory, deterministic catalog fingerprinting and drift comparison.
- The adapter is deliberately marked `in_development` and exposes only schema inspection and drift detection. It does not reuse PostgreSQL RLS assumptions, compile or deploy policy, claim tenant enforcement, or return a verified posture.
- CockroachDB native authorization, authenticated tenant binding, independent positive/negative probes, controlled policy deployment, signed evidence and runtime admission remain unimplemented. The module has authored unit tests only; no Rust build, tests or live CockroachDB validation were run.

## Native adapter inspection-session hardening

- PostgreSQL inspection now evaluates the connected role and its reachable role memberships for SUPERUSER, BYPASSRLS, CREATEROLE, CREATEDB and REPLICATION attributes before catalog access.
- MySQL/MariaDB inspection now sets subsequent transactions read-only and requires the vendor-specific SELECT statement deadline to be accepted; it no longer silently ignores unsupported timeout settings.
- SQL Server inspection now rejects sysadmin, database owner/DDL/security/access administration, db_datawriter, and effective database/object mutation privileges before inventory queries.
- MongoDB catalog operations now have an explicit socket timeout in addition to server-selection and connection timeouts.
- MySQL/MariaDB, MongoDB, Redis, SQL Server and CockroachDB discovery/inspection/drift inventory operations have a bounded sixty-second operation deadline. PostgreSQL retains server-side statement and lock deadlines.
- These are code changes and regression coverage where present, not executed validation. No Rust build, unit test suite, live database test or migration execution has been run.


## SQLite file-isolation discovery adapter added after the initial audit

- Added a SQLx SQLite read-only adapter that refuses in-memory databases and attached databases, validates the connected main file against a registered absolute path, disables trusted schema execution, and applies bounded busy/operation deadlines.
- Discovery inventories tables/views, columns, indexes and index columns, foreign keys, triggers, schema definitions, journal mode, file/directory permissions and WAL/SHM sidecar permission bits where visible.
- The adapter is marked `in_development` with schema-inspection and drift-detection capabilities only. SQLite has no native per-tenant users or RLS; policy compilation and semantic verification are explicitly denied.
- File-per-tenant selection, complete cross-platform OS ACL verification (including Windows), independent cross-tenant file-access probes, runtime admission and signed evidence remain unimplemented. No Rust build, tests or live SQLite acceptance were run.
