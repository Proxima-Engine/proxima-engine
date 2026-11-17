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
