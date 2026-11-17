# Implementation status — 17 November 2026

## Changes made

These changes are on the existing draft PR branches; no PR was merged.

- In `crates/proxima-engine/src/main.rs`, tenant policy admission now defaults to required when `PROXIMA_POLICY_ADMISSION_REQUIRED` is unset. Invalid values fail startup. Explicit opt-out is accepted only in debug builds; release builds reject it.
- The same runtime admission default and release-build requirement were applied to the embedded Engine in the Agata Proxima control-plane branch.
- In `crates/proxima-engine/src/connection_admission.rs`, the test evidence fixture now supplies `mutation_rollback:create`, `mutation_rollback:update`, and `mutation_rollback:delete` checks. The evidence authority already requires these checks for mutating operations.

## Validation and review state

- The source files were fetched from the current branch heads before each update, and GitHub accepted the updates.
- Rust tests/builds, database integration tests, and GitHub Actions were not run in this session. The evidence-fixture change addresses a mismatch identified by source inspection; it is not represented as a passing test run.
- Engine PR #30 remains open and draft. Control-plane PR #219 remains open and draft. Neither was merged.

## Remaining work

This is a bounded enforcement improvement, not completion of the multi-database platform.

- PostgreSQL still lacks independent positive and cross-tenant negative data-plane probes that produce trusted per-operation evidence.
- MySQL/MariaDB, SQL Server, MongoDB, Redis, CockroachDB, SQLite, Elasticsearch/OpenSearch, and Oracle do not have complete production adapters. Existing discovery paths and review-only policy compilers do not provide controlled deployment/rollback, trusted tenant identity binding, semantic authorization probes, runtime admission, and signed data-plane evidence as one verified lifecycle.
- Policy deployment approval/rollback orchestration, adapter-specific live drift response, multi-protocol runtime enforcement, and adversarial acceptance remain outstanding.

The adapter registry continues to keep incomplete adapters out of production registration. Keep both PRs in draft until local builds, tests, and database-specific adversarial acceptance pass.
