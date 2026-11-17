# Proxima Security Core and database adapters

## Product boundary

Agata Proxima is a database-independent tenant-security platform. The Security Core defines a common policy and verification contract. Proxima Engine is the enforcement runtime; each database adapter implements the native protocol, identity mapping, authorization inspection and enforcement behavior required by that database.

The current Engine implementation is PostgreSQL-specific. The common contract is an architectural foundation, not a claim that other databases are already supported.

## Shared contract

The Rust library module `security_core` defines:

- Versioned policy envelopes (`proxima.security.v1`).
- Protected resource references and native tenant ownership keys.
- A common operation vocabulary: read, create, update, delete and execute.
- Explicit adapter maturity and capability descriptors.
- Security posture states and inspection-completeness states.
- A fail-closed decision rule.

A report permits access only when posture is `verified`, inspection is `complete`, and the finding list is empty. Unknown, incomplete, unavailable, degraded, or failing inspection produces a deny decision.

## Adapter maturity

The Engine catalog intentionally reports PostgreSQL as `in_development`. Existing work includes signed tenant-context verification, PostgreSQL role binding, the PostgreSQL Policy Guard CLI work and protocol-level tenant-session protections. The catalog does not mark semantic policy verification, controlled policy deployment, drift detection or signed policy evidence as complete Engine capabilities.

MySQL, MariaDB, Microsoft SQL Server, MongoDB and CockroachDB are `planned`. They have no enabled adapter capabilities. They must not be used as production integrations until their own native adapter implementations and acceptance suites exist.

## Adapter responsibilities

Every adapter must implement and validate:

1. Secure connection establishment and least-privilege catalog inspection.
2. Native resource discovery and explicit tenant-resource classification.
3. Tenant identity to native principal/context binding.
4. Policy compilation using the target database's own semantics.
5. Effective grants, ownership, role inheritance and bypass-path inspection.
6. Semantic verification of read and write authorization.
7. Fail-closed behavior when inspection is incomplete or the required posture is not verified.
8. Drift detection and re-verification before reopening affected access.
9. Signed evidence with target, policy revision, coverage, timestamp and limitations.

A database driver or successful connection is not an adapter. A catalog listing is not semantic authorization verification. A generated policy is not evidence that it was safely deployed.

## PostgreSQL-specific implementation

The PostgreSQL adapter currently uses the PostgreSQL wire protocol and native role/RLS mechanisms. It must preserve the existing signed tenant identity and tenant-to-role binding while Policy Guard matures.

The Policy Guard CLI is an inspection and SQL-generation tool. Its current posture report explicitly states that catalog inspection cannot prove an arbitrary policy implements the intended tenant boundary. It must not be presented as a complete semantic verifier or as a runtime admission gate until those capabilities are implemented and tested.

The SQL guard is an additional session-protection layer. It is not a complete SQL semantic firewall or general SQL rewrite engine. Its tokenizer/parser behavior, protocol coverage and fail-closed edge cases require adversarial validation.

## Acceptance gate

An adapter may be promoted from planned to in-development only when implementation work begins. It may be called supported only after its native inspection, policy semantics, runtime enforcement, drift response, evidence and compatibility tests are complete and independently reviewed.

Do not enable planned adapter capabilities in the catalog merely to make the product appear broader.
