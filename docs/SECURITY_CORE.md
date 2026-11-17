# Proxima Security Core and database adapters

## Product boundary

Agata Proxima is a database-independent tenant-security platform. The Security Core defines a common policy and verification contract. Proxima Engine is the enforcement runtime; each database adapter implements the native protocol, identity mapping, authorization inspection and enforcement behavior required by that database.

The current Engine implementation is PostgreSQL-specific. The common contract is an architectural foundation, not a claim that other databases are already supported.

## Shared contract

The canonical JSON Schema is published at [`schemas/proxima.security.v1.schema.json`](../schemas/proxima.security.v1.schema.json). The Engine Rust model validates the same envelope before an adapter compiles it.

The Rust library module `security_core` defines:

- Versioned policy envelopes (`proxima.security.v1`).
- Protected resource references and native tenant ownership keys.
- A common operation vocabulary: read, create, update, delete and execute.
- Explicit adapter maturity and capability descriptors.
- Security posture states and inspection-completeness states.
- A fail-closed decision rule.

A report permits access only when posture is `verified`, inspection is `complete`, and the finding list is empty. Unknown, incomplete, unavailable, degraded, or failing inspection produces a deny decision.

The Rust module `database_adapter` defines the adapter boundary through `DatabaseAdapter`: native inspection, policy compilation, verification, and drift detection. Its registry rejects duplicate implementations for the same database kind. The interface is an implementation contract, not proof that a database adapter exists; the current Engine branch does not register a production-ready PostgreSQL adapter through this trait yet.

The CLI's `adapters` command reports `scope: engine_runtime`. The Cloud API reports platform-level management capabilities separately. Their scopes differ deliberately: a Cloud deployment workflow does not imply that the Engine itself performs database DDL deployment or runtime posture admission.

## Adapter maturity

The Engine catalog intentionally reports PostgreSQL as `in_development`. Existing work includes signed tenant-context verification, PostgreSQL role binding, the PostgreSQL Policy Guard CLI, Cloud-managed reviewed policy deployment and verification, a 30-second Cloud drift monitor, and protocol-level fail-closed admission against signed Control Plane posture. The Engine admission request uses a fresh request ID; the Control Plane persists the node-key-signed decision and per-registration evidence. The catalog still does not mark independent semantic positive/negative verification, Engine-native controlled deployment, or the generic `PolicyEvidenceAuthority` envelope pipeline as complete Engine capabilities.

The Engine now includes review-only native policy-plan compilers for Microsoft SQL Server RLS, MySQL/MariaDB database-per-tenant grants, MongoDB database-per-tenant collection roles, and Redis tenant-key ACL templates. Read-only native discovery adapters also inspect MySQL/MariaDB, SQL Server, MongoDB, Redis, CockroachDB, SQLite and Elasticsearch/OpenSearch. These non-PostgreSQL adapters remain `in_development`; their enabled capabilities are limited to schema/security-catalog inspection, drift fingerprinting and, for the four compiler families, review-only `policy_generation`. They are not runtime enforcement adapters. Trusted tenant-principal binding, controlled policy deployment, independently executed semantic probes, drift remediation, runtime fail-closed admission and signed per-operation data-plane evidence are not implemented. MySQL/MariaDB do not have native row-level security; their grant templates require a separate database per tenant and do not secure shared tenant tables. MongoDB collection roles likewise do not provide document-level tenant filtering. Redis templates require strict key-prefix discipline, a verified command allowlist and trusted ACL-user selection. Oracle, DynamoDB, Cassandra and VAULTDB remain planned with no enabled capabilities. VAULTDB is an Agata-native research target, not a production-supported adapter.

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

## Signed policy evidence and admission primitives

The Engine library now exposes `policy_evidence::PolicyEvidenceAuthority`. It signs policy-evidence payloads with HMAC-SHA256, binding the model version, policy revision, database kind, target, tenant, posture, inspection completeness, findings, verified operations, catalog fingerprint, timestamp and individual checks. Admission envelopes bind to the exact signed-evidence digest and expire within 60 seconds. Issuance rejects stale evidence, incomplete inspection, unresolved findings, empty operation coverage or failed checks; verification rejects altered signatures and mismatched policy, target or tenant.

The generic `PolicyEvidenceAuthority` types remain library primitives and are not yet the wire format used by the PostgreSQL listener. Separately, the PostgreSQL listener can be configured to require the hosted `/api/v1/nodes/policy-status` decision before it releases the startup `ReadyForQuery` frame; active tenant sessions are rechecked every five seconds. The Control Plane signs each response with the enrolled node key, binds it to a fresh request ID and target/tenant identity, persists the exact payload and signature, and exposes the latest 100 records in the dashboard. The response proves the Control Plane's recorded posture decision, not an independent Engine-side adversarial data probe. Do not conflate this integration with the generic `PolicyEvidenceAuthority` evidence-digest admission format.

## PostgreSQL-specific implementation

The PostgreSQL adapter currently uses the PostgreSQL wire protocol and native role/RLS mechanisms. It must preserve the existing signed tenant identity and tenant-to-role binding while Policy Guard matures.

The Policy Guard CLI is an inspection and SQL-generation tool. Its current posture report explicitly states that catalog inspection cannot prove an arbitrary policy implements the intended tenant boundary. It must not be presented as a complete semantic verifier or as a runtime admission gate until those capabilities are implemented and tested.

The SQL guard is an additional session-protection layer. It is not a complete SQL semantic firewall or general SQL rewrite engine. Its tokenizer/parser behavior, protocol coverage and fail-closed edge cases require adversarial validation.

## Acceptance gate

An adapter may be promoted from planned to in-development only when implementation work begins. It may be called supported only after its native inspection, policy semantics, runtime enforcement, drift response, evidence and compatibility tests are complete and independently reviewed.

Do not enable planned adapter capabilities in the catalog merely to make the product appear broader.
