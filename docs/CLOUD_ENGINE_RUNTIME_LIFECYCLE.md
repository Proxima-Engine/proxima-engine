# Cloud-to-Engine runtime lifecycle

## Architecture and ownership

Agata Proxima Cloud is the management control plane. It owns organization-scoped database targets, node assignments, tenant bindings, configuration revisions, credential revisions and the desired state of each assignment.

Proxima Engine is the customer-side data plane and the runtime authority. It authenticates to Cloud as an enrolled node, receives assignments authorized for its node and organization, validates and stages configuration, prepares the provider-specific runtime, supervises activation, verifies upstream connectivity and reports the result with a signed acknowledgement.

Database traffic remains in the customer's environment. Cloud manages assignment intent and receives lifecycle results; it is not placed in the application's database request path.

**Implementation status:** all twelve provider keys now have explicit Cloud assignment dispatch paths in the Engine. PostgreSQL and CockroachDB use the native PostgreSQL runtime; MySQL/MariaDB, MongoDB and Redis use their supervised protocol gateways; Microsoft SQL Server uses the Proxima TDS 7.4 gateway; SQLite, Oracle, DynamoDB, Cassandra and Elasticsearch/OpenSearch use provider-native adapters. Each adapter validates the assigned provider/runtime, tenant-binding coverage and configuration revision, performs its provider-specific preparation or health checks, and returns binding evidence before the Engine records an applied revision and signs the Cloud acknowledgement.

This is the implemented repository integration boundary, not a blanket claim that every provider/version has passed production acceptance. MySQL/MariaDB validate the protected identity registry and authenticated upstream accounts; MongoDB validates tenant/database coverage, protects the gateway registry and verifies upstream TLS/hello, while SCRAM identity behavior still requires adversarial real-server acceptance; Redis validates tenant coverage, upstream ACL identities and revocation; SQL Server provisions/verifies tenant databases and logins and starts the TDS gateway; PostgreSQL/CockroachDB verify upstream TLS, tenant roles and forced RLS; SQLite creates protected per-tenant files; Oracle manages schema-owner provisioning, rotation and revocation; Cassandra manages keyspace roles and grants; DynamoDB manages tenant IAM roles scoped to the table's leading partition keys; Elasticsearch/OpenSearch manage provider-native tenant users/roles and index permissions. Exact provider versions, live credentials, TLS, authorization and adversarial cross-tenant tests must still be verified in the customer's target environment. See the [provider runtime reference](PROVIDER_RUNTIME_REFERENCE.md) and [database production verification](DATABASE_PRODUCTION_VERIFICATION.md).

## End-to-end assignment lifecycle

1. **Node identity.** The Engine loads its persisted node identity and signing credential. The identity binds the node to its organization.
2. **Authenticated configuration pull.** The Engine signs a domain-separated request containing a timestamp and nonce. Cloud verifies the node signature, request freshness, nonce uniqueness, node status and organization ownership.
3. **Signed desired-state bundle.** Cloud returns a signed configuration bundle bound to the enrolled node and organization. The bundle identifies each assignment, target, provider, configuration revision, credential revision, endpoint and tenant bindings.
4. **Credential envelope validation.** Credential envelopes use AES-256-GCM. Associated data binds the encrypted material to the node, target and revision context. The Engine validates the bundle signature and binding before decrypting credentials in memory.
5. **Desired-state validation.** The Engine validates assignment identity, provider/runtime compatibility, endpoint values, tenant bindings and monotonic configuration and credential revisions.
6. **Provider preparation.** The Engine builds provider-specific runtime configuration and validates the tenant identity mapping. Protected identity registry files are written to the runtime state directory.
7. **Runtime activation.** The coordinator replaces the process associated with the assignment, persists the applying state, starts the selected gateway executable and waits for its loopback readiness endpoint.
8. **Provider health verification.** The Engine performs an authenticated upstream connection check using the assigned tenant identity and provider connection settings.
9. **Applied state.** The Engine persists the applied revision only after activation and provider health checks succeed.
10. **Signed acknowledgement.** The Engine signs the acknowledgement with the node identity. Cloud accepts it only for the authenticated node and current assignment revision, then records the applied or failed result.

A downloaded bundle, decrypted credential, written configuration file or open TCP listener is not, by itself, an applied runtime. The applied state represents the result of runtime activation and provider health checks.

## Trust and credential handling

### Node request authentication

The configuration-pull request is signed using the enrolled node signing key. The signed request is domain-separated, timestamped and nonce-bound. Cloud checks that the signing key belongs to the enrolled node, that the node belongs to the organization, that the timestamp is within the accepted freshness window, that the nonce has not been reused and that the node and assignment are eligible for configuration delivery.

### Configuration bundle

The signed bundle binds desired configuration to the intended node and organization. The Engine verifies the signature and checks the node and organization identifiers before processing assignments.

Credential envelopes use AES-256-GCM. Associated data binds the ciphertext to the node ID, target ID, configuration revision and credential revision. This prevents encrypted credentials from being substituted across nodes, targets or revisions.

Credential plaintext is held in memory for provider preparation and activation. The shared desired-state document and durable reconciliation record contain routing metadata and revision state, not decrypted provider credentials. Runtime identity registries contain the provider-specific material required by the gateway and are stored as protected files.

### Acknowledgement authentication

The Engine acknowledgement is signed over the node ID, organization ID, nonce, assignment ID, target ID, configuration revision, timestamp, status, runtime-health result and bounded error code. Cloud verifies the signature and current assignment revision before accepting the result.

## Durable reconciliation state

Each assignment has a durable record with these fields:

| Field | Meaning |
|---|---|
| `schema_version` | Runtime-state document format version |
| `assignment_id` | Stable Cloud assignment identity |
| `target_id` | Assigned database target |
| `provider` | Provider key associated with the assignment |
| `desired_revision` | Latest accepted configuration revision |
| `applied_revision` | Last revision that passed activation and health checks |
| `phase` | Current lifecycle phase |
| `runtime_health_passed` | Whether the applied revision passed provider health verification |
| `credential_revision` | Monotonic credential revision |
| `last_error_code` | Bounded, non-secret failure classification |
| `updated_at_unix` | Last state transition time |

The Engine stores one reconciliation record per assignment under the `runtime-state` directory beside the database-target document by default. `PROXIMA_NODE_RUNTIME_STATE_DIR` selects another directory. The desired database-target document defaults to `database-targets.json`; `PROXIMA_NODE_DATABASE_CONFIG_PATH` selects another path.

State writes use a same-directory temporary file, flush the file, atomically rename it into place and synchronize the parent directory. On Unix, the runtime state file is owner-only (mode `0600`).

### Lifecycle phases

| Phase | Meaning |
|---|---|
| `staged` | Authenticated desired configuration has been validated and persisted. |
| `applying` | The coordinator has begun replacing or activating the runtime for the desired revision. |
| `applied` | The runtime is active and provider health verification passed for the recorded applied revision. |
| `failed` | Activation or provider verification failed; the health marker is false and a bounded error code is recorded. |
| `revoked` | The assignment has been revoked, its applied marker is cleared and its identity cannot be reused for a later revision. |

The state machine rejects assignment, target or provider identity changes within an existing record; configuration and credential revision rollback; applying a revoked assignment; and an applied transition without a matching applying revision and successful provider-health result. A replacement assignment uses a new record.

When a newer desired revision arrives, the Engine retains the last applied revision in the record while marking the new desired revision as staged. This preserves the distinction between the latest requested configuration and the last successfully applied configuration.

## Runtime process supervision

The runtime supervisor owns child processes by assignment ID. It serializes concurrent starts for the same assignment, rejects duplicate child ownership, starts the selected executable with its configured arguments and environment, and tracks the child until shutdown or replacement.

The readiness address must be a loopback address. Startup waits until the listener accepts a TCP connection, checks that the child is still running and enforces the configured startup timeout. If startup fails or times out, the attempted child is stopped.

For MySQL/MariaDB, MongoDB, Redis and SQL Server, the Engine validates the provider-specific registry/configuration, persists the `applying` transition, starts the selected packaged gateway and waits for loopback readiness before recording `applied`. MySQL/MariaDB authenticate each configured upstream account and run `SELECT 1`; MongoDB verifies upstream TLS and the `hello` command; Redis authenticates configured upstream ACL identities over TLS and runs `PING`; SQL Server validates tenant login/database assignments, TLS material and the TDS gateway configuration before starting the gateway. Native providers run their provider-specific provisioning/verification adapter instead of being launched as generic TCP gateways.

The process supervisor persists PID-reuse-resistant process leases containing the assignment ID, PID, executable, arguments and OS process-start identity. On restart it can re-adopt only a process whose identity still matches the lease; otherwise it removes the stale lease and starts the requested process. Startup/readiness failures stop the attempted child. This supports process recovery, but it does not by itself prove that a customer database, network, certificate or tenant policy is production-ready.

## Provider runtime contracts

The Engine uses provider-specific runtime contracts. A provider's native security model is not converted into a generic database protocol.

| Provider | Runtime and tenant boundary |
|---|---|
| PostgreSQL | Native Proxima PostgreSQL-wire Engine runtime with PostgreSQL roles, grants and RLS. |
| CockroachDB | PostgreSQL-wire Engine runtime with CockroachDB-native roles, grants and forced RLS behavior. |
| MySQL | Dedicated MySQL-compatible gateway, tenant-specific upstream identities and database bindings. |
| MariaDB | MySQL-compatible gateway with MariaDB-specific client authentication and tenant database bindings. |
| MongoDB | Separate restricted OP_MSG gateway, SCRAM-SHA-256 identity mapping, TLS and database-per-tenant authorization. |
| Redis | Separate restricted RESP2 gateway, tenant-bound sessions, key namespace enforcement and upstream ACL identities. |
| SQL Server | Proxima TDS 7.4 gateway with LOGIN7 principal binding, assigned database enforcement, dedicated SQL logins and verified upstream TLS. |
| SQLite | Embedded database-file-per-tenant profile with path and filesystem protections. |
| Oracle | Schema-per-tenant profile with dedicated schema owners and least-privilege grants. |
| DynamoDB | AWS IAM policy construction using exact table resources and `dynamodb:LeadingKeys`; AWS IAM enforces the policy. |
| Cassandra | Keyspace-per-tenant roles and native authorization; not a CQL proxy. |
| Elasticsearch and OpenSearch | Separate provider-native role and index policy integrations using distribution-specific authorization APIs. |

For supervised process activation, the executable, identity registry format, listener and health check must match the provider contract. The MySQL/MariaDB preparation path validates exactly one identity for each assigned tenant binding, writes the registry privately, starts the packaged gateway and checks authenticated upstream connectivity. MongoDB validates exact tenant/database coverage and checks TLS plus the upstream hello command; it does not claim the hello probe proves each SCRAM identity. Redis validates exact tenant coverage and checks every upstream ACL identity with authenticated TLS sessions. Native, file and API integrations use their provider-native security boundary rather than being launched as generic TCP gateways.

## Tenant identity and isolation

Tenant bindings are validated against the assignment before a runtime is prepared. A provider identity maps to the intended tenant and assigned database, schema, keyspace, namespace or table scope.

Provider provisioning and policy enforcement remain provider-specific:

- PostgreSQL and CockroachDB use database roles, grants and row-level security.
- MySQL and MariaDB use dedicated upstream accounts and tenant-specific database grants.
- MongoDB uses database-scoped identities and MongoDB authorization.
- Redis uses tenant-bound sessions, namespace rewriting and Redis ACL users.
- SQL Server uses dedicated databases and logins.
- SQLite uses a separate protected database file for each tenant.
- Oracle uses dedicated schema owners and bounded privileges.
- DynamoDB uses IAM conditions tied to the authenticated tenant partition key.
- Cassandra uses keyspace-scoped roles and grants.
- Elasticsearch and OpenSearch use their respective native role and index authorization facilities.

The trusted application backend remains responsible for authenticating end users and authorizing organization membership. The Engine enforces the database-side tenant identity and resource boundary presented to it.

## Revision replacement, credential rotation and revocation

Configuration and credential revisions are monotonic. A lower revision is rejected. A changed assignment, target or provider identity requires a new assignment record rather than mutating the identity of an existing record.

A replacement revision is staged, prepared and activated. The applied revision advances only after the new runtime passes its health check. Credential rotation is represented by a new credential revision and is applied through the provider-specific identity and runtime preparation path.

Revocation clears the applied marker and stops the process owned by the assignment. Provider-specific identity revocation must also disable the tenant's database credentials or authorization before revocation is considered complete. Revoked assignment records cannot be reactivated; a later assignment is provisioned as a new identity.

## Operations and diagnostics

Correlate Cloud and Engine events using node ID, organization ID, assignment ID, database target ID, provider key, desired configuration revision, applied configuration revision, credential revision and acknowledgement timestamp.

The runtime record is the durable local source for desired/applied revision and phase. Engine logs should use bounded error codes and assignment identifiers; credential plaintext and full connection secrets must not be logged.

For a failed assignment, inspect node enrollment and identity persistence, configuration-pull authentication, bundle signature and credential-envelope validation, desired-state identity and revision checks, provider runtime compatibility, identity registry permissions, executable availability, child-process readiness, authenticated upstream connectivity, durable state transition and the signed Cloud acknowledgement.

## Local build and verification

Run deterministic repository checks from the Engine repository root:

```powershell
cargo fmt --check
cargo check --workspace --all-targets
cargo test --workspace
cargo build --workspace --bins
```

The test suite includes runtime-state transitions, revision rollback rejection, revoked-assignment reuse rejection, durable state serialization, process-supervisor readiness constraints, gateway registry validation and provider-specific behavior.

Run provider acceptance scripts against disposable provider instances and credentials configured in the local environment. For a Cloud-connected acceptance run, enroll a test node, create a test database target and tenant bindings, assign the target to that node, then verify the Engine's applied acknowledgement and provider-side isolation behavior. Repeat with a newer configuration revision, credential rotation, a failed health check and assignment revocation.

A Rust build or unit test validates the code paths exercised by that test. Real-provider acceptance validates the actual database, identity, TLS and authorization configuration in the target environment.


## Cloud-driven assignment removal

The authenticated configuration bundle is a complete desired-state snapshot for the enrolled node, not a patch. After persisting the new routing document, the Engine compares persisted assignment records with the current enabled assignment IDs. An assignment omitted from the snapshot, or present but no longer enabled, is revoked locally: the matching MySQL/MariaDB, MongoDB or Redis child gateway is stopped; its node-local identity registry file is removed; and the durable runtime record is marked `revoked`. Native listener assignments have their staged routing entry removed and their durable record revoked. Revoked assignment IDs cannot be reused for a later revision; Cloud must issue a new assignment identity for a fresh binding.

Revocation is provider-specific. The native adapter revokes Oracle schema-owner privileges, Cassandra tenant roles/keyspace grants, DynamoDB IAM roles and Elasticsearch/OpenSearch tenant identities; SQLite records a local tenant-file revocation marker. PostgreSQL/CockroachDB disables tenant-role login. SQL Server applies its tenant login/database lifecycle through the TDS runtime. Redis removes the assigned ACL user. MySQL/MariaDB and MongoDB remove the assignment's local gateway registry/process state; upstream account lifecycle remains governed by the provider provisioning workflow and must be verified separately. A successful local revoke acknowledgement must not be interpreted as proof that an externally managed account was deleted unless the provider evidence explicitly confirms it.
