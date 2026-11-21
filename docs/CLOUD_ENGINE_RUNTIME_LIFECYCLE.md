# Cloud-to-Engine runtime reconciliation

## Current Engine behavior

A registered node authenticates `POST /api/v1/nodes/config/pull` with its node signing key, verifies the Cloud bundle signature and node/organization binding, decrypts each AES-256-GCM credential envelope, validates the target's full-TLS requirement, and atomically writes the staged assignment document to `database-targets.json` (or `PROXIMA_NODE_DATABASE_CONFIG_PATH`).

The Engine currently supports at most one active target assignment per node. The authenticated bundle's `provider_key`, assignment ID, target ID, configuration revision, and credential revision are also persisted in a separate durable reconciliation record. The default path is `runtime-state.json` beside the database-target document; override it with `PROXIMA_NODE_RUNTIME_STATE_PATH`.

The reconciliation record is written atomically and uses owner-only permissions on Unix. It preserves the last applied revision while a newer desired revision is staged, rejects assignment/target/provider identity changes, and rejects configuration or credential revision rollback. A revoked record cannot be reused for a later revision; a newly assigned target requires a fresh state record after a separately completed revocation lifecycle.

## State semantics

- `staged`: authenticated desired configuration was received and persisted. This is not runtime activation.
- `applying`: reserved for the runtime activation coordinator after it has begun replacing the active runtime.
- `applied`: may be recorded only after runtime activation and provider-specific health/isolation verification. The state API rejects an unhealthy applied transition.
- `failed`: activation failed; the record carries a bounded non-secret error code.
- `revoked`: the assignment has been revoked and must not be reused.

The pull worker's `staged` acknowledgement is not an `applied` acknowledgement. The Engine must not report `runtime_health_passed=true` merely because the bundle was verified, credentials were decrypted, or files were written.

## Runtime activation boundary

The durable desired/applied state module is integrated with configuration staging. It is not, by itself, a process supervisor. The current Engine does not yet have a complete end-to-end coordinator that provisions the MySQL, MongoDB, and Redis tenant identity registries, activates and monitors all supported provider runtime types, performs provider-specific live health/isolation checks, stops a prior process on revocation, and then submits the signed `applied` acknowledgement. Until that coordinator is implemented and verified, Cloud assignments must remain staged/applying and must not be represented as ready.

PostgreSQL/CockroachDB use the Engine PostgreSQL-wire runtime. MySQL, MongoDB, and Redis use their distinct gateway executables and existing provider-specific identity registry formats. SQLite, SQL Server, Oracle, DynamoDB, Cassandra, Elasticsearch, and OpenSearch are native/file/provider API integrations and must not be launched as generic TCP gateway processes. Elasticsearch and OpenSearch remain separate security integrations.

## Local verification

From the repository root, run:

```powershell
cargo fmt --check
cargo check --workspace --all-targets
cargo test --workspace
cargo build --workspace --bins
```

The real-provider scripts are separate from these local unit and compile checks. Run them only against disposable provider resources and the credentials configured in the local environment. A passing build or unit test does not establish real-provider tenant isolation.
