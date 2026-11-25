# Agata Proxima Engine — implementation handoff

## Included in this source update

1. **SQL Server native tenant lifecycle:** added a TLS-verified Tiberius executor and database-per-tenant lifecycle for database/login/user provisioning, `db_datareader`/`db_datawriter` membership, isolation-option verification, password rotation, login disable and destructive offboarding. Added an ignored disposable SQL Server integration test. The Proxima TDS server is not included in this update.
2. **DynamoDB IAM:** added an AWS SDK IAM adapter using the default AWS credential provider chain, role create/update, exact inline policy write/verify, paginated policy cleanup and role deletion. Trust policies reject wildcard principals and actions outside `sts:AssumeRole`.
3. **Cassandra:** added a TLS-verified Scylla Rust driver executor for prepared metadata checks, role/keyspace provisioning, grant verification, password rotation and login disable.
4. **Oracle:** added an Oracle TNS executor using `oracle-rs`, with TLS and wallet connection options, parameterized dictionary queries, user/privilege verification and lifecycle operations.
5. **Elasticsearch/OpenSearch:** extended the native REST identity lifecycle with tenant credential authentication verification and OpenSearch backend-role mapping create/verify/revoke.
6. **Cloud-to-Engine runtime reconciliation:** exported the MySQL/MariaDB, MongoDB and Redis runtime modules from the Engine crate; invoked those modules from authenticated desired-state polling; kept supervisors alive across polling cycles; made preview assignments remain staged; emitted applied/failed acknowledgements from durable runtime state; hashed assignment IDs for state filenames; migrated legacy state filenames; and locally revoked supported gateway assignments omitted from the latest signed bundle.
7. **Verification tooling:** fixed PowerShell native-stderr handling so Cargo warnings do not become PowerShell terminating errors; added the SQL Server native integration test to the provider runner; updated provider status and run instructions.

## Build and test on Windows

Run `APPLY-AND-VERIFY.ps1` from this delivery folder. First run without `-Apply` to review the file list. Then run with `-Apply` and the actual Engine workspace path. The script backs up overwritten files, formats the workspace, resolves dependencies and refreshes `Cargo.lock`, compiles all workspace targets, and runs Engine library and binary unit tests.

```powershell
.\APPLY-AND-VERIFY.ps1 -EngineRepo "C:\Users\HomePC\source\proxima-engine"
.\APPLY-AND-VERIFY.ps1 -EngineRepo "C:\Users\HomePC\source\proxima-engine" -Apply
```

To run the full workspace suite after starting all configured integration services:

```powershell
cd C:\Users\HomePC\source\proxima-engine
cargo test --workspace --all-targets --no-fail-fast
```

For the PostgreSQL integration test, start a disposable PostgreSQL 17 service in another terminal:

```powershell
docker run --rm --name proxima-ci-postgres `
  -e POSTGRES_USER=proxima `
  -e POSTGRES_PASSWORD=proxima-dev-only `
  -e POSTGRES_DB=proxima_dev `
  -p 127.0.0.1:5432:5432 postgres:17
```

Then run:

```powershell
cargo test -p proxima-engine --test postgres_integration -- --ignored
```

SQL Server native lifecycle acceptance is available with `PROXIMA_SQLSERVER_HOST`, `PROXIMA_SQLSERVER_PORT`, `PROXIMA_SQLSERVER_ADMIN_USER`, `PROXIMA_SQLSERVER_ADMIN_PASSWORD`, and optionally `PROXIMA_SQLSERVER_CA_FILE` set:

```powershell
cargo test -p proxima-engine --test sqlserver_native_integration -- --ignored
```

## Remaining implementation work

- A complete Proxima TDS gateway server for SQL Server (TDS PreLogin/TLS, LOGIN7, tenant authentication and binding, SQL batch/RPC/prepared statements, transactions, protocol conformance and adversarial tests).
- Cloud assignment orchestration and secret delivery for the new DynamoDB, Cassandra, Oracle, Elasticsearch and OpenSearch provider adapters.
- Durable gateway process recovery/adoption after an Engine crash or restart, including safe process ownership verification.
- End-to-end upstream credential provisioning/rotation/revocation for all provider types, with remote identity cleanup and provider-specific integration tests.
- Full adversarial real-provider acceptance for every supported database and distribution.

## Execution boundaries

No GitHub writes, pushes, branches, Actions runs or Product OS operations are performed by this package. The package changes the local Engine source only. The owner runs local compilation and provider acceptance against their own services and credentials.
