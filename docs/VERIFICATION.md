# Verification and test guide

Use this guide to run the Engine test suite, exercise PostgreSQL tenant isolation, verify PgBouncer transaction-pool separation, inspect runtime endpoints, and validate signed local evidence. Record the exact source commit and toolchain with each result.

## Verification workflow

```mermaid
flowchart TD
  Source[Engine source and configuration] --> Rust[Unit and integration tests]
  Rust --> PG[PostgreSQL-backed tenant tests]
  PG --> Pool[PgBouncer tenant-pool test]
  Pool --> Runtime[Health, metrics and SQL checks]
  Runtime --> Evidence[Attestation and recorded evidence]
  Evidence --> Review[Review commit, configuration and results]
```

## 1. Run Rust tests and build the release binary

```bash
cargo test -p proxima-engine
cargo build -p proxima-engine --release
```

The PostgreSQL-backed integration test connects to a local PostgreSQL service at `127.0.0.1:5432` using:

- Database: `proxima_dev`
- User: `proxima`
- Password: `proxima-dev-only`

Start a disposable PostgreSQL 17 instance:

```bash
docker run --rm --name proxima-ci-postgres \
  -e POSTGRES_USER=proxima \
  -e POSTGRES_PASSWORD=proxima-dev-only \
  -e POSTGRES_DB=proxima_dev \
  -p 127.0.0.1:5432:5432 postgres:17
```

Keep it running in one terminal, then run the Rust test command in another. The integration test creates the `proxima_e2e` schema and tenant roles in that database. Use a disposable instance because the test drops and recreates its test schema.

GitHub Actions provisions the PostgreSQL service automatically.

## 2. Run the two-tenant acceptance test

```bash
bash scripts/test-two-tenants.sh
```

This acceptance script creates two non-superuser tenant roles, enables RLS, starts the Engine with tenant-token enforcement, and checks:

- Tenant A sees only Tenant A's record.
- Tenant B sees only Tenant B's record.
- Tenant A's cross-tenant read returns zero rows.
- Tenant A's cross-tenant write is rejected.
- An invalid tenant token is rejected.

The script runs against the disposable PostgreSQL service configured by CI. Use a disposable local database with the documented credentials when running it manually.

## 3. Run the PgBouncer tenant-pool integration test

```bash
bash scripts/test-pgbouncer-pooling.sh
```

This dedicated integration test starts an isolated Docker Compose project containing PostgreSQL, PgBouncer 1.24.1, and Proxima Engine. It generates signed tenant tokens, provisions two least-privilege tenant roles, and exercises the Engine-to-PgBouncer-to-PostgreSQL path.

The test verifies:

- Tenant A and Tenant B each read only their own records.
- Five sequential connections for Tenant A reuse the same PostgreSQL backend PID.
- Five sequential connections for Tenant B reuse the same PostgreSQL backend PID.
- Tenant A and Tenant B use distinct PostgreSQL backend PIDs and separate role-specific PgBouncer pools.
- Cross-tenant reads return zero rows for both tenants.
- A cross-tenant write is rejected by RLS.
- Missing and invalid tenant tokens are rejected.

The test uses an isolated Compose project and removes its own containers and volumes on exit. Stop any other local stack using the same host ports before running it.

The recorded [PgBouncer evidence](../evidence/pgbouncer-transaction-pooling.txt) contains the earlier local execution environment and observed backend PID values.

## 4. Engineering validation: pooling, tenant scale, authentication, and recovery

The completed [engineering case study](ENGINEERING_CASE_STUDY.md) records the observed results and the [published validation evidence](../evidence/engineering-validation-2026-11-09.md) contains the run summaries.

Run the repeatable suites from the repository root:

```bash
bash scripts/test-pgbouncer-pooling.sh
bash scripts/test-concurrent-tenant-isolation.sh
bash scripts/test-auth-recovery.sh
```

The completed runs verified:

- PgBouncer transaction pooling reused each tenant role's backend, maintained separate tenant-role pools, denied cross-tenant reads and writes, and rejected missing or invalid tenant context.
- 100 of 100 tenant checks passed with at most 25 concurrent client processes.
- 1,000 of 1,000 tenant checks passed with at most 50 concurrent client processes; every tenant resolved to its expected PostgreSQL role and exactly its own protected row.
- Valid signed tenant context authenticated; missing, malformed, tampered, and expired tokens were rejected.
- After Engine restart, a still-valid token authenticated and an expired token remained rejected.

The RLS policy and role-attribute scenarios in the case study were executed against an isolated disposable database. Removing the tenant policy failed closed; a deliberately permissive policy and a mapped role with `BYPASSRLS` reproduced cross-tenant exposure; restoring the strict policy and `NOBYPASSRLS` restored the tenant row boundary.

The authentication/recovery test connected directly to the Engine endpoint. The PgBouncer path is verified separately by the pooling suite.

## 5. Verify local HTTP surfaces

With the [Quickstart](QUICKSTART.md) stack running:

```bash
curl -fsS http://127.0.0.1:9090/healthz
curl -fsS http://127.0.0.1:9080/api/status
curl -fsS http://127.0.0.1:9090/metrics
```

Then run a SQL query through port 6432. Health confirms that the HTTP handler responds; the SQL query exercises the PostgreSQL protocol path.

## 6. Verify an attestation ledger

The verifier checks the local hash-linked ledger and validates its signatures. Supply the same signing key, organization ID, and node ID used when records were created. The CLI reads the configured ledger path; it does not automatically extract credentials from the Engine identity JSON file.

```bash
export PROXIMA_ATTESTATION_LEDGER_PATH=data/proxima-attestations.jsonl
export PROXIMA_ORGANIZATION_ID='<recorded-organization-id>'
export PROXIMA_NODE_ID='<recorded-node-id>'
export PROXIMA_NODE_SIGNING_KEY_HEX='<64-hex-character-node-key>'
cargo run -p proxima-engine --bin proxima-attest-verify
```

- Exit code 0: one or more records were present and the chain verified.
- Exit code 2: no records exist or the chain is invalid.
- Exit code 1: the ledger could not be read or verification encountered an I/O/runtime error.

Configure the signing credential and required attestation settings before expecting records. See [Configuration](CONFIGURATION.md).

## 7. Generate an emergency token

The command-line tool issues a short-lived signed break-glass token for a tenant:

```bash
export PROXIMA_TENANT_SIGNING_KEY='<local-test-secret-at-least-32-bytes>'
cargo run -p proxima-engine --bin proxima-break-glass-token -- tenant_a 300
```

The maximum lifetime is 900 seconds (15 minutes). The Engine records used nonces in its replay directory and rejects token reuse. Keep generated tokens private and out of logs.

## 8. CI workflow

The [Rust CI workflow](https://github.com/Agata-Proxima/proxima-engine/actions/workflows/ci.yml) runs on pushes to `main` and pull requests targeting `main`. It provisions PostgreSQL 17, runs the Python CLI tests, executes `cargo test -p proxima-engine`, builds the release binary, runs the two-tenant acceptance script, builds the Docker image, and runs the PgBouncer tenant-pool integration test.

A green workflow run is direct evidence that those configured checks passed for its commit. For deployment acceptance, also verify the target environment's TLS, database roles/RLS, network policy, persistence, and recovery procedures.

## Evidence record

For each verification run, record:

- Exact Git commit SHA and container image digest, when applicable.
- Operating system, CPU architecture, Rust toolchain, and container runtime versions.
- Test commands, exit status, and relevant output.
- PostgreSQL and PgBouncer versions and whether the database was disposable.
- Positive tenant access and denied cross-tenant access results.
- Backend PID observations for each tenant role.
- TLS validation and connection behavior for the target environment.
- Attestation verifier command, trusted key fingerprint, organization/node context, and result.

Never include private keys, passwords, signed tokens, or customer data in published evidence.
