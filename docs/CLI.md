# Agata CLI for Proxima Engine

The public Engine repository includes a Python 3.10+ command-line tool implemented with the Python standard library. It bootstraps local development identity, creates signed tenant test tokens, checks local diagnostics, and reports Engine status.

Run commands from the repository root:

```bash
python scripts/agata.py --help
python scripts/agata.py init
python scripts/agata.py token --tenant tenant_a --ttl 300
python scripts/agata.py doctor
python scripts/agata.py status
```

On Windows PowerShell, use the same commands with `python`. On Unix-like systems, `python3` may be the configured interpreter.

## Commands

The Rust Policy Guard binary also exposes the adapter maturity catalog:

```bash
cargo run -p proxima-engine --bin proxima-policy-guard -- adapters
```

The `adapters` command prints the versioned Proxima Security Core catalog. PostgreSQL is marked `in_development`; MySQL, MariaDB, Microsoft SQL Server, MongoDB and CockroachDB are marked `planned` with no enabled capabilities. A planned entry is not a supported database integration.

The PostgreSQL `audit` command is a catalog posture inspection, not a semantic policy verifier. Its JSON deliberately reports `security_posture: unknown` and `access_decision: deny`, even when it finds no catalog findings. A zero exit code means the inspection completed without catalog findings; it does not certify tenant isolation.


Validate a database-neutral policy document against the shared contract without connecting to a database:

```bash
cargo run -p proxima-engine --bin proxima-policy-guard -- validate-policy ./policy.json
```

The command checks the versioned envelope, explicit resources, tenant ownership keys and unique operations. It does not prove that any database adapter has enforced the policy.


| Command | Purpose |
|---|---|
| `init` | Generate local node identity and tenant-signing credentials in `.proxima-dev/` |
| `token` | Mint a short-lived signed tenant-context token |
| `verify-token` | Validate a token against the configured local signing key |
| `doctor` | Check local Engine endpoints and development prerequisites |
| `status` | Read local Engine status information |

Use `python scripts/agata.py <command> --help` to inspect command-specific arguments.

## Local credential setup

The `init` command creates `.proxima-dev/dev-config.json` and `.proxima-dev/node-identity.json`. It refuses to overwrite existing credentials. Configure the Engine's `PROXIMA_TENANT_SIGNING_KEY` with the literal `tenant_signing_key` value from the generated config.

The `.proxima-dev/` directory contains secrets and is ignored by Git. Keep it local and do not publish its contents.

The CLI operates on local development identity and local Engine endpoints. Hosted node registration and account workflows are managed separately by Agata Proxima Cloud.

## Token handling

`verify-token` accepts a generated token as a positional argument. Shell command-line arguments may appear in process listings, so use this mode with local test credentials only. Keep production tokens in protected process environments and secret stores.

## Verify tenant access

`doctor` and `status` inspect local Engine HTTP endpoints. To test database access boundaries, follow [Tenant isolation](TENANT_ISOLATION.md) with a disposable PostgreSQL database.

Run the CLI unit tests:

```bash
python -m unittest discover -s tests_cli -v
```

For the full Rust and PostgreSQL verification path, see [Verification](VERIFICATION.md).
