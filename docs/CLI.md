# Local Engine CLI for Proxima Engine

The public Engine repository includes a Python 3.10+ local-development command-line tool implemented with the Python standard library. It bootstraps local node identity, creates signed tenant test tokens, checks local diagnostics, and reports the local Engine status. This tool is separate from the Node.js Cloud API CLI distributed from the Agata Proxima website.

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

The Engine CLI operates only on local development identity and local Engine endpoints. It does not create Cloud organizations, API keys, tenants, policies or hosted nodes. For the separate Node.js Cloud API CLI, see the [downloadable CLI guide](https://agataproxima.com/developers/cli) and [standalone CLI ZIP](https://agataproxima.com/downloads/agata-proxima-cli.zip).

## Token handling

`verify-token` accepts a generated token as a positional argument. Shell command-line arguments may appear in process listings, so use this mode with local test credentials only. Keep production tokens in protected process environments and secret stores.

## Verify tenant access

`doctor` and `status` inspect local Engine HTTP endpoints. To test database access boundaries, follow [Tenant isolation](TENANT_ISOLATION.md) with a disposable PostgreSQL database.

Run the CLI unit tests:

```bash
python -m unittest discover -s tests_cli -v
```

For the full Rust and PostgreSQL verification path, see [Verification](VERIFICATION.md).
