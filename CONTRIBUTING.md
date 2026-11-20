# Contributing to Proxima Engine

Thanks for considering a contribution. This repository contains the public Rust Engine; changes to a separate hosted management service do not belong here.

## Before you start

- Search [existing issues](https://github.com/Proxima-Engine/proxima-engine/issues) before opening a new one.
- For a vulnerability, follow [SECURITY.md](SECURITY.md); do not publish exploit details in a public issue.
- For meaningful behavior changes, open an issue first so the expected behavior can be agreed.

## Local setup

Install a stable Rust toolchain and Docker with Compose. Start the disposable local stack when testing database connectivity:

```bash
docker compose -f compose.dev.yaml up --build -d
```

Run the standard checks:

```bash
cargo fmt --all -- --check
cargo test -p proxima-engine
cargo build -p proxima-engine --release
docker build -t proxima-engine:contribution .
```

The PostgreSQL integration test requires the disposable database configuration documented in [Verification](docs/VERIFICATION.md). Do not point destructive integration tests at a database containing data you need.

## Pull request checklist

- [ ] Explain the user problem and intended behavior.
- [ ] Add or update tests for behavior changes.
- [ ] Run the relevant Rust tests and release build.
- [ ] Update docs when configuration, endpoints, security assumptions, or examples change.
- [ ] Explain compatibility and security impact.
- [ ] Remove credentials, private keys, local state, and customer data from the diff.
- [ ] Do not claim an audit, certification, or performance result without evidence.

Keep changes focused and error handling explicit. Never log tenant tokens, passwords, signing keys, enrollment tokens, or full connection strings.

## Project scope

Proxima Engine, its source, tests, local status page, configuration, and documentation are maintained here. The hosted control plane and its private management application are separate and are not part of this repository.
