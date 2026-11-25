# CockroachDB quickstart

CockroachDB uses the Engine's PostgreSQL wire listener. Your application keeps its PostgreSQL-compatible driver.

## 1. Clone and build

```bash
git clone https://github.com/Proxima-Engine/proxima-engine.git
cd proxima-engine
cargo build --locked --release -p proxima-engine --bin proxima-engine
```

## 2. Configure the CockroachDB endpoint

```dotenv
PROXIMA_LISTEN_ADDR=127.0.0.1:6432
PROXIMA_UPSTREAM_ADDR=cockroach.example:26257
PROXIMA_TENANT_ROLE_PREFIX=proxima_tenant_
PROXIMA_UPSTREAM_TLS_MODE=verify-full
PROXIMA_UPSTREAM_TLS_CA_FILE=/etc/proxima/tls/cockroach-ca.pem
PROXIMA_UPSTREAM_TLS_SERVER_NAME=cockroach.example
```

Create non-admin tenant roles and forced row-level-security policies as described in [CockroachDB guide](COCKROACHDB_COMPATIBILITY.md). Do not use root or cluster-admin credentials for tenant traffic.

## 3. Run and verify

```bash
RUST_LOG=info cargo run --release -p proxima-engine
bash scripts/test-cockroachdb-tenant-isolation-ci.sh
```

The acceptance script provisions a disposable CockroachDB 25.2 node and verifies tenant-local operations, cross-tenant filtering/write rejection and invalid-token rejection. Connect clients to `127.0.0.1:6432` with the signed tenant startup parameter described in the guide.

**Next:** [Complete CockroachDB guide](COCKROACHDB_COMPATIBILITY.md) · [Tenant isolation](TENANT_ISOLATION.md)
