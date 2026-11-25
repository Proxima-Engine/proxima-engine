# PostgreSQL

Proxima Engine provides a native PostgreSQL wire listener with signed tenant context, dedicated upstream roles and PostgreSQL Row-Level Security.

## Clone and run

```sh
git clone https://github.com/Proxima-Engine/proxima-engine.git
cd proxima-engine
docker compose -f compose.dev.yaml up --build -d
curl -fsS http://127.0.0.1:9090/healthz
curl -fsS http://127.0.0.1:9080/health
```

Create a local test table:

```sh
docker compose -f compose.dev.yaml exec postgres psql -U proxima -d appdb -c "CREATE TABLE IF NOT EXISTS quickstart_messages (message text NOT NULL); TRUNCATE quickstart_messages; INSERT INTO quickstart_messages VALUES ('hello through Proxima');"
```

Query through the Engine listener:

```sh
docker compose -f compose.dev.yaml exec postgres psql "host=engine port=6432 dbname=appdb user=proxima password=local-only-change-me sslmode=disable" -c "SELECT * FROM quickstart_messages;"
```

Expected result: one row containing `hello through Proxima`.

## Build and run natively

```sh
cargo build --release -p proxima-engine
export PROXIMA_UPSTREAM_ADDR=127.0.0.1:5432
export PROXIMA_LISTEN_ADDR=127.0.0.1:6432
cargo run -p proxima-engine
```

PowerShell:

```powershell
$env:PROXIMA_UPSTREAM_ADDR = "127.0.0.1:5432"
$env:PROXIMA_LISTEN_ADDR = "127.0.0.1:6432"
cargo run -p proxima-engine
```

## Tenant isolation

1. Create tenant roles with [TENANT_ISOLATION.md](TENANT_ISOLATION.md).
2. Enable signed tenant context and row-level security.
3. Configure the trusted application to issue the tenant token.
4. Connect through the Engine listener using the PostgreSQL driver.
5. Run the two-tenant acceptance test:

```sh
cargo test -p proxima-engine --test postgres_integration -- --ignored
```

## Application drivers and operations

- [Node.js, Python and Rust drivers](INTEGRATIONS.md)
- [Runtime configuration](CONFIGURATION.md)
- [Deployment and TLS](DEPLOYMENT.md)
- [Health, metrics and recovery](OPERATIONS.md)
- [Verification workflow](VERIFICATION.md)

## Cloud assignment

In **Agata Proxima Cloud → Databases**, register the PostgreSQL endpoint, enroll a customer-hosted Engine node, assign the target and create tenant bindings. Cloud delivers the signed tenant configuration; Engine applies the target role and reports its applied revision.

