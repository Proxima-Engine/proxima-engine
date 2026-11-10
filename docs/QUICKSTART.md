# Quickstart: run Proxima Engine and query PostgreSQL

Start a local PostgreSQL database, PgBouncer transaction pool, and Proxima Engine. Send a SQL query through the PostgreSQL wire-protocol proxy and inspect health and Prometheus metrics. This local path requires no hosted account and no pre-existing database.

## Requirements

- Git
- Docker Desktop (Windows/macOS) or Docker Engine and Docker Compose (Linux)
- For the optional native build: stable Rust and Cargo
- For host-side examples: curl and psql; the Compose walkthrough runs psql inside the database container

## 1. Clone and start the stack

```bash
git clone https://github.com/Agata-Proxima/proxima-engine.git
cd proxima-engine
docker compose -f compose.dev.yaml up --build -d
```

PowerShell users can run the same Docker command. To edit local settings first, copy the example environment file with `Copy-Item .env.example .env` in PowerShell or `cp .env.example .env` in Bash.

The development profile starts:

- PostgreSQL on a private Compose network.
- PgBouncer 1.24.1 in transaction-pooling mode, with a default pool size of two.
- Proxima Engine on port 6432, published to host loopback only; its upstream is PgBouncer.
- The local status page on `127.0.0.1:9080`.
- Health and Prometheus metrics on `127.0.0.1:9090`.

The default PostgreSQL password is `local-only-change-me`. The matching local PgBouncer credential is stored in `pgbouncer-userlist.txt`. If you change `POSTGRES_PASSWORD` in `.env`, update the matching `proxima` entry in that file as well. These credentials are for the disposable local profile.

## 2. Confirm Engine health and status

```bash
curl -fsS http://127.0.0.1:9090/healthz
curl -fsS http://127.0.0.1:9080/health
curl -fsS http://127.0.0.1:9080/api/status
```

The health routes return `ok`. The JSON status route reports the active listener/upstream settings and whether tenant-token enforcement and TLS are configured.

Windows PowerShell:

```powershell
Invoke-RestMethod http://127.0.0.1:9090/healthz
Invoke-RestMethod http://127.0.0.1:9080/health
Invoke-RestMethod http://127.0.0.1:9080/api/status
```

Keep the status page and metrics listener on loopback or a restricted private network.

## 3. Create a PostgreSQL table

This command connects directly to the local database to create synthetic quickstart data:

```bash
docker compose -f compose.dev.yaml exec postgres psql -U proxima -d appdb -c "CREATE TABLE IF NOT EXISTS quickstart_messages (message text NOT NULL); TRUNCATE quickstart_messages; INSERT INTO quickstart_messages VALUES ('hello through Proxima');"
```

## 4. Query through Proxima Engine

The client connects to the Engine. The Engine forwards the PostgreSQL session through PgBouncer to PostgreSQL:

```bash
docker compose -f compose.dev.yaml exec postgres psql "host=engine port=6432 dbname=appdb user=proxima password=local-only-change-me sslmode=disable" -c "SELECT * FROM quickstart_messages;"
```

Expected result: one row containing `hello through Proxima`.

This confirms the local container build, PostgreSQL connectivity, Engine listener, PgBouncer upstream, and end-to-end SQL forwarding.

## 5. Inspect Prometheus metrics

```bash
curl -fsS http://127.0.0.1:9090/metrics
```

Look for metrics such as:

- `proxima_engine_connections_accepted_total`
- `proxima_engine_active_connections`
- `proxima_engine_processed_queries_total`

These process-local counters reset when the Engine restarts. Scrape them from a private monitoring network.

## 6. Stop the stack

```bash
docker compose -f compose.dev.yaml down
```

Named volumes remain available for the next local run. To permanently delete the disposable development data:

```bash
docker compose -f compose.dev.yaml down -v
```

## Next: verify tenant isolation

The quickstart starts with tenant-token enforcement disabled so the first SQL connection is straightforward.

Continue with the [Tenant isolation guide](TENANT_ISOLATION.md). It creates two PostgreSQL roles, enables RLS, configures signed tenant context, and tests permitted and denied cross-tenant operations. The local stack routes Engine traffic through PgBouncer transaction pooling, so the guide also gives you the same topology used by the repository's [recorded pooling evidence](../evidence/pgbouncer-transaction-pooling.txt).

## Run natively without Docker

If PostgreSQL is available at `127.0.0.1:5432`:

```bash
cargo test -p proxima-engine
cargo build -p proxima-engine --release
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

Connect your PostgreSQL client to port 6432. The Engine reads configuration from its process environment; see [Configuration](CONFIGURATION.md).

## Troubleshooting

| Symptom | First check | Guide |
|---|---|---|
| Compose cannot build | Docker is running and dependencies can be downloaded | [Deployment](DEPLOYMENT.md) |
| Health endpoint refuses connection | Inspect `docker compose -f compose.dev.yaml ps` and container logs | [Operations](OPERATIONS.md) |
| Engine cannot connect upstream | Check PgBouncer health, role credentials, and `PROXIMA_UPSTREAM_ADDR` | [Operations](OPERATIONS.md) |
| Health succeeds but SQL fails | Confirm PostgreSQL readiness and proxy host/port | [API reference](API.md) |
| Tenant rows are not isolated | Check token, role mapping, grants, and RLS policies | [Tenant isolation](TENANT_ISOLATION.md) |
| Enrollment fails | Check token expiry, node identity persistence, and variable names | [Node enrollment](NODE_ENROLLMENT.md) |
| You need a hosted account or plan | Use the hosted product | [Cloud boundary](CLOUD_CONTROL_PLANE.md) · [Billing](BILLING.md) |

## Next steps

- [ ] Run the local SQL query through Proxima Engine.
- [ ] Review the [architecture](ARCHITECTURE.md) and [configuration](CONFIGURATION.md).
- [ ] Complete the [tenant isolation guide](TENANT_ISOLATION.md).
- [ ] Connect an existing application using [driver integration recipes](INTEGRATIONS.md).
- [ ] Review [deployment](DEPLOYMENT.md), [security](SECURITY.md), and [operations](OPERATIONS.md) before routing sensitive workloads.

## Install a registered customer node (Windows and Linux)

This section installs a registered Engine node connected to Agata Proxima Cloud. It is different from the disposable local development stack above.

### Windows 10/11 and Windows Server

**Downloads required**

- [Download the Engine source ZIP](https://github.com/Proxima-Engine/proxima-engine/archive/refs/heads/feat/cloud-node-heartbeat-20261110.zip) and extract it.
- From Agata Proxima Cloud → Node Management, download the registered node's `.env`, one-time `node_enrollment_token`, and `tenant_signing_key`.
- The ZIP includes [install-customer.ps1](../install-customer.ps1) and [compose.customer.yaml](../compose.customer.yaml). These files must stay together in the extracted folder.

**Prerequisites**

Install Docker Desktop with its WSL 2 backend, enable Linux containers, and start Docker Desktop. Confirm these commands work in PowerShell:

```powershell
docker info --format '{{.OSType}}'
docker compose version
```

The first command must print `linux`; Compose must report version 2.x. Proxima Engine is a Linux container, and Docker Desktop runs it on Windows through its Linux backend.

**Prepare the downloaded files**

1. Put the node-specific `.env` in the extracted repository root, beside `compose.customer.yaml`.
2. Create a folder named `secrets` in that same directory.
3. Put the downloaded one-time token at `secrets/node_enrollment_token`.
4. Put the tenant signing key at `secrets/tenant_signing_key`.
5. Keep the folder accessible only to the operators who administer this node. The secret filenames have no `.txt` extension; enable File name extensions in File Explorer to verify them.

**Install**

Open PowerShell in the extracted folder and run:

```powershell
Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass
.\install-customer.ps1
```

The installer validates the files, Docker daemon, Linux-container mode, Compose v2 configuration, starts the Engine, and checks the actual Docker container health state. It waits up to 120 seconds and prints container logs if health does not pass. On success, it prints the Engine endpoint `127.0.0.1:6432`.

Confirm the node becomes healthy in Agata Proxima Fleet after its signed heartbeat. The Engine stores its enrolled node identity in a named Docker volume. Keep `secrets/tenant_signing_key` in place for subsequent starts; the one-time enrollment token is consumed only during first enrollment.

**Operate**

```powershell
docker compose -f compose.customer.yaml ps
docker compose -f compose.customer.yaml logs --tail 100 engine
docker compose -f compose.customer.yaml restart engine
docker compose -f compose.customer.yaml down
```

The upstream PostgreSQL hostname must be reachable from inside the Linux container. Do not set it to `localhost` unless PostgreSQL runs in that same container. Keep port 6432 private; use a private network and firewall policy when the application is on another host.

### Linux

Install Docker Engine and the Docker Compose v2 plugin. Place the same three node downloads and the `secrets/` files in the extracted repository root, then run:

```bash
chmod +x ./install-customer.sh
./install-customer.sh
```

The Bash installer validates the files and Compose configuration, builds and starts the Engine, and waits for the Docker health check.

### Installation scope

The PowerShell installer installs and operates the Proxima Engine Linux container on a Windows host. It is not an MSI package or a native Windows executable/service. The reference deployment-executor service installer uses Linux systemd; executor service installation on Windows is not included in this Engine installer. See [Node enrollment](NODE_ENROLLMENT.md) and [Customer-managed deployment executor](CUSTOMER_DEPLOYMENT_EXECUTOR.md) for the complete enrollment and deployment lifecycle.
