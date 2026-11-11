# Proxima Engine node identity and enrollment

This guide describes how a Proxima Engine node receives a registered identity from a compatible control plane, redeems a one-time enrollment token, and persists its signing credential for later starts.

## Enrollment flow

```mermaid
sequenceDiagram
  participant Admin as Organization admin
  participant Cloud as Agata Proxima Cloud
  participant Engine as Proxima Engine
  participant Store as Persistent node identity
  Admin->>Cloud: Authorize and register node
  Cloud-->>Admin: Node UUID + one-time enrollment token
  Admin->>Engine: Configure enrollment values
  Engine->>Cloud: Redeem token over HTTPS
  Cloud-->>Engine: Node identity and signing credential
  Engine->>Store: Persist node identity
  Engine->>Engine: Start with registered identity
```

The hosted product authorizes organizations and issues registration credentials. The public repository implements the Engine-side enrollment request, response validation, and local identity persistence.

## Local developer identity and hosted enrollment

For offline local development, use [Local developer mode](LOCAL_DEVELOPMENT.md). It generates a self-issued local node identity and signed test tenant tokens without a Cloud account.

For a hosted registered identity, a compatible Agata Proxima control plane issues a node UUID and a short-lived one-time enrollment token. A self-managed deployment can use its own compatible control plane.

## 1. Obtain enrollment values

Start at [agataproxima.com](https://agataproxima.com) and use the authorized organization workflow to register a node and obtain:

- The registered node UUID.
- The HTTPS enrollment URL ending in `/api/v1/nodes/enroll`.
- The one-time enrollment token.

Keep the token in a protected terminal or secret store. Do not paste it into GitHub, screenshots, chat, logs, or public documentation.

Use HTTPS for remote control-plane hosts. Loopback HTTP is reserved for local development.

## 2. One-command Docker installation (hosted Cloud)

This is the supported customer path. Docker Engine and Docker Compose v2 are required on Linux. Windows 10/11 hosts use Docker Desktop with its WSL 2 backend and Linux containers. Agata Proxima does not provision, own, or receive the customer's PostgreSQL credentials.

1. Register a node in Agata Proxima Cloud → Nodes. Copy the Windows PowerShell setup or Linux shell setup shown with the one-time enrollment token.
2. Download the public Proxima Engine source ZIP and extract it on the customer host.
3. Open a terminal in the extracted repository folder, paste the matching setup commands into that same terminal session, and run the installer:
   - Windows: `Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass` followed by `./install-customer.ps1`
   - Linux: `chmod +x ./install-customer.sh` followed by `./install-customer.sh`
4. When prompted, enter the PostgreSQL upstream host and port reachable from inside the Engine container. The installer writes the node's `.env` file and the one-time enrollment token file automatically.
5. Confirm the installer reports a healthy Engine container, then confirm the node reports healthy in Agata Proxima Fleet after its signed heartbeat.

The customer Compose file mounts only the one-time enrollment token as a read-only secret. During the HTTPS enrollment exchange, the Control Plane returns the generated node heartbeat key and a separate organization-scoped tenant-token verification key. The Engine validates both and stores them in the protected node identity file. The Control Plane master signing secret is never sent to customer nodes. The identity file is persisted in a named Docker volume; on Unix, it is created with owner-only permissions. No customer has to download or manually copy a tenant signing key.

The enrollment token is consumed during the first bootstrap. After Fleet shows the node as healthy, replace the contents of `secrets/node_enrollment_token` with the harmless text `enrollment-complete`. Keep the file itself in place because Compose references it on subsequent starts. The persisted identity is used on every later start.

The Windows PowerShell installer checks Docker Desktop's Linux-container mode, Compose v2, the generated environment and token file, then builds and starts the Engine and waits for the actual Docker health state. It is a Windows host installer for the Linux Engine container, not an MSI or a native Windows service binary.

The Linux Bash installer performs the same setup and health checks. Keep the repository's `.env` and `secrets/` directory accessible only to the operators who administer the node. Do not commit them.

The Engine listens on port 6432. By default, the host port is bound to 127.0.0.1. If the application runs in another container, attach it to the shared `proxima-engine-network` and connect to `engine:6432`. Do not expose port 6432 publicly without a customer-controlled firewall rule. The upstream PostgreSQL address must be reachable from inside the Engine container; localhost means the container itself, not the host.

## 3. Configure the Engine — PowerShell

Replace the placeholders with the values issued for the node:

```powershell
$env:PROXIMA_NODE_ID = "<node-uuid>"
$env:PROXIMA_NODE_ENROLLMENT_URL = "https://<control-plane-host>/api/v1/nodes/enroll"
$env:PROXIMA_NODE_ENROLLMENT_TOKEN = "<one-time-token>"

$env:PROXIMA_LISTEN_ADDR = "127.0.0.1:6432"
$env:PROXIMA_UPSTREAM_ADDR = "127.0.0.1:5432"

cargo run -p proxima-engine
```

The Engine sends `POST /api/v1/nodes/enroll` with JSON fields `node_id` and `enrollment_token`. The control plane validates the one-time token and returns the node identity and signing credential. The Engine validates the response and persists the identity.

Remove the bootstrap token after enrollment:

```powershell
Remove-Item Env:PROXIMA_NODE_ENROLLMENT_TOKEN -ErrorAction SilentlyContinue
```

## 4. Configure the Engine — Bash

```bash
export PROXIMA_NODE_ID="<node-uuid>"
export PROXIMA_NODE_ENROLLMENT_URL="https://<control-plane-host>/api/v1/nodes/enroll"
export PROXIMA_NODE_ENROLLMENT_TOKEN="<one-time-token>"
export PROXIMA_LISTEN_ADDR="127.0.0.1:6432"
export PROXIMA_UPSTREAM_ADDR="127.0.0.1:5432"
cargo run -p proxima-engine
unset PROXIMA_NODE_ENROLLMENT_TOKEN
```

Set the values in the same process environment that starts the Engine. The Engine reads process environment variables; it does not automatically load a plain `.env` file.

## 5. Persist and protect the identity

Default identity paths:

- Windows: `%LOCALAPPDATA%\AgataProxima\node-identity.json`, when `LOCALAPPDATA` exists.
- Other environments: `data/node-identity.json`.

Set `PROXIMA_NODE_IDENTITY_PATH` to choose another path. The identity file contains the node ID, organization ID, and a 32-byte signing credential. Restrict file permissions and include the file in protected backups.

The Engine reuses a valid saved identity on later starts, so the one-time enrollment token is needed only for the initial bootstrap. Use a separate identity path for each node.

When the Engine has a registered node identity and a compatible heartbeat endpoint, it sends an HMAC-SHA256 signed liveness report every 30 seconds. The heartbeat uses the enrolled node signing key, is independent of the hourly attestation ledger, and does not assert tenant isolation. Fleet marks a node degraded after 90 seconds without a heartbeat and offline after five minutes. The control plane rejects stale, replayed, incorrectly signed, or revoked-node heartbeats.

## 6. Credential reference

| Variable or file | Purpose | Handling |
|---|---|---|
| `PROXIMA_NODE_ENROLLMENT_TOKEN` | One-time bootstrap credential | Short-lived; remove after enrollment |
| `PROXIMA_NODE_IDENTITY_PATH` | Persistent identity file | Contains a signing credential; protect it |
| `PROXIMA_NODE_SIGNING_KEY_HEX` | 32-byte node signing key, hex encoded | Normally loaded from saved identity; never commit |
| `PROXIMA_TENANT_SIGNING_KEY` | HMAC key for application-signed tenant context | Separate from node credentials; at least 32 bytes |
| `PROXIMA_ATTESTATION_INGEST_TOKEN` | Optional bearer credential for a compatible evidence receiver | Use the required `aga_` prefix; never commit |

These credentials serve different trust boundaries. Keep each in its designated configuration field and rotate it through the corresponding issuer.

## Troubleshooting

- **401 Unauthorized:** verify that the node UUID and one-time token belong together and that the token is valid and unused.
- **Connection refused or timeout:** check DNS, routing, firewall rules, and the configured enrollment URL.
- **TLS certificate error:** use the correct HTTPS hostname and a trusted certificate chain.
- **Identity file error:** check the path, JSON format, and read/write permissions.
- **Engine exits before listening:** inspect the startup error and verify all supplied enrollment values.

See [Configuration](CONFIGURATION.md), [Operations](OPERATIONS.md), [Customer deployment executor](CUSTOMER_DEPLOYMENT_EXECUTOR.md), and [Cloud control-plane boundary](CLOUD_CONTROL_PLANE.md).
