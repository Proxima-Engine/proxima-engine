# Customer-managed Engine deployment executor

This reference executor connects Agata Proxima's signed deployment event to a customer's Docker Compose installation of Proxima Engine. It runs inside the customer's infrastructure and has permission to control the customer's Engine container.

## What it does

1. Receives deployment.created over HTTPS.
2. Verifies the exact raw-body HMAC-SHA256 signature and five-minute timestamp window.
3. Rejects events for a different node or a release version outside the customer's explicit allowlist.
4. Sends the applying callback with a stable executor and execution ID.
5. Pulls the requested versioned Engine image and applies the requested state using fixed Docker Compose arguments. For `running`, it starts the Engine; for `stopped`, it stops and recreates the container without starting it, so the applied version matches the image configured for the next start. It never executes command text from a webhook.
6. Checks the real container state. A running Engine must pass its local /healthz endpoint, and a stopped Engine must not appear among running services.
7. Sends healthy only after the check passes. If a running rollout fails and a prior known-good release is recorded, it restores that release and reports rolled_back.
8. Persists completed deployment IDs locally. It can recover from a lost local completion marker by inspecting the authoritative Control Plane deployment result before retrying side effects.

The draining state is intentionally rejected because a safe drain operation requires an application-specific connection-drain controller. Do not select that state unless you have configured and tested such a controller.

## Prerequisites

- Linux or Windows host with Docker Engine and Docker Compose v2.
- Node.js 22 or newer.
- The Engine already installed with compose.customer.yaml.
- A published Engine container image for each release version you intend to deploy.
- One organization-scoped API key with permission to write deployment results.
- Exactly one enabled HTTPS webhook subscribed to deployment.created for the organization.

The Engine image is published by the tagged-release workflow. For a tag such as v0.1.0, the workflow publishes both 0.1.0 and v0.1.0 plus latest. Make the ghcr.io/proxima-engine/proxima-engine package public before asking unauthenticated customer hosts to pull it; otherwise configure Docker registry authentication on the customer host.

One executor webhook is configured per organization. The reference executor can manage multiple registered Engine nodes when their Compose projects are on the same Docker host: configure a target map file and give each node its own project directory, Compose file, state directory and approved version list. For nodes on separate Docker hosts or clusters, use a customer-owned orchestrator/custom executor; this reference implementation does not manage remote Docker contexts.

Copy [the multi-node target map template](../deployment-executor/targets.example.json) and replace its example UUIDs, paths and release allowlists with the customer's actual values. Each node must use a separate project directory so its Compose project name and persistent node identity volume remain isolated. Example target map (save as targets.json):

```json
{
  "00000000-0000-4000-8000-000000000001": {
    "project_dir": "/opt/proxima/node-a",
    "compose_file": "compose.customer.yaml",
    "state_dir": "/var/lib/agata-deployment-executor/node-a",
    "allowed_versions": ["0.1.0", "0.1.1"]
  },
  "00000000-0000-4000-8000-000000000002": {
    "project_dir": "/opt/proxima/node-b",
    "compose_file": "compose.customer.yaml",
    "state_dir": "/var/lib/agata-deployment-executor/node-b",
    "allowed_versions": ["0.1.0"]
  }
}
```

Set PROXIMA_DEPLOYMENT_TARGETS_FILE to this file in the executor environment. Each project directory must contain its own Compose file and .env configuration. If this variable is not set, the executor supports the simpler single-node PROXIMA_NODE_ID and PROXIMA_ENGINE_ALLOWLIST settings.


## Install the Engine (customer node)

The dashboard gives the customer a node-specific `.env`, a one-time enrollment-token file and a tenant-signing-key file. The customer does not need to hand-write Docker Compose configuration or paste secrets into shell commands.

1. Install Docker Desktop (Windows) or Docker Engine with the Compose v2 plugin (Linux).
2. Download the Engine ZIP from the node setup screen and extract it.
3. In the extracted folder, create a `secrets` directory.
4. Place the downloaded `.env` in the repository root. Place the one-time token at `secrets/node_enrollment_token` and the tenant signing key at `secrets/tenant_signing_key`.
5. Run the supplied installer from that folder:

   **Windows PowerShell**
   ```powershell
   .\\install-customer.ps1
   ```

   **Linux**
   ```bash
   chmod +x ./install-customer.sh
   ./install-customer.sh
   ```

The installer validates the required files and Docker Compose configuration, builds the Engine image locally, starts the container, and waits for its real Docker health check. It prints the container logs if startup fails. The Engine consumes the one-time enrollment token from the mounted secret, persists its node identity in a Docker volume, and begins signed heartbeats. The token is not needed again after successful enrollment. Keep the `.env` and `secrets` directory private; never commit or email them.

The Engine listens on port 6432 and binds to loopback by default. Keep that binding when the application runs on the same host. If the application is on another host or container network, deliberately configure a private reachable bind address/network and firewall policy; do not expose PostgreSQL proxy traffic to the public internet.

## Install

Download this repository's ZIP and extract it to /opt/proxima on the same customer host that runs the Engine Compose project. This is the default path used by the customer Node setup and supplied systemd unit; if you choose another directory, update PROXIMA_DEPLOYMENT_PROJECT_DIR and the systemd WorkingDirectory/ExecStart paths accordingly. Create a protected environment file for the executor. Do not commit it:

```dotenv
AGATA_API_BASE_URL=https://api.agataproxima.com
AGATA_API_KEY=aga_<organization-scoped-write-key>
AGATA_WEBHOOK_SIGNING_SECRET=<one-time-webhook-signing-secret>
PROXIMA_NODE_ID=<registered-node-uuid>
PROXIMA_DEPLOYMENT_EXECUTOR_ID=customer-prod-engine-01
PROXIMA_ENGINE_ALLOWLIST=0.1.0,0.1.1
# For a same-host multi-node fleet, replace the two single-node settings above with:
# PROXIMA_DEPLOYMENT_TARGETS_FILE=/etc/agata/targets.json
PROXIMA_DEPLOYMENT_PROJECT_DIR=/opt/proxima
PROXIMA_DEPLOYMENT_COMPOSE_FILE=compose.customer.yaml
PROXIMA_DEPLOYMENT_STATE_DIR=/var/lib/agata-deployment-executor
PORT=8789
```

The allowlist must contain only Engine releases the customer has reviewed and approved. Incoming webhook values are never added to it.

The executor binds to 127.0.0.1 only. Put a customer-managed HTTPS reverse proxy in front of it. For Caddy, copy [the example Caddyfile](../deployment-executor/Caddyfile.example), replace executor.example.com with a DNS name pointing to the customer host, and reload Caddy. Caddy obtains and renews the TLS certificate automatically when ports 80 and 443 are reachable.

Example:

```caddyfile
executor.example.com {
    reverse_proxy 127.0.0.1:8789
}
```

Run the service behind a customer-managed HTTPS reverse proxy at:

POST https://<customer-executor-host>/webhooks/agata/deployments

For a smoke test:

```bash
set -a
. /etc/agata-deployment-executor.env
set +a
node ./deployment-executor/receiver.mjs
```

### Run as a Linux service

For the standard single-host installation, place the downloaded `deployment-executor.env` in `/opt/proxima` and run the supplied installer:

```bash
sudo ./install-deployment-executor.sh
```

The installer checks Node.js 22+, Docker Compose, the executor environment file and the service unit; creates the restricted service account; installs the environment file and systemd unit with protected permissions; grants the service access to the Docker socket; and enables the service. It does not configure the public HTTPS reverse proxy or DNS. Configure those separately before creating deployments.

For manual installation or a non-standard host, the repository includes a systemd unit template at `deployment-executor/agata-deployment-executor.service`. The equivalent manual steps are:

```bash
if ! id agata-deployer >/dev/null 2>&1; then
  if getent passwd 10001 >/dev/null; then echo 'UID 10001 is already in use; choose and configure a matching Engine UID before continuing.' >&2; exit 1; fi
  sudo useradd --system --uid 10001 --create-home --shell /usr/sbin/nologin agata-deployer
fi
sudo usermod -aG docker agata-deployer
sudo install -d -o root -g root -m 0700 /etc/agata
sudo install -d -o agata-deployer -g docker -m 0700 /var/lib/agata-deployment-executor
sudo chown agata-deployer:docker /opt/proxima/.env
sudo chmod 0640 /opt/proxima/.env
sudo chown -R agata-deployer:agata-deployer /opt/proxima/secrets
sudo chmod 0700 /opt/proxima/secrets
sudo chmod 0400 /opt/proxima/secrets/*
sudo install -o root -g root -m 0600 deployment-executor.env /etc/agata/deployment-executor.env
sudo install -o root -g root -m 0644 /opt/proxima/deployment-executor/agata-deployment-executor.service /etc/systemd/system/agata-deployment-executor.service
sudo systemctl daemon-reload
sudo systemctl enable --now agata-deployment-executor
sudo systemctl status agata-deployment-executor
sudo journalctl -u agata-deployment-executor -f
```

The service user is assigned UID 10001 to match the non-root Engine container, so it can read the mounted secret files without making them world-readable. Confirm UID 10001 is available before creating the account. The service user must be able to read each configured Compose project and .env file, and write to each configured executor state directory. The supplied unit allows writes to /var/lib/agata-deployment-executor; if your target map uses another state directory, add it to ReadWritePaths and create it with agata-deployer ownership before starting the service. Membership in the docker group grants host-administrator-equivalent control; review that privilege and restrict the host accordingly.

The reverse proxy must preserve the raw request body and forward X-Agata-Signature, X-Agata-Delivery-Id, X-Agata-Event, and X-Agata-Event-Id. Keep its upstream request timeout at or above six minutes: Agata Proxima allows deployment.created delivery up to six minutes for image pulls, Engine restarts and runtime health checks. The executor returns only after the Control Plane has accepted the execution result.

## Configure Agata Proxima

The recommended path is the guided setup in Deployments → Set up deployment executor. Select a healthy Engine node, enter the public HTTPS endpoint, executor identity, approved Engine versions and customer host paths. Agata Proxima creates a dedicated organization-scoped operator API key and signed deployment.created webhook, then returns a one-time deployment-executor.env file. The current API-key model grants operator-level organization access rather than deployment-only scopes; keep this key dedicated to the executor, store it as a protected secret, and revoke it when the executor is retired. Download it before leaving the result screen. If webhook creation fails after the API key is created, the wizard attempts to revoke the key.

Manual setup is also available:
1. Open Developer → API keys and create a dedicated write-capable key for the executor.
2. Open Developer → Webhooks and create one HTTPS endpoint using the route above.
3. Subscribe to exactly deployment.created. Do not use * for this executor.
4. Copy the signing secret shown once and store it as AGATA_WEBHOOK_SIGNING_SECRET.
5. Confirm there is only one enabled webhook subscribed to deployment.created for the organization.
6. Confirm the target node is healthy in Node Management.
7. Create a staging deployment using a version in the allowlist.

## Supported states and rollback

- running: pull the versioned image, start the Engine and require /healthz to pass.
- stopped: pull the versioned image, stop the Engine and verify the service is no longer running.
- draining: rejected. Add an application-specific drain controller before enabling this state.

A failed running rollout attempts to restore the previous version only when that version is recorded as known-good and remains in the allowlist. The executor reports rolled_back only after the restored Engine passes its health check. If rollback cannot be verified, it reports failed.

## Security and operations

- This process can control Docker and therefore has high privilege on its host. Run it as a dedicated OS identity and restrict access to its environment file.
- Access to the Docker socket or Docker group is effectively host-administrator access. Do not expose the Docker socket over TCP.
- Keep the API key, webhook secret, and node identity separate. The executor API key is an organization-scoped operator credential, so protect it accordingly. Rotate the API key and webhook secret independently.
- Keep the executor state directory persistent and protected. It stores deployment IDs and release metadata, not API keys or webhook secrets.
- The webhook receiver returns 503 when execution or callback delivery cannot be completed, allowing the Control Plane delivery queue to retry.
- Test invalid signatures, duplicate delivery, image pull failure, health-check failure, rollback success and rollback failure in staging before production use.

Agata Proxima records deployment intent and verified execution results. The customer remains in control of the Docker host, database, release approvals and infrastructure credentials.
