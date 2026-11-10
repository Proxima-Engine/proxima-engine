#!/usr/bin/env bash
set -Eeuo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ENV_SOURCE="$ROOT/deployment-executor.env"
UNIT_SOURCE="$ROOT/deployment-executor/agata-deployment-executor.service"
RECEIVER="$ROOT/deployment-executor/receiver.mjs"

if [[ "$(id -u)" -ne 0 ]]; then
  echo "Run this installer with sudo: sudo ./install-deployment-executor.sh" >&2
  exit 1
fi
if [[ "$ROOT" != "/opt/proxima" ]]; then
  echo "Place the reviewed Engine bundle in /opt/proxima before installing the executor. Current directory: $ROOT" >&2
  exit 1
fi
for file in "$ENV_SOURCE" "$UNIT_SOURCE" "$RECEIVER"; do
  [[ -f "$file" ]] || { echo "Missing required file: $file" >&2; exit 1; }
done
command -v node >/dev/null 2>&1 || { echo "Install Node.js 22 or newer first." >&2; exit 1; }
node -e 'if (Number(process.versions.node.split(".")[0]) < 22) process.exit(1)' || { echo "Node.js 22 or newer is required." >&2; exit 1; }
command -v docker >/dev/null 2>&1 || { echo "Docker Engine is required." >&2; exit 1; }
docker compose version >/dev/null
command -v systemctl >/dev/null 2>&1 || { echo "This installer requires systemd." >&2; exit 1; }
for key in AGATA_API_BASE_URL AGATA_API_KEY AGATA_WEBHOOK_SIGNING_SECRET PROXIMA_DEPLOYMENT_EXECUTOR_ID; do
  grep -Eq "^${key}=.+" "$ENV_SOURCE" || { echo "deployment-executor.env is missing $key. Download it from Deployments → Set up deployment executor." >&2; exit 1; }
done
grep -Eq '^PROXIMA_NODE_ID=.+' "$ENV_SOURCE" && grep -Eq '^PROXIMA_ENGINE_ALLOWLIST=.+' "$ENV_SOURCE" || grep -Eq '^PROXIMA_DEPLOYMENT_TARGETS_FILE=.+' "$ENV_SOURCE" || {
  echo "Configure PROXIMA_NODE_ID + PROXIMA_ENGINE_ALLOWLIST or PROXIMA_DEPLOYMENT_TARGETS_FILE in deployment-executor.env." >&2
  exit 1
}

if ! id agata-deployer >/dev/null 2>&1; then
  if getent passwd 10001 >/dev/null; then
    echo "UID 10001 is already in use. Resolve the UID conflict before installing." >&2
    exit 1
  fi
  useradd --system --uid 10001 --create-home --shell /usr/sbin/nologin agata-deployer
fi
getent group docker >/dev/null || { echo "Docker group not found. Install Docker Engine first." >&2; exit 1; }
usermod -aG docker agata-deployer
install -d -o root -g root -m 0700 /etc/agata
install -d -o agata-deployer -g docker -m 0700 /var/lib/agata-deployment-executor
install -o root -g root -m 0600 "$ENV_SOURCE" /etc/agata/deployment-executor.env
install -o root -g root -m 0644 "$UNIT_SOURCE" /etc/systemd/system/agata-deployment-executor.service

if [[ -f "$ROOT/.env" ]]; then
  chown agata-deployer:docker "$ROOT/.env"
  chmod 0640 "$ROOT/.env"
fi
if [[ -d "$ROOT/secrets" ]]; then
  chown -R agata-deployer:agata-deployer "$ROOT/secrets"
  chmod 0700 "$ROOT/secrets"
  find "$ROOT/secrets" -type f -exec chmod 0400 {} +
fi

systemctl daemon-reload
systemctl enable --now agata-deployment-executor
systemctl --no-pager --full status agata-deployment-executor
echo
echo "Executor service installed. Configure a public HTTPS reverse proxy for POST /webhooks/agata/deployments before enabling deployments in Agata Proxima."
echo "Review the Docker-group privilege and keep /etc/agata/deployment-executor.env restricted to root."
