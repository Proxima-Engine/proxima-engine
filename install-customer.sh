#!/usr/bin/env bash
set -Eeuo pipefail
cd "$(dirname "$0")"

for file in .env compose.customer.yaml secrets/node_enrollment_token secrets/tenant_signing_key; do
  if [[ ! -f "$file" ]]; then
    echo "Missing $file. Download .env and both secret files from Agata Proxima → Nodes, then place them in this folder." >&2
    exit 1
  fi
done
command -v docker >/dev/null 2>&1 || { echo "Docker CLI is required." >&2; exit 1; }
docker compose version >/dev/null

docker compose -f compose.customer.yaml config --quiet
echo "Building and starting Proxima Engine. The first build downloads Rust dependencies and can take several minutes."
docker compose -f compose.customer.yaml up -d --build

echo "Waiting for Engine health check..."
for attempt in $(seq 1 40); do
  if docker compose -f compose.customer.yaml ps --format json engine | grep -q '"Health":"healthy"'; then
    docker compose -f compose.customer.yaml ps
    echo "Proxima Engine is healthy. Node enrollment and signed heartbeat will now complete against the configured Agata Proxima Control Plane."
    exit 0
  fi
  sleep 3
done
docker compose -f compose.customer.yaml ps
docker compose -f compose.customer.yaml logs --tail 100 engine
echo "Engine did not become healthy within 120 seconds. Review the logs before retrying." >&2
exit 1
