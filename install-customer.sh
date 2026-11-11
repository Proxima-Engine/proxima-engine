#!/usr/bin/env bash
set -Eeuo pipefail
cd "$(dirname "$0")"

[[ -f compose.customer.yaml ]] || { echo "Run this installer from the extracted Proxima Engine repository folder." >&2; exit 1; }
command -v docker >/dev/null 2>&1 || { echo "Docker CLI is required." >&2; exit 1; }

if [[ ! -f .env ]]; then
  : "${PROXIMA_NODE_ID:?Set PROXIMA_NODE_ID using the enrollment configuration copied from Agata Proxima → Nodes}"
  PROXIMA_NODE_ENROLLMENT_URL="${PROXIMA_NODE_ENROLLMENT_URL:-https://api.agataproxima.com/api/v1/nodes/enroll}"
  if [[ -z "${PROXIMA_UPSTREAM_ADDR:-}" ]]; then
    read -r -p "PostgreSQL upstream host:port (for example, db.example.com:5432): " PROXIMA_UPSTREAM_ADDR
  fi
  [[ -n "$PROXIMA_UPSTREAM_ADDR" ]] || { echo "A PostgreSQL upstream address is required." >&2; exit 1; }
  cat > .env <<EOF
PROXIMA_NODE_ID=$PROXIMA_NODE_ID
PROXIMA_NODE_ENROLLMENT_URL=$PROXIMA_NODE_ENROLLMENT_URL
PROXIMA_UPSTREAM_ADDR=$PROXIMA_UPSTREAM_ADDR
PROXIMA_LISTEN_ADDR=${PROXIMA_LISTEN_ADDR:-0.0.0.0:6432}
PROXIMA_ENVIRONMENT=production
EOF
fi

token_file="secrets/node_enrollment_token"
if [[ ! -f "$token_file" ]]; then
  : "${PROXIMA_NODE_ENROLLMENT_TOKEN:?Copy the enrollment configuration from Agata Proxima → Nodes and rerun this installer}"
  umask 077
  mkdir -p secrets
  printf '%s' "$PROXIMA_NODE_ENROLLMENT_TOKEN" > "$token_file"
fi
unset PROXIMA_NODE_ENROLLMENT_TOKEN || true

docker compose version >/dev/null
docker compose -f compose.customer.yaml config --quiet
echo "Building and starting Proxima Engine. The first build downloads Rust dependencies and can take several minutes."
docker compose -f compose.customer.yaml up -d --build

echo "Waiting for Engine health check..."
for attempt in $(seq 1 40); do
  if docker compose -f compose.customer.yaml ps --format json engine | grep -q '"Health":"healthy"'; then
    docker compose -f compose.customer.yaml ps
    echo "Proxima Engine is healthy. Node enrollment and signed heartbeat are active. The organization-scoped tenant verification key is stored in the protected node identity file."
    exit 0
  fi
  sleep 3
done
docker compose -f compose.customer.yaml ps
docker compose -f compose.customer.yaml logs --tail 100 engine
echo "Engine did not become healthy within 120 seconds. Review the logs before retrying." >&2
exit 1
