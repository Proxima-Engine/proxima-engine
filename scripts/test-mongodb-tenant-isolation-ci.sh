#!/usr/bin/env bash
set -euo pipefail
: "${PROXIMA_MONGODB_TEST_URI:?PROXIMA_MONGODB_TEST_URI is required}"

cert_dir="$(mktemp -d)"
gateway_pid=""
cleanup() {
  if [[ -n "$gateway_pid" ]]; then
    kill "$gateway_pid" 2>/dev/null || true
    wait "$gateway_pid" 2>/dev/null || true
  fi
  rm -rf "$cert_dir"
}
trap cleanup EXIT

openssl req -x509 -newkey rsa:2048 -nodes \
  -keyout "$cert_dir/gateway-key.pem" \
  -out "$cert_dir/gateway-cert.pem" \
  -subj "/CN=localhost" -addext "subjectAltName=DNS:localhost,IP:127.0.0.1" -days 1 >/dev/null 2>&1

cat > "$cert_dir/identities.json" <<'JSON'
{
  "users": [
    {
      "username": "tenant_a_gateway",
      "tenant_id": "tenant-a",
      "database": "tenant_a_db",
      "auth_source": "admin"
    },
    {
      "username": "tenant_b_gateway",
      "tenant_id": "tenant-b",
      "database": "tenant_b_db",
      "auth_source": "admin"
    }
  ]
}
JSON

export PROXIMA_MONGODB_LISTEN_ADDR=127.0.0.1:27018
export PROXIMA_MONGODB_UPSTREAM_ADDR=127.0.0.1:27017
export PROXIMA_MONGODB_UPSTREAM_TLS=false
export PROXIMA_MONGODB_IDENTITY_REGISTRY="$cert_dir/identities.json"
export PROXIMA_MONGODB_TLS_CERT_FILE="$cert_dir/gateway-cert.pem"
export PROXIMA_MONGODB_TLS_KEY_FILE="$cert_dir/gateway-key.pem"
export PROXIMA_MONGODB_GATEWAY_ADDR=127.0.0.1:27018

target/debug/proxima-mongodb-gateway > "$cert_dir/gateway.log" 2>&1 &
gateway_pid=$!

ready=0
for _ in $(seq 1 40); do
  if nc -z 127.0.0.1 27018; then
    ready=1
    break
  fi
  if ! kill -0 "$gateway_pid" 2>/dev/null; then
    cat "$cert_dir/gateway.log"
    echo "Proxima MongoDB gateway exited before accepting connections" >&2
    exit 1
  fi
  sleep 1
done
if [[ "$ready" != "1" ]]; then
  cat "$cert_dir/gateway.log"
  echo "Proxima MongoDB gateway did not start listening" >&2
  exit 1
fi

cargo test -p proxima-engine --test mongodb_tenant_isolation -- --ignored --test-threads=1
