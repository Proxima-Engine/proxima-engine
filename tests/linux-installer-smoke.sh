#!/usr/bin/env bash
set -Eeuo pipefail

source_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
temp_root="$(mktemp -d)"
trap 'rm -rf "$temp_root"' EXIT
cp "$source_root/install-customer.sh" "$source_root/compose.customer.yaml" "$temp_root/"
cd "$temp_root"

docker() {
  case "$*" in
    "info --format {{.OSType}}") echo "linux" ;;
    "compose version") echo "Docker Compose version v2.30.0" ;;
    "compose -f compose.customer.yaml config --quiet") return 0 ;;
    "compose -f compose.customer.yaml up -d --build") return 0 ;;
    "compose -f compose.customer.yaml ps --format json engine") echo '{"Health":"healthy"}' ;;
    "compose -f compose.customer.yaml ps") echo "engine running (healthy)" ;;
    "compose -f compose.customer.yaml logs --tail 100 engine") echo "simulated engine logs" ;;
    *) echo "Unexpected Docker invocation: $*" >&2; return 1 ;;
  esac
}
export -f docker

PROXIMA_NODE_ID=00000000-0000-4000-8000-000000000001 \
PROXIMA_NODE_ENROLLMENT_URL=https://api.agataproxima.com/api/v1/nodes/enroll \
PROXIMA_NODE_ENROLLMENT_TOKEN=test-one-time-token \
PROXIMA_UPSTREAM_ADDR=postgres:5432 \
bash ./install-customer.sh

grep -Fxq "PROXIMA_NODE_ID=00000000-0000-4000-8000-000000000001" .env
grep -Fxq "PROXIMA_UPSTREAM_ADDR=postgres:5432" .env
[[ "$(cat secrets/node_enrollment_token)" == "test-one-time-token" ]]
[[ "$(stat -c '%a' secrets/node_enrollment_token)" == "600" ]]
[[ ! -e secrets/tenant_signing_key ]]

echo "PASS: Linux customer installer creates the environment and owner-only enrollment secret, validates Compose, starts the Engine and checks health."
