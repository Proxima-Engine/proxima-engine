#!/usr/bin/env bash
# Disposable authentication and Engine recovery test.
# Uses synthetic tenants and an isolated Compose project/volumes only.
set -euo pipefail

PROJECT="proxima-auth-recovery-test"
COMPOSE=(docker compose -p "$PROJECT" -f compose.dev.yaml)

cleanup() {
  "${COMPOSE[@]}" down -v >/dev/null 2>&1 || true
}
trap cleanup EXIT

if [[ ! -f .proxima-dev/dev-config.json ]]; then
  python3 scripts/agata.py init
fi

export PROXIMA_TENANT_SIGNING_KEY
PROXIMA_TENANT_SIGNING_KEY="$(python3 -c 'import json; print(json.load(open(".proxima-dev/dev-config.json", encoding="utf-8"))["tenant_signing_key"])')"

# Start an isolated PostgreSQL + PgBouncer + Engine stack with tenant
# authentication enabled by the local signing key.
"${COMPOSE[@]}" down -v >/dev/null 2>&1 || true
"${COMPOSE[@]}" up --build -d

wait_for_engine() {
  for attempt in $(seq 1 45); do
    if curl -fsS http://127.0.0.1:9090/healthz >/dev/null 2>&1; then
      return 0
    fi
    sleep 2
  done
  "${COMPOSE[@]}" logs --tail=100 engine >&2 || true
  echo "FAIL: Engine did not become healthy." >&2
  return 1
}

wait_for_engine

# Create the least-privilege tenant role used by this test.
"${COMPOSE[@]}" exec -T postgres psql -v ON_ERROR_STOP=1 -U proxima -d appdb <<'SQL'
DROP ROLE IF EXISTS proxima_tenant_tenant_auth;
CREATE ROLE proxima_tenant_tenant_auth LOGIN PASSWORD 'tenant-auth-password'
  NOSUPERUSER NOBYPASSRLS;
SQL

run_with_token() {
  local token="$1"
  PGPASSWORD='tenant-auth-password' PGOPTIONS="-c proxima_tenant_token=$token" \
    psql -X -A -t -v ON_ERROR_STOP=1 \
      "host=127.0.0.1 port=6432 dbname=appdb user=proxima sslmode=disable" \
      -c "SELECT current_user"
}

run_without_token() {
  PGPASSWORD='tenant-auth-password' PGOPTIONS='' \
    psql -X -A -t -v ON_ERROR_STOP=1 \
      "host=127.0.0.1 port=6432 dbname=appdb user=proxima sslmode=disable" \
      -c "SELECT 1"
}

valid_token="$(python3 scripts/agata.py token --tenant tenant_auth --ttl 600)"
expected_role="proxima_tenant_tenant_auth"

# 1. Valid signed token must authenticate and map to the expected role.
actual_role="$(run_with_token "$valid_token")"
test "$actual_role" = "$expected_role"
echo "PASS: valid signed token authenticated as $expected_role."

# 2. Missing tenant context must be rejected.
if run_without_token >/dev/null 2>&1; then
  echo "FAIL: missing tenant token was accepted." >&2
  exit 1
fi
echo "PASS: missing tenant token was rejected."

# 3. Malformed token must be rejected.
if run_with_token "not-a-proxima-token" >/dev/null 2>&1; then
  echo "FAIL: malformed tenant token was accepted." >&2
  exit 1
fi
echo "PASS: malformed tenant token was rejected."

# 4. A correctly shaped token with a modified signature must be rejected.
tampered_token="$(python3 - "$valid_token" <<'PY'
import sys
parts = sys.argv[1].split(".")
signature = parts[-1]
parts[-1] = ("0" if signature[0] != "0" else "1") + signature[1:]
print(".".join(parts))
PY
)"
if run_with_token "$tampered_token" >/dev/null 2>&1; then
  echo "FAIL: tampered tenant token was accepted." >&2
  exit 1
fi
echo "PASS: tampered tenant-token signature was rejected."

# 5. A validly signed token with a one-second lifetime must be rejected
# after its expiry time has passed.
expired_token="$(python3 scripts/agata.py token --tenant tenant_auth --ttl 1)"
sleep 2
if run_with_token "$expired_token" >/dev/null 2>&1; then
  echo "FAIL: expired tenant token was accepted." >&2
  exit 1
fi
echo "PASS: expired tenant token was rejected."

# 6. Simulate an Engine outage: SQL must fail while the Engine is stopped.
"${COMPOSE[@]}" stop engine >/dev/null
if run_with_token "$valid_token" >/dev/null 2>&1; then
  echo "FAIL: SQL unexpectedly succeeded while the Engine was stopped." >&2
  exit 1
fi
echo "PASS: database connection failed while the Engine was stopped."

# 7. Restart the Engine, wait for health, and prove fresh authentication works.
"${COMPOSE[@]}" start engine >/dev/null
wait_for_engine
actual_role="$(run_with_token "$valid_token")"
test "$actual_role" = "$expected_role"
echo "PASS: Engine recovered; the still-valid signed token authenticated after restart."

# 8. Restart must not revive an expired token.
if run_with_token "$expired_token" >/dev/null 2>&1; then
  echo "FAIL: Engine restart unexpectedly revived an expired token." >&2
  exit 1
fi
echo "PASS: expired token remained rejected after Engine recovery."

echo
echo "PASS: authentication and recovery scenarios completed."
echo "SCOPE: disposable local Compose environment, synthetic tenant, and local signing key."
