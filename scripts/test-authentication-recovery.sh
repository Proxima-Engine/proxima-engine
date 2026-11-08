#!/usr/bin/env bash
# Disposable local authentication and Engine-recovery test.
# Uses synthetic tenant data and an isolated Compose project/volume.
set -euo pipefail

COMPOSE=(docker compose -p proxima-auth-recovery-test -f compose.dev.yaml)
cleanup() {
  "${COMPOSE[@]}" down -v >/dev/null 2>&1 || true
}
trap cleanup EXIT

"${COMPOSE[@]}" down -v >/dev/null 2>&1 || true

if [[ ! -f .proxima-dev/dev-config.json ]]; then
  python3 scripts/agata.py init
fi

export PROXIMA_TENANT_SIGNING_KEY
PROXIMA_TENANT_SIGNING_KEY="$(python3 -c 'import json; print(json.load(open(".proxima-dev/dev-config.json"))["tenant_signing_key"])')"

echo "[1/5] Starting isolated PostgreSQL, PgBouncer, and Proxima Engine..."
"${COMPOSE[@]}" up --build -d

wait_for_engine() {
  for attempt in $(seq 1 40); do
    if curl -fsS http://127.0.0.1:9090/healthz >/dev/null 2>&1; then
      return 0
    fi
    sleep 2
  done
  echo "FAIL: Proxima Engine did not become healthy" >&2
  "${COMPOSE[@]}" logs --tail=100 engine >&2 || true
  return 1
}
wait_for_engine

echo "[2/5] Preparing synthetic tenant roles and RLS-protected records..."
"${COMPOSE[@]}" exec -T postgres psql -v ON_ERROR_STOP=1 -U proxima -d appdb <<'SQL'
CREATE ROLE proxima_tenant_tenant_a LOGIN PASSWORD 'tenant-a-password' NOSUPERUSER NOBYPASSRLS;
CREATE SCHEMA auth_recovery_test;
CREATE TABLE auth_recovery_test.records (
  id bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
  tenant_id text NOT NULL,
  secret text NOT NULL
);
INSERT INTO auth_recovery_test.records (tenant_id, secret)
VALUES ('tenant_a', 'A-secret');
ALTER TABLE auth_recovery_test.records ENABLE ROW LEVEL SECURITY;
ALTER TABLE auth_recovery_test.records FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_a_policy ON auth_recovery_test.records
  FOR ALL TO proxima_tenant_tenant_a
  USING (tenant_id = 'tenant_a')
  WITH CHECK (tenant_id = 'tenant_a');
GRANT USAGE ON SCHEMA auth_recovery_test TO proxima_tenant_tenant_a;
GRANT SELECT, INSERT, UPDATE, DELETE ON auth_recovery_test.records TO proxima_tenant_tenant_a;
GRANT USAGE, SELECT ON SEQUENCE auth_recovery_test.records_id_seq TO proxima_tenant_tenant_a;
SQL

run_tenant() {
  local token="$1"
  PGPASSWORD=tenant-a-password PGOPTIONS="-c proxima_tenant_token=$token" \
    psql -X -A -t -v ON_ERROR_STOP=1 \
      "host=127.0.0.1 port=6432 dbname=appdb user=proxima sslmode=disable" \
      -c "$2"
}

echo "[3/5] Checking valid, expired, tampered, and missing tenant tokens..."
valid_token="$(python3 scripts/agata.py token --tenant tenant_a --ttl 600)"
valid_result="$(run_tenant "$valid_token" \
  "SELECT current_user || ':' || string_agg(secret, ',') FROM auth_recovery_test.records")"
test "$valid_result" = "proxima_tenant_tenant_a:A-secret"
echo "PASS: valid signed token accepted and mapped to the tenant PostgreSQL role."

expired_token="$(python3 scripts/agata.py token --tenant tenant_a --ttl 2)"
sleep 3
if run_tenant "$expired_token" "SELECT 1" >/dev/null 2>&1; then
  echo "FAIL: expired tenant token was accepted" >&2
  exit 1
fi
echo "PASS: expired tenant token rejected."

tampered_token="$(python3 -c 'import sys; print(sys.argv[1].replace("v1.tenant_a.", "v1.tenant_b.", 1))' "$valid_token")"
if run_tenant "$tampered_token" "SELECT 1" >/dev/null 2>&1; then
  echo "FAIL: tampered tenant token was accepted" >&2
  exit 1
fi
echo "PASS: tampered tenant identity/signature rejected."

if PGPASSWORD=tenant-a-password PGOPTIONS='' \
  psql -X -A -t -v ON_ERROR_STOP=1 \
    "host=127.0.0.1 port=6432 dbname=appdb user=proxima sslmode=disable" \
    -c "SELECT 1" >/dev/null 2>&1; then
  echo "FAIL: missing tenant token was accepted" >&2
  exit 1
fi
echo "PASS: missing tenant token rejected."

echo "[4/5] Interrupting Proxima Engine and checking fail-closed behavior..."
"${COMPOSE[@]}" stop engine >/dev/null
if PGPASSWORD=tenant-a-password PGOPTIONS="-c proxima_tenant_token=$valid_token" \
  psql -X -A -t -v ON_ERROR_STOP=1 \
    "host=127.0.0.1 port=6432 dbname=appdb user=proxima sslmode=disable" \
    -c "SELECT 1" >/dev/null 2>&1; then
  echo "FAIL: database query succeeded while Proxima Engine was stopped" >&2
  exit 1
fi
echo "PASS: database access through the stopped Engine failed."

echo "[5/5] Restarting Proxima Engine and verifying service recovery..."
"${COMPOSE[@]}" start engine >/dev/null
wait_for_engine
recovery_token="$(python3 scripts/agata.py token --tenant tenant_a --ttl 600)"
recovery_result="$(run_tenant "$recovery_token" \
  "SELECT current_user || ':' || string_agg(secret, ',') FROM auth_recovery_test.records")"
test "$recovery_result" = "proxima_tenant_tenant_a:A-secret"
echo "PASS: Engine recovered; a fresh valid tenant token restored database access."
echo "PASS: Authentication and recovery checks completed."
