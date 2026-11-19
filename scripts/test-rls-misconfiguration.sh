#!/usr/bin/env bash
# Disposable local test for deliberate PostgreSQL RLS misconfiguration.
# Uses an isolated Compose project, database volume, and synthetic tenant data.
# This test intentionally demonstrates unsafe outcomes; it does not claim that
# Proxima Engine independently filters rows when PostgreSQL RLS is weakened.
set -euo pipefail

COMPOSE=(docker compose -p proxima-rls-misconfig-test -f compose.dev.yaml)
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

"${COMPOSE[@]}" up --build -d

for attempt in $(seq 1 40); do
  if curl -fsS http://127.0.0.1:9090/healthz >/dev/null 2>&1; then
    break
  fi
  sleep 2
done
curl -fsS http://127.0.0.1:9090/healthz >/dev/null

"${COMPOSE[@]}" exec -T postgres psql -v ON_ERROR_STOP=1 -U proxima -d appdb <<'SQL'
DROP SCHEMA IF EXISTS rls_misconfig_test CASCADE;
DROP ROLE IF EXISTS proxima_tenant_tenant_a;
DROP ROLE IF EXISTS proxima_tenant_tenant_b;

CREATE ROLE proxima_tenant_tenant_a LOGIN PASSWORD 'tenant-a-password' NOSUPERUSER NOBYPASSRLS;
CREATE ROLE proxima_tenant_tenant_b LOGIN PASSWORD 'tenant-b-password' NOSUPERUSER NOBYPASSRLS;

CREATE SCHEMA rls_misconfig_test;
CREATE TABLE rls_misconfig_test.records (
  id bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
  tenant_id text NOT NULL,
  secret text NOT NULL
);

INSERT INTO rls_misconfig_test.records (tenant_id, secret)
VALUES ('tenant_a', 'A-secret'), ('tenant_b', 'B-secret');

ALTER TABLE rls_misconfig_test.records ENABLE ROW LEVEL SECURITY;
ALTER TABLE rls_misconfig_test.records FORCE ROW LEVEL SECURITY;

CREATE POLICY tenant_a_policy ON rls_misconfig_test.records
  FOR ALL TO proxima_tenant_tenant_a
  USING (tenant_id = 'tenant_a')
  WITH CHECK (tenant_id = 'tenant_a');
CREATE POLICY tenant_b_policy ON rls_misconfig_test.records
  FOR ALL TO proxima_tenant_tenant_b
  USING (tenant_id = 'tenant_b')
  WITH CHECK (tenant_id = 'tenant_b');

GRANT USAGE ON SCHEMA rls_misconfig_test TO proxima_tenant_tenant_a, proxima_tenant_tenant_b;
GRANT SELECT, INSERT, UPDATE, DELETE ON rls_misconfig_test.records TO proxima_tenant_tenant_a, proxima_tenant_tenant_b;
GRANT USAGE, SELECT ON SEQUENCE rls_misconfig_test.records_id_seq TO proxima_tenant_tenant_a, proxima_tenant_tenant_b;
SQL

token_a="$(python3 scripts/agata.py token --tenant tenant_a --ttl 600)"
token_b="$(python3 scripts/agata.py token --tenant tenant_b --ttl 600)"

run_tenant() {
  local token="$1"
  local password="$2"
  local sql="$3"
  PGPASSWORD="$password" PGOPTIONS="-c proxima_tenant_token=$token" \
    psql -X -A -t -v ON_ERROR_STOP=1 \
      "host=127.0.0.1 port=6432 dbname=appdb user=proxima sslmode=disable" \
      -c "$sql"
}

# Baseline: correctly configured RLS isolates both tenants.
test "$(run_tenant "$token_a" tenant-a-password \
  "SELECT string_agg(secret, ',' ORDER BY secret) FROM rls_misconfig_test.records")" = "A-secret"
test "$(run_tenant "$token_b" tenant-b-password \
  "SELECT string_agg(secret, ',' ORDER BY secret) FROM rls_misconfig_test.records")" = "B-secret"
echo "PASS: baseline RLS exposes only each tenant's own row."

# Scenario 1: removing a tenant's policy does NOT expose all rows; it fails closed.
"${COMPOSE[@]}" exec -T postgres psql -v ON_ERROR_STOP=1 -U proxima -d appdb \
  -c "DROP POLICY tenant_a_policy ON rls_misconfig_test.records"
test "$(run_tenant "$token_a" tenant-a-password \
  "SELECT count(*) FROM rls_misconfig_test.records")" = "0"
echo "PASS: removing Tenant A's policy failed closed (zero visible rows)."

# Scenario 2: an overly permissive policy for Tenant A creates a real cross-tenant exposure.
"${COMPOSE[@]}" exec -T postgres psql -v ON_ERROR_STOP=1 -U proxima -d appdb \
  -c "CREATE POLICY unsafe_allow_all_a ON rls_misconfig_test.records FOR ALL TO proxima_tenant_tenant_a USING (true) WITH CHECK (true)"
leaked_rows="$(run_tenant "$token_a" tenant-a-password \
  "SELECT string_agg(secret, ',' ORDER BY secret) FROM rls_misconfig_test.records")"
test "$leaked_rows" = "A-secret,B-secret"
run_tenant "$token_a" tenant-a-password \
  "INSERT INTO rls_misconfig_test.records (tenant_id, secret) VALUES ('tenant_b', 'A-inserted-into-B')" >/dev/null
echo "EXPECTED EXPOSURE: permissive RLS policy let Tenant A read Tenant B's row and insert a row labelled tenant_b."
echo "Observed rows before insert: $leaked_rows"

# Scenario 3: restore strict policies, then deliberately give Tenant A BYPASSRLS.
"${COMPOSE[@]}" exec -T postgres psql -v ON_ERROR_STOP=1 -U proxima -d appdb <<'SQL'
DROP POLICY unsafe_allow_all_a ON rls_misconfig_test.records;
CREATE POLICY tenant_a_policy ON rls_misconfig_test.records
  FOR ALL TO proxima_tenant_tenant_a
  USING (tenant_id = 'tenant_a')
  WITH CHECK (tenant_id = 'tenant_a');
ALTER ROLE proxima_tenant_tenant_a BYPASSRLS;
SQL

bypass_result="$(run_tenant "$token_a" tenant-a-password \
  "SELECT current_user || '|' || string_agg(secret, ',' ORDER BY secret) FROM rls_misconfig_test.records")"
expected_bypass="proxima_tenant_tenant_a|A-inserted-into-B,A-secret,B-secret"
test "$bypass_result" = "$expected_bypass"
echo "EXPECTED EXPOSURE: Tenant A's mapped PostgreSQL role has BYPASSRLS and can see all rows despite FORCE ROW LEVEL SECURITY."
echo "Observed role and rows: $bypass_result"

# Restore least privilege and prove the original boundary works again.
"${COMPOSE[@]}" exec -T postgres psql -v ON_ERROR_STOP=1 -U proxima -d appdb \
  -c "ALTER ROLE proxima_tenant_tenant_a NOBYPASSRLS"
restored="$(run_tenant "$token_a" tenant-a-password \
  "SELECT string_agg(secret, ',' ORDER BY secret) FROM rls_misconfig_test.records")"
test "$restored" = "A-secret"
echo "PASS: restoring NOBYPASSRLS and the strict policy restored Tenant A's row boundary."
echo "PASS: deliberate RLS misconfiguration scenarios reproduced in an isolated disposable database."
echo "NOTE: Proxima verified Tenant A's signed identity and mapped it to Tenant A's PostgreSQL role; PostgreSQL RLS and role attributes determined row visibility."
