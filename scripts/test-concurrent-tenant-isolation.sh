#!/usr/bin/env bash
# Disposable concurrency test for tenant isolation through Proxima Engine + PgBouncer.
# Uses an isolated Compose project, database volume, and synthetic tenant records.
set -euo pipefail

COMPOSE=(docker compose -p proxima-concurrency-test -f compose.dev.yaml)
WORK_DIR="$(mktemp -d)"
cleanup() {
  "${COMPOSE[@]}" down -v >/dev/null 2>&1 || true
  rm -rf "$WORK_DIR"
}
trap cleanup EXIT

"${COMPOSE[@]}" down -v >/dev/null 2>&1 || true
if [[ ! -f .proxima-dev/dev-config.json ]]; then
  python3 scripts/agata.py init
fi

export PROXIMA_TENANT_SIGNING_KEY
PROXIMA_TENANT_SIGNING_KEY="$(python3 -c 'import json; print(json.load(open(".proxima-dev/dev-config.json"))["tenant_signing_key"])')"
export PROXIMA_MAX_CONNECTIONS=128

"${COMPOSE[@]}" up --build -d

for attempt in $(seq 1 40); do
  if curl -fsS http://127.0.0.1:9090/healthz >/dev/null 2>&1; then
    break
  fi
  sleep 2
done
curl -fsS http://127.0.0.1:9090/healthz >/dev/null

"${COMPOSE[@]}" exec -T postgres psql -v ON_ERROR_STOP=1 -U proxima -d appdb <<'SQL'
DROP SCHEMA IF EXISTS concurrency_tenant_test CASCADE;
DROP ROLE IF EXISTS proxima_tenant_tenant_a;
DROP ROLE IF EXISTS proxima_tenant_tenant_b;

CREATE ROLE proxima_tenant_tenant_a LOGIN PASSWORD 'tenant-a-password' NOSUPERUSER NOBYPASSRLS;
CREATE ROLE proxima_tenant_tenant_b LOGIN PASSWORD 'tenant-b-password' NOSUPERUSER NOBYPASSRLS;

CREATE SCHEMA concurrency_tenant_test;
CREATE TABLE concurrency_tenant_test.records (
  id bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
  tenant_id text NOT NULL,
  secret text NOT NULL
);

INSERT INTO concurrency_tenant_test.records (tenant_id, secret)
VALUES ('tenant_a', 'A-secret'), ('tenant_b', 'B-secret');

ALTER TABLE concurrency_tenant_test.records ENABLE ROW LEVEL SECURITY;
ALTER TABLE concurrency_tenant_test.records FORCE ROW LEVEL SECURITY;

CREATE POLICY tenant_a_policy ON concurrency_tenant_test.records
  FOR ALL TO proxima_tenant_tenant_a
  USING (tenant_id = 'tenant_a')
  WITH CHECK (tenant_id = 'tenant_a');
CREATE POLICY tenant_b_policy ON concurrency_tenant_test.records
  FOR ALL TO proxima_tenant_tenant_b
  USING (tenant_id = 'tenant_b')
  WITH CHECK (tenant_id = 'tenant_b');

GRANT USAGE ON SCHEMA concurrency_tenant_test TO proxima_tenant_tenant_a, proxima_tenant_tenant_b;
GRANT SELECT, INSERT, UPDATE, DELETE ON concurrency_tenant_test.records TO proxima_tenant_tenant_a, proxima_tenant_tenant_b;
GRANT USAGE, SELECT ON SEQUENCE concurrency_tenant_test.records_id_seq TO proxima_tenant_tenant_a, proxima_tenant_tenant_b;
SQL

token_a="$(python3 scripts/agata.py token --tenant tenant_a --ttl 900)"
token_b="$(python3 scripts/agata.py token --tenant tenant_b --ttl 900)"

run_worker() {
  local tenant="$1"
  local token="$2"
  local password="$3"
  local expected_role="proxima_tenant_${tenant}"
  local expected_secret
  if [[ "$tenant" == "tenant_a" ]]; then expected_secret="A-secret"; else expected_secret="B-secret"; fi

  local i
  for i in $(seq 1 10); do
    (
      PGPASSWORD="$password" PGOPTIONS="-c proxima_tenant_token=$token" \
        psql -X -A -t -v ON_ERROR_STOP=1 \
          "host=127.0.0.1 port=6432 dbname=appdb user=proxima sslmode=disable" \
          -c "WITH pause AS (SELECT pg_sleep(0.25)) SELECT current_user || '|' || string_agg(secret, ',' ORDER BY secret) FROM concurrency_tenant_test.records, pause" \
          >"$WORK_DIR/${tenant}_${i}.out" 2>"$WORK_DIR/${tenant}_${i}.err"
      actual="$(tr -d '\r\n' <"$WORK_DIR/${tenant}_${i}.out")"
      expected="${expected_role}|${expected_secret}"
      if [[ "$actual" != "$expected" ]]; then
        echo "FAIL: $tenant worker $i expected '$expected' but received '$actual'" >&2
        exit 1
      fi
      touch "$WORK_DIR/${tenant}_${i}.pass"
      echo "$tenant worker $i PASS"
    ) &
  done
}

echo "Starting 10 concurrent Tenant A clients and 10 concurrent Tenant B clients..."
run_worker tenant_a "$token_a" tenant-a-password
run_worker tenant_b "$token_b" tenant-b-password

wait
count_a="$(find "$WORK_DIR" -maxdepth 1 -name 'tenant_a_*.out' | wc -l | tr -d ' ')"
count_b="$(find "$WORK_DIR" -maxdepth 1 -name 'tenant_b_*.out' | wc -l | tr -d ' ')"
pass_count="$(find "$WORK_DIR" -maxdepth 1 -name '*.pass' | wc -l | tr -d ' ')"
test "$count_a" -eq 10
test "$count_b" -eq 10
test "$pass_count" -eq 20

echo "PASS: all 20 concurrent client sessions returned the correct tenant-specific PostgreSQL role and only that tenant's row."
echo "Concurrency tested: 10 simultaneous Tenant A clients + 10 simultaneous Tenant B clients."
echo "NOTE: this is a bounded local concurrency check, not a production load, capacity, or latency benchmark."
