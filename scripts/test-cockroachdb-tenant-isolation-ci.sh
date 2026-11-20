#!/usr/bin/env bash
# Disposable CockroachDB 25.2+ two-tenant acceptance test; never run on production.
set -euo pipefail

CONTAINER="proxima-cockroach-ci"
LISTEN_ADDR="127.0.0.1:16433"
METRICS_ADDR="127.0.0.1:19091"
COCKROACH_ADDR="127.0.0.1:26257"
DEV_DIR="$(mktemp -d)"

cleanup() {
  if [[ -n "${engine_pid:-}" ]]; then
    kill "$engine_pid" 2>/dev/null || true
    wait "$engine_pid" 2>/dev/null || true
  fi
  docker rm -f "$CONTAINER" >/dev/null 2>&1 || true
  rm -rf "$DEV_DIR"
}
trap cleanup EXIT

docker rm -f "$CONTAINER" >/dev/null 2>&1 || true
docker run --detach --name "$CONTAINER" --network host \
  cockroachdb/cockroach:v25.2.0 \
  start-single-node --insecure --listen-addr=127.0.0.1:26257 --http-addr=127.0.0.1:8080 >/dev/null

ready=0
for _ in $(seq 1 60); do
  if timeout 5s docker exec "$CONTAINER" cockroach sql --insecure --host=127.0.0.1 --port=26257 --execute='SELECT 1' >/dev/null 2>&1; then
    ready=1
    break
  fi
  sleep 2
done
if [[ "$ready" != "1" ]]; then
  docker logs "$CONTAINER"
  echo "CockroachDB did not become ready" >&2
  exit 1
fi

timeout 90s docker exec "$CONTAINER" cockroach sql --insecure --host=127.0.0.1 --port=26257 <<'SQL'
CREATE DATABASE proxima_dev;
CREATE USER proxima_tenant_cli_a;
CREATE USER proxima_tenant_cli_b;

CREATE TABLE proxima_dev.public.records (
  tenant_id STRING NOT NULL,
  secret STRING NOT NULL,
  PRIMARY KEY (tenant_id, secret)
);
INSERT INTO proxima_dev.public.records VALUES ('cli_a', 'A-secret'), ('cli_b', 'B-secret');

REVOKE ALL ON DATABASE proxima_dev FROM public;
GRANT CONNECT ON DATABASE proxima_dev TO proxima_tenant_cli_a, proxima_tenant_cli_b;
REVOKE ALL ON SCHEMA proxima_dev.public FROM public;
ALTER TABLE proxima_dev.public.records ENABLE ROW LEVEL SECURITY, FORCE ROW LEVEL SECURITY;
CREATE POLICY isolate_a ON proxima_dev.public.records
  TO proxima_tenant_cli_a
  USING (tenant_id = 'cli_a')
  WITH CHECK (tenant_id = 'cli_a');
CREATE POLICY isolate_b ON proxima_dev.public.records
  TO proxima_tenant_cli_b
  USING (tenant_id = 'cli_b')
  WITH CHECK (tenant_id = 'cli_b');

GRANT USAGE ON SCHEMA proxima_dev.public TO proxima_tenant_cli_a, proxima_tenant_cli_b;
GRANT SELECT, INSERT, UPDATE, DELETE ON TABLE proxima_dev.public.records
  TO proxima_tenant_cli_a, proxima_tenant_cli_b;
SQL

python3 scripts/agata.py init --directory "$DEV_DIR"
export PROXIMA_TENANT_SIGNING_KEY
PROXIMA_TENANT_SIGNING_KEY="$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["tenant_signing_key"])' "$DEV_DIR/dev-config.json")"
export PROXIMA_LISTEN_ADDR="$LISTEN_ADDR"
export PROXIMA_UPSTREAM_ADDR="$COCKROACH_ADDR"
export PROXIMA_UPSTREAM_TLS_MODE=disable
export PROXIMA_DASHBOARD_ENABLED=false
export PROXIMA_METRICS_LISTEN_ADDR="$METRICS_ADDR"
target/release/proxima-engine > /tmp/proxima-cockroach-e2e.log 2>&1 &
engine_pid=$!

for _ in $(seq 1 40); do
  if curl --max-time 2 -fsS "http://$METRICS_ADDR/healthz" >/dev/null 2>&1; then break; fi
  if ! kill -0 "$engine_pid" 2>/dev/null; then cat /tmp/proxima-cockroach-e2e.log; exit 1; fi
  sleep 1
done
if ! curl -fsS "http://$METRICS_ADDR/healthz" >/dev/null; then
  cat /tmp/proxima-cockroach-e2e.log
  echo "Proxima did not become healthy against CockroachDB" >&2
  exit 1
fi

token_a="$(python3 scripts/agata.py token --config "$DEV_DIR/dev-config.json" --tenant cli_a --ttl 300)"
token_b="$(python3 scripts/agata.py token --config "$DEV_DIR/dev-config.json" --tenant cli_b --ttl 300)"
run_tenant() {
  local token="$1" sql="$2"
  timeout 20s env -u PGPASSWORD PGCONNECT_TIMEOUT=5 PGOPTIONS="-c statement_timeout=10000 -c proxima_tenant_token=$token" psql -X -A -t -v ON_ERROR_STOP=1 \
    "host=127.0.0.1 port=16433 dbname=proxima_dev user=client sslmode=disable" -c "$sql"
}

test "$(run_tenant "$token_a" 'SELECT secret FROM public.records')" = "A-secret"
test "$(run_tenant "$token_b" 'SELECT secret FROM public.records')" = "B-secret"
test "$(run_tenant "$token_a" "SELECT count(*) FROM public.records WHERE tenant_id='cli_b'")" = "0"
if run_tenant "$token_a" "INSERT INTO public.records VALUES ('cli_b','forbidden')" >/dev/null 2>&1; then
  echo "FAIL: CockroachDB accepted a cross-tenant insert" >&2
  exit 1
fi
if run_tenant "$token_a" "UPDATE public.records SET tenant_id='cli_b' WHERE tenant_id='cli_a'" >/dev/null 2>&1; then
  echo "FAIL: CockroachDB accepted a cross-tenant update" >&2
  exit 1
fi
if run_tenant "invalid-token" 'SELECT 1' >/dev/null 2>&1; then
  echo "FAIL: invalid tenant token unexpectedly accepted" >&2
  exit 1
fi

echo "PASS: CockroachDB 25.2+ tenant A/B isolation, cross-tenant read/write denial, invalid token rejection"
