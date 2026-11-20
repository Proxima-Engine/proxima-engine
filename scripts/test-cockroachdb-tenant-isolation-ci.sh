#!/usr/bin/env bash
# Disposable CockroachDB 25.2+ two-tenant acceptance test; never run on production.
set -euo pipefail

CONTAINER="proxima-cockroach-ci"
LISTEN_ADDR="127.0.0.1:16433"
METRICS_ADDR="127.0.0.1:19091"
COCKROACH_ADDR="127.0.0.1:26257"

cleanup() {
  if [[ -n "${engine_pid:-}" ]]; then
    kill "$engine_pid" 2>/dev/null || true
    wait "$engine_pid" 2>/dev/null || true
  fi
  docker rm -f "$CONTAINER" >/dev/null 2>&1 || true
}
trap cleanup EXIT

docker rm -f "$CONTAINER" >/dev/null 2>&1 || true
docker run --detach --name "$CONTAINER" \
  --publish 127.0.0.1:26257:26257 \
  cockroachdb/cockroach:v25.2.0 \
  start-single-node --insecure --listen-addr=0.0.0.0:26257 --http-addr=0.0.0.0:8080 >/dev/null

ready=0
for _ in $(seq 1 60); do
  if docker exec "$CONTAINER" cockroach sql --insecure --host=127.0.0.1:26257 --execute='SELECT 1' >/dev/null 2>&1; then
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

docker exec "$CONTAINER" cockroach sql --insecure --host=127.0.0.1:26257 <<'SQL'
CREATE DATABASE proxima_dev;
CREATE USER proxima_tenant_cli_a WITH PASSWORD 'tenant-a-password';
CREATE USER proxima_tenant_cli_b WITH PASSWORD 'tenant-b-password';

CREATE TABLE proxima_dev.public.records (
  tenant_id STRING NOT NULL,
  secret STRING NOT NULL,
  PRIMARY KEY (tenant_id, secret)
);
INSERT INTO proxima_dev.public.records VALUES ('cli_a', 'A-secret'), ('cli_b', 'B-secret');

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

python3 scripts/agata.py init
export PROXIMA_TENANT_SIGNING_KEY
PROXIMA_TENANT_SIGNING_KEY="$(python3 -c 'import json; print(json.load(open(".proxima-dev/dev-config.json"))["tenant_signing_key"])')"
export PROXIMA_LISTEN_ADDR="$LISTEN_ADDR"
export PROXIMA_UPSTREAM_ADDR="$COCKROACH_ADDR"
export PROXIMA_DASHBOARD_ENABLED=false
export PROXIMA_METRICS_LISTEN_ADDR="$METRICS_ADDR"
target/release/proxima-engine > /tmp/proxima-cockroach-e2e.log 2>&1 &
engine_pid=$!

for _ in $(seq 1 40); do
  if curl -fsS "http://$METRICS_ADDR/healthz" >/dev/null 2>&1; then break; fi
  if ! kill -0 "$engine_pid" 2>/dev/null; then cat /tmp/proxima-cockroach-e2e.log; exit 1; fi
  sleep 1
done
if ! curl -fsS "http://$METRICS_ADDR/healthz" >/dev/null; then
  cat /tmp/proxima-cockroach-e2e.log
  echo "Proxima did not become healthy against CockroachDB" >&2
  exit 1
fi

token_a="$(python3 scripts/agata.py token --tenant cli_a --ttl 300)"
token_b="$(python3 scripts/agata.py token --tenant cli_b --ttl 300)"
run_tenant() {
  local token="$1" password="$2" sql="$3"
  PGPASSWORD="$password" PGOPTIONS="-c proxima_tenant_token=$token" psql -X -A -t -v ON_ERROR_STOP=1 \
    "host=127.0.0.1 port=16433 dbname=proxima_dev user=client sslmode=disable" -c "$sql"
}

test "$(run_tenant "$token_a" tenant-a-password 'SELECT secret FROM public.records')" = "A-secret"
test "$(run_tenant "$token_b" tenant-b-password 'SELECT secret FROM public.records')" = "B-secret"
test "$(run_tenant "$token_a" tenant-a-password "SELECT count(*) FROM public.records WHERE tenant_id='cli_b'")" = "0"
if run_tenant "$token_a" tenant-a-password "INSERT INTO public.records VALUES ('cli_b','forbidden')" >/dev/null 2>&1; then
  echo "FAIL: CockroachDB accepted a cross-tenant insert" >&2
  exit 1
fi
if run_tenant "$token_a" tenant-a-password "UPDATE public.records SET tenant_id='cli_b' WHERE tenant_id='cli_a'" >/dev/null 2>&1; then
  echo "FAIL: CockroachDB accepted a cross-tenant update" >&2
  exit 1
fi
if run_tenant "invalid-token" tenant-a-password 'SELECT 1' >/dev/null 2>&1; then
  echo "FAIL: invalid tenant token unexpectedly accepted" >&2
  exit 1
fi

echo "PASS: CockroachDB 25.2+ tenant A/B isolation, cross-tenant read/write denial, invalid token rejection"
