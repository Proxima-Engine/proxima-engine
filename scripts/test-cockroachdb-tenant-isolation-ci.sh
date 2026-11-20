#!/usr/bin/env bash
# Disposable CockroachDB 25.2+ two-tenant acceptance test; never run on production.
set -euo pipefail

CONTAINER="proxima-cockroach-ci"
LISTEN_ADDR="127.0.0.1:16433"
METRICS_ADDR="127.0.0.1:19091"
# Generate short-lived CA, node, and root client certificates for a secure test cluster.
# Bypass the image entrypoint: it creates FIFOs and a data directory in its
# working directory, which is not writable when the CI runner UID is used.
# Running the Cockroach binary directly keeps all generated files runner-owned.
cockroach_cli() {
  docker run --rm --user "$DOCKER_USER" --workdir /tmp --entrypoint cockroach \
    -v "$CERT_DIR:/certs" cockroachdb/cockroach:v25.2.0 "$@"
}

cockroach_cli cert create-ca --certs-dir=/certs --ca-key=/certs/ca.key
cockroach_cli cert create-node localhost 127.0.0.1 --certs-dir=/certs --ca-key=/certs/ca.key
cockroach_cli cert create-client root --certs-dir=/certs --ca-key=/certs/ca.key

docker run --detach --name "$CONTAINER" --network host --user "$DOCKER_USER" \
  --workdir /tmp --entrypoint cockroach -v "$CERT_DIR:/certs" \
  cockroachdb/cockroach:v25.2.0 \
  start-single-node --certs-dir=/certs --store=/tmp/cockroach-data \
  --listen-addr=127.0.0.1:26257 --http-addr=127.0.0.1:8080 >/dev/null

ready=0
for _ in $(seq 1 60); do
  if timeout 5s docker exec "$CONTAINER" cockroach sql --certs-dir=/certs --host=localhost --port=26257 --user=root --execute='SELECT 1' >/dev/null 2>&1; then
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

timeout 90s docker exec -i "$CONTAINER" cockroach sql --certs-dir=/certs --host=localhost --port=26257 --user=root <<'SQL'
SET CLUSTER SETTING server.host_based_authentication.configuration =
  E'host all root all cert\nhost all all all scram-sha-256';

CREATE DATABASE proxima_dev;
CREATE USER proxima_tenant_cli_a WITH LOGIN PASSWORD 'tenant-a-password';
CREATE USER proxima_tenant_cli_b WITH LOGIN PASSWORD 'tenant-b-password';

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

# Prove the disposable CockroachDB role and password before involving Proxima.
# This separates fixture credential failures from proxy authentication failures.
PGPASSWORD=tenant-a-password PGPASSFILE=/dev/null PGCONNECT_TIMEOUT=5 psql -w -X -A -t -v ON_ERROR_STOP=1 \
  "host=localhost port=26257 dbname=proxima_dev user=proxima_tenant_cli_a sslmode=verify-full sslrootcert=$CERT_DIR/ca.crt" \
  -c 'SELECT current_user' | grep -Fx 'proxima_tenant_cli_a'
PGPASSWORD=tenant-b-password PGPASSFILE=/dev/null PGCONNECT_TIMEOUT=5 psql -w -X -A -t -v ON_ERROR_STOP=1 \
  "host=localhost port=26257 dbname=proxima_dev user=proxima_tenant_cli_b sslmode=verify-full sslrootcert=$CERT_DIR/ca.crt" \
  -c 'SELECT current_user' | grep -Fx 'proxima_tenant_cli_b'

python3 scripts/agata.py init --directory "$DEV_DIR"
export PROXIMA_TENANT_SIGNING_KEY
PROXIMA_TENANT_SIGNING_KEY="$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["tenant_signing_key"])' "$DEV_DIR/dev-config.json")"
export PROXIMA_LISTEN_ADDR="$LISTEN_ADDR"
export PROXIMA_UPSTREAM_ADDR="localhost:26257"
export PROXIMA_UPSTREAM_TLS_MODE=verify-full
export PROXIMA_UPSTREAM_TLS_CA_FILE="$CERT_DIR/ca.crt"
export PROXIMA_UPSTREAM_TLS_SERVER_NAME=localhost
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
  local token="$1" username="$2" password="$3" sql="$4"
  timeout 20s env PGPASSWORD="$password" PGPASSFILE=/dev/null PGCONNECT_TIMEOUT=5 PGOPTIONS="-c statement_timeout=10000 -c proxima_tenant_token=$token" \
    psql -w -X -A -t -v ON_ERROR_STOP=1 \
    "host=127.0.0.1 port=16433 dbname=proxima_dev user=$username sslmode=disable" -c "$sql"
}

test "$(run_tenant "$token_a" proxima_tenant_cli_a tenant-a-password 'SELECT secret FROM public.records')" = "A-secret"
test "$(run_tenant "$token_b" proxima_tenant_cli_b tenant-b-password 'SELECT secret FROM public.records')" = "B-secret"
test "$(run_tenant "$token_a" proxima_tenant_cli_a tenant-a-password "SELECT count(*) FROM public.records WHERE tenant_id='cli_b'")" = "0"
if run_tenant "$token_a" proxima_tenant_cli_a tenant-a-password "INSERT INTO public.records VALUES ('cli_b','forbidden')" >/dev/null 2>&1; then
  echo "FAIL: CockroachDB accepted a cross-tenant insert" >&2
  exit 1
fi
if run_tenant "$token_a" proxima_tenant_cli_a tenant-a-password "UPDATE public.records SET tenant_id='cli_b' WHERE tenant_id='cli_a'" >/dev/null 2>&1; then
  echo "FAIL: CockroachDB accepted a cross-tenant update" >&2
  exit 1
fi
if run_tenant "invalid-token" proxima_tenant_cli_a tenant-a-password 'SELECT 1' >/dev/null 2>&1; then
  echo "FAIL: invalid tenant token unexpectedly accepted" >&2
  exit 1
fi

echo "PASS: CockroachDB 25.2+ tenant A/B isolation, cross-tenant read/write denial, invalid token rejection"
