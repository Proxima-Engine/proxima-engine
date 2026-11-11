#!/usr/bin/env bash
# Disposable local Compose test for tenant role separation through PgBouncer.
# Use synthetic data only. The test uses an isolated Compose project and volume.
set -euo pipefail

COMPOSE=(docker compose -p proxima-pgbouncer-test -f compose.dev.yaml)
cleanup() {
  "${COMPOSE[@]}" down -v >/dev/null 2>&1 || true
}
trap cleanup EXIT

# Start from an isolated disposable database and generate a local signing key.
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

# Create two least-privilege roles and a table with tenant-specific RLS policies.
"${COMPOSE[@]}" exec -T postgres psql -v ON_ERROR_STOP=1 -U proxima -d appdb <<'SQL'
DROP SCHEMA IF EXISTS pgbouncer_tenant_test CASCADE;
DROP ROLE IF EXISTS proxima_tenant_tenant_a;
DROP ROLE IF EXISTS proxima_tenant_tenant_b;

CREATE ROLE proxima_tenant_tenant_a LOGIN PASSWORD 'tenant-a-password' NOSUPERUSER NOBYPASSRLS;
CREATE ROLE proxima_tenant_tenant_b LOGIN PASSWORD 'tenant-b-password' NOSUPERUSER NOBYPASSRLS;

CREATE SCHEMA pgbouncer_tenant_test;
CREATE TABLE pgbouncer_tenant_test.records (
  id bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
  tenant_id text NOT NULL,
  secret text NOT NULL
);

INSERT INTO pgbouncer_tenant_test.records (tenant_id, secret)
VALUES ('tenant_a', 'A-secret'), ('tenant_b', 'B-secret');

ALTER TABLE pgbouncer_tenant_test.records ENABLE ROW LEVEL SECURITY;
ALTER TABLE pgbouncer_tenant_test.records FORCE ROW LEVEL SECURITY;

CREATE POLICY tenant_a_policy ON pgbouncer_tenant_test.records
  FOR ALL TO proxima_tenant_tenant_a
  USING (tenant_id = 'tenant_a')
  WITH CHECK (tenant_id = 'tenant_a');
CREATE POLICY tenant_b_policy ON pgbouncer_tenant_test.records
  FOR ALL TO proxima_tenant_tenant_b
  USING (tenant_id = 'tenant_b')
  WITH CHECK (tenant_id = 'tenant_b');

GRANT USAGE ON SCHEMA pgbouncer_tenant_test TO proxima_tenant_tenant_a, proxima_tenant_tenant_b;
GRANT SELECT, INSERT, UPDATE, DELETE ON pgbouncer_tenant_test.records TO proxima_tenant_tenant_a, proxima_tenant_tenant_b;
GRANT USAGE, SELECT ON SEQUENCE pgbouncer_tenant_test.records_id_seq TO proxima_tenant_tenant_a, proxima_tenant_tenant_b;
SQL

# Mint fresh tokens after the Engine build and database setup.
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

# Send each statement separately over one client connection. PgBouncer's
# transaction pool releases the server backend between these commands while
# the client remains connected. Keeping BEGIN/set_config, PID inspection, and
# COMMIT/ROLLBACK in separate -c requests also makes psql print the PID result
# instead of only the final transaction command tag.
run_tenant_transaction() {
  local token="$1"
  local password="$2"
  local begin_sql="$3"
  local end_sql="$4"
  PGPASSWORD="$password" PGOPTIONS="-c proxima_tenant_token=$token" \
    psql -X -A -t -v ON_ERROR_STOP=1 \
      "host=127.0.0.1 port=6432 dbname=appdb user=proxima sslmode=disable" \
      -c "$begin_sql" \
      -c "SELECT pg_backend_pid()" \
      -c "$end_sql"
}

# Exercise backend-local state across actual PgBouncer transaction releases.
# Proxima's tenant identity is authenticated at startup and mapped to a dedicated
# PostgreSQL role; this synthetic GUC is a probe for PostgreSQL/PgBouncer cleanup,
# not a claim that Proxima stores its tenant identity in a session variable.
assert_context_cleared_on_reused_backend() {
  local label="$1"
  local token="$2"
  local password="$3"
  local begin_sql="$4"
  local end_sql="$5"
  local setup_result before_pid reuse_result reused_pid context

  setup_result="$(run_tenant_transaction "$token" "$password" "$begin_sql" "$end_sql")"
  before_pid="$(printf '%s\n' "$setup_result" | grep -E '^[0-9]+
  if [[ ! "$before_pid" =~ ^[0-9]+$ ]]; then
    echo "FAIL: $label did not return a valid backend PID (got: $before_pid)" >&2
    exit 1
  fi

  reuse_result="$(run_tenant "$token" "$password" \
    "SELECT pg_backend_pid() || '|' || COALESCE(NULLIF(current_setting('proxima.tenant_id', true), ''), '<unset>')")"
  reused_pid="${reuse_result%%|*}"
  context="${reuse_result#*|}"

  test "$reused_pid" = "$before_pid" || {
    echo "FAIL: $label did not inspect the same reused backend (before=$before_pid after=$reused_pid)" >&2
    exit 1
  }
  test "$context" = "<unset>" || {
    echo "FAIL: $label leaked tenant context '$context' onto reused backend $reused_pid" >&2
    exit 1
  }

  echo "PASS: $label cleared before backend $reused_pid was reused"
}

# SET LOCAL semantics: transaction-scoped identity must disappear on COMMIT.
assert_context_cleared_on_reused_backend \
  "COMMIT transaction-local context" "$token_a" tenant-a-password \
  "BEGIN; SELECT set_config('proxima.tenant_id', 'tenant_a', true);" "COMMIT"

# SET LOCAL semantics must also disappear when the transaction rolls back.
assert_context_cleared_on_reused_backend \
  "ROLLBACK transaction-local context" "$token_a" tenant-a-password \
  "BEGIN; SELECT set_config('proxima.tenant_id', 'tenant_a', true);" "ROLLBACK"

# A session-scoped setting survives COMMIT in PostgreSQL. Its disappearance on
# the same backend proves PgBouncer's configured DISCARD ALL reset ran before reuse.
assert_context_cleared_on_reused_backend \
  "PgBouncer DISCARD ALL session-state reset" "$token_a" tenant-a-password \
  "BEGIN; SELECT set_config('proxima.tenant_id', 'tenant_a', false);" "COMMIT"

# Confirm tenant A and tenant B each receive only their own data.
test "$(run_tenant "$token_a" tenant-a-password \
  "SELECT string_agg(secret, ',' ORDER BY secret) FROM pgbouncer_tenant_test.records")" = "A-secret"
test "$(run_tenant "$token_b" tenant-b-password \
  "SELECT string_agg(secret, ',' ORDER BY secret) FROM pgbouncer_tenant_test.records")" = "B-secret"

# Record backend PID reuse over five sequential connections for each tenant role.
tenant_a_pid=""
for attempt in $(seq 1 5); do
  result="$(run_tenant "$token_a" tenant-a-password \
    "SELECT current_user || '|' || pg_backend_pid()")"
  role="${result%%|*}"
  pid="${result##*|}"
  test "$role" = "proxima_tenant_tenant_a"
  if [[ -z "$tenant_a_pid" ]]; then tenant_a_pid="$pid"; else test "$pid" = "$tenant_a_pid"; fi
done

tenant_b_pid=""
for attempt in $(seq 1 5); do
  result="$(run_tenant "$token_b" tenant-b-password \
    "SELECT current_user || '|' || pg_backend_pid()")"
  role="${result%%|*}"
  pid="${result##*|}"
  test "$role" = "proxima_tenant_tenant_b"
  if [[ -z "$tenant_b_pid" ]]; then tenant_b_pid="$pid"; else test "$pid" = "$tenant_b_pid"; fi
done

# Different tenant roles must occupy different PgBouncer backend pools.
test "$tenant_a_pid" != "$tenant_b_pid"

# Cross-tenant reads are filtered and cross-tenant writes are rejected by RLS.
test "$(run_tenant "$token_a" tenant-a-password \
  "SELECT count(*) FROM pgbouncer_tenant_test.records WHERE tenant_id='tenant_b'")" = "0"
test "$(run_tenant "$token_b" tenant-b-password \
  "SELECT count(*) FROM pgbouncer_tenant_test.records WHERE tenant_id='tenant_a'")" = "0"

if run_tenant "$token_a" tenant-a-password \
  "INSERT INTO pgbouncer_tenant_test.records (tenant_id, secret) VALUES ('tenant_b', 'forbidden')" >/dev/null 2>&1; then
  echo "FAIL: Tenant A cross-tenant insert unexpectedly succeeded" >&2
  exit 1
fi

if run_tenant "invalid-token" tenant-a-password "SELECT 1" >/dev/null 2>&1; then
  echo "FAIL: invalid tenant token was accepted" >&2
  exit 1
fi

if PGPASSWORD=tenant-a-password PGOPTIONS='' \
  psql -X -A -t -v ON_ERROR_STOP=1 \
    "host=127.0.0.1 port=6432 dbname=appdb user=proxima sslmode=disable" \
    -c "SELECT 1" >/dev/null 2>&1; then
  echo "FAIL: missing tenant token was accepted" >&2
  exit 1
fi

echo "PASS: PgBouncer transaction pooling reused each tenant role's backend, cleared COMMIT/ROLLBACK transaction-local context, reset session state with DISCARD ALL before backend reuse, denied cross-tenant reads/writes, and rejected invalid/missing tenant context."
echo "Tenant A backend PID: $tenant_a_pid"
echo "Tenant B backend PID: $tenant_b_pid"
 | tail -n 1)"
  if [[ ! "$before_pid" =~ ^[0-9]+$ ]]; then
    echo "FAIL: $label did not return a valid backend PID (got: $before_pid)" >&2
    exit 1
  fi

  reuse_result="$(run_tenant "$token" "$password" \
    "SELECT pg_backend_pid() || '|' || COALESCE(NULLIF(current_setting('proxima.tenant_id', true), ''), '<unset>')")"
  reused_pid="${reuse_result%%|*}"
  context="${reuse_result#*|}"

  test "$reused_pid" = "$before_pid" || {
    echo "FAIL: $label did not inspect the same reused backend (before=$before_pid after=$reused_pid)" >&2
    exit 1
  }
  test "$context" = "<unset>" || {
    echo "FAIL: $label leaked tenant context '$context' onto reused backend $reused_pid" >&2
    exit 1
  }

  echo "PASS: $label cleared before backend $reused_pid was reused"
}

# SET LOCAL semantics: transaction-scoped identity must disappear on COMMIT.
assert_context_cleared_on_reused_backend \
  "COMMIT transaction-local context" "$token_a" tenant-a-password \
  "BEGIN; SELECT set_config('proxima.tenant_id', 'tenant_a', true);" "COMMIT"

# SET LOCAL semantics must also disappear when the transaction rolls back.
assert_context_cleared_on_reused_backend \
  "ROLLBACK transaction-local context" "$token_a" tenant-a-password \
  "BEGIN; SELECT set_config('proxima.tenant_id', 'tenant_a', true);" "ROLLBACK"

# A session-scoped setting survives COMMIT in PostgreSQL. Its disappearance on
# the same backend proves PgBouncer's configured DISCARD ALL reset ran before reuse.
assert_context_cleared_on_reused_backend \
  "PgBouncer DISCARD ALL session-state reset" "$token_a" tenant-a-password \
  "BEGIN; SELECT set_config('proxima.tenant_id', 'tenant_a', false);" "COMMIT"

# Confirm tenant A and tenant B each receive only their own data.
test "$(run_tenant "$token_a" tenant-a-password \
  "SELECT string_agg(secret, ',' ORDER BY secret) FROM pgbouncer_tenant_test.records")" = "A-secret"
test "$(run_tenant "$token_b" tenant-b-password \
  "SELECT string_agg(secret, ',' ORDER BY secret) FROM pgbouncer_tenant_test.records")" = "B-secret"

# Record backend PID reuse over five sequential connections for each tenant role.
tenant_a_pid=""
for attempt in $(seq 1 5); do
  result="$(run_tenant "$token_a" tenant-a-password \
    "SELECT current_user || '|' || pg_backend_pid()")"
  role="${result%%|*}"
  pid="${result##*|}"
  test "$role" = "proxima_tenant_tenant_a"
  if [[ -z "$tenant_a_pid" ]]; then tenant_a_pid="$pid"; else test "$pid" = "$tenant_a_pid"; fi
done

tenant_b_pid=""
for attempt in $(seq 1 5); do
  result="$(run_tenant "$token_b" tenant-b-password \
    "SELECT current_user || '|' || pg_backend_pid()")"
  role="${result%%|*}"
  pid="${result##*|}"
  test "$role" = "proxima_tenant_tenant_b"
  if [[ -z "$tenant_b_pid" ]]; then tenant_b_pid="$pid"; else test "$pid" = "$tenant_b_pid"; fi
done

# Different tenant roles must occupy different PgBouncer backend pools.
test "$tenant_a_pid" != "$tenant_b_pid"

# Cross-tenant reads are filtered and cross-tenant writes are rejected by RLS.
test "$(run_tenant "$token_a" tenant-a-password \
  "SELECT count(*) FROM pgbouncer_tenant_test.records WHERE tenant_id='tenant_b'")" = "0"
test "$(run_tenant "$token_b" tenant-b-password \
  "SELECT count(*) FROM pgbouncer_tenant_test.records WHERE tenant_id='tenant_a'")" = "0"

if run_tenant "$token_a" tenant-a-password \
  "INSERT INTO pgbouncer_tenant_test.records (tenant_id, secret) VALUES ('tenant_b', 'forbidden')" >/dev/null 2>&1; then
  echo "FAIL: Tenant A cross-tenant insert unexpectedly succeeded" >&2
  exit 1
fi

if run_tenant "invalid-token" tenant-a-password "SELECT 1" >/dev/null 2>&1; then
  echo "FAIL: invalid tenant token was accepted" >&2
  exit 1
fi

if PGPASSWORD=tenant-a-password PGOPTIONS='' \
  psql -X -A -t -v ON_ERROR_STOP=1 \
    "host=127.0.0.1 port=6432 dbname=appdb user=proxima sslmode=disable" \
    -c "SELECT 1" >/dev/null 2>&1; then
  echo "FAIL: missing tenant token was accepted" >&2
  exit 1
fi

echo "PASS: PgBouncer transaction pooling reused each tenant role's backend, cleared COMMIT/ROLLBACK transaction-local context, reset session state with DISCARD ALL before backend reuse, denied cross-tenant reads/writes, and rejected invalid/missing tenant context."
echo "Tenant A backend PID: $tenant_a_pid"
echo "Tenant B backend PID: $tenant_b_pid"
