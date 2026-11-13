#!/usr/bin/env bash
# Disposable local concurrency test for 100 and 1,000 distinct tenant identities.
# Synthetic data only. Tests bounded concurrency (25/50 clients), not 1,000
# simultaneous open connections or production capacity.
set -euo pipefail

PROJECT="proxima-concurrent-tenant-test"
OVERRIDE=".proxima-dev/compose.concurrent-test.yaml"
USERLIST=".proxima-dev/pgbouncer-concurrent-userlist.txt"
COMPOSE=(docker compose -p "$PROJECT" -f compose.dev.yaml -f "$OVERRIDE")

cleanup() {
  "${COMPOSE[@]}" down -v >/dev/null 2>&1 || true
  rm -f "$OVERRIDE" "$USERLIST"
}
trap cleanup EXIT

if [[ ! -f .proxima-dev/dev-config.json ]]; then
  python3 scripts/agata.py init
fi

export PROXIMA_TENANT_SIGNING_KEY
PROXIMA_TENANT_SIGNING_KEY="$(python3 -c 'import json; print(json.load(open(".proxima-dev/dev-config.json", encoding="utf-8"))["tenant_signing_key"])')"
export PROXIMA_MAX_CONNECTIONS=128

# Generate temporary PgBouncer credentials for all tenant roles. A Compose
# override replaces only the disposable container's auth-file mount.
python3 - <<'PY'
from pathlib import Path

lines = ['"proxima" "local-only-change-me"']
for i in range(1, 1001):
    suffix = f"{i:04d}"
    lines.append(f'"proxima_tenant_tenant_{suffix}" "tenant-{suffix}-password"')
Path(".proxima-dev/pgbouncer-concurrent-userlist.txt").write_text(
    "\n".join(lines) + "\n", encoding="utf-8"
)
Path(".proxima-dev/compose.concurrent-test.yaml").write_text(
    "services:\n"
    "  pgbouncer:\n"
    "    volumes:\n"
    "      - ./.proxima-dev/pgbouncer-concurrent-userlist.txt:/etc/pgbouncer/userlist.txt:ro\n",
    encoding="utf-8",
)
PY

"${COMPOSE[@]}" down -v >/dev/null 2>&1 || true
"${COMPOSE[@]}" up --build -d

for attempt in $(seq 1 45); do
  if curl -fsS http://127.0.0.1:9090/healthz >/dev/null 2>&1; then
    break
  fi
  sleep 2
done
curl -fsS http://127.0.0.1:9090/healthz >/dev/null

# Create 1,000 least-privilege roles and synthetic tenant records.
# A generic RLS policy binds visible rows to the suffix in PostgreSQL current_user.
"${COMPOSE[@]}" exec -T postgres psql -v ON_ERROR_STOP=1 -U proxima -d appdb <<'SQL'
DROP SCHEMA IF EXISTS concurrent_tenant_test CASCADE;
DO $$
DECLARE
  i integer;
  suffix text;
BEGIN
  FOR i IN 1..1000 LOOP
    suffix := lpad(i::text, 4, '0');
    EXECUTE format('DROP ROLE IF EXISTS %I', 'proxima_tenant_tenant_' || suffix);
    EXECUTE format(
      'CREATE ROLE %I LOGIN PASSWORD %L NOSUPERUSER NOBYPASSRLS',
      'proxima_tenant_tenant_' || suffix,
      'tenant-' || suffix || '-password'
    );
  END LOOP;
END $$;

CREATE SCHEMA concurrent_tenant_test;
CREATE TABLE concurrent_tenant_test.records (
  tenant_id text PRIMARY KEY,
  secret text NOT NULL
);
INSERT INTO concurrent_tenant_test.records (tenant_id, secret)
SELECT 'tenant_' || lpad(i::text, 4, '0'),
       'secret_' || lpad(i::text, 4, '0')
FROM generate_series(1, 1000) AS i;

ALTER TABLE concurrent_tenant_test.records ENABLE ROW LEVEL SECURITY;
ALTER TABLE concurrent_tenant_test.records FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_identity_isolation ON concurrent_tenant_test.records
  FOR ALL TO PUBLIC
  USING (tenant_id = substring(current_user FROM '^proxima_tenant_(.*)$'))
  WITH CHECK (tenant_id = substring(current_user FROM '^proxima_tenant_(.*)$'));

GRANT USAGE ON SCHEMA concurrent_tenant_test TO PUBLIC;
GRANT SELECT, INSERT, UPDATE, DELETE ON concurrent_tenant_test.records TO PUBLIC;
SQL

echo "Environment ready: 1,000 distinct tenant roles and 1,000 synthetic records."
echo "Starting 100-tenant validation (25 workers), followed by 1,000-tenant validation (50 workers)."

python3 - <<'PY'
import concurrent.futures
import hashlib
import hmac
import json
import os
import statistics
import subprocess
import time
from pathlib import Path

TOTAL_TENANTS = 1000
KEY = json.loads(Path(".proxima-dev/dev-config.json").read_text(encoding="utf-8"))["tenant_signing_key"]
DSN = "host=127.0.0.1 port=6432 dbname=appdb user=proxima sslmode=disable"

def token_for(tenant):
    expiry = int(time.time()) + 3600
    payload = f"v1.{tenant}.{expiry}"
    signature = hmac.new(KEY.encode("utf-8"), payload.encode("ascii"), hashlib.sha256).hexdigest()
    return f"{payload}.{signature}"

def check_one(index):
    suffix = f"{index:04d}"
    tenant = f"tenant_{suffix}"
    expected_role = f"proxima_tenant_{tenant}"
    expected_row = f"{tenant}:secret_{suffix}"
    env = os.environ.copy()
    env["PGPASSWORD"] = f"tenant-{suffix}-password"
    env["PGOPTIONS"] = f"-c proxima_tenant_token={token_for(tenant)}"
    started = time.perf_counter()
    try:
        result = subprocess.run(
            ["psql", "-X", "-A", "-t", "-v", "ON_ERROR_STOP=1", DSN,
             "-c", "SELECT current_user || '|' || string_agg(tenant_id || ':' || secret, ',' ORDER BY tenant_id) FROM concurrent_tenant_test.records"],
            env=env, text=True, capture_output=True, timeout=45
        )
    except subprocess.TimeoutExpired:
        return index, False, time.perf_counter() - started, "psql client timed out after 45 seconds"
    elapsed = time.perf_counter() - started
    output = result.stdout.strip()
    expected = f"{expected_role}|{expected_row}"
    if result.returncode != 0:
        return index, False, elapsed, (result.stderr.strip() or f"psql exit {result.returncode}")
    if output != expected:
        return index, False, elapsed, f"identity/data mismatch: expected {expected!r}, got {output!r}"
    return index, True, elapsed, ""

def run_batch(count, workers, label):
    print(f"\n--- {label}: {count} distinct tenants; at most {workers} concurrent clients ---", flush=True)
    started = time.perf_counter()
    latencies = []
    failures = []
    completed = 0
    with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as pool:
        futures = [pool.submit(check_one, i) for i in range(1, count + 1)]
        for future in concurrent.futures.as_completed(futures):
            index, ok, elapsed, detail = future.result()
            completed += 1
            latencies.append(elapsed)
            if not ok:
                failures.append((index, detail))
            if completed % 100 == 0 or completed == count:
                print(f"Progress: {completed}/{count}; failures={len(failures)}", flush=True)
    duration = time.perf_counter() - started
    ordered = sorted(latencies)
    p95 = ordered[min(len(ordered)-1, int(len(ordered)*0.95))]
    print(f"Completed: {count}; passed: {count-len(failures)}; failed: {len(failures)}")
    print(f"Elapsed: {duration:.2f}s; observed validation throughput: {count/duration:.2f} tenant checks/s")
    print(f"Client-command latency: median={statistics.median(latencies):.3f}s; p95={p95:.3f}s; max={max(latencies):.3f}s")
    if failures:
        for index, detail in failures[:10]:
            print(f"FAIL tenant_{index:04d}: {detail}")
        raise SystemExit(f"FAIL: {len(failures)} tenant checks failed in {label}")
    print(f"PASS: every tenant saw exactly its own role and exactly its own protected row.")

run_batch(100, 25, "100-tenant concurrency")
run_batch(TOTAL_TENANTS, 50, "1,000-tenant concurrency")
print("\nPASS: 1,000 distinct tenant identities validated with bounded concurrency.")
print("SCOPE: 50 concurrent client processes maximum, not 1,000 simultaneous open connections.")
PY
