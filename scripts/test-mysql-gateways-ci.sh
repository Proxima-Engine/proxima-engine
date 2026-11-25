#!/usr/bin/env bash
set -euo pipefail
MYSQL_ROOT_PASSWORD="${MYSQL_ROOT_PASSWORD:-proxima-mysql-ci}"
MARIADB_ROOT_PASSWORD="${MARIADB_ROOT_PASSWORD:-proxima-mariadb-ci}"
GATEWAY_PID=""
cleanup() { if [[ -n "$GATEWAY_PID" ]]; then kill "$GATEWAY_PID" 2>/dev/null || true; wait "$GATEWAY_PID" 2>/dev/null || true; GATEWAY_PID=""; fi; }
trap cleanup EXIT
# The gateway intentionally refuses to start without a TLS certificate and key.
# Generate a disposable CI-only certificate for the loopback integration listener.
MYSQL_TLS_DIR="$(mktemp -d)"
cleanup_all() {
 cleanup
 rm -rf "$MYSQL_TLS_DIR"
}
trap cleanup_all EXIT
openssl req -x509 -newkey rsa:2048 -nodes -keyout "$MYSQL_TLS_DIR/gateway.key" -out "$MYSQL_TLS_DIR/gateway.crt" -days 1 -subj "/CN=localhost" >/dev/null 2>&1
export PROXIMA_MYSQL_TLS_CERT_FILE="$MYSQL_TLS_DIR/gateway.crt"
export PROXIMA_MYSQL_TLS_KEY_FILE="$MYSQL_TLS_DIR/gateway.key"
wait_db() { local p="$1" pw="$2"; for _ in $(seq 1 60); do mysqladmin --protocol=TCP -h 127.0.0.1 -P "$p" -uroot -p"$pw" ping --silent >/dev/null 2>&1 && return 0; sleep 2; done; return 1; }
provision() {
 mysql --protocol=TCP -h 127.0.0.1 -P "$1" -uroot -p"$2" <<'SQL'
CREATE DATABASE IF NOT EXISTS tenant_a;
CREATE DATABASE IF NOT EXISTS tenant_b;
CREATE TABLE IF NOT EXISTS tenant_a.records (id BIGINT PRIMARY KEY, value VARCHAR(255) NOT NULL);
CREATE TABLE IF NOT EXISTS tenant_b.records (id BIGINT PRIMARY KEY, value VARCHAR(255) NOT NULL);
DELETE FROM tenant_a.records; DELETE FROM tenant_b.records;
INSERT INTO tenant_a.records VALUES (1, 'tenant-a-secret');
INSERT INTO tenant_b.records VALUES (1, 'tenant-b-secret');
CREATE USER IF NOT EXISTS 'tenant_a_gateway'@'%' IDENTIFIED BY 'TenantAUpstream2026!';
CREATE USER IF NOT EXISTS 'tenant_b_gateway'@'%' IDENTIFIED BY 'TenantBUpstream2026!';
GRANT SELECT, INSERT, UPDATE, DELETE ON tenant_a.* TO 'tenant_a_gateway'@'%';
GRANT SELECT, INSERT, UPDATE, DELETE ON tenant_b.* TO 'tenant_b_gateway'@'%';
FLUSH PRIVILEGES;
SQL
}
registry() {
 MYSQL_UPSTREAM_PORT="$1" python3 - <<'PY'
import hashlib,json,os
p=os.environ["MYSQL_UPSTREAM_PORT"]
users=[]
for u,t,d,pw,up,upp in [("client_a","tenant-a","tenant_a","ClientPassA2026","tenant_a_gateway","TenantAUpstream2026!"),("client_b","tenant-b","tenant_b","ClientPassB2026","tenant_b_gateway","TenantBUpstream2026!")]:
 stage1=hashlib.sha256(pw.encode()).digest()
 stage2=hashlib.sha256(stage1).hexdigest()
 users.append({"username":u,"tenant_id":t,"database":d,"upstream_url":f"mysql://{up}:{upp}@127.0.0.1:{p}/{d}","auth_plugin":"caching_sha2_password","password_sha256":stage2})
with open("/tmp/proxima-mysql-registry.json","w") as f: json.dump({"users":users},f)
PY
}
run_suite() {
 registry "$2"
 PROXIMA_MYSQL_IDENTITY_REGISTRY=/tmp/proxima-mysql-registry.json PROXIMA_MYSQL_LISTEN_ADDR=127.0.0.1:3307 target/debug/proxima-mysql-gateway >/tmp/proxima-mysql-gateway.log 2>&1 &
 GATEWAY_PID=$!
 for _ in $(seq 1 30); do nc -z 127.0.0.1 3307 && break; kill -0 "$GATEWAY_PID" 2>/dev/null || { cat /tmp/proxima-mysql-gateway.log; return 1; }; sleep 1; done
 nc -z 127.0.0.1 3307 || { cat /tmp/proxima-mysql-gateway.log; return 1; }
 cargo test -p proxima-engine --test "$1" -- --ignored --test-threads=1
 cleanup
}
wait_db 3306 "$MYSQL_ROOT_PASSWORD"
wait_db 3308 "$MARIADB_ROOT_PASSWORD"
provision 3306 "$MYSQL_ROOT_PASSWORD"
provision 3308 "$MARIADB_ROOT_PASSWORD"
run_suite mysql_gateway_integration 3306
run_suite mariadb_gateway_integration 3308
