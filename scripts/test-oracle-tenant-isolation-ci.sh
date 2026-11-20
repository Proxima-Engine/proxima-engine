#!/usr/bin/env bash
set -euo pipefail

: "${ORACLE_PASSWORD:?ORACLE_PASSWORD is required}"
container="proxima-oracle-ci-$RANDOM"
tenant_a_password="$(openssl rand -hex 24)"
tenant_b_password="$(openssl rand -hex 24)"
cleanup() { docker rm -f "$container" >/dev/null 2>&1 || true; }
trap cleanup EXIT

docker run -d --name "$container" -p 127.0.0.1:1521:1521 \
  -e ORACLE_PASSWORD="$ORACLE_PASSWORD" \
  gvenzl/oracle-free:23-slim-faststart >/dev/null

ready=0
for _ in $(seq 1 90); do
  if docker exec "$container" bash -lc 'printf "SELECT 1 FROM dual;\\nEXIT\\n" | sqlplus -L -s system/"$ORACLE_PASSWORD"@//localhost:1521/FREEPDB1' >/dev/null 2>&1; then
    ready=1; break
  fi
  sleep 5
done
if [[ "$ready" != 1 ]]; then docker logs "$container"; echo "Oracle Free did not become ready" >&2; exit 1; fi

admin_sql() {
  docker exec -i "$container" bash -lc \
    'sqlplus -L -s system/"$ORACLE_PASSWORD"@//localhost:1521/FREEPDB1'
}
admin_sql <<SQL
WHENEVER SQLERROR EXIT SQL.SQLCODE
CREATE USER PROXIMA_TENANT_A_OWNER IDENTIFIED BY "$tenant_a_password" DEFAULT TABLESPACE USERS TEMPORARY TABLESPACE TEMP QUOTA 100M ON USERS;
GRANT CREATE SESSION, CREATE TABLE, CREATE SEQUENCE, CREATE VIEW, CREATE PROCEDURE, CREATE TRIGGER TO PROXIMA_TENANT_A_OWNER;
ALTER USER PROXIMA_TENANT_A_OWNER DEFAULT ROLE NONE;
CREATE USER PROXIMA_TENANT_B_OWNER IDENTIFIED BY "$tenant_b_password" DEFAULT TABLESPACE USERS TEMPORARY TABLESPACE TEMP QUOTA 100M ON USERS;
GRANT CREATE SESSION, CREATE TABLE, CREATE SEQUENCE, CREATE VIEW, CREATE PROCEDURE, CREATE TRIGGER TO PROXIMA_TENANT_B_OWNER;
ALTER USER PROXIMA_TENANT_B_OWNER DEFAULT ROLE NONE;
EXIT
SQL

tenant_sql() {
  local user="$1" password="$2"
  docker exec -i -e DB_USER="$user" -e DB_PASSWORD="$password" "$container" bash -lc \
    'sqlplus -L -s "$DB_USER/$DB_PASSWORD@//localhost:1521/FREEPDB1"'
}
a_output="$(tenant_sql PROXIMA_TENANT_A_OWNER "$tenant_a_password" <<'SQL'
WHENEVER SQLERROR EXIT SQL.SQLCODE
CREATE TABLE records (id NUMBER PRIMARY KEY, payload VARCHAR2(80) NOT NULL);
INSERT INTO records VALUES (1, 'tenant-a-only');
COMMIT;
SELECT payload FROM records WHERE id = 1;
EXIT
SQL
)"
b_output="$(tenant_sql PROXIMA_TENANT_B_OWNER "$tenant_b_password" <<'SQL'
WHENEVER SQLERROR EXIT SQL.SQLCODE
CREATE TABLE records (id NUMBER PRIMARY KEY, payload VARCHAR2(80) NOT NULL);
INSERT INTO records VALUES (1, 'tenant-b-only');
COMMIT;
SELECT payload FROM records WHERE id = 1;
EXIT
SQL
)"
grep -q 'tenant-a-only' <<<"$a_output"
grep -q 'tenant-b-only' <<<"$b_output"

expect_denied() {
  local user="$1" password="$2" sql="$3"
  if tenant_sql "$user" "$password" <<SQL >/dev/null 2>&1
WHENEVER SQLERROR EXIT SQL.SQLCODE
$sql
EXIT
SQL
  then
    echo "Oracle tenant isolation failure: statement unexpectedly succeeded: $sql" >&2
    exit 1
  fi
}
expect_denied PROXIMA_TENANT_A_OWNER "$tenant_a_password" "SELECT payload FROM PROXIMA_TENANT_B_OWNER.RECORDS"
expect_denied PROXIMA_TENANT_B_OWNER "$tenant_b_password" "SELECT payload FROM PROXIMA_TENANT_A_OWNER.RECORDS"
expect_denied PROXIMA_TENANT_A_OWNER "$tenant_a_password" 
expect_denied PROXIMA_TENANT_B_OWNER "$tenant_b_password" "SET ROLE DBA"

echo "Oracle schema-per-tenant isolation: PASS"
ALTER SESSION SET CURRENT_SCHEMA=PROXIMA_TENANT_B_OWNER\nSELECT payload FROM RECORDS'
expect_denied PROXIMA_TENANT_B_OWNER "$tenant_b_password" "SET ROLE DBA"

echo "Oracle schema-per-tenant isolation: PASS"
