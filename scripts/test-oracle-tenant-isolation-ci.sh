#!/usr/bin/env bash
set -euo pipefail

: "${ORACLE_PASSWORD:?ORACLE_PASSWORD is required}"
container="proxima-oracle-ci-$RANDOM"
tenant_a_password="$(openssl rand -hex 24)"
tenant_b_password="$(openssl rand -hex 24)"
cleanup() { docker rm -f "$container" >/dev/null 2>&1 || true; }
trap cleanup EXIT

# Docker Hub token-service requests can reset independently of the runner's
# other image pulls. Retry the explicit pull before starting the disposable DB.
image="gvenzl/oracle-free:23-slim-faststart"
pulled=0
for attempt in 1 2 3 4 5; do
  if docker pull "$image"; then
    pulled=1
    break
  fi
  if [[ "$attempt" -lt 5 ]]; then
    sleep "$((attempt * 5))"
  fi
done
if [[ "$pulled" != 1 ]]; then
  echo "Unable to pull Oracle Free image after five attempts" >&2
  exit 1
fi

docker run -d --name "$container" -p 127.0.0.1:1521:1521 \
  -e ORACLE_PASSWORD="$ORACLE_PASSWORD" \
  "$image" >/dev/null

ready=0
for _ in $(seq 1 90); do
  if docker exec "$container" bash -lc 'printf "SELECT 1 FROM dual;\nEXIT\n" | sqlplus -L -s system/"$ORACLE_PASSWORD"@//localhost:1521/FREEPDB1' >/dev/null 2>&1; then
    ready=1
    break
  fi
  sleep 5
done
if [[ "$ready" != 1 ]]; then
  docker logs "$container"
  echo "Oracle Free did not become ready" >&2
  exit 1
fi

docker exec -i "$container" bash -lc 'sqlplus -L -s system/"$ORACLE_PASSWORD"@//localhost:1521/FREEPDB1' <<SQL
WHENEVER SQLERROR EXIT FAILURE
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
    'exec sqlplus -L -s "$DB_USER/$DB_PASSWORD@//localhost:1521/FREEPDB1"'
}

a_output="$(tenant_sql PROXIMA_TENANT_A_OWNER "$tenant_a_password" <<'SQL'
WHENEVER SQLERROR EXIT FAILURE
CREATE TABLE records (id NUMBER PRIMARY KEY, payload VARCHAR2(80) NOT NULL);
INSERT INTO records VALUES (1, 'tenant-a-only');
COMMIT;
SELECT payload FROM records WHERE id = 1;
SELECT USER, SYS_CONTEXT('USERENV','SESSION_USER'), SYS_CONTEXT('USERENV','CURRENT_SCHEMA'), SYS_CONTEXT('USERENV','ISDBA') FROM dual;
SELECT PRIVILEGE FROM SESSION_PRIVS WHERE PRIVILEGE LIKE '%ANY%';
SELECT PRIVILEGE, SCHEMA FROM SESSION_SCHEMA_PRIVS;
SELECT GRANTED_ROLE FROM USER_ROLE_PRIVS;
EXIT
SQL
)"
b_output="$(tenant_sql PROXIMA_TENANT_B_OWNER "$tenant_b_password" <<'SQL'
WHENEVER SQLERROR EXIT FAILURE
CREATE TABLE records (id NUMBER PRIMARY KEY, payload VARCHAR2(80) NOT NULL);
INSERT INTO records VALUES (1, 'tenant-b-only');
COMMIT;
SELECT payload FROM records WHERE id = 1;
SELECT USER, SYS_CONTEXT('USERENV','SESSION_USER'), SYS_CONTEXT('USERENV','CURRENT_SCHEMA'), SYS_CONTEXT('USERENV','ISDBA') FROM dual;
EXIT
SQL
)"

# Assert that neither schema owner nor PUBLIC has an ANY-table privilege or
# an object grant on the other tenant's table before running negative probes.
docker exec -i "$container" bash -lc 'sqlplus -L -s system/"$ORACLE_PASSWORD"@//localhost:1521/FREEPDB1' <<'SQL'
WHENEVER SQLERROR EXIT FAILURE
SELECT grantee, privilege FROM dba_sys_privs
 WHERE grantee IN ('PROXIMA_TENANT_A_OWNER','PROXIMA_TENANT_B_OWNER','PUBLIC');
SELECT grantee, granted_role, default_role FROM dba_role_privs
 WHERE grantee IN ('PROXIMA_TENANT_A_OWNER','PROXIMA_TENANT_B_OWNER','PUBLIC');
SELECT grantee, owner, table_name, privilege FROM dba_tab_privs
 WHERE owner IN ('PROXIMA_TENANT_A_OWNER','PROXIMA_TENANT_B_OWNER')
   AND table_name='RECORDS';
SELECT grantee, schema, privilege FROM dba_schema_privs
 WHERE grantee IN ('PROXIMA_TENANT_A_OWNER','PROXIMA_TENANT_B_OWNER','PUBLIC');
SELECT owner, table_name FROM dba_tables
 WHERE owner IN ('PROXIMA_TENANT_A_OWNER','PROXIMA_TENANT_B_OWNER')
   AND table_name='RECORDS';
EXIT
SQL
grep -q 'tenant-a-only' <<<"$a_output"
grep -q 'tenant-b-only' <<<"$b_output"
grep -q 'PROXIMA_TENANT_A_OWNER' <<<"$a_output"
grep -q 'PROXIMA_TENANT_B_OWNER' <<<"$b_output"
printf 'Oracle tenant A session diagnostics:\n%s\n' "$a_output"
printf 'Oracle tenant B session diagnostics:\n%s\n' "$b_output"

expect_denied() {
  local user="$1" password="$2" statement="$3"
  local output
  if output="$(tenant_sql "$user" "$password" <<SQL
WHENEVER SQLERROR EXIT FAILURE
SELECT USER, SYS_CONTEXT('USERENV','SESSION_USER'), SYS_CONTEXT('USERENV','CURRENT_SCHEMA'), SYS_CONTEXT('USERENV','ISDBA') FROM dual;
$statement
EXIT
SQL
)"; then
    echo "Oracle tenant isolation failure: statement unexpectedly succeeded for $user: $statement" >&2
    printf '%s\n' "$output" >&2
    exit 1
  fi
}
expect_denied PROXIMA_TENANT_A_OWNER "$tenant_a_password" "SELECT payload FROM PROXIMA_TENANT_B_OWNER.RECORDS"
expect_denied PROXIMA_TENANT_B_OWNER "$tenant_b_password" "SELECT payload FROM PROXIMA_TENANT_A_OWNER.RECORDS"
expect_denied PROXIMA_TENANT_A_OWNER "$tenant_a_password" "SET ROLE DBA"

echo "Oracle schema-per-tenant isolation: PASS"
