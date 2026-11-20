#!/usr/bin/env bash
set -euo pipefail
: "${MSSQL_SA_PASSWORD:?MSSQL_SA_PASSWORD is required}"
sqlserver_id="proxima-sqlserver-ci-$RANDOM"
cleanup() { docker rm -f "$sqlserver_id" >/dev/null 2>&1 || true; }
trap cleanup EXIT
docker run -d --name "$sqlserver_id" -p 127.0.0.1:1433:1433 -e ACCEPT_EULA=Y -e MSSQL_PID=Developer -e MSSQL_SA_PASSWORD="$MSSQL_SA_PASSWORD" mcr.microsoft.com/mssql/server:2022-latest >/dev/null
SQLCMD="$(command -v sqlcmd || true)"
[[ -n "$SQLCMD" ]] || SQLCMD="/opt/mssql-tools18/bin/sqlcmd"
[[ -x "$SQLCMD" ]] || { echo "sqlcmd is not installed" >&2; exit 1; }
tenant_a_password="$(openssl rand -base64 24)"
tenant_b_password="$(openssl rand -base64 24)"
admin(){ "$SQLCMD" -C -S 127.0.0.1,1433 -U sa -P "$MSSQL_SA_PASSWORD" -b "$@"; }
ready=0
for _ in $(seq 1 60); do if admin -Q "SELECT 1" >/dev/null 2>&1; then ready=1; break; fi; sleep 2; done
[[ "$ready" == 1 ]] || { docker logs "$sqlserver_id"; echo "SQL Server did not become ready" >&2; exit 1; }
admin -v TENANT_A_PASSWORD="$tenant_a_password" -v TENANT_B_PASSWORD="$tenant_b_password" -i scripts/sqlserver-provision-two-tenants.sql
tenant_a(){ "$SQLCMD" -C -S 127.0.0.1,1433 -U proxima_tenant_a -P "$tenant_a_password" -b "$@"; }
tenant_b(){ "$SQLCMD" -C -S 127.0.0.1,1433 -U proxima_tenant_b -P "$tenant_b_password" -b "$@"; }
[[ "$(tenant_a -h -1 -W -Q "SET NOCOUNT ON; SELECT payload FROM app.records WHERE id=1")" == "tenant-a" ]]
[[ "$(tenant_b -h -1 -W -Q "SET NOCOUNT ON; SELECT payload FROM app.records WHERE id=1")" == "tenant-b" ]]
[[ "$(tenant_a -h -1 -W -Q "SET NOCOUNT ON; SELECT CASE WHEN IS_MEMBER('db_owner')=0 AND IS_SRVROLEMEMBER('sysadmin')=0 THEN 1 ELSE 0 END")" == "1" ]]
[[ "$(tenant_b -h -1 -W -Q "SET NOCOUNT ON; SELECT CASE WHEN IS_MEMBER('db_owner')=0 AND IS_SRVROLEMEMBER('sysadmin')=0 THEN 1 ELSE 0 END")" == "1" ]]
tenant_a -Q "INSERT app.records VALUES(2,N'a-write'); UPDATE app.records SET payload=N'a-updated' WHERE id=2; DELETE app.records WHERE id=2"
tenant_b -Q "INSERT app.records VALUES(2,N'b-write'); UPDATE app.records SET payload=N'b-updated' WHERE id=2; DELETE app.records WHERE id=2"
if tenant_a -Q "SELECT payload FROM proxima_tenant_b_db.app.records" >/dev/null 2>&1; then echo "tenant A crossed into tenant B database" >&2; exit 1; fi
if tenant_b -Q "SELECT payload FROM proxima_tenant_a_db.app.records" >/dev/null 2>&1; then echo "tenant B crossed into tenant A database" >&2; exit 1; fi
if tenant_a -Q "USE proxima_tenant_b_db; SELECT 1" >/dev/null 2>&1; then echo "tenant A switched to tenant B database" >&2; exit 1; fi
if tenant_a -Q "CREATE TABLE app.unauthorized(id int)" >/dev/null 2>&1; then echo "tenant A created schema objects" >&2; exit 1; fi
if tenant_a -Q "EXECUTE AS LOGIN='proxima_tenant_b'; SELECT 1" >/dev/null 2>&1; then echo "tenant A impersonated tenant B" >&2; exit 1; fi
if "$SQLCMD" -C -S 127.0.0.1,1433 -U proxima_tenant_a -P wrong-password -d proxima_tenant_a_db -b -Q "SELECT 1" >/dev/null 2>&1; then echo "invalid SQL Server credentials unexpectedly succeeded" >&2; exit 1; fi
echo "SQL Server native database-per-tenant isolation: PASS"
