$ErrorActionPreference = "Stop"
Set-StrictMode -Version Latest

$repoRoot = Split-Path -Parent $PSScriptRoot
$composeFile = Join-Path $repoRoot "docker-compose.mysql.yml"
$rootPassword = "proxima-mysql-dev-only"

function Invoke-MySql {
    param(
        [Parameter(Mandatory)][string]$User,
        [Parameter(Mandatory)][string]$Password,
        [Parameter(Mandatory)][string]$Sql,
        [switch]$RequireTls
    )
    $dockerArgs = @(
        "compose", "-f", $composeFile, "exec", "-T",
        "-e", "MYSQL_PWD=$Password",
        "mysql-test", "mysql", "--protocol=TCP", "--host=127.0.0.1",
        "--user=$User", "--batch", "--skip-column-names"
    )
    if ($RequireTls) {
        $dockerArgs += "--ssl-mode=VERIFY_IDENTITY"
        $dockerArgs += "--ssl-ca=/tmp/mysql-certs/ca.pem"
    }
    $dockerArgs += "--execute=$Sql"
    $output = & docker @dockerArgs 2>&1
    $exitCode = $LASTEXITCODE
    return [pscustomobject]@{ ExitCode = $exitCode; Output = ($output -join [Environment]::NewLine) }
}

function Assert-MySqlSuccess {
    param([string]$Name, [string]$User, [string]$Password, [string]$Sql, [switch]$RequireTls)
    $result = Invoke-MySql -User $User -Password $Password -Sql $Sql -RequireTls:$RequireTls
    if ($result.ExitCode -ne 0) { throw "$Name failed: $($result.Output)" }
    Write-Host "[PASS] $Name" -ForegroundColor Green
    return $result.Output
}

function Assert-MySqlDenied {
    param([string]$Name, [string]$User, [string]$Password, [string]$Sql)
    $result = Invoke-MySql -User $User -Password $Password -Sql $Sql -RequireTls
    if ($result.ExitCode -eq 0) { throw "$Name unexpectedly succeeded. Output: $($result.Output)" }
    Write-Host "[PASS] $Name (denied)" -ForegroundColor Green
}

$prepareScript = Join-Path $PSScriptRoot "prepare-mysql-dev-certs.ps1"
& $prepareScript
if ($LASTEXITCODE -ne 0) { throw "Local MySQL TLS certificate preparation failed." }

Write-Host "--- Start disposable MySQL 8.4 ---" -ForegroundColor Cyan
& docker compose -f $composeFile up -d --wait
if ($LASTEXITCODE -ne 0) { throw "MySQL test container did not become healthy." }

$setup = @"
DROP USER IF EXISTS 'ap_test_a_runtime'@'127.0.0.1', 'ap_test_b_runtime'@'127.0.0.1', 'ap_test_a_migrator'@'127.0.0.1', 'ap_test_b_migrator'@'127.0.0.1';
DROP DATABASE IF EXISTS ap_test_tenant_a;
DROP DATABASE IF EXISTS ap_test_tenant_b;
CREATE DATABASE ap_test_tenant_a CHARACTER SET utf8mb4 COLLATE utf8mb4_0900_ai_ci;
CREATE DATABASE ap_test_tenant_b CHARACTER SET utf8mb4 COLLATE utf8mb4_0900_ai_ci;
CREATE USER 'ap_test_a_runtime'@'127.0.0.1' IDENTIFIED BY 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa' REQUIRE SSL WITH MAX_USER_CONNECTIONS 64;
CREATE USER 'ap_test_b_runtime'@'127.0.0.1' IDENTIFIED BY 'bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb' REQUIRE SSL WITH MAX_USER_CONNECTIONS 64;
CREATE USER 'ap_test_a_migrator'@'127.0.0.1' IDENTIFIED BY 'cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc' REQUIRE SSL WITH MAX_USER_CONNECTIONS 4;
CREATE USER 'ap_test_b_migrator'@'127.0.0.1' IDENTIFIED BY 'dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd' REQUIRE SSL WITH MAX_USER_CONNECTIONS 4;
GRANT SELECT, INSERT, UPDATE, DELETE, EXECUTE, CREATE TEMPORARY TABLES, LOCK TABLES, SHOW VIEW ON ap_test_tenant_a.* TO 'ap_test_a_runtime'@'127.0.0.1';
GRANT SELECT, INSERT, UPDATE, DELETE, EXECUTE, CREATE TEMPORARY TABLES, LOCK TABLES, SHOW VIEW ON ap_test_tenant_b.* TO 'ap_test_b_runtime'@'127.0.0.1';
GRANT SELECT, INSERT, UPDATE, DELETE, CREATE, ALTER, INDEX, DROP, REFERENCES, CREATE VIEW, SHOW VIEW, TRIGGER, EVENT, CREATE ROUTINE, ALTER ROUTINE, EXECUTE ON ap_test_tenant_a.* TO 'ap_test_a_migrator'@'127.0.0.1';
GRANT SELECT, INSERT, UPDATE, DELETE, CREATE, ALTER, INDEX, DROP, REFERENCES, CREATE VIEW, SHOW VIEW, TRIGGER, EVENT, CREATE ROUTINE, ALTER ROUTINE, EXECUTE ON ap_test_tenant_b.* TO 'ap_test_b_migrator'@'127.0.0.1';
CREATE TABLE ap_test_tenant_a.records (id INT PRIMARY KEY, secret VARCHAR(100) NOT NULL);
CREATE TABLE ap_test_tenant_b.records (id INT PRIMARY KEY, secret VARCHAR(100) NOT NULL);
INSERT INTO ap_test_tenant_a.records VALUES (1, 'tenant-a-secret');
INSERT INTO ap_test_tenant_b.records VALUES (1, 'tenant-b-secret');
CREATE PROCEDURE ap_test_tenant_a.read_secret() SELECT secret FROM ap_test_tenant_a.records;
"@

try {
    Write-Host "--- Provision isolated test tenants ---" -ForegroundColor Cyan
    Assert-MySqlSuccess -Name "Create two isolated tenant databases and scoped accounts" -User "root" -Password $rootPassword -Sql $setup | Out-Null

    Write-Host "--- Runtime account checks ---" -ForegroundColor Cyan
    $own = Assert-MySqlSuccess -Name "Tenant A reads its own data over TLS" -User "ap_test_a_runtime" -Password ("a" * 64) -Sql "SELECT secret FROM ap_test_tenant_a.records" -RequireTls
    if ($own.Trim() -ne "tenant-a-secret") { throw "Tenant A returned unexpected own-tenant data." }
    Assert-MySqlDenied -Name "Tenant A cannot read Tenant B" -User "ap_test_a_runtime" -Password ("a" * 64) -Sql "SELECT secret FROM ap_test_tenant_b.records"
    Assert-MySqlDenied -Name "Tenant A cannot write Tenant B" -User "ap_test_a_runtime" -Password ("a" * 64) -Sql "INSERT INTO ap_test_tenant_b.records VALUES (2, 'forbidden')"
    Assert-MySqlDenied -Name "Runtime account cannot perform DDL" -User "ap_test_a_runtime" -Password ("a" * 64) -Sql "CREATE TABLE ap_test_tenant_a.forbidden (id INT)"
    Assert-MySqlDenied -Name "Runtime account cannot create temporary tables" -User "ap_test_a_runtime" -Password ("a" * 64) -Sql "CREATE TEMPORARY TABLE ap_test_tenant_a.temp_forbidden (id INT)"
    Assert-MySqlDenied -Name "Runtime account cannot lock tables" -User "ap_test_a_runtime" -Password ("a" * 64) -Sql "LOCK TABLES ap_test_tenant_a.records READ"
    Assert-MySqlDenied -Name "Runtime account cannot execute stored procedures" -User "ap_test_a_runtime" -Password ("a" * 64) -Sql "CALL ap_test_tenant_a.read_secret()"
    Assert-MySqlSuccess -Name "Runtime account can create a temporary table in its own database" -User "ap_test_a_runtime" -Password ("a" * 64) -Sql "CREATE TEMPORARY TABLE ap_test_tenant_a.temp_probe (id INT); INSERT INTO ap_test_tenant_a.temp_probe VALUES (1); SELECT COUNT(*) FROM ap_test_tenant_a.temp_probe" -RequireTls | Out-Null
    Assert-MySqlSuccess -Name "Runtime account can lock and unlock its own tenant table" -User "ap_test_a_runtime" -Password ("a" * 64) -Sql "LOCK TABLES ap_test_tenant_a.records READ; UNLOCK TABLES" -RequireTls | Out-Null
    Assert-MySqlSuccess -Name "Tenant A runtime can execute its own stored routine" -User "ap_test_a_runtime" -Password ("a" * 64) -Sql "CALL ap_test_tenant_a.tenant_count()" -RequireTls | Out-Null
    Assert-MySqlDenied -Name "Tenant A runtime cannot execute Tenant B stored routine" -User "ap_test_a_runtime" -Password ("a" * 64) -Sql "CALL ap_test_tenant_b.tenant_count()"
    $ownB = Assert-MySqlSuccess -Name "Tenant B reads its own data over TLS" -User "ap_test_b_runtime" -Password ("b" * 64) -Sql "SELECT secret FROM ap_test_tenant_b.records" -RequireTls
    if ($ownB.Trim() -ne "tenant-b-secret") { throw "Tenant B returned unexpected own-tenant data." }
    Assert-MySqlDenied -Name "Tenant B cannot read Tenant A" -User "ap_test_b_runtime" -Password ("b" * 64) -Sql "SELECT secret FROM ap_test_tenant_a.records"
    Assert-MySqlDenied -Name "Tenant B cannot write Tenant A" -User "ap_test_b_runtime" -Password ("b" * 64) -Sql "UPDATE ap_test_tenant_a.records SET secret='forbidden' WHERE id=1"
    Assert-MySqlDenied -Name "Runtime account cannot inspect MySQL system users" -User "ap_test_a_runtime" -Password ("a" * 64) -Sql "SELECT user, host FROM mysql.user"
    Assert-MySqlDenied -Name "Runtime account cannot create database users" -User "ap_test_a_runtime" -Password ("a" * 64) -Sql "CREATE USER 'ap_forbidden'@'127.0.0.1' IDENTIFIED BY 'eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee'"

    Write-Host "--- Migration account checks ---" -ForegroundColor Cyan
    Assert-MySqlSuccess -Name "Tenant A migrator can create objects in Tenant A" -User "ap_test_a_migrator" -Password ("c" * 64) -Sql "CREATE TABLE ap_test_tenant_a.migration_probe (id INT)" -RequireTls | Out-Null
    Assert-MySqlSuccess -Name "Tenant A migrator can create a tenant-local stored routine" -User "ap_test_a_migrator" -Password ("c" * 64) -Sql "CREATE PROCEDURE ap_test_tenant_a.tenant_count() SELECT COUNT(*) FROM ap_test_tenant_a.records" -RequireTls | Out-Null
    Assert-MySqlSuccess -Name "Tenant B migrator can create a tenant-local stored routine" -User "ap_test_b_migrator" -Password ("d" * 64) -Sql "CREATE PROCEDURE ap_test_tenant_b.tenant_count() SELECT COUNT(*) FROM ap_test_tenant_b.records" -RequireTls | Out-Null
    Assert-MySqlDenied -Name "Tenant A migrator cannot create objects in Tenant B" -User "ap_test_a_migrator" -Password ("c" * 64) -Sql "CREATE TABLE ap_test_tenant_b.forbidden (id INT)"

    Write-Host "--- Credential rotation checks ---" -ForegroundColor Cyan
    Assert-MySqlSuccess -Name "Rotate Tenant B runtime password" -User "root" -Password $rootPassword -Sql "ALTER USER 'ap_test_b_runtime'@'127.0.0.1' IDENTIFIED BY 'ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff' REQUIRE SSL" | Out-Null
    Assert-MySqlDenied -Name "Old Tenant B password is rejected after rotation" -User "ap_test_b_runtime" -Password ("b" * 64) -Sql "SELECT 1"
    $rotated = Assert-MySqlSuccess -Name "New Tenant B password works after rotation" -User "ap_test_b_runtime" -Password ("f" * 64) -Sql "SELECT secret FROM ap_test_tenant_b.records" -RequireTls
    if ($rotated.Trim() -ne "tenant-b-secret") { throw "Tenant B credential rotation changed tenant data or routing." }

    Write-Host "--- Revocation checks ---" -ForegroundColor Cyan
    Assert-MySqlSuccess -Name "Lock Tenant A runtime account" -User "root" -Password $rootPassword -Sql "ALTER USER 'ap_test_a_runtime'@'127.0.0.1' ACCOUNT LOCK" | Out-Null
    Assert-MySqlDenied -Name "Revoked Tenant A account cannot reconnect" -User "ap_test_a_runtime" -Password ("a" * 64) -Sql "SELECT 1"

    Write-Host "All MySQL database-boundary checks passed. This validates MySQL grants, not the unfinished Proxima MySQL protocol gateway." -ForegroundColor Green
}
finally {
    $cleanup = @"
DROP USER IF EXISTS 'ap_test_a_runtime'@'127.0.0.1', 'ap_test_b_runtime'@'127.0.0.1', 'ap_test_a_migrator'@'127.0.0.1', 'ap_test_b_migrator'@'127.0.0.1';
DROP DATABASE IF EXISTS ap_test_tenant_a;
DROP DATABASE IF EXISTS ap_test_tenant_b;
"@
    $null = Invoke-MySql -User "root" -Password $rootPassword -Sql $cleanup
    & docker compose -f $composeFile --profile gateway down -v --remove-orphans | Out-Null
}
