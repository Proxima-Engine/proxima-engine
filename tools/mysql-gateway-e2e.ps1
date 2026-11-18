$ErrorActionPreference = "Stop"
Set-StrictMode -Version Latest

$repoRoot = Split-Path -Parent $PSScriptRoot
$composeFile = Join-Path $repoRoot "docker-compose.mysql.yml"
$certDir = Join-Path $repoRoot "dev\mysql-certs"
$secretDir = Join-Path $repoRoot "dev\mysql-secrets"
$dataDir = Join-Path $repoRoot "dev\mysql-data"
$rootPassword = "proxima-mysql-dev-only"
$adminRandom = New-Object byte[] 32
$adminRng = [System.Security.Cryptography.RandomNumberGenerator]::Create()
$adminRng.GetBytes($adminRandom)
$adminRng.Dispose()
$adminPassword = [BitConverter]::ToString($adminRandom).Replace("-", "").ToLowerInvariant()
$tenantA = $null
$tenantB = $null
$tenantAProvisioned = $false
$tenantBProvisioned = $false
$tenantARevoked = $false
$tenantBRevoked = $false
$originalEnvironment = @{}

$environmentNames = @(
    "PROXIMA_MYSQL_UPSTREAM_HOST",
    "PROXIMA_MYSQL_UPSTREAM_PORT",
    "PROXIMA_MYSQL_UPSTREAM_SERVER_NAME",
    "PROXIMA_MYSQL_UPSTREAM_CA_FILE",
    "PROXIMA_MYSQL_PROVISIONING_USER",
    "PROXIMA_MYSQL_PROVISIONING_PASSWORD",
    "PROXIMA_MYSQL_ACCOUNT_HOST",
    "PROXIMA_MYSQL_SECRET_STORE_FILE",
    "PROXIMA_MYSQL_SECRET_STORE_KEY_FILE",
    "PROXIMA_MYSQL_PROVISIONING_JOURNAL_FILE",
    "PROXIMA_MYSQL_TENANT_ASSERTION_KEY",
    "PROXIMA_MYSQL_ISSUE_LOCAL_ASSERTION",
    "PROXIMA_MYSQL_STATEMENT_TIMEOUT_MS",
    "PROXIMA_MYSQL_TEST_GATEWAY_ADDR",
    "PROXIMA_MYSQL_TEST_CA_FILE",
    "PROXIMA_MYSQL_TEST_USER_A",
    "PROXIMA_MYSQL_TEST_PASSWORD_A",
    "PROXIMA_MYSQL_TEST_ASSERTION_A",
    "PROXIMA_MYSQL_TEST_USER_B",
    "PROXIMA_MYSQL_TEST_PASSWORD_B",
    "PROXIMA_MYSQL_TEST_ASSERTION_B",
    "PROXIMA_MYSQL_TEST_DATABASE_A",
    "PROXIMA_MYSQL_TEST_DATABASE_B",
    "PROXIMA_MYSQL_TEST_REVOKED_USER",
    "PROXIMA_MYSQL_TEST_REVOKED_PASSWORD",
    "PROXIMA_MYSQL_TEST_REVOKED_ASSERTION"
)
foreach ($name in $environmentNames) {
    $originalEnvironment[$name] = [Environment]::GetEnvironmentVariable($name, "Process")
}

function Invoke-RootSql {
    param([Parameter(Mandatory)][string]$Sql)
    $args = @(
        "compose", "-f", $composeFile, "exec", "-T",
        "-e", "MYSQL_PWD=$rootPassword",
        "mysql-test", "mysql", "--protocol=TCP", "--host=127.0.0.1",
        "--user=root", "--batch", "--skip-column-names", "--execute=$Sql"
    )
    $output = & docker @args 2>&1
    if ($LASTEXITCODE -ne 0) {
        throw "Disposable MySQL administrator command failed: $($output -join [Environment]::NewLine)"
    }
}

function Invoke-Admin {
    param(
        [Parameter(Mandatory)][string]$Command,
        [Parameter(Mandatory)][string[]]$Arguments
    )
    Push-Location $repoRoot
    try {
        $output = & cargo run --quiet -p proxima-mysql-gateway --bin proxima-mysql-admin -- $Command @Arguments 2>&1
        $exitCode = $LASTEXITCODE
    }
    finally {
        Pop-Location
    }
    $text = $output -join [Environment]::NewLine
    if ($exitCode -ne 0) {
        throw "MySQL admin command '$Command' failed: $text"
    }
    return $text
}

function New-Tenant {
    param(
        [Parameter(Mandatory)][string]$Username
    )
    $tenant = [Guid]::NewGuid()
    $text = Invoke-Admin -Command "provision" -Arguments @($tenant.ToString(), $Username)
    $passwordMatch = [regex]::Match($text, "Gateway password \(shown once\): ([0-9a-f]{64})")
    $assertionMatch = [regex]::Match($text, "LOCAL DEVELOPMENT ASSERTION \(15 minutes\): (v1\.[^\s]+)")
    if (-not $passwordMatch.Success -or -not $assertionMatch.Success) {
        throw "Provisioning output did not contain the one-time gateway password and local test assertion. Output: $text"
    }
    $tenantHex = $tenant.ToString("N")
    $tenantBytes = New-Object byte[] 16
    for ($index = 0; $index -lt 16; $index++) {
        $tenantBytes[$index] = [Convert]::ToByte($tenantHex.Substring($index * 2, 2), 16)
    }
    $sha = [System.Security.Cryptography.SHA256]::Create()
    try {
        $tenantDigest = $sha.ComputeHash($tenantBytes)
    }
    finally {
        $sha.Dispose()
    }
    $tenantSuffix = [BitConverter]::ToString($tenantDigest).Replace("-", "").ToLowerInvariant().Substring(0, 27)

    return [pscustomobject]@{
        Id = $tenant
        Username = $Username
        Password = $passwordMatch.Groups[1].Value
        Assertion = $assertionMatch.Groups[1].Value
        Database = "ap_t_$($tenant.ToString('N'))"
        RuntimeUser = "ap_r_$tenantSuffix"
        MigrationUser = "ap_m_$tenantSuffix"
    }
}

function Revoke-Tenant {
    param([Parameter(Mandatory)]$Tenant)
    $null = Invoke-Admin -Command "revoke" -Arguments @($Tenant.Id.ToString())
    Write-Host "[PASS] Revoked $($Tenant.Username)" -ForegroundColor Green
}

function Remove-TestTenant {
    param([Parameter(Mandatory)]$Tenant)
    $sql = @"
DROP USER IF EXISTS '$($Tenant.RuntimeUser)'@'172.31.90.3';
DROP USER IF EXISTS '$($Tenant.MigrationUser)'@'172.31.90.3';
DROP DATABASE IF EXISTS $($Tenant.Database);
"@
    Invoke-RootSql -Sql $sql
}

try {
    Write-Host "=== Proxima MySQL gateway end-to-end verification ===" -ForegroundColor Cyan

    & (Join-Path $PSScriptRoot "prepare-mysql-dev-certs.ps1")
    if ($LASTEXITCODE -ne 0) { throw "Local MySQL development certificate preparation failed." }

    & docker compose -f $composeFile up -d --wait mysql-test
    if ($LASTEXITCODE -ne 0) { throw "Disposable MySQL 8.4 did not become healthy." }

    $provisionerSql = @"
DROP USER IF EXISTS 'proxima_provisioner'@'%';
CREATE USER 'proxima_provisioner'@'%' IDENTIFIED BY '$adminPassword' REQUIRE SSL;
GRANT ALL PRIVILEGES ON *.* TO 'proxima_provisioner'@'%' WITH GRANT OPTION;
"@
    Invoke-RootSql -Sql $provisionerSql

    $env:PROXIMA_MYSQL_UPSTREAM_HOST = "127.0.0.1"
    $env:PROXIMA_MYSQL_UPSTREAM_PORT = "3307"
    $env:PROXIMA_MYSQL_UPSTREAM_SERVER_NAME = "localhost"
    $env:PROXIMA_MYSQL_UPSTREAM_CA_FILE = Join-Path $certDir "ca.pem"
    $env:PROXIMA_MYSQL_PROVISIONING_USER = "proxima_provisioner"
    $env:PROXIMA_MYSQL_PROVISIONING_PASSWORD = $adminPassword
    $env:PROXIMA_MYSQL_ACCOUNT_HOST = "172.31.90.3"
    $env:PROXIMA_MYSQL_SECRET_STORE_FILE = Join-Path $dataDir "tenants.enc"
    $env:PROXIMA_MYSQL_SECRET_STORE_KEY_FILE = Join-Path $secretDir "mysql-store-key"
    $env:PROXIMA_MYSQL_PROVISIONING_JOURNAL_FILE = Join-Path $dataDir "provisioning.jsonl"
    $env:PROXIMA_MYSQL_TENANT_ASSERTION_KEY = (Get-Content (Join-Path $secretDir "tenant-assertion-key.txt") -Raw).Trim()
    $env:PROXIMA_MYSQL_ISSUE_LOCAL_ASSERTION = "true"
    $env:PROXIMA_MYSQL_STATEMENT_TIMEOUT_MS = "30000"

    Write-Host "--- Provision two isolated tenants through the real MySQL DDL executor ---" -ForegroundColor Cyan
    $tenantA = New-Tenant -Username "gw_a_$([Guid]::NewGuid().ToString('N').Substring(0,8))"
    $tenantAProvisioned = $true
    $tenantB = New-Tenant -Username "gw_b_$([Guid]::NewGuid().ToString('N').Substring(0,8))"
    $tenantBProvisioned = $true

    $probeSql = @"
CREATE TABLE $($tenantA.Database).gateway_probe (id INT PRIMARY KEY, secret VARCHAR(100) NOT NULL);
CREATE TABLE $($tenantB.Database).gateway_probe (id INT PRIMARY KEY, secret VARCHAR(100) NOT NULL);
INSERT INTO $($tenantA.Database).gateway_probe VALUES (1, 'tenant-a-secret');
INSERT INTO $($tenantB.Database).gateway_probe VALUES (1, 'tenant-b-secret');
"@
    Invoke-RootSql -Sql $probeSql

    Write-Host "--- Start the separate TLS MySQL gateway ---" -ForegroundColor Cyan
    & docker compose --profile gateway -f $composeFile up -d --build --wait mysql-gateway
    if ($LASTEXITCODE -ne 0) { throw "MySQL gateway container did not become healthy." }

    $env:PROXIMA_MYSQL_TEST_GATEWAY_ADDR = "127.0.0.1:13306"
    $env:PROXIMA_MYSQL_TEST_CA_FILE = Join-Path $certDir "ca.pem"
    $env:PROXIMA_MYSQL_TEST_USER_A = $tenantA.Username
    $env:PROXIMA_MYSQL_TEST_PASSWORD_A = $tenantA.Password
    $env:PROXIMA_MYSQL_TEST_ASSERTION_A = $tenantA.Assertion
    $env:PROXIMA_MYSQL_TEST_USER_B = $tenantB.Username
    $env:PROXIMA_MYSQL_TEST_PASSWORD_B = $tenantB.Password
    $env:PROXIMA_MYSQL_TEST_ASSERTION_B = $tenantB.Assertion
    $env:PROXIMA_MYSQL_TEST_DATABASE_A = $tenantA.Database
    $env:PROXIMA_MYSQL_TEST_DATABASE_B = $tenantB.Database

    Write-Host "--- Verify real TLS authentication, routing, grants and forbidden commands ---" -ForegroundColor Cyan
    Push-Location $repoRoot
    try {
        & cargo test -p proxima-mysql-gateway --test mysql_gateway_e2e -- --ignored gateway_enforces_tenant_database_and_session_boundaries --nocapture
        if ($LASTEXITCODE -ne 0) { throw "MySQL gateway tenant-isolation integration test failed." }
    }
    finally {
        Pop-Location
    }

    Write-Host "--- Verify revocation against an already-running gateway ---" -ForegroundColor Cyan
    Revoke-Tenant -Tenant $tenantA
    $tenantARevoked = $true
    $env:PROXIMA_MYSQL_TEST_REVOKED_USER = $tenantA.Username
    $env:PROXIMA_MYSQL_TEST_REVOKED_PASSWORD = $tenantA.Password
    $env:PROXIMA_MYSQL_TEST_REVOKED_ASSERTION = $tenantA.Assertion
    Push-Location $repoRoot
    try {
        & cargo test -p proxima-mysql-gateway --test mysql_gateway_e2e -- --ignored revoked_gateway_account_cannot_open_a_new_session --nocapture
        if ($LASTEXITCODE -ne 0) { throw "Revoked MySQL gateway account was unexpectedly accepted." }
    }
    finally {
        Pop-Location
    }

    Write-Host "All MySQL gateway end-to-end checks passed." -ForegroundColor Green
}
finally {
    & docker compose --profile gateway -f $composeFile stop mysql-gateway 2>$null | Out-Null

    if ($tenantAProvisioned -and $null -ne $tenantA) {
        try {
            if (-not $tenantARevoked) { Revoke-Tenant -Tenant $tenantA }
            Remove-TestTenant -Tenant $tenantA
        }
        catch {
            Write-Warning "Tenant A cleanup requires manual review: $_"
        }
    }
    if ($tenantBProvisioned -and $null -ne $tenantB) {
        try {
            if (-not $tenantBRevoked) { Revoke-Tenant -Tenant $tenantB }
            Remove-TestTenant -Tenant $tenantB
        }
        catch {
            Write-Warning "Tenant B cleanup requires manual review: $_"
        }
    }

    try {
        Invoke-RootSql -Sql "DROP USER IF EXISTS 'proxima_provisioner'@'%';"
    }
    catch {
        Write-Warning "Disposable provisioning-account cleanup failed: $_"
    }

    foreach ($name in $environmentNames) {
        [Environment]::SetEnvironmentVariable($name, $originalEnvironment[$name], "Process")
    }
}
