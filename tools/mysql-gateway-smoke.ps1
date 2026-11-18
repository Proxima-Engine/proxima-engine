$ErrorActionPreference = "Stop"
Set-StrictMode -Version Latest

$repoRoot = Split-Path -Parent $PSScriptRoot
Push-Location $repoRoot
$composeFile = Join-Path $repoRoot "docker-compose.mysql.yml"
$rootPassword = "proxima-mysql-dev-only"
$adminRandom = New-Object byte[] 32
$adminRng = [System.Security.Cryptography.RandomNumberGenerator]::Create()
$adminRng.GetBytes($adminRandom)
$adminRng.Dispose()
$adminPassword = [BitConverter]::ToString($adminRandom).Replace("-", "").ToLowerInvariant()
$tenantId = [Guid]::NewGuid().ToString()
$tenantCompact = $tenantId.Replace("-", "").ToLowerInvariant()
$gatewayUsername = "gw_smoke_$($tenantCompact.Substring(0, 8))"
$tenantDatabase = "ap_t_$tenantCompact"
$otherDatabase = "ap_t_other"
$runtimeAccountHost = "172.31.90.3"
$migrationAccountHost = "172.31.90.4"
$certDir = Join-Path $repoRoot "dev\mysql-certs"
$secretDir = Join-Path $repoRoot "dev\mysql-secrets"
$dataDir = Join-Path $repoRoot "dev\mysql-data"
$caFile = Join-Path $certDir "ca.pem"
$assertionKeyFile = Join-Path $secretDir "tenant-assertion-key.txt"
$storeKeyFile = Join-Path $secretDir "mysql-store-key"
$storeFile = Join-Path $dataDir "tenants.enc"
$journalFile = Join-Path $dataDir "provisioning.jsonl"
$provisioned = $false
$gatewayStarted = $false
$environmentNames = @(
    "PROXIMA_MYSQL_UPSTREAM_HOST",
    "PROXIMA_MYSQL_UPSTREAM_PORT",
    "PROXIMA_MYSQL_UPSTREAM_SERVER_NAME",
    "PROXIMA_MYSQL_UPSTREAM_CA_FILE",
    "PROXIMA_MYSQL_PROVISIONING_USER",
    "PROXIMA_MYSQL_PROVISIONING_PASSWORD",
    "PROXIMA_MYSQL_RUNTIME_ACCOUNT_HOST",
    "PROXIMA_MYSQL_MIGRATION_ACCOUNT_HOST",
    "PROXIMA_MYSQL_SECRET_STORE_FILE",
    "PROXIMA_MYSQL_SECRET_STORE_KEY_FILE",
    "PROXIMA_MYSQL_PROVISIONING_JOURNAL_FILE",
    "PROXIMA_MYSQL_ISSUE_LOCAL_ASSERTION",
    "PROXIMA_MYSQL_TENANT_ASSERTION_KEY"
)
$originalEnvironment = @{}
foreach ($name in $environmentNames) {
    $originalEnvironment[$name] = [Environment]::GetEnvironmentVariable($name, "Process")
}

function Invoke-RootSql {
    param([Parameter(Mandatory)][string]$Sql)
    $dockerArgs = @(
        "compose", "-f", $composeFile, "exec", "-T",
        "-e", "MYSQL_PWD=$rootPassword",
        "mysql-test", "mysql", "--protocol=TCP", "--host=127.0.0.1",
        "--user=root", "--batch", "--skip-column-names", "--execute=$Sql"
    )
    $output = & docker @dockerArgs 2>&1
    if ($LASTEXITCODE -ne 0) { throw "MySQL test setup/cleanup SQL failed: $($output -join [Environment]::NewLine)" }
    return ($output -join [Environment]::NewLine)
}

function Invoke-AdminCli {
    param([string[]]$Arguments)
    $output = & cargo run -p proxima-mysql-gateway --bin proxima-mysql-admin -- @Arguments 2>&1
    $exitCode = $LASTEXITCODE
    if ($exitCode -ne 0) { throw "MySQL admin CLI failed: $($output -join [Environment]::NewLine)" }
    return ($output -join [Environment]::NewLine)
}

function Invoke-Probe {
    param(
        [string]$GatewayPassword,
        [string]$Assertion,
        [switch]$ExpectDenied
    )
    $probeArgs = @(
        "run", "-p", "proxima-mysql-gateway", "--bin", "proxima-mysql-probe", "--",
        "127.0.0.1", "13306", "localhost", $caFile,
        $gatewayUsername, $GatewayPassword, $Assertion, $tenantDatabase, $otherDatabase
    )
    if ($ExpectDenied) { $probeArgs += "--expect-auth-denied" }
    $output = & cargo @probeArgs 2>&1
    if ($LASTEXITCODE -ne 0) { throw "MySQL gateway protocol probe failed: $($output -join [Environment]::NewLine)" }
    Write-Host ($output -join [Environment]::NewLine)
}

function Invoke-ActiveRevocationProbe {
    param(
        [Parameter(Mandatory)][string]$GatewayPassword,
        [Parameter(Mandatory)][string]$Assertion
    )
    $stdout = Join-Path $dataDir "active-revocation.stdout.log"
    $stderr = Join-Path $dataDir "active-revocation.stderr.log"
    Remove-Item $stdout, $stderr -Force -ErrorAction SilentlyContinue
    $probeArgs = @(
        "run", "-p", "proxima-mysql-gateway", "--bin", "proxima-mysql-probe", "--",
        "127.0.0.1", "13306", "localhost", $caFile,
        $gatewayUsername, $GatewayPassword, $Assertion, $tenantDatabase, $otherDatabase,
        "--expect-revoked-after-ms", "2500"
    )
    $quotedArgs = $probeArgs | ForEach-Object { '"' + $_.Replace('"', '\"') + '"' }
    $cargoPath = (Get-Command cargo -ErrorAction Stop).Source
    $process = Start-Process -FilePath $cargoPath -ArgumentList ($quotedArgs -join " ") -WorkingDirectory $repoRoot -PassThru -NoNewWindow -RedirectStandardOutput $stdout -RedirectStandardError $stderr

    $ready = $false
    $deadline = [DateTime]::UtcNow.AddSeconds(120)
    try {
        while ([DateTime]::UtcNow -lt $deadline) {
            Start-Sleep -Milliseconds 200
            if (Test-Path $stdout) {
                $output = Get-Content $stdout -Raw -ErrorAction SilentlyContinue
                if ($output -match "ACTIVE_SESSION_READY") {
                    $ready = $true
                    break
                }
            }
            $process.Refresh()
            if ($process.HasExited) {
                $stderrText = if (Test-Path $stderr) { Get-Content $stderr -Raw } else { "" }
                throw "Active-session probe exited before becoming ready. $stderrText"
            }
        }
        if (-not $ready) {
            throw "Active-session probe did not establish a tenant session within 120 seconds."
        }

        Write-Host "[TEST] Revoking tenant while its MySQL gateway session is still open" -ForegroundColor Cyan
        Invoke-AdminCli -Arguments @("revoke", $tenantId) | Out-Null
        if (-not $process.WaitForExit(15000)) {
            throw "Active-session probe did not finish after tenant revocation."
        }
        if ($process.ExitCode -ne 0) {
            $stderrText = if (Test-Path $stderr) { Get-Content $stderr -Raw } else { "" }
            throw "Active MySQL session was not closed after revocation. $stderrText"
        }
        if (Test-Path $stdout) {
            Write-Host (Get-Content $stdout -Raw)
        }
    }
    finally {
        $process.Refresh()
        if (-not $process.HasExited) {
            $process.Kill()
            $process.WaitForExit()
        }
    }
}

function New-LocalTenantAssertion {
    param(
        [Parameter(Mandatory)][string]$TenantId,
        [Parameter(Mandatory)][string]$SigningKey,
        [int]$TtlSeconds = 3600
    )
    $expiresAt = [DateTimeOffset]::UtcNow.ToUnixTimeSeconds() + $TtlSeconds
    $message = "v1.$TenantId.$expiresAt"
    $keyBytes = [System.Text.Encoding]::UTF8.GetBytes($SigningKey)
    $messageBytes = [System.Text.Encoding]::UTF8.GetBytes($message)
    $hmac = [System.Security.Cryptography.HMACSHA256]::new($keyBytes)
    try {
        $signature = [BitConverter]::ToString($hmac.ComputeHash($messageBytes)).Replace("-", "").ToLowerInvariant()
    }
    finally {
        $hmac.Dispose()
        [Array]::Clear($keyBytes, 0, $keyBytes.Length)
        [Array]::Clear($messageBytes, 0, $messageBytes.Length)
    }
    return "v1.$TenantId.$expiresAt.$signature"
}

try {
    Write-Host "--- Prepare local TLS and secret material ---" -ForegroundColor Cyan
    & (Join-Path $PSScriptRoot "prepare-mysql-dev-certs.ps1")
    if ($LASTEXITCODE -ne 0) { throw "Local MySQL certificate preparation failed." }
    New-Item -ItemType Directory -Force -Path $dataDir | Out-Null

    $env:PROXIMA_MYSQL_UPSTREAM_HOST = "127.0.0.1"
    $env:PROXIMA_MYSQL_UPSTREAM_PORT = "3307"
    $env:PROXIMA_MYSQL_UPSTREAM_SERVER_NAME = "mysql-test"
    $env:PROXIMA_MYSQL_UPSTREAM_CA_FILE = $caFile
    $env:PROXIMA_MYSQL_PROVISIONING_USER = "proxima_provisioner"
    $env:PROXIMA_MYSQL_PROVISIONING_PASSWORD = $adminPassword
    $env:PROXIMA_MYSQL_RUNTIME_ACCOUNT_HOST = $runtimeAccountHost
    $env:PROXIMA_MYSQL_MIGRATION_ACCOUNT_HOST = $migrationAccountHost
    $env:PROXIMA_MYSQL_SECRET_STORE_FILE = $storeFile
    $env:PROXIMA_MYSQL_SECRET_STORE_KEY_FILE = $storeKeyFile
    $env:PROXIMA_MYSQL_PROVISIONING_JOURNAL_FILE = $journalFile
    $env:PROXIMA_MYSQL_ISSUE_LOCAL_ASSERTION = "true"
    $env:PROXIMA_MYSQL_TENANT_ASSERTION_KEY = (Get-Content $assertionKeyFile -Raw).Trim()

    Write-Host "--- Start disposable MySQL 8.4 ---" -ForegroundColor Cyan
    & docker compose -f $composeFile up -d --wait mysql-test
    if ($LASTEXITCODE -ne 0) { throw "MySQL 8.4 did not become healthy." }

    Write-Host "--- Build the gateway image before issuing the one-hour assertion ---" -ForegroundColor Cyan
    & docker compose -f $composeFile --profile gateway build mysql-gateway
    if ($LASTEXITCODE -ne 0) { throw "MySQL gateway image build failed." }

    $provisionerSql = @"
DROP USER IF EXISTS 'proxima_provisioner'@'%';
CREATE USER 'proxima_provisioner'@'%' IDENTIFIED BY '$adminPassword' REQUIRE SSL;
GRANT ALL PRIVILEGES ON *.* TO 'proxima_provisioner'@'%' WITH GRANT OPTION;
"@
    Invoke-RootSql -Sql $provisionerSql | Out-Null

    Write-Host "--- Provision dedicated test tenant ---" -ForegroundColor Cyan
    $provisionOutput = Invoke-AdminCli -Arguments @("provision", $tenantId, $gatewayUsername)
    $provisioned = $true
    $gatewayPasswordLine = ($provisionOutput -split '\r?\n' | Where-Object { $_ -like "Gateway password (shown once): *" } | Select-Object -Last 1)
    $assertionLine = ($provisionOutput -split '\r?\n' | Where-Object { $_ -like "LOCAL DEVELOPMENT ASSERTION (60 minutes): *" } | Select-Object -Last 1)
    if (-not $gatewayPasswordLine -or -not $assertionLine) {
        throw "Provisioning did not return the one-time gateway credential and local test assertion."
    }
    $gatewayPassword = $gatewayPasswordLine.Substring("Gateway password (shown once): ".Length).Trim()
    $assertion = $assertionLine.Substring("LOCAL DEVELOPMENT ASSERTION (60 minutes): ".Length).Trim()

    Write-Host "--- Prepare tenant and cross-tenant tables ---" -ForegroundColor Cyan
    $setupSql = @"
CREATE TABLE IF NOT EXISTS $tenantDatabase.records (id INT PRIMARY KEY, secret VARCHAR(100) NOT NULL);
INSERT INTO $tenantDatabase.records VALUES (1, 'tenant-a-secret') ON DUPLICATE KEY UPDATE secret=VALUES(secret);
CREATE DATABASE IF NOT EXISTS $otherDatabase;
CREATE TABLE IF NOT EXISTS $otherDatabase.records (id INT PRIMARY KEY, secret VARCHAR(100) NOT NULL);
INSERT INTO $otherDatabase.records VALUES (1, 'tenant-b-secret') ON DUPLICATE KEY UPDATE secret=VALUES(secret);
"@
    Invoke-RootSql -Sql $setupSql | Out-Null

    Write-Host "--- Start standalone MySQL gateway container ---" -ForegroundColor Cyan
    & docker compose -f $composeFile --profile gateway up -d --wait mysql-gateway
    if ($LASTEXITCODE -ne 0) { throw "MySQL gateway container did not start." }
    $gatewayStarted = $true

    Write-Host "--- Verify real MySQL protocol and tenant boundaries ---" -ForegroundColor Cyan
    Invoke-Probe -GatewayPassword $gatewayPassword -Assertion $assertion

    Write-Host "--- Rotate tenant assertion key and invalidate old tokens ---" -ForegroundColor Cyan
    $rotatedKeyBytes = New-Object byte[] 32
    $rng = [System.Security.Cryptography.RandomNumberGenerator]::Create()
    $rng.GetBytes($rotatedKeyBytes)
    $rng.Dispose()
    $rotatedAssertionKey = [BitConverter]::ToString($rotatedKeyBytes).Replace("-", "").ToLowerInvariant()
    [Array]::Clear($rotatedKeyBytes, 0, $rotatedKeyBytes.Length)
    $env:PROXIMA_MYSQL_TENANT_ASSERTION_KEY = $rotatedAssertionKey
    Invoke-AdminCli -Arguments @("rotate-assertion-key", $tenantId) | Out-Null
    Invoke-Probe -GatewayPassword $gatewayPassword -Assertion $assertion -ExpectDenied
    $rotatedAssertion = New-LocalTenantAssertion -TenantId $tenantId -SigningKey $rotatedAssertionKey
    Invoke-Probe -GatewayPassword $gatewayPassword -Assertion $rotatedAssertion
    $assertion = $rotatedAssertion

    Write-Host "--- Revoke tenant and verify existing and new sessions are rejected ---" -ForegroundColor Cyan
    Invoke-ActiveRevocationProbe -GatewayPassword $gatewayPassword -Assertion $assertion
    Invoke-Probe -GatewayPassword $gatewayPassword -Assertion $assertion -ExpectDenied

    Write-Host "MySQL gateway end-to-end smoke test passed." -ForegroundColor Green
}
finally {
    if ($provisioned) {
        try { Invoke-AdminCli -Arguments @("revoke", $tenantId) | Out-Null } catch {}
        try {
            $identityBytes = ([Guid]::Parse($tenantId)).ToByteArray()
            [Array]::Reverse($identityBytes, 0, 4)
            [Array]::Reverse($identityBytes, 4, 2)
            [Array]::Reverse($identityBytes, 6, 2)
            $sha = [System.Security.Cryptography.SHA256]::Create()
            $digest = $sha.ComputeHash($identityBytes)
            $sha.Dispose()
            $suffix = [BitConverter]::ToString($digest).Replace("-", "").ToLowerInvariant().Substring(0, 27)
            $runtimeUser = "ap_r_$suffix"
            $migrationUser = "ap_m_$suffix"
            $cleanupSql = @"
DROP DATABASE IF EXISTS $tenantDatabase;
DROP DATABASE IF EXISTS $otherDatabase;
DROP USER IF EXISTS '$runtimeUser'@'$accountHost';
DROP USER IF EXISTS '$migrationUser'@'$accountHost';
"@
            Invoke-RootSql -Sql $cleanupSql | Out-Null
        } catch {
            Write-Warning "Could not fully clean disposable MySQL test resources: $_"
        }
    }
    try {
        Invoke-RootSql -Sql "DROP USER IF EXISTS 'proxima_provisioner'@'%';" | Out-Null
    } catch {
        Write-Warning "Could not remove the disposable MySQL provisioning account before container cleanup: $_"
    }
    if ($gatewayStarted) {
        & docker compose -f $composeFile --profile gateway stop mysql-gateway | Out-Null
    }
    & docker compose -f $composeFile --profile gateway down -v --remove-orphans | Out-Null
    foreach ($name in $environmentNames) {
        [Environment]::SetEnvironmentVariable($name, $originalEnvironment[$name], "Process")
    }
    [Array]::Clear($adminRandom, 0, $adminRandom.Length)
    $adminPassword = $null
    $gatewayPassword = $null
    $assertion = $null
    $rotatedAssertion = $null
    $rotatedAssertionKey = $null
    Pop-Location
}
