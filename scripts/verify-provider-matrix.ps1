[CmdletBinding()]
param(
    [string]$ProjectRoot = (Resolve-Path (Join-Path $PSScriptRoot '..')).Path,
    [string]$OutputDirectory = (Join-Path (Join-Path $PSScriptRoot '..') 'verification-results')
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

if (-not (Test-Path (Join-Path $ProjectRoot 'Cargo.toml'))) {
    throw "Cargo.toml was not found under ProjectRoot: $ProjectRoot"
}
New-Item -ItemType Directory -Force -Path $OutputDirectory | Out-Null
$runId = (Get-Date).ToUniversalTime().ToString('yyyyMMddTHHmmssZ')
$results = [System.Collections.Generic.List[object]]::new()

function Add-Result([string]$Name, [string]$Status, [string]$Detail, [double]$Seconds = 0) {
    $results.Add([pscustomobject]@{
        provider = $Name
        status = $Status
        duration_seconds = [math]::Round($Seconds, 2)
        detail = $Detail
    })
}

function Invoke-CargoCheck([string]$Name, [string[]]$Arguments) {
    $timer = [Diagnostics.Stopwatch]::StartNew()
    $logPath = Join-Path $OutputDirectory "$runId-$Name.log"
    # PowerShell 7.3+ can promote native stderr (including ordinary Rust
    # warnings) into terminating ErrorRecords when ErrorActionPreference=Stop.
    # Cargo's process exit code, not the warning stream, determines PASS/FAIL.
    $nativePreferenceAvailable = Test-Path Variable:PSNativeCommandUseErrorActionPreference
    if ($nativePreferenceAvailable) { $previousNativePreference = $PSNativeCommandUseErrorActionPreference }
    $PSNativeCommandUseErrorActionPreference = $false
    try {
        & cargo @Arguments 2>&1 | ForEach-Object {
            $line = [string]$_
            Add-Content -LiteralPath $logPath -Value $line
            Write-Host $line
        }
        $exitCode = $LASTEXITCODE
    } finally {
        if ($nativePreferenceAvailable) { $PSNativeCommandUseErrorActionPreference = $previousNativePreference }
    }
    $timer.Stop()
    if ($exitCode -eq 0) { Add-Result $Name 'PASS' 'Command completed successfully.' $timer.Elapsed.TotalSeconds }
    else { Add-Result $Name 'FAIL' "cargo exited with code $exitCode." $timer.Elapsed.TotalSeconds }
    return ($exitCode -eq 0)
}

Push-Location $ProjectRoot
try {
    $fmtApplyOk = Invoke-CargoCheck 'rustfmt-apply' @('fmt', '--all')
    $fmtOk = Invoke-CargoCheck 'rustfmt-check' @('fmt', '--all', '--', '--check')
    $checkOk = Invoke-CargoCheck 'workspace-check' @('check', '--workspace', '--all-targets')
    $libOk = Invoke-CargoCheck 'library-unit-tests' @('test', '-p', 'proxima-engine', '--lib')
    $binOk = Invoke-CargoCheck 'engine-unit-tests' @('test', '-p', 'proxima-engine', '--bin', 'proxima-engine')

    $providerSpecs = @(
        @{ Name='PostgreSQL'; Env='PROXIMA_RUN_POSTGRESQL_ACCEPTANCE'; Test=@('test','-p','proxima-engine','--test','postgres_integration','--','--ignored') },
        @{ Name='MySQL 8'; Env='PROXIMA_RUN_MYSQL_ACCEPTANCE'; Test=@('test','-p','proxima-engine','--test','mysql_gateway_integration','--','--ignored') },
        @{ Name='MariaDB'; Env='PROXIMA_RUN_MARIADB_ACCEPTANCE'; Test=@('test','-p','proxima-engine','--test','mariadb_gateway_integration','--','--ignored') },
        @{ Name='MongoDB 8'; Env='PROXIMA_RUN_MONGODB_ACCEPTANCE'; Test=@('test','-p','proxima-engine','--test','mongodb_tenant_isolation','--','--ignored') },
        @{ Name='SQL Server native lifecycle acceptance'; Env='PROXIMA_RUN_SQLSERVER_ACCEPTANCE'; Test=@('test','-p','proxima-engine','--test','sqlserver_native_integration','--','--ignored') }
    )
    foreach ($spec in $providerSpecs) {
        if ([Environment]::GetEnvironmentVariable($spec.Env) -eq '1') {
            $null = Invoke-CargoCheck (($spec.Name -replace '[^A-Za-z0-9]','').ToLowerInvariant() + '-integration') $spec.Test
        }
    }

    if ([Environment]::GetEnvironmentVariable('PROXIMA_RUN_SQLSERVER_TDS_ACCEPTANCE') -eq '1') {
        $timer = [Diagnostics.Stopwatch]::StartNew()
        $tdsScript = Join-Path $ProjectRoot 'scripts/test-sqlserver-tds-gateway.ps1'
        try {
            & powershell.exe -NoProfile -ExecutionPolicy Bypass -File $tdsScript
            $tdsExit = $LASTEXITCODE
            if ($tdsExit -eq 0) { Add-Result 'SQL Server TDS cross-tenant acceptance' 'PASS' 'TDS login routing and cross-tenant denial passed.' $timer.Elapsed.TotalSeconds }
            else { Add-Result 'SQL Server TDS cross-tenant acceptance' 'FAIL' "TDS acceptance exited with code $tdsExit." $timer.Elapsed.TotalSeconds }
        } catch {
            Add-Result 'SQL Server TDS cross-tenant acceptance' 'FAIL' $_.Exception.Message $timer.Elapsed.TotalSeconds
        } finally { $timer.Stop() }
    }

    # Every catalogue provider has an explicit Engine runtime dispatch path.
    # The commands below run the corresponding provider acceptance suite.
    $providerRuntime = @(
        @{Name='PostgreSQL'; Detail='Native PostgreSQL listener, signed tenant context, tenant roles and RLS.'; Command='cargo test -p proxima-engine --test postgres_integration -- --ignored'},
        @{Name='MySQL'; Detail='Supervised MySQL protocol gateway with tenant-bound upstream accounts.'; Command='bash scripts/test-mysql-gateways-ci.sh'},
        @{Name='MariaDB'; Detail='Supervised MySQL-compatible gateway with MariaDB tenant grants.'; Command='cargo test -p proxima-engine --test mariadb_gateway_integration -- --ignored'},
        @{Name='CockroachDB'; Detail='PostgreSQL wire runtime with CockroachDB tenant roles and RLS.'; Command='bash scripts/test-cockroachdb-tenant-isolation-ci.sh'},
        @{Name='MongoDB'; Detail='Supervised OP_MSG gateway with SCRAM tenant database binding.'; Command='bash scripts/test-mongodb-tenant-isolation-ci.sh'},
        @{Name='Redis'; Detail='Supervised RESP2 gateway with tenant namespaces and Redis ACLs.'; Command='bash scripts/test-redis-tenant-gateway-ci.sh'},
        @{Name='Microsoft SQL Server'; Detail='Supervised TDS 7.4 gateway with LOGIN7 tenant and database binding.'; Command='bash scripts/test-sqlserver-tenant-isolation-ci.sh; scripts/test-sqlserver-tds-gateway.ps1'},
        @{Name='SQLite'; Detail='Native tenant-file runtime with path and filesystem isolation.'; Command='cargo test -p proxima-engine sqlite_tenant'},
        @{Name='Oracle Database'; Detail='Native Oracle schema-owner provisioning, verification, rotation and revocation.'; Command='bash scripts/test-oracle-tenant-isolation-ci.sh'},
        @{Name='Amazon DynamoDB'; Detail='AWS SDK IAM role lifecycle with table and LeadingKeys tenant scope.'; Command='bash scripts/test-dynamodb-leading-keys-aws.sh'},
        @{Name='Apache Cassandra'; Detail='Native Cassandra keyspace and tenant-role lifecycle over TLS.'; Command='bash scripts/test-cassandra-tenant-isolation-ci.sh'},
        @{Name='Elasticsearch / OpenSearch'; Detail='Native search role, tenant credential and index-scope lifecycle.'; Command='bash scripts/test-elasticsearch-tenant-isolation.sh; scripts/test-opensearch-tenant-isolation.sh'}
    )
    foreach ($item in $providerRuntime) { Add-Result $item.Name 'IMPLEMENTED' ($item.Detail + ' Acceptance: ' + $item.Command) }

    $report = [pscustomobject]@{
        schema_version = 1
        run_id = $runId
        generated_at_utc = (Get-Date).ToUniversalTime().ToString('o')
        project_root = $ProjectRoot
        rustc = (& rustc --version 2>&1 | Out-String).Trim()
        cargo = (& cargo --version 2>&1 | Out-String).Trim()
        results = $results
    }
    $jsonPath = Join-Path $OutputDirectory "$runId-provider-matrix.json"
    $mdPath = Join-Path $OutputDirectory "$runId-provider-matrix.md"
    $report | ConvertTo-Json -Depth 8 | Set-Content -Encoding UTF8 $jsonPath
    $lines = @('# Proxima provider verification', '', "Run: $runId", '', '| Provider/check | Status | Detail |', '|---|---|---|')
    foreach ($item in $results) {
        $detail = ($item.detail -replace '\|','\\|')
        $lines += "| $($item.provider) | $($item.status) | $detail |"
    }
    $lines | Set-Content -Encoding UTF8 $mdPath
    Write-Host "JSON report: $jsonPath"
    Write-Host "Markdown report: $mdPath"
    $failed = @($results | Where-Object { $_.status -eq 'FAIL' }).Count
    if ($failed -gt 0 -or -not ($fmtApplyOk -and $fmtOk -and $checkOk -and $libOk -and $binOk)) { exit 1 }
} finally {
    Pop-Location
}
