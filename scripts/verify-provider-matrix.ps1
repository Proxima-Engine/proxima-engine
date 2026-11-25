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
        } else {
            Add-Result $spec.Name 'SKIP' "Set $($spec.Env)=1 after starting the disposable provider service and configuring its test credentials."
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
    } else {
        Add-Result 'SQL Server TDS cross-tenant acceptance' 'SKIP' 'Set PROXIMA_RUN_SQLSERVER_TDS_ACCEPTANCE=1 with two provisioned SQL Server tenant logins and sqlcmd.'
    }

    # Keep provider implementation and live acceptance as separate results.
    # A concrete client adapter or policy helper is not itself a live acceptance pass.
    $notComplete = @(
        @{Name='CockroachDB'; Detail='Native PostgreSQL-wire profile exists; pinned CockroachDB 25.2 real-server acceptance is not wired into this runner.'},
        @{Name='Microsoft SQL Server'; Detail='Proxima TDS LOGIN7 gateway, SQL Server tenant lifecycle activation, Cloud assignment reconciliation and signed tenant evidence are implemented in source; live SQL Server/TDS acceptance remains opt-in.'},
        @{Name='Redis'; Detail='RESP2 gateway activation is wired; real-server adversarial tenant-isolation acceptance is not run by this runner.'},
        @{Name='Oracle'; Detail='Concrete TLS-capable Oracle driver executor and lifecycle operations are present; Cloud assignment orchestration and real Oracle acceptance remain.'},
        @{Name='Amazon DynamoDB'; Detail='Concrete AWS SDK IAM adapter and LeadingKeys policy lifecycle are present; Cloud orchestration and real AWS-account acceptance remain.'},
        @{Name='Apache Cassandra'; Detail='Concrete TLS/authenticated Scylla Rust driver executor and keyspace/role lifecycle are present; Cloud orchestration and real Cassandra acceptance remain.'},
        @{Name='Elasticsearch'; Detail='Native REST role/user provisioning, verification, rotation and revoke operations are present; Cloud assignment orchestration and adversarial acceptance remain.'},
        @{Name='OpenSearch'; Detail='Native REST role/user provisioning, verification, rotation and revoke operations are present; Cloud assignment orchestration and adversarial acceptance remain.'},
        @{Name='SQLite'; Detail='File isolation and Windows ACL unit tests run in the library suite; lifecycle/backup/restore real acceptance remains separate.'}
    )
    foreach ($item in $notComplete) { Add-Result $item.Name 'PARTIAL' $item.Detail }

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
