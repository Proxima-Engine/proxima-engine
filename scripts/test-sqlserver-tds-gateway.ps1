$ErrorActionPreference = 'Stop'

$required = @(
    'PROXIMA_SQLSERVER_TDS_TEST_SERVER',
    'PROXIMA_SQLSERVER_TENANT_A_USER',
    'PROXIMA_SQLSERVER_TENANT_A_PASSWORD',
    'PROXIMA_SQLSERVER_TENANT_A_DATABASE',
    'PROXIMA_SQLSERVER_TENANT_B_USER',
    'PROXIMA_SQLSERVER_TENANT_B_PASSWORD',
    'PROXIMA_SQLSERVER_TENANT_B_DATABASE'
)
foreach ($name in $required) {
    if ([string]::IsNullOrWhiteSpace([Environment]::GetEnvironmentVariable($name))) {
        throw "Missing required environment variable: $name"
    }
}
if (-not (Get-Command sqlcmd -ErrorAction SilentlyContinue)) {
    throw 'sqlcmd is required for SQL Server TDS gateway acceptance.'
}

$server = $env:PROXIMA_SQLSERVER_TDS_TEST_SERVER
function Invoke-TdsQuery([string]$User, [string]$Password, [string]$Database, [string]$Query) {
    $output = & sqlcmd -S $server -N -U $User -P $Password -d $Database -b -Q $Query 2>&1
    if ($LASTEXITCODE -ne 0) { throw "TDS query failed for principal '$User': $($output -join "`n")" }
    return ($output -join "`n")
}
function Assert-TdsQueryDenied([string]$User, [string]$Password, [string]$Database, [string]$Query) {
    & sqlcmd -S $server -N -U $User -P $Password -d $Database -b -Q $Query *> $null
    if ($LASTEXITCODE -eq 0) { throw "Isolation failure: '$User' unexpectedly accessed '$Database'." }
}

$a = Invoke-TdsQuery $env:PROXIMA_SQLSERVER_TENANT_A_USER $env:PROXIMA_SQLSERVER_TENANT_A_PASSWORD $env:PROXIMA_SQLSERVER_TENANT_A_DATABASE 'SELECT DB_NAME();'
if ($a -notmatch [regex]::Escape($env:PROXIMA_SQLSERVER_TENANT_A_DATABASE)) { throw 'Tenant A did not land in its assigned database.' }
$b = Invoke-TdsQuery $env:PROXIMA_SQLSERVER_TENANT_B_USER $env:PROXIMA_SQLSERVER_TENANT_B_PASSWORD $env:PROXIMA_SQLSERVER_TENANT_B_DATABASE 'SELECT DB_NAME();'
if ($b -notmatch [regex]::Escape($env:PROXIMA_SQLSERVER_TENANT_B_DATABASE)) { throw 'Tenant B did not land in its assigned database.' }

# The gateway rejects a cross-tenant initial database request in LOGIN7.
Assert-TdsQueryDenied $env:PROXIMA_SQLSERVER_TENANT_A_USER $env:PROXIMA_SQLSERVER_TENANT_A_PASSWORD $env:PROXIMA_SQLSERVER_TENANT_B_DATABASE 'SELECT DB_NAME();'
# SQL Server's per-tenant login permissions must also reject a database switch.
Assert-TdsQueryDenied $env:PROXIMA_SQLSERVER_TENANT_A_USER $env:PROXIMA_SQLSERVER_TENANT_A_PASSWORD $env:PROXIMA_SQLSERVER_TENANT_A_DATABASE ("USE [" + $env:PROXIMA_SQLSERVER_TENANT_B_DATABASE + "]; SELECT DB_NAME();")

Write-Host 'PASS: SQL Server TDS login routing, assigned database selection, and cross-tenant denial.' -ForegroundColor Green
