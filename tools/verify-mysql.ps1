$ErrorActionPreference = "Stop"
Set-StrictMode -Version Latest

$repoRoot = Split-Path -Parent $PSScriptRoot
Push-Location $repoRoot
try {
    Write-Host "=== Proxima MySQL local verification ===" -ForegroundColor Cyan

    Write-Host "[1/5] Format Rust workspace" -ForegroundColor Cyan
    & cargo fmt -p proxima-mysql-gateway
    if ($LASTEXITCODE -ne 0) { throw "cargo fmt failed." }

    Write-Host "[2/5] Rust workspace tests" -ForegroundColor Cyan
    & cargo test -p proxima-mysql-gateway --all-targets
    if ($LASTEXITCODE -ne 0) { throw "cargo test failed." }

    Write-Host "[3/5] Rust Clippy" -ForegroundColor Cyan
    & cargo clippy -p proxima-mysql-gateway --all-targets -- -D warnings
    if ($LASTEXITCODE -ne 0) { throw "cargo clippy failed." }

    Write-Host "[4/5] Real MySQL 8.4 privilege-boundary checks" -ForegroundColor Cyan
    & (Join-Path $PSScriptRoot "mysql-isolation-smoke.ps1")
    if ($LASTEXITCODE -ne 0) { throw "MySQL isolation smoke test failed." }

    Write-Host "[5/5] MySQL gateway TLS, authentication and tenant-isolation end-to-end checks" -ForegroundColor Cyan
    & (Join-Path $PSScriptRoot "mysql-gateway-smoke.ps1")
    if ($LASTEXITCODE -ne 0) { throw "MySQL gateway end-to-end smoke test failed." }

    Write-Host "All available local verification stages passed." -ForegroundColor Green
}
finally {
    Pop-Location
}
