$ErrorActionPreference = "Stop"
Set-StrictMode -Version Latest

$repoRoot = Split-Path -Parent $PSScriptRoot
Push-Location $repoRoot
try {
    Write-Host "=== Proxima MySQL local verification ===" -ForegroundColor Cyan

    Write-Host "[1/4] Rust formatting" -ForegroundColor Cyan
    & cargo fmt --all -- --check
    if ($LASTEXITCODE -ne 0) { throw "cargo fmt failed." }

    Write-Host "[2/4] Rust workspace tests" -ForegroundColor Cyan
    & cargo test --workspace --all-targets
    if ($LASTEXITCODE -ne 0) { throw "cargo test failed." }

    Write-Host "[3/4] Rust Clippy" -ForegroundColor Cyan
    & cargo clippy --workspace --all-targets -- -D warnings
    if ($LASTEXITCODE -ne 0) { throw "cargo clippy failed." }

    Write-Host "[4/4] Real MySQL 8.4 privilege-boundary checks" -ForegroundColor Cyan
    & (Join-Path $PSScriptRoot "mysql-isolation-smoke.ps1")
    if ($LASTEXITCODE -ne 0) { throw "MySQL isolation smoke test failed." }

    Write-Host "All available local verification stages passed." -ForegroundColor Green
}
finally {
    Pop-Location
}
