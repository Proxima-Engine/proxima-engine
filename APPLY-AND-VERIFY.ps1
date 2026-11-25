[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)][string]$EngineRepo,
    [switch]$Apply,
    [switch]$RunFullWorkspaceTests
)

$ErrorActionPreference = 'Stop'
$source = Join-Path $PSScriptRoot 'engine'
$EngineRepo = (Resolve-Path $EngineRepo).Path
if (-not (Test-Path (Join-Path $EngineRepo 'Cargo.toml'))) {
    throw "EngineRepo must point to the Cargo workspace root containing Cargo.toml: $EngineRepo"
}
if (-not (Test-Path (Join-Path $source 'Cargo.toml'))) {
    throw "The delivery engine source folder is missing Cargo.toml: $source"
}

if (-not $Apply) {
    Write-Host "DRY RUN. Files that will be copied into ${EngineRepo}:" -ForegroundColor Yellow
    Get-ChildItem $source -Recurse -File | ForEach-Object {
        $_.FullName.Substring($source.Length + 1)
    }
    Write-Host "Re-run with -Apply to back up overwritten files and apply the source." -ForegroundColor Yellow
    exit 0
}

$backup = Join-Path $EngineRepo ('.agata-completion-backup-' + (Get-Date -Format 'yyyyMMdd-HHmmss'))
New-Item -ItemType Directory -Path $backup | Out-Null
Get-ChildItem $source -Recurse -File | ForEach-Object {
    $relative = $_.FullName.Substring($source.Length + 1)
    $target = Join-Path $EngineRepo $relative
    $targetDir = Split-Path $target -Parent
    New-Item -ItemType Directory -Force -Path $targetDir | Out-Null
    if (Test-Path $target) {
        $backupTarget = Join-Path $backup $relative
        New-Item -ItemType Directory -Force -Path (Split-Path $backupTarget -Parent) | Out-Null
        Copy-Item -LiteralPath $target -Destination $backupTarget -Force
    }
    Copy-Item -LiteralPath $_.FullName -Destination $target -Force
}
Write-Host "Source applied. Backup: $backup" -ForegroundColor Green

$nativePreferenceAvailable = Test-Path Variable:PSNativeCommandUseErrorActionPreference
if ($nativePreferenceAvailable) { $previousNativePreference = $PSNativeCommandUseErrorActionPreference }
$PSNativeCommandUseErrorActionPreference = $false
function Invoke-CargoStep([string]$Name, [string[]]$Arguments) {
    Write-Host "`n=== $Name ===" -ForegroundColor Cyan
    & cargo @Arguments
    $code = $LASTEXITCODE
    if ($code -ne 0) { throw "Cargo step '$Name' failed with exit code $code." }
}

Push-Location $EngineRepo
try {
    Invoke-CargoStep 'Rust formatting check' @('fmt', '--all', '--', '--check')
    Invoke-CargoStep 'Workspace compile check (resolves new provider dependencies and updates Cargo.lock)' @('check', '--workspace', '--all-targets')
    Invoke-CargoStep 'Engine library unit tests' @('test', '-p', 'proxima-engine', '--lib')
    Invoke-CargoStep 'Engine binary unit tests' @('test', '-p', 'proxima-engine', '--bin', 'proxima-engine')
    if ($RunFullWorkspaceTests) {
        Invoke-CargoStep 'Full workspace test suite (requires configured live integration services)' @('test', '--workspace', '--all-targets', '--no-fail-fast')
    }
    Write-Host "`nApply and selected verification steps completed. Backup retained at $backup" -ForegroundColor Green
} finally {
    Pop-Location
    if ($nativePreferenceAvailable) { $PSNativeCommandUseErrorActionPreference = $previousNativePreference }
}
