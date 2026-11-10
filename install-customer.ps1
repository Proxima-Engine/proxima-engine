$ErrorActionPreference = "Stop"
Set-StrictMode -Version Latest

$root = Split-Path -Parent $MyInvocation.MyCommand.Path
Set-Location $root

$required = @(".env", "compose.customer.yaml", "secrets/node_enrollment_token", "secrets/tenant_signing_key")
foreach ($path in $required) {
  if (-not (Test-Path -LiteralPath (Join-Path $root $path) -PathType Leaf)) {
    throw "Missing required customer setup file: $path. Download .env and both secret files from Agata Proxima → Nodes, then place them in this folder."
  }
}
if (-not (Get-Command docker -ErrorAction SilentlyContinue)) {
  throw "Docker CLI was not found. Install Docker Desktop or Docker Engine with the Compose v2 plugin, then rerun this script."
}
$version = docker compose version
if ($LASTEXITCODE -ne 0) { throw "Docker Compose v2 is required." }
Write-Host $version

docker compose -f compose.customer.yaml config --quiet
if ($LASTEXITCODE -ne 0) { throw "Customer Compose configuration is invalid. Check .env and secret file paths." }

Write-Host "Building and starting Proxima Engine. The first build downloads Rust dependencies and can take several minutes."
docker compose -f compose.customer.yaml up -d --build
if ($LASTEXITCODE -ne 0) { throw "Engine container did not start. Inspect with: docker compose -f compose.customer.yaml logs --tail 100 engine" }

Write-Host "Waiting for the Engine health check..."
$healthy = $false
for ($attempt = 0; $attempt -lt 40; $attempt++) {
  $status = docker compose -f compose.customer.yaml ps --format json engine 2>$null
  if ($LASTEXITCODE -eq 0 -and $status -match '"Health":"healthy"') { $healthy = $true; break }
  Start-Sleep -Seconds 3
}
if (-not $healthy) {
  docker compose -f compose.customer.yaml ps
  docker compose -f compose.customer.yaml logs --tail 100 engine
  throw "Engine did not become healthy within 120 seconds. Review the logs above before retrying."
}
Write-Host "Proxima Engine is healthy. Node enrollment and signed heartbeat will now complete against the configured Agata Proxima Control Plane."
docker compose -f compose.customer.yaml ps
