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
  throw "Docker CLI was not found. Install Docker Desktop with the WSL 2 backend and Docker Compose v2, then rerun this script."
}

$dockerOs = docker info --format '{{.OSType}}'
if ($LASTEXITCODE -ne 0) {
  throw "Docker Desktop is not running or the Docker daemon is unavailable. Start Docker Desktop, wait until it reports Engine running, and rerun this script."
}
if ($dockerOs.Trim() -ne "linux") {
  throw "Proxima Engine uses a Linux container image. In Docker Desktop, switch to Linux containers and rerun this installer."
}

$version = docker compose version
if ($LASTEXITCODE -ne 0) { throw "Docker Compose v2 is required. Update Docker Desktop and confirm that 'docker compose version' works." }
Write-Host $version

$configOutput = docker compose -f compose.customer.yaml config --quiet 2>&1
if ($LASTEXITCODE -ne 0) {
  throw "Customer Compose configuration is invalid. Check .env and the two secret-file paths. Details: $configOutput"
}

Write-Host "Building and starting Proxima Engine. The first build downloads Rust dependencies and can take several minutes."
docker compose -f compose.customer.yaml up -d --build
if ($LASTEXITCODE -ne 0) {
  docker compose -f compose.customer.yaml logs --tail 100 engine
  throw "Engine container did not start. Review the logs above, correct the reported issue, and rerun this installer."
}

Write-Host "Waiting up to 120 seconds for Docker's Engine health check..."
$healthy = $false
for ($attempt = 0; $attempt -lt 40; $attempt++) {
  $containerId = docker compose -f compose.customer.yaml ps -q engine
  if ($LASTEXITCODE -eq 0 -and -not [string]::IsNullOrWhiteSpace(($containerId | Out-String).Trim())) {
    $health = docker inspect --format '{{.State.Health.Status}}' $containerId
    if ($LASTEXITCODE -eq 0 -and $health.Trim() -eq "healthy") {
      $healthy = $true
      break
    }
    if ($LASTEXITCODE -eq 0 -and $health.Trim() -eq "unhealthy") {
      break
    }
  }
  Start-Sleep -Seconds 3
}

if (-not $healthy) {
  docker compose -f compose.customer.yaml ps
  docker compose -f compose.customer.yaml logs --tail 100 engine
  throw "Engine did not pass its Docker health check within 120 seconds. Review the container status and logs above before retrying."
}

Write-Host ""
Write-Host "Proxima Engine is healthy."
Write-Host "PostgreSQL proxy: 127.0.0.1:6432"
Write-Host "Node enrollment and signed heartbeat now run from the Engine container."
Write-Host "Confirm that the registered node appears as healthy in Agata Proxima Fleet."
docker compose -f compose.customer.yaml ps
