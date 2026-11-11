$ErrorActionPreference = "Stop"
Set-StrictMode -Version Latest

$sourceRoot = Split-Path -Parent (Split-Path -Parent $MyInvocation.MyCommand.Path)
$tempRoot = Join-Path ([System.IO.Path]::GetTempPath()) ("proxima-windows-installer-test-" + [guid]::NewGuid().ToString("N"))
New-Item -ItemType Directory -Path $tempRoot -Force | Out-Null
Copy-Item (Join-Path $sourceRoot "install-customer.ps1") $tempRoot
Copy-Item (Join-Path $sourceRoot "compose.customer.yaml") $tempRoot
$env:PROXIMA_NODE_ID = "00000000-0000-4000-8000-000000000001"
$env:PROXIMA_NODE_ENROLLMENT_URL = "https://api.agataproxima.com/api/v1/nodes/enroll"
$env:PROXIMA_NODE_ENROLLMENT_TOKEN = "test-one-time-token"
$env:PROXIMA_UPSTREAM_ADDR = "postgres:5432"

$global:dockerCalls = [System.Collections.Generic.List[string]]::new()
function global:docker {
  $call = ($args | ForEach-Object { [string]$_ }) -join " "
  $global:dockerCalls.Add($call)
  $global:LASTEXITCODE = 0

  if ($call -eq "info --format {{.OSType}}") { return "linux" }
  if ($call -eq "compose version") { return "Docker Compose version v2.30.0" }
  if ($call -eq "compose -f compose.customer.yaml config --quiet") { return }
  if ($call -eq "compose -f compose.customer.yaml up -d --build") { return }
  if ($call -eq "compose -f compose.customer.yaml ps -q engine") { return "test-engine-container" }
  if ($call -eq "inspect --format {{.State.Health.Status}} test-engine-container") { return "healthy" }
  if ($call -eq "compose -f compose.customer.yaml ps") { return "engine running (healthy)" }
  throw "Unexpected Docker invocation in Windows installer test: $call"
}

try {
  & (Join-Path $tempRoot "install-customer.ps1")

  $generatedEnv = Get-Content -LiteralPath (Join-Path $tempRoot ".env") -Raw
  $generatedToken = Get-Content -LiteralPath (Join-Path $tempRoot "secrets/node_enrollment_token") -Raw
  if ($generatedEnv -notmatch "PROXIMA_UPSTREAM_ADDR=postgres:5432") {
    throw "Windows installer did not generate the PostgreSQL upstream setting."
  }
  if ($generatedEnv -notmatch "PROXIMA_NODE_HEARTBEAT_URL=https://api.agataproxima.com/api/v1/nodes/heartbeat") {
    throw "Windows installer did not persist the node heartbeat URL."
  }
  if ($generatedToken.Trim() -ne "test-one-time-token") {
    throw "Windows installer did not create the one-time enrollment secret file correctly."
  }
  if (Test-Path Env:PROXIMA_NODE_ENROLLMENT_TOKEN) {
    throw "Windows installer did not remove the one-time token from the current process environment."
  }

  $requiredCalls = @(
    "info --format {{.OSType}}",
    "compose version",
    "compose -f compose.customer.yaml config --quiet",
    "compose -f compose.customer.yaml up -d --build",
    "compose -f compose.customer.yaml ps -q engine",
    "inspect --format {{.State.Health.Status}} test-engine-container"
  )
  foreach ($requiredCall in $requiredCalls) {
    if (-not $global:dockerCalls.Contains($requiredCall)) {
      throw "Windows installer did not perform required Docker operation: $requiredCall"
    }
  }

  Write-Host "PASS: Windows PowerShell installer validates prerequisites, Linux-container mode, Compose configuration, startup and container health."
}
finally {
  Remove-Item Function:\docker -ErrorAction SilentlyContinue
  Remove-Item -LiteralPath $tempRoot -Recurse -Force -ErrorAction SilentlyContinue
}
