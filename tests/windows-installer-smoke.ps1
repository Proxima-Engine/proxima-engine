$ErrorActionPreference = "Stop"
Set-StrictMode -Version Latest

$sourceRoot = Split-Path -Parent (Split-Path -Parent $MyInvocation.MyCommand.Path)
$tempRoot = Join-Path ([System.IO.Path]::GetTempPath()) ("proxima-windows-installer-test-" + [guid]::NewGuid().ToString("N"))
New-Item -ItemType Directory -Path (Join-Path $tempRoot "secrets") -Force | Out-Null
Copy-Item (Join-Path $sourceRoot "install-customer.ps1") $tempRoot
Copy-Item (Join-Path $sourceRoot "compose.customer.yaml") $tempRoot
Set-Content -LiteralPath (Join-Path $tempRoot ".env") -Value ("PROXIMA_NODE_ID=00000000-0000-4000-8000-000000000001" + [Environment]::NewLine + "PROXIMA_UPSTREAM_ADDR=postgres:5432") -NoNewline
Set-Content -LiteralPath (Join-Path $tempRoot "secrets/node_enrollment_token") -Value "test-one-time-token" -NoNewline
Set-Content -LiteralPath (Join-Path $tempRoot "secrets/tenant_signing_key") -Value "0123456789abcdef0123456789abcdef" -NoNewline

$script:dockerCalls = [System.Collections.Generic.List[string]]::new()
function global:docker {
  $call = ($args | ForEach-Object { [string]$_ }) -join " "
  $script:dockerCalls.Add($call)
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

  $requiredCalls = @(
    "info --format {{.OSType}}",
    "compose version",
    "compose -f compose.customer.yaml config --quiet",
    "compose -f compose.customer.yaml up -d --build",
    "compose -f compose.customer.yaml ps -q engine",
    "inspect --format {{.State.Health.Status}} test-engine-container"
  )
  foreach ($requiredCall in $requiredCalls) {
    if (-not $script:dockerCalls.Contains($requiredCall)) {
      throw "Windows installer did not perform required Docker operation: $requiredCall"
    }
  }

  Write-Host "PASS: Windows PowerShell installer validates prerequisites, Linux-container mode, Compose configuration, startup and container health."
}
finally {
  Remove-Item Function:\docker -ErrorAction SilentlyContinue
  Remove-Item -LiteralPath $tempRoot -Recurse -Force -ErrorAction SilentlyContinue
}
