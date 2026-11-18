$ErrorActionPreference = "Stop"
Set-StrictMode -Version Latest

$repoRoot = Split-Path -Parent $PSScriptRoot
$certDir = Join-Path $repoRoot "dev\mysql-certs"
$secretDir = Join-Path $repoRoot "dev\mysql-secrets"
$dataDir = Join-Path $repoRoot "dev\mysql-data"

$openssl = Get-Command openssl -ErrorAction SilentlyContinue
if (-not $openssl) {
    throw "OpenSSL is required. Install Git for Windows (Git Bash includes openssl) or OpenSSL, then reopen PowerShell."
}

New-Item -ItemType Directory -Force -Path $certDir, $secretDir, $dataDir | Out-Null

$caKey = Join-Path $certDir "ca-key.pem"
$caCert = Join-Path $certDir "ca.pem"
$serverKey = Join-Path $certDir "mysql-server-key.pem"
$serverCsr = Join-Path $certDir "mysql-server.csr"
$serverCert = Join-Path $certDir "mysql-server-cert.pem"
$gatewayKey = Join-Path $certDir "gateway-key.pem"
$gatewayCsr = Join-Path $certDir "gateway.csr"
$gatewayCert = Join-Path $certDir "gateway-cert.pem"

$serverConfig = Join-Path $certDir "mysql-server.cnf"
@"
[req]
prompt = no
distinguished_name = dn
req_extensions = v3_req
[dn]
CN = mysql-test
[v3_req]
subjectAltName = @alt_names
keyUsage = critical, digitalSignature, keyEncipherment
basicConstraints = critical,CA:FALSE
extendedKeyUsage = serverAuth
[alt_names]
DNS.1 = mysql-test
DNS.2 = localhost
IP.1 = 127.0.0.1
"@ | Set-Content -Encoding ascii $serverConfig

$gatewayConfig = Join-Path $certDir "gateway.cnf"
@"
[req]
prompt = no
distinguished_name = dn
req_extensions = v3_req
[dn]
CN = localhost
[v3_req]
subjectAltName = @alt_names
keyUsage = critical, digitalSignature, keyEncipherment
extendedKeyUsage = serverAuth
[alt_names]
DNS.1 = localhost
IP.1 = 127.0.0.1
"@ | Set-Content -Encoding ascii $gatewayConfig

if (-not (Test-Path $caCert)) {
    & openssl genrsa -out $caKey 4096
    if ($LASTEXITCODE -ne 0) { throw "Could not generate local CA key." }
    & openssl req -x509 -new -nodes -key $caKey -sha256 -days 3650 -subj "/CN=Agata Proxima MySQL Development CA" -addext "basicConstraints=critical,CA:TRUE" -addext "keyUsage=critical,keyCertSign,cRLSign" -addext "subjectKeyIdentifier=hash" -out $caCert
    if ($LASTEXITCODE -ne 0) { throw "Could not generate local CA certificate." }
}

if (-not (Test-Path $serverCert)) {
    & openssl genrsa -out $serverKey 2048
    if ($LASTEXITCODE -ne 0) { throw "Could not generate MySQL server key." }
    & openssl req -new -key $serverKey -out $serverCsr -config $serverConfig
    if ($LASTEXITCODE -ne 0) { throw "Could not create MySQL server CSR." }
    & openssl x509 -req -in $serverCsr -CA $caCert -CAkey $caKey -CAcreateserial -out $serverCert -days 825 -sha256 -extensions v3_req -extfile $serverConfig
    if ($LASTEXITCODE -ne 0) { throw "Could not sign MySQL server certificate." }
}

if (-not (Test-Path $gatewayCert)) {
    & openssl genrsa -out $gatewayKey 2048
    if ($LASTEXITCODE -ne 0) { throw "Could not generate gateway TLS key." }
    & openssl req -new -key $gatewayKey -out $gatewayCsr -config $gatewayConfig
    if ($LASTEXITCODE -ne 0) { throw "Could not create gateway TLS CSR." }
    & openssl x509 -req -in $gatewayCsr -CA $caCert -CAkey $caKey -CAcreateserial -out $gatewayCert -days 825 -sha256 -extensions v3_req -extfile $gatewayConfig
    if ($LASTEXITCODE -ne 0) { throw "Could not sign gateway TLS certificate." }
}

$storeKey = Join-Path $secretDir "mysql-store-key"
$assertionKey = Join-Path $secretDir "tenant-assertion-key.txt"
if (-not (Test-Path $storeKey)) {
    $bytes = New-Object byte[] 32
    $rng = [System.Security.Cryptography.RandomNumberGenerator]::Create()
    $rng.GetBytes($bytes)
    $rng.Dispose()
    [BitConverter]::ToString($bytes).Replace("-", "").ToLowerInvariant() | Set-Content -NoNewline $storeKey
}
if (-not (Test-Path $assertionKey)) {
    $bytes = New-Object byte[] 32
    $rng = [System.Security.Cryptography.RandomNumberGenerator]::Create()
    $rng.GetBytes($bytes)
    $rng.Dispose()
    [BitConverter]::ToString($bytes).Replace("-", "").ToLowerInvariant() | Set-Content -NoNewline $assertionKey
}

$assertionValue = (Get-Content $assertionKey -Raw).Trim()
"PROXIMA_MYSQL_TENANT_ASSERTION_KEY=$assertionValue" | Set-Content -Encoding ascii (Join-Path $secretDir "mysql-gateway.env")

Write-Host "Local MySQL CA, server/gateway certificates and secret keys are ready." -ForegroundColor Green
Write-Host "Keep dev\mysql-certs, dev\mysql-secrets and dev\mysql-data private; they are excluded from Git."
Write-Host "For the gateway Compose profile, set this in the current PowerShell session:"
Write-Host '$env:PROXIMA_MYSQL_TENANT_ASSERTION_KEY = (Get-Content .\dev\mysql-secrets\tenant-assertion-key.txt -Raw).Trim()'
