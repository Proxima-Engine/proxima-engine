# Microsoft SQL Server quickstart

The TDS 7.4 gateway checks the LOGIN7 principal and requested database before forwarding the session to SQL Server over verified TLS.

## 1. Clone and build

```powershell
git clone https://github.com/Proxima-Engine/proxima-engine.git
Set-Location .\proxima-engine
cargo build --locked --release -p proxima-engine --bin proxima-sqlserver-tds-gateway
```

## 2. Provision tenants

Create one SQL Server database and restricted login per tenant. Follow [SQL Server tenant principals](SQLSERVER_NATIVE_TENANCY.md) and keep passwords in a secret manager.

## 3. Configure the gateway

Create the version 1 JSON registry described in [SQL Server runtime configuration](SQLSERVER_NATIVE_TENANCY.md). Set the upstream hostname/port, certificate name, upstream CA, client certificate/key and tenant-to-login/database mappings. Set `PROXIMA_SQLSERVER_TDS_CONFIG` to the registry path and start the gateway using the customer deployment configuration.

## 4. Connect and verify

```powershell
sqlcmd -S tcp:127.0.0.1,14330 -d AGATA_tenant_a -U agata_tenant_a_app -N
powershell -NoProfile -ExecutionPolicy Bypass -File .\scripts\test-sqlserver-tds-gateway.ps1
bash scripts/test-sqlserver-tenant-isolation-ci.sh
```

Use a disposable SQL Server instance to verify assigned login success, unassigned login rejection, database mismatch rejection and both TLS legs. Trust the gateway certificate; do not disable certificate validation.

**Next:** [Complete SQL Server guide](SQLSERVER_NATIVE_TENANCY.md) · [Deployment](DEPLOYMENT.md)
