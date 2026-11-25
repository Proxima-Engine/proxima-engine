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


## 2A. Review the version 1 registry

The registry contains the listener address, upstream SQL Server host and port, upstream certificate name, CA path, gateway client certificate/key, and one mapping per tenant. Each mapping has a unique tenant ID, SQL Server login and database. Keep the registry and private keys in secret storage and exclude them from source control.

The listener defaults to loopback. To expose it on a non-loopback interface, both the signed runtime configuration's `allow_non_loopback` setting and the operator environment setting must explicitly permit it.

## 2B. Provision SQL Server logins

Create a dedicated database and login for each tenant using a controlled SQL Server administration identity. Set the login's default database and grant only the required application data permissions. Do not give application logins server roles, cross-database chaining or elevated database permissions. Store each password in a secret manager.

## 2C. Connect the application

Keep the application's existing SQL Server driver. Point it at the TDS gateway and enable encryption with certificate validation. The requested database must match the database assigned to the LOGIN7 username. Do not use a trust-server-certificate bypass in production.

## 2D. Acceptance checklist

- An assigned tenant login reaches only its assigned database.
- An unknown/unassigned login is rejected.
- A valid login requesting another tenant's database is rejected.
- Client TLS and upstream certificate verification both succeed.
- Tenant logins have no elevated server/database roles.
- Credential rotation and revocation are verified.

See [SQL Server TDS gateway](SQLSERVER_NATIVE_TENANCY.md) for the full registry schema, lifecycle operations, deployment integration and test procedures.
