# Microsoft SQL Server — TDS gateway

Proxima Engine provides a SQL Server TDS 7.4 gateway. The gateway accepts SQL Server client connections, terminates client TLS, validates the LOGIN7 principal and requested database against the node's tenant assignment, then opens a separately certificate-verified TLS connection to the assigned SQL Server.

The SQL Server instance remains the database engine. Proxima binds each login to its assigned tenant/database; SQL Server authenticates the login and enforces that login's database permissions.

## Connection path

```text
Application / SQL Server driver
  -> TDS 7.4 + client TLS
  -> Proxima SQL Server TDS gateway
  -> LOGIN7 principal + database assignment check
  -> verified upstream TLS
  -> SQL Server (tenant login and database permissions)
```

## Build

From the Engine repository root:

```powershell
cargo build --release -p proxima-engine --bin proxima-sqlserver-tds-gateway
```

The binary is included in the Engine release container and the gateway deployment configuration.

## Runtime configuration

The gateway loads a JSON registry from `PROXIMA_SQLSERVER_TDS_CONFIG`. The registry schema is version 1:

```json
{
  "schema_version": 1,
  "provider_key": "sqlserver",
  "listen_addr": "127.0.0.1:14330",
  "upstream_host": "sqlserver.internal.example",
  "upstream_port": 1433,
  "upstream_server_name": "sqlserver.internal.example",
  "upstream_ca_pem": "/run/secrets/sqlserver-upstream-ca.pem",
  "client_cert_pem": "/run/secrets/sqlserver-gateway-cert.pem",
  "client_key_pem": "/run/secrets/sqlserver-gateway-key.pem",
  "allow_non_loopback": false,
  "tenants": [
    {
      "tenant_id": "tenant_a",
      "username": "agata_tenant_a_app",
      "database": "AGATA_tenant_a"
    },
    {
      "tenant_id": "tenant_b",
      "username": "agata_tenant_b_app",
      "database": "AGATA_tenant_b"
    }
  ]
}
```

Each tenant binding has a unique tenant ID, SQL Server login and database. Usernames and database names must be valid SQL identifiers. A login can map to one tenant database in the registry.

The gateway also enforces bounded resource use:
- `PROXIMA_SQLSERVER_TDS_MAX_CONNECTIONS` limits concurrent client sessions (default 128; any positive integer is accepted, with practical capacity determined by host resources and the upstream SQL Server budget).
- PRELOGIN, client TLS, LOGIN7, upstream PRELOGIN and upstream TLS handshakes have 10-second deadlines.
- Upstream TCP connection establishment has a 10-second deadline.
- Connections are rejected when the configured concurrency limit is exhausted.

The gateway requires:
- A PEM certificate and private key for the client-facing TLS listener.
- A PEM CA bundle used to verify the SQL Server upstream certificate.
- An upstream TLS server name matching the SQL Server certificate.
- A valid tenant registry containing at least one mapping.

The listener defaults to loopback. To expose it on a non-loopback interface, set `allow_non_loopback: true` in the signed runtime configuration and set `PROXIMA_SQLSERVER_TDS_ALLOW_NON_LOOPBACK=true` in the operator environment. Both controls are required.

## SQL Server tenant principals

Provision one dedicated SQL Server login and database for each tenant. Use a controlled administrative identity to create the tenant database, create/map the login, set its default database and grant only the required application data permissions.

The Engine's SQL Server tenant lifecycle provisions a tenant database, creates or rotates its login, disables database TRUSTWORTHY and cross-database chaining, denies VIEW ANY DATABASE, maps the login to the tenant database and verifies its assigned data roles and the absence of elevated server/database roles.

Use a strong, unique password for every tenant login and store it in your secret manager. The gateway checks the LOGIN7 username and requested database before forwarding LOGIN7 to SQL Server. SQL Server then validates the password and enforces the login's privileges.

## Connect an application

Keep the application's existing SQL Server driver. Point its server/host and port at the gateway and enable encryption with certificate validation against the gateway certificate.

Example with `sqlcmd`:

```powershell
sqlcmd -S tcp:127.0.0.1,14330 -d AGATA_tenant_a -U agata_tenant_a_app -N -C
```

For production, trust the issuing CA and validate the gateway certificate name; do not use a trust-server-certificate bypass.

The requested database in the client connection must match the database assigned to the LOGIN7 username. The gateway rejects an unassigned login or a login requesting a different database before forwarding the login to the upstream server.

## Deployment

The release includes:
- `proxima-sqlserver-tds-gateway` binary.
- SQL Server gateway runtime configuration.
- Client-facing certificate/key and upstream CA secret paths.
- Customer Compose and Kubernetes gateway deployment integration.
- CI build and package checks for the TDS gateway.

Use the Engine deployment configuration and secret mounts for your environment. Keep the gateway listener private to the application network; publish it only through an approved network boundary.

## Verification

Build the gateway and run the dedicated SQL Server TDS test script:

```powershell
cargo test -p proxima-engine tds
powershell -ExecutionPolicy Bypass -File .\scripts\test-sqlserver-tds-gateway.ps1
```

Use a disposable SQL Server environment for real server acceptance. Verify a valid tenant login, an invalid/unassigned login, a request for another tenant's database, client TLS negotiation and upstream certificate validation.

## Operational requirements

- Keep the gateway certificate and private key in the deployment secret store.
- Keep the upstream CA bundle current and verify the SQL Server certificate name.
- Use one tenant-specific login per tenant database.
- Rotate tenant credentials through the controlled provisioning lifecycle.
- Revoke tenant access by disabling the corresponding SQL Server login and removing its assignment.
- Monitor gateway logs and the Engine's runtime health and assignment acknowledgement state.
- Do not share SQL Server connection pools between tenant credentials.

## Clone, build and verify

Clone the Engine repository and enter its root:

```bash
git clone https://github.com/Proxima-Engine/proxima-engine.git
cd proxima-engine
cargo build --release -p proxima-engine --bin proxima-sqlserver-tds-gateway
powershell -NoProfile -ExecutionPolicy Bypass -File scripts/test-sqlserver-tds-gateway.ps1
bash scripts/test-sqlserver-tenant-isolation-ci.sh
```

## Cloud assignment

In **Agata Proxima Cloud → Dashboard → Databases**, register the existing Microsoft SQL Server service, enroll an Engine node, assign the target to that node, create the tenant binding and deploy the configuration. The Engine activates the Microsoft SQL Server runtime and reports the applied revision and tenant evidence to the workspace.
