# SQL Server tenant isolation: native database-per-tenant mode

## Scope and trust boundary

The SQL Server integration in this release is a **native SQL Server security profile**, not a Proxima TDS proxy. SQL Server speaks TDS and the Rust ecosystem reviewed for this work did not provide a maintained production TDS server that Proxima could safely embed. Proxima therefore does not terminate SQL Server client sessions, inspect SQL batches, or claim to bind a SQL Server connection to a Proxima control-plane identity.

Instead, each tenant receives a dedicated SQL Server database and a dedicated SQL login. The login's default database is its tenant database, and the login receives only the application-schema DML permissions needed by that application. SQL Server itself enforces the database boundary. Applications do not add tenant identifiers to SQL statements: the tenant-specific credential selects the database boundary.

This mode is appropriate where a trusted provisioning system can issue and rotate a distinct SQL login per tenant. It is not a shared-database RLS gateway and does not provide Proxima's normal gateway-side identity mapping, auditing, or policy decision point. Do not reuse one SQL login across tenants.

## Security controls

- One SQL database and one SQL login per tenant.
- No server roles, database ownership, db_owner, db_datareader, or db_datawriter grants to tenant logins.
- Grant only SELECT, INSERT, UPDATE, and DELETE on the application schema.
- Deny VIEW ANY DATABASE and ALTER ANY LOGIN to tenant logins.
- Keep TRUSTWORTHY and cross-database ownership chaining disabled.
- Do not enable guest access in tenant databases.
- Use TLS with certificate validation for application-to-SQL Server connections.
- Keep login passwords in a secret manager; rotate them independently and revoke by disabling/dropping the login.
- The SQL Server instance administrator and provisioning identity remain trusted infrastructure principals.

A database-per-tenant boundary is stronger than relying on every query to remember a tenant predicate, but it has different operational costs: database count, backup/restore, migrations, connection pools, and per-tenant credential lifecycle must be managed.

## Provisioning and verification

The CI fixture in scripts/sqlserver-provision-two-tenants.sql provisions two isolated tenant databases and least-privilege logins. The runner scripts/test-sqlserver-tenant-isolation-ci.sh tests read/write behavior, cross-database access denial, schema-creation denial, login impersonation denial, and invalid credentials against a real SQL Server 2022 instance.

Run the fixture only against a disposable SQL Server instance. It drops and recreates the named CI databases and logins. It is not a production tenant-provisioning API.

    MSSQL_SA_PASSWORD='your-disposable-admin-password' bash scripts/test-sqlserver-tenant-isolation-ci.sh

## Production deployment checklist

1. Provision a dedicated database and login for each tenant using an administrative service account.
2. Set database owner to a controlled platform principal, not the tenant login.
3. Create the application schema and grant only required object permissions.
4. Verify TRUSTWORTHY OFF, DB_CHAINING OFF, and no guest access.
5. Deliver each tenant's unique credential through a secret manager and require TLS.
6. Ensure application pools are partitioned by tenant credential and never reuse a connection across tenants.
7. Run the cross-database denial tests after every permission, migration, or SQL Server version change.
8. If a customer requires a single shared database with row-level isolation or a Proxima-managed TDS endpoint, this native profile is insufficient; that requires a separately engineered and validated TDS gateway.
