# Oracle Database quickstart

The Oracle profile provisions one least-privilege schema owner per tenant. Application connections use tenant credentials, never the provisioning identity.

## 1. Clone and build

```bash
git clone https://github.com/Proxima-Engine/proxima-engine.git
cd proxima-engine
cargo build --locked --release -p proxima-engine
```

## 2. Generate tenant provisioning SQL

```rust
use proxima_engine::oracle_tenant::OracleTenant;

let tenant = OracleTenant::new("customer_01", &generated_secret)?;
for statement in tenant.provisioning_sql() {
    // Execute only with a separate Oracle administration connection.
    println!("{statement}");
}
let tenant_database_user = tenant.connect_user();
```

Execute the generated DDL using a separately authenticated Oracle administration connection. Store tenant passwords in a secret manager.

## 3. Verify against Oracle Free

```bash
export ORACLE_PASSWORD='disposable-test-secret'
bash scripts/test-oracle-tenant-isolation-ci.sh
```

The script provisions two schema owners and verifies tenant-local access, cross-schema data isolation and effective grants. It removes its disposable test container on exit.

**Next:** [Complete Oracle guide](ORACLE_TENANCY.md) · [Security](SECURITY.md)


## 2A. Prepare Oracle Free

Use a disposable Oracle Free 23 instance for acceptance. Keep the Oracle administration connection separate from tenant application connections. Confirm the USERS tablespace and the privileges available to the provisioning account before executing generated DDL.

## 2B. Apply the tenant schema

The generated statements create one schema owner per tenant with a bounded quota and only the schema object-creation privileges described in the full guide. Review the statements and execute them through the separately authenticated Oracle administration connection. Do not execute provisioning DDL as a tenant user. Store generated tenant passwords in a secret manager.

## 2C. Configure application pools

Create a separate connection pool for each tenant using that tenant's Oracle username and password. Resolve tenant membership on the trusted backend before selecting the pool. Do not share the provisioning identity with application processes, and do not use a single privileged account with a mutable CURRENT_SCHEMA as a tenant boundary.

## 2D. Acceptance checklist

- Each tenant can create and access objects in its own schema.
- A tenant cannot read another tenant's marker data.
- Tenant users have no DBA role, ANY privileges or unintended cross-schema object grants.
- Tenant credentials are stored and rotated securely.
- Backup, recovery and the required PDB/database isolation level are documented.

This profile is schema-per-tenant within one Oracle database/PDB; it is not database-per-tenant. See [Oracle Database tenant isolation](ORACLE_TENANCY.md) for the exact grants and verification assertions.


## Windows PowerShell: clone and build

Open PowerShell in the folder where you keep source repositories. Install Git, the stable Rust toolchain and Cargo first. For gateway providers, Docker Desktop is also required for the disposable database service used by the acceptance test.

```powershell
git clone https://github.com/Proxima-Engine/proxima-engine.git
Set-Location .\proxima-engine
cargo build --locked --release -p proxima-engine
if ($LASTEXITCODE -ne 0) { throw "Proxima build failed" }
```

Run the command from the repository root. If you already cloned the repository, use `Set-Location` to enter the extracted `proxima-engine` directory instead of cloning a second copy. Keep generated credentials, certificates and local environment files outside Git.

## Configuration review before starting

Before launching this provider, verify all of the following against the full provider guide:

1. The provider endpoint, port and distribution/version identify the intended disposable or customer database.
2. Tenant IDs are resolved by the trusted application backend and are not accepted as authorization claims from a browser.
3. Each tenant has its own database/schema/keyspace/index namespace or IAM identity, as applicable to this provider.
4. Provisioning credentials are separate from tenant application credentials and are not stored in the client registry as plaintext.
5. Certificate authorities, server names and client certificates are configured for every network TLS leg.
6. Listener exposure is limited to the application network. Keep local tests on loopback.
7. Registry files and private keys have restrictive permissions and are excluded from source control.

## Runtime diagnostics

Start the provider process in a dedicated terminal and keep its logs visible while connecting a test client. Confirm the process is listening on the configured address before running application queries. If the client cannot connect, check the process output, port binding, upstream reachability and the database service's readiness before changing tenant policy.

If authentication fails, compare the client principal and tenant mapping with the registry or native provider identity. If a certificate error occurs, validate the configured CA and server name; do not disable certificate verification to make the connection succeed. If a cross-tenant test succeeds unexpectedly, stop the test and review the provider-native grants, namespace mapping and trusted tenant-resolution path before continuing.

## Production handover checklist

- Repeat the acceptance suite against a disposable instance matching the intended provider version.
- Record the exact provider version, Engine release, configuration revision and test result.
- Test allowed tenant operations and denied cross-tenant reads and writes.
- Verify backup/restore and credential rotation for the provider's isolation model.
- Move secrets into the deployment secret manager and enable verified TLS.
- Restrict network access to the Engine and database endpoints.
- Monitor Engine health, provider errors, rejected sessions and credential lifecycle.
- Use the linked complete provider guide for deployment-specific settings and operational procedures.
