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
