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
