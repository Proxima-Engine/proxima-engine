# Oracle Database tenant isolation

## Support model

Proxima's Oracle profile uses schema-per-tenant isolation backed by a dedicated Oracle database user for each tenant. In Oracle, a user owns a schema of the same name. Applications connect directly with the tenant's Oracle credentials; they do not share a privileged application account and do not pass tenant predicates in every query.

The profile is implemented in `crates/proxima-engine/src/oracle_tenant.rs` and exported as `proxima_engine::oracle_tenant::OracleTenant`. The module validates tenant identifiers, derives the tenant username, enforces a minimum generated-password length, and produces provisioning DDL for a narrowly privileged schema owner.

## Tenant provisioning

For tenant `customer_01`, Proxima derives `PROXIMA_CUSTOMER_01_OWNER`. Provisioning creates the user with a bounded 100 MB quota on the USERS tablespace and grants only the schema-owner capabilities required to create objects: CREATE SESSION, CREATE TABLE, CREATE SEQUENCE, CREATE VIEW, CREATE PROCEDURE, and CREATE TRIGGER. It assigns no DBA role, no ANY privileges, and no default roles.

Run the generated DDL only through a separately authenticated Oracle administration connection. Keep the tenant password in a secret manager and provide it only to the trusted backend that creates the tenant's connection pool. Never give an application the provisioning account's credentials.

## Rust usage

```rust
use proxima_engine::oracle_tenant::OracleTenant;

let tenant = OracleTenant::new("customer_01", &generated_secret)?;
for statement in tenant.provisioning_sql() {
    // Execute with a separately authenticated Oracle administration connection.
    // Do not execute tenant-provisioning DDL using a tenant connection.
    println!("{statement}");
}
let tenant_database_user = tenant.connect_user();
```

## Isolation properties

Each tenant has a distinct Oracle schema owner and authentication identity. Tenant accounts receive no explicit object grants, no DBA role, and no cross-schema ANY privileges. Changing CURRENT_SCHEMA changes name resolution only; it does not grant privileges. The real-database acceptance test verifies that a tenant query does not return another tenant's marker data, that no ANY-table privileges or cross-schema object grants are present, and that DBA role activation is rejected. The test deliberately checks data non-disclosure rather than treating an empty cross-schema SELECT result as proof that the SQL statement itself was rejected.

This is schema-per-tenant isolation inside one Oracle database/PDB. It is not database-per-tenant or PDB-per-tenant isolation. Customers needing stronger administrative or recovery boundaries can deploy separate PDBs or Oracle databases per tenant.

## Verification

Run `bash scripts/test-oracle-tenant-isolation-ci.sh` with Docker available and `ORACLE_PASSWORD` set. The script starts a disposable Oracle Free 23 container, provisions two independent schema owners, verifies tenant-local create/read operations, checks that cross-schema queries do not return another tenant's data, inspects effective grants, and asserts that DBA role activation is denied. The script removes its disposable container on exit.

The Rust unit tests validate identifier injection rejection, derived usernames, least-privilege DDL and password quoting. CI runs the Rust tests and the real Oracle acceptance script.
