# SQLite tenant isolation

## Support model

SQLite is embedded storage. Proxima isolates tenants with a private database file per tenant; the trusted application resolves the authenticated tenant ID and opens the corresponding file through the native SQLite module.

The module is in `crates/proxima-engine/src/sqlite_tenant.rs` and is exported as `proxima_engine::sqlite_tenant::SqliteTenantDatabase`.

## Storage layout

```text
PROXIMA_SQLITE_ROOT/
  tenant-a/tenant.sqlite
  tenant-b/tenant.sqlite
```

Use a dedicated persistent volume for the SQLite root. On Unix, tenant directories are created with mode 0700 and database files with mode 0600. The implementation validates tenant identifiers, rejects symlinked tenant directories and files, canonicalizes paths beneath the configured root, opens with SQLite's NOFOLLOW flag, enables foreign keys, disables trusted schema, enables secure deletion, uses WAL journaling, and applies a bounded busy timeout.

## Rust usage

```rust
use proxima_engine::sqlite_tenant::SqliteTenantDatabase;

let db = SqliteTenantDatabase::open("/var/lib/proxima/sqlite", "tenant-a")?;
db.connection().execute(
    "CREATE TABLE IF NOT EXISTS records (id INTEGER PRIMARY KEY, payload TEXT NOT NULL)",
    [],
)?;
```

Tenant IDs must come from the trusted authentication and authorization layer. Never accept a database path or tenant ID directly from an untrusted SQL client. Keep each returned connection bound to its original tenant for its entire lifetime.

## Security boundary and operational requirements

SQLite isolation is file- and process-based. The trusted application must be the only component allowed to resolve tenant file paths. Apply restrictive filesystem permissions and use separate OS identities or volumes when tenants require stronger infrastructure separation. Keep raw SQLite connections inside the trusted application boundary.

Use separate volumes or OS identities when stronger infrastructure separation is required. Back up each tenant file together with its WAL state using SQLite's online backup API or a quiesced/consistent backup procedure; copying only the main file while a WAL database is active is not a valid backup strategy.

## Verification

`cargo test -p proxima-engine sqlite_tenant` exercises physical file separation, invalid/path-traversal tenant IDs, symlink rejection, and Unix file permissions. The complete engine test suite runs these tests in CI.

## Clone, build and verify

Clone the Engine repository and enter its root:

```bash
git clone https://github.com/Proxima-Engine/proxima-engine.git
cd proxima-engine
cargo build --release -p proxima-engine
cargo test -p proxima-engine sqlite_tenant
```

## Cloud assignment

In **Agata Proxima Cloud → Dashboard → Databases**, register the existing SQLite service, enroll an Engine node, assign the target to that node, create the tenant binding and deploy the configuration. The Engine activates the SQLite runtime and reports the applied revision and tenant evidence to the workspace.
