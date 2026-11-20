# SQLite tenant isolation

## Support model

SQLite is embedded storage, not a separately authenticated database server. Proxima uses a database-file-per-tenant model. The trusted application resolves an authenticated tenant ID and opens that tenant's file through the native SQLite tenant module.

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

SQLite does not implement database users, server-side roles, or network authentication. File permissions protect data from other operating-system users; they do not isolate tenants from a malicious process running under the same OS identity. Proxima's trusted application layer must be the only component allowed to select tenant files. Do not expose raw SQLite connections to untrusted clients, and do not use a shared process with unrestricted filesystem access as a substitute for OS-level isolation in hostile multi-tenant environments.

Use separate volumes or OS identities when stronger infrastructure separation is required. Back up each tenant file together with its WAL state using SQLite's online backup API or a quiesced/consistent backup procedure; copying only the main file while a WAL database is active is not a valid backup strategy.

## Verification

`cargo test -p proxima-engine sqlite_tenant` exercises physical file separation, invalid/path-traversal tenant IDs, symlink rejection, and Unix file permissions. The complete engine test suite runs these tests in CI.
