# SQLite quickstart

SQLite is embedded storage. The trusted application opens a private database file for the authenticated tenant through Proxima's native Rust module.

## 1. Clone and build

```bash
git clone https://github.com/Proxima-Engine/proxima-engine.git
cd proxima-engine
cargo build --locked --release -p proxima-engine
```

## 2. Open a tenant database

```rust
use proxima_engine::sqlite_tenant::SqliteTenantDatabase;

let db = SqliteTenantDatabase::open("/var/lib/proxima/sqlite", "tenant-a")?;
db.connection().execute(
    "CREATE TABLE IF NOT EXISTS records (id INTEGER PRIMARY KEY, payload TEXT NOT NULL)",
    [],
)?;
```

Tenant identity must come from trusted server-side authentication. Never accept a file path or tenant ID directly from an untrusted SQL client. Use a persistent volume and restrictive filesystem permissions.

## 3. Verify

```bash
cargo test -p proxima-engine sqlite_tenant
```

The tests cover physical file separation, path traversal, symlink rejection and Unix file permissions. Follow the full guide for WAL-aware backup and recovery.

**Next:** [Complete SQLite guide](SQLITE_TENANCY.md) · [Architecture](ARCHITECTURE.md)


## 2A. Set the persistent storage root

Choose a directory on a persistent local volume that is writable only by the trusted application process. The module creates one tenant directory and SQLite file under this root. Do not place the directory under a public web root or a path writable by unrelated services.

Example storage layout:

```text
/var/lib/proxima/sqlite/
  tenant-a/tenant.sqlite
  tenant-b/tenant.sqlite
```

## 2B. Bind identity in the application

Authenticate the user and resolve organization and tenant membership before opening the database. Pass only the trusted tenant identifier to `SqliteTenantDatabase::open`. Never accept a filesystem path, tenant identifier or database filename directly from a browser or untrusted SQL client. Keep each connection bound to its original tenant for its full lifetime.

## 2C. Operate and back up safely

The module applies path validation and filesystem protections, enables foreign keys, disables trusted schema, enables secure deletion and WAL journaling, and uses a bounded busy timeout. Keep the root directory and its contents protected by OS permissions. Use separate OS identities or volumes when a stronger infrastructure boundary is required.

Use SQLite's online backup API or a quiesced consistent backup that includes WAL state. Copying only the main database file while WAL is active is not a valid backup procedure.

## 2D. Acceptance checklist

- Tenant A and Tenant B open different physical database files.
- Path traversal and symlink attempts are rejected.
- Files and directories have restrictive permissions on Unix.
- Tenant identity comes from trusted server-side authorization.
- Backup and restore are tested with WAL state included.

See [SQLite tenant isolation](SQLITE_TENANCY.md) for the storage layout, hardening controls and full verification details.
