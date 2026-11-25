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
