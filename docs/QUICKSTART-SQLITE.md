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
