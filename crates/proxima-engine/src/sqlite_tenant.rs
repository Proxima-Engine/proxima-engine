use rusqlite::{Connection, OpenFlags};
use std::fs::{self, OpenOptions};
use std::io;
use std::path::{Path, PathBuf};
use std::time::Duration;

const DATABASE_FILE: &str = "tenant.sqlite";

#[derive(Debug)]
pub enum SqliteTenantError { InvalidTenantId, Io(io::Error), Sqlite(rusqlite::Error), UnsafePath }
impl std::fmt::Display for SqliteTenantError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InvalidTenantId => write!(f, "invalid SQLite tenant identifier"),
            Self::Io(e) => write!(f, "SQLite tenant storage I/O error: {e}"),
            Self::Sqlite(e) => write!(f, "SQLite error: {e}"),
            Self::UnsafePath => write!(f, "SQLite tenant storage path is not a safe regular directory or file"),
        }
    }
}
impl std::error::Error for SqliteTenantError {}
impl From<io::Error> for SqliteTenantError { fn from(e: io::Error) -> Self { Self::Io(e) } }
impl From<rusqlite::Error> for SqliteTenantError { fn from(e: rusqlite::Error) -> Self { Self::Sqlite(e) } }

/// Trusted in-process SQLite connection permanently bound to one tenant file.
/// Never accept a filesystem path from an untrusted database client.
pub struct SqliteTenantDatabase { tenant_id: String, path: PathBuf, connection: Connection }

impl SqliteTenantDatabase {
    pub fn open(root: impl AsRef<Path>, tenant_id: &str) -> Result<Self, SqliteTenantError> {
        validate_tenant_id(tenant_id)?;
        fs::create_dir_all(root.as_ref())?;
        let root = fs::canonicalize(root.as_ref())?;
        let tenant_dir = root.join(tenant_id);
        match fs::create_dir(&tenant_dir) {
            Ok(()) => set_private_dir_permissions(&tenant_dir)?,
            Err(e) if e.kind() == io::ErrorKind::AlreadyExists => {},
            Err(e) => return Err(e.into()),
        }
        let metadata = fs::symlink_metadata(&tenant_dir)?;
        if metadata.file_type().is_symlink() || !metadata.is_dir() { return Err(SqliteTenantError::UnsafePath); }
        let tenant_dir = fs::canonicalize(&tenant_dir)?;
        if !tenant_dir.starts_with(&root) { return Err(SqliteTenantError::UnsafePath); }

        let path = tenant_dir.join(DATABASE_FILE);
        match OpenOptions::new().write(true).create_new(true).open(&path) {
            Ok(file) => { drop(file); set_private_file_permissions(&path)?; },
            Err(e) if e.kind() == io::ErrorKind::AlreadyExists => {},
            Err(e) => return Err(e.into()),
        }
        let metadata = fs::symlink_metadata(&path)?;
        if metadata.file_type().is_symlink() || !metadata.is_file() { return Err(SqliteTenantError::UnsafePath); }
        let canonical_path = fs::canonicalize(&path)?;
        if !canonical_path.starts_with(&tenant_dir) { return Err(SqliteTenantError::UnsafePath); }

        let flags = OpenFlags::SQLITE_OPEN_READ_WRITE | OpenFlags::SQLITE_OPEN_CREATE
            | OpenFlags::SQLITE_OPEN_FULL_MUTEX | OpenFlags::SQLITE_OPEN_NOFOLLOW;
        let connection = Connection::open_with_flags(&canonical_path, flags)?;
        connection.busy_timeout(Duration::from_secs(5))?;
        connection.execute_batch(
            "PRAGMA foreign_keys = ON; PRAGMA trusted_schema = OFF; PRAGMA secure_delete = ON; PRAGMA synchronous = FULL;"
        )?;
        let _: String = connection.query_row("PRAGMA journal_mode = WAL", [], |row| row.get(0))?;
        Ok(Self { tenant_id: tenant_id.to_owned(), path: canonical_path, connection })
    }
    pub fn tenant_id(&self) -> &str { &self.tenant_id }
    pub fn path(&self) -> &Path { &self.path }
    /// Expose only to trusted application code; never share across tenant identities.
    pub fn connection(&self) -> &Connection { &self.connection }
}

pub fn validate_tenant_id(id: &str) -> Result<(), SqliteTenantError> {
    if id.is_empty() || id.len() > 64 || !id.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_') {
        return Err(SqliteTenantError::InvalidTenantId);
    }
    Ok(())
}
#[cfg(unix)]
fn set_private_dir_permissions(path: &Path) -> io::Result<()> {
    use std::os::unix::fs::PermissionsExt;
    fs::set_permissions(path, fs::Permissions::from_mode(0o700))
}
#[cfg(not(unix))]
fn set_private_dir_permissions(_: &Path) -> io::Result<()> { Ok(()) }
#[cfg(unix)]
fn set_private_file_permissions(path: &Path) -> io::Result<()> {
    use std::os::unix::fs::PermissionsExt;
    fs::set_permissions(path, fs::Permissions::from_mode(0o600))
}
#[cfg(not(unix))]
fn set_private_file_permissions(_: &Path) -> io::Result<()> { Ok(()) }

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;
    #[test]
    fn tenant_files_are_physically_separate() {
        let root = tempdir().unwrap();
        let a = SqliteTenantDatabase::open(root.path(), "tenant-a").unwrap();
        let b = SqliteTenantDatabase::open(root.path(), "tenant-b").unwrap();
        a.connection().execute_batch("CREATE TABLE records(value TEXT); INSERT INTO records VALUES ('A-only');").unwrap();
        b.connection().execute_batch("CREATE TABLE records(value TEXT); INSERT INTO records VALUES ('B-only');").unwrap();
        let av: String = a.connection().query_row("SELECT value FROM records", [], |r| r.get(0)).unwrap();
        let bv: String = b.connection().query_row("SELECT value FROM records", [], |r| r.get(0)).unwrap();
        assert_eq!(av, "A-only"); assert_eq!(bv, "B-only"); assert_ne!(a.path(), b.path());
    }
    #[test]
    fn rejects_traversal_and_invalid_ids() {
        for id in ["", "../escape", "a/b", ".", "tenant with spaces"] {
            assert!(matches!(validate_tenant_id(id), Err(SqliteTenantError::InvalidTenantId)));
        }
        assert!(validate_tenant_id(&"x".repeat(65)).is_err());
    }
    #[cfg(unix)]
    #[test]
    fn rejects_symlinked_tenant_directory() {
        use std::os::unix::fs::symlink;
        let root = tempdir().unwrap(); let outside = tempdir().unwrap();
        symlink(outside.path(), root.path().join("tenant-a")).unwrap();
        assert!(matches!(SqliteTenantDatabase::open(root.path(), "tenant-a"), Err(SqliteTenantError::UnsafePath)));
    }
    #[cfg(unix)]
    #[test]
    fn storage_permissions_are_owner_only() {
        use std::os::unix::fs::PermissionsExt;
        let root = tempdir().unwrap(); let db = SqliteTenantDatabase::open(root.path(), "tenant-a").unwrap();
        assert_eq!(fs::metadata(db.path().parent().unwrap()).unwrap().permissions().mode() & 0o777, 0o700);
        assert_eq!(fs::metadata(db.path()).unwrap().permissions().mode() & 0o777, 0o600);
    }
}
