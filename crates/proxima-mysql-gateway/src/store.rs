//! Encrypted local registry for MySQL gateway accounts and tenant runtime secrets.
//!
//! The registry is a single-writer local store. It encrypts the complete
//! document with AES-256-GCM. The encryption key is supplied separately via a
//! protected key file and is never stored beside the encrypted registry.
use crate::auth::{
    AccountError, GatewayCredentialMaterial, TenantAccount, TenantAccountDirectory,
    TenantMigrationCredentialStore, TenantMigrationCredentials,
    TenantUpstreamCredentialStore, TenantUpstreamCredentials,
};
use crate::isolation::MySqlTenantIdentity;
use ring::{
    aead::{Aad, LessSafeKey, Nonce, UnboundKey, AES_256_GCM},
    rand::{SecureRandom, SystemRandom},
};
use serde::{Deserialize, Serialize};
use std::{
    fmt,
    fs::{self, File, OpenOptions},
    io::{Read, Write},
    path::{Path, PathBuf},
    sync::RwLock,
};
use uuid::Uuid;
use zeroize::{Zeroize, Zeroizing};
use zeroize::Zeroize;

const MAGIC: &[u8; 8] = b"APMYSQL1";
const AAD: &[u8] = b"agata-proxima-mysql-secret-store-v1";
const NONCE_LEN: usize = 12;
const MAX_STORE_BYTES: usize = 16 * 1024 * 1024;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StoreError {
    InvalidConfiguration,
    InsecureKeyPermissions,
    InvalidKey,
    CorruptStore,
    StoreUnavailable,
    DuplicateAccount,
    InvalidAccount,
    TenantAlreadyRegistered,
}

impl fmt::Display for StoreError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidConfiguration => write!(f, "invalid MySQL secret-store configuration"),
            Self::InsecureKeyPermissions => write!(f, "MySQL secret-store key file permissions are too broad"),
            Self::InvalidKey => write!(f, "MySQL secret-store key must contain exactly 32 bytes encoded as 64 hexadecimal characters"),
            Self::CorruptStore => write!(f, "MySQL encrypted secret store is invalid or cannot be authenticated"),
            Self::StoreUnavailable => write!(f, "MySQL encrypted secret store is unavailable"),
            Self::DuplicateAccount => write!(f, "MySQL gateway account already exists"),
            Self::InvalidAccount => write!(f, "invalid MySQL tenant account or runtime credential"),
            Self::TenantAlreadyRegistered => write!(f, "MySQL tenant already has runtime credentials registered"),
        }
    }
}
impl std::error::Error for StoreError {}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
struct StoreDocument {
    version: u32,
    accounts: Vec<StoredGatewayAccount>,
    upstream: Vec<StoredUpstreamCredential>,
    #[serde(default)]
    migration: Vec<StoredMigrationCredential>,
}

impl Drop for StoreDocument {
    fn drop(&mut self) {
        for account in &mut self.accounts {
            account.verifier_hex.zeroize();
        }
        for credential in &mut self.upstream {
            credential.password.zeroize();
        }
        for credential in &mut self.migration {
            credential.password.zeroize();
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct StoredGatewayAccount {
    username: String,
    tenant_id: String,
    verifier_hex: String,
    enabled: bool,
}
impl Drop for StoredGatewayAccount {
    fn drop(&mut self) {
        self.verifier_hex.zeroize();
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct StoredUpstreamCredential {
    tenant_id: String,
    username: String,
    password: String,
}
impl Drop for StoredUpstreamCredential {
    fn drop(&mut self) {
        self.password.zeroize();
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct StoredMigrationCredential {
    tenant_id: String,
    username: String,
    password: String,
}
impl Drop for StoredMigrationCredential {
    fn drop(&mut self) {
        self.password.zeroize();
    }
}

pub struct EncryptedTenantStore {
    path: PathBuf,
    key: [u8; 32],
    document: RwLock<StoreDocument>,
}

impl fmt::Debug for EncryptedTenantStore {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("EncryptedTenantStore")
            .field("path", &self.path)
            .field("key", &"[REDACTED]")
            .field("account_count", &self.document.read().map(|d| d.accounts.len()).unwrap_or(0))
            .field("tenant_credential_count", &self.document.read().map(|d| d.upstream.len()).unwrap_or(0))
            .field("migration_credential_count", &self.document.read().map(|d| d.migration.len()).unwrap_or(0))
            .finish()
    }
}

impl EncryptedTenantStore {
    /// Open or initialize the encrypted registry. The key file must contain
    /// exactly 64 hexadecimal characters. On Unix it must be owner-only (0600).
    /// On Windows, place it in a directory whose ACL grants access only to the
    /// gateway service identity and administrators.
    pub fn open(path: impl Into<PathBuf>, key_file: impl AsRef<Path>) -> Result<Self, StoreError> {
        let path = path.into();
        let key = load_key(key_file.as_ref())?;
        reject_symlink_if_present(&path)?;
        let document = if path.exists() {
            let encrypted = read_bounded(&path)?;
            decrypt_document(&key, &encrypted)?
        } else {
            StoreDocument { version: 1, ..StoreDocument::default() }
        };
        if document.version != 1 {
            return Err(StoreError::CorruptStore);
        }
        Ok(Self { path, key, document: RwLock::new(document) })
    }

    /// Refresh the in-memory snapshot from the atomically replaced encrypted
    /// file. Called at connection authorization boundaries so a gateway process
    /// observes provisioning and revocation performed by the admin CLI.
    pub fn reload_from_disk(&self) -> Result<(), StoreError> {
        reject_symlink_if_present(&self.path)?;
        let document = if self.path.exists() {
            let encrypted = read_bounded(&self.path)?;
            decrypt_document(&self.key, &encrypted)?
        } else {
            StoreDocument { version: 1, ..StoreDocument::default() }
        };
        if document.version != 1 {
            return Err(StoreError::CorruptStore);
        }
        let mut current = self.document.write().map_err(|_| StoreError::StoreUnavailable)?;
        *current = document;
        Ok(())
    }

    /// Register a new gateway account and its matching upstream runtime
    /// credential. The cleartext gateway password is returned exactly once;
    /// only its MySQL-compatible double-SHA256 verifier is persisted.
    pub fn register_tenant(
        &self,
        tenant_id: Uuid,
        gateway_username: &str,
        gateway_credential: GatewayCredentialMaterial,
        upstream_username: &str,
        upstream_password: &str,
        migration_username: &str,
        migration_password: &str,
    ) -> Result<String, StoreError> {
        self.reload_from_disk()?;
        validate_gateway_username(gateway_username)?;
        let identity = MySqlTenantIdentity::for_tenant(tenant_id);
        if upstream_username != identity.runtime_username
            || migration_username != identity.migration_username
            || !valid_password(upstream_password)
            || !valid_password(migration_password)
            || upstream_password == migration_password
        {
            return Err(StoreError::InvalidAccount);
        }
        let (gateway_password, verifier) = gateway_credential.into_parts();
        let gateway_password = Zeroizing::new(gateway_password);
        let verifier = Zeroizing::new(verifier);
        let verifier_hex = hex::encode(*verifier);
        let mut document = self.document.write().map_err(|_| StoreError::StoreUnavailable)?;
        if document.accounts.iter().any(|account| {
            account.username == gateway_username
                && (account.enabled || account.tenant_id != tenant_id.to_string())
        }) {
            return Err(StoreError::DuplicateAccount);
        }
        if document.upstream.iter().any(|entry| entry.tenant_id == tenant_id.to_string())
            || document.migration.iter().any(|entry| entry.tenant_id == tenant_id.to_string())
        {
            return Err(StoreError::TenantAlreadyRegistered);
        }
        let mut next = document.clone();
        if let Some(existing) = next.accounts.iter_mut()
            .find(|account| account.username == gateway_username)
        {
            // A previously revoked username may be reactivated only for the
            // same tenant and only with a freshly generated credential.
            if existing.tenant_id != tenant_id.to_string() || existing.enabled {
                return Err(StoreError::DuplicateAccount);
            }
            // A previously revoked username may be reactivated only with a
            // freshly generated credential for the same tenant.
            existing.verifier_hex = verifier_hex;
            existing.enabled = true;
        } else {
            next.accounts.push(StoredGatewayAccount {
                username: gateway_username.to_owned(),
                tenant_id: tenant_id.to_string(),
                verifier_hex,
                enabled: true,
            });
        }
        next.upstream.push(StoredUpstreamCredential {
            tenant_id: tenant_id.to_string(),
            username: upstream_username.to_owned(),
            password: upstream_password.to_owned(),
        });
        next.migration.push(StoredMigrationCredential {
            tenant_id: tenant_id.to_string(),
            username: migration_username.to_owned(),
            password: migration_password.to_owned(),
        });
        self.persist(&next)?;
        *document = next;
        Ok(gateway_password.to_string())
    }

    /// Rotate all three credentials atomically in the encrypted local registry.
    /// The gateway password is returned once; only its verifier is persisted.
    pub fn rotate_tenant_credentials(
        &self,
        tenant_id: Uuid,
        gateway_username: &str,
        gateway_credential: GatewayCredentialMaterial,
        runtime_username: &str,
        runtime_password: &str,
        migration_username: &str,
        migration_password: &str,
    ) -> Result<String, StoreError> {
        self.reload_from_disk()?;
        validate_gateway_username(gateway_username)?;
        let identity = MySqlTenantIdentity::for_tenant(tenant_id);
        if runtime_username != identity.runtime_username
            || migration_username != identity.migration_username
            || !valid_password(runtime_password)
            || !valid_password(migration_password)
            || runtime_password == migration_password
        {
            return Err(StoreError::InvalidAccount);
        }
        let (gateway_password, verifier) = gateway_credential.into_parts();
        let gateway_password = Zeroizing::new(gateway_password);
        let verifier = Zeroizing::new(verifier);
        let mut document = self.document.write().map_err(|_| StoreError::StoreUnavailable)?;
        let mut next = document.clone();
        let account = next.accounts.iter_mut()
            .find(|account| account.username == gateway_username
                && account.tenant_id == tenant_id.to_string()
                && account.enabled)
            .ok_or(StoreError::InvalidAccount)?;
        account.verifier_hex = hex::encode(*verifier);
        let runtime = next.upstream.iter_mut()
            .find(|entry| entry.tenant_id == tenant_id.to_string())
            .ok_or(StoreError::InvalidAccount)?;
        runtime.username = runtime_username.to_owned();
        runtime.password = runtime_password.to_owned();
        let migration = next.migration.iter_mut()
            .find(|entry| entry.tenant_id == tenant_id.to_string())
            .ok_or(StoreError::InvalidAccount)?;
        migration.username = migration_username.to_owned();
        migration.password = migration_password.to_owned();
        self.persist(&next)?;
        *document = next;
        Ok(std::mem::take(&mut *gateway_password))
    }

    /// Disable every gateway account for a tenant and remove its upstream
    /// runtime credential. Existing sessions are not force-closed by this
    /// operation; callers must drain/terminate them separately.
    pub fn revoke_tenant(&self, tenant_id: Uuid) -> Result<(), StoreError> {
        self.reload_from_disk()?;
        let mut document = self.document.write().map_err(|_| StoreError::StoreUnavailable)?;
        let mut next = document.clone();
        for account in &mut next.accounts {
            if account.tenant_id == tenant_id.to_string() {
                account.enabled = false;
            }
        }
        next.upstream.retain(|entry| entry.tenant_id != tenant_id.to_string());
        next.migration.retain(|entry| entry.tenant_id != tenant_id.to_string());
        self.persist(&next)?;
        *document = next;
        Ok(())
    }

    /// Rotate a gateway login credential. The replacement is returned once.
    pub fn rotate_gateway_credential(
        &self,
        username: &str,
        credential: GatewayCredentialMaterial,
    ) -> Result<String, StoreError> {
        self.reload_from_disk()?;
        validate_gateway_username(username)?;
        let (password, verifier) = credential.into_parts();
        let password = Zeroizing::new(password);
        let verifier = Zeroizing::new(verifier);
        let mut document = self.document.write().map_err(|_| StoreError::StoreUnavailable)?;
        let mut next = document.clone();
        let account = next.accounts.iter_mut()
            .find(|account| account.username == username && account.enabled)
            .ok_or(StoreError::InvalidAccount)?;
        account.verifier_hex = hex::encode(*verifier);
        self.persist(&next)?;
        *document = next;
        Ok(std::mem::take(&mut *password))
    }

    /// Rotate the tenant's upstream MySQL runtime password. The gateway
    /// account verifier is intentionally unaffected.
    pub fn rotate_upstream_password(
        &self,
        tenant_id: Uuid,
        password: &str,
    ) -> Result<(), StoreError> {
        self.reload_from_disk()?;
        if !valid_password(password) {
            return Err(StoreError::InvalidAccount);
        }
        let mut document = self.document.write().map_err(|_| StoreError::StoreUnavailable)?;
        let mut next = document.clone();
        let entry = next.upstream.iter_mut()
            .find(|entry| entry.tenant_id == tenant_id.to_string())
            .ok_or(StoreError::InvalidAccount)?;
        entry.password = password.to_owned();
        self.persist(&next)?;
        *document = next;
        Ok(())
    }

    pub fn rotate_migration_password(
        &self,
        tenant_id: Uuid,
        password: &str,
    ) -> Result<(), StoreError> {
        self.reload_from_disk()?;
        if !valid_password(password) {
            return Err(StoreError::InvalidAccount);
        }
        let mut document = self.document.write().map_err(|_| StoreError::StoreUnavailable)?;
        let mut next = document.clone();
        let entry = next.migration.iter_mut()
            .find(|entry| entry.tenant_id == tenant_id.to_string())
            .ok_or(StoreError::InvalidAccount)?;
        entry.password = password.to_owned();
        self.persist(&next)?;
        *document = next;
        Ok(())
    }

    fn persist(&self, document: &StoreDocument) -> Result<(), StoreError> {
        let encrypted = encrypt_document(&self.key, document)?;
        let parent = self.path.parent()
            .filter(|path| !path.as_os_str().is_empty())
            .unwrap_or_else(|| Path::new("."));
        fs::create_dir_all(parent).map_err(|_| StoreError::StoreUnavailable)?;
        reject_symlink_if_present(&self.path)?;
        let mut random = [0u8; 8];
        SystemRandom::new().fill(&mut random).map_err(|_| StoreError::StoreUnavailable)?;
        let temp_path = self.path.with_extension(format!("tmp-{}", hex::encode(random)));
        let mut options = OpenOptions::new();
        options.write(true).create_new(true);
        set_private_file_mode(&mut options);
        let mut file = options.open(&temp_path).map_err(|_| StoreError::StoreUnavailable)?;
        let write_result = (|| {
            file.write_all(&encrypted)?;
            file.sync_all()?;
            drop(file);
            fs::rename(&temp_path, &self.path)?;
            if let Ok(directory) = File::open(parent) {
                let _ = directory.sync_all();
            }
            Ok::<(), std::io::Error>(())
        })();
        if write_result.is_err() {
            let _ = fs::remove_file(&temp_path);
            return Err(StoreError::StoreUnavailable);
        }
        Ok(())
    }
}

impl Drop for EncryptedTenantStore {
    fn drop(&mut self) {
        use zeroize::Zeroize;
        self.key.zeroize();
    }
}

impl TenantAccountDirectory for EncryptedTenantStore {
    fn find_account(&self, username: &str) -> Result<Option<TenantAccount>, AccountError> {
        self.reload_from_disk().map_err(|_| AccountError::DirectoryUnavailable)?;
        let document = self.document.read().map_err(|_| AccountError::DirectoryUnavailable)?;
        let Some(account) = document.accounts.iter()
            .find(|account| account.username == username && account.enabled)
        else {
            return Ok(None);
        };
        let tenant_id = Uuid::parse_str(&account.tenant_id)
            .map_err(|_| AccountError::DirectoryUnavailable)?;
        let verifier = hex::decode(&account.verifier_hex)
            .map_err(|_| AccountError::DirectoryUnavailable)?;
        let verifier: [u8; 32] = verifier.try_into()
            .map_err(|_| AccountError::DirectoryUnavailable)?;
        Ok(Some(TenantAccount::from_verifier(
            account.username.clone(), tenant_id, verifier
        )))
    }
}

impl TenantUpstreamCredentialStore for EncryptedTenantStore {
    fn load_runtime_credentials(&self, tenant_id: Uuid) -> Result<Option<TenantUpstreamCredentials>, AccountError> {
        self.reload_from_disk().map_err(|_| AccountError::DirectoryUnavailable)?;
        let document = self.document.read().map_err(|_| AccountError::DirectoryUnavailable)?;
        let Some(entry) = document.upstream.iter()
            .find(|entry| entry.tenant_id == tenant_id.to_string())
        else {
            return Ok(None);
        };
        Ok(Some(TenantUpstreamCredentials {
            tenant_id,
            username: entry.username.clone(),
            password: entry.password.clone(),
        }))
    }
}

impl TenantMigrationCredentialStore for EncryptedTenantStore {
    fn load_migration_credentials(&self, tenant_id: Uuid) -> Result<Option<TenantMigrationCredentials>, AccountError> {
        self.reload_from_disk().map_err(|_| AccountError::DirectoryUnavailable)?;
        let document = self.document.read().map_err(|_| AccountError::DirectoryUnavailable)?;
        let Some(entry) = document.migration.iter()
            .find(|entry| entry.tenant_id == tenant_id.to_string())
        else {
            return Ok(None);
        };
        Ok(Some(TenantMigrationCredentials {
            tenant_id,
            username: entry.username.clone(),
            password: entry.password.clone(),
        }))
    }
}

fn load_key(path: &Path) -> Result<[u8; 32], StoreError> {
    reject_symlink_if_present(path)?;
    let metadata = fs::metadata(path).map_err(|_| StoreError::StoreUnavailable)?;
    if !metadata.is_file() {
        return Err(StoreError::InvalidConfiguration);
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if metadata.permissions().mode() & 0o077 != 0 {
            return Err(StoreError::InsecureKeyPermissions);
        }
    }
    let mut encoded = String::new();
    if File::open(path)
        .and_then(|mut file| file.read_to_string(&mut encoded))
        .is_err()
    {
        encoded.zeroize();
        return Err(StoreError::StoreUnavailable);
    }
    let mut trimmed = encoded.trim().to_owned();
    encoded.zeroize();
    if trimmed.len() != 64 || !trimmed.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        trimmed.zeroize();
        return Err(StoreError::InvalidKey);
    }
    let decoded = hex::decode(&trimmed);
    trimmed.zeroize();
    let mut bytes = decoded.map_err(|_| StoreError::InvalidKey)?;
    let key: [u8; 32] = match bytes.as_slice().try_into() {
        Ok(key) => key,
        Err(_) => {
            bytes.zeroize();
            return Err(StoreError::InvalidKey);
        }
    };
    bytes.zeroize();
    Ok(key)
}

fn read_bounded(path: &Path) -> Result<Vec<u8>, StoreError> {
    let metadata = fs::metadata(path).map_err(|_| StoreError::StoreUnavailable)?;
    if !metadata.is_file() || metadata.len() as usize > MAX_STORE_BYTES {
        return Err(StoreError::CorruptStore);
    }
    let mut file = File::open(path).map_err(|_| StoreError::StoreUnavailable)?;
    let mut bytes = Vec::with_capacity(metadata.len() as usize);
    file.take((MAX_STORE_BYTES + 1) as u64)
        .read_to_end(&mut bytes)
        .map_err(|_| StoreError::StoreUnavailable)?;
    if bytes.len() > MAX_STORE_BYTES {
        return Err(StoreError::CorruptStore);
    }
    Ok(bytes)
}

fn encrypt_document(key: &[u8; 32], document: &StoreDocument) -> Result<Vec<u8>, StoreError> {
    let mut plaintext = serde_json::to_vec(document).map_err(|_| StoreError::StoreUnavailable)?;
    if plaintext.len() > MAX_STORE_BYTES {
        return Err(StoreError::StoreUnavailable);
    }
    let mut nonce_bytes = [0u8; NONCE_LEN];
    SystemRandom::new().fill(&mut nonce_bytes).map_err(|_| StoreError::StoreUnavailable)?;
    let unbound = UnboundKey::new(&AES_256_GCM, key).map_err(|_| StoreError::InvalidKey)?;
    let cipher = LessSafeKey::new(unbound);
    let nonce = Nonce::assume_unique_for_key(nonce_bytes);
    cipher.seal_in_place_append_tag(nonce, Aad::from(AAD), &mut plaintext)
        .map_err(|_| StoreError::StoreUnavailable)?;
    let mut output = Vec::with_capacity(MAGIC.len() + NONCE_LEN + plaintext.len());
    output.extend_from_slice(MAGIC);
    output.extend_from_slice(&nonce_bytes);
    output.extend_from_slice(&plaintext);
    Ok(output)
}

fn decrypt_document(key: &[u8; 32], encrypted: &[u8]) -> Result<StoreDocument, StoreError> {
    if encrypted.len() < MAGIC.len() + NONCE_LEN + 16
        || encrypted.len() > MAX_STORE_BYTES + MAGIC.len() + NONCE_LEN + 16
        || &encrypted[..MAGIC.len()] != MAGIC
    {
        return Err(StoreError::CorruptStore);
    }
    let nonce_bytes: [u8; NONCE_LEN] = encrypted[MAGIC.len()..MAGIC.len() + NONCE_LEN]
        .try_into().map_err(|_| StoreError::CorruptStore)?;
    let mut ciphertext = encrypted[MAGIC.len() + NONCE_LEN..].to_vec();
    let unbound = UnboundKey::new(&AES_256_GCM, key).map_err(|_| StoreError::InvalidKey)?;
    let cipher = LessSafeKey::new(unbound);
    let nonce = Nonce::assume_unique_for_key(nonce_bytes);
    let plaintext = cipher.open_in_place(nonce, Aad::from(AAD), &mut ciphertext)
        .map_err(|_| StoreError::CorruptStore)?;
    let parsed = serde_json::from_slice(plaintext);
    ciphertext.zeroize();
    let document: StoreDocument = parsed.map_err(|_| StoreError::CorruptStore)?;
    Ok(document)
}

fn reject_symlink_if_present(path: &Path) -> Result<(), StoreError> {
    match fs::symlink_metadata(path) {
        Ok(metadata) if metadata.file_type().is_symlink() => Err(StoreError::InvalidConfiguration),
        Ok(_) => Ok(()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(_) => Err(StoreError::StoreUnavailable),
    }
}

fn set_private_file_mode(options: &mut OpenOptions) {
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
}

fn validate_gateway_username(username: &str) -> Result<(), StoreError> {
    if username.is_empty() || username.len() > 32
        || !username.bytes().all(|byte| byte.is_ascii_alphanumeric() || byte == b'_')
    {
        return Err(StoreError::InvalidAccount);
    }
    Ok(())
}

fn valid_password(password: &str) -> bool {
    password.len() == 64 && password.bytes().all(|byte| byte.is_ascii_hexdigit())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::auth::{generate_gateway_credential, TenantAccountDirectory, TenantUpstreamCredentialStore};
    use tempfile::tempdir;

    fn test_store() -> (tempfile::TempDir, EncryptedTenantStore) {
        let dir = tempdir().unwrap();
        let key_path = dir.path().join("key.hex");
        let key = "ab".repeat(32);
        fs::write(&key_path, &key).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&key_path, fs::Permissions::from_mode(0o600)).unwrap();
        }
        let store = EncryptedTenantStore::open(dir.path().join("tenants.enc"), &key_path).unwrap();
        (dir, store)
    }

    #[test]
    fn registry_persists_encrypted_credentials_and_reopens() {
        let (dir, store) = test_store();
        let tenant = Uuid::new_v4();
        let gateway = generate_gateway_credential().unwrap();
        let gateway_password = gateway.password().to_owned();
        let identity = MySqlTenantIdentity::for_tenant(tenant);
        let runtime_password = "c".repeat(64);
        store.register_tenant(
            tenant, "gateway_a", gateway, &identity.runtime_username, &runtime_password, &identity.migration_username, &"d".repeat(64)
        ).unwrap();

        let encrypted = fs::read(dir.path().join("tenants.enc")).unwrap();
        assert!(!String::from_utf8_lossy(&encrypted).contains(&gateway_password));
        assert!(!String::from_utf8_lossy(&encrypted).contains(&runtime_password));

        let key_path = dir.path().join("key.hex");
        let reopened = EncryptedTenantStore::open(dir.path().join("tenants.enc"), key_path).unwrap();
        let account = reopened.find_account("gateway_a").unwrap().unwrap();
        assert_eq!(account.tenant_id, tenant);
        let upstream = reopened.load_runtime_credentials(tenant).unwrap().unwrap();
        assert_eq!(upstream.password, runtime_password);
        let migration = reopened.load_migration_credentials(tenant).unwrap().unwrap();
        assert_eq!(migration.username, MySqlTenantIdentity::for_tenant(tenant).migration_username);
        assert_eq!(migration.password, "d".repeat(64));
    }

    #[test]
    fn encrypted_registry_authenticates_gateway_password_with_mysql_scramble() {
        use crate::auth::{authenticate, CACHING_SHA2_PASSWORD};
        use sha2::Digest;
        use crate::protocol::{ClientHandshake, CLIENT_CONNECT_ATTRS, CLIENT_PLUGIN_AUTH, CLIENT_PROTOCOL_41, CLIENT_SECURE_CONNECTION};

        let (_dir, store) = test_store();
        let tenant = Uuid::new_v4();
        let gateway = generate_gateway_credential().unwrap();
        let identity = MySqlTenantIdentity::for_tenant(tenant);
        let gateway_password = store.register_tenant(
            tenant, "gateway_auth_test", gateway, &identity.runtime_username, &"9".repeat(64), &identity.migration_username, &"8".repeat(64)
        ).unwrap();

        let challenge = [0x5au8; 20];
        let first = sha2::Sha256::digest(gateway_password.as_bytes());
        let second = sha2::Sha256::digest(first);
        let mut material = Vec::new();
        material.extend_from_slice(&second);
        material.extend_from_slice(&challenge);
        let mask = sha2::Sha256::digest(material);
        let response = first.iter().zip(mask.iter()).map(|(left, right)| left ^ right).collect();

        let handshake = ClientHandshake {
            capability_flags: CLIENT_PROTOCOL_41 | CLIENT_SECURE_CONNECTION | CLIENT_PLUGIN_AUTH | CLIENT_CONNECT_ATTRS,
            max_packet_size: 4096,
            character_set: 45,
            username: "gateway_auth_test".into(),
            auth_response: response,
            requested_database: None,
            auth_plugin_name: Some(CACHING_SHA2_PASSWORD.into()),
            connection_attributes: Vec::new(),
        };
        assert_eq!(authenticate(&handshake, &challenge, true, &store), Ok(tenant));
        let mut invalid = handshake;
        invalid.auth_response[0] ^= 1;
        assert!(authenticate(&invalid, &challenge, true, &store).is_err());
    }

    #[test]
    fn rotates_gateway_runtime_and_migration_credentials_atomically() {
        let (_dir, store) = test_store();
        let tenant = Uuid::new_v4();
        let identity = MySqlTenantIdentity::for_tenant(tenant);
        let initial = generate_gateway_credential().unwrap();
        store.register_tenant(
            tenant,
            "gateway_rotate",
            initial,
            &identity.runtime_username,
            &"a".repeat(64),
            &identity.migration_username,
            &"b".repeat(64),
        ).unwrap();

        let new_gateway = generate_gateway_credential().unwrap();
        let new_gateway_password = store.rotate_tenant_credentials(
            tenant,
            "gateway_rotate",
            new_gateway,
            &identity.runtime_username,
            &"c".repeat(64),
            &identity.migration_username,
            &"d".repeat(64),
        ).unwrap();

        let runtime = store.load_runtime_credentials(tenant).unwrap().unwrap();
        let migration = store.load_migration_credentials(tenant).unwrap().unwrap();
        assert_eq!(runtime.password, "c".repeat(64));
        assert_eq!(migration.password, "d".repeat(64));
        let account = store.find_account("gateway_rotate").unwrap().unwrap();
        assert_eq!(account.tenant_id, tenant);
        assert_eq!(new_gateway_password.len(), 64);
    }

    #[test]
    fn running_gateway_store_observes_external_provisioning_and_revocation() {
        let dir = tempdir().unwrap();
        let key_path = dir.path().join("key.hex");
        fs::write(&key_path, "cd".repeat(32)).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&key_path, fs::Permissions::from_mode(0o600)).unwrap();
        }
        let store_path = dir.path().join("tenants.enc");
        let gateway_view = EncryptedTenantStore::open(&store_path, &key_path).unwrap();
        let admin_view = EncryptedTenantStore::open(&store_path, &key_path).unwrap();

        let tenant = Uuid::new_v4();
        let identity = MySqlTenantIdentity::for_tenant(tenant);
        admin_view.register_tenant(
            tenant,
            "gateway_live_reload",
            generate_gateway_credential().unwrap(),
            &identity.runtime_username,
            &"1".repeat(64),
            &identity.migration_username,
            &"2".repeat(64),
        ).unwrap();

        assert!(gateway_view.find_account("gateway_live_reload").unwrap().is_some());
        admin_view.revoke_tenant(tenant).unwrap();
        assert!(gateway_view.find_account("gateway_live_reload").unwrap().is_none());
        assert!(gateway_view.load_runtime_credentials(tenant).unwrap().is_none());
    }

    #[test]
    fn tampered_or_wrong_key_store_fails_closed() {
        let (dir, store) = test_store();
        let tenant = Uuid::new_v4();
        let gateway = generate_gateway_credential().unwrap();
        let identity = MySqlTenantIdentity::for_tenant(tenant);
        store.register_tenant(tenant, "gateway_b", gateway, &identity.runtime_username, &"d".repeat(64), &identity.migration_username, &"e".repeat(64)).unwrap();
        drop(store);

        let path = dir.path().join("tenants.enc");
        let mut bytes = fs::read(&path).unwrap();
        let last = bytes.len() - 1;
        bytes[last] ^= 0x80;
        fs::write(&path, bytes).unwrap();
        assert!(matches!(
            EncryptedTenantStore::open(&path, dir.path().join("key.hex")),
            Err(StoreError::CorruptStore)
        ));
    }

    #[test]
    fn revoked_tenant_is_not_authenticatable_and_has_no_upstream_secret() {
        let (_dir, store) = test_store();
        let tenant = Uuid::new_v4();
        let gateway = generate_gateway_credential().unwrap();
        let identity = MySqlTenantIdentity::for_tenant(tenant);
        store.register_tenant(tenant, "gateway_c", gateway, &identity.runtime_username, &"e".repeat(64), &identity.migration_username, &"f".repeat(64)).unwrap();
        store.revoke_tenant(tenant).unwrap();
        assert!(store.find_account("gateway_c").unwrap().is_none());
        assert!(store.load_runtime_credentials(tenant).unwrap().is_none());
        assert!(store.load_migration_credentials(tenant).unwrap().is_none());

        let replacement = generate_gateway_credential().unwrap();
        let replacement_password = store.register_tenant(
            tenant,
            "gateway_c",
            replacement,
            &identity.runtime_username,
            &"7".repeat(64),
            &identity.migration_username,
            &"8".repeat(64),
        ).unwrap();
        assert_eq!(replacement_password.len(), 64);
        assert!(store.find_account("gateway_c").unwrap().is_some());
        assert!(store.load_runtime_credentials(tenant).unwrap().is_some());
    }

    #[test]
    fn rejects_insecure_key_permissions_and_bad_account_names() {
        let dir = tempdir().unwrap();
        let key_path = dir.path().join("key.hex");
        fs::write(&key_path, "ab".repeat(32)).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&key_path, fs::Permissions::from_mode(0o644)).unwrap();
            assert_eq!(
                EncryptedTenantStore::open(dir.path().join("store.enc"), &key_path).err(),
                Some(StoreError::InsecureKeyPermissions)
            );
        }
        let (_dir, store) = test_store();
        assert_eq!(
            store.register_tenant(
                Uuid::new_v4(),
                "invalid username",
                generate_gateway_credential().unwrap(),
                "invalid",
                &"f".repeat(64),
                "invalid_migrator",
                &"g".repeat(64)
            ).err(),
            Some(StoreError::InvalidAccount)
        );
    }
}
