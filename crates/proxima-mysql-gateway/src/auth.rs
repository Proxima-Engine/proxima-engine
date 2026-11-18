//! TLS-required MySQL caching_sha2_password gateway-account authentication.
//!
//! The account directory stores SHA256(SHA256(password)) verifier material,
//! never plaintext passwords. This module authenticates the gateway account;
//! tenant assertion validation remains a separate mandatory authorization step.
use crate::protocol::ClientHandshake;
use sha2::{Digest, Sha256};
use crate::isolation::MySqlTenantIdentity;
use std::fmt;
use subtle::ConstantTimeEq;
use ring::rand::{SecureRandom, SystemRandom};
use uuid::Uuid;
use zeroize::Zeroize;

pub const CACHING_SHA2_PASSWORD: &str = "caching_sha2_password";

#[derive(Clone, PartialEq, Eq)]
pub struct TenantAccount {
    pub username: String,
    pub tenant_id: Uuid,
    password_verifier: [u8; 32],
}
impl TenantAccount {
    pub fn from_verifier(username: String, tenant_id: Uuid, password_verifier: [u8; 32]) -> Self {
        Self { username, tenant_id, password_verifier }
    }
}
impl Drop for TenantAccount {
    fn drop(&mut self) {
        self.password_verifier.zeroize();
    }
}
impl fmt::Debug for TenantAccount {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("TenantAccount")
            .field("username", &self.username)
            .field("tenant_id", &self.tenant_id)
            .field("password_verifier", &"[REDACTED]")
            .finish()
    }
}

pub trait TenantAccountDirectory: Send + Sync {
    fn find_account(&self, username: &str) -> Result<Option<TenantAccount>, AccountError>;
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AccountError {
    TlsRequired,
    UnsupportedAuthenticationPlugin,
    InvalidAuthenticationResponse,
    UnknownAccount,
    DirectoryUnavailable,
    RandomSourceUnavailable,
}
impl fmt::Display for AccountError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::TlsRequired => write!(f, "MySQL gateway authentication requires TLS"),
            Self::UnsupportedAuthenticationPlugin => write!(f, "unsupported MySQL authentication plugin"),
            Self::InvalidAuthenticationResponse => write!(f, "invalid MySQL gateway credentials"),
            Self::UnknownAccount => write!(f, "invalid MySQL gateway credentials"),
            Self::DirectoryUnavailable => write!(f, "MySQL tenant account directory is unavailable"),
            Self::RandomSourceUnavailable => write!(f, "operating-system random source is unavailable"),
        }
    }
}
impl std::error::Error for AccountError {}

/// Verify a caching_sha2_password response for a 20-byte server challenge.
/// The caller must use a cryptographically secure random challenge for each
/// connection and must not reuse it.
pub fn authenticate<D: TenantAccountDirectory + ?Sized>(
    handshake: &ClientHandshake,
    challenge: &[u8; 20],
    tls_active: bool,
    directory: &D,
) -> Result<Uuid, AccountError> {
    if !tls_active { return Err(AccountError::TlsRequired); }
    if handshake.auth_plugin_name.as_deref() != Some(CACHING_SHA2_PASSWORD) {
        return Err(AccountError::UnsupportedAuthenticationPlugin);
    }
    if handshake.username.is_empty()
        || handshake.username.len() > 32
        || !handshake.username.bytes().all(|byte| byte.is_ascii_alphanumeric() || byte == b'_')
        || handshake.auth_response.len() != 32
    {
        return Err(AccountError::InvalidAuthenticationResponse);
    }
    let account = directory
        .find_account(&handshake.username)?
        .ok_or(AccountError::UnknownAccount)?;

    if account.username != handshake.username {
        return Err(AccountError::InvalidAuthenticationResponse);
    }

    let mut material = Vec::with_capacity(52);
    material.extend_from_slice(&account.password_verifier);
    material.extend_from_slice(challenge);
    let mask = Sha256::digest(&material);
    let mut recovered_stage_one = [0u8; 32];
    for index in 0..32 {
        recovered_stage_one[index] = handshake.auth_response[index] ^ mask[index];
    }
    let candidate_verifier = Sha256::digest(recovered_stage_one);
    if candidate_verifier[..].ct_eq(&account.password_verifier[..]).unwrap_u8() != 1 {
        return Err(AccountError::InvalidAuthenticationResponse);
    }
    Ok(account.tenant_id)
}



#[derive(Clone, PartialEq, Eq)]
pub struct TenantUpstreamCredentials {
    pub tenant_id: Uuid,
    pub username: String,
    pub password: String,
}
impl fmt::Debug for TenantUpstreamCredentials {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("TenantUpstreamCredentials")
            .field("tenant_id", &self.tenant_id)
            .field("username", &self.username)
            .field("password", &"[REDACTED]")
            .finish()
    }
}
impl Drop for TenantUpstreamCredentials {
    fn drop(&mut self) {
        self.password.zeroize();
    }
}

pub trait TenantUpstreamCredentialStore: Send + Sync {
    fn load_runtime_credentials(&self, tenant_id: Uuid) -> Result<Option<TenantUpstreamCredentials>, AccountError>;
}

#[derive(Clone, PartialEq, Eq)]
pub struct TenantMigrationCredentials {
    pub tenant_id: Uuid,
    pub username: String,
    pub password: String,
}
impl fmt::Debug for TenantMigrationCredentials {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("TenantMigrationCredentials")
            .field("tenant_id", &self.tenant_id)
            .field("username", &self.username)
            .field("password", &"[REDACTED]")
            .finish()
    }
}
impl Drop for TenantMigrationCredentials {
    fn drop(&mut self) {
        self.password.zeroize();
    }
}

pub trait TenantMigrationCredentialStore: Send + Sync {
    fn load_migration_credentials(&self, tenant_id: Uuid) -> Result<Option<TenantMigrationCredentials>, AccountError>;
}

#[derive(Clone, PartialEq, Eq)]
pub struct AuthenticatedTenantSession {
    pub tenant_id: Uuid,
    pub database_name: String,
    pub upstream_username: String,
    pub upstream_password: String,
}
impl fmt::Debug for AuthenticatedTenantSession {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("AuthenticatedTenantSession")
            .field("tenant_id", &self.tenant_id)
            .field("database_name", &self.database_name)
            .field("upstream_username", &self.upstream_username)
            .field("upstream_password", &"[REDACTED]")
            .finish()
    }
}
impl Drop for AuthenticatedTenantSession {
    fn drop(&mut self) {
        self.upstream_password.zeroize();
    }
}

/// Complete the identity-to-upstream-credential binding. The caller must invoke
/// this before opening a database connection and must keep the returned session
/// immutable for the entire client connection lifetime.
pub fn authenticate_and_resolve<
    D: TenantAccountDirectory + ?Sized,
    C: TenantUpstreamCredentialStore + ?Sized,
>(
    handshake: &ClientHandshake,
    challenge: &[u8; 20],
    client_tls_active: bool,
    account_directory: &D,
    assertion_key: &[u8],
    now: u64,
    credential_store: &C,
) -> Result<AuthenticatedTenantSession, AccountError> {
    let tenant_id = authenticate(handshake, challenge, client_tls_active, account_directory)?;
    let route = crate::tenant::authorize_handshake(handshake, tenant_id, assertion_key, now)
        .map_err(|_| AccountError::InvalidAuthenticationResponse)?;
    let mut credentials = credential_store
        .load_runtime_credentials(tenant_id)?
        .ok_or(AccountError::DirectoryUnavailable)?;
    if credentials.tenant_id != tenant_id
        || credentials.username != expected_runtime_username(tenant_id)
        || credentials.password.is_empty()
        || credentials.password.len() != 64
        || !credentials.password.bytes().all(|byte| byte.is_ascii_hexdigit())
    {
        return Err(AccountError::DirectoryUnavailable);
    }
    Ok(AuthenticatedTenantSession {
        tenant_id,
        database_name: route.database_name,
        upstream_username: std::mem::take(&mut credentials.username),
        upstream_password: std::mem::take(&mut credentials.password),
    })
}

fn expected_runtime_username(tenant_id: Uuid) -> String {
    MySqlTenantIdentity::for_tenant(tenant_id).runtime_username
}



/// One-time high-entropy gateway credential material. The cleartext password
/// is returned to the trusted provisioning caller once; only the verifier
/// should be persisted in the gateway account directory.
pub struct GatewayCredentialMaterial {
    password: String,
    verifier: [u8; 32],
}
impl GatewayCredentialMaterial {
    pub fn password(&self) -> &str { &self.password }
    pub fn verifier(&self) -> [u8; 32] { self.verifier }

    /// Consume the one-time credential material. Persist only the verifier.
    pub fn into_parts(mut self) -> (String, [u8; 32]) {
        let password = std::mem::take(&mut self.password);
        let verifier = std::mem::replace(&mut self.verifier, [0u8; 32]);
        (password, verifier)
    }
}
impl Drop for GatewayCredentialMaterial {
    fn drop(&mut self) {
        self.password.zeroize();
        self.verifier.zeroize();
    }
}
impl fmt::Debug for GatewayCredentialMaterial {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("GatewayCredentialMaterial")
            .field("password", &"[REDACTED]")
            .field("verifier", &"[REDACTED]")
            .finish()
    }
}

pub fn generate_gateway_credential() -> Result<GatewayCredentialMaterial, AccountError> {
    let mut random = [0u8; 32];
    SystemRandom::new()
        .fill(&mut random)
        .map_err(|_| AccountError::RandomSourceUnavailable)?;
    let password = hex::encode(random);
    let first = Sha256::digest(password.as_bytes());
    let verifier = Sha256::digest(first).into();
    Ok(GatewayCredentialMaterial { password, verifier })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::protocol::{CLIENT_CONNECT_ATTRS, CLIENT_PROTOCOL_41, CLIENT_SECURE_CONNECTION};
    use std::collections::HashMap;

    struct MemoryDirectory(HashMap<String, TenantAccount>);
    impl TenantAccountDirectory for MemoryDirectory {
        fn find_account(&self, username: &str) -> Result<Option<TenantAccount>, AccountError> {
            Ok(self.0.get(username).cloned())
        }
    }

    fn password_verifier(password: &[u8]) -> [u8; 32] {
        let first = Sha256::digest(password);
        Sha256::digest(first).into()
    }
    fn response(password: &[u8], challenge: &[u8; 20]) -> Vec<u8> {
        let first = Sha256::digest(password);
        let second = Sha256::digest(first);
        let mut material = Vec::new();
        material.extend_from_slice(&second);
        material.extend_from_slice(challenge);
        let mask = Sha256::digest(material);
        first.iter().zip(mask.iter()).map(|(a, b)| a ^ b).collect()
    }
    fn test_handshake(user: &str, auth: Vec<u8>) -> ClientHandshake {
        ClientHandshake {
            capability_flags: CLIENT_PROTOCOL_41 | CLIENT_SECURE_CONNECTION | CLIENT_CONNECT_ATTRS,
            max_packet_size: 1024,
            character_set: 45,
            username: user.into(),
            auth_response: auth,
            requested_database: None,
            auth_plugin_name: Some(CACHING_SHA2_PASSWORD.into()),
            connection_attributes: vec![],
        }
    }


    #[test]
    fn generated_gateway_credentials_are_high_entropy_and_debug_redacted() {
        let first = generate_gateway_credential().unwrap();
        let second = generate_gateway_credential().unwrap();
        assert_eq!(first.password().len(), 64);
        assert_ne!(first.password(), second.password());
        let debug = format!("{first:?}");
        assert!(!debug.contains(first.password()));
        assert!(debug.contains("REDACTED"));
    }


    struct MemoryCredentialStore(TenantUpstreamCredentials);
    impl TenantUpstreamCredentialStore for MemoryCredentialStore {
        fn load_runtime_credentials(&self, tenant_id: Uuid) -> Result<Option<TenantUpstreamCredentials>, AccountError> {
            if self.0.tenant_id == tenant_id { Ok(Some(self.0.clone())) } else { Ok(None) }
        }
    }

    #[test]
    fn authenticated_gateway_account_and_assertion_resolve_exact_upstream_tenant() {
        let tenant = Uuid::new_v4();
        let gateway_password = b"gateway-password-test";
        let challenge = [5u8; 20];
        let account = TenantAccount::from_verifier(
            "gateway_a".into(), tenant, password_verifier(gateway_password)
        );
        let directory = MemoryDirectory(HashMap::from([("gateway_a".into(), account)]));
        let runtime_name = expected_runtime_username(tenant);
        let store = MemoryCredentialStore(TenantUpstreamCredentials {
            tenant_id: tenant,
            username: runtime_name.clone(),
            password: "a".repeat(64),
        });
        let assertion = crate::tenant::TenantAssertion::issue(
            tenant, 500, b"0123456789abcdef0123456789abcdef"
        ).unwrap();
        let mut handshake = test_handshake("gateway_a", response(gateway_password, &challenge));
        handshake.connection_attributes.push((
            crate::tenant::TENANT_ASSERTION_ATTRIBUTE.into(), assertion
        ));
        let session = authenticate_and_resolve(
            &handshake, &challenge, true, &directory,
            b"0123456789abcdef0123456789abcdef", 100, &store
        ).unwrap();
        assert_eq!(session.tenant_id, tenant);
        assert_eq!(session.upstream_username, runtime_name);
        assert_eq!(session.database_name, format!("ap_t_{}", tenant.simple()));
        assert!(!format!("{session:?}").contains(&session.upstream_password));
    }

    #[test]
    fn rejects_upstream_credentials_for_another_tenant_or_unexpected_account() {
        let tenant = Uuid::new_v4();
        let gateway_password = b"gateway-password-test";
        let challenge = [6u8; 20];
        let account = TenantAccount::from_verifier(
            "gateway_a".into(), tenant, password_verifier(gateway_password)
        );
        let directory = MemoryDirectory(HashMap::from([("gateway_a".into(), account)]));
        let store = MemoryCredentialStore(TenantUpstreamCredentials {
            tenant_id: tenant,
            username: "root".into(),
            password: "a".repeat(64),
        });
        let assertion = crate::tenant::TenantAssertion::issue(
            tenant, 500, b"0123456789abcdef0123456789abcdef"
        ).unwrap();
        let mut handshake = test_handshake("gateway_a", response(gateway_password, &challenge));
        handshake.connection_attributes.push((
            crate::tenant::TENANT_ASSERTION_ATTRIBUTE.into(), assertion
        ));
        assert_eq!(
            authenticate_and_resolve(
                &handshake, &challenge, true, &directory,
                b"0123456789abcdef0123456789abcdef", 100, &store
            ),
            Err(AccountError::DirectoryUnavailable)
        );
    }

    #[test]
    fn authenticates_caching_sha2_account_and_returns_bound_tenant() {
        let tenant = Uuid::new_v4();
        let password = b"correct horse battery staple";
        let challenge = [7u8; 20];
        let account = TenantAccount::from_verifier("tenant_a".into(), tenant, password_verifier(password));
        let directory = MemoryDirectory(HashMap::from([("tenant_a".into(), account)]));
        let handshake = test_handshake("tenant_a", response(password, &challenge));
        assert_eq!(authenticate(&handshake, &challenge, true, &directory), Ok(tenant));
    }

    #[test]
    fn rejects_wrong_password() {
        let tenant = Uuid::new_v4();
        let challenge = [9u8; 20];
        let account = TenantAccount::from_verifier("tenant_a".into(), tenant, password_verifier(b"correct"));
        let directory = MemoryDirectory(HashMap::from([("tenant_a".into(), account)]));
        let handshake = test_handshake("tenant_a", response(b"wrong", &challenge));
        assert_eq!(authenticate(&handshake, &challenge, true, &directory), Err(AccountError::InvalidAuthenticationResponse));
    }

    #[test]
    fn rejects_plaintext_transport_even_with_valid_credentials() {
        let tenant = Uuid::new_v4();
        let challenge = [3u8; 20];
        let password = b"secret";
        let account = TenantAccount::from_verifier("tenant_a".into(), tenant, password_verifier(password));
        let directory = MemoryDirectory(HashMap::from([("tenant_a".into(), account)]));
        let handshake = test_handshake("tenant_a", response(password, &challenge));
        assert_eq!(authenticate(&handshake, &challenge, false, &directory), Err(AccountError::TlsRequired));
    }

    #[test]
    fn rejects_unknown_accounts_without_disclosing_username_existence() {
        let directory = MemoryDirectory(HashMap::new());
        let handshake = test_handshake("unknown", vec![0; 32]);
        assert_eq!(authenticate(&handshake, &[1; 20], true, &directory), Err(AccountError::UnknownAccount));
    }
}
