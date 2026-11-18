//! TLS-required MySQL caching_sha2_password gateway-account authentication.
//!
//! The account directory stores SHA256(SHA256(password)) verifier material,
//! never plaintext passwords. This module authenticates the gateway account;
//! tenant assertion validation remains a separate mandatory authorization step.
use crate::protocol::ClientHandshake;
use sha2::{Digest, Sha256};
use std::fmt;
use subtle::ConstantTimeEq;
use uuid::Uuid;

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
impl fmt::Debug for TenantAccount {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("TenantAccount")
            .field("username", &self.username)
            .field("tenant_id", &self.tenant_id)
            .field("password_verifier", &"[REDACTED]")
            .finish()
    }
}

pub trait TenantAccountDirectory {
    fn find_account(&self, username: &str) -> Result<Option<TenantAccount>, AccountError>;
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AccountError {
    TlsRequired,
    UnsupportedAuthenticationPlugin,
    InvalidAuthenticationResponse,
    UnknownAccount,
    DirectoryUnavailable,
}
impl fmt::Display for AccountError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::TlsRequired => write!(f, "MySQL gateway authentication requires TLS"),
            Self::UnsupportedAuthenticationPlugin => write!(f, "unsupported MySQL authentication plugin"),
            Self::InvalidAuthenticationResponse => write!(f, "invalid MySQL gateway credentials"),
            Self::UnknownAccount => write!(f, "invalid MySQL gateway credentials"),
            Self::DirectoryUnavailable => write!(f, "MySQL tenant account directory is unavailable"),
        }
    }
}
impl std::error::Error for AccountError {}

/// Verify a caching_sha2_password response for a 20-byte server challenge.
/// The caller must use a cryptographically secure random challenge for each
/// connection and must not reuse it.
pub fn authenticate(
    handshake: &ClientHandshake,
    challenge: &[u8; 20],
    tls_active: bool,
    directory: &impl TenantAccountDirectory,
) -> Result<Uuid, AccountError> {
    if !tls_active { return Err(AccountError::TlsRequired); }
    if handshake.auth_plugin_name.as_deref() != Some(CACHING_SHA2_PASSWORD) {
        return Err(AccountError::UnsupportedAuthenticationPlugin);
    }
    if handshake.auth_response.len() != 32 {
        return Err(AccountError::InvalidAuthenticationResponse);
    }
    let account = directory
        .find_account(&handshake.username)?
        .ok_or(AccountError::UnknownAccount)?;

    let mut material = Vec::with_capacity(52);
    material.extend_from_slice(&account.password_verifier);
    material.extend_from_slice(challenge);
    let mask = Sha256::digest(&material);
    let mut recovered_stage_one = [0u8; 32];
    for index in 0..32 {
        recovered_stage_one[index] = handshake.auth_response[index] ^ mask[index];
    }
    let candidate_verifier = Sha256::digest(recovered_stage_one);
    if candidate_verifier.as_slice().ct_eq(&account.password_verifier).unwrap_u8() != 1 {
        return Err(AccountError::InvalidAuthenticationResponse);
    }
    Ok(account.tenant_id)
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
