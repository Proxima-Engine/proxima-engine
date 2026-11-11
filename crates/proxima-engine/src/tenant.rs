use hmac::{Hmac, Mac};
use sha2::{Digest, Sha256};
use std::fmt;
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};

type HmacSha256 = Hmac<Sha256>;

const VERSION: &str = "v1";
const MAX_TENANT_ID_LENGTH: usize = 128;
const SIGNATURE_HEX_LENGTH: usize = 64;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TenantContext {
    pub tenant_id: String,
    pub expires_at: u64,
    pub emergency: bool,
    pub emergency_nonce_hash: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TenantTokenError {
    InvalidFormat,
    UnsupportedVersion,
    InvalidTenantId,
    InvalidExpiry,
    Expired,
    InvalidSignature,
    EmergencyTokenLifetimeInvalid,
    EmergencyTokenReplay,
    EmergencyReplayStoreUnavailable,
}

impl fmt::Display for TenantTokenError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidFormat => write!(f, "invalid Proxima tenant token format"),
            Self::UnsupportedVersion => write!(f, "unsupported Proxima tenant token version"),
            Self::InvalidTenantId => write!(f, "invalid tenant identifier"),
            Self::InvalidExpiry => write!(f, "invalid tenant token expiry"),
            Self::Expired => write!(f, "tenant token has expired"),
            Self::InvalidSignature => write!(f, "invalid tenant token signature"),
            Self::EmergencyTokenLifetimeInvalid => {
                write!(f, "emergency token lifetime must be at most 15 minutes")
            }
            Self::EmergencyTokenReplay => write!(f, "emergency token has already been used"),
            Self::EmergencyReplayStoreUnavailable => {
                write!(f, "emergency replay protection is unavailable")
            }
        }
    }
}

impl std::error::Error for TenantTokenError {}

#[derive(Clone)]
pub struct TenantTokenVerifier {
    secret: Vec<u8>,
    previous_secret: Option<Vec<u8>>,
    replay_dir: PathBuf,
}

impl TenantTokenVerifier {
    pub fn new(secret: impl AsRef<[u8]>) -> Result<Self, TenantTokenError> {
        let secret = secret.as_ref();
        if secret.len() < 32 {
            return Err(TenantTokenError::InvalidSignature);
        }

        let replay_dir = std::env::var_os("PROXIMA_BREAK_GLASS_REPLAY_DIR")
            .map(PathBuf::from)
            .unwrap_or_else(|| PathBuf::from("data/proxima-break-glass-replays"));
        Ok(Self {
            secret: secret.to_vec(),
            previous_secret: None,
            replay_dir,
        })
    }

    pub fn new_with_previous(
        secret: impl AsRef<[u8]>,
        previous_secret: Option<&[u8]>,
    ) -> Result<Self, TenantTokenError> {
        let secret = secret.as_ref();
        if secret.len() < 32 || previous_secret.is_some_and(|previous| previous.len() < 32) {
            return Err(TenantTokenError::InvalidSignature);
        }
        let replay_dir = std::env::var_os("PROXIMA_BREAK_GLASS_REPLAY_DIR")
            .map(PathBuf::from)
            .unwrap_or_else(|| PathBuf::from("data/proxima-break-glass-replays"));
        Ok(Self {
            secret: secret.to_vec(),
            previous_secret: previous_secret.map(ToOwned::to_owned),
            replay_dir,
        })
    }

    pub fn with_replay_dir(
        secret: impl AsRef<[u8]>,
        replay_dir: PathBuf,
    ) -> Result<Self, TenantTokenError> {
        let secret = secret.as_ref();
        if secret.len() < 32 {
            return Err(TenantTokenError::InvalidSignature);
        }
        Ok(Self {
            secret: secret.to_vec(),
            previous_secret: None,
            replay_dir,
        })
    }

    pub fn verify(
        &self,
        token: &str,
        now_unix_seconds: u64,
    ) -> Result<TenantContext, TenantTokenError> {
        if token.starts_with("bg1.") {
            return self.verify_break_glass(token, now_unix_seconds);
        }
        let mut parts = token.split('.');
        let version = parts.next().ok_or(TenantTokenError::InvalidFormat)?;
        let tenant_id = parts.next().ok_or(TenantTokenError::InvalidFormat)?;
        let expiry = parts.next().ok_or(TenantTokenError::InvalidFormat)?;
        let signature = parts.next().ok_or(TenantTokenError::InvalidFormat)?;

        if parts.next().is_some() {
            return Err(TenantTokenError::InvalidFormat);
        }

        if version != VERSION {
            return Err(TenantTokenError::UnsupportedVersion);
        }

        validate_tenant_id(tenant_id)?;

        let expires_at = expiry
            .parse::<u64>()
            .map_err(|_| TenantTokenError::InvalidExpiry)?;

        if now_unix_seconds >= expires_at {
            return Err(TenantTokenError::Expired);
        }

        let expected = sign_payload(&self.secret, version, tenant_id, expires_at);
        let valid_current = constant_time_hex_eq(&expected, signature);
        let valid_previous = self.previous_secret.as_ref().is_some_and(|secret| {
            constant_time_hex_eq(&sign_payload(secret, version, tenant_id, expires_at), signature)
        });
        if !valid_current && !valid_previous {
            return Err(TenantTokenError::InvalidSignature);
        }

        Ok(TenantContext {
            tenant_id: tenant_id.to_owned(),
            expires_at,
            emergency: false,
            emergency_nonce_hash: None,
        })
    }

    pub fn verify_now(&self, token: &str) -> Result<TenantContext, TenantTokenError> {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|_| TenantTokenError::InvalidExpiry)?
            .as_secs();

        self.verify(token, now)
    }

    fn verify_break_glass(&self, token: &str, now: u64) -> Result<TenantContext, TenantTokenError> {
        let parts: Vec<&str> = token.split('.').collect();
        if parts.len() != 5 || parts[0] != "bg1" {
            return Err(TenantTokenError::InvalidFormat);
        }
        let tenant_id = parts[1];
        validate_tenant_id(tenant_id)?;
        let expires_at = parts[2]
            .parse::<u64>()
            .map_err(|_| TenantTokenError::InvalidExpiry)?;
        if expires_at <= now {
            return Err(TenantTokenError::Expired);
        }
        if expires_at.saturating_sub(now) > 900 {
            return Err(TenantTokenError::EmergencyTokenLifetimeInvalid);
        }
        let nonce = parts[3];
        if nonce.len() != 32 || !nonce.bytes().all(|b| b.is_ascii_hexdigit()) {
            return Err(TenantTokenError::InvalidFormat);
        }
        let payload = format!("bg1.{tenant_id}.{expires_at}.{nonce}");
        let valid_current = constant_time_hex_eq(&sign_message(&self.secret, &payload), parts[4]);
        let valid_previous = self.previous_secret.as_ref().is_some_and(|secret| {
            constant_time_hex_eq(&sign_message(secret, &payload), parts[4])
        });
        if !valid_current && !valid_previous {
            return Err(TenantTokenError::InvalidSignature);
        }
        fs::create_dir_all(&self.replay_dir)
            .map_err(|_| TenantTokenError::EmergencyReplayStoreUnavailable)?;
        let nonce_hash = format!("{:x}", Sha256::digest(nonce.as_bytes()));
        let replay_path = self.replay_dir.join(format!("{nonce_hash}.used"));
        let mut file = match OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(replay_path)
        {
            Ok(file) => file,
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
                return Err(TenantTokenError::EmergencyTokenReplay)
            }
            Err(_) => return Err(TenantTokenError::EmergencyReplayStoreUnavailable),
        };
        file.write_all(format!("expires_at={expires_at}\n").as_bytes())
            .and_then(|_| file.sync_all())
            .map_err(|_| TenantTokenError::EmergencyReplayStoreUnavailable)?;
        Ok(TenantContext {
            tenant_id: tenant_id.to_owned(),
            expires_at,
            emergency: true,
            emergency_nonce_hash: Some(nonce_hash),
        })
    }

    #[cfg(test)]
    pub(crate) fn sign_for_test(&self, tenant_id: &str, expires_at: u64) -> String {
        validate_tenant_id(tenant_id).unwrap();
        format!(
            "{VERSION}.{tenant_id}.{expires_at}.{}",
            sign_payload(&self.secret, VERSION, tenant_id, expires_at)
        )
    }
}

pub fn issue_break_glass_token(
    secret: &[u8],
    tenant_id: &str,
    ttl_seconds: u64,
) -> Result<String, String> {
    if secret.len() < 32 {
        return Err("tenant signing secret must be at least 32 bytes".into());
    }
    if !(1..=900).contains(&ttl_seconds) {
        return Err("TTL must be between 1 and 900 seconds".into());
    }
    validate_tenant_id(tenant_id).map_err(|e| e.to_string())?;
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| "system clock before UNIX epoch".to_string())?
        .as_secs();
    let expires_at = now.saturating_add(ttl_seconds);
    let nonce = uuid::Uuid::new_v4().simple().to_string();
    let payload = format!("bg1.{tenant_id}.{expires_at}.{nonce}");
    Ok(format!("{payload}.{}", sign_message(secret, &payload)))
}

fn validate_tenant_id(tenant_id: &str) -> Result<(), TenantTokenError> {
    if tenant_id.is_empty()
        || tenant_id.len() > MAX_TENANT_ID_LENGTH
        || !tenant_id
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-' || byte == b'_')
    {
        return Err(TenantTokenError::InvalidTenantId);
    }

    Ok(())
}

fn sign_payload(secret: &[u8], version: &str, tenant_id: &str, expires_at: u64) -> String {
    let payload = format!("{version}.{tenant_id}.{expires_at}");
    sign_message(secret, &payload)
}

fn sign_message(secret: &[u8], payload: &str) -> String {
    let mut mac = HmacSha256::new_from_slice(secret).expect("HMAC accepts keys of any length");
    mac.update(payload.as_bytes());

    let mut output = String::with_capacity(SIGNATURE_HEX_LENGTH);
    for byte in mac.finalize().into_bytes() {
        output.push_str(&format!("{byte:02x}"));
    }
    output
}

fn constant_time_hex_eq(expected: &str, actual: &str) -> bool {
    if actual.len() != expected.len() {
        return false;
    }

    let mut difference = 0u8;
    for (left, right) in expected.bytes().zip(actual.bytes()) {
        difference |= left ^ right;
    }

    difference == 0
}

#[cfg(test)]
mod tests {
    use super::*;

    fn verifier() -> TenantTokenVerifier {
        TenantTokenVerifier::new(b"01234567890123456789012345678901").unwrap()
    }

    #[test]
    fn verifies_signed_tenant_context() {
        let verifier = verifier();
        let token = verifier.sign_for_test("tenant_a", 2_000);

        assert_eq!(
            verifier.verify(&token, 1_000).unwrap(),
            TenantContext {
                tenant_id: "tenant_a".into(),
                expires_at: 2_000,
                emergency: false,
                emergency_nonce_hash: None
            }
        );
    }

    #[test]
    fn rejects_tampered_tenant_id() {
        let verifier = verifier();
        let token = verifier.sign_for_test("tenant_a", 2_000);
        let tampered = token.replacen("tenant_a", "tenant_b", 1);

        assert_eq!(
            verifier.verify(&tampered, 1_000),
            Err(TenantTokenError::InvalidSignature)
        );
    }

    #[test]
    fn rejects_expired_token() {
        let verifier = verifier();
        let token = verifier.sign_for_test("tenant_a", 2_000);

        assert_eq!(
            verifier.verify(&token, 2_000),
            Err(TenantTokenError::Expired)
        );
    }

    #[test]
    fn emergency_token_is_tenant_bound_short_lived_and_one_time() {
        let dir = tempfile::tempdir().unwrap();
        let secret = b"01234567890123456789012345678901";
        let verifier =
            TenantTokenVerifier::with_replay_dir(secret, dir.path().to_path_buf()).unwrap();
        let token = issue_break_glass_token(secret, "tenant_a", 300).unwrap();
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let context = verifier.verify(&token, now).unwrap();
        assert_eq!(context.tenant_id, "tenant_a");
        assert!(context.emergency);
        assert!(context.emergency_nonce_hash.is_some());
        assert_eq!(
            verifier.verify(&token, now),
            Err(TenantTokenError::EmergencyTokenReplay)
        );
    }

    #[test]
    fn emergency_token_lifetime_is_bounded() {
        let secret = b"01234567890123456789012345678901";
        assert!(issue_break_glass_token(secret, "tenant_a", 901).is_err());
        assert!(issue_break_glass_token(secret, "tenant_a", 0).is_err());
    }

    #[test]
    fn rejects_weak_signing_secret() {
        assert!(matches!(
            TenantTokenVerifier::new("too-short"),
            Err(TenantTokenError::InvalidSignature)
        ));
    }

    #[test]
    fn rejects_invalid_tenant_identifier() {
        let verifier = verifier();

        assert_eq!(
            verifier.verify("v1.bad!.2000.00", 0),
            Err(TenantTokenError::InvalidTenantId)
        );
    }

    #[test]
    fn rejects_extra_token_parts() {
        let verifier = verifier();
        assert_eq!(
            verifier.verify("v1.tenant_a.2000.00.extra", 1000),
            Err(TenantTokenError::InvalidFormat)
        );
    }
}

#[cfg(test)]
mod previous_key_tests {
    use super::*;

    #[test]
    fn accepts_existing_tokens_with_previous_key_during_rotation() {
        let previous = b"legacy-global-tenant-signing-key-0001";
        let current = b"organization-scoped-tenant-signing-key-01";
        let verifier = TenantTokenVerifier::new_with_previous(current, Some(previous)).unwrap();
        let token = format!("v1.tenant_a.2000.{}", sign_payload(previous, "v1", "tenant_a", 2000));
        assert_eq!(verifier.verify(&token, 1000).unwrap().tenant_id, "tenant_a");
    }

    #[test]
    fn rejects_previous_key_when_not_configured() {
        let previous = b"legacy-global-tenant-signing-key-0001";
        let current = b"organization-scoped-tenant-signing-key-01";
        let verifier = TenantTokenVerifier::new(current).unwrap();
        let token = format!("v1.tenant_a.2000.{}", sign_payload(previous, "v1", "tenant_a", 2000));
        assert_eq!(verifier.verify(&token, 1000), Err(TenantTokenError::InvalidSignature));
    }
}
