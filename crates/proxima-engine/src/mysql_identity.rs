use sha1::{Digest, Sha1};
use std::collections::HashMap;
use std::fs;
use std::path::Path;

#[derive(Clone)]
pub struct TenantPrincipal {
    pub username: String,
    pub tenant_id: String,
    pub database: String,
    pub upstream_url: String,
    pub(crate) password_sha1: [u8; 20],
}

#[derive(Debug)]
pub enum IdentityError {
    Io(std::io::Error),
    InvalidRegistry(String),
}

impl std::fmt::Display for IdentityError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Io(error) => write!(f, "identity registry I/O error: {error}"),
            Self::InvalidRegistry(message) => {
                write!(f, "invalid MySQL identity registry: {message}")
            }
        }
    }
}

impl std::error::Error for IdentityError {}

impl From<std::io::Error> for IdentityError {
    fn from(value: std::io::Error) -> Self {
        Self::Io(value)
    }
}

pub struct MysqlIdentityRegistry {
    principals: HashMap<String, TenantPrincipal>,
}

impl MysqlIdentityRegistry {
    pub fn load(path: impl AsRef<Path>) -> Result<Self, IdentityError> {
        let contents = fs::read_to_string(path)?;
        Self::from_json(&contents)
    }

    pub fn from_json(contents: &str) -> Result<Self, IdentityError> {
        let root: serde_json::Value = serde_json::from_str(contents)
            .map_err(|error| IdentityError::InvalidRegistry(error.to_string()))?;

        let users = root
            .get("users")
            .and_then(serde_json::Value::as_array)
            .ok_or_else(|| IdentityError::InvalidRegistry("users must be an array".into()))?;

        if users.is_empty() {
            return Err(IdentityError::InvalidRegistry(
                "at least one user must be provisioned".into(),
            ));
        }

        let mut principals = HashMap::new();

        for (index, user) in users.iter().enumerate() {
            let field = |name: &str| -> Result<String, IdentityError> {
                user.get(name)
                    .and_then(serde_json::Value::as_str)
                    .map(str::trim)
                    .filter(|value| !value.is_empty())
                    .map(str::to_owned)
                    .ok_or_else(|| {
                        IdentityError::InvalidRegistry(format!("users[{index}].{name} is required"))
                    })
            };

            let username = field("username")?;
            let tenant_id = field("tenant_id")?;
            let database = field("database")?;
            let upstream_url = field("upstream_url")?;
            let password_hash_hex = field("password_sha1")?;

            if !valid_database_name(&database) {
                return Err(IdentityError::InvalidRegistry(format!(
                    "users[{index}].database contains invalid characters"
                )));
            }

            if tenant_id.len() > 128 || username.len() > 128 || database.len() > 64 {
                return Err(IdentityError::InvalidRegistry(format!(
                    "users[{index}] contains an identifier that exceeds its length limit"
                )));
            }

            if !upstream_url.starts_with("mysql://") {
                return Err(IdentityError::InvalidRegistry(format!(
                    "users[{index}].upstream_url must use the mysql:// scheme supported by mysql_async"
                )));
            }

            let upstream_options = mysql_async::Opts::from_url(&upstream_url).map_err(|error| {
                IdentityError::InvalidRegistry(format!(
                    "users[{index}].upstream_url is invalid: {error}"
                ))
            })?;

            if upstream_options.db_name() != Some(database.as_str()) {
                return Err(IdentityError::InvalidRegistry(format!(
                    "users[{index}].database must match the database selected by upstream_url"
                )));
            }

            if !matches!(upstream_options.ip_or_hostname(), "localhost" | "127.0.0.1" | "::1")
                && upstream_options.ssl_opts().is_none()
            {
                return Err(IdentityError::InvalidRegistry(format!(
                    "users[{index}].upstream_url must require verified TLS for non-loopback upstream hosts (add require_ssl=true)"
                )));
            }

            if upstream_options.user().is_none() || upstream_options.pass().is_none() {
                return Err(IdentityError::InvalidRegistry(format!(
                    "users[{index}].upstream_url must include explicit upstream credentials"
                )));
            }

            let decoded = hex::decode(&password_hash_hex).map_err(|_| {
                IdentityError::InvalidRegistry(format!(
                    "users[{index}].password_sha1 must be hexadecimal"
                ))
            })?;

            let password_sha1: [u8; 20] = decoded.try_into().map_err(|_| {
                IdentityError::InvalidRegistry(format!(
                    "users[{index}].password_sha1 must contain exactly 20 bytes"
                ))
            })?;

            let principal = TenantPrincipal {
                username: username.clone(),
                tenant_id,
                database,
                upstream_url,
                password_sha1,
            };

            if principals.insert(username.clone(), principal).is_some() {
                return Err(IdentityError::InvalidRegistry(format!(
                    "duplicate username: {username}"
                )));
            }
        }

        Ok(Self { principals })
    }

    /// Verifies a MySQL mysql_native_password challenge response.
    ///
    /// The registry stores SHA1(password), never the plaintext password.
    /// Returns the immutable tenant principal only after successful
    /// authentication.
    pub fn authenticate(
        &self,
        auth_plugin: &str,
        username: &[u8],
        salt: &[u8],
        auth_data: &[u8],
    ) -> Option<TenantPrincipal> {
        if auth_plugin != "mysql_native_password" || salt.len() != 20 {
            return None;
        }

        let username = std::str::from_utf8(username).ok()?;
        let principal = self.principals.get(username)?;

        if !verify_native_password(&principal.password_sha1, salt, auth_data) {
            return None;
        }

        Some(principal.clone())
    }

    pub fn principal_count(&self) -> usize {
        self.principals.len()
    }
}

fn valid_database_name(value: &str) -> bool {
    !value.is_empty()
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'_' || byte == b'$')
}

fn verify_native_password(stored_stage1: &[u8; 20], salt: &[u8], auth_data: &[u8]) -> bool {
    if auth_data.is_empty() {
        let empty_password_hash: [u8; 20] = Sha1::digest([]).into();
        return constant_time_equal(stored_stage1, &empty_password_hash);
    }

    if auth_data.len() != 20 {
        return false;
    }

    // mysql_native_password:
    // stage1 = SHA1(password)
    // stage2 = SHA1(stage1)
    // challenge = SHA1(salt || stage2)
    // response = stage1 XOR challenge
    let stage2 = Sha1::digest(stored_stage1);
    let mut challenge_input = Vec::with_capacity(salt.len() + stage2.len());
    challenge_input.extend_from_slice(salt);
    challenge_input.extend_from_slice(&stage2);

    let challenge = Sha1::digest(&challenge_input);

    let mut recovered_stage1 = [0u8; 20];
    for index in 0..20 {
        recovered_stage1[index] = auth_data[index] ^ challenge[index];
    }

    let recovered_stage2 = Sha1::digest(recovered_stage1);
    constant_time_equal(&recovered_stage2, &stage2)
}

fn constant_time_equal(left: &[u8], right: &[u8]) -> bool {
    if left.len() != right.len() {
        return false;
    }

    let mut difference = 0u8;
    for (a, b) in left.iter().zip(right.iter()) {
        difference |= a ^ b;
    }

    difference == 0
}

#[cfg(test)]
mod tests {
    use super::*;

    const SALT: &[u8; 20] = b"proxima-test-salt-12";

    fn password_stage1(password: &str) -> [u8; 20] {
        Sha1::digest(password.as_bytes()).into()
    }

    fn native_response(password: &str, salt: &[u8]) -> Vec<u8> {
        let stage1 = password_stage1(password);
        let stage2 = Sha1::digest(stage1);

        let mut input = Vec::new();
        input.extend_from_slice(salt);
        input.extend_from_slice(&stage2);

        let challenge = Sha1::digest(input);

        stage1
            .iter()
            .zip(challenge.iter())
            .map(|(a, b)| a ^ b)
            .collect()
    }

    fn registry_json() -> String {
        let hash = hex::encode(password_stage1("correct-password"));

        format!(
            r#"{{
                "users": [
                    {{
                        "username": "tenant_a_app",
                        "tenant_id": "tenant-a",
                        "database": "tenant_a_db",
                        "upstream_url": "mysql://tenant_a:secret@127.0.0.1:3306/tenant_a_db",
                        "password_sha1": "{hash}"
                    }}
                ]
            }}"#
        )
    }

    #[test]
    fn loads_valid_registry() {
        let registry = MysqlIdentityRegistry::from_json(&registry_json()).unwrap();
        assert_eq!(registry.principal_count(), 1);
    }

    #[test]
    fn authenticates_valid_native_password() {
        let registry = MysqlIdentityRegistry::from_json(&registry_json()).unwrap();
        let response = native_response("correct-password", SALT);

        let principal =
            registry.authenticate("mysql_native_password", b"tenant_a_app", SALT, &response);

        assert_eq!(principal.unwrap().tenant_id, "tenant-a");
    }

    #[test]
    fn rejects_wrong_password() {
        let registry = MysqlIdentityRegistry::from_json(&registry_json()).unwrap();
        let response = native_response("wrong-password", SALT);

        assert!(registry
            .authenticate("mysql_native_password", b"tenant_a_app", SALT, &response,)
            .is_none());
    }

    #[test]
    fn rejects_unknown_username() {
        let registry = MysqlIdentityRegistry::from_json(&registry_json()).unwrap();
        let response = native_response("correct-password", SALT);

        assert!(registry
            .authenticate("mysql_native_password", b"tenant_b_app", SALT, &response,)
            .is_none());
    }

    #[test]
    fn rejects_unsupported_auth_plugin() {
        let registry = MysqlIdentityRegistry::from_json(&registry_json()).unwrap();
        let response = native_response("correct-password", SALT);

        assert!(registry
            .authenticate("caching_sha2_password", b"tenant_a_app", SALT, &response,)
            .is_none());
    }

    #[test]
    fn rejects_wrong_salt_length() {
        let registry = MysqlIdentityRegistry::from_json(&registry_json()).unwrap();
        let response = native_response("correct-password", SALT);

        assert!(registry
            .authenticate(
                "mysql_native_password",
                b"tenant_a_app",
                b"short",
                &response,
            )
            .is_none());
    }

    #[test]
    fn rejects_malformed_auth_response() {
        let registry = MysqlIdentityRegistry::from_json(&registry_json()).unwrap();

        assert!(registry
            .authenticate("mysql_native_password", b"tenant_a_app", SALT, b"short",)
            .is_none());
    }

    #[test]
    fn rejects_duplicate_usernames() {
        let hash = hex::encode(password_stage1("password"));
        let json = format!(
            r#"{{
                "users": [
                    {{
                        "username":"same",
                        "tenant_id":"a",
                        "database":"db_a",
                        "upstream_url":"mysql://user:pass@localhost/db_a",
                        "password_sha1":"{hash}"
                    }},
                    {{
                        "username":"same",
                        "tenant_id":"b",
                        "database":"db_b",
                        "upstream_url":"mysql://user:pass@localhost/db_b",
                        "password_sha1":"{hash}"
                    }}
                ]
            }}"#
        );

        assert!(MysqlIdentityRegistry::from_json(&json).is_err());
    }

    #[test]
    fn rejects_remote_upstream_without_tls() {
        let json = registry_json().replace("127.0.0.1:3306", "db.example.com:3306");
        assert!(MysqlIdentityRegistry::from_json(&json).is_err());
    }

    #[test]
    fn accepts_remote_upstream_with_tls() {
        let json = registry_json().replace(
            "127.0.0.1:3306/tenant_a_db",
            "db.example.com:3306/tenant_a_db?require_ssl=true"
        );
        assert!(MysqlIdentityRegistry::from_json(&json).is_ok());
    }

    #[test]
    fn rejects_upstream_database_mismatch() {
        let json = registry_json().replace(
            "127.0.0.1:3306/tenant_a_db",
            "127.0.0.1:3306/tenant_b_db"
        );
        assert!(MysqlIdentityRegistry::from_json(&json).is_err());
    }

    #[test]
    fn rejects_upstream_url_without_database() {
        let json = registry_json().replace(
            "127.0.0.1:3306/tenant_a_db",
            "127.0.0.1:3306/"
        );
        assert!(MysqlIdentityRegistry::from_json(&json).is_err());
    }

    #[test]
    fn rejects_mysqls_scheme_not_supported_by_driver() {
        let json = registry_json().replace("mysql://", "mysqls://");
        assert!(MysqlIdentityRegistry::from_json(&json).is_err());
    }

    #[test]
    fn rejects_invalid_database_identifier() {
        let json = registry_json().replace("tenant_a_db", "tenant_a; DROP TABLE users");

        assert!(MysqlIdentityRegistry::from_json(&json).is_err());
    }

    #[test]
    fn rejects_missing_registry_users() {
        assert!(MysqlIdentityRegistry::from_json("{}").is_err());
    }

    #[test]
    fn rejects_invalid_password_hash_length() {
        let json =
            registry_json().replace(&hex::encode(password_stage1("correct-password")), "abcd");

        assert!(MysqlIdentityRegistry::from_json(&json).is_err());
    }
}

impl std::fmt::Debug for TenantPrincipal {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TenantPrincipal")
            .field("username", &self.username)
            .field("tenant_id", &self.tenant_id)
            .field("database", &self.database)
            .field("upstream_url", &"[REDACTED]")
            .field("password_sha1", &"[REDACTED]")
            .finish()
    }
}
