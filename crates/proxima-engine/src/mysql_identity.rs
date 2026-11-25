use sha1::{Digest, Sha1};
use sha2::Sha256;
use std::collections::HashMap;
use std::fs;
use std::path::Path;

#[derive(Clone)]
pub struct TenantPrincipal {
    pub username: String,
    pub tenant_id: String,
    pub database: String,
    pub upstream_url: String,
    pub upstream_tls_ca_file: Option<String>,
    pub(crate) auth_plugin: &'static str,
    pub(crate) password_sha1: Option<[u8; 20]>,
    pub(crate) password_sha256: Option<[u8; 32]>,
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

        let upstream_tls_ca_file = root
            .get("upstream_tls_ca_file")
            .and_then(serde_json::Value::as_str)
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .map(str::to_owned);
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
            let password_sha1_hex = user
                .get("password_sha1")
                .and_then(serde_json::Value::as_str)
                .map(str::trim)
                .filter(|v| !v.is_empty());
            let password_sha256_hex = user
                .get("password_sha256")
                .and_then(serde_json::Value::as_str)
                .map(str::trim)
                .filter(|v| !v.is_empty());
            if password_sha1_hex.is_some() == password_sha256_hex.is_some() {
                return Err(IdentityError::InvalidRegistry(format!(
                    "users[{index}] must contain exactly one of password_sha1 or password_sha256"
                )));
            }
            let auth_plugin = user
                .get("auth_plugin")
                .and_then(serde_json::Value::as_str)
                .unwrap_or(if password_sha256_hex.is_some() {
                    "caching_sha2_password"
                } else {
                    "mysql_native_password"
                });
            let (password_sha1, password_sha256, expected_plugin) =
                if let Some(hash) = password_sha1_hex {
                    let decoded = hex::decode(hash).map_err(|_| {
                        IdentityError::InvalidRegistry(format!(
                            "users[{index}].password_sha1 must be hexadecimal"
                        ))
                    })?;
                    let hash: [u8; 20] = decoded.try_into().map_err(|_| {
                        IdentityError::InvalidRegistry(format!(
                            "users[{index}].password_sha1 must contain exactly 20 bytes"
                        ))
                    })?;
                    (Some(hash), None, "mysql_native_password")
                } else {
                    let decoded = hex::decode(password_sha256_hex.unwrap()).map_err(|_| {
                        IdentityError::InvalidRegistry(format!(
                            "users[{index}].password_sha256 must be hexadecimal"
                        ))
                    })?;
                    let hash: [u8; 32] = decoded.try_into().map_err(|_| {
                        IdentityError::InvalidRegistry(format!(
                            "users[{index}].password_sha256 must contain exactly 32 bytes"
                        ))
                    })?;
                    (None, Some(hash), "caching_sha2_password")
                };
            if auth_plugin != expected_plugin {
                return Err(IdentityError::InvalidRegistry(format!(
                    "users[{index}].auth_plugin does not match its verifier format"
                )));
            }

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

            if !matches!(
                upstream_options.ip_or_hostname(),
                "localhost" | "127.0.0.1" | "::1"
            ) && (upstream_options.ssl_opts().is_none() || upstream_tls_ca_file.is_none())
            {
                return Err(IdentityError::InvalidRegistry(format!(
                    "users[{index}].upstream_url must require verified TLS and the registry must provide upstream_tls_ca_file for non-loopback hosts"
                )));
            }

            if upstream_options.user().is_none() || upstream_options.pass().is_none() {
                return Err(IdentityError::InvalidRegistry(format!(
                    "users[{index}].upstream_url must include explicit upstream credentials"
                )));
            }

            let principal = TenantPrincipal {
                username: username.clone(),
                tenant_id,
                database,
                upstream_url,
                upstream_tls_ca_file: upstream_tls_ca_file.clone(),
                auth_plugin: expected_plugin,
                password_sha1,
                password_sha256,
            };

            if principals.insert(username.clone(), principal).is_some() {
                return Err(IdentityError::InvalidRegistry(format!(
                    "duplicate username: {username}"
                )));
            }
        }

        Ok(Self { principals })
    }

    /// Verifies a MySQL client challenge response using the selected plugin.
    /// Only one-way password verifiers are stored; plaintext passwords are never retained.
    pub fn authenticate(
        &self,
        auth_plugin: &str,
        username: &[u8],
        salt: &[u8],
        auth_data: &[u8],
    ) -> Option<TenantPrincipal> {
        if salt.len() != 20 {
            return None;
        }
        let username = std::str::from_utf8(username).ok()?;
        let principal = self.principals.get(username)?;
        if auth_plugin != principal.auth_plugin {
            return None;
        }
        let valid = match (
            auth_plugin,
            principal.password_sha1.as_ref(),
            principal.password_sha256.as_ref(),
        ) {
            ("mysql_native_password", Some(hash), None) => {
                verify_native_password(hash, salt, auth_data)
            }
            ("caching_sha2_password", None, Some(hash)) => {
                verify_caching_sha2_password(hash, salt, auth_data)
            }
            _ => false,
        };
        valid.then(|| principal.clone())
    }

    pub fn auth_plugin_for_username(&self, username: &[u8]) -> &'static str {
        std::str::from_utf8(username)
            .ok()
            .and_then(|name| self.principals.get(name))
            .map(|principal| principal.auth_plugin)
            .unwrap_or("caching_sha2_password")
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

fn verify_caching_sha2_password(stored_stage2: &[u8; 32], salt: &[u8], auth_data: &[u8]) -> bool {
    if auth_data.is_empty() {
        let stage1 = Sha256::digest([]);
        let empty_stage2 = Sha256::digest(stage1);
        return constant_time_equal(stored_stage2, &empty_stage2);
    }
    if auth_data.len() != 32 {
        return false;
    }
    // MySQL caching_sha2_password fast-auth:
    // stage1 = SHA256(password), stage2 = SHA256(stage1)
    // challenge = SHA256(stage2 || nonce), response = stage1 XOR challenge.
    let challenge = {
        let mut input = Vec::with_capacity(stored_stage2.len() + salt.len());
        input.extend_from_slice(stored_stage2);
        input.extend_from_slice(salt);
        Sha256::digest(input)
    };
    let mut recovered_stage1 = [0u8; 32];
    for index in 0..32 {
        recovered_stage1[index] = auth_data[index] ^ challenge[index];
    }
    let recovered_stage2 = Sha256::digest(recovered_stage1);
    constant_time_equal(&recovered_stage2, stored_stage2)
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

    fn caching_stage2(password: &str) -> [u8; 32] {
        let stage1 = Sha256::digest(password.as_bytes());
        Sha256::digest(stage1).into()
    }

    fn caching_response(password: &str, salt: &[u8]) -> Vec<u8> {
        let stage1 = Sha256::digest(password.as_bytes());
        let stage2 = Sha256::digest(stage1);
        let mut input = Vec::new();
        input.extend_from_slice(&stage2);
        input.extend_from_slice(salt);
        let challenge = Sha256::digest(input);
        stage1
            .iter()
            .zip(challenge.iter())
            .map(|(a, b)| a ^ b)
            .collect()
    }

    fn caching_registry_json() -> String {
        let hash = hex::encode(caching_stage2("correct-password"));
        format!(
            r#"{{"users":[{{"username":"tenant_sha2","tenant_id":"tenant-sha2","database":"tenant_sha2_db","upstream_url":"mysql://tenant_sha2:secret@127.0.0.1:3306/tenant_sha2_db","auth_plugin":"caching_sha2_password","password_sha256":"{hash}"}}]}}"#
        )
    }

    #[test]
    fn authenticates_caching_sha2_password_with_stage2_verifier() {
        let registry = MysqlIdentityRegistry::from_json(&caching_registry_json()).unwrap();
        let response = caching_response("correct-password", SALT);
        let principal = registry
            .authenticate("caching_sha2_password", b"tenant_sha2", SALT, &response)
            .unwrap();
        assert_eq!(principal.tenant_id, "tenant-sha2");
        assert_eq!(
            registry.auth_plugin_for_username(b"tenant_sha2"),
            "caching_sha2_password"
        );
    }

    #[test]
    fn rejects_wrong_caching_sha2_password() {
        let registry = MysqlIdentityRegistry::from_json(&caching_registry_json()).unwrap();
        let response = caching_response("wrong-password", SALT);
        assert!(registry
            .authenticate("caching_sha2_password", b"tenant_sha2", SALT, &response)
            .is_none());
    }

    #[test]
    fn rejects_malformed_caching_sha2_response() {
        let registry = MysqlIdentityRegistry::from_json(&caching_registry_json()).unwrap();
        assert!(registry
            .authenticate("caching_sha2_password", b"tenant_sha2", SALT, b"short")
            .is_none());
    }

    #[test]
    fn rejects_mismatched_auth_plugin_and_verifier() {
        let registry = MysqlIdentityRegistry::from_json(&caching_registry_json()).unwrap();
        let response = caching_response("correct-password", SALT);
        assert!(registry
            .authenticate("mysql_native_password", b"tenant_sha2", SALT, &response)
            .is_none());
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
        let json = registry_json()
            .replace(
                "\"users\"",
                "\"upstream_tls_ca_file\":\"/etc/ssl/certs/mysql-ca.pem\",\"users\"",
            )
            .replace(
                "127.0.0.1:3306/tenant_a_db",
                "db.example.com:3306/tenant_a_db?require_ssl=true",
            );
        assert!(MysqlIdentityRegistry::from_json(&json).is_ok());
    }

    #[test]
    fn rejects_upstream_database_mismatch() {
        let json =
            registry_json().replace("127.0.0.1:3306/tenant_a_db", "127.0.0.1:3306/tenant_b_db");
        assert!(MysqlIdentityRegistry::from_json(&json).is_err());
    }

    #[test]
    fn rejects_upstream_url_without_database() {
        let json = registry_json().replace("127.0.0.1:3306/tenant_a_db", "127.0.0.1:3306/");
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
            .field("auth_plugin", &self.auth_plugin)
            .field("password_sha1", &"[REDACTED]")
            .field("password_sha256", &"[REDACTED]")
            .finish()
    }
}
