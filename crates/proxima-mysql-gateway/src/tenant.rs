//! Tenant assertion validation and server-derived MySQL routing.
//!
//! Client-supplied schema/database names are never used to select a tenant.
//! A valid signed assertion must match the tenant resolved from the authenticated
//! gateway account. The account directory and password verifier are interfaces,
//! not an in-memory or insecure placeholder.
use crate::protocol::ClientHandshake;
use hmac::{Hmac, Mac};
use sha2::Sha256;
use std::fmt;
use uuid::Uuid;

type HmacSha256 = Hmac<Sha256>;
pub const TENANT_ASSERTION_ATTRIBUTE: &str = "_proxima_tenant_assertion";
pub const MAX_ASSERTION_TTL_SECONDS: u64 = 3_600;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TenantError {
    InvalidSigningKey,
    MalformedAssertion,
    InvalidSignature,
    ExpiredAssertion,
    AssertionLifetimeExceeded,
    TenantMismatch,
    ClientDatabaseSelection,
    MissingAssertion,
}
impl fmt::Display for TenantError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidSigningKey => write!(f, "tenant signing key must contain at least 32 bytes"),
            Self::MalformedAssertion => write!(f, "malformed Proxima MySQL tenant assertion"),
            Self::InvalidSignature => write!(f, "invalid Proxima MySQL tenant assertion signature"),
            Self::ExpiredAssertion => write!(f, "Proxima MySQL tenant assertion has expired"),
            Self::AssertionLifetimeExceeded => write!(f, "Proxima MySQL tenant assertion lifetime exceeds the one-hour maximum"),
            Self::TenantMismatch => write!(f, "authenticated MySQL account and tenant assertion do not match"),
            Self::ClientDatabaseSelection => write!(f, "client-selected MySQL database is forbidden; routing is server-controlled"),
            Self::MissingAssertion => write!(f, "required Proxima MySQL tenant assertion is missing"),
        }
    }
}
impl std::error::Error for TenantError {}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TenantAssertion {
    pub tenant_id: Uuid,
    pub expires_at: u64,
}

impl TenantAssertion {
    pub fn issue(tenant_id: Uuid, expires_at: u64, key: &[u8]) -> Result<String, TenantError> {
        validate_key(key)?;
        let payload = format!("v1.{tenant_id}.{expires_at}");
        let mut mac = HmacSha256::new_from_slice(key).map_err(|_| TenantError::InvalidSigningKey)?;
        mac.update(payload.as_bytes());
        Ok(format!("{payload}.{}", hex::encode(mac.finalize().into_bytes())))
    }

    pub fn verify(token: &str, key: &[u8], now: u64) -> Result<Self, TenantError> {
        validate_key(key)?;
        let mut parts = token.split('.');
        let version = parts.next().ok_or(TenantError::MalformedAssertion)?;
        let tenant = parts.next().ok_or(TenantError::MalformedAssertion)?;
        let expiry = parts.next().ok_or(TenantError::MalformedAssertion)?;
        let signature = parts.next().ok_or(TenantError::MalformedAssertion)?;
        if version != "v1" || parts.next().is_some() {
            return Err(TenantError::MalformedAssertion);
        }
        let tenant_id = Uuid::parse_str(tenant).map_err(|_| TenantError::MalformedAssertion)?;
        let expires_at = expiry.parse::<u64>().map_err(|_| TenantError::MalformedAssertion)?;
        if expires_at <= now { return Err(TenantError::ExpiredAssertion); }
        if expires_at > now.saturating_add(MAX_ASSERTION_TTL_SECONDS) {
            return Err(TenantError::AssertionLifetimeExceeded);
        }
        let signature = hex::decode(signature).map_err(|_| TenantError::MalformedAssertion)?;
        let payload = format!("v1.{tenant_id}.{expires_at}");
        let mut mac = HmacSha256::new_from_slice(key).map_err(|_| TenantError::InvalidSigningKey)?;
        mac.update(payload.as_bytes());
        mac.verify_slice(&signature).map_err(|_| TenantError::InvalidSignature)?;
        Ok(Self { tenant_id, expires_at })
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TenantRoute {
    pub tenant_id: Uuid,
    pub database_name: String,
}

impl TenantRoute {
    pub fn from_verified_tenant(tenant_id: Uuid) -> Self {
        Self { tenant_id, database_name: format!("ap_t_{}", tenant_id.simple()) }
    }
}

pub fn assertion_from_handshake(handshake: &ClientHandshake) -> Result<&str, TenantError> {
    let mut found = None;
    for (key, value) in &handshake.connection_attributes {
        if key == TENANT_ASSERTION_ATTRIBUTE {
            if found.is_some() { return Err(TenantError::MalformedAssertion); }
            found = Some(value.as_str());
        }
    }
    found.ok_or(TenantError::MissingAssertion)
}

/// Call only after gateway-account authentication and trusted account-to-tenant
/// resolution. This function does not authenticate the MySQL password.
pub fn authorize_handshake(
    handshake: &ClientHandshake,
    authenticated_tenant: Uuid,
    signing_key: &[u8],
    now: u64,
) -> Result<TenantRoute, TenantError> {
    if handshake.requested_database.is_some() {
        return Err(TenantError::ClientDatabaseSelection);
    }
    let token = assertion_from_handshake(handshake)?;
    let assertion = TenantAssertion::verify(token, signing_key, now)?;
    if assertion.tenant_id != authenticated_tenant {
        return Err(TenantError::TenantMismatch);
    }
    Ok(TenantRoute::from_verified_tenant(authenticated_tenant))
}

fn validate_key(key: &[u8]) -> Result<(), TenantError> {
    if key.len() < 32 { return Err(TenantError::InvalidSigningKey); }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::protocol::{ClientHandshake, CLIENT_CONNECT_ATTRS, CLIENT_PROTOCOL_41, CLIENT_SECURE_CONNECTION};
    const KEY: &[u8] = b"0123456789abcdef0123456789abcdef";

    fn handshake(token: &str, requested_database: Option<&str>) -> ClientHandshake {
        ClientHandshake {
            capability_flags: CLIENT_PROTOCOL_41 | CLIENT_SECURE_CONNECTION | CLIENT_CONNECT_ATTRS,
            max_packet_size: 1024,
            character_set: 45,
            username: "gateway_account_a".into(),
            auth_response: vec![1, 2, 3],
            requested_database: requested_database.map(str::to_owned),
            auth_plugin_name: Some("caching_sha2_password".into()),
            connection_attributes: vec![(TENANT_ASSERTION_ATTRIBUTE.into(), token.into())],
        }
    }

    #[test]
    fn valid_assertion_routes_only_to_server_derived_database() {
        let tenant = Uuid::parse_str("aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa").unwrap();
        let token = TenantAssertion::issue(tenant, 500, KEY).unwrap();
        let route = authorize_handshake(&handshake(&token, None), tenant, KEY, 100).unwrap();
        assert_eq!(route.database_name, format!("ap_t_{}", tenant.simple()));
    }

    #[test]
    fn assertion_tampering_is_rejected() {
        let tenant = Uuid::new_v4();
        let token = TenantAssertion::issue(tenant, 500, KEY).unwrap();
        let tampered = token.replace(".500.", ".501.");
        assert_eq!(TenantAssertion::verify(&tampered, KEY, 100), Err(TenantError::InvalidSignature));
    }

    #[test]
    fn expired_assertion_is_rejected() {
        let tenant = Uuid::new_v4();
        let token = TenantAssertion::issue(tenant, 100, KEY).unwrap();
        assert_eq!(TenantAssertion::verify(&token, KEY, 100), Err(TenantError::ExpiredAssertion));
    }


    #[test]
    fn assertion_lifetime_is_limited_to_one_hour() {
        let tenant = Uuid::new_v4();
        let token = TenantAssertion::issue(tenant, 3701, KEY).unwrap();
        assert_eq!(TenantAssertion::verify(&token, KEY, 100), Err(TenantError::AssertionLifetimeExceeded));
    }

    #[test]
    fn cross_tenant_assertion_is_rejected() {
        let tenant_a = Uuid::new_v4();
        let tenant_b = Uuid::new_v4();
        let token = TenantAssertion::issue(tenant_a, 500, KEY).unwrap();
        assert_eq!(authorize_handshake(&handshake(&token, None), tenant_b, KEY, 100), Err(TenantError::TenantMismatch));
    }

    #[test]
    fn client_cannot_select_another_database() {
        let tenant = Uuid::new_v4();
        let token = TenantAssertion::issue(tenant, 500, KEY).unwrap();
        assert_eq!(authorize_handshake(&handshake(&token, Some("tenant_b")), tenant, KEY, 100), Err(TenantError::ClientDatabaseSelection));
    }

    #[test]
    fn short_signing_key_is_rejected() {
        assert_eq!(TenantAssertion::issue(Uuid::new_v4(), 500, b"short"), Err(TenantError::InvalidSigningKey));
    }
}
