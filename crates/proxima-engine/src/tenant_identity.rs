//! Cross-database trusted tenant identity claims.
//!
//! Tokens are bound to one authenticated principal, tenant, database target,
//! database family, policy revision, and short validity window. A verified
//! identity is a distinct type so callers cannot treat decoded, unsigned claims
//! as trusted context.

use crate::{policy_evidence::AdmissionExpectation, security_core::DatabaseKind};
use hmac::{Hmac, Mac};
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use std::fmt;

type HmacSha256 = Hmac<Sha256>;
const TOKEN_VERSION: &str = "pti1";
const CLAIMS_VERSION: &str = "proxima.tenant-identity.v1";
const SIGNING_DOMAIN: &[u8] = b"proxima-tenant-identity-v1\0";
const MAX_TOKEN_BYTES: usize = 16 * 1024;
const MAX_IDENTITY_LIFETIME_SECONDS: i64 = 60;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TenantIdentityError {
    pub code: &'static str,
    pub detail: &'static str,
}

impl fmt::Display for TenantIdentityError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{}: {}", self.code, self.detail)
    }
}

impl std::error::Error for TenantIdentityError {}

fn error(code: &'static str, detail: &'static str) -> TenantIdentityError {
    TenantIdentityError { code, detail }
}

/// Claims produced by a trusted identity issuer. The principal and tenant
/// relationship must come from authenticated control-plane identity.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TenantIdentityClaims {
    pub schema_version: String,
    pub tenant_id: String,
    pub principal_id: String,
    pub target_id: String,
    pub database_kind: DatabaseKind,
    pub policy_id: String,
    pub policy_revision: u64,
    pub request_id: String,
    pub issued_at_unix: i64,
    pub expires_at_unix: i64,
}

/// Scope expected by the receiving database runtime.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct TenantIdentityExpectation<'a> {
    pub tenant_id: &'a str,
    pub principal_id: &'a str,
    pub target_id: &'a str,
    pub database_kind: DatabaseKind,
    pub policy_id: &'a str,
    pub policy_revision: u64,
}

/// A verified identity has private claims and can only be constructed by
/// TenantIdentityAuthority after signature, lifetime, and scope checks pass.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct VerifiedTenantIdentity {
    claims: TenantIdentityClaims,
}

impl VerifiedTenantIdentity {
    pub fn tenant_id(&self) -> &str { &self.claims.tenant_id }
    pub fn principal_id(&self) -> &str { &self.claims.principal_id }
    pub fn target_id(&self) -> &str { &self.claims.target_id }
    pub fn database_kind(&self) -> DatabaseKind { self.claims.database_kind }
    pub fn policy_id(&self) -> &str { &self.claims.policy_id }
    pub fn policy_revision(&self) -> u64 { self.claims.policy_revision }
    pub fn request_id(&self) -> &str { &self.claims.request_id }
    pub fn issued_at_unix(&self) -> i64 { self.claims.issued_at_unix }
    pub fn expires_at_unix(&self) -> i64 { self.claims.expires_at_unix }

    /// Derive admission expectations from verified claims instead of accepting
    /// separate caller-supplied tenant, target, or policy values.
    pub fn admission_expectation(&self) -> AdmissionExpectation<'_> {
        AdmissionExpectation {
            database_kind: self.claims.database_kind,
            policy_id: &self.claims.policy_id,
            policy_revision: self.claims.policy_revision,
            target_id: &self.claims.target_id,
            tenant_id: &self.claims.tenant_id,
        }
    }
}

#[derive(Clone)]
pub struct TenantIdentityAuthority {
    key: Vec<u8>,
}

impl TenantIdentityAuthority {
    pub fn new(key: impl AsRef<[u8]>) -> Result<Self, TenantIdentityError> {
        let key = key.as_ref();
        if key.len() < 32 {
            return Err(error("identity_key_too_short", "Tenant identity signing keys must contain at least 32 bytes."));
        }
        Ok(Self { key: key.to_vec() })
    }

    /// Sign one exact, short-lived tenant/database/policy scope.
    pub fn sign(&self, claims: &TenantIdentityClaims, now_unix: i64) -> Result<String, TenantIdentityError> {
        validate_claims(claims)?;
        validate_time(claims, now_unix)?;
        let payload = serde_json::to_vec(claims)
            .map_err(|_| error("identity_serialization_failed", "Tenant identity claims could not be serialized."))?;
        let mut mac = HmacSha256::new_from_slice(&self.key)
            .map_err(|_| error("identity_key_invalid", "Tenant identity signing key could not be initialized."))?;
        mac.update(SIGNING_DOMAIN);
        mac.update(&payload);
        Ok(format!("{TOKEN_VERSION}.{}.{}", hex::encode(payload), hex::encode(mac.finalize().into_bytes())))
    }

    /// Verify signature, short lifetime, and every expected scope field.
    pub fn verify(
        &self,
        token: &str,
        expected: TenantIdentityExpectation<'_>,
        now_unix: i64,
    ) -> Result<VerifiedTenantIdentity, TenantIdentityError> {
        if token.len() > MAX_TOKEN_BYTES {
            return Err(error("identity_token_too_large", "Tenant identity token exceeds the configured size bound."));
        }
        let mut parts = token.split('.');
        if parts.next() != Some(TOKEN_VERSION) {
            return Err(error("identity_token_version_invalid", "Tenant identity token has an unsupported version."));
        }
        let encoded_payload = parts.next().ok_or_else(|| error("identity_token_malformed", "Tenant identity token is incomplete."))?;
        let encoded_signature = parts.next().ok_or_else(|| error("identity_token_malformed", "Tenant identity token is incomplete."))?;
        if parts.next().is_some() {
            return Err(error("identity_token_malformed", "Tenant identity token contains extra fields."));
        }
        let payload = hex::decode(encoded_payload)
            .map_err(|_| error("identity_token_malformed", "Tenant identity payload is not valid hexadecimal."))?;
        let signature = hex::decode(encoded_signature)
            .map_err(|_| error("identity_token_malformed", "Tenant identity signature is not valid hexadecimal."))?;
        let mut mac = HmacSha256::new_from_slice(&self.key)
            .map_err(|_| error("identity_key_invalid", "Tenant identity verification key could not be initialized."))?;
        mac.update(SIGNING_DOMAIN);
        mac.update(&payload);
        mac.verify_slice(&signature)
            .map_err(|_| error("identity_signature_invalid", "Tenant identity signature verification failed."))?;
        let claims: TenantIdentityClaims = serde_json::from_slice(&payload)
            .map_err(|_| error("identity_claims_invalid", "Signed tenant identity claims are malformed or contain unknown fields."))?;
        validate_claims(&claims)?;
        validate_time(&claims, now_unix)?;
        if claims.tenant_id != expected.tenant_id
            || claims.principal_id != expected.principal_id
            || claims.target_id != expected.target_id
            || claims.database_kind != expected.database_kind
            || claims.policy_id != expected.policy_id
            || claims.policy_revision != expected.policy_revision
        {
            return Err(error("identity_scope_mismatch", "Tenant identity is not bound to the authenticated principal, database target, engine, tenant, and exact policy revision."));
        }
        Ok(VerifiedTenantIdentity { claims })
    }
}

fn valid_text(value: &str, max_bytes: usize) -> bool {
    !value.trim().is_empty() && value.len() <= max_bytes && !value.contains('\0')
}

fn validate_claims(claims: &TenantIdentityClaims) -> Result<(), TenantIdentityError> {
    let lifetime = claims.expires_at_unix.checked_sub(claims.issued_at_unix);
    if claims.schema_version != CLAIMS_VERSION
        || !valid_text(&claims.tenant_id, 128)
        || !valid_text(&claims.principal_id, 256)
        || !valid_text(&claims.target_id, 256)
        || !valid_text(&claims.policy_id, 128)
        || !valid_text(&claims.request_id, 128)
        || claims.policy_revision == 0
        || claims.issued_at_unix < 0
        || claims.expires_at_unix <= claims.issued_at_unix
        || lifetime.map_or(true, |seconds| seconds > MAX_IDENTITY_LIFETIME_SECONDS)
    {
        return Err(error("identity_claims_invalid", "Tenant identity claims are incomplete, malformed, or exceed the 60-second lifetime bound."));
    }
    Ok(())
}

fn validate_time(claims: &TenantIdentityClaims, now_unix: i64) -> Result<(), TenantIdentityError> {
    if now_unix < claims.issued_at_unix {
        return Err(error("identity_not_yet_valid", "Tenant identity is not valid yet."));
    }
    if now_unix >= claims.expires_at_unix {
        return Err(error("identity_expired", "Tenant identity has expired."));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn authority() -> TenantIdentityAuthority {
        TenantIdentityAuthority::new([7; 32]).unwrap()
    }

    fn claims() -> TenantIdentityClaims {
        TenantIdentityClaims {
            schema_version: CLAIMS_VERSION.into(),
            tenant_id: "tenant-a".into(),
            principal_id: "app-service-7".into(),
            target_id: "db-target-1".into(),
            database_kind: DatabaseKind::PostgreSql,
            policy_id: "tenant-boundary".into(),
            policy_revision: 9,
            request_id: "req-1".into(),
            issued_at_unix: 1_900_000_000,
            expires_at_unix: 1_900_000_030,
        }
    }

    fn expected() -> TenantIdentityExpectation<'static> {
        TenantIdentityExpectation {
            tenant_id: "tenant-a",
            principal_id: "app-service-7",
            target_id: "db-target-1",
            database_kind: DatabaseKind::PostgreSql,
            policy_id: "tenant-boundary",
            policy_revision: 9,
        }
    }

    #[test]
    fn identity_is_bound_to_principal_database_and_policy_revision() {
        let authority = authority();
        let token = authority.sign(&claims(), 1_900_000_001).unwrap();
        let verified = authority.verify(&token, expected(), 1_900_000_002).unwrap();
        assert_eq!(verified.tenant_id(), "tenant-a");
        assert_eq!(verified.target_id(), "db-target-1");
        assert_eq!(verified.admission_expectation().policy_revision, 9);

        let wrong_target = TenantIdentityExpectation { target_id: "other-db", ..expected() };
        assert_eq!(authority.verify(&token, wrong_target, 1_900_000_002).unwrap_err().code, "identity_scope_mismatch");
        let wrong_kind = TenantIdentityExpectation { database_kind: DatabaseKind::MySql, ..expected() };
        assert_eq!(authority.verify(&token, wrong_kind, 1_900_000_002).unwrap_err().code, "identity_scope_mismatch");
        let wrong_policy = TenantIdentityExpectation { policy_revision: 10, ..expected() };
        assert_eq!(authority.verify(&token, wrong_policy, 1_900_000_002).unwrap_err().code, "identity_scope_mismatch");
        let wrong_principal = TenantIdentityExpectation { principal_id: "other-app", ..expected() };
        assert_eq!(authority.verify(&token, wrong_principal, 1_900_000_002).unwrap_err().code, "identity_scope_mismatch");
    }

    #[test]
    fn tampering_and_expiry_are_rejected() {
        let authority = authority();
        let token = authority.sign(&claims(), 1_900_000_001).unwrap();
        let mut parts = token.split('.').map(str::to_owned).collect::<Vec<_>>();
        parts[1].push_str("00");
        assert_eq!(
            authority.verify(&parts.join("."), expected(), 1_900_000_002).unwrap_err().code,
            "identity_signature_invalid"
        );
        assert_eq!(authority.verify(&token, expected(), 1_900_000_030).unwrap_err().code, "identity_expired");

        let mut long_lived = claims();
        long_lived.expires_at_unix = long_lived.issued_at_unix + 61;
        assert_eq!(authority.sign(&long_lived, 1_900_000_001).unwrap_err().code, "identity_claims_invalid");
    }
}
