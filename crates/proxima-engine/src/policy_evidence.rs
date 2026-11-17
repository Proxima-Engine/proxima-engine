//! Signed policy evidence and short-lived runtime-admission envelopes.
//!
//! This module defines cryptographic objects and fail-closed verification rules.
//! A runtime must still call the verifier at its protocol admission boundary and
//! obtain evidence from a trusted native database inspector before using it.

use crate::security_core::{
    AccessDecision, DatabaseKind, InspectionCompleteness, Operation, SecurityFinding,
    SecurityPosture, SECURITY_MODEL_VERSION,
};
use hmac::{Hmac, Mac};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

type HmacSha256 = Hmac<Sha256>;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EvidenceError {
    pub code: &'static str,
    pub detail: &'static str,
}

fn error(code: &'static str, detail: &'static str) -> EvidenceError {
    EvidenceError { code, detail }
}

fn validate_key(key: &[u8]) -> Result<(), EvidenceError> {
    if key.len() < 32 {
        return Err(error("signing_key_too_short", "Policy evidence and admission keys must contain at least 32 bytes."));
    }
    Ok(())
}

fn sign_bytes(key: &[u8], payload: &[u8]) -> Result<String, EvidenceError> {
    validate_key(key)?;
    let mut mac = HmacSha256::new_from_slice(key)
        .map_err(|_| error("invalid_signing_key", "The HMAC signing key could not be initialized."))?;
    mac.update(payload);
    Ok(hex::encode(mac.finalize().into_bytes()))
}

fn verify_bytes(key: &[u8], payload: &[u8], signature: &str) -> Result<(), EvidenceError> {
    validate_key(key)?;
    let signature = hex::decode(signature)
        .map_err(|_| error("invalid_signature_encoding", "The signature is not valid hexadecimal."))?;
    let mut mac = HmacSha256::new_from_slice(key)
        .map_err(|_| error("invalid_signing_key", "The HMAC verification key could not be initialized."))?;
    mac.update(payload);
    mac.verify_slice(&signature)
        .map_err(|_| error("signature_mismatch", "The signed policy object has been modified or was signed by another authority."))
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EvidenceCheck {
    pub check_id: String,
    pub passed: bool,
    pub detail: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PolicyEvidencePayload {
    pub model_version: String,
    pub policy_id: String,
    pub policy_revision: u64,
    pub database_kind: DatabaseKind,
    pub target_id: String,
    pub tenant_id: String,
    pub posture: SecurityPosture,
    pub inspection: InspectionCompleteness,
    pub findings: Vec<SecurityFinding>,
    pub verified_operations: Vec<Operation>,
    pub fingerprint: String,
    pub observed_at_unix: i64,
    pub checks: Vec<EvidenceCheck>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SignedPolicyEvidence {
    pub payload: PolicyEvidencePayload,
    pub signature: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SignedPolicyAdmission {
    pub model_version: String,
    pub policy_id: String,
    pub policy_revision: u64,
    pub target_id: String,
    pub tenant_id: String,
    pub issued_at_unix: i64,
    pub expires_at_unix: i64,
    pub evidence_sha256: String,
    pub signature: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AdmissionExpectation<'a> {
    pub database_kind: DatabaseKind,
    pub policy_id: &'a str,
    pub policy_revision: u64,
    pub target_id: &'a str,
    pub tenant_id: &'a str,
}

#[derive(Clone)]
pub struct PolicyEvidenceAuthority {
    evidence_key: Vec<u8>,
    admission_key: Vec<u8>,
}

impl PolicyEvidenceAuthority {
    pub fn new(evidence_key: Vec<u8>, admission_key: Vec<u8>) -> Result<Self, EvidenceError> {
        validate_key(&evidence_key)?;
        validate_key(&admission_key)?;
        Ok(Self { evidence_key, admission_key })
    }

    /// Sign a complete inspection result, including failures. Signing evidence
    /// does not make an insecure result eligible for runtime admission.
    pub fn sign_evidence(&self, payload: PolicyEvidencePayload) -> Result<SignedPolicyEvidence, EvidenceError> {
        validate_evidence_payload(&payload)?;
        let bytes = serde_json::to_vec(&payload)
            .map_err(|_| error("evidence_serialization_failed", "The evidence payload could not be serialized."))?;
        let signature = sign_bytes(&self.evidence_key, &bytes)?;
        Ok(SignedPolicyEvidence { payload, signature })
    }

    pub fn verify_evidence(&self, evidence: &SignedPolicyEvidence) -> Result<(), EvidenceError> {
        validate_evidence_payload(&evidence.payload)?;
        let bytes = serde_json::to_vec(&evidence.payload)
            .map_err(|_| error("evidence_serialization_failed", "The evidence payload could not be serialized."))?;
        verify_bytes(&self.evidence_key, &bytes, &evidence.signature)
    }

    /// Issue a short-lived admission envelope only for complete, clean evidence
    /// with successful positive/negative checks and an explicit operation set.
    pub fn issue_admission(
        &self,
        evidence: &SignedPolicyEvidence,
        issued_at_unix: i64,
        lifetime_seconds: i64,
    ) -> Result<SignedPolicyAdmission, EvidenceError> {
        self.verify_evidence(evidence)?;
        validate_admission_eligibility(&evidence.payload)?;
        if issued_at_unix < evidence.payload.observed_at_unix || issued_at_unix - evidence.payload.observed_at_unix > 60 {
            return Err(error("evidence_stale", "Policy evidence must be no more than 60 seconds old when admission is issued."));
        }
        if !(1..=60).contains(&lifetime_seconds) {
            return Err(error("invalid_admission_lifetime", "Runtime admission envelopes must expire within 1 to 60 seconds."));
        }
        let expires_at_unix = issued_at_unix.checked_add(lifetime_seconds)
            .ok_or_else(|| error("invalid_admission_lifetime", "The admission expiry timestamp overflowed."))?;
        let evidence_bytes = serde_json::to_vec(evidence)
            .map_err(|_| error("evidence_serialization_failed", "The signed evidence could not be serialized."))?;
        let evidence_sha256 = hex::encode(Sha256::digest(&evidence_bytes));
        let mut admission = SignedPolicyAdmission {
            model_version: SECURITY_MODEL_VERSION.into(),
            policy_id: evidence.payload.policy_id.clone(),
            policy_revision: evidence.payload.policy_revision,
            target_id: evidence.payload.target_id.clone(),
            tenant_id: evidence.payload.tenant_id.clone(),
            issued_at_unix,
            expires_at_unix,
            evidence_sha256,
            signature: String::new(),
        };
        admission.signature = sign_bytes(&self.admission_key, &admission_claims_bytes(&admission)?)?;
        Ok(admission)
    }

    /// Verify the admission signature, exact policy/target/tenant binding,
    /// evidence digest, evidence signature and short expiry window.
    pub fn verify_admission(
        &self,
        admission: &SignedPolicyAdmission,
        evidence: &SignedPolicyEvidence,
        expected: AdmissionExpectation<'_>,
        now_unix: i64,
    ) -> Result<AccessDecision, EvidenceError> {
        self.verify_evidence(evidence)?;
        let payload = &evidence.payload;
        if admission.model_version != SECURITY_MODEL_VERSION || payload.model_version != SECURITY_MODEL_VERSION {
            return Err(error("unsupported_security_model", "The admission or evidence uses an unknown security-model version."));
        }
        if payload.database_kind != expected.database_kind {
            return Err(error("database_kind_mismatch", "The signed evidence belongs to a different database engine than the requested target."));
        }
        if admission.policy_id != expected.policy_id || admission.policy_revision != expected.policy_revision
            || payload.policy_id != expected.policy_id || payload.policy_revision != expected.policy_revision {
            return Err(error("policy_revision_mismatch", "The admission and evidence do not match the requested policy revision."));
        }
        if admission.target_id != expected.target_id || payload.target_id != expected.target_id {
            return Err(error("target_mismatch", "The admission and evidence are bound to a different database target."));
        }
        if admission.tenant_id != expected.tenant_id || payload.tenant_id != expected.tenant_id {
            return Err(error("tenant_mismatch", "The admission and evidence are bound to a different tenant."));
        }
        if admission.issued_at_unix > now_unix {
            return Err(error("admission_not_yet_valid", "The admission envelope is not valid yet."));
        }
        if admission.expires_at_unix <= now_unix {
            return Err(error("admission_expired", "The admission envelope has expired."));
        }
        let lifetime = admission.expires_at_unix.checked_sub(admission.issued_at_unix)
            .ok_or_else(|| error("invalid_admission_lifetime", "The admission timestamps are inconsistent."))?;
        if !(1..=60).contains(&lifetime) {
            return Err(error("invalid_admission_lifetime", "The admission lifetime exceeds the 60-second maximum."));
        }
        if payload.observed_at_unix > admission.issued_at_unix
            || admission.issued_at_unix.checked_sub(payload.observed_at_unix).map_or(true, |age| age > 60) {
            return Err(error("evidence_stale", "The signed evidence was not fresh when this admission was issued."));
        }
        let evidence_bytes = serde_json::to_vec(evidence)
            .map_err(|_| error("evidence_serialization_failed", "The signed evidence could not be serialized."))?;
        let digest = hex::encode(Sha256::digest(&evidence_bytes));
        if admission.evidence_sha256 != digest {
            return Err(error("evidence_digest_mismatch", "The admission does not reference this exact signed evidence record."));
        }
        verify_bytes(&self.admission_key, &admission_claims_bytes(admission)?, &admission.signature)?;
        validate_admission_eligibility(payload)?;
        Ok(AccessDecision::Allow)
    }
}

fn admission_claims_bytes(admission: &SignedPolicyAdmission) -> Result<Vec<u8>, EvidenceError> {
    #[derive(Serialize)]
    struct Claims<'a> {
        model_version: &'a str,
        policy_id: &'a str,
        policy_revision: u64,
        target_id: &'a str,
        tenant_id: &'a str,
        issued_at_unix: i64,
        expires_at_unix: i64,
        evidence_sha256: &'a str,
    }
    serde_json::to_vec(&Claims {
        model_version: &admission.model_version,
        policy_id: &admission.policy_id,
        policy_revision: admission.policy_revision,
        target_id: &admission.target_id,
        tenant_id: &admission.tenant_id,
        issued_at_unix: admission.issued_at_unix,
        expires_at_unix: admission.expires_at_unix,
        evidence_sha256: &admission.evidence_sha256,
    }).map_err(|_| error("admission_serialization_failed", "The admission claims could not be serialized."))
}

fn validate_evidence_payload(payload: &PolicyEvidencePayload) -> Result<(), EvidenceError> {
    if payload.model_version != SECURITY_MODEL_VERSION || payload.policy_id.trim().is_empty()
        || payload.policy_revision == 0 || payload.target_id.trim().is_empty()
        || payload.tenant_id.trim().is_empty() || payload.fingerprint.len() != 64
        || hex::decode(&payload.fingerprint).map_or(true, |bytes| bytes.len() != 32)
        || payload.observed_at_unix < 0 {
        return Err(error("invalid_evidence_payload", "The policy evidence is missing a required identity, revision, fingerprint or timestamp."));
    }
    Ok(())
}

fn validate_admission_eligibility(payload: &PolicyEvidencePayload) -> Result<(), EvidenceError> {
    if payload.posture != SecurityPosture::Verified || payload.inspection != InspectionCompleteness::Complete
        || !payload.findings.is_empty() || payload.verified_operations.is_empty()
        || payload.checks.is_empty() || payload.checks.iter().any(|check| !check.passed) {
        return Err(error("evidence_not_admissible", "Only complete, verified evidence with no findings, explicit operations and all checks passing can authorize runtime admission."));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn authority() -> PolicyEvidenceAuthority {
        PolicyEvidenceAuthority::new(vec![7; 32], vec![9; 32]).unwrap()
    }

    fn evidence_payload() -> PolicyEvidencePayload {
        PolicyEvidencePayload {
            model_version: SECURITY_MODEL_VERSION.into(),
            policy_id: "tenant-data".into(),
            policy_revision: 4,
            database_kind: DatabaseKind::PostgreSql,
            target_id: "db-prod-01".into(),
            tenant_id: "tenant-a".into(),
            posture: SecurityPosture::Verified,
            inspection: InspectionCompleteness::Complete,
            findings: vec![],
            verified_operations: vec![Operation::Read, Operation::Create, Operation::Update, Operation::Delete],
            fingerprint: "a".repeat(64),
            observed_at_unix: 1_800_000_000,
            checks: vec![
                EvidenceCheck { check_id: "tenant-a-allow".into(), passed: true, detail: "own tenant access allowed".into() },
                EvidenceCheck { check_id: "tenant-b-deny".into(), passed: true, detail: "cross-tenant access denied".into() },
            ],
        }
    }

    fn expected() -> AdmissionExpectation<'static> {
        AdmissionExpectation { database_kind: DatabaseKind::PostgreSql, policy_id: "tenant-data", policy_revision: 4, target_id: "db-prod-01", tenant_id: "tenant-a" }
    }

    #[test]
    fn signed_evidence_and_short_lived_admission_verify() {
        let authority = authority();
        let evidence = authority.sign_evidence(evidence_payload()).unwrap();
        let admission = authority.issue_admission(&evidence, 1_800_000_010, 30).unwrap();
        assert_eq!(authority.verify_admission(&admission, &evidence, expected(), 1_800_000_020), Ok(AccessDecision::Allow));
    }

    #[test]
    fn modified_evidence_is_rejected() {
        let authority = authority();
        let mut evidence = authority.sign_evidence(evidence_payload()).unwrap();
        evidence.payload.fingerprint = "b".repeat(64);
        assert_eq!(authority.verify_evidence(&evidence).unwrap_err().code, "signature_mismatch");
    }

    #[test]
    fn admission_is_bound_to_exact_policy_target_and_tenant() {
        let authority = authority();
        let evidence = authority.sign_evidence(evidence_payload()).unwrap();
        let admission = authority.issue_admission(&evidence, 1_800_000_010, 30).unwrap();
        let wrong_tenant = AdmissionExpectation { tenant_id: "tenant-b", ..expected() };
        assert_eq!(authority.verify_admission(&admission, &evidence, wrong_tenant, 1_800_000_020).unwrap_err().code, "tenant_mismatch");
    }

    #[test]
    fn expired_and_overlong_admissions_are_rejected() {
        let authority = authority();
        let evidence = authority.sign_evidence(evidence_payload()).unwrap();
        assert_eq!(authority.issue_admission(&evidence, 1_800_000_010, 61).unwrap_err().code, "invalid_admission_lifetime");
        let admission = authority.issue_admission(&evidence, 1_800_000_010, 30).unwrap();
        assert_eq!(authority.verify_admission(&admission, &evidence, expected(), 1_800_000_040).unwrap_err().code, "admission_expired");
    }

    #[test]
    fn incomplete_or_failing_evidence_cannot_issue_admission() {
        let authority = authority();
        let mut payload = evidence_payload();
        payload.inspection = InspectionCompleteness::Incomplete;
        let evidence = authority.sign_evidence(payload).unwrap();
        assert_eq!(authority.issue_admission(&evidence, 1_800_000_010, 30).unwrap_err().code, "evidence_not_admissible");
    }

    #[test]
    fn short_signing_keys_are_rejected() {
        let result = PolicyEvidenceAuthority::new(vec![1; 16], vec![2; 32]);
        assert!(matches!(result, Err(error) if error.code == "signing_key_too_short"));
    }
}
