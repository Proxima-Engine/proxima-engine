//! One-use, connection-bound policy admission replay protection.
//!
//! The protocol listener must call `consume_for_connection` before admitting a
//! tenant session. A valid signed envelope is accepted by at most one connection
//! per process. Reconnects require fresh evidence and a fresh envelope.

use crate::policy_evidence::{
    AdmissionExpectation, EvidenceError, PolicyEvidenceAuthority,
    SignedPolicyAdmission, SignedPolicyEvidence,
};
use crate::security_core::AccessDecision;
use std::collections::HashMap;
use std::sync::Mutex;

#[derive(Default)]
pub struct ConnectionAdmissionGate {
    consumed: Mutex<HashMap<String, (String, i64)>>,
}

impl ConnectionAdmissionGate {
    pub fn new() -> Self {
        Self::default()
    }

    /// Verify all signed claims and atomically bind this admission to one
    /// connection identifier. Reuse by the same connection is also rejected:
    /// admission is a one-shot transition, not a reusable bearer credential.
    pub fn consume_for_connection(
        &self,
        authority: &PolicyEvidenceAuthority,
        admission: &SignedPolicyAdmission,
        evidence: &SignedPolicyEvidence,
        expected: AdmissionExpectation<'_>,
        connection_id: &str,
        now_unix: i64,
    ) -> Result<AccessDecision, EvidenceError> {
        if connection_id.trim().is_empty() || connection_id.len() > 256 {
            return Err(EvidenceError {
                code: "invalid_connection_id",
                detail: "A non-empty, bounded protocol connection identifier is required.",
            });
        }

        // Cryptographic, freshness, target, revision and tenant checks happen
        // before consuming the replay slot. Invalid attempts cannot burn a
        // legitimate admission belonging to a valid connection.
        authority.verify_admission(admission, evidence, expected, now_unix)?;

        let mut consumed = self.consumed.lock().map_err(|_| EvidenceError {
            code: "admission_gate_unavailable",
            detail: "The in-process admission replay registry is unavailable; access is denied.",
        })?;

        consumed.retain(|_, (_, expires_at)| *expires_at > now_unix);
        let key = admission.signature.clone();
        if consumed.contains_key(&key) {
            return Err(EvidenceError {
                code: "admission_replay_detected",
                detail: "This signed admission has already been consumed by a protocol connection.",
            });
        }

        consumed.insert(key, (connection_id.to_owned(), admission.expires_at_unix));
        Ok(AccessDecision::Allow)
    }

    /// Number of unexpired admissions currently held by this process.
    /// Exposed for health/diagnostic tests, never as an authorization decision.
    pub fn active_consumptions(&self, now_unix: i64) -> Result<usize, EvidenceError> {
        let mut consumed = self.consumed.lock().map_err(|_| EvidenceError {
            code: "admission_gate_unavailable",
            detail: "The in-process admission replay registry is unavailable.",
        })?;
        consumed.retain(|_, (_, expires_at)| *expires_at > now_unix);
        Ok(consumed.len())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::policy_evidence::{EvidenceCheck, PolicyEvidenceAuthority};
    use crate::security_core::{
        DatabaseKind, InspectionCompleteness, Operation, SecurityFinding, SecurityPosture,
        SECURITY_MODEL_VERSION,
    };

    fn authority() -> PolicyEvidenceAuthority {
        PolicyEvidenceAuthority::new(vec![11; 32], vec![19; 32]).unwrap()
    }

    fn signed_pair(authority: &PolicyEvidenceAuthority) -> (SignedPolicyEvidence, SignedPolicyAdmission) {
        let payload = PolicyEvidencePayload {
            model_version: SECURITY_MODEL_VERSION.into(),
            policy_id: "tenant-boundary".into(),
            policy_revision: 3,
            database_kind: DatabaseKind::PostgreSql,
            target_id: "prod-db".into(),
            tenant_id: "tenant-a".into(),
            posture: SecurityPosture::Verified,
            inspection: InspectionCompleteness::Complete,
            findings: Vec::<SecurityFinding>::new(),
            verified_operations: vec![Operation::Read, Operation::Create, Operation::Update, Operation::Delete],
            fingerprint: "c".repeat(64),
            observed_at_unix: 1_900_000_000,
            checks: vec![
                EvidenceCheck { check_id: "own-tenant-allow".into(), passed: true, detail: "own tenant allowed".into() },
                EvidenceCheck { check_id: "cross-tenant-deny".into(), passed: true, detail: "other tenant denied".into() },
            ],
        };
        let evidence = authority.sign_evidence(payload).unwrap();
        let admission = authority.issue_admission(&evidence, 1_900_000_001, 30).unwrap();
        (evidence, admission)
    }

    fn expected() -> AdmissionExpectation<'static> {
        AdmissionExpectation { database_kind: DatabaseKind::PostgreSql, policy_id: "tenant-boundary", policy_revision: 3, target_id: "prod-db", tenant_id: "tenant-a" }
    }

    #[test]
    fn admission_is_consumed_once() {
        let authority = authority();
        let gate = ConnectionAdmissionGate::new();
        let (evidence, admission) = signed_pair(&authority);
        assert_eq!(gate.consume_for_connection(&authority, &admission, &evidence, expected(), "conn-1", 1_900_000_002), Ok(AccessDecision::Allow));
        assert_eq!(gate.consume_for_connection(&authority, &admission, &evidence, expected(), "conn-1", 1_900_000_003).unwrap_err().code, "admission_replay_detected");
    }

    #[test]
    fn admission_cannot_be_replayed_on_another_connection() {
        let authority = authority();
        let gate = ConnectionAdmissionGate::new();
        let (evidence, admission) = signed_pair(&authority);
        gate.consume_for_connection(&authority, &admission, &evidence, expected(), "conn-tenant-a", 1_900_000_002).unwrap();
        assert_eq!(gate.consume_for_connection(&authority, &admission, &evidence, expected(), "conn-tenant-b", 1_900_000_003).unwrap_err().code, "admission_replay_detected");
    }

    #[test]
    fn expired_entries_are_pruned() {
        let authority = authority();
        let gate = ConnectionAdmissionGate::new();
        let (evidence, admission) = signed_pair(&authority);
        gate.consume_for_connection(&authority, &admission, &evidence, expected(), "conn-1", 1_900_000_002).unwrap();
        assert_eq!(gate.active_consumptions(1_900_000_031).unwrap(), 0);
    }

    #[test]
    fn invalid_connection_identifier_fails_closed() {
        let authority = authority();
        let gate = ConnectionAdmissionGate::new();
        let (evidence, admission) = signed_pair(&authority);
        assert_eq!(gate.consume_for_connection(&authority, &admission, &evidence, expected(), "", 1_900_000_002).unwrap_err().code, "invalid_connection_id");
    }
}
