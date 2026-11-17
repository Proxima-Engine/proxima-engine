//! Fail-closed orchestration for the database-independent Security Core.
//!
//! This module centralizes the inspection, compilation and drift lifecycle. It
//! deliberately does not apply generated policy: native changes require a
//! separately authorized deployment workflow.

use crate::connection_admission::ConnectionAdmissionGate;
use crate::database_adapter::{AdapterError, AdapterRegistry, AdapterTarget, CompiledPolicy, DriftReport, InspectionRequest, InspectionSnapshot};
use crate::policy_evidence::{EvidenceError, PolicyEvidenceAuthority, SignedPolicyAdmission, SignedPolicyEvidence};
use crate::tenant_identity::VerifiedTenantIdentity;
use crate::security_core::{AccessDecision, DatabaseKind, InspectionCompleteness, SecurityFinding, SecurityPosture, TenantSecurityPolicy, VerificationReport, SECURITY_MODEL_VERSION};
use std::collections::HashSet;

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum SecurityCoreError {
    AdapterUnavailable(DatabaseKind),
    InvalidPolicy,
    Adapter(AdapterError),
    SnapshotTargetMismatch,
    SnapshotKindMismatch,
    IncompleteInspection,
    DuplicateInspectedResource(String),
    InvalidCompilation,
    DriftInspectionIncomplete,
    DriftFingerprintMismatch,
    InvalidFingerprint,
    DuplicateCompiledResource(String),
    Admission(EvidenceError),
    IdentityScopeMismatch,
    EvidenceScopeMismatch,
    EvidenceCoverageIncomplete,
}

impl From<AdapterError> for SecurityCoreError {
    fn from(error: AdapterError) -> Self { Self::Adapter(error) }
}

impl From<EvidenceError> for SecurityCoreError {
    fn from(error: EvidenceError) -> Self { Self::Admission(error) }
}

pub struct SecurityCoreCoordinator { registry: AdapterRegistry }

impl SecurityCoreCoordinator {
    pub fn new(registry: AdapterRegistry) -> Self { Self { registry } }
    pub fn registry(&self) -> &AdapterRegistry { &self.registry }

    /// Generate a reviewable native plan. Applying it is intentionally separate.
    pub fn compile(&self, kind: DatabaseKind, policy: &TenantSecurityPolicy) -> Result<CompiledPolicy, SecurityCoreError> {
        policy.validate().map_err(|_| SecurityCoreError::InvalidPolicy)?;
        let adapter = self.registry.get(kind).ok_or(SecurityCoreError::AdapterUnavailable(kind))?;
        let compiled = adapter.compile_policy(policy)?;
        if compiled.database_kind != kind || compiled.policy_id != policy.policy_id || compiled.revision != policy.revision || !compiled.requires_approval || compiled.changes.is_empty() {
            return Err(SecurityCoreError::InvalidCompilation);
        }
        let mut covered = HashSet::new();
        for change in &compiled.changes {
            if change.action.trim().is_empty() || change.definition.is_null() { return Err(SecurityCoreError::InvalidCompilation); }
            if !covered.insert(change.resource.resource.clone()) {
                return Err(SecurityCoreError::DuplicateCompiledResource(change.resource.resource.name.clone()));
            }
        }
        if covered.len() != policy.resources.len()
            || policy.resources.iter().any(|item| !covered.contains(&item.resource))
        {
            return Err(SecurityCoreError::InvalidCompilation);
        }
        for change in &compiled.changes {
            let Some(required) = policy.resources.iter().find(|item| item.resource == change.resource.resource) else {
                return Err(SecurityCoreError::InvalidCompilation);
            };
            if change.resource.tenant_key != required.tenant_key
                || required.operations.iter().any(|operation| !change.resource.operations.contains(operation))
            {
                return Err(SecurityCoreError::InvalidCompilation);
            }
        }
        Ok(compiled)
    }

    /// Inspect and semantically verify native state. Any missing resource or
    /// operation, incomplete inspection, finding, or identity mismatch denies.
    pub async fn inspect_and_verify(&self, kind: DatabaseKind, request: &InspectionRequest) -> Result<VerificationReport, SecurityCoreError> {
        self.inspect_and_verify_snapshot(kind, request).await.map(|(report, _)| report)
    }

    /// Inspect and semantically verify native state. Any missing resource or
    /// operation, incomplete inspection, finding, or identity mismatch denies.
    async fn inspect_and_verify_snapshot(&self, kind: DatabaseKind, request: &InspectionRequest) -> Result<(VerificationReport, InspectionSnapshot), SecurityCoreError> {
        request.policy.validate().map_err(|_| SecurityCoreError::InvalidPolicy)?;
        let adapter = self.registry.get(kind).ok_or(SecurityCoreError::AdapterUnavailable(kind))?;
        let snapshot = adapter.inspect(request).await?;
        self.validate_snapshot(kind, request, &snapshot)?;
        let mut report = adapter.verify(&request.policy, &snapshot).await?;
        let mut failures = Vec::new();
        if snapshot.completeness != InspectionCompleteness::Complete || snapshot.posture != SecurityPosture::Verified || !snapshot.findings.is_empty() {
            failures.push(SecurityFinding { code: "native_inspection_not_clean".into(), resource: None, detail: "Native inspection is incomplete or reports an unverified posture.".into() });
            failures.extend(snapshot.findings.iter().cloned());
        }
        let mut seen = HashSet::new();
        for item in &snapshot.resources {
            if !seen.insert(item.resource.resource.clone()) { return Err(SecurityCoreError::DuplicateInspectedResource(item.resource.resource.name.clone())); }
        }
        for required in &request.policy.resources {
            let Some(actual) = snapshot.resources.iter().find(|item| item.resource.resource == required.resource) else {
                failures.push(SecurityFinding { code: "required_resource_not_inspected".into(), resource: Some(required.resource.clone()), detail: "A protected resource is absent from the inspection snapshot.".into() });
                continue;
            };
            if actual.completeness != InspectionCompleteness::Complete || actual.posture != SecurityPosture::Verified || !actual.findings.is_empty() {
                failures.push(SecurityFinding { code: "resource_posture_not_verified".into(), resource: Some(required.resource.clone()), detail: "The protected resource is incomplete or has native findings.".into() });
                failures.extend(actual.findings.iter().cloned());
            }
            if actual.resource.tenant_key != required.tenant_key {
                failures.push(SecurityFinding { code: "tenant_ownership_key_mismatch".into(), resource: Some(required.resource.clone()), detail: "The inspected native tenant ownership key differs from the approved policy.".into() });
            }
            for operation in &required.operations {
                if !actual.verified_operations.contains(operation) {
                    failures.push(SecurityFinding { code: "operation_not_verified".into(), resource: Some(required.resource.clone()), detail: format!("Native enforcement for {operation:?} was not verified.") });
                }
            }
        }
        if report.model_version != SECURITY_MODEL_VERSION || report.posture != SecurityPosture::Verified || report.inspection != InspectionCompleteness::Complete || !report.findings.is_empty() {
            failures.push(SecurityFinding { code: "semantic_verification_denied".into(), resource: None, detail: "The adapter did not return a clean, complete semantic verification.".into() });
        }
        if !failures.is_empty() {
            report.posture = SecurityPosture::Blocked;
            report.inspection = InspectionCompleteness::Incomplete;
            report.findings.extend(failures);
        }
        // Preserve the adapter's model version: an unknown version must never
        // be normalized into the current model and accidentally accepted.
        if report.access_decision() != AccessDecision::Allow {
            return Ok((report, snapshot));
        }
        Ok((report, snapshot))
    }

    /// Perform current native inspection, bind signed probe evidence to that
    /// exact inspection and consume both the verified tenant identity and the
    /// admission exactly once. The generic evidence format is resource-agnostic,
    /// so this path fails closed for multi-resource policies until per-resource
    /// semantic evidence is available.
    pub async fn inspect_and_admit(
        &self,
        kind: DatabaseKind,
        request: &InspectionRequest,
        identity: &VerifiedTenantIdentity,
        evidence_authority: &PolicyEvidenceAuthority,
        evidence: &SignedPolicyEvidence,
        admission: &SignedPolicyAdmission,
        gate: &ConnectionAdmissionGate,
        connection_id: &str,
        now_unix: i64,
    ) -> Result<AccessDecision, SecurityCoreError> {
        if identity.database_kind() != kind
            || identity.target_id() != request.target.target_id
            || identity.policy_id() != request.policy.policy_id
            || identity.policy_revision() != request.policy.revision
        {
            return Err(SecurityCoreError::IdentityScopeMismatch);
        }
        let (report, snapshot) = self.inspect_and_verify_snapshot(kind, request).await?;
        if report.access_decision() != AccessDecision::Allow {
            return Ok(AccessDecision::Deny);
        }
        evidence_authority.verify_evidence(evidence)?;
        let payload = &evidence.payload;
        let current_fingerprint = snapshot.fingerprint.as_deref()
            .ok_or(SecurityCoreError::EvidenceScopeMismatch)?;
        if payload.database_kind != kind
            || payload.policy_id != request.policy.policy_id
            || payload.policy_revision != request.policy.revision
            || payload.target_id != request.target.target_id
            || payload.tenant_id != identity.tenant_id()
            || payload.fingerprint != current_fingerprint
        {
            return Err(SecurityCoreError::EvidenceScopeMismatch);
        }
        if !same_protected_resource_scope(&request.policy.resources, &payload.protected_resources) {
            return Err(SecurityCoreError::EvidenceCoverageIncomplete);
        }
        let required_operations: HashSet<_> = request.policy.resources.iter()
            .flat_map(|resource| resource.operations.iter().copied())
            .collect();
        let evidenced_operations: HashSet<_> = payload.verified_operations.iter().copied().collect();
        let declared_operation_count: usize = request.policy.resources.iter()
            .map(|resource| resource.operations.len())
            .sum();
        if required_operations.len() != declared_operation_count
            || evidenced_operations.len() != payload.verified_operations.len()
            || evidenced_operations != required_operations
        {
            return Err(SecurityCoreError::EvidenceCoverageIncomplete);
        }
        gate.consume_for_identity(
            evidence_authority,
            admission,
            evidence,
            identity,
            connection_id,
            now_unix,
        ).map_err(SecurityCoreError::Admission)
    }


    pub async fn detect_drift(&self, kind: DatabaseKind, target: &AdapterTarget, previous_fingerprint: Option<&str>) -> Result<DriftReport, SecurityCoreError> {
        let adapter = self.registry.get(kind).ok_or(SecurityCoreError::AdapterUnavailable(kind))?;
        let report = adapter.detect_drift(target, previous_fingerprint).await?;
        if report.database_kind != kind || report.target != *target { return Err(SecurityCoreError::SnapshotTargetMismatch); }
        if report.completeness != InspectionCompleteness::Complete { return Err(SecurityCoreError::DriftInspectionIncomplete); }
        if report.previous_fingerprint.as_deref() != previous_fingerprint {
            return Err(SecurityCoreError::DriftFingerprintMismatch);
        }
        if previous_fingerprint.is_some_and(|value| !is_sha256(value)) {
            return Err(SecurityCoreError::DriftFingerprintMismatch);
        }
        if report.observed_at.trim().is_empty() || report.observed_fingerprint.as_deref().map_or(true, |value| !is_sha256(value)) {
            return Err(SecurityCoreError::DriftInspectionIncomplete);
        }
        if let (Some(previous), Some(observed)) = (previous_fingerprint, report.observed_fingerprint.as_deref()) {
            let actual_drift = previous != observed;
            if report.detected != actual_drift { return Err(SecurityCoreError::DriftFingerprintMismatch); }
        } else if report.detected {
            // Without a trusted baseline, an adapter cannot assert that drift
            // was or was not detected. Establish the first baseline as clean only.
            return Err(SecurityCoreError::DriftFingerprintMismatch);
        }
        if report.detected && report.findings.is_empty() {
            return Err(SecurityCoreError::DriftFingerprintMismatch);
        }
        Ok(report)
    }

    fn validate_snapshot(&self, kind: DatabaseKind, request: &InspectionRequest, snapshot: &InspectionSnapshot) -> Result<(), SecurityCoreError> {
        if snapshot.database_kind != kind { return Err(SecurityCoreError::SnapshotKindMismatch); }
        if snapshot.target != request.target { return Err(SecurityCoreError::SnapshotTargetMismatch); }
        if snapshot.observed_at.trim().is_empty() { return Err(SecurityCoreError::IncompleteInspection); }
        if snapshot.fingerprint.as_deref().map_or(true, |value| !is_sha256(value)) {
            return Err(SecurityCoreError::InvalidFingerprint);
        }
        for resource in &snapshot.resources {
            if resource.fingerprint.as_deref().map_or(true, |value| !is_sha256(value)) {
                return Err(SecurityCoreError::InvalidFingerprint);
            }
        }
        Ok(())
    }
}


fn same_protected_resource_scope(
    expected: &[crate::security_core::ProtectedResource],
    observed: &[crate::security_core::ProtectedResource],
) -> bool {
    expected.len() == observed.len()
        && expected.iter().all(|resource| observed.contains(resource))
}

fn is_sha256(value: &str) -> bool {
    value.len() == 64 && value.bytes().all(|byte| byte.is_ascii_hexdigit())
}


#[cfg(test)]
mod tests {
    use super::*;
    use crate::connection_admission::ConnectionAdmissionGate;
    use crate::database_adapter::{AdapterFuture, DatabaseAdapter, ResourceInspection};
    use crate::policy_evidence::{EvidenceCheck, EvidenceCheckKind, PolicyEvidenceAuthority, PolicyEvidencePayload};
    use crate::tenant_identity::{TenantIdentityAuthority, TenantIdentityClaims, TenantIdentityExpectation};
    use crate::security_core::{
        AdapterCapabilities, AdapterDescriptor, AdapterMaturity, Operation,
        ProtectedResource, ResourceKind, ResourceRef, SECURITY_MODEL_VERSION,
    };

    struct FixtureAdapter { omit_read: bool, wrong_tenant_key: bool, lie_about_previous: bool, omit_fingerprint: bool }

    impl DatabaseAdapter for FixtureAdapter {
        fn descriptor(&self) -> AdapterDescriptor {
            AdapterDescriptor {
                kind: DatabaseKind::PostgreSql,
                name: "fixture-postgresql",
                maturity: AdapterMaturity::Supported,
                capabilities: AdapterCapabilities {
                    schema_inspection: true,
                    tenant_identity_enforcement: true,
                    policy_semantic_verification: true,
                    policy_generation: true,
                    controlled_policy_deployment: true,
                    drift_detection: true,
                    runtime_fail_closed_admission: true,
                    signed_security_evidence: true,
                },
                status_note: "test fixture",
            }
        }

        fn inspect<'a>(&'a self, request: &'a InspectionRequest) -> AdapterFuture<'a, Result<InspectionSnapshot, AdapterError>> {
            let resources = request.policy.resources.iter().cloned().map(|mut resource| {
                if self.wrong_tenant_key {
                    resource.tenant_key = "account_id".into();
                }
                let mut operations = resource.operations.clone();
                if self.omit_read {
                    operations.retain(|operation| *operation != Operation::Read);
                }
                ResourceInspection {
                    resource,
                    completeness: InspectionCompleteness::Complete,
                    posture: SecurityPosture::Verified,
                    verified_operations: operations,
                    findings: Vec::new(),
                    fingerprint: if self.omit_fingerprint { None } else { Some("a".repeat(64)) },
                }
            }).collect();
            let omit_fingerprint = self.omit_fingerprint;
            Box::pin(async move {
                Ok(InspectionSnapshot {
                    database_kind: DatabaseKind::PostgreSql,
                    target: request.target.clone(),
                    completeness: InspectionCompleteness::Complete,
                    posture: SecurityPosture::Verified,
                    resources,
                    findings: Vec::new(),
                    fingerprint: if omit_fingerprint { None } else { Some("a".repeat(64)) },
                    observed_at: "2026-11-17T00:00:00Z".into(),
                })
            })
        }

        fn compile_policy(&self, policy: &TenantSecurityPolicy) -> Result<CompiledPolicy, AdapterError> {
            Ok(CompiledPolicy {
                database_kind: DatabaseKind::PostgreSql,
                policy_id: policy.policy_id.clone(),
                revision: policy.revision,
                changes: policy.resources.iter().map(|resource| {
                    let mut resource = resource.clone();
                    if self.wrong_tenant_key { resource.tenant_key = "account_id".into(); }
                    crate::database_adapter::NativePolicyChange {
                        resource,
                        action: "reviewed_change".into(),
                        definition: serde_json::json!({"kind":"fixture"}),
                    }
                }).collect(),
                requires_approval: true,
            })
        }

        fn verify<'a>(&'a self, _policy: &'a TenantSecurityPolicy, _snapshot: &'a InspectionSnapshot) -> AdapterFuture<'a, Result<VerificationReport, AdapterError>> {
            Box::pin(async {
                Ok(VerificationReport {
                    model_version: SECURITY_MODEL_VERSION.into(),
                    posture: SecurityPosture::Verified,
                    inspection: InspectionCompleteness::Complete,
                    findings: Vec::new(),
                })
            })
        }

        fn detect_drift<'a>(&'a self, target: &'a AdapterTarget, previous_fingerprint: Option<&'a str>) -> AdapterFuture<'a, Result<DriftReport, AdapterError>> {
            Box::pin(async move {
                Ok(DriftReport {
                    database_kind: DatabaseKind::PostgreSql,
                    target: target.clone(),
                    detected: previous_fingerprint.is_some_and(|value| value != "a".repeat(64)),
                    completeness: InspectionCompleteness::Complete,
                    previous_fingerprint: if self.lie_about_previous { Some("f".repeat(64)) } else { previous_fingerprint.map(str::to_owned) },
                    observed_fingerprint: Some("a".repeat(64)),
                    findings: Vec::new(),
                    observed_at: "2026-11-17T00:00:00Z".into(),
                })
            })
        }
    }

    fn request() -> InspectionRequest {
        InspectionRequest {
            target: AdapterTarget {
                target_id: "fixture-target".into(),
                database_name: "app".into(),
                namespace: Some("public".into()),
            },
            policy: TenantSecurityPolicy {
                schema_version: SECURITY_MODEL_VERSION.into(),
                policy_id: "tenant-boundary".into(),
                revision: 1,
                tenant_identity_claim: "tenant_id".into(),
                resources: vec![ProtectedResource {
                    resource: ResourceRef {
                        namespace: Some("public".into()),
                        name: "records".into(),
                        kind: ResourceKind::Table,
                    },
                    tenant_key: "tenant_id".into(),
                    operations: vec![Operation::Read, Operation::Create, Operation::Update, Operation::Delete],
                }],
            },
        }
    }

    fn identity(request: &InspectionRequest, now: i64) -> crate::tenant_identity::VerifiedTenantIdentity {
        let authority = TenantIdentityAuthority::new(vec![31; 32]).unwrap();
        let claims = TenantIdentityClaims {
            schema_version: "proxima.tenant-identity.v1".into(),
            tenant_id: "tenant-a".into(),
            principal_id: "app-service".into(),
            target_id: request.target.target_id.clone(),
            database_kind: DatabaseKind::PostgreSql,
            policy_id: request.policy.policy_id.clone(),
            policy_revision: request.policy.revision,
            request_id: "550e8400-e29b-41d4-a716-446655440001".into(),
            issued_at_unix: now,
            expires_at_unix: now + 30,
        };
        let expected = TenantIdentityExpectation {
            tenant_id: "tenant-a",
            principal_id: "app-service",
            target_id: &request.target.target_id,
            database_kind: DatabaseKind::PostgreSql,
            policy_id: &request.policy.policy_id,
            policy_revision: request.policy.revision,
        };
        let token = authority.sign(&claims, now).unwrap();
        authority.verify(&token, expected, now).unwrap()
    }

    fn signed_evidence(
        request: &InspectionRequest,
        resources: Vec<ProtectedResource>,
        now: i64,
    ) -> (
        PolicyEvidenceAuthority,
        crate::policy_evidence::SignedPolicyEvidence,
        crate::policy_evidence::SignedPolicyAdmission,
    ) {
        let mut operations = Vec::new();
        let mut checks = Vec::new();
        for resource in &resources {
            for operation in &resource.operations {
                if !operations.contains(operation) {
                    operations.push(*operation);
                }
                checks.push(EvidenceCheck {
                    resource: resource.resource.clone(),
                    operation: *operation,
                    kind: EvidenceCheckKind::OwnTenantAllow,
                    passed: true,
                    detail: "own-tenant operation probe passed".into(),
                });
                checks.push(EvidenceCheck {
                    resource: resource.resource.clone(),
                    operation: *operation,
                    kind: EvidenceCheckKind::CrossTenantDeny,
                    passed: true,
                    detail: "cross-tenant operation probe denied".into(),
                });
                if matches!(operation, Operation::Create | Operation::Update | Operation::Delete) {
                    checks.push(EvidenceCheck {
                        resource: resource.resource.clone(),
                        operation: *operation,
                        kind: EvidenceCheckKind::MutationRollback,
                        passed: true,
                        detail: "mutation probe rolled back".into(),
                    });
                }
            }
        }
        let authority = PolicyEvidenceAuthority::new(vec![41; 32], vec![43; 32]).unwrap();
        let evidence = authority.sign_evidence(PolicyEvidencePayload {
            model_version: SECURITY_MODEL_VERSION.into(),
            policy_id: request.policy.policy_id.clone(),
            policy_revision: request.policy.revision,
            database_kind: DatabaseKind::PostgreSql,
            target_id: request.target.target_id.clone(),
            tenant_id: "tenant-a".into(),
            posture: SecurityPosture::Verified,
            inspection: InspectionCompleteness::Complete,
            findings: Vec::new(),
            protected_resources: resources,
            verified_operations: operations,
            fingerprint: "a".repeat(64),
            observed_at_unix: now - 1,
            checks,
        }).unwrap();
        let admission = authority.issue_admission(&evidence, now, 30).unwrap();
        (authority, evidence, admission)
    }

    fn two_resource_request() -> InspectionRequest {
        let mut request = request();
        let mut second = request.policy.resources[0].clone();
        second.resource.name = "invoices".into();
        request.policy.resources.push(second);
        request
    }

    fn coordinator(omit_read: bool) -> SecurityCoreCoordinator {
        let mut registry = AdapterRegistry::default();
        registry.register(std::sync::Arc::new(FixtureAdapter { omit_read, wrong_tenant_key: false, lie_about_previous: false, omit_fingerprint: false })).unwrap();
        SecurityCoreCoordinator::new(registry)
    }

    #[test]
    fn fingerprint_validator_rejects_malformed_digests() {
        assert!(!is_sha256(""));
        assert!(!is_sha256("not-a-digest"));
        assert!(!is_sha256(&"g".repeat(64)));
        assert!(is_sha256(&"a".repeat(64)));
    }

    #[tokio::test]
    async fn missing_native_fingerprint_fails_closed() {
        let mut registry = AdapterRegistry::default();
        registry.register(std::sync::Arc::new(FixtureAdapter {
            omit_read: false,
            wrong_tenant_key: false,
            lie_about_previous: false,
            omit_fingerprint: true,
        })).unwrap();
        let coordinator = SecurityCoreCoordinator::new(registry);
        assert_eq!(
            coordinator.inspect_and_verify(DatabaseKind::PostgreSql, &request()).await,
            Err(SecurityCoreError::InvalidFingerprint)
        );
    }

    #[tokio::test]
    async fn complete_native_operation_coverage_allows() {
        let coordinator = coordinator(false);
        let report = coordinator.inspect_and_verify(DatabaseKind::PostgreSql, &request()).await.unwrap();
        assert_eq!(report.access_decision(), AccessDecision::Allow);
    }

    #[tokio::test]
    async fn missing_native_operation_coverage_denies() {
        let coordinator = coordinator(true);
        let report = coordinator.inspect_and_verify(DatabaseKind::PostgreSql, &request()).await.unwrap();
        assert_eq!(report.access_decision(), AccessDecision::Deny);
        assert!(report.findings.iter().any(|finding| finding.code == "operation_not_verified"));
    }

    #[test]
    fn compilation_rejects_a_different_tenant_ownership_key() {
        let mut registry = AdapterRegistry::default();
        registry.register(std::sync::Arc::new(FixtureAdapter { omit_read: false, wrong_tenant_key: true, lie_about_previous: false, omit_fingerprint: false })).unwrap();
        let coordinator = SecurityCoreCoordinator::new(registry);
        assert_eq!(coordinator.compile(DatabaseKind::PostgreSql, &request().policy), Err(SecurityCoreError::InvalidCompilation));
    }

    #[tokio::test]
    async fn mismatched_native_tenant_key_denies_admission() {
        let mut registry = AdapterRegistry::default();
        registry.register(std::sync::Arc::new(FixtureAdapter { omit_read: false, wrong_tenant_key: true, lie_about_previous: false, omit_fingerprint: false })).unwrap();
        let coordinator = SecurityCoreCoordinator::new(registry);
        let report = coordinator.inspect_and_verify(DatabaseKind::PostgreSql, &request()).await.unwrap();
        assert_eq!(report.access_decision(), AccessDecision::Deny);
        assert!(report.findings.iter().any(|finding| finding.code == "tenant_ownership_key_mismatch"));
    }

    #[tokio::test]
    async fn drift_report_cannot_substitute_the_previous_fingerprint() {
        let mut registry = AdapterRegistry::default();
        registry.register(std::sync::Arc::new(FixtureAdapter {
            omit_read: false,
            wrong_tenant_key: false,
            lie_about_previous: true,
            omit_fingerprint: false,
        })).unwrap();
        let coordinator = SecurityCoreCoordinator::new(registry);
        let target = request().target;
        assert_eq!(
            coordinator.detect_drift(DatabaseKind::PostgreSql, &target, Some(&"a".repeat(64))).await,
            Err(SecurityCoreError::DriftFingerprintMismatch)
        );
    }

    #[tokio::test]
    async fn multi_resource_admission_requires_per_resource_probe_evidence() {
        let request = two_resource_request();
        let now = 1_900_000_010;
        let identity = identity(&request, now);
        let coordinator = coordinator(false);
        let gate = ConnectionAdmissionGate::new();
        let (authority, evidence, admission) =
            signed_evidence(&request, vec![request.policy.resources[0].clone()], now);

        assert_eq!(
            coordinator.inspect_and_admit(
                DatabaseKind::PostgreSql, &request, &identity, &authority,
                &evidence, &admission, &gate, "fixture-connection", now,
            ).await,
            Err(SecurityCoreError::EvidenceCoverageIncomplete)
        );
    }

    #[tokio::test]
    async fn complete_multi_resource_admission_consumes_identity_once() {
        let request = two_resource_request();
        let now = 1_900_000_010;
        let identity = identity(&request, now);
        let coordinator = coordinator(false);
        let gate = ConnectionAdmissionGate::new();
        let (authority, evidence, admission) =
            signed_evidence(&request, request.policy.resources.clone(), now);

        assert_eq!(
            coordinator.inspect_and_admit(
                DatabaseKind::PostgreSql, &request, &identity, &authority,
                &evidence, &admission, &gate, "fixture-connection", now,
            ).await,
            Ok(AccessDecision::Allow)
        );
        assert!(matches!(
            coordinator.inspect_and_admit(
                DatabaseKind::PostgreSql, &request, &identity, &authority,
                &evidence, &admission, &gate, "fixture-connection-2", now,
            ).await,
            Err(SecurityCoreError::Admission(error)) if error.code == "admission_replay_detected"
        ));
    }

    #[test]
    fn compilation_requires_approval_and_covers_each_policy_resource() {
        let coordinator = coordinator(false);
        let compiled = coordinator.compile(DatabaseKind::PostgreSql, &request().policy).unwrap();
        assert!(compiled.requires_approval);
        assert_eq!(compiled.changes.len(), 1);
    }
}
