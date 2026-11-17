//! Fail-closed orchestration for the database-independent Security Core.
//!
//! This module centralizes the inspection, compilation and drift lifecycle. It
//! deliberately does not apply generated policy: native changes require a
//! separately authorized deployment workflow.

use crate::database_adapter::{AdapterError, AdapterRegistry, AdapterTarget, CompiledPolicy, DriftReport, InspectionRequest, InspectionSnapshot};
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
    DuplicateCompiledResource(String),
}

impl From<AdapterError> for SecurityCoreError {
    fn from(error: AdapterError) -> Self { Self::Adapter(error) }
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
        if report.access_decision() != AccessDecision::Allow { return Ok(report); }
        Ok(report)
    }

    pub async fn detect_drift(&self, kind: DatabaseKind, target: &AdapterTarget, previous_fingerprint: Option<&str>) -> Result<DriftReport, SecurityCoreError> {
        let adapter = self.registry.get(kind).ok_or(SecurityCoreError::AdapterUnavailable(kind))?;
        let report = adapter.detect_drift(target, previous_fingerprint).await?;
        if report.database_kind != kind || report.target != *target { return Err(SecurityCoreError::SnapshotTargetMismatch); }
        if report.completeness != InspectionCompleteness::Complete { return Err(SecurityCoreError::DriftInspectionIncomplete); }
        if report.previous_fingerprint.as_deref() != previous_fingerprint {
            return Err(SecurityCoreError::DriftFingerprintMismatch);
        }
        if report.observed_at.trim().is_empty() || report.observed_fingerprint.as_deref().map_or(true, str::is_empty) {
            return Err(SecurityCoreError::DriftInspectionIncomplete);
        }
        if let (Some(previous), Some(observed)) = (previous_fingerprint, report.observed_fingerprint.as_deref()) {
            let actual_drift = previous != observed;
            if report.detected != actual_drift { return Err(SecurityCoreError::DriftFingerprintMismatch); }
        } else if previous_fingerprint.is_some() {
            return Err(SecurityCoreError::DriftInspectionIncomplete);
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
        Ok(())
    }
}


#[cfg(test)]
mod tests {
    use super::*;
    use crate::database_adapter::{AdapterFuture, DatabaseAdapter, ResourceInspection};
    use crate::security_core::{
        AdapterCapabilities, AdapterDescriptor, AdapterMaturity, Operation,
        ProtectedResource, ResourceKind, ResourceRef, SECURITY_MODEL_VERSION,
    };

    struct FixtureAdapter { omit_read: bool, wrong_tenant_key: bool, lie_about_previous: bool }

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
            let mut operations = request.policy.resources[0].operations.clone();
            if self.omit_read { operations.retain(|operation| *operation != Operation::Read); }
            let mut resource = request.policy.resources[0].clone();
            if self.wrong_tenant_key { resource.tenant_key = "account_id".into(); }
            Box::pin(async move {
                Ok(InspectionSnapshot {
                    database_kind: DatabaseKind::PostgreSql,
                    target: request.target.clone(),
                    completeness: InspectionCompleteness::Complete,
                    posture: SecurityPosture::Verified,
                    resources: vec![ResourceInspection {
                        resource,
                        completeness: InspectionCompleteness::Complete,
                        posture: SecurityPosture::Verified,
                        verified_operations: operations,
                        findings: Vec::new(),
                        fingerprint: Some("a".repeat(64)),
                    }],
                    findings: Vec::new(),
                    fingerprint: Some("a".repeat(64)),
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

    fn coordinator(omit_read: bool) -> SecurityCoreCoordinator {
        let mut registry = AdapterRegistry::default();
        registry.register(std::sync::Arc::new(FixtureAdapter { omit_read, wrong_tenant_key: false, lie_about_previous: false })).unwrap();
        SecurityCoreCoordinator::new(registry)
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
        registry.register(std::sync::Arc::new(FixtureAdapter { omit_read: false, wrong_tenant_key: true, lie_about_previous: false })).unwrap();
        let coordinator = SecurityCoreCoordinator::new(registry);
        assert_eq!(coordinator.compile(DatabaseKind::PostgreSql, &request().policy), Err(SecurityCoreError::InvalidCompilation));
    }

    #[tokio::test]
    async fn mismatched_native_tenant_key_denies_admission() {
        let mut registry = AdapterRegistry::default();
        registry.register(std::sync::Arc::new(FixtureAdapter { omit_read: false, wrong_tenant_key: true })).unwrap();
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
        })).unwrap();
        let coordinator = SecurityCoreCoordinator::new(registry);
        let target = request().target;
        assert_eq!(
            coordinator.detect_drift(DatabaseKind::PostgreSql, &target, Some(&"a".repeat(64))).await,
            Err(SecurityCoreError::DriftFingerprintMismatch)
        );
    }

    #[test]
    fn compilation_requires_approval_and_covers_each_policy_resource() {
        let coordinator = coordinator(false);
        let compiled = coordinator.compile(DatabaseKind::PostgreSql, &request().policy).unwrap();
        assert!(compiled.requires_approval);
        assert_eq!(compiled.changes.len(), 1);
    }
}
