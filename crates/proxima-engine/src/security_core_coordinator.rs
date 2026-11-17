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
            covered.insert(change.resource.resource.clone());
        }
        if policy.resources.iter().any(|item| !covered.contains(&item.resource)) { return Err(SecurityCoreError::InvalidCompilation); }
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
        Ok(report)
    }

    fn validate_snapshot(&self, kind: DatabaseKind, request: &InspectionRequest, snapshot: &InspectionSnapshot) -> Result<(), SecurityCoreError> {
        if snapshot.database_kind != kind { return Err(SecurityCoreError::SnapshotKindMismatch); }
        if snapshot.target != request.target { return Err(SecurityCoreError::SnapshotTargetMismatch); }
        if snapshot.observed_at.trim().is_empty() { return Err(SecurityCoreError::IncompleteInspection); }
        Ok(())
    }
}
