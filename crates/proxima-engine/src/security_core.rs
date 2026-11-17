//! Database-independent tenant-security contracts used by Proxima Engine.
//!
//! Database adapters translate this contract into native database controls. The
//! catalog deliberately distinguishes implemented work from planned adapters;
//! listing a database never implies that its adapter is production-supported.

use serde::{Deserialize, Serialize};
use std::collections::HashSet;

pub const SECURITY_MODEL_VERSION: &str = "proxima.security.v1";

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DatabaseKind {
    #[serde(rename = "postgresql")]
    PostgreSql,
    #[serde(rename = "mysql")]
    MySql,
    #[serde(rename = "mariadb")]
    MariaDb,
    #[serde(rename = "sql_server")]
    SqlServer,
    #[serde(rename = "mongodb")]
    MongoDb,
    #[serde(rename = "cockroachdb")]
    CockroachDb,
    #[serde(rename = "vaultdb")]
    VaultDb,
    #[serde(rename = "redis")]
    Redis,
    #[serde(rename = "sqlite")]
    Sqlite,
    #[serde(rename = "oracle")]
    Oracle,
    #[serde(rename = "dynamodb")]
    DynamoDb,
    #[serde(rename = "cassandra")]
    Cassandra,
    #[serde(rename = "elasticsearch")]
    Elasticsearch,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AdapterMaturity {
    InDevelopment,
    Planned,
    Supported,
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
pub struct AdapterCapabilities {
    pub schema_inspection: bool,
    pub tenant_identity_enforcement: bool,
    pub policy_semantic_verification: bool,
    pub policy_generation: bool,
    pub controlled_policy_deployment: bool,
    pub drift_detection: bool,
    pub runtime_fail_closed_admission: bool,
    pub signed_security_evidence: bool,
}

impl AdapterCapabilities {
    /// Production support is an end-to-end claim. A compiler or a successful
    /// connection test is not sufficient to mark an adapter supported.
    pub fn is_production_complete(&self) -> bool {
        self.schema_inspection
            && self.tenant_identity_enforcement
            && self.policy_semantic_verification
            && self.policy_generation
            && self.controlled_policy_deployment
            && self.drift_detection
            && self.runtime_fail_closed_admission
            && self.signed_security_evidence
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct AdapterDescriptor {
    pub kind: DatabaseKind,
    pub name: &'static str,
    pub maturity: AdapterMaturity,
    pub capabilities: AdapterCapabilities,
    pub status_note: &'static str,
}

/// The public catalog is a statement of actual implementation maturity, not a
/// marketing list. Planned adapters expose no capabilities until implemented.
pub fn adapter_catalog() -> Vec<AdapterDescriptor> {
    vec![
        AdapterDescriptor {
            kind: DatabaseKind::PostgreSql,
            name: "PostgreSQL",
            maturity: AdapterMaturity::InDevelopment,
            capabilities: AdapterCapabilities {
                schema_inspection: true,
                tenant_identity_enforcement: true,
                policy_semantic_verification: false,
                policy_generation: true,
                controlled_policy_deployment: false,
                drift_detection: false,
                runtime_fail_closed_admission: true,
                signed_security_evidence: true,
            },
            status_note: "PostgreSQL protocol startup and active sessions can require fresh signed Control Plane admission; signed per-registration admission evidence is persisted. Independent positive/negative semantic verification and Engine-native deployment remain incomplete.",
        },
        AdapterDescriptor {
            kind: DatabaseKind::MySql,
            name: "MySQL",
            maturity: AdapterMaturity::InDevelopment,
            capabilities: AdapterCapabilities { schema_inspection: true, policy_generation: true, drift_detection: true, ..AdapterCapabilities::default() },
            status_note: "TLS-verified catalog discovery, table/schema privilege inspection and fingerprint drift detection are implemented. Database-per-tenant grant plans remain review-only; runtime principal binding and semantic verification are not implemented.",
        },
        AdapterDescriptor {
            kind: DatabaseKind::MariaDb,
            name: "MariaDB",
            maturity: AdapterMaturity::InDevelopment,
            capabilities: AdapterCapabilities { policy_generation: true, ..AdapterCapabilities::default() },
            status_note: "Reviewable database-per-tenant grant templates require a trusted application-host scope. No shared-table row-level enforcement, native inspection, runtime principal binding or drift verification is implemented.",
        },
        AdapterDescriptor {
            kind: DatabaseKind::SqlServer,
            name: "Microsoft SQL Server",
            maturity: AdapterMaturity::InDevelopment,
            capabilities: AdapterCapabilities { policy_generation: true, ..AdapterCapabilities::default() },
            status_note: "Reviewable native Row-Level Security predicate and policy DDL can be generated. Session-context trust, catalog inspection, deployment, semantic verification and runtime admission are not implemented.",
        },
        AdapterDescriptor {
            kind: DatabaseKind::MongoDb,
            name: "MongoDB",
            maturity: AdapterMaturity::InDevelopment,
            capabilities: AdapterCapabilities { policy_generation: true, ..AdapterCapabilities::default() },
            status_note: "Reviewable database-per-tenant collection-role templates exist. Shared-collection document-level enforcement and native runtime verification are not implemented.",
        },
        AdapterDescriptor {
            kind: DatabaseKind::CockroachDb,
            name: "CockroachDB",
            maturity: AdapterMaturity::Planned,
            capabilities: AdapterCapabilities::default(),
            status_note: "CockroachDB-specific authorization semantics and runtime enforcement require separate implementation and validation.",
        },
        AdapterDescriptor {
            kind: DatabaseKind::Redis,
            name: "Redis",
            maturity: AdapterMaturity::InDevelopment,
            capabilities: AdapterCapabilities { policy_generation: true, ..AdapterCapabilities::default() },
            status_note: "Reviewable tenant-prefixed ACL templates derive a narrower command allowlist from requested operations; Redis ACLs cannot distinguish create-only from update-only upsert semantics. Native ACL inspection, trusted principal selection, runtime enforcement and drift verification are not implemented.",
        },
        AdapterDescriptor {
            kind: DatabaseKind::VaultDb,
            name: "VAULTDB (Agata-native research engine)",
            maturity: AdapterMaturity::Planned,
            capabilities: AdapterCapabilities::default(),
            status_note: "Agata-owned embedded relational research engine; tenant identity, resource authorization, isolation enforcement and security acceptance are not implemented.",
        },
        AdapterDescriptor { kind: DatabaseKind::Sqlite, name: "SQLite", maturity: AdapterMaturity::Planned, capabilities: AdapterCapabilities::default(), status_note: "File-per-tenant and OS-level isolation research only; no runtime adapter is implemented." },
        AdapterDescriptor { kind: DatabaseKind::Oracle, name: "Oracle Database", maturity: AdapterMaturity::Planned, capabilities: AdapterCapabilities::default(), status_note: "Oracle VPD and Database Vault integration are not implemented." },
        AdapterDescriptor { kind: DatabaseKind::DynamoDb, name: "Amazon DynamoDB", maturity: AdapterMaturity::Planned, capabilities: AdapterCapabilities::default(), status_note: "Partition-key and IAM LeadingKeys enforcement are not implemented." },
        AdapterDescriptor { kind: DatabaseKind::Cassandra, name: "Apache Cassandra", maturity: AdapterMaturity::Planned, capabilities: AdapterCapabilities::default(), status_note: "Keyspace-per-tenant isolation is not implemented." },
        AdapterDescriptor { kind: DatabaseKind::Elasticsearch, name: "Elasticsearch / OpenSearch", maturity: AdapterMaturity::Planned, capabilities: AdapterCapabilities::default(), status_note: "Document-level security and role enforcement are not implemented." },
    ]
}

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ResourceKind {
    Table,
    View,
    Sequence,
    Collection,
    Procedure,
    Function,
    Keyspace,
}

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Operation {
    Read,
    Create,
    Update,
    Delete,
    Execute,
}

#[derive(Clone, Debug, Eq, Hash, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ResourceRef {
    pub namespace: Option<String>,
    pub name: String,
    pub kind: ResourceKind,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProtectedResource {
    pub resource: ResourceRef,
    /// Native tenant ownership attribute (column, field, or equivalent).
    pub tenant_key: String,
    pub operations: Vec<Operation>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TenantSecurityPolicy {
    pub schema_version: String,
    pub policy_id: String,
    pub revision: u64,
    pub tenant_identity_claim: String,
    pub resources: Vec<ProtectedResource>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum PolicyValidationError {
    UnsupportedSchemaVersion,
    EmptyPolicyId,
    PolicyIdTooLong,
    ZeroRevision,
    EmptyTenantIdentityClaim,
    TenantIdentityClaimTooLong,
    NoProtectedResources,
    TooManyResources,
    EmptyResourceName,
    ResourceNameTooLong,
    EmptyNamespace,
    NamespaceTooLong,
    EmptyTenantKey,
    TenantKeyTooLong,
    NoOperations,
    DuplicateResource,
    DuplicateOperation,
}

impl TenantSecurityPolicy {
    /// Validate the database-neutral policy envelope before an adapter compiles it.
    pub fn validate(&self) -> Result<(), PolicyValidationError> {
        if self.schema_version != SECURITY_MODEL_VERSION {
            return Err(PolicyValidationError::UnsupportedSchemaVersion);
        }
        if self.policy_id.trim().is_empty() || self.policy_id.contains('\0') {
            return Err(PolicyValidationError::EmptyPolicyId);
        }
        if self.policy_id.chars().count() > 128 {
            return Err(PolicyValidationError::PolicyIdTooLong);
        }
        if self.revision == 0 {
            return Err(PolicyValidationError::ZeroRevision);
        }
        if self.tenant_identity_claim.trim().is_empty() || self.tenant_identity_claim.contains('\0') {
            return Err(PolicyValidationError::EmptyTenantIdentityClaim);
        }
        if self.tenant_identity_claim.chars().count() > 128 {
            return Err(PolicyValidationError::TenantIdentityClaimTooLong);
        }
        if self.resources.is_empty() {
            return Err(PolicyValidationError::NoProtectedResources);
        }
        if self.resources.len() > 1000 {
            return Err(PolicyValidationError::TooManyResources);
        }

        let mut resources = HashSet::new();
        for item in &self.resources {
            if item.resource.name.trim().is_empty() || item.resource.name.contains('\0') {
                return Err(PolicyValidationError::EmptyResourceName);
            }
            if item.resource.name.chars().count() > 256 {
                return Err(PolicyValidationError::ResourceNameTooLong);
            }
            if let Some(namespace) = item.resource.namespace.as_deref() {
                if namespace.trim().is_empty() || namespace.contains('\0') {
                    return Err(PolicyValidationError::EmptyNamespace);
                }
                if namespace.chars().count() > 256 {
                    return Err(PolicyValidationError::NamespaceTooLong);
                }
            }
            if item.tenant_key.trim().is_empty() || item.tenant_key.contains('\0') {
                return Err(PolicyValidationError::EmptyTenantKey);
            }
            if item.tenant_key.chars().count() > 256 {
                return Err(PolicyValidationError::TenantKeyTooLong);
            }
            if item.operations.is_empty() {
                return Err(PolicyValidationError::NoOperations);
            }
            if !resources.insert(item.resource.clone()) {
                return Err(PolicyValidationError::DuplicateResource);
            }
            let mut operations = HashSet::new();
            if item.operations.iter().any(|operation| !operations.insert(*operation)) {
                return Err(PolicyValidationError::DuplicateOperation);
            }
        }
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum InspectionCompleteness {
    Complete,
    Incomplete,
    Unavailable,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SecurityPosture {
    Verified,
    NeedsAttention,
    Blocked,
    Unknown,
    Degraded,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AccessDecision {
    Allow,
    Deny,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct SecurityFinding {
    pub code: String,
    pub resource: Option<ResourceRef>,
    pub detail: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct VerificationReport {
    pub model_version: String,
    pub posture: SecurityPosture,
    pub inspection: InspectionCompleteness,
    pub findings: Vec<SecurityFinding>,
}

impl VerificationReport {
    /// Fail closed: an incomplete, unavailable, degraded, unknown, or failing
    /// inspection can never be converted into an allow decision.
    pub fn access_decision(&self) -> AccessDecision {
        if self.model_version == SECURITY_MODEL_VERSION
            && self.posture == SecurityPosture::Verified
            && self.inspection == InspectionCompleteness::Complete
            && self.findings.is_empty()
        {
            AccessDecision::Allow
        } else {
            AccessDecision::Deny
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn valid_policy() -> TenantSecurityPolicy {
        TenantSecurityPolicy {
            schema_version: SECURITY_MODEL_VERSION.into(),
            policy_id: "invoices".into(),
            revision: 1,
            tenant_identity_claim: "tenant_id".into(),
            resources: vec![ProtectedResource {
                resource: ResourceRef {
                    namespace: Some("public".into()),
                    name: "invoices".into(),
                    kind: ResourceKind::Table,
                },
                tenant_key: "tenant_id".into(),
                operations: vec![Operation::Read, Operation::Create, Operation::Update, Operation::Delete],
            }],
        }
    }

    #[test]
    fn accepts_a_valid_database_neutral_policy() {
        assert!(valid_policy().validate().is_ok());
    }

    #[test]
    fn rejects_duplicate_resources_and_operations() {
        let mut policy = valid_policy();
        policy.resources.push(policy.resources[0].clone());
        assert_eq!(policy.validate(), Err(PolicyValidationError::DuplicateResource));

        let mut policy = valid_policy();
        policy.resources[0].operations.push(Operation::Read);
        assert_eq!(policy.validate(), Err(PolicyValidationError::DuplicateOperation));
    }

    #[test]
    fn rejects_unknown_schema_and_empty_ownership_key() {
        let mut policy = valid_policy();
        policy.schema_version = "future.version".into();
        assert_eq!(policy.validate(), Err(PolicyValidationError::UnsupportedSchemaVersion));

        let mut policy = valid_policy();
        policy.resources[0].tenant_key.clear();
        assert_eq!(policy.validate(), Err(PolicyValidationError::EmptyTenantKey));
    }

    #[test]
    fn enforces_the_shared_schema_limits_and_rejects_unknown_fields() {
        let mut policy = valid_policy();
        policy.policy_id = "x".repeat(129);
        assert_eq!(policy.validate(), Err(PolicyValidationError::PolicyIdTooLong));

        let mut policy = valid_policy();
        policy.resources[0].resource.namespace = Some(" ".into());
        assert_eq!(policy.validate(), Err(PolicyValidationError::EmptyNamespace));

        let mut policy = valid_policy();
        policy.resources[0].tenant_key = "k".repeat(257);
        assert_eq!(policy.validate(), Err(PolicyValidationError::TenantKeyTooLong));

        let unknown_field = r#"{
          "schema_version":"proxima.security.v1","policy_id":"p","revision":1,
          "tenant_identity_claim":"tenant_id","unexpected":true,
          "resources":[{"resource":{"name":"invoices","kind":"table"},"tenant_key":"tenant_id","operations":["read"]}]
        }"#;
        assert!(serde_json::from_str::<TenantSecurityPolicy>(unknown_field).is_err());
    }

    #[test]
    fn only_complete_verified_inspection_can_allow_access() {
        let verified = VerificationReport {
            model_version: SECURITY_MODEL_VERSION.into(),
            posture: SecurityPosture::Verified,
            inspection: InspectionCompleteness::Complete,
            findings: vec![],
        };
        assert_eq!(verified.access_decision(), AccessDecision::Allow);

        let mut unknown_model = verified.clone();
        unknown_model.model_version = "future.security.model".into();
        assert_eq!(unknown_model.access_decision(), AccessDecision::Deny);

        for (posture, inspection) in [
            (SecurityPosture::Verified, InspectionCompleteness::Unavailable),
            (SecurityPosture::Verified, InspectionCompleteness::Incomplete),
            (SecurityPosture::Unknown, InspectionCompleteness::Complete),
            (SecurityPosture::Degraded, InspectionCompleteness::Complete),
            (SecurityPosture::NeedsAttention, InspectionCompleteness::Complete),
            (SecurityPosture::Blocked, InspectionCompleteness::Complete),
        ] {
            let report = VerificationReport {
                model_version: SECURITY_MODEL_VERSION.into(),
                posture,
                inspection,
                findings: vec![],
            };
            assert_eq!(report.access_decision(), AccessDecision::Deny);
        }
    }

    #[test]
    fn supported_maturity_requires_the_complete_end_to_end_capability_set() {
        let complete = AdapterCapabilities {
            schema_inspection: true,
            tenant_identity_enforcement: true,
            policy_semantic_verification: true,
            policy_generation: true,
            controlled_policy_deployment: true,
            drift_detection: true,
            runtime_fail_closed_admission: true,
            signed_security_evidence: true,
        };
        assert!(complete.is_production_complete());
        for field in 0..8 {
            let mut partial = complete;
            match field {
                0 => partial.schema_inspection = false,
                1 => partial.tenant_identity_enforcement = false,
                2 => partial.policy_semantic_verification = false,
                3 => partial.policy_generation = false,
                4 => partial.controlled_policy_deployment = false,
                5 => partial.drift_detection = false,
                6 => partial.runtime_fail_closed_admission = false,
                _ => partial.signed_security_evidence = false,
            }
            assert!(!partial.is_production_complete());
        }
    }

    #[test]
    fn planned_adapters_make_no_unsupported_capability_claims() {
        let catalog = adapter_catalog();
        assert_eq!(catalog.len(), 13);
        for adapter in catalog.iter().filter(|adapter| adapter.maturity == AdapterMaturity::Planned) {
            assert_eq!(adapter.capabilities, AdapterCapabilities::default());
        }
    }
}
