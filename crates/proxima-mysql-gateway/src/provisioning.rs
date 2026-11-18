//! Journaled execution contract for MySQL tenant DDL.
//!
//! MySQL DDL implicitly commits. This module requires a durable journal and
//! compensates only operations whose success was recorded. It never assumes
//! that a failed network call means the server did not apply the statement.
use proxima_engine::mysql_isolation::{MySqlProvisioningPlan, MySqlTenantIdentity};
use std::fmt;

pub trait MySqlDdlExecutor {
    fn execute(&mut self, statement: &str) -> Result<(), ()>;
}

pub trait ProvisioningJournal {
    fn begin(&mut self, tenant_id: &str) -> Result<(), ()>;
    fn step_started(&mut self, tenant_id: &str, step: usize) -> Result<(), ()>;
    fn step_applied(&mut self, tenant_id: &str, step: usize) -> Result<(), ()>;
    fn step_compensated(&mut self, tenant_id: &str, step: usize) -> Result<(), ()>;
    fn needs_reconciliation(&mut self, tenant_id: &str, failed_step: usize) -> Result<(), ()>;
    fn complete(&mut self, tenant_id: &str) -> Result<(), ()>;
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ProvisioningError {
    JournalUnavailable,
    ExecutionFailed { failed_step: usize, compensation_failures: usize },
}
impl fmt::Display for ProvisioningError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::JournalUnavailable => write!(f, "MySQL provisioning journal is unavailable; provisioning was not started"),
            Self::ExecutionFailed { failed_step, compensation_failures } => write!(f, "MySQL provisioning stopped at step {failed_step}; reconciliation is required ({compensation_failures} compensation operations failed)"),
        }
    }
}
impl std::error::Error for ProvisioningError {}

/// Execute a validated plan. A durable journal must be available before any
/// DDL is sent. On ambiguous failure, only acknowledged steps are compensated.
/// The journal records that the failed DDL may have committed before its reply
/// was lost, so operator reconciliation remains mandatory.
pub fn execute_provisioning(
    plan: &MySqlProvisioningPlan,
    executor: &mut impl MySqlDdlExecutor,
    journal: &mut impl ProvisioningJournal,
) -> Result<MySqlTenantIdentity, ProvisioningError> {
    let tenant_id = plan.identity().tenant_id.to_string();
    journal.begin(&tenant_id).map_err(|_| ProvisioningError::JournalUnavailable)?;
    let mut applied = Vec::new();

    for (index, statement) in plan.statements().iter().enumerate() {
        if journal.step_started(&tenant_id, index).is_err() {
            if applied.is_empty() {
                return Err(ProvisioningError::JournalUnavailable);
            }
            let mut compensation_failures = compensate(plan, &applied, executor, journal, &tenant_id);
            if journal.needs_reconciliation(&tenant_id, index).is_err() {
                compensation_failures += 1;
            }
            return Err(ProvisioningError::ExecutionFailed {
                failed_step: index,
                compensation_failures,
            });
        }
        if executor.execute(statement).is_err() {
            let mut compensation_failures = compensate(plan, &applied, executor, journal, &tenant_id);
            if journal.needs_reconciliation(&tenant_id, index).is_err() {
                compensation_failures += 1;
            }
            return Err(ProvisioningError::ExecutionFailed {
                failed_step: index,
                compensation_failures,
            });
        }
        applied.push(index);
        if journal.step_applied(&tenant_id, index).is_err() {
            let mut compensation_failures = compensate(plan, &applied, executor, journal, &tenant_id);
            if journal.needs_reconciliation(&tenant_id, index).is_err() {
                compensation_failures += 1;
            }
            return Err(ProvisioningError::ExecutionFailed {
                failed_step: index,
                compensation_failures,
            });
        }
    }

    if journal.complete(&tenant_id).is_err() {
        let mut compensation_failures = compensate(
            plan, &applied, executor, journal, &tenant_id
        );
        if journal.needs_reconciliation(&tenant_id, plan.statements().len()).is_err() {
            compensation_failures += 1;
        }
        return Err(ProvisioningError::ExecutionFailed {
            failed_step: plan.statements().len(),
            compensation_failures,
        });
    }
    Ok(plan.identity().clone())
}


fn compensate(
    plan: &MySqlProvisioningPlan,
    applied: &[usize],
    executor: &mut impl MySqlDdlExecutor,
    journal: &mut impl ProvisioningJournal,
    tenant_id: &str,
) -> usize {
    let mut failures = 0usize;
    for (original_step, sql) in compensation_statements(plan, applied) {
        if executor.execute(&sql).is_err()
            || journal.step_compensated(tenant_id, original_step).is_err()
        {
            failures += 1;
        }
    }
    failures
}

fn compensation_statements(
    plan: &MySqlProvisioningPlan,
    applied: &[usize],
) -> Vec<(usize, String)> {
    let identity = plan.identity();
    let host = plan.account_host();
    let mut statements = Vec::new();
    if applied.contains(&2) {
        statements.push((2, format!("DROP USER IF EXISTS '{}'@'{}'", identity.migration_username, host)));
    }
    if applied.contains(&1) {
        statements.push((1, format!("DROP USER IF EXISTS '{}'@'{}'", identity.runtime_username, host)));
    }
    if applied.contains(&0) {
        statements.push((0, format!("DROP DATABASE {}", identity.database_name)));
    }
    statements
}

#[cfg(test)]
mod tests {
    use super::*;
    use proxima_engine::mysql_isolation::build_provisioning_plan;
    use uuid::Uuid;

    #[derive(Default)]
    struct FakeExecutor {
        calls: Vec<String>,
        fail_at: Option<usize>,
    }
    impl MySqlDdlExecutor for FakeExecutor {
        fn execute(&mut self, statement: &str) -> Result<(), ()> {
            let index = self.calls.len();
            self.calls.push(statement.to_owned());
            if self.fail_at == Some(index) { Err(()) } else { Ok(()) }
        }
    }

    #[derive(Default)]
    struct FakeJournal { events: Vec<String> }
    impl ProvisioningJournal for FakeJournal {
        fn begin(&mut self, tenant_id: &str) -> Result<(), ()> {
            self.events.push(format!("begin:{tenant_id}")); Ok(())
        }
        fn step_started(&mut self, _tenant_id: &str, step: usize) -> Result<(), ()> {
            self.events.push(format!("started:{step}")); Ok(())
        }
        fn step_applied(&mut self, _tenant_id: &str, step: usize) -> Result<(), ()> {
            self.events.push(format!("applied:{step}")); Ok(())
        }
        fn step_compensated(&mut self, _tenant_id: &str, step: usize) -> Result<(), ()> {
            self.events.push(format!("compensated:{step}")); Ok(())
        }
        fn needs_reconciliation(&mut self, _tenant_id: &str, step: usize) -> Result<(), ()> {
            self.events.push(format!("reconcile:{step}")); Ok(())
        }
        fn complete(&mut self, tenant_id: &str) -> Result<(), ()> {
            self.events.push(format!("complete:{tenant_id}")); Ok(())
        }
    }

    const PASSWORD_A: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    const PASSWORD_B: &str = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";

    fn plan() -> MySqlProvisioningPlan {
        build_provisioning_plan(Uuid::new_v4(), "127.0.0.1", PASSWORD_A, PASSWORD_B).unwrap()
    }

    #[test]
    fn successful_provisioning_journals_each_step() {
        let plan = plan();
        let mut executor = FakeExecutor::default();
        let mut journal = FakeJournal::default();
        let result = execute_provisioning(&plan, &mut executor, &mut journal).unwrap();
        assert_eq!(result, plan.identity().clone());
        assert_eq!(executor.calls.len(), 5);
        assert!(journal.events.iter().any(|event| event.starts_with("complete:")));
    }

    #[test]
    fn failed_provisioning_compensates_confirmed_resources_and_flags_reconciliation() {
        let plan = plan();
        let mut executor = FakeExecutor { calls: Vec::new(), fail_at: Some(3) };
        let mut journal = FakeJournal::default();
        let error = execute_provisioning(&plan, &mut executor, &mut journal).unwrap_err();
        assert!(matches!(error, ProvisioningError::ExecutionFailed { failed_step: 3, .. }));
        assert!(journal.events.iter().any(|event| event == "reconcile:3"));
        assert!(executor.calls.iter().any(|sql| sql.starts_with("DROP USER IF EXISTS")));
        assert!(executor.calls.iter().any(|sql| sql.starts_with("DROP DATABASE")));
    }

    #[test]
    fn first_statement_failure_never_drops_a_preexisting_database() {
        let plan = plan();
        let mut executor = FakeExecutor { calls: Vec::new(), fail_at: Some(0) };
        let mut journal = FakeJournal::default();
        let _ = execute_provisioning(&plan, &mut executor, &mut journal);
        assert_eq!(executor.calls.len(), 1);
        assert!(!executor.calls.iter().any(|sql| sql.starts_with("DROP DATABASE")));
    }

    #[test]
    fn errors_do_not_disclose_passwords_or_sql() {
        let error = ProvisioningError::ExecutionFailed { failed_step: 2, compensation_failures: 1 };
        let message = error.to_string();
        assert!(!message.contains(PASSWORD_A));
        assert!(!message.contains("CREATE USER"));
    }
}
