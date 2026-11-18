//! Journaled execution contract for MySQL tenant DDL.
//!
//! MySQL DDL implicitly commits. This module requires a durable journal and
//! compensates only operations whose success was recorded. It never assumes
//! that a failed network call means the server did not apply the statement.
use crate::{
    isolation::{MySqlProvisioningPlan, MySqlTenantIdentity},
    protocol::Packet,
    upstream::{connect_admin, read_packet, write_packet, UpstreamTlsConfig},
};
use std::{fmt, future::Future, pin::Pin, time::Duration};
use tokio::{net::TcpStream, time::timeout};
use tokio_rustls::client::TlsStream;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DdlExecutionError;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct JournalError;

pub trait MySqlDdlExecutor: Send {
    fn execute<'a>(
        &'a mut self,
        statement: &'a str,
    ) -> Pin<Box<dyn Future<Output = Result<(), DdlExecutionError>> + Send + 'a>>;
}

/// Verified-TLS administrator connection used only by tenant provisioning.
/// Do not share this connection with application traffic.
pub struct MySqlAdminExecutor {
    stream: TlsStream<TcpStream>,
    max_packet_size: usize,
    statement_timeout: Duration,
    usable: bool,
}

impl MySqlAdminExecutor {
    pub async fn connect(
        config: &UpstreamTlsConfig,
        username: &str,
        password: &str,
        statement_timeout: Duration,
    ) -> Result<Self, DdlExecutionError> {
        if statement_timeout.is_zero() {
            return Err(DdlExecutionError);
        }
        let stream = connect_admin(config, username, password)
            .await
            .map_err(|_| DdlExecutionError)?;
        // The configured maximum is already validated by UpstreamTlsConfig.
        Ok(Self {
            stream,
            max_packet_size: config.max_packet_size(),
            statement_timeout,
            usable: true,
        })
    }
}

impl MySqlDdlExecutor for MySqlAdminExecutor {
    fn execute<'a>(
        &'a mut self,
        statement: &'a str,
    ) -> Pin<Box<dyn Future<Output = Result<(), DdlExecutionError>> + Send + 'a>> {
        Box::pin(async move {
            if !self.usable || statement.is_empty()
                || statement.len() + 1 > self.max_packet_size
                || statement.as_bytes().contains(&0)
            {
                return Err(DdlExecutionError);
            }
            let mut payload = Vec::with_capacity(statement.len() + 1);
            payload.push(0x03); // COM_QUERY
            payload.extend_from_slice(statement.as_bytes());
            let request = Packet { sequence: 0, payload };
            if write_packet(&mut self.stream, &request, self.max_packet_size).await.is_err() {
                self.usable = false;
                return Err(DdlExecutionError);
            }
            let response = match timeout(
                self.statement_timeout,
                read_packet(&mut self.stream, self.max_packet_size),
            ).await {
                Ok(Ok(packet)) => packet,
                _ => {
                    self.usable = false;
                    return Err(DdlExecutionError);
                }
            };
            if response.sequence != 1 {
                self.usable = false;
                return Err(DdlExecutionError);
            }
            match response.payload.first() {
                Some(0x00) => Ok(()), // OK packet
                Some(0xff) => Err(DdlExecutionError), // ERR packet; stream remains synchronized
                _ => {
                    // DDL plan statements must return OK or ERR. A result set,
                    // LOCAL INFILE request or unknown response makes the
                    // connection unsuitable for compensation.
                    self.usable = false;
                    Err(DdlExecutionError)
                }
            }
        })
    }
}

pub trait ProvisioningJournal {
    fn begin(&mut self, tenant_id: &str) -> Result<(), JournalError>;
    fn step_started(&mut self, tenant_id: &str, step: usize) -> Result<(), JournalError>;
    fn step_applied(&mut self, tenant_id: &str, step: usize) -> Result<(), JournalError>;
    fn step_compensated(&mut self, tenant_id: &str, step: usize) -> Result<(), JournalError>;
    fn needs_reconciliation(&mut self, tenant_id: &str, failed_step: usize) -> Result<(), JournalError>;
    fn complete(&mut self, tenant_id: &str) -> Result<(), JournalError>;
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
pub async fn execute_provisioning(
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
            let mut compensation_failures = compensate(plan, &applied, executor, journal, &tenant_id).await;
            if journal.needs_reconciliation(&tenant_id, index).is_err() {
                compensation_failures += 1;
            }
            return Err(ProvisioningError::ExecutionFailed {
                failed_step: index,
                compensation_failures,
            });
        }
        if executor.execute(statement).await.is_err() {
            let mut compensation_failures = compensate(plan, &applied, executor, journal, &tenant_id).await;
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
        ).await;
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


async fn compensate(
    plan: &MySqlProvisioningPlan,
    applied: &[usize],
    executor: &mut impl MySqlDdlExecutor,
    journal: &mut impl ProvisioningJournal,
    tenant_id: &str,
) -> usize {
    let mut failures = 0usize;
    for (original_step, sql) in compensation_statements(plan, applied) {
        if executor.execute(&sql).await.is_err()
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
    use crate::isolation::build_provisioning_plan;
    use uuid::Uuid;

    #[derive(Default)]
    struct FakeExecutor {
        calls: Vec<String>,
        fail_at: Option<usize>,
    }
    impl MySqlDdlExecutor for FakeExecutor {
        fn execute<'a>(
            &'a mut self,
            statement: &'a str,
        ) -> Pin<Box<dyn Future<Output = Result<(), DdlExecutionError>> + Send + 'a>> {
            Box::pin(async move {
                let index = self.calls.len();
                self.calls.push(statement.to_owned());
                if self.fail_at == Some(index) { Err(DdlExecutionError) } else { Ok(()) }
            })
        }
    }

    #[derive(Default)]
    struct FakeJournal { events: Vec<String> }
    impl ProvisioningJournal for FakeJournal {
        fn begin(&mut self, tenant_id: &str) -> Result<(), JournalError> {
            self.events.push(format!("begin:{tenant_id}")); Ok(())
        }
        fn step_started(&mut self, _tenant_id: &str, step: usize) -> Result<(), JournalError> {
            self.events.push(format!("started:{step}")); Ok(())
        }
        fn step_applied(&mut self, _tenant_id: &str, step: usize) -> Result<(), JournalError> {
            self.events.push(format!("applied:{step}")); Ok(())
        }
        fn step_compensated(&mut self, _tenant_id: &str, step: usize) -> Result<(), JournalError> {
            self.events.push(format!("compensated:{step}")); Ok(())
        }
        fn needs_reconciliation(&mut self, _tenant_id: &str, step: usize) -> Result<(), JournalError> {
            self.events.push(format!("reconcile:{step}")); Ok(())
        }
        fn complete(&mut self, tenant_id: &str) -> Result<(), JournalError> {
            self.events.push(format!("complete:{tenant_id}")); Ok(())
        }
    }

    const PASSWORD_A: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    const PASSWORD_B: &str = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";

    fn plan() -> MySqlProvisioningPlan {
        build_provisioning_plan(Uuid::new_v4(), "127.0.0.1", PASSWORD_A, PASSWORD_B).unwrap()
    }

    #[tokio::test]
    async fn successful_provisioning_journals_each_step() {
        let plan = plan();
        let mut executor = FakeExecutor::default();
        let mut journal = FakeJournal::default();
        let result = execute_provisioning(&plan, &mut executor, &mut journal).await.unwrap();
        assert_eq!(result, plan.identity().clone());
        assert_eq!(executor.calls.len(), 5);
        assert!(journal.events.iter().any(|event| event.starts_with("complete:")));
    }

    #[tokio::test]
    async fn failed_provisioning_compensates_confirmed_resources_and_flags_reconciliation() {
        let plan = plan();
        let mut executor = FakeExecutor { calls: Vec::new(), fail_at: Some(3) };
        let mut journal = FakeJournal::default();
        let error = execute_provisioning(&plan, &mut executor, &mut journal).await.unwrap_err();
        assert!(matches!(error, ProvisioningError::ExecutionFailed { failed_step: 3, .. }));
        assert!(journal.events.iter().any(|event| event == "reconcile:3"));
        assert!(executor.calls.iter().any(|sql| sql.starts_with("DROP USER IF EXISTS")));
        assert!(executor.calls.iter().any(|sql| sql.starts_with("DROP DATABASE")));
    }

    #[tokio::test]
    async fn first_statement_failure_never_drops_a_preexisting_database() {
        let plan = plan();
        let mut executor = FakeExecutor { calls: Vec::new(), fail_at: Some(0) };
        let mut journal = FakeJournal::default();
        let _ = execute_provisioning(&plan, &mut executor, &mut journal).await;
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
