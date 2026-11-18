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
use serde::{Deserialize, Serialize};
use std::{
    collections::HashSet,
    fmt,
    future::Future,
    fs::{self, File, OpenOptions},
    io::{BufRead, BufReader, Write},
    path::{Path, PathBuf},
    pin::Pin,
    time::{Duration, SystemTime, UNIX_EPOCH},
};
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

#[derive(Debug, Serialize, Deserialize)]
struct JournalEvent {
    tenant_id: String,
    event: String,
    step: Option<usize>,
    note: Option<String>,
    timestamp: u64,
}

/// Append-only, fsync-backed journal. A tenant left active by a process crash
/// is blocked on restart until an operator explicitly acknowledges reconciliation.
pub struct FileProvisioningJournal {
    file: File,
    active: HashSet<String>,
    blocked: HashSet<String>,
}

impl FileProvisioningJournal {
    pub fn open(path: impl Into<PathBuf>) -> Result<Self, JournalError> {
        let path = path.into();
        match fs::symlink_metadata(&path) {
            Ok(metadata) if metadata.file_type().is_symlink() => return Err(JournalError),
            Ok(_) => {}
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(_) => return Err(JournalError),
        }
        let parent = path.parent()
            .filter(|parent| !parent.as_os_str().is_empty())
            .unwrap_or_else(|| Path::new("."));
        fs::create_dir_all(parent).map_err(|_| JournalError)?;

        let mut active = HashSet::new();
        let mut blocked = HashSet::new();
        if path.exists() {
            let metadata = fs::metadata(&path).map_err(|_| JournalError)?;
            if !metadata.is_file() { return Err(JournalError); }
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                if metadata.permissions().mode() & 0o077 != 0 {
                    return Err(JournalError);
                }
            }
            let file = File::open(&path).map_err(|_| JournalError)?;
            let reader = BufReader::new(file);
            for line in reader.lines() {
                let line = line.map_err(|_| JournalError)?;
                let event: JournalEvent = serde_json::from_str(&line).map_err(|_| JournalError)?;
                if !valid_journal_event(&event) {
                    return Err(JournalError);
                }
                apply_journal_state(&event, &mut active, &mut blocked)?;
            }
        }
        // A begin without a terminal event is ambiguous after a restart.
        blocked.extend(active.drain());

        let mut options = OpenOptions::new();
        options.create(true).append(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        let file = options.open(&path).map_err(|_| JournalError)?;
        Ok(Self { file, active, blocked })
    }

    fn append(&mut self, tenant_id: &str, event: &str, step: Option<usize>, note: Option<&str>) -> Result<(), JournalError> {
        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|_| JournalError)?
            .as_secs();
        let record = JournalEvent {
            tenant_id: tenant_id.to_owned(),
            event: event.to_owned(),
            step,
            note: note.map(str::to_owned),
            timestamp,
        };
        let mut bytes = serde_json::to_vec(&record).map_err(|_| JournalError)?;
        bytes.push(b'\n');
        self.file.write_all(&bytes).map_err(|_| JournalError)?;
        self.file.sync_data().map_err(|_| JournalError)?;
        Ok(())
    }

    /// Resolve a crash or ambiguous DDL outcome after an operator has inspected
    /// the MySQL server and confirmed that the tenant is safe to retry.
    pub fn acknowledge_reconciliation(
        &mut self,
        tenant_id: &str,
        operator_note: &str,
    ) -> Result<(), JournalError> {
        if operator_note.trim().is_empty() || operator_note.len() > 1024
            || !self.blocked.contains(tenant_id)
        {
            return Err(JournalError);
        }
        self.append(tenant_id, "reconciled", None, Some(operator_note.trim()))?;
        self.blocked.remove(tenant_id);
        Ok(())
    }

    pub fn reconciliation_required(&self, tenant_id: &str) -> bool {
        self.blocked.contains(tenant_id)
    }
}

fn valid_journal_event(event: &JournalEvent) -> bool {
    if event.timestamp == 0 || event.note.as_ref().is_some_and(|note| note.len() > 1024) {
        return false;
    }
    match event.event.as_str() {
        "begin" | "complete" | "reconciled" => event.step.is_none(),
        "step_started" | "step_applied" | "step_compensated" | "needs_reconciliation" => event.step.is_some(),
        _ => false,
    }
}

fn apply_journal_state(
    event: &JournalEvent,
    active: &mut HashSet<String>,
    blocked: &mut HashSet<String>,
) -> Result<(), JournalError> {
    match event.event.as_str() {
        "begin" => {
            if active.contains(&event.tenant_id) || blocked.contains(&event.tenant_id) {
                return Err(JournalError);
            }
            active.insert(event.tenant_id.clone());
        }
        "step_started" | "step_applied" | "step_compensated" => {
            if !active.contains(&event.tenant_id) { return Err(JournalError); }
        }
        "complete" => {
            if !active.remove(&event.tenant_id) { return Err(JournalError); }
        }
        "needs_reconciliation" => {
            if !active.remove(&event.tenant_id) { return Err(JournalError); }
            blocked.insert(event.tenant_id.clone());
        }
        "reconciled" => {
            // A crash can leave an unfinished begin event without an explicit
            // needs_reconciliation record. The operator acknowledgement must
            // be able to close that ambiguous active state on the next restart.
            if !blocked.remove(&event.tenant_id) && !active.remove(&event.tenant_id) {
                return Err(JournalError);
            }
        }
        _ => return Err(JournalError),
    }
    Ok(())
}

impl ProvisioningJournal for FileProvisioningJournal {
    fn begin(&mut self, tenant_id: &str) -> Result<(), JournalError> {
        if tenant_id.is_empty() || self.active.contains(tenant_id) || self.blocked.contains(tenant_id) {
            return Err(JournalError);
        }
        self.append(tenant_id, "begin", None, None)?;
        self.active.insert(tenant_id.to_owned());
        Ok(())
    }
    fn step_started(&mut self, tenant_id: &str, step: usize) -> Result<(), JournalError> {
        if !self.active.contains(tenant_id) { return Err(JournalError); }
        self.append(tenant_id, "step_started", Some(step), None)
    }
    fn step_applied(&mut self, tenant_id: &str, step: usize) -> Result<(), JournalError> {
        if !self.active.contains(tenant_id) { return Err(JournalError); }
        self.append(tenant_id, "step_applied", Some(step), None)
    }
    fn step_compensated(&mut self, tenant_id: &str, step: usize) -> Result<(), JournalError> {
        if !self.active.contains(tenant_id) { return Err(JournalError); }
        self.append(tenant_id, "step_compensated", Some(step), None)
    }
    fn needs_reconciliation(&mut self, tenant_id: &str, failed_step: usize) -> Result<(), JournalError> {
        if !self.active.contains(tenant_id) { return Err(JournalError); }
        self.append(tenant_id, "needs_reconciliation", Some(failed_step), None)?;
        self.active.remove(tenant_id);
        self.blocked.insert(tenant_id.to_owned());
        Ok(())
    }
    fn complete(&mut self, tenant_id: &str) -> Result<(), JournalError> {
        if !self.active.contains(tenant_id) { return Err(JournalError); }
        self.append(tenant_id, "complete", None, None)?;
        self.active.remove(tenant_id);
        Ok(())
    }
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
    let (identity, ()) = execute_provisioning_with_finalize(
        plan,
        executor,
        journal,
        |_| Ok(()),
        |_, _| Ok(()),
    ).await?;
    Ok(identity)
}

/// Run the DDL plan, persist the gateway's local tenant credentials, and only
/// then mark provisioning complete. If finalization or journal completion
/// fails, revoke the local record and compensate the acknowledged DDL steps.
pub async fn execute_provisioning_with_finalize<T, F, R>(
    plan: &MySqlProvisioningPlan,
    executor: &mut impl MySqlDdlExecutor,
    journal: &mut impl ProvisioningJournal,
    finalize: F,
    rollback_finalize: R,
) -> Result<(MySqlTenantIdentity, T), ProvisioningError>
where
    F: FnOnce(&MySqlTenantIdentity) -> Result<T, ()>,
    R: FnOnce(&MySqlTenantIdentity, &T) -> Result<(), ()>,
{
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
            let mut compensation_failures = compensate(plan, &applied, executor, journal, &tenant_id).await;
            if journal.needs_reconciliation(&tenant_id, index).is_err() {
                compensation_failures += 1;
            }
            return Err(ProvisioningError::ExecutionFailed {
                failed_step: index,
                compensation_failures,
            });
        }
    }

    let identity = plan.identity().clone();
    let finalized = match finalize(&identity) {
        Ok(value) => value,
        Err(()) => {
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
    };

    if journal.complete(&tenant_id).is_err() {
        let mut compensation_failures = 0usize;
        if rollback_finalize(&identity, &finalized).is_err() {
            compensation_failures += 1;
        }
        compensation_failures += compensate(
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
    Ok((identity, finalized))
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
    fn file_journal_blocks_crash_interrupted_tenants_until_acknowledged() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("mysql-provisioning.jsonl");
        let tenant = Uuid::new_v4().to_string();
        {
            let mut journal = FileProvisioningJournal::open(&path).unwrap();
            journal.begin(&tenant).unwrap();
            journal.step_started(&tenant, 0).unwrap();
        }
        {
            let mut journal = FileProvisioningJournal::open(&path).unwrap();
            assert!(journal.reconciliation_required(&tenant));
            assert!(journal.begin(&tenant).is_err());
            journal.acknowledge_reconciliation(&tenant, "Inspected MySQL state; safe to retry").unwrap();
            assert!(!journal.reconciliation_required(&tenant));
            journal.begin(&tenant).unwrap();
            journal.complete(&tenant).unwrap();
        }
        let journal = FileProvisioningJournal::open(&path).unwrap();
        assert!(!journal.reconciliation_required(&tenant));
        let text = std::fs::read_to_string(path).unwrap();
        assert!(text.contains("Inspected MySQL state; safe to retry"));
    }

    #[test]
    fn file_journal_rejects_corrupt_or_out_of_order_events() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("bad-journal.jsonl");
        std::fs::write(
            &path,
            r#"{"tenant_id":"tenant-a","event":"step_applied","step":0,"note":null,"timestamp":1}"#,
        ).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
        }
        assert!(FileProvisioningJournal::open(&path).is_err());
    }

    #[test]
    fn errors_do_not_disclose_passwords_or_sql() {
        let error = ProvisioningError::ExecutionFailed { failed_step: 2, compensation_failures: 1 };
        let message = error.to_string();
        assert!(!message.contains(PASSWORD_A));
        assert!(!message.contains("CREATE USER"));
    }
}
