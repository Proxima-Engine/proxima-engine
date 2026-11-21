use std::{future::Future, io, path::Path};

use crate::{
    runtime_activation::{GatewayProcessSpec, RuntimeProcessSupervisor},
    runtime_reconciliation::{self, RuntimeRecord},
};

#[derive(Clone, Default)]
pub struct RuntimeCoordinator {
    supervisor: RuntimeProcessSupervisor,
}

impl RuntimeCoordinator {
    pub fn new() -> Self { Self::default() }

    pub async fn activate<F, Fut>(
        &self,
        state_path: &Path,
        state: &mut RuntimeRecord,
        spec: GatewayProcessSpec,
        provider_health_check: F,
    ) -> io::Result<()>
    where
        F: FnOnce() -> Fut,
        Fut: Future<Output = io::Result<()>>,
    {
        if spec.assignment_id != state.assignment_id {
            return Err(io::Error::new(io::ErrorKind::InvalidInput, "gateway assignment does not match runtime state"));
        }
        let revision = state.desired_revision;
        let credential_revision = state.credential_revision;

        // Reconciliation is idempotent across lost acknowledgements and worker
        // retries: replace any prior child for this assignment before applying
        // the current desired revision.
        self.supervisor.stop(&state.assignment_id).await?;
        state.begin_apply(revision, credential_revision)?;
        runtime_reconciliation::persist(state_path, state)?;

        if let Err(error) = self.supervisor.start(spec).await {
            state.mark_failed("GATEWAY_START_FAILED")?;
            runtime_reconciliation::persist(state_path, state)?;
            return Err(error);
        }
        if let Err(error) = provider_health_check().await {
            let _ = self.supervisor.stop(&state.assignment_id).await;
            state.mark_failed("PROVIDER_HEALTH_FAILED")?;
            runtime_reconciliation::persist(state_path, state)?;
            return Err(error);
        }
        if let Err(error) = state.mark_applied(revision, true) {
            let _ = self.supervisor.stop(&state.assignment_id).await;
            state.mark_failed("RUNTIME_STATE_TRANSITION_FAILED")?;
            runtime_reconciliation::persist(state_path, state)?;
            return Err(error);
        }
        if let Err(error) = runtime_reconciliation::persist(state_path, state) {
            let _ = self.supervisor.stop(&state.assignment_id).await;
            return Err(error);
        }
        Ok(())
    }

    pub async fn revoke(&self, state_path: &Path, state: &mut RuntimeRecord) -> io::Result<()> {
        self.supervisor.stop(&state.assignment_id).await?;
        state.begin_revocation();
        runtime_reconciliation::persist(state_path, state)
    }

    pub async fn is_running(&self, assignment_id: &str) -> bool {
        self.supervisor.is_running(assignment_id).await
    }

    pub async fn shutdown(&self) -> io::Result<()> { self.supervisor.stop_all().await }
}
