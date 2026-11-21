use std::{collections::HashMap, io, net::SocketAddr, process::Stdio, sync::Arc, time::Duration};

use tokio::{
    net::TcpStream,
    process::{Child, Command},
    sync::Mutex,
    time::{sleep, timeout, Instant},
};

#[derive(Clone, Debug)]
pub struct GatewayProcessSpec {
    pub assignment_id: String,
    pub executable: String,
    pub args: Vec<String>,
    pub env: Vec<(String, String)>,
    pub readiness_addr: SocketAddr,
    pub startup_timeout: Duration,
}

#[derive(Clone, Default)]
pub struct RuntimeProcessSupervisor {
    children: Arc<Mutex<HashMap<String, Child>>>,
}

impl RuntimeProcessSupervisor {
    pub fn new() -> Self { Self::default() }

    pub async fn start(&self, spec: GatewayProcessSpec) -> io::Result<()> {
        if spec.assignment_id.trim().is_empty() {
            return Err(io::Error::new(io::ErrorKind::InvalidInput, "assignment_id cannot be empty"));
        }
        if !spec.readiness_addr.ip().is_loopback() {
            return Err(io::Error::new(io::ErrorKind::PermissionDenied, "gateway readiness address must be loopback"));
        }
        if spec.startup_timeout.is_zero() {
            return Err(io::Error::new(io::ErrorKind::InvalidInput, "startup_timeout must be positive"));
        }

        // Keep the lock through spawn + insertion so two concurrent reconciliations
        // cannot launch duplicate children for the same assignment.
        {
            let mut children = self.children.lock().await;
            if children.contains_key(&spec.assignment_id) {
                return Err(io::Error::new(io::ErrorKind::AlreadyExists, "assignment already has a supervised process"));
            }
            let mut command = Command::new(&spec.executable);
            command.args(&spec.args)
                .stdin(Stdio::null())
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .kill_on_drop(true);
            for (key, value) in &spec.env { command.env(key, value); }
            let child = command.spawn()?;
            children.insert(spec.assignment_id.clone(), child);
        }

        match self.wait_until_ready(&spec.assignment_id, spec.readiness_addr, spec.startup_timeout).await {
            Ok(()) => Ok(()),
            Err(error) => {
                let _ = self.stop(&spec.assignment_id).await;
                Err(error)
            }
        }
    }

    async fn wait_until_ready(&self, assignment_id: &str, address: SocketAddr, startup_timeout: Duration) -> io::Result<()> {
        let deadline = Instant::now() + startup_timeout;
        loop {
            {
                let mut children = self.children.lock().await;
                let child = children.get_mut(assignment_id).ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, "supervised process disappeared during startup"))?;
                if let Some(status) = child.try_wait()? {
                    children.remove(assignment_id);
                    return Err(io::Error::new(io::ErrorKind::Other, format!("gateway exited before readiness: {status}")));
                }
            }
            if timeout(Duration::from_millis(400), TcpStream::connect(address)).await.is_ok_and(|result| result.is_ok()) {
                // Verify the child still exists after the listener becomes reachable.
                let mut children = self.children.lock().await;
                let child = children.get_mut(assignment_id).ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, "gateway exited during readiness check"))?;
                if child.try_wait()?.is_none() { return Ok(()); }
                children.remove(assignment_id);
                return Err(io::Error::new(io::ErrorKind::Other, "gateway exited immediately after listener readiness"));
            }
            if Instant::now() >= deadline {
                return Err(io::Error::new(io::ErrorKind::TimedOut, "gateway did not become reachable before startup timeout"));
            }
            sleep(Duration::from_millis(150)).await;
        }
    }

    pub async fn stop(&self, assignment_id: &str) -> io::Result<()> {
        let child = self.children.lock().await.remove(assignment_id);
        if let Some(mut child) = child {
            if child.try_wait()?.is_none() {
                child.start_kill()?;
                let _ = child.wait().await?;
            }
        }
        Ok(())
    }

    pub async fn stop_all(&self) -> io::Result<()> {
        let ids: Vec<String> = self.children.lock().await.keys().cloned().collect();
        for id in ids { self.stop(&id).await?; }
        Ok(())
    }

    pub async fn is_running(&self, assignment_id: &str) -> bool {
        let mut children = self.children.lock().await;
        match children.get_mut(assignment_id) {
            Some(child) => matches!(child.try_wait(), Ok(None)),
            None => false,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[tokio::test]
    async fn refuses_non_loopback_readiness_addresses() {
        let supervisor = RuntimeProcessSupervisor::new();
        let spec = GatewayProcessSpec {
            assignment_id: "assignment-a".into(),
            executable: "not-started".into(),
            args: vec![],
            env: vec![],
            readiness_addr: "0.0.0.0:9000".parse().unwrap(),
            startup_timeout: Duration::from_secs(1),
        };
        assert_eq!(supervisor.start(spec).await.unwrap_err().kind(), io::ErrorKind::PermissionDenied);
    }
}
