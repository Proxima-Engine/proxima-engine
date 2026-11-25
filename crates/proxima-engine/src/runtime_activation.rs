//! Gateway process supervision with durable, PID-reuse-resistant process leases.
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    collections::HashMap,
    fs, io,
    net::SocketAddr,
    path::{Path, PathBuf},
    process::{Command as StdCommand, Stdio as StdStdio},
    sync::Arc,
    time::Duration,
};
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

#[derive(Clone)]
pub struct RuntimeProcessSupervisor {
    children: Arc<Mutex<HashMap<String, Child>>>,
    lease_dir: PathBuf,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct ProcessLease {
    schema_version: u32,
    assignment_id: String,
    pid: u32,
    executable: String,
    args: Vec<String>,
    process_identity: String,
}

impl RuntimeProcessSupervisor {
    pub fn new() -> Self {
        let lease_dir = std::env::var_os("PROXIMA_NODE_RUNTIME_PROCESS_DIR")
            .map(PathBuf::from)
            .unwrap_or_else(|| PathBuf::from("data/runtime-processes"));
        Self {
            children: Arc::new(Mutex::new(HashMap::new())),
            lease_dir,
        }
    }

    pub async fn start(&self, spec: GatewayProcessSpec) -> io::Result<()> {
        if spec.assignment_id.trim().is_empty() {
            return Err(invalid("assignment_id cannot be empty"));
        }
        if !spec.readiness_addr.ip().is_loopback() {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "gateway readiness address must be loopback",
            ));
        }
        let executable =
            fs::canonicalize(&spec.executable).unwrap_or_else(|_| PathBuf::from(&spec.executable));
        let executable = executable.to_string_lossy().into_owned();
        {
            let children = self.children.lock().await;
            if children.contains_key(&spec.assignment_id) {
                return Err(io::Error::new(
                    io::ErrorKind::AlreadyExists,
                    "assignment already has a supervised process",
                ));
            }
        }

        // Re-adopt a still-running process only when its PID, executable, command
        // line and OS process-start identity all match the durable lease. This
        // prevents PID reuse from attaching an unrelated process to an assignment.
        let lease_path = self.lease_path(&spec.assignment_id);
        if let Some(lease) = self.read_lease(&lease_path)? {
            if lease.assignment_id == spec.assignment_id && self.lease_process_matches(&lease) {
                if lease.executable == executable && lease.args == spec.args {
                    return self
                        .wait_for_address(spec.readiness_addr, spec.startup_timeout)
                        .await;
                }
                terminate_verified(&lease)?;
            }
            let _ = fs::remove_file(&lease_path);
        }

        let mut command = Command::new(&executable);
        command
            .args(&spec.args)
            .stdin(StdStdio::null())
            .stdout(StdStdio::null())
            .stderr(StdStdio::null())
            .kill_on_drop(true);
        for (key, value) in &spec.env {
            command.env(key, value);
        }
        let child = command.spawn()?;
        let pid = child
            .id()
            .ok_or_else(|| invalid("gateway child process has no PID"))?;
        let mut identity = None;
        for _ in 0..20 {
            identity = process_identity(pid);
            if identity.is_some() {
                break;
            }
            sleep(Duration::from_millis(50)).await;
        }
        let Some(process_identity) = identity else {
            let mut child = child;
            let _ = child.start_kill();
            let _ = child.wait().await;
            return Err(io::Error::new(
                io::ErrorKind::Other,
                "could not establish gateway process identity",
            ));
        };
        let lease = ProcessLease {
            schema_version: 1,
            assignment_id: spec.assignment_id.clone(),
            pid,
            executable: executable.clone(),
            args: spec.args.clone(),
            process_identity,
        };
        self.write_lease(&lease_path, &lease)?;
        {
            let mut children = self.children.lock().await;
            children.insert(spec.assignment_id.clone(), child);
        }
        match self
            .wait_until_ready(
                &spec.assignment_id,
                spec.readiness_addr,
                spec.startup_timeout,
            )
            .await
        {
            Ok(()) => Ok(()),
            Err(error) => {
                let _ = self.stop(&spec.assignment_id).await;
                Err(error)
            }
        }
    }

    async fn wait_until_ready(
        &self,
        assignment_id: &str,
        address: SocketAddr,
        startup_timeout: Duration,
    ) -> io::Result<()> {
        let deadline = Instant::now() + startup_timeout;
        loop {
            {
                let mut children = self.children.lock().await;
                let child = children
                    .get_mut(assignment_id)
                    .ok_or_else(|| invalid("supervised process disappeared during startup"))?;
                if let Some(status) = child.try_wait()? {
                    children.remove(assignment_id);
                    let _ = fs::remove_file(self.lease_path(assignment_id));
                    return Err(io::Error::new(
                        io::ErrorKind::Other,
                        format!("gateway exited before readiness: {status}"),
                    ));
                }
            }
            if timeout(Duration::from_millis(500), TcpStream::connect(address))
                .await
                .is_ok_and(|r| r.is_ok())
            {
                return Ok(());
            }
            if Instant::now() >= deadline {
                return Err(io::Error::new(
                    io::ErrorKind::TimedOut,
                    "gateway did not become reachable before startup timeout",
                ));
            }
            sleep(Duration::from_millis(200)).await;
        }
    }

    async fn wait_for_address(
        &self,
        address: SocketAddr,
        startup_timeout: Duration,
    ) -> io::Result<()> {
        let deadline = Instant::now() + startup_timeout;
        loop {
            if timeout(Duration::from_millis(500), TcpStream::connect(address))
                .await
                .is_ok_and(|r| r.is_ok())
            {
                return Ok(());
            }
            if Instant::now() >= deadline {
                return Err(io::Error::new(
                    io::ErrorKind::TimedOut,
                    "recovered gateway process is not reachable",
                ));
            }
            sleep(Duration::from_millis(200)).await;
        }
    }

    pub async fn stop(&self, assignment_id: &str) -> io::Result<()> {
        let child = { self.children.lock().await.remove(assignment_id) };
        if let Some(mut child) = child {
            match child.try_wait()? {
                Some(_) => {}
                None => {
                    child.start_kill()?;
                    let _ = child.wait().await?;
                }
            }
        } else if let Some(lease) = self.read_lease(&self.lease_path(assignment_id))? {
            if lease.assignment_id == assignment_id && self.lease_process_matches(&lease) {
                terminate_verified(&lease)?;
            }
        }
        let _ = fs::remove_file(self.lease_path(assignment_id));
        Ok(())
    }

    pub async fn stop_all(&self) -> io::Result<()> {
        let mut ids: std::collections::HashSet<String> =
            { self.children.lock().await.keys().cloned().collect() };
        if self.lease_dir.exists() {
            for entry in fs::read_dir(&self.lease_dir)? {
                let path = entry?.path();
                if path.extension().and_then(|x| x.to_str()) != Some("json") {
                    continue;
                }
                if let Some(lease) = self.read_lease(&path)? {
                    ids.insert(lease.assignment_id);
                }
            }
        }
        for id in ids {
            self.stop(&id).await?;
        }
        Ok(())
    }

    pub async fn is_running(&self, assignment_id: &str) -> bool {
        {
            let mut children = self.children.lock().await;
            if let Some(child) = children.get_mut(assignment_id) {
                return matches!(child.try_wait(), Ok(None));
            }
        }
        self.read_lease(&self.lease_path(assignment_id))
            .ok()
            .flatten()
            .is_some_and(|lease| {
                lease.assignment_id == assignment_id && self.lease_process_matches(&lease)
            })
    }

    fn lease_path(&self, assignment_id: &str) -> PathBuf {
        let hash = hex::encode(Sha256::digest(assignment_id.as_bytes()));
        self.lease_dir.join(format!("{hash}.json"))
    }
    fn read_lease(&self, path: &Path) -> io::Result<Option<ProcessLease>> {
        if !path.exists() {
            return Ok(None);
        }
        let raw = fs::read(path)?;
        let lease: ProcessLease = serde_json::from_slice(&raw)
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
        if lease.schema_version != 1 || lease.pid == 0 {
            return Err(invalid("invalid gateway process lease"));
        }
        Ok(Some(lease))
    }
    fn write_lease(&self, path: &Path, lease: &ProcessLease) -> io::Result<()> {
        fs::create_dir_all(&self.lease_dir)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&self.lease_dir, fs::Permissions::from_mode(0o700))?;
        }
        let tmp = path.with_extension("json.tmp");
        if tmp.exists() {
            fs::remove_file(&tmp)?;
        }
        let bytes =
            serde_json::to_vec(lease).map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
        #[cfg(unix)]
        {
            use std::io::Write;
            use std::os::unix::fs::OpenOptionsExt;
            let mut f = fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .mode(0o600)
                .open(&tmp)?;
            f.write_all(&bytes)?;
            f.sync_all()?;
        }
        #[cfg(not(unix))]
        {
            fs::write(&tmp, bytes)?;
        }
        if path.exists() {
            fs::remove_file(path)?;
        }
        fs::rename(tmp, path)?;
        Ok(())
    }
    fn lease_process_matches(&self, lease: &ProcessLease) -> bool {
        process_identity(lease.pid).is_some_and(|identity| identity == lease.process_identity)
    }
}

impl Default for RuntimeProcessSupervisor {
    fn default() -> Self {
        Self::new()
    }
}

fn process_identity(pid: u32) -> Option<String> {
    #[cfg(target_os = "linux")]
    {
        let root = PathBuf::from(format!("/proc/{pid}"));
        let executable = fs::read_link(root.join("exe"))
            .ok()?
            .to_string_lossy()
            .into_owned();
        let command = fs::read(root.join("cmdline")).ok()?;
        let stat = fs::read_to_string(root.join("stat")).ok()?;
        let close = stat.rfind(')')?;
        let fields: Vec<&str> = stat[close + 1..].split_whitespace().collect();
        let start_ticks = *fields.get(19)?;
        Some(format!(
            "{executable}\n{}\n{start_ticks}",
            hex::encode(command)
        ))
    }
    #[cfg(target_os = "windows")]
    {
        let script = format!("$p=Get-CimInstance Win32_Process -Filter 'ProcessId = {pid}'; if ($p) {{ [Console]::Write($p.ExecutablePath + [char]10 + $p.CommandLine + [char]10 + $p.CreationDate) }}");
        let out = StdCommand::new("powershell.exe")
            .args(["-NoProfile", "-NonInteractive", "-Command", &script])
            .stdout(StdStdio::piped())
            .stderr(StdStdio::null())
            .output()
            .ok()?;
        if !out.status.success() || out.stdout.is_empty() {
            return None;
        }
        Some(String::from_utf8_lossy(&out.stdout).trim().to_owned())
    }
    #[cfg(target_os = "macos")]
    {
        let out = StdCommand::new("ps")
            .args(["-p", &pid.to_string(), "-o", "lstart=", "-o", "command="])
            .output()
            .ok()?;
        if !out.status.success() || out.stdout.is_empty() {
            return None;
        }
        Some(String::from_utf8_lossy(&out.stdout).trim().to_owned())
    }
    #[cfg(not(any(target_os = "linux", target_os = "windows", target_os = "macos")))]
    {
        let _ = pid;
        None
    }
}

fn terminate_verified(lease: &ProcessLease) -> io::Result<()> {
    if process_identity(lease.pid).as_deref() != Some(lease.process_identity.as_str()) {
        return Ok(());
    }
    #[cfg(target_os = "windows")]
    {
        let status = StdCommand::new("taskkill.exe")
            .args(["/PID", &lease.pid.to_string(), "/T", "/F"])
            .status()?;
        if !status.success() && process_identity(lease.pid).is_some() {
            return Err(io::Error::new(
                io::ErrorKind::Other,
                "could not terminate recovered gateway process",
            ));
        }
    }
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    {
        let _ = StdCommand::new("kill")
            .args(["-TERM", &lease.pid.to_string()])
            .status()?;
        for _ in 0..20 {
            if process_identity(lease.pid).is_none() {
                return Ok(());
            }
            std::thread::sleep(Duration::from_millis(100));
        }
        if process_identity(lease.pid).as_deref() == Some(lease.process_identity.as_str()) {
            let _ = StdCommand::new("kill")
                .args(["-KILL", &lease.pid.to_string()])
                .status()?;
        }
    }
    Ok(())
}
fn invalid(message: impl std::fmt::Display) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidInput, message.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn current_process_has_a_stable_os_identity() {
        let pid = std::process::id();
        let first = process_identity(pid).expect("current process identity should be readable");
        let second =
            process_identity(pid).expect("current process identity should remain readable");
        assert_eq!(first, second);
    }

    #[test]
    fn process_lease_round_trips_with_assignment_and_start_identity() {
        let lease = ProcessLease {
            schema_version: 1,
            assignment_id: "assignment-01".into(),
            pid: 12345,
            executable: "C:/Agata/proxima-gateway.exe".into(),
            args: vec!["--config-hash".into(), "sha256:abc".into()],
            process_identity: "process-start-identity".into(),
        };
        let encoded = serde_json::to_vec(&lease).unwrap();
        let decoded: ProcessLease = serde_json::from_slice(&encoded).unwrap();
        assert_eq!(decoded.assignment_id, lease.assignment_id);
        assert_eq!(decoded.pid, lease.pid);
        assert_eq!(decoded.process_identity, lease.process_identity);
        assert_eq!(decoded.args, lease.args);
    }
}
