//! Durable desired-versus-applied state for node database assignments.
//!
//! This module deliberately does not equate a downloaded or decrypted bundle with
//! an applied runtime. Callers may transition to Applied only after the provider
//! runtime has been activated and its provider-specific health/isolation checks pass.

use std::{
    fs::{self, File, OpenOptions},
    io::{self, Write},
    path::{Path, PathBuf},
    time::{SystemTime, UNIX_EPOCH},
};

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum RuntimePhase {
    Empty,
    Staged,
    Applying,
    Applied,
    Failed,
    Revoked,
}

impl RuntimePhase {
    fn as_str(&self) -> &'static str {
        match self {
            Self::Empty => "empty",
            Self::Staged => "staged",
            Self::Applying => "applying",
            Self::Applied => "applied",
            Self::Failed => "failed",
            Self::Revoked => "revoked",
        }
    }

    fn parse(value: &str) -> io::Result<Self> {
        match value {
            "empty" => Ok(Self::Empty),
            "staged" => Ok(Self::Staged),
            "applying" => Ok(Self::Applying),
            "applied" => Ok(Self::Applied),
            "failed" => Ok(Self::Failed),
            "revoked" => Ok(Self::Revoked),
            _ => Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "unknown runtime phase",
            )),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RuntimeRecord {
    pub assignment_id: String,
    pub target_id: String,
    pub provider: String,
    pub desired_revision: u64,
    pub applied_revision: Option<u64>,
    pub phase: RuntimePhase,
    pub runtime_health_passed: bool,
    pub credential_revision: u64,
    pub last_error_code: Option<String>,
    pub updated_at_unix: u64,
}

impl RuntimeRecord {
    pub fn staged(
        assignment_id: String,
        target_id: String,
        provider: String,
        revision: u64,
        credential_revision: u64,
    ) -> io::Result<Self> {
        if assignment_id.trim().is_empty()
            || target_id.trim().is_empty()
            || provider.trim().is_empty()
            || revision == 0
        {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "invalid assignment identity or revision",
            ));
        }
        Ok(Self {
            assignment_id,
            target_id,
            provider,
            desired_revision: revision,
            applied_revision: None,
            phase: RuntimePhase::Staged,
            runtime_health_passed: false,
            credential_revision,
            last_error_code: None,
            updated_at_unix: now(),
        })
    }

    /// Begins reconciliation. Older revisions and identity changes cannot overwrite
    /// the durable record for an existing assignment.
    pub fn begin_apply(&mut self, revision: u64, credential_revision: u64) -> io::Result<()> {
        if revision != self.desired_revision || revision == 0 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "desired revision mismatch",
            ));
        }
        if credential_revision < self.credential_revision {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "credential revision rollback rejected",
            ));
        }
        if self.phase == RuntimePhase::Revoked {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "revoked assignment cannot be applied",
            ));
        }
        self.credential_revision = credential_revision;
        self.phase = RuntimePhase::Applying;
        self.runtime_health_passed = false;
        self.last_error_code = None;
        self.updated_at_unix = now();
        Ok(())
    }

    /// Reconcile a newer authenticated Cloud desired revision without claiming
    /// that the runtime is active. Preserve the last applied revision so callers
    /// can keep the previous runtime as the rollback target until replacement health
    /// checks pass. Assignment identity and both revision counters are monotonic.
    pub fn update_desired(
        &mut self,
        assignment_id: &str,
        target_id: &str,
        provider: &str,
        revision: u64,
        credential_revision: u64,
    ) -> io::Result<()> {
        if self.phase == RuntimePhase::Revoked {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "revoked assignment cannot be reused",
            ));
        }
        if assignment_id != self.assignment_id
            || target_id != self.target_id
            || provider != self.provider
        {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "assignment identity change requires a new runtime record",
            ));
        }
        if revision < self.desired_revision || revision == 0 {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "configuration revision rollback rejected",
            ));
        }
        if credential_revision < self.credential_revision {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "credential revision rollback rejected",
            ));
        }
        if revision == self.desired_revision && credential_revision == self.credential_revision {
            return Ok(());
        }
        self.desired_revision = revision;
        self.credential_revision = credential_revision;
        self.phase = RuntimePhase::Staged;
        self.runtime_health_passed = false;
        self.last_error_code = None;
        self.updated_at_unix = now();
        Ok(())
    }

    /// This is the only transition that records an applied revision. The caller
    /// must supply proof that runtime activation and provider-specific health checks
    /// have already completed successfully.
    pub fn mark_applied(&mut self, revision: u64, provider_health_passed: bool) -> io::Result<()> {
        if self.phase != RuntimePhase::Applying || revision != self.desired_revision {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "assignment is not applying this revision",
            ));
        }
        if !provider_health_passed {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "provider health verification is required",
            ));
        }
        self.applied_revision = Some(revision);
        self.runtime_health_passed = true;
        self.phase = RuntimePhase::Applied;
        self.last_error_code = None;
        self.updated_at_unix = now();
        Ok(())
    }

    pub fn mark_failed(&mut self, error_code: &str) -> io::Result<()> {
        let code = error_code.trim();
        if code.is_empty()
            || code.len() > 96
            || !code
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-')
        {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "invalid failure code",
            ));
        }
        self.phase = RuntimePhase::Failed;
        self.runtime_health_passed = false;
        self.last_error_code = Some(code.to_owned());
        self.updated_at_unix = now();
        Ok(())
    }

    /// Revocation invalidates the applied marker immediately. The caller must
    /// stop the runtime and revoke provider identities before reporting revocation
    /// as externally complete.
    pub fn begin_revocation(&mut self) {
        self.phase = RuntimePhase::Revoked;
        self.runtime_health_passed = false;
        self.applied_revision = None;
        self.last_error_code = None;
        self.updated_at_unix = now();
    }

    fn to_json(&self) -> String {
        serde_json::json!({
            "schema_version": 1,
            "assignment_id": self.assignment_id,
            "target_id": self.target_id,
            "provider": self.provider,
            "desired_revision": self.desired_revision,
            "applied_revision": self.applied_revision,
            "phase": self.phase.as_str(),
            "runtime_health_passed": self.runtime_health_passed,
            "credential_revision": self.credential_revision,
            "last_error_code": self.last_error_code,
            "updated_at_unix": self.updated_at_unix
        })
        .to_string()
    }

    fn from_json(raw: &str) -> io::Result<Self> {
        let value: serde_json::Value =
            serde_json::from_str(raw).map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
        if value.get("schema_version").and_then(|v| v.as_u64()) != Some(1) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "unsupported runtime state schema",
            ));
        }
        let string = |key: &str| {
            value
                .get(key)
                .and_then(|v| v.as_str())
                .map(str::to_owned)
                .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, format!("missing {key}")))
        };
        let number = |key: &str| {
            value
                .get(key)
                .and_then(|v| v.as_u64())
                .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, format!("missing {key}")))
        };
        let phase = RuntimePhase::parse(&string("phase")?)?;
        let applied_revision = match value.get("applied_revision") {
            Some(serde_json::Value::Number(n)) => n.as_u64(),
            Some(serde_json::Value::Null) | None => None,
            _ => {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "invalid applied_revision",
                ))
            }
        };
        let runtime_health_passed = value
            .get("runtime_health_passed")
            .and_then(|v| v.as_bool())
            .ok_or_else(|| {
                io::Error::new(io::ErrorKind::InvalidData, "missing runtime_health_passed")
            })?;
        if runtime_health_passed
            != (phase == RuntimePhase::Applied
                && applied_revision == Some(number("desired_revision")?))
        {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "inconsistent applied health marker",
            ));
        }
        Ok(Self {
            assignment_id: string("assignment_id")?,
            target_id: string("target_id")?,
            provider: string("provider")?,
            desired_revision: number("desired_revision")?,
            applied_revision,
            phase,
            runtime_health_passed,
            credential_revision: number("credential_revision")?,
            last_error_code: value
                .get("last_error_code")
                .and_then(|v| v.as_str())
                .map(str::to_owned),
            updated_at_unix: number("updated_at_unix")?,
        })
    }
}

/// Atomically persist state using a same-directory temporary file and rename.
/// On Unix, the state file is restricted to its owner (0600).
pub fn persist(path: impl AsRef<Path>, record: &RuntimeRecord) -> io::Result<()> {
    let path = path.as_ref();
    let parent = path
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or(Path::new("."));
    fs::create_dir_all(parent)?;
    let mut temp = PathBuf::from(path);
    let suffix = format!("tmp-{}", std::process::id());
    let name = path
        .file_name()
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "state path has no filename"))?;
    temp.set_file_name(format!("{}.{}", name.to_string_lossy(), suffix));
    let mut options = OpenOptions::new();
    options.write(true).create(true).truncate(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let result = (|| {
        let mut file = options.open(&temp)?;
        file.write_all(record.to_json().as_bytes())?;
        file.sync_all()?;
        fs::rename(&temp, path)?;
        #[cfg(unix)]
        std::fs::File::open(parent)?.sync_all()?;
        Ok(())
    })();
    if result.is_err() {
        let _ = fs::remove_file(&temp);
    }
    result
}

pub fn load(path: impl AsRef<Path>) -> io::Result<RuntimeRecord> {
    let raw = fs::read_to_string(path)?;
    RuntimeRecord::from_json(&raw)
}

fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn applied_requires_health_and_matching_revision() {
        let mut state =
            RuntimeRecord::staged("a".into(), "t".into(), "postgresql".into(), 8, 2).unwrap();
        state.begin_apply(8, 2).unwrap();
        assert!(state.mark_applied(8, false).is_err());
        state.mark_applied(8, true).unwrap();
        assert_eq!(state.applied_revision, Some(8));
        assert!(state.runtime_health_passed);
    }

    #[test]
    fn stale_and_credential_rollback_are_rejected() {
        let mut state =
            RuntimeRecord::staged("a".into(), "t".into(), "mongodb".into(), 9, 4).unwrap();
        assert!(state.begin_apply(8, 4).is_err());
        assert!(state.begin_apply(9, 3).is_err());
    }

    #[test]
    fn desired_revision_updates_preserve_last_applied_revision_until_verified() {
        let mut state =
            RuntimeRecord::staged("a".into(), "t".into(), "mysql".into(), 4, 2).unwrap();
        state.begin_apply(4, 2).unwrap();
        state.mark_applied(4, true).unwrap();
        state.update_desired("a", "t", "mysql", 5, 3).unwrap();
        assert_eq!(state.desired_revision, 5);
        assert_eq!(state.credential_revision, 3);
        assert_eq!(state.applied_revision, Some(4));
        assert_eq!(state.phase, RuntimePhase::Staged);
        assert!(!state.runtime_health_passed);
        state.begin_apply(5, 3).unwrap();
        state.mark_applied(5, true).unwrap();
        assert_eq!(state.applied_revision, Some(5));
    }

    #[test]
    fn desired_revision_rejects_identity_and_revision_rollback() {
        let mut state =
            RuntimeRecord::staged("a".into(), "t".into(), "mongodb".into(), 7, 4).unwrap();
        assert!(state.update_desired("other", "t", "mongodb", 8, 4).is_err());
        assert!(state.update_desired("a", "other", "mongodb", 8, 4).is_err());
        assert!(state.update_desired("a", "t", "redis", 8, 4).is_err());
        assert!(state.update_desired("a", "t", "mongodb", 6, 4).is_err());
        assert!(state.update_desired("a", "t", "mongodb", 8, 3).is_err());
    }

    #[test]
    fn revoked_assignment_cannot_be_reused_for_a_new_revision() {
        let mut state =
            RuntimeRecord::staged("a".into(), "t".into(), "redis".into(), 3, 1).unwrap();
        state.begin_revocation();
        assert!(state.update_desired("a", "t", "redis", 4, 2).is_err());
    }

    #[test]
    fn revoked_assignment_cannot_be_reapplied() {
        let mut state =
            RuntimeRecord::staged("a".into(), "t".into(), "redis".into(), 3, 1).unwrap();
        state.begin_revocation();
        assert!(state.begin_apply(3, 1).is_err());
        assert_eq!(state.applied_revision, None);
    }

    #[test]
    fn durable_state_round_trips_and_rejects_corrupt_health_claims() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("runtime-state.json");
        let mut state =
            RuntimeRecord::staged("a".into(), "t".into(), "postgresql".into(), 2, 1).unwrap();
        state.begin_apply(2, 1).unwrap();
        state.mark_applied(2, true).unwrap();
        persist(&path, &state).unwrap();
        assert_eq!(load(&path).unwrap(), state);
        let tampered = state.to_json().replace(
            "\"runtime_health_passed\":true",
            "\"runtime_health_passed\":false",
        );
        let tampered_path = dir.path().join("tampered-runtime-state.json");
        fs::write(&tampered_path, tampered).unwrap();
        assert!(load(&tampered_path).is_err());
    }

    #[test]
    fn failure_never_preserves_healthy_marker() {
        let mut state =
            RuntimeRecord::staged("a".into(), "t".into(), "mysql".into(), 1, 1).unwrap();
        state.begin_apply(1, 1).unwrap();
        state.mark_failed("UPSTREAM_AUTH_FAILED").unwrap();
        assert_eq!(state.phase, RuntimePhase::Failed);
        assert!(!state.runtime_health_passed);
        assert_eq!(state.applied_revision, None);
    }
}
