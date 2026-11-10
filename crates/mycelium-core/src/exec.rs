use serde::{Deserialize, Serialize};

/// Context handed to [`crate::device::Device::exec`] for every unit of work.
///
/// The write/dry-run gates live here so they can be threaded from the CLI
/// all the way down to the transport — a driver cannot "forget" to honor
/// them, and a plugin host API enforces the same gates before touching
/// the wire (secure by default, tenet #9/self-validating).
#[derive(Clone, Debug)]
pub struct ExecContext {
    /// Capability id being executed (for error messages and logging).
    pub capability: String,
    /// Session opted into state-changing operations.
    pub allow_writes: bool,
    /// Compute/validate everything, apply nothing.
    pub dry_run: bool,
}

impl ExecContext {
    pub fn readonly(capability: impl Into<String>) -> Self {
        Self {
            capability: capability.into(),
            allow_writes: false,
            dry_run: false,
        }
    }

    /// Refuse to proceed when this capability mutates state but writes are
    /// not permitted. A dry run is allowed without write permission because
    /// it computes a plan and must not touch the transport.
    pub fn gate(&self, mutation: bool) -> Result<(), crate::MyceliumError> {
        if mutation && !self.allow_writes && !self.dry_run {
            return Err(crate::MyceliumError::WritesNotPermitted(
                self.capability.clone(),
            ));
        }
        Ok(())
    }
}

/// Raw result of running command(s) on an appliance.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExecOutcome {
    pub exit_code: i32,
    pub stdout: String,
    pub stderr: String,
}

impl ExecOutcome {
    pub fn success(&self) -> bool {
        self.exit_code == 0
    }
}

/// A transport that can run raw command strings against an appliance.
/// Implemented by SSH sessions, ipmitool wrappers, HTTP clients — and the
/// Lua plugin host, which never touches one directly: plugins *declare*
/// commands, the host runs them (gates stay in Rust, tenet #7).
#[async_trait::async_trait]
pub trait Transport: Send + Sync {
    async fn exec(&self, command: &str) -> crate::Result<ExecOutcome>;
}

/// Test/in-memory transport: canned answers keyed by exact command.
#[derive(Default, Clone)]
pub struct RecordingTransport {
    pub answers: std::sync::Arc<std::sync::Mutex<std::collections::BTreeMap<String, ExecOutcome>>>,
    pub calls: std::sync::Arc<std::sync::Mutex<Vec<String>>>,
}

impl RecordingTransport {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn reply(&self, command: impl Into<String>, stdout: impl Into<String>) {
        let mut guard = self.answers.lock().expect("recorder poisoned");
        guard.insert(
            command.into(),
            ExecOutcome {
                exit_code: 0,
                stdout: stdout.into(),
                stderr: String::new(),
            },
        );
    }
}

#[async_trait::async_trait]
impl Transport for RecordingTransport {
    async fn exec(&self, command: &str) -> crate::Result<ExecOutcome> {
        self.calls
            .lock()
            .expect("recorder poisoned")
            .push(command.to_owned());
        let guard = self.answers.lock().expect("recorder poisoned");
        Ok(guard.get(command).cloned().unwrap_or(ExecOutcome {
            exit_code: 127,
            stdout: String::new(),
            stderr: format!("no canned answer for: {command}"),
        }))
    }
}
