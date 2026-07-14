//! The managed-process registry.

use std::collections::{HashMap, HashSet};
use std::sync::Mutex;
use std::sync::atomic::{AtomicU8, Ordering};

use sealant_protocol::{
    ControlError, ExecutionId, ProcessId, ProcessState, ProcessSummary, SessionId,
};
use tokio::io::AsyncWriteExt;
use tokio::process::ChildStdin;

fn state_to_u8(state: ProcessState) -> u8 {
    match state {
        ProcessState::Created => 0,
        ProcessState::Starting => 1,
        ProcessState::Running => 2,
        ProcessState::Terminating => 3,
        ProcessState::Exited => 4,
        ProcessState::Signaled => 5,
        ProcessState::Failed => 6,
    }
}

fn state_from_u8(value: u8) -> ProcessState {
    match value {
        0 => ProcessState::Created,
        1 => ProcessState::Starting,
        2 => ProcessState::Running,
        3 => ProcessState::Terminating,
        4 => ProcessState::Exited,
        5 => ProcessState::Signaled,
        _ => ProcessState::Failed,
    }
}

/// A managed process. Shared (`Arc`) between the registry, the wait task, and signal handlers.
#[derive(Debug)]
pub struct ProcessEntry {
    /// Stable logical id.
    pub process_id: ProcessId,
    /// OS pid.
    pub pid: i32,
    /// OS process group id (equal to `pid` for the group leader).
    pub pgid: i32,
    /// Resolved executable.
    pub executable: String,
    /// Associated execution, when any.
    pub execution_id: Option<ExecutionId>,
    /// Associated session, when any.
    pub session_id: Option<SessionId>,
    state: AtomicU8,
    stdin: tokio::sync::Mutex<Option<ChildStdin>>,
}

impl ProcessEntry {
    /// Create an entry in the [`ProcessState::Starting`] state.
    #[must_use]
    pub fn new(
        process_id: ProcessId,
        pid: i32,
        pgid: i32,
        executable: String,
        execution_id: Option<ExecutionId>,
        session_id: Option<SessionId>,
        stdin: Option<ChildStdin>,
    ) -> Self {
        Self {
            process_id,
            pid,
            pgid,
            executable,
            execution_id,
            session_id,
            state: AtomicU8::new(state_to_u8(ProcessState::Starting)),
            stdin: tokio::sync::Mutex::new(stdin),
        }
    }

    /// Current lifecycle state.
    #[must_use]
    pub fn state(&self) -> ProcessState {
        state_from_u8(self.state.load(Ordering::Acquire))
    }

    /// Set the lifecycle state.
    pub fn set_state(&self, state: ProcessState) {
        self.state.store(state_to_u8(state), Ordering::Release);
    }

    /// Whether the process is still live (running, starting, or terminating).
    #[must_use]
    pub fn is_live(&self) -> bool {
        matches!(
            self.state(),
            ProcessState::Starting | ProcessState::Running | ProcessState::Terminating
        )
    }

    /// Write bytes to the process's stdin.
    ///
    /// # Errors
    /// Returns an error if stdin was not opened or has been closed, or on a write failure.
    pub async fn write_stdin(&self, data: &[u8]) -> Result<(), ControlError> {
        let mut guard = self.stdin.lock().await;
        match guard.as_mut() {
            Some(stdin) => stdin
                .write_all(data)
                .await
                .map_err(|e| ControlError::invalid_argument(format!("stdin write failed: {e}"))),
            None => Err(ControlError::invalid_argument(
                "process stdin is not open".to_owned(),
            )),
        }
    }

    /// Close the process's stdin (EOF), if open.
    pub async fn close_stdin(&self) {
        let mut guard = self.stdin.lock().await;
        if let Some(mut stdin) = guard.take() {
            let _ = stdin.shutdown().await;
        }
    }

    /// A serialisable summary of this entry.
    #[must_use]
    pub fn summary(&self) -> ProcessSummary {
        ProcessSummary {
            process_id: self.process_id.clone(),
            pid: self.pid,
            pgid: self.pgid,
            state: self.state(),
            executable: self.executable.clone(),
            execution_id: self.execution_id.clone(),
            session_id: self.session_id.clone(),
        }
    }
}

/// Thread-safe registry of managed processes.
#[derive(Debug, Default)]
pub struct ProcessRegistry {
    inner: Mutex<HashMap<ProcessId, std::sync::Arc<ProcessEntry>>>,
    /// OS pids of children some Tokio task owns and will `wait()` itself — the orphan reaper
    /// must never reap these. Its mutex doubles as the spawn↔reap critical section
    /// (see [`Self::owned_pids`]).
    owned: Mutex<HashSet<i32>>,
}

impl ProcessRegistry {
    /// An empty registry.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, HashMap<ProcessId, std::sync::Arc<ProcessEntry>>> {
        self.inner.lock().unwrap_or_else(|e| e.into_inner())
    }

    /// Insert an entry.
    pub fn insert(&self, entry: std::sync::Arc<ProcessEntry>) {
        self.lock().insert(entry.process_id.clone(), entry);
    }

    /// Look up an entry by id.
    #[must_use]
    pub fn get(&self, id: &ProcessId) -> Option<std::sync::Arc<ProcessEntry>> {
        self.lock().get(id).cloned()
    }

    /// Remove an entry by id.
    pub fn remove(&self, id: &ProcessId) -> Option<std::sync::Arc<ProcessEntry>> {
        self.lock().remove(id)
    }

    /// Number of registered processes.
    #[must_use]
    pub fn len(&self) -> usize {
        self.lock().len()
    }

    /// Whether the registry is empty.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.lock().is_empty()
    }

    /// Summaries of registered processes, optionally filtered by execution.
    #[must_use]
    pub fn list(&self, execution: Option<&ExecutionId>) -> Vec<ProcessSummary> {
        self.lock()
            .values()
            .filter(|e| execution.is_none_or(|x| e.execution_id.as_ref() == Some(x)))
            .map(|e| e.summary())
            .collect()
    }

    /// All entries that are still live.
    #[must_use]
    pub fn running(&self) -> Vec<std::sync::Arc<ProcessEntry>> {
        self.lock()
            .values()
            .filter(|e| e.is_live())
            .cloned()
            .collect()
    }

    /// Lock the owned-pid set — the spawn↔reap critical section.
    ///
    /// A spawn path that will `wait()` its child itself must hold this guard from just before
    /// `spawn()` until the new pid is inserted; the orphan reaper holds it for a whole sweep.
    /// This closes the race where a child exits before its ownership is recorded and the reaper
    /// misreads it as an adopted orphan, stealing the exit status from the owner's `wait()`.
    pub fn owned_pids(&self) -> std::sync::MutexGuard<'_, HashSet<i32>> {
        self.owned.lock().unwrap_or_else(|e| e.into_inner())
    }

    /// Drop ownership of an OS pid once its owner has reaped it (idempotent).
    pub fn release_pid(&self, pid: i32) {
        self.owned_pids().remove(&pid);
    }
}
