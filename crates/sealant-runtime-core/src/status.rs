//! Lock-light runtime status: lifecycle state, live counters, and degradation reasons.

use std::sync::Mutex;
use std::sync::atomic::{AtomicU8, AtomicU32, Ordering};

use sealant_protocol::RuntimeState;

fn state_to_u8(state: RuntimeState) -> u8 {
    match state {
        RuntimeState::Starting => 0,
        RuntimeState::Healthy => 1,
        RuntimeState::Degraded => 2,
        RuntimeState::Unhealthy => 3,
        RuntimeState::ShuttingDown => 4,
        RuntimeState::Stopped => 5,
    }
}

fn state_from_u8(value: u8) -> RuntimeState {
    match value {
        0 => RuntimeState::Starting,
        1 => RuntimeState::Healthy,
        2 => RuntimeState::Degraded,
        3 => RuntimeState::Unhealthy,
        4 => RuntimeState::ShuttingDown,
        _ => RuntimeState::Stopped,
    }
}

/// Shared, thread-safe runtime status. Cheap to read from any task.
#[derive(Debug)]
pub struct RuntimeStatus {
    state: AtomicU8,
    active_processes: AtomicU32,
    active_sessions: AtomicU32,
    active_executions: AtomicU32,
    degradation: Mutex<Vec<String>>,
}

impl RuntimeStatus {
    /// A fresh status in the [`RuntimeState::Starting`] state.
    #[must_use]
    pub fn new() -> Self {
        Self {
            state: AtomicU8::new(state_to_u8(RuntimeState::Starting)),
            active_processes: AtomicU32::new(0),
            active_sessions: AtomicU32::new(0),
            active_executions: AtomicU32::new(0),
            degradation: Mutex::new(Vec::new()),
        }
    }

    /// The current lifecycle state.
    #[must_use]
    pub fn state(&self) -> RuntimeState {
        state_from_u8(self.state.load(Ordering::Acquire))
    }

    /// Set the lifecycle state.
    pub fn set_state(&self, state: RuntimeState) {
        self.state.store(state_to_u8(state), Ordering::Release);
    }

    /// Increment the active-process counter.
    pub fn inc_processes(&self) {
        self.active_processes.fetch_add(1, Ordering::Relaxed);
    }

    /// Decrement the active-process counter (saturating at zero).
    pub fn dec_processes(&self) {
        let _ = self
            .active_processes
            .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |v| {
                Some(v.saturating_sub(1))
            });
    }

    /// Increment the active-session counter.
    pub fn inc_sessions(&self) {
        self.active_sessions.fetch_add(1, Ordering::Relaxed);
    }

    /// Decrement the active-session counter (saturating at zero).
    pub fn dec_sessions(&self) {
        let _ = self
            .active_sessions
            .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |v| {
                Some(v.saturating_sub(1))
            });
    }

    /// Increment the active-execution counter.
    pub fn inc_executions(&self) {
        self.active_executions.fetch_add(1, Ordering::Relaxed);
    }

    /// Decrement the active-execution counter (saturating at zero).
    pub fn dec_executions(&self) {
        let _ = self
            .active_executions
            .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |v| {
                Some(v.saturating_sub(1))
            });
    }

    /// Current `(processes, sessions, executions)` counts.
    #[must_use]
    pub fn counts(&self) -> (u32, u32, u32) {
        (
            self.active_processes.load(Ordering::Relaxed),
            self.active_sessions.load(Ordering::Relaxed),
            self.active_executions.load(Ordering::Relaxed),
        )
    }

    /// Record a degradation reason (deduplicated).
    pub fn add_degradation(&self, reason: impl Into<String>) {
        let reason = reason.into();
        let mut guard = self.degradation.lock().unwrap_or_else(|e| e.into_inner());
        if !guard.contains(&reason) {
            guard.push(reason);
        }
    }

    /// Clear all degradation reasons.
    pub fn clear_degradation(&self) {
        self.degradation
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .clear();
    }

    /// Snapshot the current degradation reasons.
    #[must_use]
    pub fn degradation_reasons(&self) -> Vec<String> {
        self.degradation
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .clone()
    }
}

impl Default for RuntimeStatus {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn state_transitions_round_trip() {
        let status = RuntimeStatus::new();
        assert_eq!(status.state(), RuntimeState::Starting);
        status.set_state(RuntimeState::Healthy);
        assert_eq!(status.state(), RuntimeState::Healthy);
        status.set_state(RuntimeState::ShuttingDown);
        assert_eq!(status.state(), RuntimeState::ShuttingDown);
    }

    #[test]
    fn counters_saturate_at_zero() {
        let status = RuntimeStatus::new();
        status.inc_processes();
        status.inc_processes();
        status.dec_processes();
        status.dec_processes();
        status.dec_processes();
        assert_eq!(status.counts().0, 0);
    }

    #[test]
    fn degradation_reasons_dedupe() {
        let status = RuntimeStatus::new();
        status.add_degradation("sink-disconnected");
        status.add_degradation("sink-disconnected");
        status.add_degradation("spool-full");
        assert_eq!(status.degradation_reasons().len(), 2);
        status.clear_degradation();
        assert!(status.degradation_reasons().is_empty());
    }
}
