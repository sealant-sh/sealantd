//! Logical identifier generation.
//!
//! Ids are minted as `<prefix>_<runtimeToken>_<counter>` so they are unique within a runtime and
//! globally unique across runtimes (the token derives from the random [`RuntimeId`]). They are
//! deliberately not derived from OS pids.

use std::sync::atomic::{AtomicU64, Ordering};

use sealant_protocol::{EventId, ProcessId, RequestId, RuntimeId, SessionId};

/// Mint a fresh, random runtime id (`rt_<16 hex>`).
#[must_use]
pub fn new_runtime_id() -> RuntimeId {
    RuntimeId::new(format!("{}_{}", RuntimeId::PREFIX, random_token()))
}

fn random_token() -> String {
    let mut buf = [0u8; 8];
    match getrandom::getrandom(&mut buf) {
        Ok(()) => hex::encode(buf),
        Err(_) => {
            // Fallback that never panics: mix wall-clock nanos with the pid.
            let nanos = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_nanos() as u64)
                .unwrap_or(0);
            let pid = u64::from(std::process::id());
            format!("{:016x}", nanos ^ pid.rotate_left(32))
        }
    }
}

/// Mints monotonically-numbered logical ids for one runtime.
#[derive(Debug)]
pub struct IdGenerator {
    token: String,
    counter: AtomicU64,
}

impl IdGenerator {
    /// Create a generator whose ids embed a short token derived from `runtime_id`.
    #[must_use]
    pub fn new(runtime_id: &RuntimeId) -> Self {
        let token = runtime_id
            .as_str()
            .rsplit('_')
            .next()
            .filter(|s| !s.is_empty())
            .unwrap_or("0")
            .to_owned();
        Self {
            token,
            counter: AtomicU64::new(0),
        }
    }

    fn mint(&self, prefix: &str) -> String {
        let n = self.counter.fetch_add(1, Ordering::Relaxed);
        format!("{prefix}_{}_{n:x}", self.token)
    }

    /// Mint a fresh session id.
    #[must_use]
    pub fn session_id(&self) -> SessionId {
        SessionId::new(self.mint(SessionId::PREFIX))
    }

    /// Mint a fresh process id.
    #[must_use]
    pub fn process_id(&self) -> ProcessId {
        ProcessId::new(self.mint(ProcessId::PREFIX))
    }

    /// Mint a fresh event id.
    #[must_use]
    pub fn event_id(&self) -> EventId {
        EventId::new(self.mint(EventId::PREFIX))
    }

    /// Mint a fresh request id (used by clients/tools).
    #[must_use]
    pub fn request_id(&self) -> RequestId {
        RequestId::new(self.mint(RequestId::PREFIX))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn runtime_ids_are_prefixed_and_distinct() {
        let a = new_runtime_id();
        let b = new_runtime_id();
        assert!(a.as_str().starts_with("rt_"));
        assert_ne!(a, b);
    }

    #[test]
    fn minted_ids_are_unique_and_prefixed() {
        let idgen = IdGenerator::new(&RuntimeId::new("rt_abcd1234"));
        let e1 = idgen.event_id();
        let e2 = idgen.event_id();
        assert_ne!(e1, e2);
        assert!(e1.as_str().starts_with("evt_abcd1234_"));
        assert!(idgen.process_id().as_str().starts_with("proc_abcd1234_"));
        assert!(idgen.session_id().as_str().starts_with("ses_abcd1234_"));
    }
}
