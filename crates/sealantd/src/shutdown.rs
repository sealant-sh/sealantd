//! The shutdown signal shared between the control handler, OS signal handlers, and `main`.

use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};

use tokio::sync::Notify;

/// A one-shot-style shutdown request that records whether the stop is graceful or forced.
#[derive(Debug)]
pub struct ShutdownSignal {
    notify: Notify,
    requested: AtomicBool,
    hard: AtomicBool,
    grace_ms: AtomicU64,
}

impl ShutdownSignal {
    /// Create a signal with a default grace period.
    #[must_use]
    pub fn new(default_grace_ms: u64) -> Self {
        Self {
            notify: Notify::new(),
            requested: AtomicBool::new(false),
            hard: AtomicBool::new(false),
            grace_ms: AtomicU64::new(default_grace_ms),
        }
    }

    /// Request a graceful shutdown, optionally overriding the grace period.
    pub fn request_graceful(&self, grace_ms: Option<u64>) {
        if let Some(grace) = grace_ms {
            self.grace_ms.store(grace, Ordering::Relaxed);
        }
        self.requested.store(true, Ordering::Release);
        self.notify.notify_one();
    }

    /// Request an immediate, forced shutdown.
    pub fn request_hard(&self) {
        self.hard.store(true, Ordering::Release);
        self.requested.store(true, Ordering::Release);
        self.notify.notify_one();
    }

    /// Wait until shutdown is requested (returns immediately if already requested).
    pub async fn wait(&self) {
        loop {
            let notified = self.notify.notified();
            if self.requested.load(Ordering::Acquire) {
                return;
            }
            notified.await;
            if self.requested.load(Ordering::Acquire) {
                return;
            }
        }
    }

    /// Whether the requested shutdown is forced.
    #[must_use]
    pub fn is_hard(&self) -> bool {
        self.hard.load(Ordering::Acquire)
    }

    /// The effective grace period in milliseconds.
    #[must_use]
    pub fn grace_ms(&self) -> u64 {
        self.grace_ms.load(Ordering::Relaxed)
    }
}
