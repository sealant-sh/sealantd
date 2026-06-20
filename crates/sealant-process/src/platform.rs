//! Linux process-supervision primitives: child-subreaper, adopted-orphan reaping, and pidfd
//! capability detection. Off Linux these are no-ops returning `false`.
//!
//! With `PR_SET_CHILD_SUBREAPER` (or when running as PID 1) a process that double-forks an orphan
//! has that orphan reparented to the daemon. The [`spawn_orphan_reaper`] task reaps such orphans so
//! they do not linger as zombies — without stealing children that Tokio owns and reaps itself
//! (those are identified via the [`ProcessRegistry`] and left alone).

use std::sync::Arc;

use crate::registry::ProcessRegistry;

/// Make the current process a child subreaper. Returns whether it took effect.
#[cfg(target_os = "linux")]
#[must_use]
pub fn set_child_subreaper() -> bool {
    nix::sys::prctl::set_child_subreaper(true).is_ok()
}

/// Off Linux there is no subreaper concept.
#[cfg(not(target_os = "linux"))]
#[must_use]
pub fn set_child_subreaper() -> bool {
    false
}

/// Whether the kernel supports `pidfd_open(2)` (Linux >= 5.3).
#[cfg(target_os = "linux")]
#[must_use]
pub fn pidfd_supported() -> bool {
    std::fs::read_to_string("/proc/sys/kernel/osrelease")
        .ok()
        .is_some_and(|release| kernel_at_least(&release, 5, 3))
}

/// Off Linux there is no pidfd.
#[cfg(not(target_os = "linux"))]
#[must_use]
pub fn pidfd_supported() -> bool {
    false
}

#[cfg(target_os = "linux")]
fn kernel_at_least(release: &str, major: u32, minor: u32) -> bool {
    let mut parts = release
        .split(|c: char| !c.is_ascii_digit())
        .filter(|s| !s.is_empty());
    let parsed_major = parts.next().and_then(|s| s.parse().ok()).unwrap_or(0u32);
    let parsed_minor = parts.next().and_then(|s| s.parse().ok()).unwrap_or(0u32);
    (parsed_major, parsed_minor) >= (major, minor)
}

/// Spawn the adopted-orphan reaper task. No-op off Linux.
#[cfg(target_os = "linux")]
pub fn spawn_orphan_reaper(registry: Arc<ProcessRegistry>) {
    use tokio::signal::unix::{SignalKind, signal};
    tokio::spawn(async move {
        let mut sigchld = match signal(SignalKind::child()) {
            Ok(stream) => stream,
            Err(error) => {
                tracing::warn!(%error, "cannot install SIGCHLD handler; orphan reaping disabled");
                return;
            }
        };
        // A periodic sweep catches any zombie missed because we stopped at a Tokio-owned one.
        let mut sweep = tokio::time::interval(std::time::Duration::from_secs(2));
        loop {
            tokio::select! {
                _ = sigchld.recv() => reap_orphans(&registry),
                _ = sweep.tick() => reap_orphans(&registry),
            }
        }
    });
}

/// Off Linux there are no adopted orphans to reap.
#[cfg(not(target_os = "linux"))]
pub fn spawn_orphan_reaper(_registry: Arc<ProcessRegistry>) {}

#[cfg(target_os = "linux")]
fn reap_orphans(registry: &ProcessRegistry) {
    use nix::sys::wait::{Id, WaitPidFlag, waitid, waitpid};
    // Peek at each waitable child WITHOUT reaping it (WNOWAIT); `Err` (ECHILD/transient) ends the loop.
    while let Ok(status) = waitid(
        Id::All,
        WaitPidFlag::WEXITED | WaitPidFlag::WNOHANG | WaitPidFlag::WNOWAIT,
    ) {
        let Some(pid) = status.pid() else {
            break; // StillAlive: a child exists but none has exited.
        };
        if registry.contains_pid(pid.as_raw()) {
            // Tokio owns and will reap this one. Stop so we don't spin on it; the periodic sweep
            // retries any orphans queued behind it.
            break;
        }
        // Adopted orphan: actually reap it.
        let _ = waitpid(pid, Some(WaitPidFlag::WNOHANG));
        tracing::debug!(orphan_pid = pid.as_raw(), "reaped adopted orphan");
    }
}

#[cfg(test)]
mod tests {
    #[cfg(target_os = "linux")]
    #[test]
    fn kernel_version_comparison() {
        use super::kernel_at_least;
        assert!(kernel_at_least("6.8.0-31-generic", 5, 3));
        assert!(kernel_at_least("5.3.0", 5, 3));
        assert!(!kernel_at_least("5.2.99", 5, 3));
        assert!(!kernel_at_least("4.19.0", 5, 3));
    }
}
