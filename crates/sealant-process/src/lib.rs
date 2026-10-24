//! Process execution, registry, process groups, and reaping.
//!
//! [`ProcessRuntime`] spawns non-interactive processes in their own process group, captures
//! stdout/stderr as binary-safe `io.chunk` telemetry, emits `process.started`/`process.exited`
//! lifecycle events, enforces timeouts with graceful-then-forced termination, and terminates the
//! whole managed tree on shutdown.
#![cfg_attr(not(test), deny(clippy::unwrap_used, clippy::expect_used))]
// `deny`, not `forbid`: one module, `identity`, sets a child's user in `pre_exec` (std has no safe
// way to set supplementary groups or a umask); everything else stays free of unsafe code.
#![deny(unsafe_code)]

pub mod activity;
pub mod identity;
pub mod platform;
pub mod registry;
pub mod runtime;
pub mod sftp;
pub mod signals;
pub mod spawn;

pub use registry::{ProcessEntry, ProcessRegistry};

/// A running session as an `exec` that names it sees it: who its leader runs as, and the marker
/// ([`sealant_protocol::SESSION_ENV`]) its processes carry. The `exec` carries the marker only
/// when it runs as that same user and group.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SessionMark {
    pub uid: u32,
    pub gid: u32,
    pub marker: String,
}
pub use runtime::ProcessRuntime;
pub use sftp::SftpRuntime;
pub use spawn::{Bound, CommandGateExt, GatedChild, SpawnedPid};
