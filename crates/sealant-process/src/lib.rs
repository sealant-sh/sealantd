//! Process execution, registry, process groups, and reaping.
//!
//! [`ProcessRuntime`] spawns non-interactive processes in their own process group, captures
//! stdout/stderr as binary-safe `io.chunk` telemetry, emits `process.started`/`process.exited`
//! lifecycle events, enforces timeouts with graceful-then-forced termination, and terminates the
//! whole managed tree on shutdown.
#![cfg_attr(not(test), deny(clippy::unwrap_used, clippy::expect_used))]
#![forbid(unsafe_code)]

pub mod platform;
pub mod registry;
pub mod runtime;
pub mod signals;

pub use registry::{ProcessEntry, ProcessRegistry};
pub use runtime::ProcessRuntime;
