//! sealantd library: the runtime composition root, control dispatch, and lifecycle.
//!
//! The `sealantd` binary is a thin wrapper over [`run`]. Exposing the runtime as a library lets
//! integration tests drive it in-process.
#![cfg_attr(not(test), deny(clippy::unwrap_used, clippy::expect_used))]
#![forbid(unsafe_code)]

pub mod app;
pub mod runtime;
pub mod shutdown;

pub use app::run;
pub use runtime::Runtime;
pub use shutdown::ShutdownSignal;
