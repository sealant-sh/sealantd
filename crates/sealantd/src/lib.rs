//! sealantd library: the runtime composition root, control dispatch, and lifecycle.
//!
//! The `sealantd` binary is a thin wrapper over [`run`]. Exposing the runtime as a library lets
//! integration tests drive it in-process.
#![cfg_attr(not(test), deny(clippy::unwrap_used, clippy::expect_used))]
#![forbid(unsafe_code)]

pub mod app;
pub mod binds;
pub mod boot;
pub mod capture;
pub(crate) mod control_frontends;
pub mod docker;
pub(crate) mod dotfiles_verb;
pub mod runtime;
pub mod shutdown;
pub mod sweep;
pub mod unclaimed;

/// What the root tests reach into the daemon with, in a build with the `test-support` feature
/// only (`scripts/ci-test-support-gate.sh` keeps it out of every build of the daemon).
#[cfg(feature = "test-support")]
pub mod test_support {
    /// `<point>:<name>=<gate>`: the dotfiles copy holds at `point` (`made`, `final`) for the
    /// directory named `name` until `gate` exists, having written `<gate>.reached`.
    pub const DOTFILES_HOLD_ENV: &str = "SEALANTD_DOTFILES_TEST_HOLD";
}

pub use app::run;
pub use boot::{BootConfig, run_boot};
pub use runtime::Runtime;
pub use shutdown::ShutdownSignal;
