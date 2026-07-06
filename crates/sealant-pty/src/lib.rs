//! PTY allocation, interactive sessions, input/output capture, and resize (plan §11).
//!
//! [`SessionRuntime`] allocates a pseudoterminal, starts a shell as a session leader with the slave
//! as its controlling terminal, captures `pty.output` as binary-safe telemetry, forwards
//! `pty.input`, propagates terminal resize, and releases all resources on normal or abnormal exit.
//! It is the in-workspace half of the ssh-gateway session boundary (brief §3); the gateway owns auth.
#![cfg_attr(not(test), deny(clippy::unwrap_used, clippy::expect_used))]

pub mod pty;
pub mod session;

pub use session::{SessionRegistry, SessionRuntime};
