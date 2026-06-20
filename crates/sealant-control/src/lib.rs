//! Unix-socket and stdio control transport: length-prefixed framing and per-connection dispatch.
//!
//! The transport is deliberately thin. A [`ControlService`] implements command handling and event
//! subscription; [`serve_unix`] / [`serve_stdio`] accept connections and pump frames. Each frame is
//! a single JSON message validated against the configured maximum size before allocation.
#![cfg_attr(not(test), deny(clippy::unwrap_used, clippy::expect_used))]
#![forbid(unsafe_code)]

pub mod frame;
pub mod server;
pub mod service;

pub use frame::{FrameError, read_frame, write_frame};
pub use server::{ConnError, handle_connection, serve_stdio, serve_unix};
pub use service::ControlService;
