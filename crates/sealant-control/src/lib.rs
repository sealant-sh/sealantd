//! Unix-socket, vsock and stdio control transport: length-prefixed framing and per-connection dispatch.
//!
//! The transport is deliberately thin. A [`ControlService`] implements command handling and event
//! subscription; [`serve_unix`] / [`serve_stdio`] accept connections and pump frames. Each frame is
//! a single JSON message validated against the configured maximum size before allocation.
#![cfg_attr(not(test), deny(clippy::unwrap_used, clippy::expect_used))]
#![forbid(unsafe_code)]

pub mod frame;
pub mod peer;
pub mod scope;
pub mod server;
pub mod service;
pub mod vsock;
pub mod wss;

pub use frame::{FrameError, read_frame, write_frame};
pub use peer::peer_allowed;
pub use scope::{ControlScope, ScopedService};
pub use server::{ConnError, OUTBOUND_CAPACITY, handle_connection, serve_stdio, serve_unix};
pub use service::{ChannelRegistry, ConnHandle, ControlService};
#[cfg(target_os = "linux")]
pub use vsock::serve_vsock;
pub use vsock::{PeerAcceptor, VMADDR_CID_HOST, peer_cid_allowed, serve_peers};
pub use wss::{CONTROL_PATH, WssConfig, WssListener, serve_wss};
