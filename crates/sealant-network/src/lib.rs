//! Network telemetry (plan §14).
//!
//! The honest, unprivileged path is an **explicit egress proxy**: child processes are pointed at a
//! local proxy via `HTTP_PROXY`/`HTTPS_PROXY`, and the proxy observes plain-HTTP request metadata
//! (method/host/path/status/bytes) and HTTPS `CONNECT` tunnels (host/port/bytes — encrypted body is
//! never inspected). Privileged backends (eBPF/netlink) need capabilities the workspace does not
//! convey, so [`capability::detect_mode`] degrades to proxy/off rather than failing.
#![cfg_attr(not(test), deny(clippy::unwrap_used, clippy::expect_used))]
#![forbid(unsafe_code)]

pub mod capability;
pub mod forward;
pub mod proxy;
pub mod runtime;

pub use forward::ForwardRuntime;
pub use runtime::{NetworkConfig, NetworkRuntime};
