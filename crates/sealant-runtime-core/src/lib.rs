//! Configuration, identity, clock, and runtime status for sealantd.
//!
//! This crate holds runtime-wide state that the daemon binary composes: validated
//! [`RuntimeConfig`], a monotonic + wall [`Clock`], an [`IdGenerator`] that mints logical ids, and
//! a lock-light [`RuntimeStatus`] tracking lifecycle state and live counters.
#![cfg_attr(not(test), deny(clippy::unwrap_used, clippy::expect_used))]
#![forbid(unsafe_code)]

pub mod clock;
pub mod config;
pub mod error;
pub mod idgen;
pub mod redact;
pub mod status;

pub use clock::Clock;
pub use config::{Bind, BindableMount, RuntimeConfig};
pub use error::ConfigError;
pub use idgen::{IdGenerator, new_runtime_id};
pub use redact::Redactor;
pub use status::RuntimeStatus;
