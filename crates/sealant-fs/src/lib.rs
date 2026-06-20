//! Filesystem telemetry (plan §13): a hybrid baseline-snapshot + live-watcher + final-diff strategy.
//!
//! [`snapshot`] walks a workspace root (ignore rules, no symlink following, path-bounded) capturing
//! per-entry metadata + optional content hashes. [`diff`] compares two snapshots into normalized
//! `file.changed` events, with heuristic (inferred) rename detection. [`FilesystemRuntime`] ties them
//! together with a live `notify` watcher that emits events, coalesces editor temp-file noise, and on
//! watcher overflow emits `file.watchOverflow` and rescans.
#![cfg_attr(not(test), deny(clippy::unwrap_used, clippy::expect_used))]
#![forbid(unsafe_code)]

pub mod diff;
pub mod runtime;
pub mod snapshot;
pub mod watcher;

pub use runtime::{FilesystemConfig, FilesystemRuntime};
pub use snapshot::{Snapshot, snapshot};
