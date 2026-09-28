//! Typed errors for the `boot` supervisor. Every prep error is fatal: rather than leave a
//! half-started container that looks healthy, `boot` logs the error and exits non-zero.

use std::path::Path;

/// A fatal error during boot preparation.
#[derive(Debug, thiserror::Error)]
pub enum BootError {
    /// Invalid or missing configuration in the `SEALANT_*` env contract.
    #[error("invalid boot configuration: {0}")]
    Config(String),

    /// A filesystem operation failed.
    #[error("{context}: {source}")]
    Io {
        /// What was being attempted.
        context: String,
        /// The underlying I/O error.
        source: std::io::Error,
    },

    /// A base64 secret could not be decoded.
    #[error("failed to decode {what}: {source}")]
    Base64 {
        /// Which value failed to decode.
        what: String,
        /// The underlying decode error.
        source: base64::DecodeError,
    },

    /// `git clone` failed.
    #[error("git clone failed: {0}")]
    Clone(String),

    /// A required external command could not be spawned or exited non-zero.
    #[error("{command} failed: {detail}")]
    Command {
        /// The command name.
        command: String,
        /// Human-readable detail (exit status / stderr / spawn error).
        detail: String,
    },

    /// SSH bring-up failed.
    #[error("ssh bring-up failed: {0}")]
    Ssh(String),

    /// Dotfiles apply failed.
    #[error("dotfiles apply failed: {0}")]
    Dotfiles(String),

    /// The async runtime could not be built.
    #[error("failed to start async runtime: {0}")]
    Runtime(String),

    /// Another sealantd holds this disk ([`crate::boot::lock::DiskLock`]): nothing was touched.
    #[error("{0}")]
    DiskInUse(String),

    /// A recovery boot on a disk that was never materialized
    /// ([`crate::boot::capture::never_materialized`]): nothing to save, and nothing was touched.
    #[error("nothing to save: never materialized ({0})")]
    NeverMaterialized(String),
}

impl BootError {
    /// Construct a [`BootError::Config`].
    pub fn config(message: impl Into<String>) -> Self {
        Self::Config(message.into())
    }

    /// Wrap an I/O error with context.
    pub fn io(context: impl Into<String>, source: std::io::Error) -> Self {
        Self::Io {
            context: context.into(),
            source,
        }
    }

    /// Wrap an I/O error that happened against a specific path.
    pub fn io_path(action: &str, path: &Path, source: std::io::Error) -> Self {
        Self::Io {
            context: format!("{action} {}", path.display()),
            source,
        }
    }

    /// Wrap a base64 decode error.
    pub fn base64(what: impl Into<String>, source: base64::DecodeError) -> Self {
        Self::Base64 {
            what: what.into(),
            source,
        }
    }

    /// Wrap a failed external command.
    pub fn command(command: impl Into<String>, detail: impl Into<String>) -> Self {
        Self::Command {
            command: command.into(),
            detail: detail.into(),
        }
    }
}
