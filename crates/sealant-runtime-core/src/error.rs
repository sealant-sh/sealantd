//! Runtime-core error types.

/// Configuration validation failures (plan §9: validate before reporting healthy).
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum ConfigError {
    /// The default shell was empty.
    #[error("default shell must not be empty")]
    EmptyShell,
    /// The socket path had no parent directory.
    #[error("socket path `{0}` must have a parent directory")]
    InvalidSocketPath(String),
    /// A numeric bound was zero where a positive value is required.
    #[error("`{field}` must be greater than zero")]
    NonPositive {
        /// The offending field name.
        field: &'static str,
    },
    /// The I/O chunk size exceeded the maximum frame size.
    #[error("ioChunkBytes ({chunk}) must not exceed maxFrameBytes ({max_frame})")]
    ChunkLargerThanFrame {
        /// Configured chunk size.
        chunk: u64,
        /// Configured max frame size.
        max_frame: u64,
    },
}
