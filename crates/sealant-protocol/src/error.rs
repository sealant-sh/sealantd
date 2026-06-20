//! Deterministic control error codes and the error envelope.

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

/// Closed union of control error codes returned in a [`crate::ControlResponse`].
///
/// Marked `#[non_exhaustive]` so future codes can be added without breaking exhaustive matches in
/// downstream Rust crates; the TypeScript client decodes unknown codes as an opaque fallback.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "kebab-case")]
#[non_exhaustive]
pub enum ControlErrorCode {
    /// The frame body was not valid JSON.
    InvalidJson,
    /// The frame declared a `schemaVersion` the daemon does not support.
    UnsupportedVersion,
    /// The declared frame length exceeded the configured maximum.
    FrameTooLarge,
    /// The `cmd` discriminator did not match any known command.
    UnknownCommand,
    /// A command argument failed validation.
    InvalidArgument,
    /// The request frame omitted a command.
    MissingCommand,
    /// No execution exists for the supplied [`crate::ExecutionId`].
    ExecutionNotFound,
    /// No session exists for the supplied [`crate::SessionId`].
    SessionNotFound,
    /// No process exists for the supplied [`crate::ProcessId`].
    ProcessNotFound,
    /// The child process could not be spawned (e.g. executable not found).
    ProcessStartFailed,
    /// A pseudoterminal could not be allocated.
    PtyAllocationFailed,
    /// The OS denied the operation (e.g. signal delivery across a privilege boundary).
    PermissionDenied,
    /// Runtime policy refused the operation.
    PolicyDenied,
    /// The requested feature is disabled by a kill switch or configuration.
    FeatureUnavailable,
    /// The host lacks a kernel feature or Linux capability required for this operation.
    CapabilityUnavailable,
    /// A bounded queue rejected the work under the active backpressure policy.
    QueueFull,
    /// The daemon is draining and will not accept new work.
    RuntimeShuttingDown,
    /// An unexpected internal error occurred.
    InternalError,
}

impl ControlErrorCode {
    /// The stable kebab-case wire string for this code.
    #[must_use]
    pub fn as_wire(self) -> &'static str {
        match self {
            Self::InvalidJson => "invalid-json",
            Self::UnsupportedVersion => "unsupported-version",
            Self::FrameTooLarge => "frame-too-large",
            Self::UnknownCommand => "unknown-command",
            Self::InvalidArgument => "invalid-argument",
            Self::MissingCommand => "missing-command",
            Self::ExecutionNotFound => "execution-not-found",
            Self::SessionNotFound => "session-not-found",
            Self::ProcessNotFound => "process-not-found",
            Self::ProcessStartFailed => "process-start-failed",
            Self::PtyAllocationFailed => "pty-allocation-failed",
            Self::PermissionDenied => "permission-denied",
            Self::PolicyDenied => "policy-denied",
            Self::FeatureUnavailable => "feature-unavailable",
            Self::CapabilityUnavailable => "capability-unavailable",
            Self::QueueFull => "queue-full",
            Self::RuntimeShuttingDown => "runtime-shutting-down",
            Self::InternalError => "internal-error",
        }
    }
}

impl core::fmt::Display for ControlErrorCode {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(self.as_wire())
    }
}

/// A typed control error: exactly one of these (or an ack) answers every request.
#[derive(Clone, PartialEq, Debug, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct ControlError {
    /// The deterministic error code.
    pub code: ControlErrorCode,
    /// A human-readable, secret-free explanation.
    pub message: String,
    /// Optional structured detail (never secrets).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub detail: Option<serde_json::Value>,
}

impl ControlError {
    /// Construct an error with the given code and message.
    pub fn new(code: ControlErrorCode, message: impl Into<String>) -> Self {
        Self {
            code,
            message: message.into(),
            detail: None,
        }
    }

    /// Attach structured detail (caller must ensure it contains no secrets).
    #[must_use]
    pub fn with_detail(mut self, detail: serde_json::Value) -> Self {
        self.detail = Some(detail);
        self
    }

    /// The error code.
    #[must_use]
    pub fn code(&self) -> ControlErrorCode {
        self.code
    }

    /// An [`ControlErrorCode::InvalidArgument`] error.
    pub fn invalid_argument(message: impl Into<String>) -> Self {
        Self::new(ControlErrorCode::InvalidArgument, message)
    }

    /// An [`ControlErrorCode::InvalidJson`] error.
    pub fn invalid_json(message: impl Into<String>) -> Self {
        Self::new(ControlErrorCode::InvalidJson, message)
    }

    /// A [`ControlErrorCode::FrameTooLarge`] error.
    pub fn frame_too_large(message: impl Into<String>) -> Self {
        Self::new(ControlErrorCode::FrameTooLarge, message)
    }

    /// An [`ControlErrorCode::UnknownCommand`] error.
    pub fn unknown_command(message: impl Into<String>) -> Self {
        Self::new(ControlErrorCode::UnknownCommand, message)
    }

    /// A [`ControlErrorCode::ProcessNotFound`] error.
    pub fn process_not_found(message: impl Into<String>) -> Self {
        Self::new(ControlErrorCode::ProcessNotFound, message)
    }

    /// A [`ControlErrorCode::SessionNotFound`] error.
    pub fn session_not_found(message: impl Into<String>) -> Self {
        Self::new(ControlErrorCode::SessionNotFound, message)
    }

    /// A [`ControlErrorCode::ProcessStartFailed`] error.
    pub fn process_start_failed(message: impl Into<String>) -> Self {
        Self::new(ControlErrorCode::ProcessStartFailed, message)
    }

    /// A [`ControlErrorCode::FeatureUnavailable`] error.
    pub fn feature_unavailable(message: impl Into<String>) -> Self {
        Self::new(ControlErrorCode::FeatureUnavailable, message)
    }

    /// A [`ControlErrorCode::RuntimeShuttingDown`] error.
    pub fn runtime_shutting_down(message: impl Into<String>) -> Self {
        Self::new(ControlErrorCode::RuntimeShuttingDown, message)
    }

    /// An [`ControlErrorCode::InternalError`] error.
    pub fn internal(message: impl Into<String>) -> Self {
        Self::new(ControlErrorCode::InternalError, message)
    }
}

impl core::fmt::Display for ControlError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "{}: {}", self.code.as_wire(), self.message)
    }
}

impl std::error::Error for ControlError {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn error_code_wire_strings_are_kebab_case() {
        let json = serde_json::to_string(&ControlErrorCode::PtyAllocationFailed).expect("ser");
        assert_eq!(json, "\"pty-allocation-failed\"");
        assert_eq!(
            ControlErrorCode::PtyAllocationFailed.as_wire(),
            "pty-allocation-failed"
        );
    }

    #[test]
    fn error_round_trips_with_detail() {
        let err = ControlError::invalid_argument("bad cwd")
            .with_detail(serde_json::json!({ "field": "cwd" }));
        let json = serde_json::to_string(&err).expect("ser");
        let back: ControlError = serde_json::from_str(&json).expect("de");
        assert_eq!(back.code, ControlErrorCode::InvalidArgument);
        assert_eq!(back.message, "bad cwd");
        assert!(back.detail.is_some());
    }
}
