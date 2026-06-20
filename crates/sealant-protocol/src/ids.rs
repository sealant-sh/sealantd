//! Typed identifiers and sequence/clock newtypes for the control protocol.
//!
//! Identifiers are intentionally opaque strings so the daemon can correlate with the monorepo's
//! existing `text` ids: [`ExecutionId`] carries the run/attempt id supplied by the orchestrator,
//! while the daemon mints its own [`SessionId`], [`ProcessId`], and [`EventId`]. The OS PID is
//! never used as the stable product-level [`ProcessId`].

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

macro_rules! string_id {
    ($(#[$meta:meta])* $name:ident, $prefix:literal) => {
        $(#[$meta])*
        #[derive(Clone, PartialEq, Eq, Hash, PartialOrd, Ord, Debug, Serialize, Deserialize, JsonSchema)]
        #[serde(transparent)]
        pub struct $name(String);

        impl $name {
            /// Conventional prefix used when the runtime mints a fresh value of this id.
            pub const PREFIX: &'static str = $prefix;

            /// Wrap an existing string as this id without imposing a format.
            pub fn new(value: impl Into<String>) -> Self {
                Self(value.into())
            }

            /// Borrow the underlying string.
            #[must_use]
            pub fn as_str(&self) -> &str {
                self.0.as_str()
            }

            /// Consume into the owned string.
            #[must_use]
            pub fn into_inner(self) -> String {
                self.0
            }

            /// Whether the underlying string is empty.
            #[must_use]
            pub fn is_empty(&self) -> bool {
                self.0.is_empty()
            }
        }

        impl core::fmt::Display for $name {
            fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
                f.write_str(&self.0)
            }
        }

        impl From<String> for $name {
            fn from(value: String) -> Self {
                Self(value)
            }
        }

        impl From<&str> for $name {
            fn from(value: &str) -> Self {
                Self(value.to_owned())
            }
        }

        impl AsRef<str> for $name {
            fn as_ref(&self) -> &str {
                &self.0
            }
        }

        impl core::str::FromStr for $name {
            type Err = core::convert::Infallible;
            fn from_str(s: &str) -> Result<Self, Self::Err> {
                Ok(Self(s.to_owned()))
            }
        }
    };
}

string_id!(
    /// Daemon instance identity. One runtime per sandbox + run.
    RuntimeId,
    "rt"
);
string_id!(
    /// Task/execution correlation. Carries the monorepo run/attempt id when supplied.
    ExecutionId,
    "exec"
);
string_id!(
    /// PTY or interactive session correlation. Minted by the runtime.
    SessionId,
    "ses"
);
string_id!(
    /// Stable logical process identifier. Never the OS PID.
    ProcessId,
    "proc"
);
string_id!(
    /// Control-request correlation and duplicate-detection key.
    RequestId,
    "req"
);
string_id!(
    /// Globally unique telemetry-event idempotency key.
    EventId,
    "evt"
);

/// Monotonic order within a defined sequence domain (one domain per runtime).
///
/// This represents the order in which Sealant observed or enqueued an event, not unknowable kernel
/// causality. Final values are assigned at a single deterministic point per runtime.
#[derive(
    Clone,
    Copy,
    PartialEq,
    Eq,
    Hash,
    PartialOrd,
    Ord,
    Debug,
    Default,
    Serialize,
    Deserialize,
    JsonSchema,
)]
#[serde(transparent)]
pub struct Sequence(pub u64);

impl Sequence {
    /// The first sequence value.
    pub const ZERO: Self = Self(0);

    /// The raw counter value.
    #[must_use]
    pub fn get(self) -> u64 {
        self.0
    }

    /// The next sequence value (saturating at [`u64::MAX`]).
    #[must_use]
    pub fn next(self) -> Self {
        Self(self.0.saturating_add(1))
    }
}

impl core::fmt::Display for Sequence {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "{}", self.0)
    }
}

/// Monotonic per-stream byte position. Distinguishes redaction/truncation from gaps.
#[derive(
    Clone,
    Copy,
    PartialEq,
    Eq,
    Hash,
    PartialOrd,
    Ord,
    Debug,
    Default,
    Serialize,
    Deserialize,
    JsonSchema,
)]
#[serde(transparent)]
pub struct StreamOffset(pub u64);

impl StreamOffset {
    /// The offset at the start of a stream.
    pub const ZERO: Self = Self(0);

    /// The raw byte position.
    #[must_use]
    pub fn get(self) -> u64 {
        self.0
    }

    /// Advance the offset by `bytes` (saturating at [`u64::MAX`]).
    #[must_use]
    pub fn advance(self, bytes: u64) -> Self {
        Self(self.0.saturating_add(bytes))
    }
}

/// Wall-clock timestamp as microseconds since the Unix epoch.
#[derive(
    Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Debug, Serialize, Deserialize, JsonSchema,
)]
#[serde(transparent)]
pub struct WallClockMicros(pub i64);

impl WallClockMicros {
    /// The raw microsecond count since the Unix epoch.
    #[must_use]
    pub fn get(self) -> i64 {
        self.0
    }
}

/// Local monotonic clock reading in nanoseconds.
///
/// Suitable only for duration-safe local ordering; it is not wall-clock time and is not comparable
/// across daemon restarts.
#[derive(
    Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Debug, Serialize, Deserialize, JsonSchema,
)]
#[serde(transparent)]
pub struct MonotonicNanos(pub u64);

impl MonotonicNanos {
    /// The raw nanosecond reading.
    #[must_use]
    pub fn get(self) -> u64 {
        self.0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn string_id_is_transparent() {
        let id = ExecutionId::new("run-123");
        let json = serde_json::to_string(&id).expect("serialize");
        assert_eq!(json, "\"run-123\"");
        let back: ExecutionId = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(back, id);
        assert_eq!(ExecutionId::PREFIX, "exec");
    }

    #[test]
    fn sequence_advances_and_saturates() {
        assert_eq!(Sequence::ZERO.next(), Sequence(1));
        assert_eq!(Sequence(u64::MAX).next(), Sequence(u64::MAX));
        assert_eq!(StreamOffset::ZERO.advance(10).advance(5), StreamOffset(15));
    }
}
