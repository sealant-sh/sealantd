//! Telemetry event envelope, payloads, and the shared runtime/capture enums.
//!
//! On the wire an event is a flat JSON object: the [`EventEnvelope`] metadata fields plus the
//! flattened, internally-tagged [`EventPayload`] whose `eventType` discriminator sits at the top
//! level (see [`crate`] for the framing model).

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::bytes::Base64Bytes;
use crate::ids::{
    EventId, ExecutionId, MonotonicNanos, ProcessId, RequestId, RuntimeId, Sequence, SessionId,
    StreamOffset, WallClockMicros,
};

/// Lifecycle state of the runtime as a whole.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub enum RuntimeState {
    /// Starting up and validating configuration; not yet emitting heartbeats.
    Starting,
    /// Fully operational.
    Healthy,
    /// Operational but a subsystem is degraded; see degradation reasons.
    Degraded,
    /// Not operational for its core purpose.
    Unhealthy,
    /// Draining and refusing new work.
    ShuttingDown,
    /// Stopped.
    Stopped,
}

/// Lifecycle state of a managed process. Mirrors the process state machine (plan §10.3).
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub enum ProcessState {
    /// Record created, not yet spawning.
    Created,
    /// Spawning.
    Starting,
    /// Running.
    Running,
    /// Graceful termination requested.
    Terminating,
    /// Exited normally.
    Exited,
    /// Terminated by a signal.
    Signaled,
    /// Failed to start or an internal error occurred.
    Failed,
}

/// Why a process ended.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub enum ExitReason {
    /// Exited with a status code.
    Exited,
    /// Killed by a signal.
    Signaled,
    /// Killed because its timeout elapsed.
    Timeout,
    /// Killed because the execution or runtime was cancelled/shut down.
    Cancelled,
    /// Could not be started.
    StartFailed,
    /// The final result was not observable (e.g. reaped elsewhere).
    Lost,
}

/// Which stream a chunk of bytes belongs to.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug, Serialize, Deserialize, JsonSchema)]
pub enum StreamKind {
    /// Non-PTY standard input.
    #[serde(rename = "stdin")]
    Stdin,
    /// Non-PTY standard output.
    #[serde(rename = "stdout")]
    Stdout,
    /// Non-PTY standard error.
    #[serde(rename = "stderr")]
    Stderr,
    /// Bytes written into a PTY.
    #[serde(rename = "pty.input")]
    PtyInput,
    /// Bytes read from a PTY.
    #[serde(rename = "pty.output")]
    PtyOutput,
}

/// Encoding of an inline content field.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub enum Encoding {
    /// Base64 (standard alphabet, padded).
    Base64,
}

/// How an observation was captured. Used for honest provenance.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub enum CaptureMethod {
    /// An OS pipe (non-PTY stdio).
    Pipe,
    /// A pseudoterminal.
    Pty,
    /// An explicit egress proxy.
    Proxy,
    /// inotify filesystem events.
    Inotify,
    /// A filesystem snapshot/diff.
    Snapshot,
    /// An eBPF program.
    Ebpf,
    /// netlink / conntrack.
    Netlink,
    /// Generated internally by the daemon (lifecycle, heartbeats, drop accounting).
    Internal,
}

/// Certainty of an inferred or best-effort attribution.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub enum Confidence {
    /// Directly observed.
    Observed,
    /// Inferred (best-effort) and may be wrong.
    Inferred,
    /// Attribution unknown.
    Unknown,
}

/// Priority class governing preservation guarantees in the telemetry pipeline (plan §15).
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub enum EventPriority {
    /// Lifecycle, errors, drops, corruption — spool before delivery, never silently discarded.
    Critical,
    /// I/O chunks, filesystem mutations, network connections — bounded buffering / spill.
    Normal,
    /// Repeated metrics and verbose noise — first candidates for coalescing or dropping.
    Low,
}

/// Optional features that can be toggled by kill switch (plan §17).
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub enum Feature {
    /// Filesystem diff generation.
    FilesystemDiffing,
    /// Live inotify watching.
    LiveFilesystemWatching,
    /// Network collection.
    NetworkCollection,
    /// Payload capture (request/response bodies).
    PayloadCapture,
    /// Verbose I/O capture.
    VerboseIoCapture,
    /// Per-process resource sampling.
    ResourceSampling,
}

/// A content-addressed reference to a stored artifact (large outputs, patches, captures).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct ArtifactRef {
    /// Hash algorithm (e.g. `sha256`).
    pub algo: String,
    /// Hex-encoded content hash.
    pub hash: String,
    /// Total artifact size in bytes.
    pub bytes: u64,
}

/// Records any transformation applied to captured content.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct TransformMeta {
    /// Content had secrets redacted.
    #[serde(default)]
    pub redacted: bool,
    /// Content was truncated to a limit.
    #[serde(default)]
    pub truncated: bool,
    /// Multiple observations were coalesced into one.
    #[serde(default)]
    pub coalesced: bool,
    /// The original byte count before transformation, when it differs from `byteCount`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub original_byte_count: Option<u64>,
}

/// Payload for `process.started`.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct ProcessStarted {
    /// OS process id (informational; not the stable [`ProcessId`]).
    pub pid: i32,
    /// OS process group id.
    pub pgid: i32,
    /// Whether a pidfd was obtained for race-free signaling/reaping.
    #[serde(default)]
    pub pidfd: bool,
    /// Resolved executable.
    pub executable: String,
    /// Argument vector (excluding argv0).
    #[serde(default)]
    pub args: Vec<String>,
    /// Working directory.
    pub cwd: String,
    /// When the process started.
    pub started_at: WallClockMicros,
}

/// Payload for `process.exited`.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct ProcessExited {
    /// Exit status code, when the process exited normally.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub exit_code: Option<i32>,
    /// Terminating signal number, when signaled.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub signal: Option<i32>,
    /// Why the process ended.
    pub reason: ExitReason,
    /// Wall-clock duration from start to exit, in microseconds.
    pub duration_micros: u64,
}

/// Payload for `io.chunk`.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct IoChunk {
    /// Which stream produced the bytes.
    pub stream: StreamKind,
    /// Encoding of the inline `content`, when present.
    pub encoding: Encoding,
    /// Number of original bytes observed (may exceed inline content if truncated).
    pub byte_count: u64,
    /// Monotonic per-stream byte position of the first byte in this chunk.
    pub stream_offset: StreamOffset,
    /// Inline bytes (base64), when captured inline.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub content: Option<Base64Bytes>,
    /// Reference to externally-stored bytes, when offloaded as an artifact.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub artifact: Option<ArtifactRef>,
    /// Transformation metadata, when content was redacted/truncated/coalesced.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub transform: Option<TransformMeta>,
}

/// Payload for `runtime.stateChanged`.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct RuntimeStateChanged {
    /// The new runtime state.
    pub state: RuntimeState,
    /// Optional human-readable reason.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
}

/// Payload for `runtime.heartbeat`.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct RuntimeHeartbeat {
    /// Current runtime state at heartbeat time.
    pub state: RuntimeState,
}

/// Payload for `telemetry.dropped`: explicit, non-silent accounting of lost telemetry.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct TelemetryDropped {
    /// Why telemetry was dropped (e.g. `queue-full`, `disk-limit`).
    pub reason: String,
    /// Number of events dropped in this accounting record.
    pub count: u64,
    /// Priority class of the dropped events.
    pub priority: EventPriority,
}

/// Kind of filesystem change (plan §13).
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub enum FileChangeKind {
    /// A new entry appeared.
    Added,
    /// An entry's content changed.
    Modified,
    /// An entry was removed.
    Deleted,
    /// An entry was renamed/moved.
    Renamed,
    /// Only metadata (permissions/times) changed.
    MetadataChanged,
}

/// Type of a filesystem entry.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub enum FileType {
    /// Regular file.
    File,
    /// Directory.
    Dir,
    /// Symbolic link.
    Symlink,
    /// Anything else (device, socket, fifo).
    Other,
}

/// Snapshot metadata for a filesystem entry (plan §13).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct FileEntry {
    /// Path relative to the workspace root.
    pub path: String,
    /// Entry type.
    pub file_type: FileType,
    /// Size in bytes.
    pub size: u64,
    /// Modification time (microseconds since the Unix epoch).
    pub mtime_micros: i64,
    /// Unix mode bits.
    pub mode: u32,
    /// Optional content hash (e.g. `sha256:...`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub hash: Option<String>,
    /// Symlink target, when the entry is a symlink.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub symlink_target: Option<String>,
}

/// Payload for `file.changed`: a single observed filesystem mutation.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct FileChange {
    /// The kind of change.
    pub kind: FileChangeKind,
    /// Affected path (the destination for a rename), relative to the workspace root.
    pub path: String,
    /// Source path for a rename.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rename_from: Option<String>,
    /// Snapshot metadata, when available (added/modified/metadata).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub entry: Option<FileEntry>,
    /// Whether the change attribution is certain (vs inferred, e.g. a heuristic rename).
    #[serde(default)]
    pub certain: bool,
}

/// Payload for `file.watchOverflow`: the watcher could not guarantee completeness; a rescan follows.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct FileWatchOverflow {
    /// The watched root.
    pub root: String,
}

/// Payload for `file.snapshotCompleted`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct FileSnapshotCompleted {
    /// The snapshotted root.
    pub root: String,
    /// Number of entries captured.
    pub file_count: u64,
}

/// Payload for `file.diffAvailable`: a summary of a baseline→final diff.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct FileDiffAvailable {
    /// Entries added.
    pub added: u64,
    /// Entries modified.
    pub modified: u64,
    /// Entries deleted.
    pub deleted: u64,
    /// Entries renamed.
    pub renamed: u64,
}

/// The typed, internally-tagged telemetry payload. The tag field is `eventType`.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(tag = "eventType")]
pub enum EventPayload {
    /// The runtime changed lifecycle state.
    #[serde(rename = "runtime.stateChanged")]
    RuntimeStateChanged(RuntimeStateChanged),
    /// Periodic liveness heartbeat.
    #[serde(rename = "runtime.heartbeat")]
    RuntimeHeartbeat(RuntimeHeartbeat),
    /// A managed process started.
    #[serde(rename = "process.started")]
    ProcessStarted(ProcessStarted),
    /// A managed process exited.
    #[serde(rename = "process.exited")]
    ProcessExited(ProcessExited),
    /// A chunk of stream bytes was captured.
    #[serde(rename = "io.chunk")]
    IoChunk(IoChunk),
    /// Telemetry was dropped; never silent.
    #[serde(rename = "telemetry.dropped")]
    TelemetryDropped(TelemetryDropped),
    /// A filesystem change was observed.
    #[serde(rename = "file.changed")]
    FileChange(FileChange),
    /// The filesystem watcher overflowed; a rescan follows.
    #[serde(rename = "file.watchOverflow")]
    FileWatchOverflow(FileWatchOverflow),
    /// A filesystem snapshot completed.
    #[serde(rename = "file.snapshotCompleted")]
    FileSnapshotCompleted(FileSnapshotCompleted),
    /// A baseline→final diff summary is available.
    #[serde(rename = "file.diffAvailable")]
    FileDiffAvailable(FileDiffAvailable),
}

impl EventPayload {
    /// The `eventType` discriminator string for this payload.
    #[must_use]
    pub fn event_type(&self) -> &'static str {
        match self {
            Self::RuntimeStateChanged(_) => "runtime.stateChanged",
            Self::RuntimeHeartbeat(_) => "runtime.heartbeat",
            Self::ProcessStarted(_) => "process.started",
            Self::ProcessExited(_) => "process.exited",
            Self::IoChunk(_) => "io.chunk",
            Self::TelemetryDropped(_) => "telemetry.dropped",
            Self::FileChange(_) => "file.changed",
            Self::FileWatchOverflow(_) => "file.watchOverflow",
            Self::FileSnapshotCompleted(_) => "file.snapshotCompleted",
            Self::FileDiffAvailable(_) => "file.diffAvailable",
        }
    }

    /// Default priority class for this payload (plan §15).
    #[must_use]
    pub fn priority(&self) -> EventPriority {
        match self {
            Self::RuntimeStateChanged(_)
            | Self::ProcessStarted(_)
            | Self::ProcessExited(_)
            | Self::TelemetryDropped(_)
            | Self::FileWatchOverflow(_)
            | Self::FileDiffAvailable(_) => EventPriority::Critical,
            Self::IoChunk(_) | Self::FileChange(_) | Self::FileSnapshotCompleted(_) => {
                EventPriority::Normal
            }
            Self::RuntimeHeartbeat(_) => EventPriority::Low,
        }
    }
}

/// A fully-sequenced telemetry event ready for the wire.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct EventEnvelope {
    /// Wire compatibility version.
    pub schema_version: u32,
    /// Globally unique idempotency key.
    pub event_id: EventId,
    /// Daemon instance identity.
    pub runtime_id: RuntimeId,
    /// Task/execution correlation, when known.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub execution_id: Option<ExecutionId>,
    /// Session correlation, when known.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub session_id: Option<SessionId>,
    /// Process correlation, when known.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub process_id: Option<ProcessId>,
    /// Originating control request, when applicable.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub request_id: Option<RequestId>,
    /// Monotonic order within the runtime's sequence domain.
    pub sequence: Sequence,
    /// Wall-clock observation time (microseconds since the Unix epoch).
    pub observed_at: WallClockMicros,
    /// Monotonic local-ordering reference (nanoseconds).
    pub monotonic_timestamp: MonotonicNanos,
    /// How the observation was captured.
    pub capture_method: CaptureMethod,
    /// Attribution certainty.
    pub confidence: Confidence,
    /// The typed payload (its `eventType` is flattened to the top level).
    #[serde(flatten)]
    pub payload: EventPayload,
}

impl EventEnvelope {
    /// The `eventType` of this envelope's payload.
    #[must_use]
    pub fn event_type(&self) -> &'static str {
        self.payload.event_type()
    }

    /// The priority class of this envelope's payload.
    #[must_use]
    pub fn priority(&self) -> EventPriority {
        self.payload.priority()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::SCHEMA_VERSION;

    fn sample_io_envelope() -> EventEnvelope {
        EventEnvelope {
            schema_version: SCHEMA_VERSION,
            event_id: EventId::new("evt_1"),
            runtime_id: RuntimeId::new("rt_1"),
            execution_id: Some(ExecutionId::new("run-7")),
            session_id: None,
            process_id: Some(ProcessId::new("proc_1")),
            request_id: None,
            sequence: Sequence(42),
            observed_at: WallClockMicros(1_700_000_000_000_000),
            monotonic_timestamp: MonotonicNanos(123),
            capture_method: CaptureMethod::Pipe,
            confidence: Confidence::Observed,
            payload: EventPayload::IoChunk(IoChunk {
                stream: StreamKind::Stdout,
                encoding: Encoding::Base64,
                byte_count: 3,
                stream_offset: StreamOffset(0),
                content: Some(Base64Bytes::new(vec![0u8, 1, 2])),
                artifact: None,
                transform: None,
            }),
        }
    }

    #[test]
    fn envelope_flattens_event_type_to_top_level() {
        let env = sample_io_envelope();
        let value = serde_json::to_value(&env).expect("ser");
        assert_eq!(value["eventType"], "io.chunk");
        assert_eq!(value["stream"], "stdout");
        assert_eq!(value["byteCount"], 3);
        assert_eq!(value["executionId"], "run-7");
        // Optional unset fields are omitted.
        assert!(value.get("sessionId").is_none());
    }

    #[test]
    fn envelope_round_trips() {
        let env = sample_io_envelope();
        let json = serde_json::to_string(&env).expect("ser");
        let back: EventEnvelope = serde_json::from_str(&json).expect("de");
        assert_eq!(back, env);
        assert_eq!(back.event_type(), "io.chunk");
        assert_eq!(back.priority(), EventPriority::Normal);
    }

    #[test]
    fn pty_stream_kinds_use_dotted_wire_names() {
        let json = serde_json::to_string(&StreamKind::PtyOutput).expect("ser");
        assert_eq!(json, "\"pty.output\"");
    }
}
