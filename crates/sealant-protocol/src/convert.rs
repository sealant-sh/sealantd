//! Conversions between the hand-written domain types and the generated Protobuf [`crate::wire`]
//! types, plus the byte-level encode/decode entry points used by the transport and spool (ADR-0012).

use prost::Message as _;

use crate::ids::{
    ChannelId, EventId, ExecutionId, MonotonicNanos, ProcessId, RequestId, RuntimeId, Sequence,
    SessionId, StreamOffset, WallClockMicros,
};
use crate::wire;
use crate::{
    ArtifactRef, AttachMode, AttachSessionArgs, Base64Bytes, Capabilities, CaptureMethod,
    CaptureMode, CapturePolicy, ClientMessage, Command, CommandResult, Confidence, ControlError,
    ControlErrorCode, ControlRequest, ControlResponse, Encoding, EnvVar, EventEnvelope,
    EventPayload, ExecAccepted, ExecArgs, ExecutionStartArgs, ExitReason, Feature, FeatureMatrix,
    FeatureState, ForwardOpened, HealthReport, IoChunk, Limits, NetworkMode, OpenForwardArgs,
    OpenSessionArgs, OpenSftpArgs, ProcessAttached, ProcessExited, ProcessList, ProcessStarted,
    ProcessState, ProcessSummary, ResponseOutcome, RuntimeHeartbeat, RuntimeMetrics, RuntimeState,
    RuntimeStateChanged, ServerMessage, SessionList, SessionOpened, SessionSummary, SftpOpened,
    ShutdownAccepted, Signal, StreamAttached, StreamEnd, StreamFrame, StreamKind, StreamPayload,
    TelemetryDropped, TransformMeta,
};
use crate::{
    FileChange, FileChangeKind, FileDiffAvailable, FileEntry, FileSnapshotCompleted, FileType,
    FileWatchOverflow,
};
use crate::{NetworkRequest, NetworkScheme, NetworkSourceObserved};

/// Errors decoding a wire message into a domain type.
#[derive(Debug, thiserror::Error)]
pub enum WireError {
    /// Protobuf decoding failed.
    #[error("protobuf decode error: {0}")]
    Decode(#[from] prost::DecodeError),
    /// A required message field was absent.
    #[error("missing required field: {0}")]
    MissingField(&'static str),
    /// A required `oneof` had no case set.
    #[error("missing oneof: {0}")]
    MissingOneof(&'static str),
    /// An enum field held an unspecified or unknown value.
    #[error("unknown enum value for {0}")]
    UnknownEnum(&'static str),
}

fn unknown(name: &'static str) -> WireError {
    WireError::UnknownEnum(name)
}

// ---------- enums (domain variant names match wire variant names) ----------

macro_rules! enum_pair {
    ($from_fn:ident, $domain:ty, $wire:path, [$($v:ident),+ $(,)?]) => {
        impl From<$domain> for $wire {
            fn from(value: $domain) -> Self {
                match value { $(<$domain>::$v => <$wire>::$v,)+ }
            }
        }
        fn $from_fn(raw: i32) -> Result<$domain, WireError> {
            match <$wire>::try_from(raw) {
                $(Ok(<$wire>::$v) => Ok(<$domain>::$v),)+
                _ => Err(unknown(stringify!($domain))),
            }
        }
    };
}

enum_pair!(
    rt_state,
    RuntimeState,
    wire::RuntimeState,
    [
        Starting,
        Healthy,
        Degraded,
        Unhealthy,
        ShuttingDown,
        Stopped
    ]
);
enum_pair!(
    proc_state,
    ProcessState,
    wire::ProcessState,
    [
        Created,
        Starting,
        Running,
        Terminating,
        Exited,
        Signaled,
        Failed
    ]
);
enum_pair!(
    exit_reason,
    ExitReason,
    wire::ExitReason,
    [Exited, Signaled, Timeout, Cancelled, StartFailed, Lost]
);
enum_pair!(
    stream_kind,
    StreamKind,
    wire::StreamKind,
    [Stdin, Stdout, Stderr, PtyInput, PtyOutput]
);
enum_pair!(
    capture_method,
    CaptureMethod,
    wire::CaptureMethod,
    [Pipe, Pty, Proxy, Inotify, Snapshot, Ebpf, Netlink, Internal]
);
enum_pair!(
    confidence,
    Confidence,
    wire::Confidence,
    [Observed, Inferred, Unknown]
);
enum_pair!(
    priority,
    crate::EventPriority,
    wire::EventPriority,
    [Critical, Normal, Low]
);
enum_pair!(
    feature,
    Feature,
    wire::Feature,
    [
        FilesystemDiffing,
        LiveFilesystemWatching,
        NetworkCollection,
        PayloadCapture,
        VerboseIoCapture,
        ResourceSampling
    ]
);
enum_pair!(
    signal,
    Signal,
    wire::Signal,
    [Hup, Int, Quit, Term, Kill, Usr1, Usr2, Stop, Cont]
);
enum_pair!(
    attach_mode,
    AttachMode,
    wire::AttachMode,
    [Interactive, Observe]
);
enum_pair!(
    capture_mode,
    CaptureMode,
    wire::CaptureMode,
    [Full, MetadataOnly, Disabled]
);
enum_pair!(
    network_mode,
    NetworkMode,
    wire::NetworkMode,
    [Off, Metadata, Proxy, Privileged, Payload]
);
enum_pair!(
    error_code,
    ControlErrorCode,
    wire::ControlErrorCode,
    [
        InvalidJson,
        UnsupportedVersion,
        FrameTooLarge,
        UnknownCommand,
        InvalidArgument,
        MissingCommand,
        ExecutionNotFound,
        SessionNotFound,
        ProcessNotFound,
        ProcessStartFailed,
        PtyAllocationFailed,
        PermissionDenied,
        PolicyDenied,
        FeatureUnavailable,
        CapabilityUnavailable,
        QueueFull,
        RuntimeShuttingDown,
        InternalError
    ]
);

fn enum_i32<D, W>(value: D) -> i32
where
    W: From<D> + Into<i32>,
{
    let w: W = W::from(value);
    w.into()
}

// ---------- id helpers ----------

fn opt_id<T: AsRef<str>>(id: Option<T>) -> Option<String> {
    id.map(|i| i.as_ref().to_owned())
}

// ---------- value messages ----------

impl From<EnvVar> for wire::EnvVar {
    fn from(v: EnvVar) -> Self {
        Self {
            key: v.key,
            value: v.value,
        }
    }
}
impl From<wire::EnvVar> for EnvVar {
    fn from(v: wire::EnvVar) -> Self {
        Self {
            key: v.key,
            value: v.value,
        }
    }
}

impl From<CapturePolicy> for wire::CapturePolicy {
    fn from(p: CapturePolicy) -> Self {
        Self {
            stdout: enum_i32::<_, wire::CaptureMode>(p.stdout),
            stderr: enum_i32::<_, wire::CaptureMode>(p.stderr),
            stdin: enum_i32::<_, wire::CaptureMode>(p.stdin),
        }
    }
}
impl TryFrom<wire::CapturePolicy> for CapturePolicy {
    type Error = WireError;
    fn try_from(p: wire::CapturePolicy) -> Result<Self, WireError> {
        Ok(Self {
            stdout: capture_mode(p.stdout)?,
            stderr: capture_mode(p.stderr)?,
            stdin: capture_mode(p.stdin)?,
        })
    }
}

impl From<ArtifactRef> for wire::ArtifactRef {
    fn from(a: ArtifactRef) -> Self {
        Self {
            algo: a.algo,
            hash: a.hash,
            bytes: a.bytes,
        }
    }
}
impl From<wire::ArtifactRef> for ArtifactRef {
    fn from(a: wire::ArtifactRef) -> Self {
        Self {
            algo: a.algo,
            hash: a.hash,
            bytes: a.bytes,
        }
    }
}

impl From<TransformMeta> for wire::TransformMeta {
    fn from(t: TransformMeta) -> Self {
        Self {
            redacted: t.redacted,
            truncated: t.truncated,
            coalesced: t.coalesced,
            original_byte_count: t.original_byte_count,
        }
    }
}
impl From<wire::TransformMeta> for TransformMeta {
    fn from(t: wire::TransformMeta) -> Self {
        Self {
            redacted: t.redacted,
            truncated: t.truncated,
            coalesced: t.coalesced,
            original_byte_count: t.original_byte_count,
        }
    }
}

impl From<Limits> for wire::Limits {
    fn from(l: Limits) -> Self {
        Self {
            max_frame_bytes: l.max_frame_bytes,
            max_processes: l.max_processes,
            max_sessions: l.max_sessions,
            event_queue_capacity: l.event_queue_capacity,
            spool_limit_bytes: l.spool_limit_bytes,
            max_inline_payload_bytes: l.max_inline_payload_bytes,
            io_chunk_bytes: l.io_chunk_bytes,
        }
    }
}
impl From<wire::Limits> for Limits {
    fn from(l: wire::Limits) -> Self {
        Self {
            max_frame_bytes: l.max_frame_bytes,
            max_processes: l.max_processes,
            max_sessions: l.max_sessions,
            event_queue_capacity: l.event_queue_capacity,
            spool_limit_bytes: l.spool_limit_bytes,
            max_inline_payload_bytes: l.max_inline_payload_bytes,
            io_chunk_bytes: l.io_chunk_bytes,
        }
    }
}

impl From<FeatureMatrix> for wire::FeatureMatrix {
    fn from(f: FeatureMatrix) -> Self {
        Self {
            io_capture: f.io_capture,
            pty: f.pty,
            filesystem: f.filesystem,
            network: enum_i32::<_, wire::NetworkMode>(f.network),
            privileged: f.privileged,
            pidfd: f.pidfd,
            subreaper: f.subreaper,
        }
    }
}
impl TryFrom<wire::FeatureMatrix> for FeatureMatrix {
    type Error = WireError;
    fn try_from(f: wire::FeatureMatrix) -> Result<Self, WireError> {
        Ok(Self {
            io_capture: f.io_capture,
            pty: f.pty,
            filesystem: f.filesystem,
            network: network_mode(f.network)?,
            privileged: f.privileged,
            pidfd: f.pidfd,
            subreaper: f.subreaper,
        })
    }
}

impl From<FeatureState> for wire::FeatureState {
    fn from(f: FeatureState) -> Self {
        Self {
            feature: enum_i32::<_, wire::Feature>(f.feature),
            enabled: f.enabled,
        }
    }
}
impl TryFrom<wire::FeatureState> for FeatureState {
    type Error = WireError;
    fn try_from(f: wire::FeatureState) -> Result<Self, WireError> {
        Ok(Self {
            feature: feature(f.feature)?,
            enabled: f.enabled,
        })
    }
}

// ---------- event payloads ----------

impl From<ProcessStarted> for wire::ProcessStarted {
    fn from(p: ProcessStarted) -> Self {
        Self {
            pid: p.pid,
            pgid: p.pgid,
            pidfd: p.pidfd,
            executable: p.executable,
            args: p.args,
            cwd: p.cwd,
            started_at: p.started_at.get(),
        }
    }
}
impl From<wire::ProcessStarted> for ProcessStarted {
    fn from(p: wire::ProcessStarted) -> Self {
        Self {
            pid: p.pid,
            pgid: p.pgid,
            pidfd: p.pidfd,
            executable: p.executable,
            args: p.args,
            cwd: p.cwd,
            started_at: WallClockMicros(p.started_at),
        }
    }
}

impl From<ProcessExited> for wire::ProcessExited {
    fn from(p: ProcessExited) -> Self {
        Self {
            exit_code: p.exit_code,
            signal: p.signal,
            reason: enum_i32::<_, wire::ExitReason>(p.reason),
            duration_micros: p.duration_micros,
        }
    }
}
impl TryFrom<wire::ProcessExited> for ProcessExited {
    type Error = WireError;
    fn try_from(p: wire::ProcessExited) -> Result<Self, WireError> {
        Ok(Self {
            exit_code: p.exit_code,
            signal: p.signal,
            reason: exit_reason(p.reason)?,
            duration_micros: p.duration_micros,
        })
    }
}

impl From<IoChunk> for wire::IoChunk {
    fn from(c: IoChunk) -> Self {
        Self {
            stream: enum_i32::<_, wire::StreamKind>(c.stream),
            byte_count: c.byte_count,
            stream_offset: c.stream_offset.get(),
            content: c.content.map(Base64Bytes::into_inner),
            artifact: c.artifact.map(Into::into),
            transform: c.transform.map(Into::into),
        }
    }
}
impl TryFrom<wire::IoChunk> for IoChunk {
    type Error = WireError;
    fn try_from(c: wire::IoChunk) -> Result<Self, WireError> {
        Ok(Self {
            stream: stream_kind(c.stream)?,
            encoding: Encoding::Base64,
            byte_count: c.byte_count,
            stream_offset: StreamOffset(c.stream_offset),
            content: c.content.map(Base64Bytes::new),
            artifact: c.artifact.map(Into::into),
            transform: c.transform.map(Into::into),
        })
    }
}

impl From<TelemetryDropped> for wire::TelemetryDropped {
    fn from(d: TelemetryDropped) -> Self {
        Self {
            reason: d.reason,
            count: d.count,
            priority: enum_i32::<_, wire::EventPriority>(d.priority),
        }
    }
}
impl TryFrom<wire::TelemetryDropped> for TelemetryDropped {
    type Error = WireError;
    fn try_from(d: wire::TelemetryDropped) -> Result<Self, WireError> {
        Ok(Self {
            reason: d.reason,
            count: d.count,
            priority: priority(d.priority)?,
        })
    }
}

enum_pair!(
    file_change_kind,
    FileChangeKind,
    wire::FileChangeKind,
    [Added, Modified, Deleted, Renamed, MetadataChanged]
);
enum_pair!(
    file_type,
    FileType,
    wire::FileType,
    [File, Dir, Symlink, Other]
);

impl From<FileEntry> for wire::FileEntry {
    fn from(e: FileEntry) -> Self {
        Self {
            path: e.path,
            file_type: enum_i32::<_, wire::FileType>(e.file_type),
            size: e.size,
            mtime_micros: e.mtime_micros,
            mode: e.mode,
            hash: e.hash,
            symlink_target: e.symlink_target,
        }
    }
}
impl TryFrom<wire::FileEntry> for FileEntry {
    type Error = WireError;
    fn try_from(e: wire::FileEntry) -> Result<Self, WireError> {
        Ok(Self {
            path: e.path,
            file_type: file_type(e.file_type)?,
            size: e.size,
            mtime_micros: e.mtime_micros,
            mode: e.mode,
            hash: e.hash,
            symlink_target: e.symlink_target,
        })
    }
}

impl From<FileChange> for wire::FileChange {
    fn from(c: FileChange) -> Self {
        Self {
            kind: enum_i32::<_, wire::FileChangeKind>(c.kind),
            path: c.path,
            rename_from: c.rename_from,
            entry: c.entry.map(Into::into),
            certain: c.certain,
        }
    }
}
impl TryFrom<wire::FileChange> for FileChange {
    type Error = WireError;
    fn try_from(c: wire::FileChange) -> Result<Self, WireError> {
        Ok(Self {
            kind: file_change_kind(c.kind)?,
            path: c.path,
            rename_from: c.rename_from,
            entry: c.entry.map(TryInto::try_into).transpose()?,
            certain: c.certain,
        })
    }
}

impl From<FileWatchOverflow> for wire::FileWatchOverflow {
    fn from(o: FileWatchOverflow) -> Self {
        Self { root: o.root }
    }
}
impl From<wire::FileWatchOverflow> for FileWatchOverflow {
    fn from(o: wire::FileWatchOverflow) -> Self {
        Self { root: o.root }
    }
}
impl From<FileSnapshotCompleted> for wire::FileSnapshotCompleted {
    fn from(s: FileSnapshotCompleted) -> Self {
        Self {
            root: s.root,
            file_count: s.file_count,
        }
    }
}
impl From<wire::FileSnapshotCompleted> for FileSnapshotCompleted {
    fn from(s: wire::FileSnapshotCompleted) -> Self {
        Self {
            root: s.root,
            file_count: s.file_count,
        }
    }
}
impl From<FileDiffAvailable> for wire::FileDiffAvailable {
    fn from(d: FileDiffAvailable) -> Self {
        Self {
            added: d.added,
            modified: d.modified,
            deleted: d.deleted,
            renamed: d.renamed,
        }
    }
}
impl From<wire::FileDiffAvailable> for FileDiffAvailable {
    fn from(d: wire::FileDiffAvailable) -> Self {
        Self {
            added: d.added,
            modified: d.modified,
            deleted: d.deleted,
            renamed: d.renamed,
        }
    }
}

enum_pair!(
    network_scheme,
    NetworkScheme,
    wire::NetworkScheme,
    [Http, HttpsConnect]
);

impl From<NetworkRequest> for wire::NetworkRequest {
    fn from(r: NetworkRequest) -> Self {
        Self {
            scheme: enum_i32::<_, wire::NetworkScheme>(r.scheme),
            method: r.method,
            host: r.host,
            port: u32::from(r.port),
            path: r.path,
            status: r.status,
            bytes_sent: r.bytes_sent,
            bytes_received: r.bytes_received,
            duration_micros: r.duration_micros,
        }
    }
}
impl TryFrom<wire::NetworkRequest> for NetworkRequest {
    type Error = WireError;
    fn try_from(r: wire::NetworkRequest) -> Result<Self, WireError> {
        Ok(Self {
            scheme: network_scheme(r.scheme)?,
            method: r.method,
            host: r.host,
            port: r.port as u16,
            path: r.path,
            status: r.status,
            bytes_sent: r.bytes_sent,
            bytes_received: r.bytes_received,
            duration_micros: r.duration_micros,
        })
    }
}

impl From<NetworkSourceObserved> for wire::NetworkSourceObserved {
    fn from(s: NetworkSourceObserved) -> Self {
        Self {
            host: s.host,
            resolved_ips: s.resolved_ips,
            port: u32::from(s.port),
            scheme: s.scheme.map(enum_i32::<_, wire::NetworkScheme>),
            method: s.method,
            path: s.path,
            status: s.status,
        }
    }
}
impl TryFrom<wire::NetworkSourceObserved> for NetworkSourceObserved {
    type Error = WireError;
    fn try_from(s: wire::NetworkSourceObserved) -> Result<Self, WireError> {
        Ok(Self {
            host: s.host,
            resolved_ips: s.resolved_ips,
            port: s.port as u16,
            scheme: s.scheme.map(network_scheme).transpose()?,
            method: s.method,
            path: s.path,
            status: s.status,
        })
    }
}

impl From<EventPayload> for wire::event_envelope::Payload {
    fn from(p: EventPayload) -> Self {
        use wire::event_envelope::Payload as W;
        match p {
            EventPayload::RuntimeStateChanged(s) => {
                W::RuntimeStateChanged(wire::RuntimeStateChanged {
                    state: enum_i32::<_, wire::RuntimeState>(s.state),
                    reason: s.reason,
                })
            }
            EventPayload::RuntimeHeartbeat(h) => W::RuntimeHeartbeat(wire::RuntimeHeartbeat {
                state: enum_i32::<_, wire::RuntimeState>(h.state),
            }),
            EventPayload::ProcessStarted(s) => W::ProcessStarted(s.into()),
            EventPayload::ProcessExited(e) => W::ProcessExited(e.into()),
            EventPayload::IoChunk(c) => W::IoChunk(c.into()),
            EventPayload::TelemetryDropped(d) => W::TelemetryDropped(d.into()),
            EventPayload::FileChange(c) => W::FileChange(c.into()),
            EventPayload::FileWatchOverflow(o) => W::FileWatchOverflow(o.into()),
            EventPayload::FileSnapshotCompleted(s) => W::FileSnapshotCompleted(s.into()),
            EventPayload::FileDiffAvailable(d) => W::FileDiffAvailable(d.into()),
            EventPayload::NetworkRequest(r) => W::NetworkRequest(r.into()),
            EventPayload::NetworkSourceObserved(s) => W::NetworkSourceObserved(s.into()),
        }
    }
}
impl TryFrom<wire::event_envelope::Payload> for EventPayload {
    type Error = WireError;
    fn try_from(p: wire::event_envelope::Payload) -> Result<Self, WireError> {
        use wire::event_envelope::Payload as W;
        Ok(match p {
            W::RuntimeStateChanged(s) => EventPayload::RuntimeStateChanged(RuntimeStateChanged {
                state: rt_state(s.state)?,
                reason: s.reason,
            }),
            W::RuntimeHeartbeat(h) => EventPayload::RuntimeHeartbeat(RuntimeHeartbeat {
                state: rt_state(h.state)?,
            }),
            W::ProcessStarted(s) => EventPayload::ProcessStarted(s.into()),
            W::ProcessExited(e) => EventPayload::ProcessExited(e.try_into()?),
            W::IoChunk(c) => EventPayload::IoChunk(c.try_into()?),
            W::TelemetryDropped(d) => EventPayload::TelemetryDropped(d.try_into()?),
            W::FileChange(c) => EventPayload::FileChange(c.try_into()?),
            W::FileWatchOverflow(o) => EventPayload::FileWatchOverflow(o.into()),
            W::FileSnapshotCompleted(s) => EventPayload::FileSnapshotCompleted(s.into()),
            W::FileDiffAvailable(d) => EventPayload::FileDiffAvailable(d.into()),
            W::NetworkRequest(r) => EventPayload::NetworkRequest(r.try_into()?),
            W::NetworkSourceObserved(s) => EventPayload::NetworkSourceObserved(s.try_into()?),
        })
    }
}

impl From<EventEnvelope> for wire::EventEnvelope {
    fn from(e: EventEnvelope) -> Self {
        Self {
            schema_version: e.schema_version,
            event_id: e.event_id.into_inner(),
            runtime_id: e.runtime_id.into_inner(),
            execution_id: opt_id(e.execution_id),
            session_id: opt_id(e.session_id),
            process_id: opt_id(e.process_id),
            request_id: opt_id(e.request_id),
            sequence: e.sequence.get(),
            observed_at: e.observed_at.get(),
            monotonic_timestamp: e.monotonic_timestamp.get(),
            capture_method: enum_i32::<_, wire::CaptureMethod>(e.capture_method),
            confidence: enum_i32::<_, wire::Confidence>(e.confidence),
            payload: Some(e.payload.into()),
        }
    }
}
impl TryFrom<wire::EventEnvelope> for EventEnvelope {
    type Error = WireError;
    fn try_from(e: wire::EventEnvelope) -> Result<Self, WireError> {
        Ok(Self {
            schema_version: e.schema_version,
            event_id: EventId::new(e.event_id),
            runtime_id: RuntimeId::new(e.runtime_id),
            execution_id: e.execution_id.map(ExecutionId::new),
            session_id: e.session_id.map(SessionId::new),
            process_id: e.process_id.map(ProcessId::new),
            request_id: e.request_id.map(RequestId::new),
            sequence: Sequence(e.sequence),
            observed_at: WallClockMicros(e.observed_at),
            monotonic_timestamp: MonotonicNanos(e.monotonic_timestamp),
            capture_method: capture_method(e.capture_method)?,
            confidence: confidence(e.confidence)?,
            payload: e
                .payload
                .ok_or(WireError::MissingOneof("EventEnvelope.payload"))?
                .try_into()?,
        })
    }
}

// ---------- command args ----------

impl From<ExecArgs> for wire::ExecArgs {
    fn from(a: ExecArgs) -> Self {
        Self {
            execution_id: opt_id(a.execution_id),
            session_id: opt_id(a.session_id),
            executable: a.executable,
            args: a.args,
            cwd: a.cwd,
            env: a.env.into_iter().map(Into::into).collect(),
            stdin: a.stdin,
            timeout_millis: a.timeout_millis,
            background: a.background,
            capture: a.capture.map(Into::into),
            graceful_signal: a.graceful_signal.map(enum_i32::<_, wire::Signal>),
            attach: a.attach,
        }
    }
}
impl TryFrom<wire::ExecArgs> for ExecArgs {
    type Error = WireError;
    fn try_from(a: wire::ExecArgs) -> Result<Self, WireError> {
        Ok(Self {
            execution_id: a.execution_id.map(ExecutionId::new),
            session_id: a.session_id.map(SessionId::new),
            executable: a.executable,
            args: a.args,
            cwd: a.cwd,
            env: a.env.into_iter().map(Into::into).collect(),
            stdin: a.stdin,
            timeout_millis: a.timeout_millis,
            background: a.background,
            capture: a.capture.map(TryInto::try_into).transpose()?,
            graceful_signal: a.graceful_signal.map(signal).transpose()?,
            attach: a.attach,
        })
    }
}

impl From<OpenSessionArgs> for wire::OpenSessionArgs {
    fn from(a: OpenSessionArgs) -> Self {
        Self {
            execution_id: opt_id(a.execution_id),
            shell: a.shell,
            args: a.args,
            cwd: a.cwd,
            env: a.env.into_iter().map(Into::into).collect(),
            cols: u32::from(a.cols),
            rows: u32::from(a.rows),
            term: a.term,
        }
    }
}
impl TryFrom<wire::OpenSessionArgs> for OpenSessionArgs {
    type Error = WireError;
    fn try_from(a: wire::OpenSessionArgs) -> Result<Self, WireError> {
        Ok(Self {
            execution_id: a.execution_id.map(ExecutionId::new),
            shell: a.shell,
            args: a.args,
            cwd: a.cwd,
            env: a.env.into_iter().map(Into::into).collect(),
            cols: a.cols as u16,
            rows: a.rows as u16,
            term: a.term,
        })
    }
}

impl From<AttachSessionArgs> for wire::AttachSessionArgs {
    fn from(a: AttachSessionArgs) -> Self {
        Self {
            session_id: a.session_id.into_inner(),
            mode: enum_i32::<_, wire::AttachMode>(a.mode),
        }
    }
}
impl TryFrom<wire::AttachSessionArgs> for AttachSessionArgs {
    type Error = WireError;
    fn try_from(a: wire::AttachSessionArgs) -> Result<Self, WireError> {
        Ok(Self {
            session_id: SessionId::new(a.session_id),
            mode: attach_mode(a.mode)?,
        })
    }
}

impl From<OpenForwardArgs> for wire::OpenForwardArgs {
    fn from(a: OpenForwardArgs) -> Self {
        Self {
            host: a.host,
            port: u32::from(a.port),
            execution_id: opt_id(a.execution_id),
        }
    }
}
impl From<wire::OpenForwardArgs> for OpenForwardArgs {
    fn from(a: wire::OpenForwardArgs) -> Self {
        Self {
            host: a.host,
            port: a.port as u16,
            execution_id: a.execution_id.map(ExecutionId::new),
        }
    }
}

impl From<OpenSftpArgs> for wire::OpenSftpArgs {
    fn from(a: OpenSftpArgs) -> Self {
        Self {
            execution_id: opt_id(a.execution_id),
            cwd: a.cwd,
        }
    }
}
impl From<wire::OpenSftpArgs> for OpenSftpArgs {
    fn from(a: wire::OpenSftpArgs) -> Self {
        Self {
            execution_id: a.execution_id.map(ExecutionId::new),
            cwd: a.cwd,
        }
    }
}

impl From<ExecutionStartArgs> for wire::ExecutionStartArgs {
    fn from(a: ExecutionStartArgs) -> Self {
        Self {
            execution_id: opt_id(a.execution_id),
            labels_json: a.labels.map(|v| v.to_string()),
        }
    }
}
impl TryFrom<wire::ExecutionStartArgs> for ExecutionStartArgs {
    type Error = WireError;
    fn try_from(a: wire::ExecutionStartArgs) -> Result<Self, WireError> {
        Ok(Self {
            execution_id: a.execution_id.map(ExecutionId::new),
            labels: a.labels_json.and_then(|s| serde_json::from_str(&s).ok()),
        })
    }
}

impl From<Command> for wire::command::Command {
    fn from(c: Command) -> Self {
        use wire::command::Command as W;
        match c {
            Command::RuntimeHealth => W::RuntimeHealth(wire::Empty {}),
            Command::RuntimeGetCapabilities => W::RuntimeGetCapabilities(wire::Empty {}),
            Command::RuntimeGracefulShutdown { grace_millis } => {
                W::RuntimeGracefulShutdown(wire::RuntimeGracefulShutdownArgs { grace_millis })
            }
            Command::RuntimeKill => W::RuntimeKill(wire::Empty {}),
            Command::ExecutionStart(a) => W::ExecutionStart(a.into()),
            Command::ExecutionStop { execution_id } => W::ExecutionStop(wire::ExecutionStopArgs {
                execution_id: execution_id.into_inner(),
            }),
            Command::Exec(a) => W::Exec(a.into()),
            Command::SignalProcess {
                process_id,
                signal: sig,
            } => W::SignalProcess(wire::SignalProcessArgs {
                process_id: process_id.into_inner(),
                signal: enum_i32::<_, wire::Signal>(sig),
            }),
            Command::KillProcess { process_id } => W::KillProcess(wire::KillProcessArgs {
                process_id: process_id.into_inner(),
            }),
            Command::ListProcesses { execution_id } => W::ListProcesses(wire::ListProcessesArgs {
                execution_id: opt_id(execution_id),
            }),
            Command::WriteStdin(a) => W::WriteStdin(wire::WriteStdinArgs {
                process_id: opt_id(a.process_id),
                session_id: opt_id(a.session_id),
                data: a.data.into_inner(),
            }),
            Command::CloseStdin { process_id } => W::CloseStdin(wire::CloseStdinArgs {
                process_id: process_id.into_inner(),
            }),
            Command::OpenSession(a) => W::OpenSession(a.into()),
            Command::CloseSession { session_id } => W::CloseSession(wire::CloseSessionArgs {
                session_id: session_id.into_inner(),
            }),
            Command::ResizePty {
                session_id,
                cols,
                rows,
            } => W::ResizePty(wire::ResizePtyArgs {
                session_id: session_id.into_inner(),
                cols: u32::from(cols),
                rows: u32::from(rows),
            }),
            Command::ListSessions => W::ListSessions(wire::Empty {}),
            Command::SetFeatureState {
                feature: feat,
                enabled,
            } => W::SetFeatureState(wire::SetFeatureStateArgs {
                feature: enum_i32::<_, wire::Feature>(feat),
                enabled,
            }),
            Command::GetRuntimeMetrics => W::GetRuntimeMetrics(wire::Empty {}),
            Command::AttachSession(a) => W::AttachSession(a.into()),
            Command::DetachSession { channel_id } => W::DetachSession(wire::DetachSessionArgs {
                channel_id: channel_id.into_inner(),
            }),
            Command::OpenForward(a) => W::OpenForward(a.into()),
            Command::CloseForward { channel_id } => W::CloseForward(wire::CloseForwardArgs {
                channel_id: channel_id.into_inner(),
            }),
            Command::OpenSftp(a) => W::OpenSftp(a.into()),
            Command::CloseSftp { channel_id } => W::CloseSftp(wire::CloseSftpArgs {
                channel_id: channel_id.into_inner(),
            }),
        }
    }
}
impl TryFrom<wire::command::Command> for Command {
    type Error = WireError;
    fn try_from(c: wire::command::Command) -> Result<Self, WireError> {
        use crate::WriteStdinArgs;
        use wire::command::Command as W;
        Ok(match c {
            W::RuntimeHealth(_) => Command::RuntimeHealth,
            W::RuntimeGetCapabilities(_) => Command::RuntimeGetCapabilities,
            W::RuntimeGracefulShutdown(a) => Command::RuntimeGracefulShutdown {
                grace_millis: a.grace_millis,
            },
            W::RuntimeKill(_) => Command::RuntimeKill,
            W::ExecutionStart(a) => Command::ExecutionStart(a.try_into()?),
            W::ExecutionStop(a) => Command::ExecutionStop {
                execution_id: ExecutionId::new(a.execution_id),
            },
            W::Exec(a) => Command::Exec(a.try_into()?),
            W::SignalProcess(a) => Command::SignalProcess {
                process_id: ProcessId::new(a.process_id),
                signal: signal(a.signal)?,
            },
            W::KillProcess(a) => Command::KillProcess {
                process_id: ProcessId::new(a.process_id),
            },
            W::ListProcesses(a) => Command::ListProcesses {
                execution_id: a.execution_id.map(ExecutionId::new),
            },
            W::WriteStdin(a) => Command::WriteStdin(WriteStdinArgs {
                process_id: a.process_id.map(ProcessId::new),
                session_id: a.session_id.map(SessionId::new),
                data: Base64Bytes::new(a.data),
            }),
            W::CloseStdin(a) => Command::CloseStdin {
                process_id: ProcessId::new(a.process_id),
            },
            W::OpenSession(a) => Command::OpenSession(a.try_into()?),
            W::CloseSession(a) => Command::CloseSession {
                session_id: SessionId::new(a.session_id),
            },
            W::ResizePty(a) => Command::ResizePty {
                session_id: SessionId::new(a.session_id),
                cols: a.cols as u16,
                rows: a.rows as u16,
            },
            W::ListSessions(_) => Command::ListSessions,
            W::SetFeatureState(a) => Command::SetFeatureState {
                feature: feature(a.feature)?,
                enabled: a.enabled,
            },
            W::GetRuntimeMetrics(_) => Command::GetRuntimeMetrics,
            W::AttachSession(a) => Command::AttachSession(a.try_into()?),
            W::DetachSession(a) => Command::DetachSession {
                channel_id: ChannelId::new(a.channel_id),
            },
            W::OpenForward(a) => Command::OpenForward(a.into()),
            W::CloseForward(a) => Command::CloseForward {
                channel_id: ChannelId::new(a.channel_id),
            },
            W::OpenSftp(a) => Command::OpenSftp(a.into()),
            W::CloseSftp(a) => Command::CloseSftp {
                channel_id: ChannelId::new(a.channel_id),
            },
        })
    }
}

// ---------- results ----------

impl From<Capabilities> for wire::Capabilities {
    fn from(c: Capabilities) -> Self {
        Self {
            schema_version: c.schema_version,
            runtime_id: c.runtime_id.into_inner(),
            workspace_id: c.workspace_id,
            os: c.os,
            arch: c.arch,
            daemon_version: c.daemon_version,
            features: Some(c.features.into()),
            limits: Some(c.limits.into()),
        }
    }
}
impl TryFrom<wire::Capabilities> for Capabilities {
    type Error = WireError;
    fn try_from(c: wire::Capabilities) -> Result<Self, WireError> {
        Ok(Self {
            schema_version: c.schema_version,
            runtime_id: RuntimeId::new(c.runtime_id),
            workspace_id: c.workspace_id,
            os: c.os,
            arch: c.arch,
            daemon_version: c.daemon_version,
            features: c
                .features
                .ok_or(WireError::MissingField("Capabilities.features"))?
                .try_into()?,
            limits: c
                .limits
                .ok_or(WireError::MissingField("Capabilities.limits"))?
                .into(),
        })
    }
}

impl From<HealthReport> for wire::HealthReport {
    fn from(h: HealthReport) -> Self {
        Self {
            state: enum_i32::<_, wire::RuntimeState>(h.state),
            runtime_id: h.runtime_id.into_inner(),
            uptime_millis: h.uptime_millis,
            active_executions: h.active_executions,
            active_sessions: h.active_sessions,
            active_processes: h.active_processes,
            queue_depth: h.queue_depth,
            queue_capacity: h.queue_capacity,
            spool_bytes: h.spool_bytes,
            spool_limit_bytes: h.spool_limit_bytes,
            retry_count: h.retry_count,
            last_delivery_at: h.last_delivery_at.map(WallClockMicros::get),
            dropped_events: h.dropped_events,
            redacted_events: h.redacted_events,
            coalesced_events: h.coalesced_events,
            truncated_events: h.truncated_events,
            sink_connected: h.sink_connected,
            feature_states: h.feature_states.into_iter().map(Into::into).collect(),
            degradation_reasons: h.degradation_reasons,
        }
    }
}
impl TryFrom<wire::HealthReport> for HealthReport {
    type Error = WireError;
    fn try_from(h: wire::HealthReport) -> Result<Self, WireError> {
        Ok(Self {
            state: rt_state(h.state)?,
            runtime_id: RuntimeId::new(h.runtime_id),
            uptime_millis: h.uptime_millis,
            active_executions: h.active_executions,
            active_sessions: h.active_sessions,
            active_processes: h.active_processes,
            queue_depth: h.queue_depth,
            queue_capacity: h.queue_capacity,
            spool_bytes: h.spool_bytes,
            spool_limit_bytes: h.spool_limit_bytes,
            retry_count: h.retry_count,
            last_delivery_at: h.last_delivery_at.map(WallClockMicros),
            dropped_events: h.dropped_events,
            redacted_events: h.redacted_events,
            coalesced_events: h.coalesced_events,
            truncated_events: h.truncated_events,
            sink_connected: h.sink_connected,
            feature_states: h
                .feature_states
                .into_iter()
                .map(TryInto::try_into)
                .collect::<Result<_, _>>()?,
            degradation_reasons: h.degradation_reasons,
        })
    }
}

impl From<ProcessSummary> for wire::ProcessSummary {
    fn from(p: ProcessSummary) -> Self {
        Self {
            process_id: p.process_id.into_inner(),
            pid: p.pid,
            pgid: p.pgid,
            state: enum_i32::<_, wire::ProcessState>(p.state),
            executable: p.executable,
            execution_id: opt_id(p.execution_id),
            session_id: opt_id(p.session_id),
        }
    }
}
impl TryFrom<wire::ProcessSummary> for ProcessSummary {
    type Error = WireError;
    fn try_from(p: wire::ProcessSummary) -> Result<Self, WireError> {
        Ok(Self {
            process_id: ProcessId::new(p.process_id),
            pid: p.pid,
            pgid: p.pgid,
            state: proc_state(p.state)?,
            executable: p.executable,
            execution_id: p.execution_id.map(ExecutionId::new),
            session_id: p.session_id.map(SessionId::new),
        })
    }
}

impl From<SessionSummary> for wire::SessionSummary {
    fn from(s: SessionSummary) -> Self {
        Self {
            session_id: s.session_id.into_inner(),
            process_id: s.process_id.into_inner(),
            pid: s.pid,
            cols: u32::from(s.cols),
            rows: u32::from(s.rows),
            execution_id: opt_id(s.execution_id),
        }
    }
}
impl From<wire::SessionSummary> for SessionSummary {
    fn from(s: wire::SessionSummary) -> Self {
        Self {
            session_id: SessionId::new(s.session_id),
            process_id: ProcessId::new(s.process_id),
            pid: s.pid,
            cols: s.cols as u16,
            rows: s.rows as u16,
            execution_id: s.execution_id.map(ExecutionId::new),
        }
    }
}

impl From<CommandResult> for wire::command_result::Result {
    fn from(r: CommandResult) -> Self {
        use wire::command_result::Result as W;
        match r {
            CommandResult::Health(h) => W::Health(h.into()),
            CommandResult::Capabilities(c) => W::Capabilities(c.into()),
            CommandResult::ExecAccepted(a) => W::ExecAccepted(wire::ExecAccepted {
                process_id: a.process_id.into_inner(),
                pid: a.pid,
                pgid: a.pgid,
                pidfd: a.pidfd,
            }),
            CommandResult::SessionOpened(s) => W::SessionOpened(wire::SessionOpened {
                session_id: s.session_id.into_inner(),
                process_id: s.process_id.into_inner(),
                pid: s.pid,
            }),
            CommandResult::ProcessList(l) => W::ProcessList(wire::ProcessList {
                processes: l.processes.into_iter().map(Into::into).collect(),
            }),
            CommandResult::SessionList(l) => W::SessionList(wire::SessionList {
                sessions: l.sessions.into_iter().map(Into::into).collect(),
            }),
            CommandResult::Metrics(m) => W::Metrics(wire::RuntimeMetrics {
                uptime_millis: m.uptime_millis,
                events_emitted: m.events_emitted,
                events_delivered: m.events_delivered,
                dropped_events: m.dropped_events,
                queue_depth: m.queue_depth,
                spool_bytes: m.spool_bytes,
                active_processes: m.active_processes,
                active_sessions: m.active_sessions,
            }),
            CommandResult::ShutdownAccepted(s) => W::ShutdownAccepted(wire::ShutdownAccepted {
                grace_millis: s.grace_millis,
            }),
            CommandResult::StreamAttached(s) => W::StreamAttached(wire::StreamAttached {
                channel_id: s.channel_id.into_inner(),
            }),
            CommandResult::ProcessAttached(p) => W::ProcessAttached(wire::ProcessAttached {
                process_id: p.process_id.into_inner(),
                pid: p.pid,
                pgid: p.pgid,
                channel_id: p.channel_id.into_inner(),
            }),
            CommandResult::ForwardOpened(f) => W::ForwardOpened(wire::ForwardOpened {
                channel_id: f.channel_id.into_inner(),
            }),
            CommandResult::SftpOpened(s) => W::SftpOpened(wire::SftpOpened {
                channel_id: s.channel_id.into_inner(),
            }),
            CommandResult::Accepted => W::Accepted(wire::Empty {}),
        }
    }
}
impl TryFrom<wire::command_result::Result> for CommandResult {
    type Error = WireError;
    fn try_from(r: wire::command_result::Result) -> Result<Self, WireError> {
        use wire::command_result::Result as W;
        Ok(match r {
            W::Health(h) => CommandResult::Health(h.try_into()?),
            W::Capabilities(c) => CommandResult::Capabilities(c.try_into()?),
            W::ExecAccepted(a) => CommandResult::ExecAccepted(ExecAccepted {
                process_id: ProcessId::new(a.process_id),
                pid: a.pid,
                pgid: a.pgid,
                pidfd: a.pidfd,
            }),
            W::SessionOpened(s) => CommandResult::SessionOpened(SessionOpened {
                session_id: SessionId::new(s.session_id),
                process_id: ProcessId::new(s.process_id),
                pid: s.pid,
            }),
            W::ProcessList(l) => CommandResult::ProcessList(ProcessList {
                processes: l
                    .processes
                    .into_iter()
                    .map(TryInto::try_into)
                    .collect::<Result<_, _>>()?,
            }),
            W::SessionList(l) => CommandResult::SessionList(SessionList {
                sessions: l.sessions.into_iter().map(Into::into).collect(),
            }),
            W::Metrics(m) => CommandResult::Metrics(RuntimeMetrics {
                uptime_millis: m.uptime_millis,
                events_emitted: m.events_emitted,
                events_delivered: m.events_delivered,
                dropped_events: m.dropped_events,
                queue_depth: m.queue_depth,
                spool_bytes: m.spool_bytes,
                active_processes: m.active_processes,
                active_sessions: m.active_sessions,
            }),
            W::ShutdownAccepted(s) => CommandResult::ShutdownAccepted(ShutdownAccepted {
                grace_millis: s.grace_millis,
            }),
            W::StreamAttached(s) => CommandResult::StreamAttached(StreamAttached {
                channel_id: ChannelId::new(s.channel_id),
            }),
            W::ProcessAttached(p) => CommandResult::ProcessAttached(ProcessAttached {
                process_id: ProcessId::new(p.process_id),
                pid: p.pid,
                pgid: p.pgid,
                channel_id: ChannelId::new(p.channel_id),
            }),
            W::ForwardOpened(f) => CommandResult::ForwardOpened(ForwardOpened {
                channel_id: ChannelId::new(f.channel_id),
            }),
            W::SftpOpened(s) => CommandResult::SftpOpened(SftpOpened {
                channel_id: ChannelId::new(s.channel_id),
            }),
            W::Accepted(_) => CommandResult::Accepted,
        })
    }
}

// ---------- error ----------

impl From<ControlError> for wire::ControlError {
    fn from(e: ControlError) -> Self {
        Self {
            code: enum_i32::<_, wire::ControlErrorCode>(e.code),
            message: e.message,
            detail_json: e.detail.map(|v| v.to_string()),
        }
    }
}
impl TryFrom<wire::ControlError> for ControlError {
    type Error = WireError;
    fn try_from(e: wire::ControlError) -> Result<Self, WireError> {
        Ok(ControlError {
            code: error_code(e.code)?,
            message: e.message,
            detail: e.detail_json.and_then(|s| serde_json::from_str(&s).ok()),
        })
    }
}

// ---------- top-level messages ----------

impl From<ControlRequest> for wire::ControlRequest {
    fn from(r: ControlRequest) -> Self {
        Self {
            schema_version: r.schema_version,
            request_id: r.request_id.into_inner(),
            command: Some(wire::Command {
                command: Some(r.command.into()),
            }),
        }
    }
}
impl TryFrom<wire::ControlRequest> for ControlRequest {
    type Error = WireError;
    fn try_from(r: wire::ControlRequest) -> Result<Self, WireError> {
        let command = r
            .command
            .and_then(|c| c.command)
            .ok_or(WireError::MissingOneof("ControlRequest.command"))?;
        Ok(Self {
            schema_version: r.schema_version,
            request_id: RequestId::new(r.request_id),
            command: command.try_into()?,
        })
    }
}

impl From<ResponseOutcome> for wire::ResponseOutcome {
    fn from(o: ResponseOutcome) -> Self {
        use wire::response_outcome::Outcome as W;
        let outcome = match o {
            ResponseOutcome::Ok { result } => W::Ok(wire::CommandResult {
                result: result.map(Into::into),
            }),
            ResponseOutcome::Error { error } => W::Error(error.into()),
        };
        Self {
            outcome: Some(outcome),
        }
    }
}
impl TryFrom<wire::ResponseOutcome> for ResponseOutcome {
    type Error = WireError;
    fn try_from(o: wire::ResponseOutcome) -> Result<Self, WireError> {
        use wire::response_outcome::Outcome as W;
        match o
            .outcome
            .ok_or(WireError::MissingOneof("ResponseOutcome.outcome"))?
        {
            W::Ok(cr) => Ok(ResponseOutcome::Ok {
                result: cr.result.map(TryInto::try_into).transpose()?,
            }),
            W::Error(e) => Ok(ResponseOutcome::Error {
                error: e.try_into()?,
            }),
        }
    }
}

impl From<ControlResponse> for wire::ControlResponse {
    fn from(r: ControlResponse) -> Self {
        Self {
            schema_version: r.schema_version,
            request_id: r.request_id.into_inner(),
            outcome: Some(r.outcome.into()),
        }
    }
}
impl TryFrom<wire::ControlResponse> for ControlResponse {
    type Error = WireError;
    fn try_from(r: wire::ControlResponse) -> Result<Self, WireError> {
        Ok(Self {
            schema_version: r.schema_version,
            request_id: RequestId::new(r.request_id),
            outcome: r
                .outcome
                .ok_or(WireError::MissingField("ControlResponse.outcome"))?
                .try_into()?,
        })
    }
}

// ---------- stream frames ----------
//
// `StreamPayload::Data` carries raw bytes verbatim; it must never travel through any telemetry
// redaction/coalescing path. These conversions are the only transformation applied (domain<->wire).

/// Convert a domain [`StreamFrame`] to its wire form.
#[must_use]
pub fn stream_frame_to_wire(frame: StreamFrame) -> wire::StreamFrame {
    use wire::stream_frame::Payload as W;
    let payload = match frame.payload {
        StreamPayload::Data { data } => W::Data(data.into_inner()),
        StreamPayload::WindowUpdate { credits } => {
            W::WindowUpdate(wire::StreamWindowUpdate { credits })
        }
        StreamPayload::End(end) => W::End(wire::StreamEnd {
            exit_code: end.exit_code,
            signal: end.signal,
            error: end.error,
        }),
    };
    wire::StreamFrame {
        channel_id: frame.channel_id.into_inner(),
        seq: frame.seq,
        payload: Some(payload),
    }
}

/// Convert a wire [`wire::StreamFrame`] back to the domain type.
///
/// # Errors
/// Returns [`WireError`] if the `payload` oneof is absent.
pub fn stream_frame_from_wire(frame: wire::StreamFrame) -> Result<StreamFrame, WireError> {
    use wire::stream_frame::Payload as W;
    let payload = match frame
        .payload
        .ok_or(WireError::MissingOneof("StreamFrame.payload"))?
    {
        W::Data(bytes) => StreamPayload::data(bytes),
        W::WindowUpdate(u) => StreamPayload::WindowUpdate { credits: u.credits },
        W::End(e) => StreamPayload::End(StreamEnd {
            exit_code: e.exit_code,
            signal: e.signal,
            error: e.error,
        }),
    };
    Ok(StreamFrame {
        channel_id: ChannelId::new(frame.channel_id),
        seq: frame.seq,
        payload,
    })
}

impl From<ClientMessage> for wire::ClientMessage {
    fn from(m: ClientMessage) -> Self {
        use wire::client_message::Message as W;
        let message = match m {
            ClientMessage::Request(r) => W::Request(r.into()),
            ClientMessage::Stream(f) => W::Stream(stream_frame_to_wire(f)),
        };
        Self {
            message: Some(message),
        }
    }
}
impl TryFrom<wire::ClientMessage> for ClientMessage {
    type Error = WireError;
    fn try_from(m: wire::ClientMessage) -> Result<Self, WireError> {
        use wire::client_message::Message as W;
        match m
            .message
            .ok_or(WireError::MissingOneof("ClientMessage.message"))?
        {
            W::Request(r) => Ok(ClientMessage::Request(r.try_into()?)),
            W::Stream(f) => Ok(ClientMessage::Stream(stream_frame_from_wire(f)?)),
        }
    }
}

impl From<ServerMessage> for wire::ServerMessage {
    fn from(m: ServerMessage) -> Self {
        use wire::server_message::Message as W;
        let message = match m {
            ServerMessage::Response(r) => W::Response(r.into()),
            ServerMessage::Event(e) => W::Event(e.into()),
            ServerMessage::Stream(f) => W::Stream(stream_frame_to_wire(f)),
        };
        Self {
            message: Some(message),
        }
    }
}
impl TryFrom<wire::ServerMessage> for ServerMessage {
    type Error = WireError;
    fn try_from(m: wire::ServerMessage) -> Result<Self, WireError> {
        use wire::server_message::Message as W;
        match m
            .message
            .ok_or(WireError::MissingOneof("ServerMessage.message"))?
        {
            W::Response(r) => Ok(ServerMessage::Response(r.try_into()?)),
            W::Event(e) => Ok(ServerMessage::Event(e.try_into()?)),
            W::Stream(f) => Ok(ServerMessage::Stream(stream_frame_from_wire(f)?)),
        }
    }
}

// ---------- byte-level entry points ----------

/// Encode a client message to protobuf bytes.
#[must_use]
pub fn encode_client(message: &ClientMessage) -> Vec<u8> {
    wire::ClientMessage::from(message.clone()).encode_to_vec()
}

/// Decode a client message from protobuf bytes.
///
/// # Errors
/// Returns [`WireError`] on a malformed frame.
pub fn decode_client(bytes: &[u8]) -> Result<ClientMessage, WireError> {
    wire::ClientMessage::decode(bytes)?.try_into()
}

/// Encode a server message to protobuf bytes.
#[must_use]
pub fn encode_server(message: &ServerMessage) -> Vec<u8> {
    wire::ServerMessage::from(message.clone()).encode_to_vec()
}

/// Decode a server message from protobuf bytes.
///
/// # Errors
/// Returns [`WireError`] on a malformed frame.
pub fn decode_server(bytes: &[u8]) -> Result<ServerMessage, WireError> {
    wire::ServerMessage::decode(bytes)?.try_into()
}

/// Encode a single telemetry event to protobuf bytes (used by the durable spool).
#[must_use]
pub fn encode_event(event: &EventEnvelope) -> Vec<u8> {
    wire::EventEnvelope::from(event.clone()).encode_to_vec()
}

/// Decode a single telemetry event from protobuf bytes.
///
/// # Errors
/// Returns [`WireError`] on a malformed record.
pub fn decode_event(bytes: &[u8]) -> Result<EventEnvelope, WireError> {
    wire::EventEnvelope::decode(bytes)?.try_into()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::SCHEMA_VERSION;

    #[test]
    fn client_exec_round_trips_through_protobuf() {
        let msg = ClientMessage::Request(ControlRequest::new(
            RequestId::new("req_1"),
            Command::Exec(ExecArgs {
                execution_id: Some(ExecutionId::new("run-7")),
                session_id: None,
                executable: "/bin/echo".to_owned(),
                args: vec!["hi".to_owned()],
                cwd: None,
                env: vec![EnvVar {
                    key: "A".into(),
                    value: "b".into(),
                }],
                stdin: true,
                attach: true,
                timeout_millis: Some(5000),
                background: false,
                capture: None,
                graceful_signal: Some(Signal::Term),
            }),
        ));
        let bytes = encode_client(&msg);
        let back = decode_client(&bytes).expect("decode");
        assert_eq!(back, msg);
    }

    #[test]
    fn server_event_io_chunk_round_trips_binary_safe() {
        let env = EventEnvelope {
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
                byte_count: 5,
                stream_offset: StreamOffset(0),
                content: Some(Base64Bytes::new(vec![0u8, 0xff, b'a', 0, 0xfe])),
                artifact: None,
                transform: None,
            }),
        };
        let msg = ServerMessage::Event(env);
        let bytes = encode_server(&msg);
        let back = decode_server(&bytes).expect("decode");
        assert_eq!(back, msg);
    }

    #[test]
    fn client_stream_data_round_trips_binary_safe() {
        // Raw bytes including NUL and invalid UTF-8 must survive verbatim (no redaction path).
        let raw = vec![0u8, 0xff, b'a', 0x00, 0xfe, b'\n'];
        let msg =
            ClientMessage::Stream(StreamFrame::data(ChannelId::new("chan_7"), 42, raw.clone()));
        let bytes = encode_client(&msg);
        let back = decode_client(&bytes).expect("decode");
        assert_eq!(back, msg);
        match back {
            ClientMessage::Stream(StreamFrame {
                payload: StreamPayload::Data { data },
                seq,
                ..
            }) => {
                assert_eq!(data.as_slice(), raw.as_slice());
                assert_eq!(seq, 42);
            }
            other => panic!("expected stream data, got {other:?}"),
        }
    }

    #[test]
    fn server_stream_end_round_trips() {
        let msg = ServerMessage::Stream(StreamFrame::end(
            ChannelId::new("chan_8"),
            1,
            StreamEnd {
                exit_code: Some(7),
                signal: None,
                error: None,
            },
        ));
        let bytes = encode_server(&msg);
        assert_eq!(decode_server(&bytes).expect("decode"), msg);
    }

    #[test]
    fn server_stream_window_update_round_trips() {
        let msg = ServerMessage::Stream(StreamFrame::window_update(
            ChannelId::new("chan_9"),
            2,
            4096,
        ));
        let bytes = encode_server(&msg);
        assert_eq!(decode_server(&bytes).expect("decode"), msg);
    }

    #[test]
    fn attach_session_command_round_trips() {
        let msg = ClientMessage::Request(ControlRequest::new(
            RequestId::new("req_a"),
            Command::AttachSession(AttachSessionArgs {
                session_id: SessionId::new("ses_1"),
                mode: AttachMode::Interactive,
            }),
        ));
        let bytes = encode_client(&msg);
        assert_eq!(decode_client(&bytes).expect("decode"), msg);
    }

    #[test]
    fn open_forward_command_and_result_round_trip() {
        let msg = ClientMessage::Request(ControlRequest::new(
            RequestId::new("req_f"),
            Command::OpenForward(OpenForwardArgs {
                host: "127.0.0.1".to_owned(),
                port: 8000,
                execution_id: Some(ExecutionId::new("run-1")),
            }),
        ));
        let bytes = encode_client(&msg);
        assert_eq!(decode_client(&bytes).expect("decode"), msg);

        let result = ServerMessage::Response(ControlResponse::ok_with(
            RequestId::new("req_f"),
            CommandResult::ForwardOpened(ForwardOpened {
                channel_id: ChannelId::new("chan_f"),
            }),
        ));
        let rbytes = encode_server(&result);
        assert_eq!(decode_server(&rbytes).expect("decode"), result);
    }

    #[test]
    fn open_sftp_command_and_result_round_trip() {
        let msg = ClientMessage::Request(ControlRequest::new(
            RequestId::new("req_s"),
            Command::OpenSftp(OpenSftpArgs {
                execution_id: None,
                cwd: Some("/work".to_owned()),
            }),
        ));
        let bytes = encode_client(&msg);
        assert_eq!(decode_client(&bytes).expect("decode"), msg);

        let result = ServerMessage::Response(ControlResponse::ok_with(
            RequestId::new("req_s"),
            CommandResult::SftpOpened(SftpOpened {
                channel_id: ChannelId::new("chan_s"),
            }),
        ));
        let rbytes = encode_server(&result);
        assert_eq!(decode_server(&rbytes).expect("decode"), result);
    }

    #[test]
    fn server_error_response_round_trips() {
        let msg = ServerMessage::Response(ControlResponse::error(
            RequestId::new("req_2"),
            ControlError::invalid_argument("bad cwd"),
        ));
        let bytes = encode_server(&msg);
        assert_eq!(decode_server(&bytes).expect("decode"), msg);
    }

    /// In-repo fuzz harness (plan §22 Phase 7): the control-protocol decoders are the untrusted
    /// attack surface. Hammer them with a seeded budget of random and bit-flipped-valid inputs; a
    /// panic (or abort) here fails the test. Deeper fuzzing lives in `fuzz/` (cargo-fuzz).
    #[test]
    fn decoders_never_panic_on_arbitrary_input() {
        let mut state: u64 = 0x9E37_79B9_7F4A_7C15;
        let mut next = || {
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            state
        };

        // a) Purely random buffers of varying length.
        for _ in 0..30_000 {
            let len = (next() % 600) as usize;
            let buf: Vec<u8> = (0..len).map(|_| (next() & 0xff) as u8).collect();
            let _ = decode_client(&buf);
            let _ = decode_server(&buf);
            let _ = decode_event(&buf);
        }

        // b) Bit-flipped near-valid messages (exercise structured-but-corrupt inputs).
        let valid = encode_client(&ClientMessage::Request(ControlRequest::new(
            RequestId::new("r"),
            Command::RuntimeHealth,
        )));
        for _ in 0..30_000 {
            let mut buf = valid.clone();
            if !buf.is_empty() {
                let idx = (next() as usize) % buf.len();
                buf[idx] ^= 1u8 << (next() % 8);
            }
            let _ = decode_client(&buf);
            let _ = decode_server(&buf);
            let _ = decode_event(&buf);
        }
    }
}
