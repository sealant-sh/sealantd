//! Control commands, their arguments, and their acknowledgement result types (plan §8.5/§8.6).

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::bytes::Base64Bytes;
use crate::event::{Feature, ProcessState, RuntimeState};
use crate::ids::{ChannelId, ExecutionId, ProcessId, RuntimeId, SessionId, WallClockMicros};

/// A POSIX signal that may be delivered to a managed process group.
///
/// A closed set is used (rather than an arbitrary integer) so invalid signal input is rejected at
/// the protocol boundary. The runtime maps each variant to the host signal number.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug, Serialize, Deserialize, JsonSchema)]
pub enum Signal {
    /// `SIGHUP`
    #[serde(rename = "SIGHUP")]
    Hup,
    /// `SIGINT`
    #[serde(rename = "SIGINT")]
    Int,
    /// `SIGQUIT`
    #[serde(rename = "SIGQUIT")]
    Quit,
    /// `SIGTERM`
    #[serde(rename = "SIGTERM")]
    Term,
    /// `SIGKILL`
    #[serde(rename = "SIGKILL")]
    Kill,
    /// `SIGUSR1`
    #[serde(rename = "SIGUSR1")]
    Usr1,
    /// `SIGUSR2`
    #[serde(rename = "SIGUSR2")]
    Usr2,
    /// `SIGSTOP`
    #[serde(rename = "SIGSTOP")]
    Stop,
    /// `SIGCONT`
    #[serde(rename = "SIGCONT")]
    Cont,
}

impl Signal {
    /// The canonical signal name (e.g. `SIGTERM`).
    #[must_use]
    pub fn name(self) -> &'static str {
        match self {
            Self::Hup => "SIGHUP",
            Self::Int => "SIGINT",
            Self::Quit => "SIGQUIT",
            Self::Term => "SIGTERM",
            Self::Kill => "SIGKILL",
            Self::Usr1 => "SIGUSR1",
            Self::Usr2 => "SIGUSR2",
            Self::Stop => "SIGSTOP",
            Self::Cont => "SIGCONT",
        }
    }
}

/// Per-stream capture mode (plan §12).
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub enum CaptureMode {
    /// Capture content and metadata.
    Full,
    /// Capture only metadata (byte counts, offsets), not content.
    MetadataOnly,
    /// Do not capture.
    Disabled,
}

/// Capture policy for a process's streams.
#[derive(Clone, Copy, PartialEq, Eq, Debug, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct CapturePolicy {
    /// Capture mode for stdout.
    pub stdout: CaptureMode,
    /// Capture mode for stderr.
    pub stderr: CaptureMode,
    /// Capture mode for stdin (off by default).
    pub stdin: CaptureMode,
}

impl Default for CapturePolicy {
    fn default() -> Self {
        Self {
            stdout: CaptureMode::Full,
            stderr: CaptureMode::Full,
            stdin: CaptureMode::Disabled,
        }
    }
}

/// A single environment variable in a child's explicit environment overlay.
#[derive(Clone, PartialEq, Eq, Debug, Serialize, Deserialize, JsonSchema)]
pub struct EnvVar {
    /// Variable name.
    pub key: String,
    /// Variable value.
    pub value: String,
}

/// Network observation mode reported in capabilities (plan §14).
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug, Default, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub enum NetworkMode {
    /// No network observation.
    #[default]
    Off,
    /// Best-effort DNS and connection metadata without elevated privilege.
    Metadata,
    /// Explicit local egress proxy with observable HTTP/CONNECT metadata.
    Proxy,
    /// Privileged backend (eBPF/netlink/etc.).
    Privileged,
    /// Policy-gated payload capture.
    Payload,
}

/// Arguments to `exec` (plan §10.1).
#[derive(Clone, PartialEq, Eq, Debug, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct ExecArgs {
    /// Execution to associate this process with.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub execution_id: Option<ExecutionId>,
    /// Session to associate this process with.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub session_id: Option<SessionId>,
    /// Executable to run. Shell execution must be explicit (e.g. `/bin/bash -lc ...`).
    pub executable: String,
    /// Argument vector (excluding argv0).
    #[serde(default)]
    pub args: Vec<String>,
    /// Working directory; defaults to the configured workspace root.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cwd: Option<String>,
    /// Validated environment overlay applied over the child base environment.
    #[serde(default)]
    pub env: Vec<EnvVar>,
    /// Open a stdin pipe so the client can `writeStdin`.
    #[serde(default)]
    pub stdin: bool,
    /// Bind this process's stdout/stderr to a fresh reliable [`ChannelId`] (exec-attach, §1.A).
    ///
    /// When set, the process's combined stdout+stderr is delivered over a backpressured
    /// `StreamFrame::Data` channel exactly like a session attach — raw bytes, never redacted or
    /// coalesced, terminated by `StreamFrame::End{exit_code}` on process exit. The result carries the
    /// minted channel (`ProcessAttached`) instead of the bare `ExecAccepted`. The lossy `IoChunk`
    /// telemetry tap stays on in parallel; the channel is the faithful path VSCode's non-PTY
    /// bootstrap reads from. Requires a connection-scoped writer (the request is routed accordingly).
    #[serde(default)]
    pub attach: bool,
    /// Timeout after which the process is terminated.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub timeout_millis: Option<u64>,
    /// Run in the background (do not imply foreground stream draining semantics).
    #[serde(default)]
    pub background: bool,
    /// Per-stream capture policy; defaults to full stdout/stderr, no stdin.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub capture: Option<CapturePolicy>,
    /// Signal to send first on graceful termination (defaults to `SIGTERM`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub graceful_signal: Option<Signal>,
}

/// Arguments to `execution.start`.
#[derive(Clone, PartialEq, Debug, Default, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct ExecutionStartArgs {
    /// Caller-supplied execution id (e.g. the monorepo run/attempt id). Minted if absent.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub execution_id: Option<ExecutionId>,
    /// Optional non-secret labels for correlation.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub labels: Option<serde_json::Value>,
}

/// Arguments to `writeStdin`. Exactly one of `processId` / `sessionId` must be set.
#[derive(Clone, PartialEq, Eq, Debug, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct WriteStdinArgs {
    /// Target process (non-PTY stdin).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub process_id: Option<ProcessId>,
    /// Target session (PTY input).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub session_id: Option<SessionId>,
    /// Bytes to write (base64).
    pub data: Base64Bytes,
}

/// Arguments to `openSession` (plan §11).
#[derive(Clone, PartialEq, Eq, Debug, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct OpenSessionArgs {
    /// Execution to associate the session with.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub execution_id: Option<ExecutionId>,
    /// Shell/command to run; defaults to the configured default shell.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub shell: Option<String>,
    /// Arguments to the shell/command.
    #[serde(default)]
    pub args: Vec<String>,
    /// Working directory.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cwd: Option<String>,
    /// Environment overlay.
    #[serde(default)]
    pub env: Vec<EnvVar>,
    /// Initial terminal columns.
    pub cols: u16,
    /// Initial terminal rows.
    pub rows: u16,
    /// `TERM` value to advertise to the child.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub term: Option<String>,
}

/// How a gateway wants to consume a session's reliable output stream.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug, Default, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub enum AttachMode {
    /// Interactive: the attaching connection drives input and consumes output.
    #[default]
    Interactive,
    /// Observe: a read-only mirror of the session's output.
    Observe,
}

/// Arguments to `attachSession`: bind a session's PTY output to a fresh reliable channel.
#[derive(Clone, PartialEq, Eq, Debug, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct AttachSessionArgs {
    /// Session whose output to stream.
    pub session_id: SessionId,
    /// Consumption mode.
    #[serde(default)]
    pub mode: AttachMode,
}

/// Arguments to `openForward` (direct-tcpip): open a TCP connection from inside the container.
#[derive(Clone, PartialEq, Eq, Debug, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct OpenForwardArgs {
    /// Destination host (resolved inside the container).
    pub host: String,
    /// Destination port.
    pub port: u16,
    /// Execution to correlate the forward with, when any.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub execution_id: Option<ExecutionId>,
}

/// Arguments to `openSftp`: spawn an in-container `sftp-server` bound to a reliable channel.
#[derive(Clone, PartialEq, Eq, Debug, Default, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct OpenSftpArgs {
    /// Execution to correlate the bridge with, when any.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub execution_id: Option<ExecutionId>,
    /// Working directory for the sftp-server process.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cwd: Option<String>,
}

/// The set of control commands. Adjacently tagged: `{ "cmd": ..., "args": ... }`.
#[derive(Clone, PartialEq, Debug, Serialize, Deserialize, JsonSchema)]
#[serde(tag = "cmd", content = "args", rename_all = "camelCase")]
pub enum Command {
    /// Report current health.
    #[serde(rename = "runtime.health")]
    RuntimeHealth,
    /// Report environment-dependent capabilities and limits.
    #[serde(rename = "runtime.getCapabilities")]
    RuntimeGetCapabilities,
    /// Begin graceful shutdown.
    #[serde(rename = "runtime.gracefulShutdown")]
    RuntimeGracefulShutdown {
        /// Override the configured grace period (milliseconds).
        #[serde(default, skip_serializing_if = "Option::is_none")]
        grace_millis: Option<u64>,
    },
    /// Force immediate shutdown.
    #[serde(rename = "runtime.kill")]
    RuntimeKill,
    /// Start (declare) an execution context.
    #[serde(rename = "execution.start")]
    ExecutionStart(ExecutionStartArgs),
    /// Stop an execution and terminate its processes/sessions.
    #[serde(rename = "execution.stop")]
    ExecutionStop {
        /// Execution to stop.
        execution_id: ExecutionId,
    },
    /// Run a non-interactive process.
    Exec(ExecArgs),
    /// Send a signal to a process group.
    #[serde(rename = "signalProcess")]
    SignalProcess {
        /// Target process.
        process_id: ProcessId,
        /// Signal to deliver.
        signal: Signal,
    },
    /// Forcefully kill a process group.
    #[serde(rename = "killProcess")]
    KillProcess {
        /// Target process.
        process_id: ProcessId,
    },
    /// List managed processes, optionally filtered by execution.
    #[serde(rename = "listProcesses")]
    ListProcesses {
        /// Optional execution filter.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        execution_id: Option<ExecutionId>,
    },
    /// Write bytes to a process's stdin or a session's PTY input.
    #[serde(rename = "writeStdin")]
    WriteStdin(WriteStdinArgs),
    /// Close a process's stdin.
    #[serde(rename = "closeStdin")]
    CloseStdin {
        /// Target process.
        process_id: ProcessId,
    },
    /// Open an interactive PTY session.
    #[serde(rename = "openSession")]
    OpenSession(OpenSessionArgs),
    /// Close a session and release its PTY.
    #[serde(rename = "closeSession")]
    CloseSession {
        /// Target session.
        session_id: SessionId,
    },
    /// Resize a session's PTY.
    #[serde(rename = "resizePty")]
    ResizePty {
        /// Target session.
        session_id: SessionId,
        /// New columns.
        cols: u16,
        /// New rows.
        rows: u16,
    },
    /// List active sessions.
    #[serde(rename = "listSessions")]
    ListSessions,
    /// Toggle a feature kill switch.
    #[serde(rename = "setFeatureState")]
    SetFeatureState {
        /// Feature to toggle.
        feature: Feature,
        /// Desired enabled state.
        enabled: bool,
    },
    /// Report runtime metrics.
    #[serde(rename = "getRuntimeMetrics")]
    GetRuntimeMetrics,
    /// Attach a fresh reliable output channel to a session's PTY.
    #[serde(rename = "attachSession")]
    AttachSession(AttachSessionArgs),
    /// Detach (and close) a previously attached session channel.
    #[serde(rename = "detachSession")]
    DetachSession {
        /// Channel to detach.
        channel_id: ChannelId,
    },
    /// Open a direct-tcpip forward (container → host:port) bound to a reliable channel.
    #[serde(rename = "openForward")]
    OpenForward(OpenForwardArgs),
    /// Close a previously opened forward.
    #[serde(rename = "closeForward")]
    CloseForward {
        /// Channel to close.
        channel_id: ChannelId,
    },
    /// Open an SFTP bridge (in-container `sftp-server` stdio) bound to a reliable channel.
    #[serde(rename = "openSftp")]
    OpenSftp(OpenSftpArgs),
    /// Close a previously opened SFTP bridge.
    #[serde(rename = "closeSftp")]
    CloseSftp {
        /// Channel to close.
        channel_id: ChannelId,
    },
}

impl Command {
    /// The wire `cmd` discriminator for this command.
    #[must_use]
    pub fn name(&self) -> &'static str {
        match self {
            Self::RuntimeHealth => "runtime.health",
            Self::RuntimeGetCapabilities => "runtime.getCapabilities",
            Self::RuntimeGracefulShutdown { .. } => "runtime.gracefulShutdown",
            Self::RuntimeKill => "runtime.kill",
            Self::ExecutionStart(_) => "execution.start",
            Self::ExecutionStop { .. } => "execution.stop",
            Self::Exec(_) => "exec",
            Self::SignalProcess { .. } => "signalProcess",
            Self::KillProcess { .. } => "killProcess",
            Self::ListProcesses { .. } => "listProcesses",
            Self::WriteStdin(_) => "writeStdin",
            Self::CloseStdin { .. } => "closeStdin",
            Self::OpenSession(_) => "openSession",
            Self::CloseSession { .. } => "closeSession",
            Self::ResizePty { .. } => "resizePty",
            Self::ListSessions => "listSessions",
            Self::SetFeatureState { .. } => "setFeatureState",
            Self::GetRuntimeMetrics => "getRuntimeMetrics",
            Self::AttachSession(_) => "attachSession",
            Self::DetachSession { .. } => "detachSession",
            Self::OpenForward(_) => "openForward",
            Self::CloseForward { .. } => "closeForward",
            Self::OpenSftp(_) => "openSftp",
            Self::CloseSftp { .. } => "closeSftp",
        }
    }
}

/// State of a single feature kill switch.
#[derive(Clone, Copy, PartialEq, Eq, Debug, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct FeatureState {
    /// The feature.
    pub feature: Feature,
    /// Whether it is currently enabled.
    pub enabled: bool,
}

/// Bounded resource limits reported in capabilities.
#[derive(Clone, Copy, PartialEq, Eq, Debug, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct Limits {
    /// Maximum control-frame body size.
    pub max_frame_bytes: u32,
    /// Maximum concurrent managed processes.
    pub max_processes: u32,
    /// Maximum concurrent sessions.
    pub max_sessions: u32,
    /// Event queue capacity.
    pub event_queue_capacity: u64,
    /// Durable spool disk limit.
    pub spool_limit_bytes: u64,
    /// Maximum inline event payload before offloading to an artifact.
    pub max_inline_payload_bytes: u64,
    /// I/O capture chunk size.
    pub io_chunk_bytes: u32,
}

/// Environment-dependent feature availability.
#[derive(Clone, Copy, PartialEq, Eq, Debug, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct FeatureMatrix {
    /// Non-PTY I/O capture available.
    pub io_capture: bool,
    /// PTY sessions available.
    pub pty: bool,
    /// Filesystem telemetry available.
    pub filesystem: bool,
    /// Network observation mode.
    pub network: NetworkMode,
    /// Whether any privileged collector is active.
    pub privileged: bool,
    /// pidfd available for race-free signaling.
    pub pidfd: bool,
    /// `PR_SET_CHILD_SUBREAPER` in effect.
    pub subreaper: bool,
}

/// Result of `runtime.getCapabilities`.
#[derive(Clone, PartialEq, Eq, Debug, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct Capabilities {
    /// Wire schema version.
    pub schema_version: u32,
    /// Daemon instance id.
    pub runtime_id: RuntimeId,
    /// Bound workspace id, when known.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub workspace_id: Option<String>,
    /// Operating system (e.g. `linux`).
    pub os: String,
    /// CPU architecture (e.g. `x86_64`).
    pub arch: String,
    /// Daemon build version.
    pub daemon_version: String,
    /// Feature availability.
    pub features: FeatureMatrix,
    /// Resource limits.
    pub limits: Limits,
}

/// Result of `runtime.health`.
#[derive(Clone, PartialEq, Debug, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct HealthReport {
    /// Current runtime state.
    pub state: RuntimeState,
    /// Daemon instance id.
    pub runtime_id: RuntimeId,
    /// Uptime in milliseconds.
    pub uptime_millis: u64,
    /// Active executions.
    pub active_executions: u32,
    /// Active sessions.
    pub active_sessions: u32,
    /// Active processes.
    pub active_processes: u32,
    /// Current event queue depth.
    pub queue_depth: u64,
    /// Event queue capacity.
    pub queue_capacity: u64,
    /// Bytes currently held in the durable spool.
    pub spool_bytes: u64,
    /// Spool disk limit.
    pub spool_limit_bytes: u64,
    /// Delivery retry count.
    pub retry_count: u64,
    /// Time of last successful delivery.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_delivery_at: Option<WallClockMicros>,
    /// Count of dropped events.
    pub dropped_events: u64,
    /// Count of redacted events.
    pub redacted_events: u64,
    /// Count of coalesced events.
    pub coalesced_events: u64,
    /// Count of truncated events.
    pub truncated_events: u64,
    /// Whether the delivery sink is connected.
    pub sink_connected: bool,
    /// Feature kill-switch states.
    #[serde(default)]
    pub feature_states: Vec<FeatureState>,
    /// Concrete degradation reasons, when degraded/unhealthy.
    #[serde(default)]
    pub degradation_reasons: Vec<String>,
}

/// Result of `exec`: the process was accepted; its exit arrives later as an event.
#[derive(Clone, PartialEq, Eq, Debug, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct ExecAccepted {
    /// Stable logical process id.
    pub process_id: ProcessId,
    /// OS pid.
    pub pid: i32,
    /// OS process group id.
    pub pgid: i32,
    /// Whether a pidfd was obtained.
    pub pidfd: bool,
}

/// Result of `openSession`.
#[derive(Clone, PartialEq, Eq, Debug, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct SessionOpened {
    /// Session id.
    pub session_id: SessionId,
    /// Logical process id of the session leader.
    pub process_id: ProcessId,
    /// OS pid of the session leader.
    pub pid: i32,
}

/// Summary of one managed process for `listProcesses`.
#[derive(Clone, PartialEq, Eq, Debug, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct ProcessSummary {
    /// Logical process id.
    pub process_id: ProcessId,
    /// OS pid.
    pub pid: i32,
    /// OS process group id.
    pub pgid: i32,
    /// Lifecycle state.
    pub state: ProcessState,
    /// Executable.
    pub executable: String,
    /// Associated execution, when any.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub execution_id: Option<ExecutionId>,
    /// Associated session, when any.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub session_id: Option<SessionId>,
}

/// Result of `listProcesses`.
#[derive(Clone, PartialEq, Eq, Debug, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct ProcessList {
    /// Managed processes.
    pub processes: Vec<ProcessSummary>,
}

/// Summary of one session for `listSessions`.
#[derive(Clone, PartialEq, Eq, Debug, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct SessionSummary {
    /// Session id.
    pub session_id: SessionId,
    /// Logical process id of the session leader.
    pub process_id: ProcessId,
    /// OS pid of the session leader.
    pub pid: i32,
    /// Current columns.
    pub cols: u16,
    /// Current rows.
    pub rows: u16,
    /// Associated execution, when any.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub execution_id: Option<ExecutionId>,
}

/// Result of `listSessions`.
#[derive(Clone, PartialEq, Eq, Debug, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct SessionList {
    /// Active sessions.
    pub sessions: Vec<SessionSummary>,
}

/// Result of `getRuntimeMetrics`.
#[derive(Clone, Copy, PartialEq, Eq, Debug, Default, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct RuntimeMetrics {
    /// Uptime in milliseconds.
    pub uptime_millis: u64,
    /// Total events produced.
    pub events_emitted: u64,
    /// Total events successfully delivered.
    pub events_delivered: u64,
    /// Total events dropped.
    pub dropped_events: u64,
    /// Current event queue depth.
    pub queue_depth: u64,
    /// Bytes currently in the spool.
    pub spool_bytes: u64,
    /// Active processes.
    pub active_processes: u32,
    /// Active sessions.
    pub active_sessions: u32,
}

/// Result of `runtime.gracefulShutdown`.
#[derive(Clone, Copy, PartialEq, Eq, Debug, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct ShutdownAccepted {
    /// Grace period that will be honored, in milliseconds.
    pub grace_millis: u64,
}

/// Result of `attachSession`: the channel the session's output now streams on.
#[derive(Clone, PartialEq, Eq, Debug, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct StreamAttached {
    /// The newly minted output channel.
    pub channel_id: ChannelId,
}

/// Result of an exec-attach (`exec` with `attach: true`): the process was accepted *and* its
/// stdout/stderr now stream over a fresh reliable channel (§1.A exec-attach). Symmetric to
/// [`ExecAccepted`] + [`StreamAttached`].
#[derive(Clone, PartialEq, Eq, Debug, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct ProcessAttached {
    /// Stable logical process id (as in [`ExecAccepted`]).
    pub process_id: ProcessId,
    /// OS pid.
    pub pid: i32,
    /// OS process group id.
    pub pgid: i32,
    /// The newly minted output channel carrying the process's stdout/stderr.
    pub channel_id: ChannelId,
}

/// Result of `openForward`: the channel the forwarded TCP bytes now flow on.
#[derive(Clone, PartialEq, Eq, Debug, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct ForwardOpened {
    /// The newly minted forward channel.
    pub channel_id: ChannelId,
}

/// Result of `openSftp`: the channel the sftp-server stdio is bridged over.
#[derive(Clone, PartialEq, Eq, Debug, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct SftpOpened {
    /// The newly minted sftp channel.
    pub channel_id: ChannelId,
}

/// The acknowledgement payload carried by a successful [`crate::ControlResponse`].
#[derive(Clone, PartialEq, Debug, Serialize, Deserialize, JsonSchema)]
#[serde(tag = "type", rename_all = "camelCase")]
pub enum CommandResult {
    /// Health report.
    Health(HealthReport),
    /// Capability report.
    Capabilities(Capabilities),
    /// `exec` accepted.
    ExecAccepted(ExecAccepted),
    /// Session opened.
    SessionOpened(SessionOpened),
    /// Process list.
    ProcessList(ProcessList),
    /// Session list.
    SessionList(SessionList),
    /// Runtime metrics.
    Metrics(RuntimeMetrics),
    /// Shutdown accepted.
    ShutdownAccepted(ShutdownAccepted),
    /// Session output attached to a channel.
    StreamAttached(StreamAttached),
    /// `exec` accepted with its stdout/stderr attached to a channel (exec-attach).
    ProcessAttached(ProcessAttached),
    /// A forward was opened on a channel.
    ForwardOpened(ForwardOpened),
    /// An SFTP bridge was opened on a channel.
    SftpOpened(SftpOpened),
    /// Generic acknowledgement with no data.
    Accepted,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn exec_command_round_trips_adjacently_tagged() {
        let cmd = Command::Exec(ExecArgs {
            execution_id: Some(ExecutionId::new("run-1")),
            session_id: None,
            executable: "/bin/echo".to_owned(),
            args: vec!["hi".to_owned()],
            cwd: None,
            env: vec![],
            stdin: false,
            attach: false,
            timeout_millis: None,
            background: false,
            capture: None,
            graceful_signal: None,
        });
        let value = serde_json::to_value(&cmd).expect("ser");
        assert_eq!(value["cmd"], "exec");
        assert_eq!(value["args"]["executable"], "/bin/echo");
        let back: Command = serde_json::from_value(value).expect("de");
        assert_eq!(back, cmd);
        assert_eq!(back.name(), "exec");
    }

    #[test]
    fn unit_command_has_no_args() {
        let value = serde_json::to_value(Command::RuntimeHealth).expect("ser");
        assert_eq!(value["cmd"], "runtime.health");
        assert!(value.get("args").is_none());
    }

    #[test]
    fn signal_uses_canonical_names() {
        assert_eq!(
            serde_json::to_string(&Signal::Term).expect("ser"),
            "\"SIGTERM\""
        );
        assert_eq!(Signal::Kill.name(), "SIGKILL");
    }

    #[test]
    fn command_result_is_internally_tagged() {
        let value = serde_json::to_value(CommandResult::Accepted).expect("ser");
        assert_eq!(value["type"], "accepted");
    }
}
