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
    /// Run as this user (a login name or a decimal uid, looked up in the passwd database): its
    /// uid, groups, `HOME`, `USER`, `LOGNAME` and `SHELL`, umask `0002`, and a private `TMPDIR`
    /// and `XDG_RUNTIME_DIR`. Only one of the executor's people: the boot's owner map's, else a
    /// uid in Mend's reserved range (40001-49999) whose primary group is 40000; anyone else is
    /// refused (`invalid-argument`). Absent: as the daemon's child environment says (root).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub user: Option<String>,
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
    /// How the leader is wired: a pseudoterminal (default) or plain pipes.
    #[serde(default)]
    pub mode: SessionMode,
    /// Run the leader as this user, as [`ExecArgs::user`] does.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub user: Option<String>,
}

/// How a session's leader is wired to the daemon.
///
/// `Pty` is the interactive shape: a controlling terminal, keystroke input, PTY output, resize.
/// `Pipe` is the protocol shape for processes that speak a byte protocol over stdio (JSON-RPC /
/// NDJSON servers): no tty, stdout is the journaled and attachable output, stderr is recorded as
/// telemetry only (diagnostics, never mixed into the protocol stream), stdin is the input path, and
/// resize is rejected. Everything else — the durable journal, reattach from a sequence, tombstones,
/// signals, close — is identical between the two.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug, Default, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub enum SessionMode {
    /// A pseudoterminal session (interactive shells, TUIs).
    #[default]
    Pty,
    /// A plain-pipe session (protocol processes).
    Pipe,
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
    /// When set, replay the durable output journal from this sequence (clamped to the first
    /// retained record) before live frames; data-frame `seq` values are journal sequences.
    /// `None` = live tail only.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub from_sequence: Option<u64>,
}

/// Arguments to `readSessionOutput`: a one-shot batch read of a session's durable output journal.
#[derive(Clone, PartialEq, Eq, Debug, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct ReadSessionOutputArgs {
    /// Session whose journal to read.
    pub session_id: SessionId,
    /// First sequence to return (clamped to the first retained record).
    pub from_sequence: u64,
    /// Cap on returned payload bytes (defaulted/clamped by the daemon).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_bytes: Option<u64>,
}

/// Arguments to `openForward` (direct-tcpip): open a TCP connection from inside the container.
/// Transport for a forward: a TCP byte stream (the default), or UDP datagrams
/// where every `StreamPayload::Data` frame is EXACTLY one datagram — the frame
/// boundary is the datagram boundary, end to end.
#[derive(Clone, Copy, PartialEq, Eq, Debug, Default, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "lowercase")]
pub enum ForwardProtocol {
    /// Connected TCP stream; frames chunk arbitrarily.
    #[default]
    Tcp,
    /// Connected UDP socket; one Data frame = one datagram, both directions.
    Udp,
}

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
    /// Forward transport; omitted means TCP (the wire default predates UDP).
    #[serde(default)]
    pub protocol: ForwardProtocol,
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

/// Arguments to `dotfiles.apply`: apply a person's dotfiles into their home, as their user (Mend's
/// per-person layout: a person's first process in an executor someone else launched). At least
/// one of `repository` and `archiveDir`; the repository applies first, as at boot.
#[derive(Clone, PartialEq, Eq, Debug, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct DotfilesApplyArgs {
    /// The user to apply as: a login name or a decimal uid, one of the executor's people (as
    /// [`ExecArgs::user`]). Their passwd home is the target.
    pub user: String,
    /// A dotfiles repository to clone and apply.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub repository: Option<DotfilesRepository>,
    /// A directory of caller-staged archives (`manifest.json` and `*.tar.gz`, as
    /// `SEALANT_DOTFILES_ARCHIVE_DIR` holds them).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub archive_dir: Option<String>,
    /// The execution the bootstrap process belongs to.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub execution_id: Option<ExecutionId>,
}

/// A dotfiles repository, as the boot's `SEALANT_DOTFILES_*` names one.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct DotfilesRepository {
    /// Clone URL.
    pub url: String,
    /// Branch or ref; absent clones the remote's default branch.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reference: Option<String>,
    /// `auto` (default), `chezmoi`, `stow` or `copy`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub manager: Option<String>,
    /// `home` (default) or `config`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub target: Option<String>,
    /// Run the bootstrap command once the files are applied.
    #[serde(default)]
    pub bootstrap: bool,
    /// The bootstrap command, relative to the checkout (default `./install.sh`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub bootstrap_command: Option<String>,
    /// HTTP username for the clone (default `x-access-token`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub http_username: Option<String>,
    /// HTTP token for the clone. Never logged.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub http_token: Option<String>,
}

impl std::fmt::Debug for DotfilesRepository {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DotfilesRepository")
            .field("url", &self.url)
            .field("reference", &self.reference)
            .field("manager", &self.manager)
            .field("target", &self.target)
            .field("bootstrap", &self.bootstrap)
            .field("bootstrap_command", &self.bootstrap_command)
            .field("http_username", &self.http_username)
            .field(
                "http_token",
                &self.http_token.as_ref().map(|_| "<redacted>"),
            )
            .finish()
    }
}

/// Result of `dotfiles.apply`: answered once every file is applied, before any bootstrap ends.
#[derive(Clone, PartialEq, Eq, Debug, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct DotfilesApplied {
    /// The login name applied as.
    pub user: String,
    /// The home applied into.
    pub home: String,
    /// The bootstrap commands, started as one managed process running as the user (its
    /// `process.started` / `process.exited` and output say how `./install.sh` goes); absent when
    /// no tree had one to run.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub bootstrap: Option<ExecAccepted>,
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
    /// Point a bindable mount's path at a subdirectory of its root; an empty subpath unbinds.
    #[serde(rename = "bindMount")]
    BindMount {
        /// The declared mount path (e.g. `/workspace/repo`), a symlink once bound.
        mount_path: String,
        /// Path under the mount's root, relative, no `.`/`..`; empty to unbind.
        subpath: String,
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
    /// Send a signal to a session's process group (SIGINT/SIGTERM/...).
    #[serde(rename = "signalSession")]
    SignalSession {
        /// Target session.
        session_id: SessionId,
        /// Signal to deliver to the group.
        signal: Signal,
    },
    /// Read a batch of a session's durable output journal from a sequence.
    #[serde(rename = "readSessionOutput")]
    ReadSessionOutput(ReadSessionOutputArgs),
    /// Take a small-class capture of the workspace now and stage it for shipping (ADR-0015).
    #[serde(rename = "capture.now")]
    CaptureNow {
        /// Why the capture is taken.
        kind: CaptureKind,
    },
    /// A forced capture, then ship and register what `kind` waits for (the platform's suspend
    /// and terminate hooks call this). `suspend`: a small-class snap; returns once every capture
    /// ahead of a bulk capture still uploading is registered. `final`: the executor is ending —
    /// admission of new processes closes for good, every managed process and session is
    /// terminated (`SIGTERM`, `SIGKILL` after `grace_ms`) and awaited, then the small and the
    /// bulk class are snapped and everything ships; the report's `complete` says whether all of
    /// it happened. `deadline_ms` is honoured as given, never clamped to the shutdown grace;
    /// absent, a suspend flush is bounded by the shutdown grace and a final flush by nothing.
    #[serde(rename = "capture.flush")]
    CaptureFlush {
        /// What the flush waits for.
        #[serde(default)]
        kind: CaptureFlushKind,
        /// How long it may take, milliseconds.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        deadline_ms: Option<u64>,
        /// Final only: how long managed processes get after `SIGTERM` before `SIGKILL`,
        /// milliseconds; absent, the shutdown grace.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        grace_ms: Option<u64>,
    },
    /// Report the capture engine's state.
    #[serde(rename = "capture.status")]
    CaptureStatus,
    /// Report the worktree lease epoch this executor holds.
    #[serde(rename = "lease.epoch")]
    LeaseEpoch,
    /// Fetch the plan again and bring the workspace to it: a standby executor that booted on
    /// the project base takes the worktree the control plane assigned it (its id, its lease
    /// epoch, its chain head materialized as a delta over the disk) and continues the chain
    /// from there. Idempotent: a plan that names what the executor already has does nothing.
    #[serde(rename = "capture.replan")]
    CaptureReplan,
    /// Apply a person's dotfiles into their home, as their user; `./install.sh` runs after, as
    /// a managed process of that user.
    #[serde(rename = "dotfiles.apply")]
    DotfilesApply(Box<DotfilesApplyArgs>),
}

/// What a `capture.flush` waits for.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug, Default, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "lowercase")]
pub enum CaptureFlushKind {
    /// Every capture ahead of a bulk capture still uploading is registered (a change, a diff);
    /// the bulk capture keeps uploading. What a client that sends no kind gets.
    #[default]
    Suspend,
    /// The executor is ending: admission closes, managed processes are terminated and awaited,
    /// then both classes are snapped and everything ships, bulk included.
    Final,
}

/// Why a capture is taken (ADR-0015 manifest `kind`).
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "lowercase")]
pub enum CaptureKind {
    /// Cadence-driven.
    Auto,
    /// Agent turn boundary.
    Turn,
    /// Explicit checkpoint.
    Checkpoint,
    /// Suspend hook.
    Suspend,
    /// Session end.
    Final,
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
            Self::BindMount { .. } => "bindMount",
            Self::GetRuntimeMetrics => "getRuntimeMetrics",
            Self::AttachSession(_) => "attachSession",
            Self::DetachSession { .. } => "detachSession",
            Self::OpenForward(_) => "openForward",
            Self::CloseForward { .. } => "closeForward",
            Self::OpenSftp(_) => "openSftp",
            Self::CloseSftp { .. } => "closeSftp",
            Self::SignalSession { .. } => "signalSession",
            Self::ReadSessionOutput(_) => "readSessionOutput",
            Self::CaptureNow { .. } => "capture.now",
            Self::CaptureFlush { .. } => "capture.flush",
            Self::CaptureStatus => "capture.status",
            Self::LeaseEpoch => "lease.epoch",
            Self::CaptureReplan => "capture.replan",
            Self::DotfilesApply(_) => "dotfiles.apply",
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
    /// Pipe-mode sessions ([`SessionMode::Pipe`]) available.
    #[serde(default)]
    pub pipe_sessions: bool,
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
    /// What this daemon can do beyond the schema, by name: `restore.owner_map` (a capture
    /// restore takes an owner map), `exec.user` and `dotfiles.user` (an execution and the
    /// dotfiles applier run as a given user). Mend's per-person layout runs on a daemon that
    /// names all three. A daemon from before this list reports none.
    #[serde(default)]
    pub supports: Vec<String>,
    /// The capabilities a process run as a person holds in this daemon: `CAP_FOWNER`, or none.
    /// Empty from an older daemon.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub person_capabilities: Vec<String>,
    /// Why a process run as a person holds no `CAP_FOWNER` here (no-new-privileges is set, the
    /// daemon's bounding set lacks it, or the daemon is not root): pnpm cannot relink bins as a
    /// person then. `None` when it holds it, and from an older daemon.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub person_capabilities_withheld: Option<String>,
    /// Whether no-new-privileges is set on the daemon, and so on everything it starts: true in
    /// every executor (plan §18) but a per-person one (a boot under an owner map), where every
    /// person has `sudo` (Mend's ADR 0016). `None` is unknown: an older daemon that did not report
    /// it (which always set it), or a daemon that could not read it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub no_new_privileges: Option<bool>,
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

/// Lifecycle state of an interactive session.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug, Default, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub enum SessionState {
    /// The session leader is running.
    #[default]
    Running,
    /// The session leader has exited; the entry is retained for journal replay until closed.
    Exited,
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
    /// Lifecycle state.
    #[serde(default)]
    pub state: SessionState,
    /// Exit code, when exited normally.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub exit_code: Option<i32>,
    /// Terminating signal, when signaled.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub signal: Option<i32>,
    /// Wall-clock start time (unix micros).
    #[serde(default)]
    pub started_at_micros: i64,
    /// First output sequence still retained in the journal.
    #[serde(default)]
    pub first_journal_sequence: u64,
    /// Next output sequence the journal will assign (i.e. current end cursor).
    #[serde(default)]
    pub next_journal_sequence: u64,
    /// How the leader is wired (PTY unless opened in pipe mode).
    #[serde(default)]
    pub mode: SessionMode,
}

/// Result of `listSessions`.
#[derive(Clone, PartialEq, Eq, Debug, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct SessionList {
    /// Active sessions.
    pub sessions: Vec<SessionSummary>,
}

/// One journal record returned by `readSessionOutput`.
#[derive(Clone, PartialEq, Eq, Debug, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct SessionOutputChunk {
    /// Journal sequence of this chunk.
    pub sequence: u64,
    /// Redacted output bytes.
    pub data: crate::Base64Bytes,
}

/// Result of `readSessionOutput`: a batch of journal records plus cursors and lifecycle state.
#[derive(Clone, PartialEq, Eq, Debug, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct SessionOutput {
    /// The session read.
    pub session_id: SessionId,
    /// Records in `[fromSequence, nextSequence)` order.
    pub chunks: Vec<SessionOutputChunk>,
    /// Pass as the next `fromSequence` to continue reading.
    pub next_sequence: u64,
    /// First sequence still retained (requests below this were clamped up).
    pub first_available_sequence: u64,
    /// Lifecycle state at read time.
    pub state: SessionState,
    /// Exit code, when exited.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub exit_code: Option<i32>,
    /// Terminating signal, when signaled.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub signal: Option<i32>,
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

/// Result of `capture.now`: the capture staged for shipping (or the unchanged head).
#[derive(Clone, PartialEq, Eq, Debug, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct CaptureStaged {
    /// Chain position.
    pub n: u64,
    /// Capture id (sha256 of the manifest bytes).
    pub capture_id: String,
    /// Kind.
    pub kind: CaptureKind,
    /// Nothing changed since the previous capture; `n` and `capture_id` name that one.
    pub unchanged: bool,
}

/// What a capture snapped (ADR-0015): the small class is git, `.git` bookkeeping and the harness
/// home; the bulk class is dependencies and build outputs.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "lowercase")]
pub enum CaptureClass {
    /// Git pack, `.git` bookkeeping, harness home.
    Small,
    /// Dependencies and build outputs.
    Bulk,
}

/// Result of `capture.status` and `capture.flush`.
#[derive(Clone, PartialEq, Eq, Debug, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct CaptureStatusReport {
    /// Lease epoch this executor holds.
    pub epoch: u64,
    /// Worktree the chain belongs to.
    pub worktree_id: String,
    /// Highest registered chain position, when any.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub head_n: Option<u64>,
    /// Captures staged and not yet registered (including `pending_bulk`).
    pub pending: u64,
    /// Bytes staged on local disk awaiting upload.
    pub staged_bytes: u64,
    /// Objects uploaded this process lifetime.
    pub uploaded_objects: u64,
    /// Bytes uploaded this process lifetime.
    pub uploaded_bytes: u64,
    /// Captures registered this process lifetime.
    pub registered: u64,
    /// The registrar fenced this epoch; shipping stopped.
    pub fenced: bool,
    /// The harness process group is paused (`SIGSTOP`) pending a successful heartbeat.
    pub paused: bool,
    /// Wall-clock time of the last snap, Unix milliseconds.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_snap_unix_ms: Option<u64>,
    /// Classes with a capture the registrar refused for the session's byte quota. Nothing is
    /// dropped: the capture stays queued (counted in `pending`) with its staged bytes, the class
    /// keeps snapping (a newer capture replaces the held one), and the executor asks again after
    /// a backoff until the budget allows. Cleared when the class registers.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub refused: Vec<CaptureClass>,
    /// Of `pending`, the bulk captures whose objects are still uploading. A `suspend`
    /// `capture.flush` returns once every other capture is registered: a small capture is
    /// staged ahead of a bulk one still uploading, so these register after it, in the
    /// background. A `final` flush waits for them.
    #[serde(default)]
    pub pending_bulk: u64,
    /// Bytes staged on this disk that no upload has taken yet, over every pending capture (an
    /// object two captures share counts once): what would be lost if the disk went now.
    #[serde(default)]
    pub pending_bytes: u64,
    /// A final `capture.flush` ran to the end on this executor: admission closed, every managed
    /// process terminated and awaited, the small and the bulk class snapped after that, and
    /// everything registered (`pending` 0, not fenced). The only answer that means "saved";
    /// `pending == 0` alone does not. `false` from an older daemon.
    #[serde(default)]
    pub complete: bool,
    /// Why `complete` is false: `not-final`, `in-progress` (a final flush is running),
    /// `processes-remain`, `sweep-unavailable`, `snapshot-failed` (a final snap failed, or a
    /// class's last snap did: `snaps`), `unreadable`, `fenced`, `conflict`, `deadline`,
    /// `ship-failed`, `pending`, `sealing`, `changed` (the disk changed after the final flush,
    /// or its changes can no longer be observed — a watcher overflow, a class that polls: a
    /// final flush asked again snaps again and can answer complete), `unwatched`,
    /// `store-fidelity` (the store does not read every manifest feature this daemon writes: it
    /// would restore less than was captured, so no final flush over it completes) or `internal`.
    /// Absent when `complete`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub incomplete_reason: Option<String>,
    /// Paths the last snap of each class could not read, summed over both classes (a
    /// directory counts once). Never taken as deleted: an automatic snap carries a path's last
    /// captured content forward, a final snap fails instead. `None` from an older daemon.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub unreadable: Option<u64>,
    /// Of `unreadable`, the paths whose last captured content was carried forward.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub carried: Option<u64>,
    /// The first 20 unreadable paths, virtual (`tree/<path>`, `.git/<path>`, `harness/<path>`).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub unreadable_paths: Vec<String>,
    /// A capture the registrar refused to register (422 on `capture.register`) that the
    /// executor is working through: `missing-objects` or `unrestorable`. Never dropped: its
    /// staged objects are uploaded again, then it is rebuilt from disk in its place. `None`
    /// when nothing is refused.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub register_refused: Option<String>,
    /// That capture's chain position.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub register_refused_n: Option<u64>,
    /// The first 20 keys the registrar named as missing.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub register_missing: Vec<String>,
    /// Register refusals this daemon has seen since it started. `None` from an older daemon.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub register_refusals: Option<u64>,
    /// The refused capture waits to be rebuilt from disk; nothing behind it registers first.
    #[serde(default)]
    pub repairing: bool,
    /// A bulk build is in progress (reading, or paused mid-way for a small capture): its
    /// capture is not queued yet, so `pending` and `pending_bulk` do not count it, but
    /// `pending_bytes` counts what it has staged so far. A drain is not done while this is true.
    #[serde(default)]
    pub bulk_building: bool,
    /// Each captured class's snaps: how many failed, and the last one's error while it fails.
    /// `complete` is false while any class's last snap failed. Empty from an older daemon.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub snaps: Vec<CaptureClassSnaps>,
    /// The executor `plan.get` named (the launch), when it named one: with `epoch`, whose
    /// evidence this is (cross-repo decision 17). `None` from an older daemon, or when the plan
    /// named none.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub launch: Option<String>,
    /// Random per daemon process. `None` from an older daemon: the answer is ordered against no
    /// other by position.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub boot_id: Option<String>,
    /// The daemon processes that opened this disk's staging directory, this one included; `0`
    /// when it could not be persisted (then this boot is ordered against no other).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub boot_generation: Option<u64>,
    /// Strictly increasing within one boot over every answer and every final seal; the content
    /// is computed under it, so a higher one never describes an older state. Same
    /// `(epoch, launch, boot_id)`: order by this; same `(epoch, launch)` and different boots
    /// with generations above 0: by `(boot_generation, observation)`; anything else is
    /// incomparable, and fails closed.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub observation: Option<u64>,
    /// A capture step that has been running longer than it is expected to take at most (a
    /// snap, or a `git` a snap waits on), while it runs: an observation, not a failure — the
    /// step may still finish. The innermost one when several are. A `git` of a snap is killed
    /// at its own limit and the snap fails (`snaps`) and is taken again. `None` while nothing
    /// is past its bound, and from an older daemon.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub overdue: Option<CaptureOverdue>,
    /// This executor restores under an owner map (`SEALANT_CAPTURE_OWNER_MAP`, Mend's per-person
    /// layout): its worktree root was given to the change's owner and the group at boot, and
    /// every restore gives people their directories and the group its bits. `false` from a boot
    /// without a map, and from an older daemon: a control plane that expects the per-person
    /// layout refuses the executor then (a restore without the map leaves the worktree root's
    /// at the recorded modes, which no person can edit).
    #[serde(default)]
    pub owner_map: bool,
}

/// A capture step past its bound ([`CaptureStatusReport::overdue`]).
#[derive(Clone, PartialEq, Eq, Debug, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct CaptureOverdue {
    /// What is running, outermost first, `›`-separated: `small snap › git cat-file
    /// --batch-check`.
    pub step: String,
    /// When it started, Unix milliseconds (display only: order evidence by `observation`).
    pub started_unix_ms: u64,
    /// How long it has been running when this answer was computed, milliseconds.
    pub running_ms: u64,
    /// How long it is expected to take at most, milliseconds.
    pub bound_ms: u64,
}

/// One class's snaps (`capture.status`): a snap that fails for any reason, scheduled or forced,
/// is counted and its error kept until one succeeds.
#[derive(Clone, PartialEq, Eq, Debug, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct CaptureClassSnaps {
    /// The class.
    pub class: CaptureClass,
    /// Snaps of this class that failed since the daemon started.
    pub snaps_failed: u64,
    /// The last snap's error, while the last snap failed.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_snap_error: Option<String>,
    /// When the current run of failed snaps began (Unix ms), while the last snap failed.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub snap_failing_since_unix_ms: Option<u64>,
}

/// Result of `capture.replan`: the identity the executor now acts under and what the delta
/// materialize did.
#[derive(Clone, PartialEq, Eq, Debug, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct CaptureReplanned {
    /// Worktree the plan named.
    pub worktree_id: String,
    /// Lease epoch the plan named.
    pub epoch: u64,
    /// The chain head materialized, when the chain has one.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub head_n: Option<u64>,
    /// Its capture id.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub head_capture_id: Option<String>,
    /// Files written.
    pub files_written: u64,
    /// Bytes written.
    pub bytes_written: u64,
    /// Files already on disk as the plan has them.
    pub files_skipped: u64,
    /// Bytes those files hold.
    pub bytes_skipped: u64,
    /// Files and symlinks removed because the plan no longer names them.
    pub removed: u64,
    /// The plan named the worktree, epoch and head the executor already had; nothing was done.
    pub unchanged: bool,
}

/// Result of `lease.epoch`.
#[derive(Clone, PartialEq, Eq, Debug, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct LeaseEpochReport {
    /// Lease epoch this executor holds.
    pub epoch: u64,
    /// Worktree the lease is on.
    pub worktree_id: String,
    /// Whether the registrar has fenced this epoch.
    pub fenced: bool,
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
    /// A batch of session journal output.
    SessionOutput(SessionOutput),
    /// A capture was staged.
    CaptureStaged(CaptureStaged),
    /// Capture engine state.
    CaptureStatus(Box<CaptureStatusReport>),
    /// Lease epoch.
    LeaseEpoch(LeaseEpochReport),
    /// The plan was fetched again and the workspace brought to it.
    CaptureReplanned(CaptureReplanned),
    /// A person's dotfiles were applied.
    DotfilesApplied(DotfilesApplied),
    /// Generic acknowledgement with no data.
    Accepted,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn exec_command_round_trips_adjacently_tagged() {
        let cmd = Command::Exec(ExecArgs {
            user: None,
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
