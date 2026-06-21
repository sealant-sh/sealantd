//! The runtime composition root and control dispatch.

use std::collections::HashMap;
use std::sync::Arc;
use std::sync::Mutex;
use std::time::Duration;

use sealant_control::{ConnHandle, ControlService};
use sealant_eventlog::{FsyncPolicy, Spool, SpoolConfig};
use sealant_fs::snapshot::SnapshotConfig;
use sealant_fs::{FilesystemConfig, FilesystemRuntime};
use sealant_network::{ForwardRuntime, NetworkConfig, NetworkRuntime};
use sealant_process::{ProcessRegistry, ProcessRuntime, SftpRuntime};
use sealant_protocol::{
    Capabilities, Command, CommandResult, Confidence, ControlError, ControlRequest,
    ControlResponse, EventEnvelope, EventPayload, ExecutionId, Feature, FeatureMatrix,
    FeatureState, ForwardOpened, HealthReport, NetworkMode, ProcessAttached, ProcessList,
    ProcessState, RuntimeHeartbeat, RuntimeMetrics, RuntimeState, RuntimeStateChanged,
    SCHEMA_VERSION, SftpOpened, ShutdownAccepted, Signal, StreamAttached,
};
use sealant_pty::{SessionRegistry, SessionRuntime};
use sealant_runtime_core::{Clock, IdGenerator, Redactor, RuntimeConfig, RuntimeStatus};
use sealant_telemetry::{Correlation, EventBus};
use tokio::sync::broadcast;

use crate::shutdown::ShutdownSignal;

/// Daemon build version.
pub const DAEMON_VERSION: &str = env!("CARGO_PKG_VERSION");

/// Collect the values of secret-looking env vars so captured I/O can redact them (plan §18).
fn secret_env_values(config: &RuntimeConfig) -> Vec<String> {
    const MARKERS: &[&str] = &[
        "TOKEN",
        "SECRET",
        "PASSWORD",
        "PASSWD",
        "APIKEY",
        "CREDENTIAL",
    ];
    config
        .child_env
        .iter()
        .filter(|var| {
            let key = var.key.to_ascii_uppercase();
            MARKERS.iter().any(|m| key.contains(m)) || key.ends_with("_KEY") || key == "KEY"
        })
        .map(|var| var.value.clone())
        .collect()
}

fn default_feature_states() -> HashMap<Feature, bool> {
    HashMap::from([
        (Feature::FilesystemDiffing, true),
        (Feature::LiveFilesystemWatching, true),
        (Feature::NetworkCollection, false),
        (Feature::PayloadCapture, false),
        (Feature::VerboseIoCapture, true),
        (Feature::ResourceSampling, false),
    ])
}

/// Build the event bus: durable (spool-backed) when a spool directory is configured, otherwise a
/// direct broadcast bus. Falls back to direct mode if the spool cannot be opened.
fn build_bus(
    config: &Arc<RuntimeConfig>,
    clock: &Arc<Clock>,
    idgen: &Arc<IdGenerator>,
) -> Arc<EventBus> {
    let capacity = usize::try_from(config.limits.event_queue_capacity).unwrap_or(4096);
    let direct = || {
        Arc::new(EventBus::new(
            config.runtime_id.clone(),
            clock.clone(),
            idgen.clone(),
            capacity,
        ))
    };
    let Some(dir) = &config.spool_dir else {
        return direct();
    };
    let spool_config = SpoolConfig {
        dir: dir.clone(),
        segment_bytes: (config.limits.spool_limit_bytes / 8).clamp(1 << 20, 64 << 20),
        disk_limit_bytes: config.limits.spool_limit_bytes,
        max_payload_bytes: config.limits.max_frame_bytes,
        fsync: FsyncPolicy::Never,
    };
    match Spool::open(spool_config) {
        Ok(spool) => Arc::new(EventBus::durable(
            config.runtime_id.clone(),
            clock.clone(),
            idgen.clone(),
            capacity,
            spool,
            Duration::from_millis(1000),
        )),
        Err(error) => {
            tracing::warn!(%error, dir = %dir.display(), "spool open failed; telemetry durability disabled");
            direct()
        }
    }
}

/// The composed runtime. Shared via `Arc` and used as the control service.
#[derive(Debug)]
pub struct Runtime {
    config: Arc<RuntimeConfig>,
    clock: Arc<Clock>,
    idgen: Arc<IdGenerator>,
    status: Arc<RuntimeStatus>,
    bus: Arc<EventBus>,
    processes: ProcessRuntime,
    sessions: SessionRuntime,
    filesystem: Arc<FilesystemRuntime>,
    network: Arc<NetworkRuntime>,
    forwards: Arc<ForwardRuntime>,
    sftp: Arc<SftpRuntime>,
    extra_env: Arc<Mutex<Vec<(String, String)>>>,
    shutdown: Arc<ShutdownSignal>,
    features: Mutex<HashMap<Feature, bool>>,
    pidfd_supported: bool,
    subreaper: bool,
}

impl Runtime {
    /// Build the runtime from validated configuration.
    #[must_use]
    pub fn new(config: RuntimeConfig, shutdown: Arc<ShutdownSignal>) -> Arc<Self> {
        let config = Arc::new(config);
        let clock = Arc::new(Clock::new());
        let idgen = Arc::new(IdGenerator::new(&config.runtime_id));
        let status = Arc::new(RuntimeStatus::new());
        let bus = build_bus(&config, &clock, &idgen);
        let extra_env = Arc::new(Mutex::new(Vec::new()));
        // Redact the values of secret-looking env vars from captured I/O (plan §18).
        let redactor = Arc::new(Redactor::new(secret_env_values(&config)));
        let processes = ProcessRuntime {
            registry: Arc::new(ProcessRegistry::new()),
            bus: bus.clone(),
            idgen: idgen.clone(),
            status: status.clone(),
            clock: clock.clone(),
            config: config.clone(),
            extra_env: extra_env.clone(),
            redactor,
        };
        let sessions = SessionRuntime {
            registry: Arc::new(SessionRegistry::new()),
            bus: bus.clone(),
            idgen: idgen.clone(),
            status: status.clone(),
            clock: clock.clone(),
            config: config.clone(),
            extra_env: extra_env.clone(),
        };
        let filesystem = Arc::new(FilesystemRuntime::new(
            bus.clone(),
            FilesystemConfig {
                root: config.workspace_root.clone(),
                snapshot: SnapshotConfig::default(),
                execution_id: config.default_execution_id.clone(),
            },
        ));
        let network = Arc::new(NetworkRuntime::new(
            bus.clone(),
            NetworkConfig {
                mode: config.network_mode,
                execution_id: config.default_execution_id.clone(),
            },
        ));
        // Become a child subreaper so double-forked orphans reparent here (and the reaper can
        // collect them). Harmless and idempotent; a no-op off Linux.
        let subreaper = sealant_process::platform::set_child_subreaper();
        // Defense in depth: children can never escalate via setuid binaries (plan §18).
        if sealant_process::platform::set_no_new_privs() {
            tracing::debug!("PR_SET_NO_NEW_PRIVS engaged");
        }
        let pidfd_supported = sealant_process::platform::pidfd_supported();
        Arc::new(Self {
            config,
            clock,
            idgen,
            status,
            bus,
            processes,
            sessions,
            filesystem,
            network,
            forwards: Arc::new(ForwardRuntime::new()),
            sftp: Arc::new(SftpRuntime::new()),
            extra_env,
            shutdown,
            features: Mutex::new(default_feature_states()),
            pidfd_supported,
            subreaper,
        })
    }

    /// The managed-process registry (used to start the adopted-orphan reaper).
    #[must_use]
    pub fn process_registry(&self) -> Arc<ProcessRegistry> {
        self.processes.registry.clone()
    }

    /// The interactive-session runtime (used by tests to drive PTY input/attachment directly).
    #[must_use]
    pub fn session_runtime(&self) -> &SessionRuntime {
        &self.sessions
    }

    /// Number of live direct-tcpip forwards across all connections. Used by tests to assert that
    /// connection teardown reaps the forward's runtime map entry (no leak per disconnect).
    #[must_use]
    pub fn forward_count(&self) -> usize {
        self.forwards.len()
    }

    /// Number of live SFTP bridges across all connections (test observability for teardown).
    #[must_use]
    pub fn sftp_count(&self) -> usize {
        self.sftp.len()
    }

    /// Spawn a managed process through the process runtime so its stdout/stderr flow onto the event
    /// bus and its lifecycle is registered/reaped like any control-driven `exec`. Used by the boot
    /// supervisor to run lifecycle steps and the harness with full telemetry.
    ///
    /// # Errors
    /// Returns a [`ControlError`] if arguments are invalid or the process cannot be spawned.
    pub fn spawn_managed(
        &self,
        args: sealant_protocol::ExecArgs,
    ) -> Result<sealant_protocol::ExecAccepted, ControlError> {
        self.processes.exec(args, None)
    }

    /// Subscribe to the telemetry event bus (used by the boot supervisor to await a managed
    /// process's `process.exited`).
    #[must_use]
    pub fn event_subscriber(&self) -> broadcast::Receiver<EventEnvelope> {
        self.bus.subscribe()
    }

    /// The default execution id, when configured.
    #[must_use]
    pub fn default_execution_id(&self) -> Option<ExecutionId> {
        self.config.default_execution_id.clone()
    }

    /// The configured Unix control-socket path.
    #[must_use]
    pub fn socket_path(&self) -> std::path::PathBuf {
        self.config.socket_path.clone()
    }

    /// Uids permitted to connect to the control socket (beyond the daemon's own uid and root).
    #[must_use]
    pub fn allowed_peer_uids(&self) -> Vec<u32> {
        self.config.allowed_peer_uids.clone()
    }

    /// The shared shutdown signal.
    #[must_use]
    pub fn shutdown(&self) -> &Arc<ShutdownSignal> {
        &self.shutdown
    }

    /// Current runtime state.
    #[must_use]
    pub fn state(&self) -> RuntimeState {
        self.status.state()
    }

    /// The heartbeat interval.
    #[must_use]
    pub fn heartbeat_interval(&self) -> Duration {
        Duration::from_millis(self.config.heartbeat_interval_ms)
    }

    fn transition(&self, state: RuntimeState, reason: Option<String>) {
        self.status.set_state(state);
        self.bus.publish(
            &Correlation::new(),
            sealant_protocol::CaptureMethod::Internal,
            Confidence::Observed,
            EventPayload::RuntimeStateChanged(RuntimeStateChanged { state, reason }),
        );
    }

    /// Start the durable telemetry delivery task (replays the spool, then delivers live events).
    /// No-op for a direct (non-durable) bus. Requires a Tokio runtime.
    pub fn start_telemetry(&self) {
        self.bus.start_delivery();
    }

    /// Start filesystem observation if enabled (baseline snapshot + live watch).
    pub fn start_filesystem(&self) {
        if !self.config.watch_filesystem {
            return;
        }
        if let Err(error) = self.filesystem.start() {
            tracing::warn!(%error, "filesystem watch failed to start; degraded");
            self.status.add_degradation("filesystem-watch-failed");
        }
    }

    /// Finalize filesystem observation (final snapshot + diff), if enabled.
    pub fn finalize_filesystem(&self) {
        if self.config.watch_filesystem {
            self.filesystem.finalize();
        }
    }

    /// Start network observation if requested, and inject proxy routing into the child environment.
    /// Returns the effective mode (degraded if privilege or binding is unavailable).
    pub async fn start_network(&self) -> NetworkMode {
        let mode = self.network.start().await;
        let proxy_env = self.network.proxy_env();
        if !proxy_env.is_empty() {
            *self.extra_env.lock().unwrap_or_else(|e| e.into_inner()) = proxy_env;
        }
        mode
    }

    /// Transition to healthy after startup validation. Emits `runtime.stateChanged`.
    pub fn mark_healthy(&self) {
        self.transition(RuntimeState::Healthy, None);
        tracing::info!(
            runtime_id = %self.config.runtime_id,
            config_hash = %self.config.config_hash(),
            "runtime healthy"
        );
    }

    /// Publish a heartbeat with the current state.
    pub fn publish_heartbeat(&self) {
        self.bus.publish(
            &Correlation::new(),
            sealant_protocol::CaptureMethod::Internal,
            Confidence::Observed,
            EventPayload::RuntimeHeartbeat(RuntimeHeartbeat {
                state: self.status.state(),
            }),
        );
    }

    /// Begin shutdown: announce, then terminate the managed process tree.
    pub async fn begin_shutdown(&self) {
        self.transition(
            RuntimeState::ShuttingDown,
            Some("shutdown requested".to_owned()),
        );
        let (signal, grace) = if self.shutdown.is_hard() {
            (Signal::Kill, Duration::ZERO)
        } else {
            (
                Signal::Term,
                Duration::from_millis(self.shutdown.grace_ms()),
            )
        };
        // Terminate interactive sessions and managed processes concurrently.
        tokio::join!(
            self.sessions.terminate_all(grace),
            self.processes.terminate_all(signal, grace),
        );
        // Capture the final filesystem state (final snapshot + baseline→final diff).
        self.finalize_filesystem();
        // Stop the egress proxy.
        self.network.shutdown();
    }

    /// Finish shutdown: mark stopped.
    pub fn finish_shutdown(&self) {
        self.transition(RuntimeState::Stopped, None);
    }

    fn feature_states(&self) -> Vec<FeatureState> {
        let guard = self.features.lock().unwrap_or_else(|e| e.into_inner());
        let mut states: Vec<FeatureState> = guard
            .iter()
            .map(|(&feature, &enabled)| FeatureState { feature, enabled })
            .collect();
        states.sort_by_key(|s| format!("{:?}", s.feature));
        states
    }

    fn set_feature(&self, feature: Feature, enabled: bool) {
        self.features
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .insert(feature, enabled);
    }

    /// Build a health report.
    #[must_use]
    pub fn health_report(&self) -> HealthReport {
        let (processes, sessions, executions) = self.status.counts();
        HealthReport {
            state: self.status.state(),
            runtime_id: self.config.runtime_id.clone(),
            uptime_millis: self.clock.uptime_millis(),
            active_executions: executions,
            active_sessions: sessions,
            active_processes: processes,
            queue_depth: self.bus.queue_depth(),
            queue_capacity: self.config.limits.event_queue_capacity,
            spool_bytes: self.bus.spool_bytes(),
            spool_limit_bytes: self.config.limits.spool_limit_bytes,
            retry_count: 0,
            last_delivery_at: None,
            dropped_events: self.bus.dropped(),
            redacted_events: u64::from(self.status.redacted()),
            coalesced_events: 0,
            truncated_events: 0,
            sink_connected: self.bus.subscriber_count() > 0,
            feature_states: self.feature_states(),
            degradation_reasons: self.status.degradation_reasons(),
        }
    }

    /// Build a capabilities report (honest about what is wired today).
    #[must_use]
    pub fn capabilities(&self) -> Capabilities {
        Capabilities {
            schema_version: SCHEMA_VERSION,
            runtime_id: self.config.runtime_id.clone(),
            sandbox_id: self.config.sandbox_id.clone(),
            os: std::env::consts::OS.to_owned(),
            arch: std::env::consts::ARCH.to_owned(),
            daemon_version: DAEMON_VERSION.to_owned(),
            features: FeatureMatrix {
                io_capture: true,
                pty: true,
                filesystem: self.config.watch_filesystem,
                network: self.network.capability_mode(),
                privileged: false,
                pidfd: self.pidfd_supported,
                subreaper: self.subreaper,
            },
            limits: self.config.limits,
        }
    }

    fn metrics(&self) -> RuntimeMetrics {
        let (processes, sessions, _executions) = self.status.counts();
        RuntimeMetrics {
            uptime_millis: self.clock.uptime_millis(),
            events_emitted: self.bus.emitted(),
            events_delivered: self.bus.emitted().saturating_sub(self.bus.dropped()),
            dropped_events: self.bus.dropped(),
            queue_depth: self.bus.queue_depth(),
            spool_bytes: self.bus.spool_bytes(),
            active_processes: processes,
            active_sessions: sessions,
        }
    }

    async fn dispatch(&self, request: ControlRequest) -> ControlResponse {
        let rid = request.request_id.clone();
        if matches!(
            self.status.state(),
            RuntimeState::ShuttingDown | RuntimeState::Stopped
        ) {
            // Still answer health/metrics during drain, but refuse new work.
            match &request.command {
                Command::RuntimeHealth
                | Command::GetRuntimeMetrics
                | Command::ListProcesses { .. } => {}
                _ => {
                    return ControlResponse::error(
                        rid,
                        ControlError::runtime_shutting_down("runtime is shutting down".to_owned()),
                    );
                }
            }
        }

        match request.command {
            Command::RuntimeHealth => {
                ControlResponse::ok_with(rid, CommandResult::Health(self.health_report()))
            }
            Command::RuntimeGetCapabilities => {
                ControlResponse::ok_with(rid, CommandResult::Capabilities(self.capabilities()))
            }
            Command::GetRuntimeMetrics => {
                ControlResponse::ok_with(rid, CommandResult::Metrics(self.metrics()))
            }
            Command::RuntimeGracefulShutdown { grace_millis } => {
                self.shutdown.request_graceful(grace_millis);
                ControlResponse::ok_with(
                    rid,
                    CommandResult::ShutdownAccepted(ShutdownAccepted {
                        grace_millis: self.shutdown.grace_ms(),
                    }),
                )
            }
            Command::RuntimeKill => {
                self.shutdown.request_hard();
                ControlResponse::accepted(rid)
            }
            Command::ExecutionStart(args) => {
                self.status.inc_executions();
                let _ = args;
                ControlResponse::accepted(rid)
            }
            Command::ExecutionStop { execution_id } => {
                self.stop_execution(&execution_id);
                self.status.dec_executions();
                ControlResponse::accepted(rid)
            }
            Command::Exec(args) => match self.processes.exec(args, Some(rid.clone())) {
                Ok(accepted) => {
                    ControlResponse::ok_with(rid, CommandResult::ExecAccepted(accepted))
                }
                Err(error) => ControlResponse::error(rid, error),
            },
            Command::SignalProcess { process_id, signal } => {
                match self.processes.signal(&process_id, signal) {
                    Ok(()) => ControlResponse::accepted(rid),
                    Err(error) => ControlResponse::error(rid, error),
                }
            }
            Command::KillProcess { process_id } => match self.processes.kill(&process_id) {
                Ok(()) => ControlResponse::accepted(rid),
                Err(error) => ControlResponse::error(rid, error),
            },
            Command::ListProcesses { execution_id } => ControlResponse::ok_with(
                rid,
                CommandResult::ProcessList(ProcessList {
                    processes: self.processes.list(execution_id.as_ref()),
                }),
            ),
            Command::WriteStdin(args) => match (args.process_id, args.session_id) {
                (Some(process_id), None) => {
                    match self
                        .processes
                        .write_stdin(&process_id, args.data.as_slice())
                        .await
                    {
                        Ok(()) => ControlResponse::accepted(rid),
                        Err(error) => ControlResponse::error(rid, error),
                    }
                }
                (None, Some(session_id)) => {
                    match self
                        .sessions
                        .write_input(&session_id, args.data.as_slice())
                        .await
                    {
                        Ok(()) => ControlResponse::accepted(rid),
                        Err(error) => ControlResponse::error(rid, error),
                    }
                }
                _ => ControlResponse::error(
                    rid,
                    ControlError::invalid_argument(
                        "exactly one of processId or sessionId is required".to_owned(),
                    ),
                ),
            },
            Command::CloseStdin { process_id } => {
                match self.processes.close_stdin(&process_id).await {
                    Ok(()) => ControlResponse::accepted(rid),
                    Err(error) => ControlResponse::error(rid, error),
                }
            }
            Command::ListSessions => {
                ControlResponse::ok_with(rid, CommandResult::SessionList(self.sessions.list()))
            }
            Command::OpenSession(args) => match self.sessions.open(args) {
                Ok(opened) => ControlResponse::ok_with(rid, CommandResult::SessionOpened(opened)),
                Err(error) => ControlResponse::error(rid, error),
            },
            Command::CloseSession { session_id } => match self.sessions.close(&session_id) {
                Ok(()) => ControlResponse::accepted(rid),
                Err(error) => ControlResponse::error(rid, error),
            },
            Command::ResizePty {
                session_id,
                cols,
                rows,
            } => match self.sessions.resize(&session_id, cols, rows) {
                Ok(()) => ControlResponse::accepted(rid),
                Err(error) => ControlResponse::error(rid, error),
            },
            Command::SetFeatureState { feature, enabled } => {
                self.set_feature(feature, enabled);
                ControlResponse::accepted(rid)
            }
            // Streaming commands are routed through dispatch_streaming (they need the ConnHandle).
            Command::AttachSession(_)
            | Command::DetachSession { .. }
            | Command::OpenForward(_)
            | Command::CloseForward { .. }
            | Command::OpenSftp(_)
            | Command::CloseSftp { .. } => ControlResponse::error(
                rid,
                ControlError::unknown_command(
                    "streaming command requires a connection-scoped writer".to_owned(),
                ),
            ),
        }
    }

    fn stop_execution(&self, execution_id: &ExecutionId) {
        for summary in self.processes.list(Some(execution_id)) {
            if !matches!(summary.state, ProcessState::Exited | ProcessState::Signaled) {
                let _ = self.processes.signal(&summary.process_id, Signal::Term);
            }
        }
    }

    /// Dispatch the connection-scoped streaming commands (gateway consolidation §1.A/§1.B/§1.C).
    ///
    /// Each open binds a fresh [`ChannelId`] to a byte source and pumps it over `conn.out_tx` with
    /// backpressure; inbound bytes arrive as `ClientMessage::Stream` and are routed by the control
    /// server to the sink registered here. None of these touch the telemetry `EventBus`.
    async fn dispatch_streaming(
        &self,
        request: ControlRequest,
        conn: &ConnHandle,
    ) -> ControlResponse {
        let rid = request.request_id.clone();
        if matches!(
            self.status.state(),
            RuntimeState::ShuttingDown | RuntimeState::Stopped
        ) {
            return ControlResponse::error(
                rid,
                ControlError::runtime_shutting_down("runtime is shutting down".to_owned()),
            );
        }

        match request.command {
            // §1.A exec-attach — run a non-PTY process and bind its stdout/stderr to a fresh
            // reliable channel (VSCode's non-PTY bootstrap reads its output losslessly here).
            Command::Exec(args) => {
                let channel_id = self.idgen.channel_id();
                match self.processes.exec_attached(
                    args,
                    Some(rid.clone()),
                    channel_id.clone(),
                    conn.out_tx.clone(),
                ) {
                    Ok(accepted) => {
                        // Eager closer: a connection drop kills the attached process group (so a
                        // disconnected gateway does not leave a bootstrap exec running). The capture
                        // tasks then hit EOF and exit; the waiter reaps the registry entry.
                        let processes = self.processes.clone();
                        let close_proc = accepted.process_id.clone();
                        conn.register_closer(
                            channel_id.clone(),
                            Box::new(move || {
                                let _ = processes.kill(&close_proc);
                            }),
                        )
                        .await;
                        ControlResponse::ok_with(
                            rid,
                            CommandResult::ProcessAttached(ProcessAttached {
                                process_id: accepted.process_id,
                                pid: accepted.pid,
                                pgid: accepted.pgid,
                                channel_id,
                            }),
                        )
                    }
                    Err(error) => ControlResponse::error(rid, error),
                }
            }

            // §1.A — attach a session's PTY output to a fresh reliable channel.
            Command::AttachSession(args) => {
                let channel_id = self.idgen.channel_id();
                match self.sessions.attach(
                    &args.session_id,
                    channel_id.clone(),
                    conn.out_tx.clone(),
                ) {
                    Ok(()) => {
                        // No inbound sink for attach: client keystrokes use writeStdin (the PTY is
                        // the input path). Register an eager closer so a connection drop detaches the
                        // session (the capture loop stops fanning out) — the same eager teardown path
                        // as forwards/sftp.
                        let sessions = self.sessions.clone();
                        let detach_channel = channel_id.clone();
                        conn.register_closer(
                            channel_id.clone(),
                            Box::new(move || sessions.detach(&detach_channel)),
                        )
                        .await;
                        ControlResponse::ok_with(
                            rid,
                            CommandResult::StreamAttached(StreamAttached { channel_id }),
                        )
                    }
                    Err(error) => ControlResponse::error(rid, error),
                }
            }
            Command::DetachSession { channel_id } => {
                self.sessions.detach(&channel_id);
                conn.deregister_channel(&channel_id).await;
                ControlResponse::accepted(rid)
            }

            // §1.B — open a direct-tcpip forward to host:port.
            //
            // Forwarding is a gateway *transport* primitive (the SSH direct-tcpip substrate), not
            // telemetry capture. It is deliberately NOT gated on `Feature::NetworkCollection` — that
            // kill switch governs whether the daemon *observes/records* network traffic, a separate
            // concern from whether a tunnel may be opened at all. Like session-attach and SFTP, the
            // forward is a connection-scoped channel with its own eager teardown; it carries bytes,
            // it does not capture them.
            Command::OpenForward(args) => {
                let channel_id = self.idgen.channel_id();
                match self
                    .forwards
                    .open(
                        channel_id.clone(),
                        &args.host,
                        args.port,
                        args.execution_id,
                        conn.out_tx.clone(),
                    )
                    .await
                {
                    Ok(inbound) => {
                        conn.register_channel(channel_id.clone(), inbound).await;
                        // Eager closer: on connection drop, abort BOTH pumps and reap the
                        // ForwardRuntime map entry. Without this an idle upstream's socket→gateway
                        // pump blocks on read() forever (it never calls out_tx.send, so never sees
                        // the closed queue), leaking the task, the socket FD, and the map entry.
                        let forwards = self.forwards.clone();
                        let close_channel = channel_id.clone();
                        conn.register_closer(
                            channel_id.clone(),
                            Box::new(move || forwards.close(&close_channel)),
                        )
                        .await;
                        ControlResponse::ok_with(
                            rid,
                            CommandResult::ForwardOpened(ForwardOpened { channel_id }),
                        )
                    }
                    Err(error) => ControlResponse::error(rid, error),
                }
            }
            Command::CloseForward { channel_id } => {
                self.forwards.close(&channel_id);
                conn.deregister_channel(&channel_id).await;
                ControlResponse::accepted(rid)
            }

            // §1.C — open an SFTP bridge (in-container sftp-server stdio).
            Command::OpenSftp(args) => {
                let cwd = args
                    .cwd
                    .map_or_else(|| self.config.workspace_root.clone(), Into::into);
                let channel_id = self.idgen.channel_id();
                match self
                    .sftp
                    .open(channel_id.clone(), &cwd, conn.out_tx.clone())
                {
                    Ok(inbound) => {
                        conn.register_channel(channel_id.clone(), inbound).await;
                        // Eager closer: on connection drop, abort all bridge tasks and reap the
                        // SftpRuntime map entry (kill_on_drop reaps the child). Without this an
                        // sftp-server that produces no output leaves its stdout→gateway pump blocked
                        // on read(), leaking the task and the map entry — same hazard as forwards.
                        let sftp = self.sftp.clone();
                        let close_channel = channel_id.clone();
                        conn.register_closer(
                            channel_id.clone(),
                            Box::new(move || sftp.close(&close_channel)),
                        )
                        .await;
                        ControlResponse::ok_with(
                            rid,
                            CommandResult::SftpOpened(SftpOpened { channel_id }),
                        )
                    }
                    Err(error) => ControlResponse::error(rid, error),
                }
            }
            Command::CloseSftp { channel_id } => {
                self.sftp.close(&channel_id);
                conn.deregister_channel(&channel_id).await;
                ControlResponse::accepted(rid)
            }

            // Unreachable: handle_on_connection only routes the six streaming commands here.
            other => ControlResponse::error(
                rid,
                ControlError::unknown_command(format!(
                    "{} is not a streaming command",
                    other.name()
                )),
            ),
        }
    }
}

impl ControlService for Runtime {
    async fn handle_on_connection(
        &self,
        request: ControlRequest,
        conn: &ConnHandle,
    ) -> ControlResponse {
        // Streaming commands need this connection's backpressured writer + channel registry; the
        // rest go through the connection-agnostic dispatch unchanged. An `exec` with `attach: true`
        // is exec-attach (§1.A): it also needs the connection's writer, so route it here too.
        match &request.command {
            Command::AttachSession(_)
            | Command::DetachSession { .. }
            | Command::OpenForward(_)
            | Command::CloseForward { .. }
            | Command::OpenSftp(_)
            | Command::CloseSftp { .. } => self.dispatch_streaming(request, conn).await,
            Command::Exec(args) if args.attach => self.dispatch_streaming(request, conn).await,
            _ => self.dispatch(request).await,
        }
    }

    fn subscribe_events(&self) -> broadcast::Receiver<EventEnvelope> {
        self.bus.subscribe()
    }

    fn max_frame_bytes(&self) -> u32 {
        self.config.limits.max_frame_bytes
    }
}
