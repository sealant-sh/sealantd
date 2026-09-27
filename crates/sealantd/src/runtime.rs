//! The runtime composition root and control dispatch.

use std::collections::HashMap;
use std::sync::Arc;
use std::sync::Mutex;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

use sealant_control::{ConnHandle, ControlService};
use sealant_eventlog::{FsyncPolicy, Spool, SpoolConfig};
use sealant_fs::snapshot::SnapshotConfig;
use sealant_fs::{FilesystemConfig, FilesystemRuntime};
use sealant_network::{ForwardRuntime, NetworkConfig, NetworkRuntime};
use sealant_process::{ProcessRegistry, ProcessRuntime, SftpRuntime};
use sealant_protocol::{
    Capabilities, Command, CommandResult, Confidence, ControlError, ControlRequest,
    ControlResponse, EventEnvelope, EventPayload, ExecutionId, Feature, FeatureMatrix,
    FeatureState, ForwardOpened, HealthReport, NetworkMode, ProcessAttached, ProcessId,
    ProcessList, ProcessState, RuntimeHeartbeat, RuntimeMetrics, RuntimeState, RuntimeStateChanged,
    SCHEMA_VERSION, SftpOpened, ShutdownAccepted, Signal, StreamAttached,
};
use sealant_pty::{SessionRegistry, SessionRuntime};
use sealant_runtime_core::{Clock, IdGenerator, Redactor, RuntimeConfig, RuntimeStatus};
use sealant_telemetry::{Correlation, EventBus};
use tokio::sync::broadcast;

use crate::shutdown::ShutdownSignal;

/// Daemon build version.
pub const DAEMON_VERSION: &str = env!("CARGO_PKG_VERSION");

/// The environment entry a test marks its processes with, to narrow a sweep to them.
pub const SWEEP_MARK_ENV: &str = "SEALANTD_SWEEP_MARK";

/// A mark no process holds.
fn new_unit_mark() -> u64 {
    use std::sync::atomic::AtomicU64;
    static NEXT: AtomicU64 = AtomicU64::new(1);
    NEXT.fetch_add(1, Ordering::Relaxed)
}

/// The exit code of a daemon whose final capture flush did not complete (`EX_TEMPFAIL`): what
/// is on this disk is not all registered, and the staging directory is left as it is.
pub const EXIT_CAPTURE_INCOMPLETE: u8 = 75;

/// Collect the values captured I/O must redact (plan §18): the values of secret-looking env vars
/// plus every launcher-provided secret literal, whatever its name.
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
        .chain(config.redact_literals.iter().cloned())
        .collect()
}

/// Initial feature states, derived from configuration rather than hardcoded: a disabled
/// filesystem watcher must be visible as disabled in health, not reported as live.
fn default_feature_states(config: &RuntimeConfig) -> HashMap<Feature, bool> {
    HashMap::from([
        (Feature::FilesystemDiffing, config.watch_filesystem),
        (Feature::LiveFilesystemWatching, config.watch_filesystem),
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
    /// The live execution association stamped onto filesystem events; updated as executions and
    /// runs start/stop so a run's edits correlate to that run.
    fs_execution: sealant_fs::SharedExecution,
    network: Arc<NetworkRuntime>,
    forwards: Arc<ForwardRuntime>,
    sftp: Arc<SftpRuntime>,
    binds: Arc<crate::binds::BindRuntime>,
    /// The capture engine (ADR-0015), installed by boot once the harness is running.
    capture: std::sync::OnceLock<Arc<crate::capture::CaptureRuntime>>,
    extra_env: Arc<Mutex<Vec<(String, String)>>>,
    shutdown: Arc<ShutdownSignal>,
    /// A final capture flush began: the executor is ending, and no new process, exec, session
    /// or SFTP bridge is admitted, ever again.
    admission_closed: AtomicBool,
    /// One final capture flush at a time (the signal listener's, a control command's, and the
    /// boot supervisor's after the harness exits can overlap).
    final_lock: tokio::sync::Mutex<()>,
    /// Narrows the final flush's sweep of processes outside the managed groups to those whose
    /// environment holds `SEALANTD_SWEEP_MARK=<mark>`. `None` in a daemon: the sweep takes
    /// every process in its scope ([`crate::sweep`]). Unit tests share one process, and every
    /// runtime in it would take every other's processes, so a unit test's runtime starts with
    /// a mark nobody holds.
    sweep_mark: Mutex<Option<String>>,
    /// The last quiesce's outcome (`None`: none ran; `Some(None)`: every writer stopped). A
    /// final flush asked again after one that stopped every writer does not quiesce again:
    /// admission is closed, and nothing is left to stop.
    quiesced: Mutex<Option<Option<&'static str>>>,
    /// Quiesces run (test observability).
    quiesces: std::sync::atomic::AtomicU64,
    features: Mutex<HashMap<Feature, bool>>,
    pidfd_supported: bool,
    /// `PR_SET_CHILD_SUBREAPER` took effect: an orphan of anything sealantd started stays its
    /// descendant, which the final capture's sweep relies on outside a PID namespace of its own.
    subreaper: AtomicBool,
    /// The workspace's own Docker daemon, whose containers the final capture stops
    /// ([`crate::docker`]). Set by boot; none by default.
    workspace_docker: Mutex<Option<crate::docker::DockerEndpoint>>,
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
            redactor: redactor.clone(),
        };
        let sessions = SessionRuntime {
            registry: Arc::new(SessionRegistry::new()),
            bus: bus.clone(),
            idgen: idgen.clone(),
            status: status.clone(),
            clock: clock.clone(),
            config: config.clone(),
            extra_env: extra_env.clone(),
            redactor: redactor.clone(),
        };
        let fs_execution: sealant_fs::SharedExecution =
            Arc::new(Mutex::new(config.default_execution_id.clone()));
        let filesystem = Arc::new(FilesystemRuntime::new(
            bus.clone(),
            FilesystemConfig {
                root: config.workspace_root.clone(),
                snapshot: SnapshotConfig::default(),
                execution: fs_execution.clone(),
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
        let sftp = Arc::new(SftpRuntime::new());
        let binds = Arc::new(crate::binds::BindRuntime::new(
            config.bindable_mounts.clone(),
            std::path::PathBuf::from(crate::binds::BINDS_STATE_FILE),
        ));
        let features = Mutex::new(default_feature_states(&config));
        Arc::new(Self {
            config,
            clock,
            idgen,
            status,
            bus,
            processes,
            sessions,
            filesystem,
            fs_execution,
            network,
            forwards: Arc::new(ForwardRuntime::new()),
            sftp,
            binds,
            capture: std::sync::OnceLock::new(),
            extra_env,
            shutdown,
            admission_closed: AtomicBool::new(false),
            final_lock: tokio::sync::Mutex::new(()),
            quiesced: Mutex::new(None),
            quiesces: std::sync::atomic::AtomicU64::new(0),
            sweep_mark: Mutex::new(cfg!(test).then(|| format!("unit-test-{}", new_unit_mark()))),
            features,
            pidfd_supported,
            subreaper: AtomicBool::new(subreaper),
            workspace_docker: Mutex::new(None),
        })
    }

    /// The bindable mounts and their live bindings (ADR-0014).
    #[must_use]
    pub fn binds(&self) -> &crate::binds::BindRuntime {
        &self.binds
    }

    /// Install the capture engine (once). Returns `false` if one is already installed.
    pub fn install_capture(&self, capture: Arc<crate::capture::CaptureRuntime>) -> bool {
        self.capture.set(capture).is_ok()
    }

    /// The capture engine, when this workspace is a capture-store workspace.
    #[must_use]
    pub fn capture(&self) -> Option<Arc<crate::capture::CaptureRuntime>> {
        self.capture.get().cloned()
    }

    /// The final capture flush: this executor is ending. In this order, because a writer that
    /// runs past the last snap loses what it writes (an agent writing during the upload, or
    /// from its SIGTERM handler, after the snap that was meant to be the last):
    ///
    /// 1. admission closes for good — no new process, exec, session, SFTP bridge, execution,
    ///    bind or re-plan;
    /// 2. every managed process and session is terminated (a process the fence paused is
    ///    continued, then `SIGTERM`; `SIGKILL` after `grace_ms`, the shutdown grace when
    ///    absent; a hard shutdown kills at once) and awaited, and SFTP bridges are closed;
    /// 3. the small AND the bulk class are snapped — both must succeed;
    /// 4. everything ships until nothing is pending.
    ///
    /// The report's `complete` is true only when all of that happened; every failure is
    /// `complete: false` with its reason, logged at error, and the staging directory stays as
    /// it is. `deadline_ms` bounds the whole of it (the grace included); none: until complete,
    /// or until it never can be (a fence, a conflict, a failed snap). A flush that returned at
    /// its deadline does not end the daemon: admission stays closed, the writers stay stopped,
    /// the ship worker keeps uploading, and `capture.status` turns `complete` once it is done.
    /// Idempotent: serialized, and a final flush asked again after one that stopped every
    /// writer does not stop them again, and snaps only what changed (nothing, as a rule) before
    /// it ships what is left. `None` without a capture engine.
    pub async fn final_flush(
        &self,
        deadline_ms: Option<u64>,
        grace_ms: Option<u64>,
    ) -> Option<sealant_protocol::CaptureStatusReport> {
        let capture = self.capture()?;
        let _one = self.final_lock.lock().await;
        let start = Instant::now();
        let deadline = deadline_ms.map(Duration::from_millis);
        let grace = Duration::from_millis(grace_ms.unwrap_or_else(|| self.shutdown.grace_ms()));
        let grace = deadline.map_or(grace, |d| grace.min(d));
        let previous = *self.quiesced.lock().unwrap_or_else(|e| e.into_inner());
        let quiesced = match previous {
            // Every writer stopped the last time, and admission has been closed since.
            Some(None) => None,
            _ => {
                let quiesced = self.quiesce(grace).await;
                *self.quiesced.lock().unwrap_or_else(|e| e.into_inner()) = Some(quiesced);
                quiesced
            }
        };
        let left = deadline.map(|d| d.saturating_sub(start.elapsed()));
        let flushing = Arc::clone(&capture);
        let report =
            match tokio::task::spawn_blocking(move || flushing.flush_final(left, quiesced)).await {
                Ok(report) => report,
                Err(error) => {
                    tracing::error!(%error, "final capture flush task failed");
                    capture.record_final_incomplete("internal");
                    capture.status()
                }
            };
        if report.complete {
            tracing::info!(
                head_n = ?report.head_n,
                took_ms = start.elapsed().as_millis() as u64,
                "final capture complete: everything on this disk is registered"
            );
        } else {
            tracing::error!(
                reason = report.incomplete_reason.as_deref().unwrap_or("unknown"),
                pending = report.pending,
                pending_bulk = report.pending_bulk,
                pending_bytes = report.pending_bytes,
                fenced = report.fenced,
                "FINAL CAPTURE INCOMPLETE: work product is on this disk only; the staging \
                 directory is kept"
            );
        }
        Some(report)
    }

    /// Whether this is a capture-store workspace whose captures are not known complete: no
    /// final flush completed, or something was staged after it. The daemon then exits with
    /// [`EXIT_CAPTURE_INCOMPLETE`], never 0.
    #[must_use]
    pub fn capture_incomplete(&self) -> bool {
        self.capture().is_some_and(|c| !c.status().complete)
    }

    /// Close admission and stop every writer in the workspace: SFTP bridges closed, paused
    /// processes continued, then `SIGTERM` (or `SIGKILL` on a hard shutdown) to every managed
    /// process group and `SIGHUP` to every session, `SIGKILL` after `grace`, and awaited; then
    /// at the same time every process outside those groups ([`crate::sweep`]: the PID namespace
    /// when sealantd is its PID 1, else sealantd's descendants) the same way.
    /// Every container of the workspace's own Docker daemon is stopped at the same time. Returns
    /// why the capture that follows cannot be complete (`processes-remain`,
    /// `sweep-unavailable`), or `None`.
    async fn quiesce(&self, grace: Duration) -> Option<&'static str> {
        self.admission_closed.store(true, Ordering::SeqCst);
        self.quiesces.fetch_add(1, Ordering::Relaxed);
        let sftp = self.sftp.close_all();
        let (signal, grace) = if self.shutdown.is_hard() {
            (Signal::Kill, Duration::ZERO)
        } else {
            (Signal::Term, grace)
        };
        let running: Vec<_> = self
            .processes
            .list(None)
            .into_iter()
            .filter(|p| !matches!(p.state, ProcessState::Exited | ProcessState::Signaled))
            .collect();
        // A process group the capture fence stopped (`SIGSTOP`) would not act on `SIGTERM`
        // until the `SIGKILL`: continue it first.
        for process in &running {
            let _ = self.processes.signal(&process.process_id, Signal::Cont);
        }
        let sessions = self.sessions.registry.len();
        // Every other writer at the same time, under the same grace: a process that left its
        // group (`setsid`, a double fork, a daemon) is in none of the groups terminated here,
        // and would write past the last snap. The sweep also sees the managed processes (they
        // are sealantd's descendants); a second `SIGTERM` changes nothing for them.
        let mark = self
            .sweep_mark
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .clone();
        let admit = move |pid: i32| {
            mark.as_deref()
                .is_none_or(|m| crate::sweep::has_env_entry(pid, SWEEP_MARK_ENV, m))
        };
        let sweeper = crate::sweep::Sweeper::this_process();
        let docker = self
            .workspace_docker
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .clone();
        let started = Instant::now();
        // And every container of the workspace's own Docker daemon: a container can bind-mount
        // the worktree, and its processes are neither in sealantd's groups nor its descendants.
        let stop_containers = async {
            match &docker {
                None => Ok(None),
                Some(endpoint) => crate::docker::stop_all(endpoint, grace).await.map(Some),
            }
        };
        let ((), (), (swept, sweep_left), containers) = tokio::join!(
            self.sessions.terminate_all(grace),
            self.processes.terminate_all(signal, grace),
            sweeper.sweep(grace, self.shutdown.is_hard(), &admit),
            stop_containers,
        );
        let managed_left = self.processes.registry.running().len() + self.sessions.registry.len();
        let (containers_stopped, containers_left) = match &containers {
            Ok(None) => (0, 0),
            Ok(Some(stopped)) => (stopped.containers, stopped.running),
            Err(error) => {
                // Known to exist and not reached: nobody knows what still runs there.
                tracing::error!(
                    endpoint = %docker.as_ref().map(ToString::to_string).unwrap_or_default(),
                    %error,
                    "the workspace's Docker daemon could not be reached; its containers may \
                     still be writing"
                );
                (0, 1)
            }
        };
        let remaining = managed_left + sweep_left + containers_left;
        let sweep_unavailable = self.sweep_unavailable();
        tracing::info!(
            processes = running.len(),
            sessions,
            sftp,
            swept,
            sweep_scope = ?sweeper.scope,
            containers = containers_stopped,
            remaining,
            took_ms = started.elapsed().as_millis() as u64,
            "admission closed; every writer terminated for the final capture"
        );
        if remaining > 0 {
            tracing::error!(
                remaining,
                "processes or containers outlived SIGKILL; the final capture cannot be complete"
            );
            return Some("processes-remain");
        }
        if sweep_unavailable {
            tracing::error!(
                "this daemon is not a child subreaper: an orphan may have left its descendants \
                 unseen; the final capture cannot be complete"
            );
            return Some("sweep-unavailable");
        }
        None
    }

    /// Whether the final capture's sweep cannot guarantee it sees every writer: outside a PID
    /// namespace of its own it takes sealantd's descendants, and without
    /// `PR_SET_CHILD_SUBREAPER` an orphan is re-parented away from sealantd, out of sight.
    /// Every final flush on such a daemon is incomplete (`sweep-unavailable`).
    #[must_use]
    pub fn sweep_unavailable(&self) -> bool {
        crate::sweep::Scope::detect() == crate::sweep::Scope::Descendants
            && !self.subreaper.load(Ordering::Relaxed)
    }

    /// How many times a final flush stopped the writers (test observability).
    #[doc(hidden)]
    #[must_use]
    pub fn quiesce_count(&self) -> u64 {
        self.quiesces.load(Ordering::Relaxed)
    }

    /// Test hook: behave as if `PR_SET_CHILD_SUBREAPER` had (not) taken effect.
    #[doc(hidden)]
    pub fn set_subreaper_for_test(&self, subreaper: bool) {
        self.subreaper.store(subreaper, Ordering::Relaxed);
    }

    /// The workspace's own Docker daemon, whose containers every final capture stops
    /// ([`crate::docker::workspace_endpoint`]).
    pub fn set_workspace_docker(&self, endpoint: Option<crate::docker::DockerEndpoint>) {
        *self
            .workspace_docker
            .lock()
            .unwrap_or_else(|e| e.into_inner()) = endpoint;
    }

    /// Narrow the final flush's sweep to processes whose environment holds
    /// `SEALANTD_SWEEP_MARK=<mark>` ([`SWEEP_MARK_ENV`]); `None` sweeps every process in scope,
    /// as a daemon does. For tests that share a process with other runtimes.
    #[doc(hidden)]
    pub fn set_sweep_mark(&self, mark: Option<String>) {
        *self.sweep_mark.lock().unwrap_or_else(|e| e.into_inner()) = mark;
    }

    /// The error for new work once a final capture flush closed admission.
    fn admission_closed_error() -> ControlError {
        ControlError::runtime_shutting_down(
            "the executor is ending: a final capture flush closed admission".to_owned(),
        )
    }

    /// Whether a final capture flush closed admission (the executor is ending).
    #[must_use]
    pub fn admission_is_closed(&self) -> bool {
        self.admission_closed.load(Ordering::SeqCst)
    }

    /// The deadline a suspend `capture.flush` runs under: the caller's, as given; without one,
    /// the shutdown grace (as it always was).
    fn suspend_deadline(&self, deadline_ms: Option<u64>) -> Duration {
        Duration::from_millis(deadline_ms.unwrap_or_else(|| self.shutdown.grace_ms()))
    }

    /// Deliver a signal to a managed process's group (the capture fence pauses the harness).
    ///
    /// # Errors
    /// Returns [`ControlError`] if the process is unknown or signalling fails.
    pub fn signal_process(
        &self,
        process_id: &ProcessId,
        signal: Signal,
    ) -> Result<(), ControlError> {
        self.processes.signal(process_id, signal)
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
        if self.admission_is_closed() {
            return Err(Self::admission_closed_error());
        }
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

    /// Start filesystem observation if enabled (baseline snapshot + live watch). A start failure
    /// is loud: it downgrades the advertised feature states and health so a record consumer can
    /// see that file evidence is missing, instead of silently producing zero file events.
    pub fn start_filesystem(&self) {
        if !self.config.watch_filesystem {
            return;
        }
        if let Err(error) = self.filesystem.start() {
            tracing::error!(%error, root = %self.config.workspace_root.display(),
                "filesystem watch failed to start; file evidence will be missing");
            self.status.add_degradation("filesystem-watch-failed");
            self.set_feature(Feature::FilesystemDiffing, false);
            self.set_feature(Feature::LiveFilesystemWatching, false);
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

    /// Begin shutdown: announce, then terminate the managed process tree (already gone when a
    /// final capture flush ran: it terminates the tree before its snaps).
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
        // Drain the durable delivery queue before callers tear down connections, so the final
        // filesystem diff and exit events reach subscribers and the spool.
        self.bus.flush(Duration::from_secs(2)).await;
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
            workspace_id: self.config.workspace_id.clone(),
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
                subreaper: self.subreaper.load(Ordering::Relaxed),
                pipe_sessions: true,
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

    pub(crate) async fn dispatch(&self, request: ControlRequest) -> ControlResponse {
        let rid = request.request_id.clone();
        if matches!(
            self.status.state(),
            RuntimeState::ShuttingDown | RuntimeState::Stopped
        ) {
            // Still answer health/metrics during drain, but refuse new work.
            match &request.command {
                Command::RuntimeHealth
                | Command::GetRuntimeMetrics
                | Command::ListProcesses { .. }
                | Command::CaptureStatus
                | Command::LeaseEpoch => {}
                _ => {
                    return ControlResponse::error(
                        rid,
                        ControlError::runtime_shutting_down("runtime is shutting down".to_owned()),
                    );
                }
            }
        }

        // A final capture flush began: this executor admits no new writer (nor a re-plan or a
        // bind, which would change what the last capture is taken of).
        if self.admission_is_closed()
            && matches!(
                &request.command,
                Command::Exec(_)
                    | Command::OpenSession(_)
                    | Command::ExecutionStart(_)
                    | Command::BindMount { .. }
                    | Command::CaptureReplan
            )
        {
            return ControlResponse::error(rid, Self::admission_closed_error());
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
                // Writers stop, then the final capture, then the shutdown.
                self.final_flush(None, grace_millis).await;
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
                self.note_execution(args.execution_id.as_ref());
                ControlResponse::accepted(rid)
            }
            Command::ExecutionStop { execution_id } => {
                self.stop_execution(&execution_id);
                self.clear_execution(&execution_id);
                self.status.dec_executions();
                ControlResponse::accepted(rid)
            }
            Command::Exec(args) => {
                self.note_execution(args.execution_id.as_ref());
                match self.processes.exec(args, Some(rid.clone())) {
                    Ok(accepted) => {
                        ControlResponse::ok_with(rid, CommandResult::ExecAccepted(accepted))
                    }
                    Err(error) => ControlResponse::error(rid, error),
                }
            }
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
            Command::OpenSession(args) => {
                self.note_execution(args.execution_id.as_ref());
                match self.sessions.open(args) {
                    Ok(opened) => {
                        ControlResponse::ok_with(rid, CommandResult::SessionOpened(opened))
                    }
                    Err(error) => ControlResponse::error(rid, error),
                }
            }
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
            Command::SignalSession { session_id, signal } => {
                match self.sessions.signal(&session_id, signal) {
                    Ok(()) => ControlResponse::accepted(rid),
                    Err(error) => ControlResponse::error(rid, error),
                }
            }
            Command::ReadSessionOutput(args) => {
                match self.sessions.read_output(
                    &args.session_id,
                    args.from_sequence,
                    args.max_bytes,
                ) {
                    Ok(output) => {
                        ControlResponse::ok_with(rid, CommandResult::SessionOutput(output))
                    }
                    Err(error) => ControlResponse::error(rid, error),
                }
            }
            Command::SetFeatureState { feature, enabled } => {
                self.set_feature(feature, enabled);
                ControlResponse::accepted(rid)
            }
            Command::BindMount {
                mount_path,
                subpath,
            } => match self.binds.bind(&mount_path, &subpath) {
                Ok(()) => ControlResponse::accepted(rid),
                Err(error) => ControlResponse::error(rid, error),
            },
            Command::CaptureNow { kind } => match self.capture() {
                None => ControlResponse::error(rid, crate::capture::not_enabled()),
                Some(capture) => {
                    match tokio::task::spawn_blocking(move || capture.snap(kind)).await {
                        Ok(Ok(staged)) => {
                            ControlResponse::ok_with(rid, CommandResult::CaptureStaged(staged))
                        }
                        Ok(Err(error)) => ControlResponse::error(rid, error),
                        Err(error) => {
                            ControlResponse::error(rid, ControlError::internal(error.to_string()))
                        }
                    }
                }
            },
            Command::CaptureFlush {
                kind: sealant_protocol::CaptureFlushKind::Final,
                deadline_ms,
                grace_ms,
            } => match self.final_flush(deadline_ms, grace_ms).await {
                // Answered whatever happened: `complete` and `incomplete_reason` say what.
                Some(report) => ControlResponse::ok_with(rid, CommandResult::CaptureStatus(report)),
                None => ControlResponse::error(rid, crate::capture::not_enabled()),
            },
            Command::CaptureFlush {
                kind: sealant_protocol::CaptureFlushKind::Suspend,
                deadline_ms,
                grace_ms: _,
            } => match self.capture() {
                None => ControlResponse::error(rid, crate::capture::not_enabled()),
                Some(capture) => {
                    let deadline = self.suspend_deadline(deadline_ms);
                    match tokio::task::spawn_blocking(move || capture.flush_suspend(deadline)).await
                    {
                        Ok(Ok(report)) => {
                            ControlResponse::ok_with(rid, CommandResult::CaptureStatus(report))
                        }
                        Ok(Err(error)) => ControlResponse::error(rid, error),
                        Err(error) => {
                            ControlResponse::error(rid, ControlError::internal(error.to_string()))
                        }
                    }
                }
            },
            Command::CaptureStatus => match self.capture() {
                None => ControlResponse::error(rid, crate::capture::not_enabled()),
                Some(capture) => {
                    ControlResponse::ok_with(rid, CommandResult::CaptureStatus(capture.status()))
                }
            },
            Command::LeaseEpoch => match self.capture() {
                None => ControlResponse::error(rid, crate::capture::not_enabled()),
                Some(capture) => {
                    ControlResponse::ok_with(rid, CommandResult::LeaseEpoch(capture.lease_epoch()))
                }
            },
            Command::CaptureReplan => match self.capture() {
                None => ControlResponse::error(rid, crate::capture::not_enabled()),
                Some(capture) => {
                    match tokio::task::spawn_blocking(move || capture.replan()).await {
                        Ok(Ok(replanned)) => ControlResponse::ok_with(
                            rid,
                            CommandResult::CaptureReplanned(replanned),
                        ),
                        Ok(Err(error)) => ControlResponse::error(rid, error),
                        Err(error) => {
                            ControlResponse::error(rid, ControlError::internal(error.to_string()))
                        }
                    }
                }
            },
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

    /// Note that work is running under `execution_id`: filesystem events observed from now on are
    /// stamped with it (last-started wins; workspaces run one harness/run at a time in practice).
    fn note_execution(&self, execution_id: Option<&ExecutionId>) {
        if let Some(id) = execution_id {
            *self.fs_execution.lock().unwrap_or_else(|e| e.into_inner()) = Some(id.clone());
        }
    }

    /// The execution stopped; fall back to the configured default association.
    fn clear_execution(&self, execution_id: &ExecutionId) {
        let mut guard = self.fs_execution.lock().unwrap_or_else(|e| e.into_inner());
        if guard.as_ref() == Some(execution_id) {
            (*guard).clone_from(&self.config.default_execution_id);
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
        // An exec-attach spawns a writer, and so does an `sftp-server`.
        if self.admission_is_closed()
            && matches!(&request.command, Command::Exec(_) | Command::OpenSftp(_))
        {
            return ControlResponse::error(rid, Self::admission_closed_error());
        }

        match request.command {
            // §1.A exec-attach — run a non-PTY process and bind its stdout/stderr to a fresh
            // reliable channel (VSCode's non-PTY bootstrap reads its output losslessly here).
            Command::Exec(args) => {
                self.note_execution(args.execution_id.as_ref());
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

            // §1.A — attach a session's PTY output to a fresh reliable channel, optionally
            // replaying the durable journal from a sequence first (reattach + scrollback).
            Command::AttachSession(args) => {
                let channel_id = self.idgen.channel_id();
                match self
                    .sessions
                    .attach(
                        &args.session_id,
                        channel_id.clone(),
                        conn.out_tx.clone(),
                        args.from_sequence,
                    )
                    .await
                {
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
                        args.protocol,
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
