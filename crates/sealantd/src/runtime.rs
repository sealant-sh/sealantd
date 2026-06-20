//! The runtime composition root and control dispatch.

use std::collections::HashMap;
use std::sync::Arc;
use std::sync::Mutex;
use std::time::Duration;

use sealant_control::ControlService;
use sealant_process::{ProcessRegistry, ProcessRuntime};
use sealant_protocol::{
    Capabilities, Command, CommandResult, Confidence, ControlError, ControlRequest,
    ControlResponse, EventEnvelope, EventPayload, ExecutionId, Feature, FeatureMatrix,
    FeatureState, HealthReport, NetworkMode, ProcessList, ProcessState, RuntimeHeartbeat,
    RuntimeMetrics, RuntimeState, RuntimeStateChanged, SCHEMA_VERSION, SessionList,
    ShutdownAccepted, Signal,
};
use sealant_runtime_core::{Clock, IdGenerator, RuntimeConfig, RuntimeStatus};
use sealant_telemetry::{Correlation, EventBus};
use tokio::sync::broadcast;

use crate::shutdown::ShutdownSignal;

/// Daemon build version.
pub const DAEMON_VERSION: &str = env!("CARGO_PKG_VERSION");

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

/// The composed runtime. Shared via `Arc` and used as the control service.
#[derive(Debug)]
pub struct Runtime {
    config: Arc<RuntimeConfig>,
    clock: Arc<Clock>,
    #[allow(dead_code)]
    idgen: Arc<IdGenerator>,
    status: Arc<RuntimeStatus>,
    bus: Arc<EventBus>,
    processes: ProcessRuntime,
    shutdown: Arc<ShutdownSignal>,
    features: Mutex<HashMap<Feature, bool>>,
}

impl Runtime {
    /// Build the runtime from validated configuration.
    #[must_use]
    pub fn new(config: RuntimeConfig, shutdown: Arc<ShutdownSignal>) -> Arc<Self> {
        let config = Arc::new(config);
        let clock = Arc::new(Clock::new());
        let idgen = Arc::new(IdGenerator::new(&config.runtime_id));
        let status = Arc::new(RuntimeStatus::new());
        let bus = Arc::new(EventBus::new(
            config.runtime_id.clone(),
            clock.clone(),
            idgen.clone(),
            usize::try_from(config.limits.event_queue_capacity).unwrap_or(4096),
        ));
        let processes = ProcessRuntime {
            registry: Arc::new(ProcessRegistry::new()),
            bus: bus.clone(),
            idgen: idgen.clone(),
            status: status.clone(),
            clock: clock.clone(),
            config: config.clone(),
        };
        Arc::new(Self {
            config,
            clock,
            idgen,
            status,
            bus,
            processes,
            shutdown,
            features: Mutex::new(default_feature_states()),
        })
    }

    /// The configured Unix control-socket path.
    #[must_use]
    pub fn socket_path(&self) -> std::path::PathBuf {
        self.config.socket_path.clone()
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
        self.processes.terminate_all(signal, grace).await;
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
            queue_depth: 0,
            queue_capacity: self.config.limits.event_queue_capacity,
            spool_bytes: 0,
            spool_limit_bytes: self.config.limits.spool_limit_bytes,
            retry_count: 0,
            last_delivery_at: None,
            dropped_events: 0,
            redacted_events: 0,
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
                pty: false,
                filesystem: false,
                network: NetworkMode::Off,
                privileged: false,
                pidfd: false,
                subreaper: false,
            },
            limits: self.config.limits,
        }
    }

    fn metrics(&self) -> RuntimeMetrics {
        let (processes, sessions, _executions) = self.status.counts();
        RuntimeMetrics {
            uptime_millis: self.clock.uptime_millis(),
            events_emitted: self.bus.emitted(),
            events_delivered: self.bus.emitted(),
            dropped_events: 0,
            queue_depth: 0,
            spool_bytes: 0,
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
                (None, Some(_session_id)) => ControlResponse::error(
                    rid,
                    ControlError::feature_unavailable(
                        "PTY sessions are not yet available".to_owned(),
                    ),
                ),
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
            Command::ListSessions => ControlResponse::ok_with(
                rid,
                CommandResult::SessionList(SessionList { sessions: vec![] }),
            ),
            Command::OpenSession(_) | Command::CloseSession { .. } | Command::ResizePty { .. } => {
                ControlResponse::error(
                    rid,
                    ControlError::feature_unavailable(
                        "PTY sessions are not yet available".to_owned(),
                    ),
                )
            }
            Command::SetFeatureState { feature, enabled } => {
                self.set_feature(feature, enabled);
                ControlResponse::accepted(rid)
            }
        }
    }

    fn stop_execution(&self, execution_id: &ExecutionId) {
        for summary in self.processes.list(Some(execution_id)) {
            if !matches!(summary.state, ProcessState::Exited | ProcessState::Signaled) {
                let _ = self.processes.signal(&summary.process_id, Signal::Term);
            }
        }
    }
}

impl ControlService for Runtime {
    async fn handle(&self, request: ControlRequest) -> ControlResponse {
        self.dispatch(request).await
    }

    fn subscribe_events(&self) -> broadcast::Receiver<EventEnvelope> {
        self.bus.subscribe()
    }

    fn max_frame_bytes(&self) -> u32 {
        self.config.limits.max_frame_bytes
    }
}
