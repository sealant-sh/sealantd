//! The process runtime: spawn, capture, wait, signal, and shutdown.

use std::process::Stdio;
use std::sync::Arc;
use std::time::{Duration, Instant};

use sealant_protocol::{
    CaptureMethod, CaptureMode, ChannelId, Confidence, ControlError, ControlErrorCode, Encoding,
    EventPayload, ExecAccepted, ExecArgs, ExitReason, IoChunk, ProcessExited, ProcessId,
    ProcessStarted, ProcessState, ProcessSummary, RequestId, ServerMessage, Signal, StreamEnd,
    StreamFrame, StreamKind, StreamOffset, TransformMeta,
};
use sealant_runtime_core::{Clock, IdGenerator, Redactor, RuntimeConfig, RuntimeStatus};
use sealant_telemetry::{Correlation, EventBus};
use std::os::unix::process::ExitStatusExt;
use std::sync::atomic::{AtomicU64, Ordering};
use tokio::io::{AsyncRead, AsyncReadExt};
use tokio::sync::mpsc;

use crate::registry::{ProcessEntry, ProcessRegistry};
use crate::signals;

/// A reliable exec-attach output sink: a non-PTY process's stdout/stderr is delivered over one
/// gateway connection's backpressured outbound queue as raw [`StreamFrame::Data`], distinct from the
/// lossy `IoChunk` telemetry tap (§1.A exec-attach). The stdout and stderr capture tasks share a
/// single sink (and thus a single per-channel `seq`) so the gateway sees one ordered byte stream —
/// exactly mirroring the PTY session-attach machinery.
///
/// Awaiting `out_tx.send(...)` is the backpressure: a capture task only reads its next pipe chunk
/// once the gateway accepts the previous one, so a slow gateway throttles the pipe drain and the
/// kernel pipe buffer backpressures the process. The bytes are forwarded raw (never redacted or
/// coalesced); the parallel `IoChunk` tap keeps applying redaction independently.
#[derive(Debug, Clone)]
pub struct AttachSink {
    /// The channel the process output streams on.
    pub channel_id: ChannelId,
    /// The connection's backpressured outbound queue.
    pub out_tx: mpsc::Sender<ServerMessage>,
    /// Per-channel monotonic data-frame counter, shared across stdout+stderr (gap detection only).
    seq: Arc<AtomicU64>,
}

impl AttachSink {
    /// Create a fresh attach sink for `channel_id` bound to the connection's `out_tx`.
    #[must_use]
    pub fn new(channel_id: ChannelId, out_tx: mpsc::Sender<ServerMessage>) -> Self {
        Self {
            channel_id,
            out_tx,
            seq: Arc::new(AtomicU64::new(0)),
        }
    }

    /// Forward one raw chunk over the channel, awaiting the send (backpressure). Returns `Err(())`
    /// once the gateway queue is closed so the caller stops trying.
    async fn forward(&self, data: &[u8]) -> Result<(), ()> {
        let seq = self.seq.fetch_add(1, Ordering::Relaxed);
        let frame = StreamFrame::data(self.channel_id.clone(), seq, data);
        self.out_tx
            .send(ServerMessage::Stream(frame))
            .await
            .map_err(|_| ())
    }
}

/// Composition of the dependencies needed to run processes.
#[derive(Debug, Clone)]
pub struct ProcessRuntime {
    /// The managed-process registry.
    pub registry: Arc<ProcessRegistry>,
    /// The telemetry bus.
    pub bus: Arc<EventBus>,
    /// The id generator.
    pub idgen: Arc<IdGenerator>,
    /// Shared runtime status (live counters).
    pub status: Arc<RuntimeStatus>,
    /// The clock.
    pub clock: Arc<Clock>,
    /// Runtime configuration.
    pub config: Arc<RuntimeConfig>,
    /// Extra environment injected into every child last (e.g. egress-proxy routing); the workspace
    /// controls these so a request cannot override them.
    pub extra_env: Arc<std::sync::Mutex<Vec<(String, String)>>>,
    /// Secret redactor applied to captured I/O.
    pub redactor: Arc<Redactor>,
}

fn validate_env(env: &[sealant_protocol::EnvVar]) -> Result<(), ControlError> {
    for var in env {
        if var.key.is_empty()
            || var.key.contains('=')
            || var.key.contains('\0')
            || var.value.contains('\0')
        {
            return Err(ControlError::invalid_argument(format!(
                "invalid environment variable name {:?}",
                var.key
            )));
        }
    }
    Ok(())
}

impl ProcessRuntime {
    /// Spawn a non-interactive process. Returns immediately with an [`ExecAccepted`]; the exit is
    /// later surfaced as a `process.exited` event (plan §8.6).
    ///
    /// # Errors
    /// Returns a [`ControlError`] if arguments are invalid or the process cannot be spawned.
    pub fn exec(
        &self,
        args: ExecArgs,
        request_id: Option<RequestId>,
    ) -> Result<ExecAccepted, ControlError> {
        self.exec_inner(args, request_id, None)
    }

    /// Spawn a non-interactive process with its stdout/stderr additionally bound to a reliable
    /// exec-attach channel (§1.A exec-attach). The attach binding is established atomically at spawn
    /// — before any pipe byte is read — so the initial output burst that VSCode's bootstrap reads is
    /// never lost. The lossy `IoChunk` telemetry tap stays on in parallel. A final
    /// `StreamFrame::End{exit_code}` is emitted on the channel when the process exits.
    ///
    /// # Errors
    /// Returns a [`ControlError`] if arguments are invalid or the process cannot be spawned.
    pub fn exec_attached(
        &self,
        args: ExecArgs,
        request_id: Option<RequestId>,
        channel_id: ChannelId,
        out_tx: mpsc::Sender<ServerMessage>,
    ) -> Result<ExecAccepted, ControlError> {
        let sink = AttachSink::new(channel_id, out_tx);
        self.exec_inner(args, request_id, Some(sink))
    }

    fn exec_inner(
        &self,
        args: ExecArgs,
        request_id: Option<RequestId>,
        attach: Option<AttachSink>,
    ) -> Result<ExecAccepted, ControlError> {
        if args.executable.trim().is_empty() {
            return Err(ControlError::invalid_argument(
                "executable must not be empty".to_owned(),
            ));
        }
        validate_env(&args.env)?;

        // Enforce the process limit before spawning; overflow is rejected cleanly, not crashed.
        let active = self.status.counts().0;
        if active >= self.config.limits.max_processes {
            return Err(ControlError::new(
                ControlErrorCode::PolicyDenied,
                format!(
                    "process limit reached ({}/{})",
                    active, self.config.limits.max_processes
                ),
            ));
        }

        let cwd = args
            .cwd
            .clone()
            .map_or_else(|| self.config.workspace_root.clone(), Into::into);

        let mut command = tokio::process::Command::new(&args.executable);
        command.args(&args.args);
        command.env_clear();
        for var in &self.config.child_env {
            command.env(&var.key, &var.value);
        }
        for var in &args.env {
            command.env(&var.key, &var.value);
        }
        for (key, value) in self
            .extra_env
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .iter()
        {
            command.env(key, value);
        }
        command.current_dir(&cwd);
        command.stdin(if args.stdin {
            Stdio::piped()
        } else {
            Stdio::null()
        });
        command.stdout(Stdio::piped());
        command.stderr(Stdio::piped());
        // Own process group so signals reach the whole managed tree, not just the direct child.
        command.process_group(0);
        command.kill_on_drop(true);

        let mut child = command
            .spawn()
            .map_err(|e| ControlError::process_start_failed(format!("{}: {e}", args.executable)))?;

        let pid = child.id().map_or(-1, |p| p as i32);
        // process_group(0) makes the child a group leader, so pgid == pid.
        let pgid = pid;
        let process_id = self.idgen.process_id();
        let execution_id = args
            .execution_id
            .clone()
            .or_else(|| self.config.default_execution_id.clone());

        let stdout = child.stdout.take();
        let stderr = child.stderr.take();
        let stdin = child.stdin.take();
        let policy = args.capture.unwrap_or(self.config.capture);

        let correlation = Correlation::new()
            .execution(execution_id.clone())
            .session(args.session_id.clone())
            .process(process_id.clone())
            .request(request_id);

        let entry = Arc::new(ProcessEntry::new(
            process_id.clone(),
            pid,
            pgid,
            args.executable.clone(),
            execution_id,
            args.session_id.clone(),
            stdin,
        ));
        entry.set_state(ProcessState::Running);
        self.registry.insert(entry.clone());
        self.status.inc_processes();

        self.bus.publish(
            &correlation,
            CaptureMethod::Internal,
            Confidence::Observed,
            EventPayload::ProcessStarted(ProcessStarted {
                pid,
                pgid,
                pidfd: false,
                executable: args.executable.clone(),
                args: args.args.clone(),
                cwd: cwd.display().to_string(),
                started_at: self.clock.wall_now(),
            }),
        );

        let chunk_size = self.config.io_chunk_bytes;
        // Both stdout and stderr fan into the SAME attach sink (shared seq) so the gateway sees one
        // ordered byte stream — exactly like a PTY attach.
        let stdout_handle = stdout.map(|s| {
            let bus = self.bus.clone();
            let corr = correlation.clone();
            tokio::spawn(capture_stream(
                s,
                StreamKind::Stdout,
                policy.stdout,
                chunk_size,
                bus,
                corr,
                self.redactor.clone(),
                self.status.clone(),
                attach.clone(),
            ))
        });
        let stderr_handle = stderr.map(|s| {
            let bus = self.bus.clone();
            let corr = correlation.clone();
            tokio::spawn(capture_stream(
                s,
                StreamKind::Stderr,
                policy.stderr,
                chunk_size,
                bus,
                corr,
                self.redactor.clone(),
                self.status.clone(),
                attach.clone(),
            ))
        });

        let timeout = args.timeout_millis.map(Duration::from_millis);
        let grace = Duration::from_millis(self.config.shutdown_grace_ms);
        let waiter_bus = self.bus.clone();
        let waiter_registry = self.registry.clone();
        let waiter_status = self.status.clone();
        let waiter_entry = entry;
        let waiter_proc = process_id.clone();
        let waiter_attach = attach;
        tokio::spawn(async move {
            let start = Instant::now();
            let outcome = run_to_exit(child, pgid, timeout, grace).await;
            // Drain captured output before publishing the exit, so all io.chunks precede it.
            if let Some(handle) = stdout_handle {
                let _ = handle.await;
            }
            if let Some(handle) = stderr_handle {
                let _ = handle.await;
            }
            // Both capture tasks have joined, so by here the attach channel has received every byte
            // of stdout/stderr. Emit a final End{exit_code, signal} so the gateway maps the exec
            // channel's exit-status (the lossless analogue of the IoChunk→ProcessExited telemetry).
            if let Some(sink) = waiter_attach {
                let end = StreamFrame::end(
                    sink.channel_id.clone(),
                    u64::MAX,
                    StreamEnd {
                        exit_code: outcome.exit_code,
                        signal: outcome.signal,
                        error: None,
                    },
                );
                let _ = sink.out_tx.send(ServerMessage::Stream(end)).await;
            }
            let duration_micros = start.elapsed().as_micros() as u64;
            waiter_entry.set_state(outcome.state);
            waiter_bus.publish(
                &correlation,
                CaptureMethod::Internal,
                Confidence::Observed,
                EventPayload::ProcessExited(ProcessExited {
                    exit_code: outcome.exit_code,
                    signal: outcome.signal,
                    reason: outcome.reason,
                    duration_micros,
                }),
            );
            waiter_registry.remove(&waiter_proc);
            waiter_status.dec_processes();
        });

        Ok(ExecAccepted {
            process_id,
            pid,
            pgid,
            pidfd: false,
        })
    }

    /// Deliver a signal to a managed process's group.
    ///
    /// # Errors
    /// Returns [`ControlError`] if the process is unknown or signalling fails.
    pub fn signal(&self, process_id: &ProcessId, signal: Signal) -> Result<(), ControlError> {
        let entry = self
            .registry
            .get(process_id)
            .ok_or_else(|| ControlError::process_not_found(process_id.to_string()))?;
        signals::signal_group(entry.pgid, signals::to_nix(signal)).map_err(|e| {
            ControlError::new(
                sealant_protocol::ControlErrorCode::PermissionDenied,
                e.to_string(),
            )
        })
    }

    /// Forcefully kill a managed process's group with `SIGKILL`.
    ///
    /// # Errors
    /// Returns [`ControlError`] if the process is unknown or signalling fails.
    pub fn kill(&self, process_id: &ProcessId) -> Result<(), ControlError> {
        self.signal(process_id, Signal::Kill)
    }

    /// Write bytes to a process's stdin.
    ///
    /// # Errors
    /// Returns [`ControlError`] if the process is unknown or stdin is unavailable.
    pub async fn write_stdin(
        &self,
        process_id: &ProcessId,
        data: &[u8],
    ) -> Result<(), ControlError> {
        let entry = self
            .registry
            .get(process_id)
            .ok_or_else(|| ControlError::process_not_found(process_id.to_string()))?;
        entry.write_stdin(data).await
    }

    /// Close a process's stdin.
    ///
    /// # Errors
    /// Returns [`ControlError`] if the process is unknown.
    pub async fn close_stdin(&self, process_id: &ProcessId) -> Result<(), ControlError> {
        let entry = self
            .registry
            .get(process_id)
            .ok_or_else(|| ControlError::process_not_found(process_id.to_string()))?;
        entry.close_stdin().await;
        Ok(())
    }

    /// List managed processes, optionally filtered by execution.
    #[must_use]
    pub fn list(&self, execution: Option<&sealant_protocol::ExecutionId>) -> Vec<ProcessSummary> {
        self.registry.list(execution)
    }

    /// Terminate all managed processes: graceful signal, then `SIGKILL` after the grace period.
    pub async fn terminate_all(&self, graceful: Signal, grace: Duration) {
        let running = self.registry.running();
        if running.is_empty() {
            return;
        }
        let nix_graceful = signals::to_nix(graceful);
        for entry in &running {
            entry.set_state(ProcessState::Terminating);
            let _ = signals::signal_group(entry.pgid, nix_graceful);
        }
        wait_until_empty(&self.registry, grace).await;

        for entry in self.registry.running() {
            let _ = signals::signal_group(entry.pgid, nix::sys::signal::Signal::SIGKILL);
        }
        wait_until_empty(&self.registry, Duration::from_secs(2)).await;
    }
}

async fn wait_until_empty(registry: &ProcessRegistry, within: Duration) {
    let deadline = Instant::now() + within;
    while !registry.is_empty() && Instant::now() < deadline {
        tokio::time::sleep(Duration::from_millis(25)).await;
    }
}

struct ExitOutcome {
    exit_code: Option<i32>,
    signal: Option<i32>,
    reason: ExitReason,
    state: ProcessState,
}

async fn run_to_exit(
    mut child: tokio::process::Child,
    pgid: i32,
    timeout: Option<Duration>,
    grace: Duration,
) -> ExitOutcome {
    let mut timed_out = false;
    let status = match timeout {
        Some(limit) => {
            tokio::select! {
                result = child.wait() => result,
                () = tokio::time::sleep(limit) => {
                    timed_out = true;
                    let _ = signals::signal_group(pgid, nix::sys::signal::Signal::SIGTERM);
                    tokio::select! {
                        result = child.wait() => result,
                        () = tokio::time::sleep(grace) => {
                            let _ = signals::signal_group(pgid, nix::sys::signal::Signal::SIGKILL);
                            child.wait().await
                        }
                    }
                }
            }
        }
        None => child.wait().await,
    };

    match status {
        Ok(exit) => {
            let exit_code = exit.code();
            let signal = exit.signal();
            let reason = if timed_out {
                ExitReason::Timeout
            } else if exit_code.is_some() {
                ExitReason::Exited
            } else if signal.is_some() {
                ExitReason::Signaled
            } else {
                ExitReason::Lost
            };
            let state = match reason {
                ExitReason::Exited => ProcessState::Exited,
                ExitReason::Signaled | ExitReason::Timeout => ProcessState::Signaled,
                _ => ProcessState::Failed,
            };
            ExitOutcome {
                exit_code,
                signal,
                reason,
                state,
            }
        }
        Err(_) => ExitOutcome {
            exit_code: None,
            signal: None,
            reason: ExitReason::Lost,
            state: ProcessState::Failed,
        },
    }
}

#[expect(
    clippy::too_many_arguments,
    reason = "captured pipe needs full context per task"
)]
async fn capture_stream<R: AsyncRead + Unpin>(
    mut reader: R,
    stream: StreamKind,
    mode: CaptureMode,
    chunk_size: usize,
    bus: Arc<EventBus>,
    correlation: Correlation,
    redactor: Arc<Redactor>,
    status: Arc<RuntimeStatus>,
    attach: Option<AttachSink>,
) {
    // When attached we must read every byte even if telemetry capture is disabled, so the reliable
    // exec-attach stream stays lossless. When neither capture nor attach is active we just drain.
    if matches!(mode, CaptureMode::Disabled) && attach.is_none() {
        let mut sink = [0u8; 8192];
        loop {
            match reader.read(&mut sink).await {
                Ok(0) | Err(_) => break,
                Ok(_) => {}
            }
        }
        return;
    }

    let mut offset = StreamOffset::ZERO;
    let mut buf = vec![0u8; chunk_size.max(1)];
    let mut attach = attach;
    loop {
        let n = match reader.read(&mut buf).await {
            Ok(0) => break,
            Ok(n) => n,
            Err(_) => break,
        };

        // (b) reliable exec-attach fan-out (backpressured, RAW bytes, never redacted). Sharing this
        // single reader means the attach stream sees every byte; awaiting the send throttles this
        // loop's next read so a slow gateway backpressures the process — the inverse of the lossy
        // IoChunk tap below. Done before the telemetry publish so attach ordering is independent of
        // capture mode. If the gateway queue is closed, drop the sink and keep draining for telemetry.
        if let Some(sink) = &attach
            && sink.forward(&buf[..n]).await.is_err()
        {
            attach = None;
        }

        // (a) lossy telemetry tap (always on, redaction applies here only). When capture is disabled
        // but we are attached, skip emitting a telemetry chunk (we only read to feed the attach).
        if matches!(mode, CaptureMode::Disabled) {
            offset = offset.advance(n as u64);
            continue;
        }
        let (content, byte_count, transform) = if matches!(mode, CaptureMode::Full) {
            let (data, redacted) = redactor.redact(&buf[..n]);
            if redacted > 0 {
                status.add_redacted(redacted);
                let len = data.len() as u64;
                (
                    Some(sealant_protocol::Base64Bytes::new(data)),
                    len,
                    Some(TransformMeta {
                        redacted: true,
                        truncated: false,
                        coalesced: false,
                        original_byte_count: Some(n as u64),
                    }),
                )
            } else {
                (
                    Some(sealant_protocol::Base64Bytes::new(&buf[..n])),
                    n as u64,
                    None,
                )
            }
        } else {
            (None, n as u64, None)
        };
        bus.publish(
            &correlation,
            CaptureMethod::Pipe,
            Confidence::Observed,
            EventPayload::IoChunk(IoChunk {
                stream,
                encoding: Encoding::Base64,
                byte_count,
                stream_offset: offset,
                content,
                artifact: None,
                transform,
            }),
        );
        offset = offset.advance(n as u64);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use sealant_protocol::EventPayload;
    use sealant_runtime_core::new_runtime_id;
    use std::time::Duration;
    use tokio::sync::broadcast::Receiver;

    fn runtime() -> ProcessRuntime {
        let rt = new_runtime_id();
        let clock = Arc::new(Clock::new());
        let idgen = Arc::new(IdGenerator::new(&rt));
        let bus = Arc::new(EventBus::new(
            rt.clone(),
            clock.clone(),
            idgen.clone(),
            1024,
        ));
        let mut config = RuntimeConfig::new(rt);
        config.workspace_root = std::env::temp_dir();
        config.shutdown_grace_ms = 500;
        ProcessRuntime {
            registry: Arc::new(ProcessRegistry::new()),
            bus,
            idgen,
            status: Arc::new(RuntimeStatus::new()),
            clock,
            config: Arc::new(config),
            extra_env: Arc::new(std::sync::Mutex::new(Vec::new())),
            redactor: Arc::new(Redactor::default()),
        }
    }

    async fn collect_until_exit(
        rx: &mut Receiver<sealant_protocol::EventEnvelope>,
    ) -> Vec<EventPayload> {
        let mut payloads = Vec::new();
        loop {
            let env = tokio::time::timeout(Duration::from_secs(5), rx.recv())
                .await
                .expect("no timeout")
                .expect("event");
            let is_exit = matches!(env.payload, EventPayload::ProcessExited(_));
            payloads.push(env.payload);
            if is_exit {
                break;
            }
        }
        payloads
    }

    fn exec_args(executable: &str, args: &[&str]) -> ExecArgs {
        ExecArgs {
            execution_id: None,
            session_id: None,
            executable: executable.to_owned(),
            args: args.iter().map(|s| (*s).to_owned()).collect(),
            cwd: None,
            env: vec![],
            stdin: false,
            attach: false,
            timeout_millis: None,
            background: false,
            capture: None,
            graceful_signal: None,
        }
    }

    #[tokio::test]
    async fn exec_emits_started_output_and_exit() {
        let rt = runtime();
        let mut rx = rt.bus.subscribe();
        let accepted = rt
            .exec(exec_args("/bin/echo", &["hello"]), None)
            .expect("spawn");
        assert!(accepted.process_id.as_str().starts_with("proc_"));

        let payloads = collect_until_exit(&mut rx).await;
        assert!(matches!(
            payloads.first(),
            Some(EventPayload::ProcessStarted(_))
        ));

        let stdout: Vec<u8> = payloads
            .iter()
            .filter_map(|p| match p {
                EventPayload::IoChunk(c) if c.stream == StreamKind::Stdout => {
                    c.content.as_ref().map(|b| b.as_slice().to_vec())
                }
                _ => None,
            })
            .flatten()
            .collect();
        assert_eq!(stdout, b"hello\n");

        match payloads.last() {
            Some(EventPayload::ProcessExited(e)) => {
                assert_eq!(e.exit_code, Some(0));
                assert_eq!(e.reason, ExitReason::Exited);
            }
            other => panic!("expected exit, got {other:?}"),
        }
        // Registry is cleaned up.
        assert_eq!(rt.registry.len(), 0);
        assert_eq!(rt.status.counts().0, 0);
    }

    #[tokio::test]
    async fn redacts_secret_tokens_in_captured_output() {
        let rt = runtime();
        let mut rx = rt.bus.subscribe();
        rt.exec(
            exec_args(
                "/bin/sh",
                &["-c", "printf 'KEY=sk-abcdef012345678901234567'"],
            ),
            None,
        )
        .expect("spawn");
        let payloads = collect_until_exit(&mut rx).await;
        let chunks: Vec<_> = payloads
            .iter()
            .filter_map(|p| match p {
                EventPayload::IoChunk(c) if c.stream == StreamKind::Stdout => Some(c.clone()),
                _ => None,
            })
            .collect();
        let combined: Vec<u8> = chunks
            .iter()
            .filter_map(|c| c.content.as_ref().map(|b| b.as_slice().to_vec()))
            .flatten()
            .collect();
        let text = String::from_utf8_lossy(&combined);
        assert!(!text.contains("sk-abcdef"), "secret leaked: {text}");
        assert!(
            text.contains("***REDACTED***"),
            "no redaction marker: {text}"
        );
        assert!(
            chunks
                .iter()
                .any(|c| c.transform.as_ref().is_some_and(|t| t.redacted))
        );
        assert!(rt.status.redacted() >= 1);
    }

    #[tokio::test]
    async fn enforces_process_limit() {
        let rt = runtime();
        let max = rt.config.limits.max_processes;
        for _ in 0..max {
            rt.status.inc_processes();
        }
        let error = rt
            .exec(exec_args("/bin/echo", &["x"]), None)
            .expect_err("limit should reject");
        assert_eq!(error.code(), ControlErrorCode::PolicyDenied);
    }

    #[tokio::test]
    async fn capture_is_binary_safe() {
        let rt = runtime();
        let mut rx = rt.bus.subscribe();
        // Emit bytes including NUL and a high byte via printf.
        rt.exec(exec_args("/bin/sh", &["-c", r"printf 'a\000b\377c'"]), None)
            .expect("spawn");
        let payloads = collect_until_exit(&mut rx).await;
        let stdout: Vec<u8> = payloads
            .iter()
            .filter_map(|p| match p {
                EventPayload::IoChunk(c) if c.stream == StreamKind::Stdout => {
                    c.content.as_ref().map(|b| b.as_slice().to_vec())
                }
                _ => None,
            })
            .flatten()
            .collect();
        assert_eq!(stdout, vec![b'a', 0x00, b'b', 0xff, b'c']);
    }

    #[tokio::test]
    async fn nonzero_exit_code_is_reported() {
        let rt = runtime();
        let mut rx = rt.bus.subscribe();
        rt.exec(exec_args("/bin/sh", &["-c", "exit 42"]), None)
            .expect("spawn");
        let payloads = collect_until_exit(&mut rx).await;
        match payloads.last() {
            Some(EventPayload::ProcessExited(e)) => assert_eq!(e.exit_code, Some(42)),
            other => panic!("expected exit, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn timeout_terminates_a_hung_process() {
        let rt = runtime();
        let mut rx = rt.bus.subscribe();
        let mut args = exec_args("/bin/sh", &["-c", "sleep 30"]);
        args.timeout_millis = Some(150);
        rt.exec(args, None).expect("spawn");
        let payloads = collect_until_exit(&mut rx).await;
        match payloads.last() {
            Some(EventPayload::ProcessExited(e)) => {
                assert_eq!(e.reason, ExitReason::Timeout);
                assert_eq!(e.signal, Some(nix::sys::signal::Signal::SIGTERM as i32));
            }
            other => panic!("expected timeout exit, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn command_not_found_is_reported() {
        let rt = runtime();
        let err = rt
            .exec(exec_args("/nonexistent/binary-xyz", &[]), None)
            .unwrap_err();
        assert_eq!(
            err.code(),
            sealant_protocol::ControlErrorCode::ProcessStartFailed
        );
    }

    fn stream_bytes(payloads: &[EventPayload], kind: StreamKind) -> Vec<u8> {
        payloads
            .iter()
            .filter_map(|p| match p {
                EventPayload::IoChunk(c) if c.stream == kind => {
                    c.content.as_ref().map(|b| b.as_slice().to_vec())
                }
                _ => None,
            })
            .flatten()
            .collect()
    }

    #[tokio::test]
    async fn stdin_streaming_echoes_through_cat() {
        let rt = runtime();
        let mut rx = rt.bus.subscribe();
        let mut args = exec_args("/bin/cat", &[]);
        args.stdin = true;
        let accepted = rt.exec(args, None).expect("spawn");
        rt.write_stdin(&accepted.process_id, b"hello stdin\n")
            .await
            .expect("write");
        rt.close_stdin(&accepted.process_id).await.expect("close");
        let payloads = collect_until_exit(&mut rx).await;
        assert_eq!(
            stream_bytes(&payloads, StreamKind::Stdout),
            b"hello stdin\n"
        );
        match payloads.last() {
            Some(EventPayload::ProcessExited(e)) => assert_eq!(e.exit_code, Some(0)),
            other => panic!("expected exit, got {other:?}"),
        }
    }

    /// Whether `pid` is a live, running process — not gone and not a zombie.
    fn is_running(pid: i32) -> bool {
        #[cfg(target_os = "linux")]
        {
            match std::fs::read_to_string(format!("/proc/{pid}/stat")) {
                Err(_) => false, // gone
                Ok(stat) => {
                    // Format: "pid (comm) state ...". comm may contain spaces and ')', so the state
                    // char is the first non-space after the LAST ')'.
                    let state = stat
                        .rsplit(')')
                        .next()
                        .and_then(|rest| rest.trim_start().chars().next());
                    !matches!(state, Some('Z') | None)
                }
            }
        }
        #[cfg(not(target_os = "linux"))]
        {
            // No /proc; macOS reaps zombies promptly, so existence ≈ running.
            nix::sys::signal::kill(nix::unistd::Pid::from_raw(pid), None).is_ok()
        }
    }

    #[tokio::test]
    async fn killing_process_group_reaps_grandchild() {
        use nix::sys::signal::kill;
        use nix::unistd::Pid;

        let rt = runtime();
        let mut rx = rt.bus.subscribe();
        // sh backgrounds a sleep (same process group, no job control) and blocks on wait.
        let accepted = rt
            .exec(
                exec_args("/bin/sh", &["-c", "sleep 30 & echo $!; wait"]),
                None,
            )
            .expect("spawn");

        // Capture the grandchild pid printed to stdout.
        let grandchild = loop {
            let env = tokio::time::timeout(Duration::from_secs(5), rx.recv())
                .await
                .expect("no timeout")
                .expect("event");
            if let EventPayload::IoChunk(c) = &env.payload
                && c.stream == StreamKind::Stdout
                && let Some(content) = &c.content
                && let Ok(pid) = String::from_utf8_lossy(content.as_slice())
                    .trim()
                    .parse::<i32>()
            {
                break pid;
            }
        };
        assert!(
            kill(Pid::from_raw(grandchild), None).is_ok(),
            "grandchild should be alive before kill"
        );

        rt.kill(&accepted.process_id).expect("kill");

        // Drain to the managed process exit.
        loop {
            let env = tokio::time::timeout(Duration::from_secs(5), rx.recv())
                .await
                .expect("no timeout")
                .expect("event");
            if matches!(env.payload, EventPayload::ProcessExited(_)) {
                break;
            }
        }

        // The grandchild must be terminated by the process-group kill — no orphan left running.
        // Under PID 1 (e.g. a container with no reaper) a killed orphan can briefly remain a
        // zombie; a zombie is terminated, not running, so gone-or-zombie both pass.
        let mut terminated = false;
        for _ in 0..200 {
            if !is_running(grandchild) {
                terminated = true;
                break;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        assert!(
            terminated,
            "grandchild {grandchild} should be terminated by the group kill"
        );
        assert_eq!(rt.registry.len(), 0);
    }

    #[tokio::test]
    async fn ignored_sigterm_escalates_to_sigkill() {
        let rt = runtime();
        let mut rx = rt.bus.subscribe();
        // Ignore SIGTERM and spin; the timeout path must escalate to an untrappable SIGKILL.
        let mut args = exec_args("/bin/sh", &["-c", "trap '' TERM; while true; do :; done"]);
        args.timeout_millis = Some(150);
        rt.exec(args, None).expect("spawn");
        let payloads = collect_until_exit(&mut rx).await;
        match payloads.last() {
            Some(EventPayload::ProcessExited(e)) => {
                assert_eq!(e.reason, ExitReason::Timeout);
                assert_eq!(e.signal, Some(nix::sys::signal::Signal::SIGKILL as i32));
            }
            other => panic!("expected sigkill timeout exit, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn concurrent_stdout_and_stderr_are_captured() {
        let rt = runtime();
        let mut rx = rt.bus.subscribe();
        rt.exec(
            exec_args("/bin/sh", &["-c", "printf out >&1; printf err >&2"]),
            None,
        )
        .expect("spawn");
        let payloads = collect_until_exit(&mut rx).await;
        assert_eq!(stream_bytes(&payloads, StreamKind::Stdout), b"out");
        assert_eq!(stream_bytes(&payloads, StreamKind::Stderr), b"err");
    }

    #[tokio::test]
    async fn large_stdout_is_chunked_with_monotonic_offsets() {
        let rt = runtime();
        let mut rx = rt.bus.subscribe();
        rt.exec(
            exec_args(
                "/bin/sh",
                &["-c", "head -c 1000000 /dev/zero | tr '\\0' 'A'"],
            ),
            None,
        )
        .expect("spawn");
        let payloads = collect_until_exit(&mut rx).await;

        let out = stream_bytes(&payloads, StreamKind::Stdout);
        assert_eq!(out.len(), 1_000_000);
        assert!(out.iter().all(|&b| b == b'A'));

        // Offsets must be contiguous and cover the whole stream.
        let mut expected = 0u64;
        for payload in &payloads {
            if let EventPayload::IoChunk(c) = payload
                && c.stream == StreamKind::Stdout
            {
                assert_eq!(c.stream_offset.get(), expected);
                expected += c.byte_count;
            }
        }
        assert_eq!(expected, 1_000_000);
    }
}
