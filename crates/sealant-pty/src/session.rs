//! Interactive session lifecycle: registry, open/write/resize/close, and output capture.

use std::collections::HashMap;
use std::io;
use std::os::fd::OwnedFd;
use std::os::unix::process::ExitStatusExt;
use std::sync::Arc;
use std::sync::Mutex;
use std::sync::atomic::{AtomicU16, Ordering};
use std::time::{Duration, Instant};

use nix::sys::signal::Signal as NixSignal;
use nix::unistd::Pid;
use sealant_protocol::{
    Base64Bytes, CaptureMethod, Confidence, ControlError, Encoding, EventPayload, ExecutionId,
    ExitReason, IoChunk, OpenSessionArgs, ProcessExited, ProcessId, ProcessStarted, SessionId,
    SessionList, SessionOpened, SessionSummary, StreamKind, StreamOffset,
};
use sealant_runtime_core::{Clock, IdGenerator, RuntimeConfig, RuntimeStatus};
use sealant_telemetry::{Correlation, EventBus};
use tokio::io::unix::AsyncFd;

use crate::pty::{self, PtyChild};

/// Default terminal type advertised to the child when the caller does not specify one.
const DEFAULT_TERM: &str = "xterm-256color";

/// A live interactive session: a shell running under a PTY.
#[derive(Debug)]
pub struct SessionEntry {
    /// Session id.
    pub session_id: SessionId,
    /// Logical process id of the session leader.
    pub process_id: ProcessId,
    /// OS pid of the session leader (also its session id / process-group id).
    pub pid: i32,
    /// The PTY master, shared between capture, input, and resize.
    pub master: Arc<AsyncFd<OwnedFd>>,
    /// Associated execution, when any.
    pub execution_id: Option<ExecutionId>,
    cols: AtomicU16,
    rows: AtomicU16,
}

impl SessionEntry {
    /// A summary of this session.
    #[must_use]
    pub fn summary(&self) -> SessionSummary {
        SessionSummary {
            session_id: self.session_id.clone(),
            process_id: self.process_id.clone(),
            pid: self.pid,
            cols: self.cols.load(Ordering::Relaxed),
            rows: self.rows.load(Ordering::Relaxed),
            execution_id: self.execution_id.clone(),
        }
    }
}

/// Thread-safe registry of interactive sessions.
#[derive(Debug, Default)]
pub struct SessionRegistry {
    inner: Mutex<HashMap<SessionId, Arc<SessionEntry>>>,
}

impl SessionRegistry {
    /// An empty registry.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, HashMap<SessionId, Arc<SessionEntry>>> {
        self.inner.lock().unwrap_or_else(|e| e.into_inner())
    }

    fn insert(&self, entry: Arc<SessionEntry>) {
        self.lock().insert(entry.session_id.clone(), entry);
    }

    /// Look up a session.
    #[must_use]
    pub fn get(&self, id: &SessionId) -> Option<Arc<SessionEntry>> {
        self.lock().get(id).cloned()
    }

    fn remove(&self, id: &SessionId) -> Option<Arc<SessionEntry>> {
        self.lock().remove(id)
    }

    /// Number of live sessions.
    #[must_use]
    pub fn len(&self) -> usize {
        self.lock().len()
    }

    /// Whether there are no sessions.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.lock().is_empty()
    }

    /// Summaries of all sessions.
    #[must_use]
    pub fn list(&self) -> Vec<SessionSummary> {
        self.lock().values().map(|e| e.summary()).collect()
    }

    /// All session leader pids.
    #[must_use]
    pub fn pids(&self) -> Vec<i32> {
        self.lock().values().map(|e| e.pid).collect()
    }
}

/// Runs and supervises interactive PTY sessions.
#[derive(Debug, Clone)]
pub struct SessionRuntime {
    /// Session registry.
    pub registry: Arc<SessionRegistry>,
    /// Telemetry bus.
    pub bus: Arc<EventBus>,
    /// Id generator.
    pub idgen: Arc<IdGenerator>,
    /// Live counters.
    pub status: Arc<RuntimeStatus>,
    /// Clock.
    pub clock: Arc<Clock>,
    /// Configuration.
    pub config: Arc<RuntimeConfig>,
}

fn signal_session(pid: i32, signal: NixSignal) {
    // The session leader is its own process-group leader (setsid), so signal the whole group.
    let _ = nix::sys::signal::killpg(Pid::from_raw(pid), signal);
}

impl SessionRuntime {
    /// Open an interactive session.
    ///
    /// # Errors
    /// Returns a [`ControlError`] if the PTY cannot be allocated or the shell cannot start.
    pub fn open(&self, args: OpenSessionArgs) -> Result<SessionOpened, ControlError> {
        let shell = args
            .shell
            .clone()
            .unwrap_or_else(|| self.config.default_shell.clone());
        let cwd = args
            .cwd
            .clone()
            .map_or_else(|| self.config.workspace_root.clone(), Into::into);
        let term = args.term.clone().unwrap_or_else(|| DEFAULT_TERM.to_owned());
        let mut env: Vec<(String, String)> = self
            .config
            .child_env
            .iter()
            .map(|v| (v.key.clone(), v.value.clone()))
            .collect();
        env.extend(args.env.iter().map(|v| (v.key.clone(), v.value.clone())));

        let PtyChild { master, child, pid } = pty::spawn(
            &shell, &args.args, &cwd, &env, args.cols, args.rows, &term,
        )
        .map_err(|e| {
            ControlError::new(
                sealant_protocol::ControlErrorCode::PtyAllocationFailed,
                format!("{shell}: {e}"),
            )
        })?;

        let session_id = self.idgen.session_id();
        let process_id = self.idgen.process_id();
        let execution_id = args
            .execution_id
            .clone()
            .or_else(|| self.config.default_execution_id.clone());
        let master = Arc::new(master);

        let entry = Arc::new(SessionEntry {
            session_id: session_id.clone(),
            process_id: process_id.clone(),
            pid,
            master: master.clone(),
            execution_id: execution_id.clone(),
            cols: AtomicU16::new(args.cols),
            rows: AtomicU16::new(args.rows),
        });
        self.registry.insert(entry);
        self.status.inc_sessions();

        let correlation = Correlation::new()
            .execution(execution_id)
            .session(Some(session_id.clone()))
            .process(process_id.clone());

        self.bus.publish(
            &correlation,
            CaptureMethod::Pty,
            Confidence::Observed,
            EventPayload::ProcessStarted(ProcessStarted {
                pid,
                pgid: pid,
                pidfd: false,
                executable: shell,
                args: args.args.clone(),
                cwd: cwd.display().to_string(),
                started_at: self.clock.wall_now(),
            }),
        );

        // Capture pty.output until the slave closes.
        let capture_bus = self.bus.clone();
        let capture_corr = correlation.clone();
        let capture_master = master.clone();
        let chunk_size = self.config.io_chunk_bytes;
        let capture = tokio::spawn(async move {
            capture_output(capture_master, capture_bus, capture_corr, chunk_size).await;
        });

        // Wait for the leader to exit, then publish the final result.
        let waiter_bus = self.bus.clone();
        let waiter_registry = self.registry.clone();
        let waiter_status = self.status.clone();
        let waiter_session = session_id.clone();
        let mut child = child;
        tokio::spawn(async move {
            let start = Instant::now();
            let status_result = child.wait().await;
            let _ = capture.await;
            let (exit_code, signal, reason) = classify(&status_result);
            waiter_bus.publish(
                &correlation,
                CaptureMethod::Pty,
                Confidence::Observed,
                EventPayload::ProcessExited(ProcessExited {
                    exit_code,
                    signal,
                    reason,
                    duration_micros: start.elapsed().as_micros() as u64,
                }),
            );
            waiter_registry.remove(&waiter_session);
            waiter_status.dec_sessions();
        });

        Ok(SessionOpened {
            session_id,
            process_id,
            pid,
        })
    }

    /// Write bytes to a session's PTY input.
    ///
    /// # Errors
    /// Returns a [`ControlError`] if the session is unknown or the write fails.
    pub async fn write_input(
        &self,
        session_id: &SessionId,
        data: &[u8],
    ) -> Result<(), ControlError> {
        let entry = self
            .registry
            .get(session_id)
            .ok_or_else(|| ControlError::session_not_found(session_id.to_string()))?;
        pty::write_all(&entry.master, data)
            .await
            .map_err(|e| ControlError::invalid_argument(format!("pty input write failed: {e}")))?;

        // Record the forwarded input as evidence (redaction is a later-phase concern).
        let correlation = Correlation::new()
            .execution(entry.execution_id.clone())
            .session(Some(session_id.clone()))
            .process(entry.process_id.clone());
        self.bus.publish(
            &correlation,
            CaptureMethod::Pty,
            Confidence::Observed,
            EventPayload::IoChunk(IoChunk {
                stream: StreamKind::PtyInput,
                encoding: Encoding::Base64,
                byte_count: data.len() as u64,
                stream_offset: StreamOffset::ZERO,
                content: Some(Base64Bytes::new(data)),
                artifact: None,
                transform: None,
            }),
        );
        Ok(())
    }

    /// Resize a session's PTY.
    ///
    /// # Errors
    /// Returns a [`ControlError`] if the session is unknown or the ioctl fails.
    pub fn resize(&self, session_id: &SessionId, cols: u16, rows: u16) -> Result<(), ControlError> {
        let entry = self
            .registry
            .get(session_id)
            .ok_or_else(|| ControlError::session_not_found(session_id.to_string()))?;
        pty::resize(&entry.master, cols, rows)
            .map_err(|e| ControlError::invalid_argument(format!("pty resize failed: {e}")))?;
        entry.cols.store(cols, Ordering::Relaxed);
        entry.rows.store(rows, Ordering::Relaxed);
        Ok(())
    }

    /// Close a session by hanging up its terminal (SIGHUP). The wait task publishes the exit.
    ///
    /// # Errors
    /// Returns a [`ControlError`] if the session is unknown.
    pub fn close(&self, session_id: &SessionId) -> Result<(), ControlError> {
        let entry = self
            .registry
            .get(session_id)
            .ok_or_else(|| ControlError::session_not_found(session_id.to_string()))?;
        signal_session(entry.pid, NixSignal::SIGHUP);
        Ok(())
    }

    /// List active sessions.
    #[must_use]
    pub fn list(&self) -> SessionList {
        SessionList {
            sessions: self.registry.list(),
        }
    }

    /// Hang up and then kill all sessions on shutdown.
    pub async fn terminate_all(&self, grace: Duration) {
        let pids = self.registry.pids();
        if pids.is_empty() {
            return;
        }
        for pid in &pids {
            signal_session(*pid, NixSignal::SIGHUP);
        }
        let deadline = Instant::now() + grace;
        while !self.registry.is_empty() && Instant::now() < deadline {
            tokio::time::sleep(Duration::from_millis(25)).await;
        }
        for pid in self.registry.pids() {
            signal_session(pid, NixSignal::SIGKILL);
        }
        let hard = Instant::now() + Duration::from_secs(2);
        while !self.registry.is_empty() && Instant::now() < hard {
            tokio::time::sleep(Duration::from_millis(25)).await;
        }
    }
}

fn classify(
    result: &io::Result<std::process::ExitStatus>,
) -> (Option<i32>, Option<i32>, ExitReason) {
    match result {
        Ok(status) => {
            let code = status.code();
            let signal = status.signal();
            let reason = if code.is_some() {
                ExitReason::Exited
            } else if signal.is_some() {
                ExitReason::Signaled
            } else {
                ExitReason::Lost
            };
            (code, signal, reason)
        }
        Err(_) => (None, None, ExitReason::Lost),
    }
}

async fn capture_output(
    master: Arc<AsyncFd<OwnedFd>>,
    bus: Arc<EventBus>,
    correlation: Correlation,
    chunk_size: usize,
) {
    let mut offset = StreamOffset::ZERO;
    let mut buf = vec![0u8; chunk_size.max(1)];
    loop {
        match pty::read(&master, &mut buf).await {
            Ok(0) => break,
            Ok(n) => {
                bus.publish(
                    &correlation,
                    CaptureMethod::Pty,
                    Confidence::Observed,
                    EventPayload::IoChunk(IoChunk {
                        stream: StreamKind::PtyOutput,
                        encoding: Encoding::Base64,
                        byte_count: n as u64,
                        stream_offset: offset,
                        content: Some(Base64Bytes::new(&buf[..n])),
                        artifact: None,
                        transform: None,
                    }),
                );
                offset = offset.advance(n as u64);
            }
            Err(e) if pty::is_eof_error(&e) => break,
            Err(_) => break,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use sealant_protocol::{EventEnvelope, EventPayload};
    use sealant_runtime_core::new_runtime_id;
    use tokio::sync::broadcast::Receiver;

    fn runtime() -> SessionRuntime {
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
        config.default_shell = "/bin/sh".to_owned();
        config.shutdown_grace_ms = 500;
        SessionRuntime {
            registry: Arc::new(SessionRegistry::new()),
            bus,
            idgen,
            status: Arc::new(RuntimeStatus::new()),
            clock,
            config: Arc::new(config),
        }
    }

    fn session_args(args: &[&str], cols: u16, rows: u16) -> OpenSessionArgs {
        OpenSessionArgs {
            execution_id: None,
            shell: Some("/bin/sh".to_owned()),
            args: args.iter().map(|s| (*s).to_owned()).collect(),
            cwd: None,
            env: vec![],
            cols,
            rows,
            term: None,
        }
    }

    async fn output_until_exit(rx: &mut Receiver<EventEnvelope>) -> Vec<u8> {
        let mut out = Vec::new();
        loop {
            let env = tokio::time::timeout(Duration::from_secs(5), rx.recv())
                .await
                .expect("no timeout")
                .expect("event");
            match env.payload {
                EventPayload::IoChunk(c) if c.stream == StreamKind::PtyOutput => {
                    if let Some(content) = c.content {
                        out.extend_from_slice(content.as_slice());
                    }
                }
                EventPayload::ProcessExited(_) => break,
                _ => {}
            }
        }
        out
    }

    async fn wait_for_output(
        rx: &mut Receiver<EventEnvelope>,
        needle: &str,
        within: Duration,
    ) -> bool {
        let mut acc = String::new();
        let deadline = Instant::now() + within;
        loop {
            let remaining = deadline.saturating_duration_since(Instant::now());
            if remaining.is_zero() {
                return false;
            }
            match tokio::time::timeout(remaining, rx.recv()).await {
                Ok(Ok(env)) => {
                    if let EventPayload::IoChunk(c) = &env.payload
                        && c.stream == StreamKind::PtyOutput
                        && let Some(content) = &c.content
                    {
                        acc.push_str(&String::from_utf8_lossy(content.as_slice()));
                    }
                    if acc.contains(needle) {
                        return true;
                    }
                }
                _ => return false,
            }
        }
    }

    #[tokio::test]
    async fn session_runs_under_a_controlling_tty() {
        let rt = runtime();
        let mut rx = rt.bus.subscribe();
        let opened = rt
            .open(session_args(&["-c", "test -t 0 && echo ISTTY"], 80, 24))
            .expect("open");
        assert!(opened.session_id.as_str().starts_with("ses_"));
        let out = output_until_exit(&mut rx).await;
        assert!(
            String::from_utf8_lossy(&out).contains("ISTTY"),
            "stdin should be a tty; got {:?}",
            String::from_utf8_lossy(&out)
        );
        assert_eq!(rt.registry.len(), 0);
        assert_eq!(rt.status.counts().1, 0);
    }

    #[tokio::test]
    async fn initial_window_size_is_applied() {
        let rt = runtime();
        let mut rx = rt.bus.subscribe();
        rt.open(session_args(&["-c", "stty size"], 120, 40))
            .expect("open");
        let out = output_until_exit(&mut rx).await;
        assert!(
            String::from_utf8_lossy(&out).contains("40 120"),
            "stty size should report rows cols; got {:?}",
            String::from_utf8_lossy(&out)
        );
    }

    #[tokio::test]
    async fn pty_output_is_binary_safe() {
        let rt = runtime();
        let mut rx = rt.bus.subscribe();
        rt.open(session_args(&["-c", r"printf '\000\377AB'"], 80, 24))
            .expect("open");
        let out = output_until_exit(&mut rx).await;
        assert!(
            out.windows(4).any(|w| w == [0x00, 0xff, b'A', b'B']),
            "raw bytes should round-trip; got {out:?}"
        );
    }

    #[tokio::test]
    async fn resize_propagates_and_close_releases() {
        let rt = runtime();
        let mut rx = rt.bus.subscribe();
        let opened = rt.open(session_args(&[], 80, 24)).expect("open");

        rt.write_input(&opened.session_id, b"stty size\n")
            .await
            .expect("write");
        assert!(
            wait_for_output(&mut rx, "24 80", Duration::from_secs(4)).await,
            "initial size 24 80 expected"
        );

        rt.resize(&opened.session_id, 132, 50).expect("resize");
        rt.write_input(&opened.session_id, b"stty size\n")
            .await
            .expect("write");
        assert!(
            wait_for_output(&mut rx, "50 132", Duration::from_secs(4)).await,
            "resized size 50 132 expected"
        );

        rt.close(&opened.session_id).expect("close");
        let mut released = false;
        for _ in 0..200 {
            if rt.registry.is_empty() {
                released = true;
                break;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        assert!(released, "session resources should be released after close");
        assert_eq!(rt.status.counts().1, 0);
    }
}
