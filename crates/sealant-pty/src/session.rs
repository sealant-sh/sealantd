//! Interactive session lifecycle: registry, open/write/resize/close, and output capture.

use std::collections::HashMap;
use std::io;
use std::os::fd::OwnedFd;
use std::os::unix::process::ExitStatusExt;
use std::sync::Mutex;
use std::sync::atomic::{AtomicU16, Ordering};
use std::sync::{Arc, Weak};
use std::time::{Duration, Instant};

use nix::sys::signal::Signal as NixSignal;
use nix::unistd::Pid;
use sealant_process::SessionMark;
use sealant_protocol::SESSION_ENV;
use sealant_protocol::{
    Base64Bytes, CaptureMethod, ChannelId, Confidence, ControlError, EventPayload, ExecutionId,
    ExitReason, OpenSessionArgs, ProcessExited, ProcessId, ProcessStarted, ServerMessage,
    SessionId, SessionList, SessionMode, SessionOpened, SessionOutput, SessionOutputChunk,
    SessionState, SessionSummary, Signal, StreamEnd, StreamFrame, StreamKind,
};
use sealant_runtime_core::{
    Clock, FinishReason, IdGenerator, MaskedChunk, Redactor, RuntimeConfig, RuntimeStatus,
    new_secret,
};
use sealant_telemetry::{Correlation, EventBus, StreamRecorder};
use tokio::io::unix::AsyncFd;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWriteExt};
use tokio::process::{ChildStderr, ChildStdin, ChildStdout};
use tokio::sync::{mpsc, oneshot, watch};

use crate::journal::SessionJournal;
use crate::pipe::{self, PipeChild};
use crate::pty::{self, PtyChild};

/// Default terminal type advertised to the child when the caller does not specify one.
const DEFAULT_TERM: &str = "xterm-256color";

/// A reliable per-session output attachment: bytes from the PTY are pushed to one gateway
/// connection's backpressured outbound queue (distinct from the lossy telemetry `IoChunk`
/// broadcast). Awaiting `out_tx.send(...)` is the backpressure; the kernel PTY buffer throttles the
/// shell when the gateway is slow.
///
/// There is exactly one PTY reader per session (the capture loop). It fans each chunk out to both
/// the telemetry bus and, when an attachment is present, this sink — so attach and telemetry share a
/// single `read()` and the attach stream is lossless (no second reader racing for the same bytes).
#[derive(Debug, Clone)]
pub struct ChannelSink {
    /// The channel id the gateway attached.
    pub channel_id: ChannelId,
    /// The connection's backpressured outbound queue.
    pub out_tx: mpsc::Sender<ServerMessage>,
    /// Gate for live fan-out: held false while an attach is replaying journal history, so live
    /// frames never interleave with replayed ones.
    ready: watch::Receiver<bool>,
    /// Keeps the gate's sender alive for the sink's lifetime (a dropped sender reads as open).
    _ready_tx: Arc<watch::Sender<bool>>,
    /// First journal sequence this sink should receive live (earlier ones were replayed).
    start_seq: Arc<std::sync::atomic::AtomicU64>,
}

/// The leader's input side, by session mode. Output is owned by the capture task in both modes.
#[derive(Debug)]
pub enum LeaderIo {
    /// PTY: the master, owned by capture and borrowed by input and resize while the leader lives.
    Pty {
        /// The PTY master.
        master: Weak<AsyncFd<OwnedFd>>,
    },
    /// Pipe: the child's stdin, held until the leader exits (or the pipe breaks).
    Pipe {
        /// The stdin pipe; `None` once it has been closed.
        stdin: tokio::sync::Mutex<Option<ChildStdin>>,
    },
}

/// A live session: a leader running under a PTY or over plain pipes.
#[derive(Debug)]
pub struct SessionEntry {
    /// Session id.
    pub session_id: SessionId,
    /// Logical process id of the session leader.
    pub process_id: ProcessId,
    /// OS pid of the session leader (also its session id / process-group id).
    pub pid: i32,
    /// How the leader is wired.
    pub mode: SessionMode,
    /// The leader's input path (and, for PTY, the resize handle).
    pub io: LeaderIo,
    /// Associated execution, when any.
    pub execution_id: Option<ExecutionId>,
    /// The reliable output attachment, when a gateway has attached.
    pub attached: Mutex<Option<ChannelSink>>,
    /// The durable, redacted output journal (the reattach/scrollback read surface).
    pub journal: Arc<Mutex<SessionJournal>>,
    /// Wall-clock start time (unix micros).
    pub started_at_micros: i64,
    /// `Some((exit_code, signal))` once the leader has exited.
    exit: Mutex<Option<(Option<i32>, Option<i32>)>>,
    /// True from the moment the leader is reaped, before its output has drained.
    exited: watch::Sender<bool>,
    /// Who the leader runs as, and the secret its processes carry in [`SESSION_ENV`].
    mark: SessionMark,
    /// The masked record of forwarded input. Held across each write and its record, so the record
    /// keeps the order the leader got the bytes in; `None` once the leader exited.
    input: tokio::sync::Mutex<Option<StreamRecorder>>,
    cols: AtomicU16,
    rows: AtomicU16,
}

impl SessionEntry {
    /// Lifecycle state plus exit codes, when exited.
    #[must_use]
    pub fn exit_status(&self) -> Option<(Option<i32>, Option<i32>)> {
        *self.exit.lock().unwrap_or_else(|e| e.into_inner())
    }

    fn mark_exited(&self, exit_code: Option<i32>, signal: Option<i32>) {
        *self.exit.lock().unwrap_or_else(|e| e.into_inner()) = Some((exit_code, signal));
        self.exited.send_replace(true);
    }

    /// Whether the leader has exited: true as soon as it is reaped, which can be well before
    /// [`SessionEntry::exit_status`] says so, once its output has drained.
    #[must_use]
    pub fn exit_watch(&self) -> watch::Receiver<bool> {
        self.exited.subscribe()
    }

    /// Who the leader runs as and the marker its processes carry.
    #[must_use]
    pub fn mark(&self) -> SessionMark {
        self.mark.clone()
    }

    /// A summary of this session.
    #[must_use]
    pub fn summary(&self) -> SessionSummary {
        let exit = self.exit_status();
        let (first_seq, next_seq) = {
            let journal = self.journal.lock().unwrap_or_else(|e| e.into_inner());
            (journal.first_seq(), journal.next_seq())
        };
        SessionSummary {
            session_id: self.session_id.clone(),
            process_id: self.process_id.clone(),
            pid: self.pid,
            cols: self.cols.load(Ordering::Relaxed),
            rows: self.rows.load(Ordering::Relaxed),
            execution_id: self.execution_id.clone(),
            state: if exit.is_some() {
                SessionState::Exited
            } else {
                SessionState::Running
            },
            exit_code: exit.and_then(|(code, _)| code),
            signal: exit.and_then(|(_, sig)| sig),
            started_at_micros: self.started_at_micros,
            first_journal_sequence: first_seq,
            next_journal_sequence: next_seq,
            mode: self.mode,
        }
    }
}

/// Cap on retained exited-session tombstones; the oldest is evicted (journal files deleted).
const MAX_FINISHED_SESSIONS: usize = 128;

/// Thread-safe registry of interactive sessions.
///
/// Running sessions live in `running`; when a leader exits its entry moves to `finished` as a
/// tombstone (state, exit code, journal) so clients can still observe the exit and replay the
/// scrollback. Tombstones are dropped on an explicit `closeSession` or by FIFO eviction.
#[derive(Debug, Default)]
pub struct SessionRegistry {
    inner: Mutex<HashMap<SessionId, Arc<SessionEntry>>>,
    finished: Mutex<Vec<Arc<SessionEntry>>>,
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

    fn lock_finished(&self) -> std::sync::MutexGuard<'_, Vec<Arc<SessionEntry>>> {
        self.finished.lock().unwrap_or_else(|e| e.into_inner())
    }

    fn insert(&self, entry: Arc<SessionEntry>) {
        self.lock().insert(entry.session_id.clone(), entry);
    }

    /// Look up a session — running first, then exited tombstones.
    #[must_use]
    pub fn get(&self, id: &SessionId) -> Option<Arc<SessionEntry>> {
        if let Some(entry) = self.lock().get(id).cloned() {
            return Some(entry);
        }
        self.lock_finished()
            .iter()
            .find(|e| &e.session_id == id)
            .cloned()
    }

    /// Look up a *running* session only.
    #[must_use]
    pub fn get_running(&self, id: &SessionId) -> Option<Arc<SessionEntry>> {
        self.lock().get(id).cloned()
    }

    /// Move a running session to the finished tombstones (evicting the oldest beyond the cap).
    fn finish(&self, id: &SessionId) -> Option<Arc<SessionEntry>> {
        let entry = self.lock().remove(id)?;
        let mut finished = self.lock_finished();
        finished.push(entry.clone());
        if finished.len() > MAX_FINISHED_SESSIONS {
            let evicted = finished.remove(0);
            evicted
                .journal
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .remove_files();
        }
        Some(entry)
    }

    /// Drop an exited session's tombstone (and its journal files). Returns whether one existed.
    fn remove_finished(&self, id: &SessionId) -> bool {
        let mut finished = self.lock_finished();
        let Some(pos) = finished.iter().position(|e| &e.session_id == id) else {
            return false;
        };
        let removed = finished.remove(pos);
        removed
            .journal
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .remove_files();
        true
    }

    /// Number of running sessions.
    #[must_use]
    pub fn len(&self) -> usize {
        self.lock().len()
    }

    /// Whether there are no running sessions.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.lock().is_empty()
    }

    /// Summaries of all sessions: running first, then retained exited tombstones.
    #[must_use]
    pub fn list(&self) -> Vec<SessionSummary> {
        let mut out: Vec<SessionSummary> = self.lock().values().map(|e| e.summary()).collect();
        out.extend(self.lock_finished().iter().map(|e| e.summary()));
        out
    }

    /// Snapshot of all running session entries.
    #[must_use]
    pub fn entries(&self) -> Vec<Arc<SessionEntry>> {
        self.lock().values().cloned().collect()
    }

    /// All running session leader pids.
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
    /// Extra environment injected into every session child last (e.g. egress-proxy routing).
    pub extra_env: Arc<std::sync::Mutex<Vec<(String, String)>>>,
    /// Secret redaction applied to output before it reaches the journal, telemetry, or a sink.
    pub redactor: Arc<Redactor>,
}

/// After `close()` sends the hangup, how long the leader may linger before its group is killed.
const CLOSE_KILL_GRACE: Duration = Duration::from_secs(2);

fn signal_session(pid: i32, signal: NixSignal) {
    // The session leader is its own process-group leader (setsid), so signal the whole group.
    let _ = nix::sys::signal::killpg(Pid::from_raw(pid), signal);
}

/// Map a protocol signal onto the host signal for group delivery.
fn to_nix_signal(signal: Signal) -> NixSignal {
    match signal {
        Signal::Hup => NixSignal::SIGHUP,
        Signal::Int => NixSignal::SIGINT,
        Signal::Quit => NixSignal::SIGQUIT,
        Signal::Term => NixSignal::SIGTERM,
        Signal::Kill => NixSignal::SIGKILL,
        Signal::Usr1 => NixSignal::SIGUSR1,
        Signal::Usr2 => NixSignal::SIGUSR2,
        Signal::Stop => NixSignal::SIGSTOP,
        Signal::Cont => NixSignal::SIGCONT,
    }
}

impl SessionRuntime {
    /// Open an interactive session.
    ///
    /// # Errors
    /// Returns a [`ControlError`] if the PTY cannot be allocated or the shell cannot start.
    pub fn open(&self, args: OpenSessionArgs) -> Result<SessionOpened, ControlError> {
        // Enforce the session limit before allocating a PTY; overflow is rejected cleanly.
        let active = self.status.counts().1;
        if active >= self.config.limits.max_sessions {
            return Err(ControlError::new(
                sealant_protocol::ControlErrorCode::PolicyDenied,
                format!(
                    "session limit reached ({}/{})",
                    active, self.config.limits.max_sessions
                ),
            ));
        }
        let shell = args
            .shell
            .clone()
            .unwrap_or_else(|| self.config.default_shell.clone());
        let cwd = args
            .cwd
            .clone()
            .map_or_else(|| self.config.workspace_root.clone(), Into::into);
        let term = args.term.clone().unwrap_or_else(|| DEFAULT_TERM.to_owned());
        // A named user: resolved here and admitted only if the runtime's people include it,
        // its private directories made, its identity set in the leader before exec
        // ([`sealant_process::identity`]).
        let run_as = args
            .user
            .as_deref()
            .map(|user| sealant_process::identity::RunAs::resolve(user, &self.config.people))
            .transpose()
            .map_err(ControlError::invalid_argument)?;
        if let Some(user) = &run_as {
            user.prepare_dirs().map_err(|e| {
                ControlError::new(
                    sealant_protocol::ControlErrorCode::ProcessStartFailed,
                    format!("the private directories of user {}: {e}", user.name),
                )
            })?;
        }
        // A person's leader inherits none of the launcher's tokens or the daemon's own keys.
        let inherited = |key: &str| {
            run_as.is_none()
                || !(sealant_process::identity::withheld_from_person(key)
                    || self.config.person_withheld.iter().any(|k| k == key))
        };
        let mut env: Vec<(String, String)> = self
            .config
            .child_env
            .iter()
            .filter(|v| inherited(&v.key))
            .map(|v| (v.key.clone(), v.value.clone()))
            .collect();
        // The user's identity over the daemon's child environment and the image's person
        // environment (`sealant_process::identity::PERSON_ENV_FILE`), under the caller's overlay.
        if let Some(user) = &run_as {
            let base_path = env
                .iter()
                .rev()
                .find(|(key, _)| key == "PATH")
                .map(|(_, value)| value.clone());
            env.extend(sealant_process::identity::person_env(base_path.as_deref()));
            env.extend(user.env());
        }
        env.extend(args.env.iter().map(|v| (v.key.clone(), v.value.clone())));
        env.extend(
            self.extra_env
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .iter()
                .filter(|(key, _)| inherited(key))
                .cloned(),
        );
        let marker = new_secret().map_err(|e| {
            ControlError::internal(format!("no secret for the session's marker: {e}"))
        })?;
        env.retain(|(key, _)| key != SESSION_ENV);
        env.push((SESSION_ENV.to_owned(), marker.clone()));
        let (uid, gid) = run_as.as_ref().map_or_else(
            || {
                (
                    nix::unistd::geteuid().as_raw(),
                    nix::unistd::getegid().as_raw(),
                )
            },
            |user| (user.uid, user.gid),
        );

        // Spawn the leader in the requested shape. Both shapes yield a child to wait on, an input
        // handle for `write_input`, and an output source for the single capture reader.
        let (child, pid, spawned_pid, io, outputs, method) = match args.mode {
            SessionMode::Pty => {
                let PtyChild {
                    master,
                    child,
                    pid,
                    spawned,
                } = pty::spawn(
                    &shell,
                    &args.args,
                    &cwd,
                    &env,
                    (args.cols, args.rows),
                    &term,
                    run_as.as_ref(),
                )
                .map_err(|e| {
                    ControlError::new(
                        sealant_protocol::ControlErrorCode::PtyAllocationFailed,
                        format!("{shell}: {e}"),
                    )
                })?;
                let master = Arc::new(master);
                (
                    child,
                    pid,
                    spawned,
                    LeaderIo::Pty {
                        master: Arc::downgrade(&master),
                    },
                    LeaderOutputs::Pty { master },
                    CaptureMethod::Pty,
                )
            }
            SessionMode::Pipe => {
                let PipeChild {
                    stdin,
                    stdout,
                    stderr,
                    child,
                    pid,
                    spawned,
                } = pipe::spawn(&shell, &args.args, &cwd, &env, run_as.as_ref()).map_err(|e| {
                    ControlError::new(
                        sealant_protocol::ControlErrorCode::ProcessStartFailed,
                        format!("{shell}: {e}"),
                    )
                })?;
                (
                    child,
                    pid,
                    spawned,
                    LeaderIo::Pipe {
                        stdin: tokio::sync::Mutex::new(Some(stdin)),
                    },
                    LeaderOutputs::Pipe { stdout, stderr },
                    CaptureMethod::Pipe,
                )
            }
        };

        let session_id = self.idgen.session_id();
        let process_id = self.idgen.process_id();
        let execution_id = args
            .execution_id
            .clone()
            .or_else(|| self.config.default_execution_id.clone());

        // The durable output journal is a product guarantee (reattach + scrollback); a session
        // that cannot journal must not open.
        let journal_dir = self.config.session_journal_dir.clone().unwrap_or_else(|| {
            std::env::temp_dir().join(format!("sealantd-journals-{}", self.config.runtime_id))
        });
        let journal = SessionJournal::create(
            &journal_dir,
            session_id.as_str(),
            self.config.session_journal_segment_bytes,
        )
        .map_err(|e| {
            signal_session(pid, NixSignal::SIGKILL);
            ControlError::internal(format!(
                "session journal create failed under {}: {e}",
                journal_dir.display()
            ))
        })?;

        // A PTY echoes a multi-line secret with CRLF line ends, and a terminal sends one typed or
        // pasted with CR. Output, pipe stderr and input each mask through their own state.
        let (patterns, input_patterns) = match args.mode {
            SessionMode::Pty => (
                Arc::new(self.redactor.with_line_ends(b"\r\n")),
                Arc::new(self.redactor.with_line_ends(b"\r")),
            ),
            SessionMode::Pipe => (self.redactor.clone(), self.redactor.clone()),
        };
        let correlation = Correlation::new()
            .execution(execution_id.clone())
            .session(Some(session_id.clone()))
            .process(process_id.clone());
        let (input_method, input_stream) = match args.mode {
            SessionMode::Pty => (CaptureMethod::Pty, StreamKind::PtyInput),
            SessionMode::Pipe => (CaptureMethod::Pipe, StreamKind::Stdin),
        };
        let entry = Arc::new(SessionEntry {
            session_id: session_id.clone(),
            process_id: process_id.clone(),
            pid,
            mode: args.mode,
            io,
            execution_id: execution_id.clone(),
            attached: Mutex::new(None),
            journal: Arc::new(Mutex::new(journal)),
            started_at_micros: self.clock.wall_now().get(),
            exit: Mutex::new(None),
            exited: watch::Sender::new(false),
            mark: SessionMark { uid, gid, marker },
            input: tokio::sync::Mutex::new(Some(StreamRecorder::new(
                self.bus.clone(),
                self.status.clone(),
                correlation.clone(),
                input_method,
                input_stream,
                input_patterns.stream(),
            ))),
            cols: AtomicU16::new(args.cols),
            rows: AtomicU16::new(args.rows),
        });
        self.registry.insert(entry.clone());
        self.status.inc_sessions();

        self.bus.publish(
            &correlation,
            method,
            Confidence::Observed,
            // The arguments' count and lengths, never their text: they can carry secrets.
            EventPayload::ProcessStarted(ProcessStarted::new(
                pid,
                pid,
                false,
                shell,
                &args.args,
                cwd.display().to_string(),
                self.clock.wall_now(),
            )),
        );

        // Capture the leader's output until it closes or the leader exits. This is the SINGLE
        // output reader per session: it publishes every chunk as `IoChunk` telemetry and, when a
        // gateway is attached, also forwards the same chunk to the attach sink (sharing one read so
        // the attach stream is lossless). PTY: the master. Pipe: stdout — stderr gets its own
        // telemetry-only reader so diagnostics never interleave with the protocol stream.
        let fanout = Fanout {
            bus: self.bus.clone(),
            correlation: correlation.clone(),
            entry: entry.clone(),
            redactor: patterns,
            status: self.status.clone(),
        };
        let chunk_size = self.config.io_chunk_bytes;
        let (leader_exited_tx, leader_exited_rx) = oneshot::channel();
        let capture = match outputs {
            LeaderOutputs::Pty { master } => tokio::spawn(async move {
                capture_output(
                    master,
                    chunk_size,
                    CaptureContext {
                        fanout,
                        leader_exited_rx,
                    },
                )
                .await;
            }),
            // Stdout and stderr drain side by side, and both end before the exit is published.
            LeaderOutputs::Pipe { stdout, stderr } => tokio::spawn(async move {
                tokio::join!(
                    capture_pipe_output(stdout, chunk_size, fanout.clone()),
                    capture_stderr(stderr, chunk_size, fanout),
                );
            }),
        };

        // Wait for the leader to exit, then publish the final result.
        let waiter_bus = self.bus.clone();
        let waiter_registry = self.registry.clone();
        let waiter_status = self.status.clone();
        let waiter_session = session_id.clone();
        let waiter_entry = entry.clone();
        let mut child = child;
        tokio::spawn(async move {
            let start = Instant::now();
            let status_result = child.wait().await;
            // Forwards bound to the session end now, not once its output has drained, which an
            // attached client that stopped reading can hold up indefinitely.
            waiter_entry.exited.send_replace(true);
            // Reaped: hand the pid back to the orphan reaper before anything slower runs.
            drop(spawned_pid);
            let _ = leader_exited_tx.send(());
            let _ = capture.await;
            // No input is forwarded once the leader exited: the input stream is cut, and what the
            // record still holds is masked if it could begin a secret, before the exit. No
            // tombstone keeps the mask patterns.
            let input = waiter_entry.input.lock().await.take();
            if let Some(mut recorder) = input {
                recorder.end(FinishReason::Cutoff);
            }
            let (exit_code, signal, reason) = classify(&status_result);
            waiter_bus.publish(
                &correlation,
                method,
                Confidence::Observed,
                EventPayload::ProcessExited(ProcessExited {
                    exit_code,
                    signal,
                    reason,
                    duration_micros: start.elapsed().as_micros() as u64,
                }),
            );
            // `capture.await` above drained all bytes available when the leader exited, fanning
            // every chunk to both the telemetry bus AND the attach sink (single reader). Do not
            // wait for helper processes that inherited the slave: the session belongs to its
            // leader. Send a final End{exit_code, signal} and clear the attachment.
            // The entry itself becomes an exited tombstone (state + exit code + journal) so
            // clients can still observe the exit and replay the scrollback after the fact.
            let entry = waiter_registry.get_running(&waiter_session);
            if let Some(entry) = &entry {
                entry.mark_exited(exit_code, signal);
            }
            waiter_registry.finish(&waiter_session);
            if let Some(entry) = entry {
                let sink = entry
                    .attached
                    .lock()
                    .unwrap_or_else(|e| e.into_inner())
                    .take();
                if let Some(sink) = sink {
                    let frame = StreamFrame::end(
                        sink.channel_id.clone(),
                        u64::MAX,
                        StreamEnd {
                            exit_code,
                            signal,
                            error: None,
                        },
                    );
                    let _ = sink.out_tx.send(ServerMessage::Stream(frame)).await;
                }
            }
            waiter_status.dec_sessions();
        });

        Ok(SessionOpened {
            session_id,
            process_id,
            pid,
        })
    }

    /// Write bytes to a session's input: the PTY master, or the leader's stdin pipe.
    ///
    /// # Errors
    /// Returns a [`ControlError`] if the session is unknown, its leader exited, or the write fails.
    pub async fn write_input(
        &self,
        session_id: &SessionId,
        data: &[u8],
    ) -> Result<(), ControlError> {
        let entry = self
            .registry
            .get_running(session_id)
            .ok_or_else(|| ControlError::session_not_found(session_id.to_string()))?;
        let mut input = entry.input.lock().await;
        let mut exited = entry.exit_watch();
        // A leader that exited takes no input, even while its output still drains and a helper
        // holds its input open.
        let Some(recorder) = input.as_mut().filter(|_| !*exited.borrow()) else {
            return Err(ControlError::session_not_found(session_id.to_string()));
        };
        // Each part the leader accepts is recorded as it is written, so what was forwarded is in
        // the record even when the rest fails. A write the leader's exit leaves blocked (a helper
        // holds the input and never reads) is abandoned, so it cannot hold the record open.
        let mut rest = data;
        while !rest.is_empty() {
            let written = tokio::select! {
                biased;
                _ = exited.wait_for(|exited| *exited) => {
                    Err(ControlError::session_not_found(session_id.to_string()))
                }
                written = forward_input(&entry, session_id, rest) => written,
            };
            match written {
                Ok(n) => {
                    recorder.read(&rest[..n]);
                    rest = &rest[n..];
                }
                Err(error) => {
                    // The input stream was cut: what the record holds could begin a secret.
                    recorder.end(FinishReason::Cutoff);
                    return Err(error);
                }
            }
        }
        Ok(())
    }

    /// Attach a reliable output channel to a session's PTY.
    ///
    /// The single PTY reader (the capture loop, [`capture_output`]) fans each chunk out to both the
    /// telemetry bus and this sink: instead of relying on the lossy `IoChunk` broadcast, the attach
    /// sink receives each chunk as a [`StreamFrame::Data`] via an **awaited** `out_tx.send`. Awaiting
    /// that send is the backpressure — the capture loop only issues its next `pty::read` once the
    /// gateway has accepted the chunk, so a slow gateway throttles the PTY drain and the kernel PTY
    /// buffer backpressures the shell. This is the exact inversion of the lossy `Lagged`-drop path.
    ///
    /// Re-attaching replaces the prior attachment (the old gateway simply stops receiving frames).
    ///
    /// With `from_sequence`, the durable journal is replayed first — data frames carry journal
    /// sequences, so `[from, live)` is delivered exactly once and in order before live output.
    /// Attaching to an *exited* session replays the retained scrollback and then sends the final
    /// `End{exit_code, signal}` frame.
    ///
    /// # Errors
    /// Returns a [`ControlError`] if the session is unknown.
    pub async fn attach(
        &self,
        session_id: &SessionId,
        channel_id: ChannelId,
        out_tx: mpsc::Sender<ServerMessage>,
        from_sequence: Option<u64>,
    ) -> Result<(), ControlError> {
        let entry = self
            .registry
            .get(session_id)
            .ok_or_else(|| ControlError::session_not_found(session_id.to_string()))?;

        if let Some((exit_code, signal)) = entry.exit_status() {
            // Exited tombstone: replay-only, no live sink to install.
            if let Some(from) = from_sequence {
                replay_journal(&entry, &channel_id, &out_tx, from).await;
            }
            let frame = StreamFrame::end(
                channel_id,
                u64::MAX,
                StreamEnd {
                    exit_code,
                    signal,
                    error: None,
                },
            );
            let _ = out_tx.send(ServerMessage::Stream(frame)).await;
            return Ok(());
        }

        let Some(from) = from_sequence else {
            // Live tail only: the sink is ready immediately and receives every chunk from now on.
            let (ready_tx, ready_rx) = watch::channel(true);
            *entry.attached.lock().unwrap_or_else(|e| e.into_inner()) = Some(ChannelSink {
                channel_id,
                out_tx,
                ready: ready_rx,
                _ready_tx: Arc::new(ready_tx),
                start_seq: Arc::new(std::sync::atomic::AtomicU64::new(0)),
            });
            return Ok(());
        };

        // Replay + live: install the sink gated closed so the capture loop journals but does not
        // fan out; snapshot the journal end (nothing at/after it has been sent — the gate was
        // closed before the snapshot); replay [from, end); then open the gate. The capture loop
        // skips live chunks below `start_seq` (they were part of the replayed range).
        let (ready_tx, ready_rx) = watch::channel(false);
        let ready_tx = Arc::new(ready_tx);
        let start_seq = Arc::new(std::sync::atomic::AtomicU64::new(u64::MAX));
        *entry.attached.lock().unwrap_or_else(|e| e.into_inner()) = Some(ChannelSink {
            channel_id: channel_id.clone(),
            out_tx: out_tx.clone(),
            ready: ready_rx,
            _ready_tx: ready_tx.clone(),
            start_seq: start_seq.clone(),
        });
        let upper = entry
            .journal
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .next_seq();
        start_seq.store(upper, Ordering::SeqCst);
        replay_journal_until(&entry, &channel_id, &out_tx, from, upper).await;
        let _ = ready_tx.send(true);
        Ok(())
    }

    /// Whether the session currently has no reliable output attachment.
    ///
    /// A missing session counts as clear. Used to observe connection-scoped teardown: after a
    /// gateway connection drops, the capture loop clears a stale (closed) attachment.
    #[must_use]
    pub fn attachment_is_clear(&self, session_id: &SessionId) -> bool {
        self.registry.get(session_id).is_none_or(|entry| {
            entry
                .attached
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .is_none()
        })
    }

    /// Detach a session's reliable output channel by channel id.
    ///
    /// Idempotent: detaching an unknown/stale channel is a no-op. The capture loop simply stops
    /// fanning out once the attachment is cleared.
    pub fn detach(&self, channel_id: &ChannelId) {
        for entry in self.registry.entries() {
            let mut guard = entry.attached.lock().unwrap_or_else(|e| e.into_inner());
            if guard
                .as_ref()
                .is_some_and(|sink| &sink.channel_id == channel_id)
            {
                *guard = None;
                return;
            }
        }
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
        let LeaderIo::Pty { master } = &entry.io else {
            return Err(ControlError::invalid_argument(
                "pipe-mode session has no terminal to resize".to_owned(),
            ));
        };
        let master = master
            .upgrade()
            .ok_or_else(|| ControlError::session_not_found(session_id.to_string()))?;
        pty::resize(&master, cols, rows)
            .map_err(|e| ControlError::invalid_argument(format!("pty resize failed: {e}")))?;
        entry.cols.store(cols, Ordering::Relaxed);
        entry.rows.store(rows, Ordering::Relaxed);
        Ok(())
    }

    /// Close a session. Running: hang up its terminal (SIGHUP; the wait task publishes the exit
    /// and leaves an exited tombstone). Exited: drop the tombstone and its journal files.
    ///
    /// # Errors
    /// Returns a [`ControlError`] if the session is unknown.
    pub fn close(&self, session_id: &SessionId) -> Result<(), ControlError> {
        if let Some(entry) = self.registry.get_running(session_id) {
            signal_session(entry.pid, NixSignal::SIGHUP);
            // SIGHUP alone is not a reliable teardown: an interactive shell parked at its prompt
            // can absorb it without exiting (dash, for one, defers pending-signal processing
            // until the current input read completes — a read that will never complete once the
            // client is gone). A close means "this session ends", so escalate to SIGKILL after a
            // grace window if the leader is still running — same ladder as `terminate_all`.
            let registry = self.registry.clone();
            let session_id = session_id.clone();
            let pid = entry.pid;
            tokio::spawn(async move {
                tokio::time::sleep(CLOSE_KILL_GRACE).await;
                if registry
                    .get_running(&session_id)
                    .is_some_and(|entry| entry.pid == pid)
                {
                    signal_session(pid, NixSignal::SIGKILL);
                }
            });
            return Ok(());
        }
        if self.registry.remove_finished(session_id) {
            return Ok(());
        }
        Err(ControlError::session_not_found(session_id.to_string()))
    }

    /// Deliver a signal to a running session's process group.
    ///
    /// # Errors
    /// Returns a [`ControlError`] if the session is unknown or already exited.
    pub fn signal(&self, session_id: &SessionId, signal: Signal) -> Result<(), ControlError> {
        let entry = self
            .registry
            .get_running(session_id)
            .ok_or_else(|| ControlError::session_not_found(session_id.to_string()))?;
        signal_session(entry.pid, to_nix_signal(signal));
        Ok(())
    }

    /// Read a batch of a session's durable output journal from `from_sequence` (clamped to the
    /// first retained record), bounded by `max_bytes` of payload.
    ///
    /// # Errors
    /// Returns a [`ControlError`] if the session is unknown (running and exited both read fine).
    pub fn read_output(
        &self,
        session_id: &SessionId,
        from_sequence: u64,
        max_bytes: Option<u64>,
    ) -> Result<SessionOutput, ControlError> {
        /// Per-response payload cap: stay comfortably under the control frame limit.
        const DEFAULT_MAX_BYTES: u64 = 1024 * 1024;
        let entry = self
            .registry
            .get(session_id)
            .ok_or_else(|| ControlError::session_not_found(session_id.to_string()))?;
        let budget = max_bytes
            .unwrap_or(DEFAULT_MAX_BYTES)
            .clamp(1, DEFAULT_MAX_BYTES);
        let exit = entry.exit_status();
        let (chunks, first_available, journal_end) = {
            let journal = entry.journal.lock().unwrap_or_else(|e| e.into_inner());
            (
                journal.read_from(from_sequence, budget),
                journal.first_seq(),
                journal.next_seq(),
            )
        };
        let next_sequence = chunks.last().map_or_else(
            || from_sequence.clamp(first_available, journal_end),
            |c| c.sequence + 1,
        );
        Ok(SessionOutput {
            session_id: session_id.clone(),
            chunks: chunks
                .into_iter()
                .map(|c| SessionOutputChunk {
                    sequence: c.sequence,
                    data: Base64Bytes::new(c.data),
                })
                .collect(),
            next_sequence,
            first_available_sequence: first_available,
            state: if exit.is_some() {
                SessionState::Exited
            } else {
                SessionState::Running
            },
            exit_code: exit.and_then(|(code, _)| code),
            signal: exit.and_then(|(_, sig)| sig),
        })
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

/// Write a first part of `data` to the leader (the PTY master, or its stdin pipe), returning how
/// many bytes it took.
async fn forward_input(
    entry: &SessionEntry,
    session_id: &SessionId,
    data: &[u8],
) -> Result<usize, ControlError> {
    match &entry.io {
        LeaderIo::Pty { master } => {
            let master = master
                .upgrade()
                .ok_or_else(|| ControlError::session_not_found(session_id.to_string()))?;
            pty::write(&master, data)
                .await
                .map_err(|e| ControlError::invalid_argument(format!("pty input write failed: {e}")))
        }
        LeaderIo::Pipe { stdin } => {
            let mut guard = stdin.lock().await;
            let Some(pipe) = guard.as_mut() else {
                return Err(ControlError::invalid_argument(
                    "session stdin is closed".to_owned(),
                ));
            };
            let written = match pipe.write(data).await {
                Ok(0) => Err(io::ErrorKind::WriteZero.into()),
                written => written,
            };
            if let Err(e) = &written {
                // A broken pipe means the leader stopped reading; drop our end so the next
                // write fails fast instead of blocking on a dead reader.
                if e.kind() == io::ErrorKind::BrokenPipe {
                    *guard = None;
                }
            }
            written.map_err(|e| ControlError::invalid_argument(format!("stdin write failed: {e}")))
        }
    }
}

/// The single PTY reader for a session. Reads `pty.output` until the slave closes or the session
/// leader exits and, for each chunk, (a) publishes a lossy `IoChunk` telemetry event
/// (recording/redaction path) and (b), when a gateway is attached, forwards the same bytes to the
/// attach sink as a [`StreamFrame::Data`] via an **awaited** `out_tx.send`.
///
/// Because there is exactly one reader, the attach sink sees every byte (no second reader racing for
/// the fd). Awaiting the attach send applies backpressure to this loop: the next `pty::read` waits
/// until the gateway accepts the chunk, so a slow gateway throttles the PTY drain and the kernel PTY
/// buffer backpressures the shell — the inversion of the lossy `Lagged`-drop path. Telemetry
/// publish stays non-blocking (it may drop on lag, as before); only the attach send blocks.
/// The leader's output source, handed to the capture reader at open.
enum LeaderOutputs {
    Pty {
        master: Arc<AsyncFd<OwnedFd>>,
    },
    Pipe {
        stdout: ChildStdout,
        stderr: ChildStderr,
    },
}

/// Everything a captured chunk fans out to: the durable journal, the telemetry tap, and the
/// reliable attach sink, plus the patterns each reader masks its own stream with. Shared by the
/// PTY and pipe readers so both modes have exactly the same delivery guarantees.
#[derive(Clone)]
struct Fanout {
    bus: Arc<EventBus>,
    correlation: Correlation,
    entry: Arc<SessionEntry>,
    redactor: Arc<Redactor>,
    status: Arc<RuntimeStatus>,
}

struct CaptureContext {
    fanout: Fanout,
    leader_exited_rx: oneshot::Receiver<()>,
}

impl Fanout {
    /// A recorder for one of the session's output streams, masking with its own state.
    fn recorder(&self, method: CaptureMethod, stream: StreamKind) -> StreamRecorder {
        StreamRecorder::new(
            self.bus.clone(),
            self.status.clone(),
            self.correlation.clone(),
            method,
            stream,
            self.redactor.stream(),
        )
    }

    /// Deliver the next raw output bytes: masked once, journaled (minting the wire sequence), then
    /// published as telemetry, then forwarded to the attach sink with backpressure.
    async fn deliver(&self, recorder: &mut StreamRecorder, raw: &[u8]) {
        let (chunk, seq) = recorder.read_journaled(raw, |chunk| self.journal(chunk));
        self.attach(&chunk, seq).await;
    }

    /// Deliver what the output's masker still holds at its end, the same way.
    async fn finish(&self, recorder: &mut StreamRecorder, end: FinishReason) {
        let (chunk, seq) = recorder.end_journaled(end, |chunk| self.journal(chunk));
        self.attach(&chunk, seq).await;
    }

    /// Append a masked chunk to the durable journal; the sequence minted here is the wire
    /// sequence for both live frames and replays. A chunk that records nothing mints none.
    fn journal(&self, chunk: &MaskedChunk) -> Option<u64> {
        let entry = &self.entry;
        let seq = {
            let mut journal = entry.journal.lock().unwrap_or_else(|e| e.into_inner());
            journal.append(chunk)
        };
        seq.unwrap_or_else(|error| {
            tracing::error!(%error, session = %entry.session_id,
                "session journal append failed; output recording degraded");
            self.status.add_degradation("session-journal-append-failed");
            Some(u64::MAX)
        })
    }

    async fn attach(&self, chunk: &MaskedChunk, seq: Option<u64>) {
        let Some(seq) = seq else { return };
        let entry = &self.entry;
        let recorded = chunk.recorded();
        // Reliable attach fan-out (backpressured). Snapshot the sink under the lock, then send
        // outside it. A replaying attach holds the gate closed; chunks below its start_seq are
        // covered by the replay and skipped here. If the gateway queue is closed (connection
        // gone), clear the stale attachment so we stop trying.
        let sink = entry
            .attached
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .clone();
        if let Some(sink) = sink {
            let mut ready = sink.ready.clone();
            // An error means the attach task died before opening the gate; treat the attachment
            // as stale and drop it.
            let gate_open = ready.wait_for(|open| *open).await.is_ok();
            let wanted = gate_open && seq >= sink.start_seq.load(Ordering::SeqCst);
            let delivered = if wanted {
                let frame = StreamFrame::data(sink.channel_id.clone(), seq, recorded);
                sink.out_tx.send(ServerMessage::Stream(frame)).await.is_ok()
            } else {
                gate_open
            };
            if !delivered {
                let mut guard = entry.attached.lock().unwrap_or_else(|e| e.into_inner());
                if guard
                    .as_ref()
                    .is_some_and(|s| s.channel_id == sink.channel_id)
                {
                    *guard = None;
                }
            }
        }
    }
}

/// How long the post-exit drain waits before re-checking a quiet PTY. Bytes the leader wrote
/// right before exiting can still be in flight through the kernel's tty flip-buffer work when we
/// look (a plain `FIONREAD`/`read` sees nothing yet), so one quiet check is not proof the stream
/// is drained — two checks this far apart are.
const POST_EXIT_QUIET_RECHECK: Duration = Duration::from_millis(2);

/// Cap on bytes drained after the leader exits. The leader's own undelivered output is bounded by
/// kernel PTY buffering (well under this), so the cap only ever cuts a HELPER that keeps writing
/// after the leader died — bounding how far such a helper can extend the attachment (the session
/// belongs to its leader) without putting any time limit on delivering the leader's bytes to a
/// slow consumer.
const POST_EXIT_DRAIN_BUDGET: usize = 256 * 1024;

/// Post-exit drain state: how much more we are willing to read, and whether the last poll found
/// the PTY quiet (two consecutive quiet polls end the drain).
struct PostExitDrain {
    budget: usize,
    saw_quiet: bool,
}

async fn capture_output(master: Arc<AsyncFd<OwnedFd>>, chunk_size: usize, context: CaptureContext) {
    let CaptureContext {
        fanout,
        mut leader_exited_rx,
    } = context;
    let mut recorder = fanout.recorder(CaptureMethod::Pty, StreamKind::PtyOutput);
    let mut buf = vec![0u8; chunk_size.max(1)];
    let mut post_exit: Option<PostExitDrain> = None;
    // The terminal's own end (EOF, or EIO once it hangs up) is the stream's end; a drain that
    // stops before it (the byte budget, two quiet polls) is a cutoff.
    let end = loop {
        let read_result = match &mut post_exit {
            Some(drain) => {
                if drain.budget == 0 {
                    break FinishReason::Cutoff;
                }
                let read_size = drain.budget.min(buf.len());
                match pty::try_read(&master, &mut buf[..read_size]) {
                    Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                        if drain.saw_quiet {
                            break FinishReason::Cutoff;
                        }
                        drain.saw_quiet = true;
                        tokio::time::sleep(POST_EXIT_QUIET_RECHECK).await;
                        continue;
                    }
                    other => {
                        drain.saw_quiet = false;
                        other
                    }
                }
            }
            None => tokio::select! {
                biased;
                _ = &mut leader_exited_rx => {
                    post_exit = Some(PostExitDrain {
                        budget: POST_EXIT_DRAIN_BUDGET,
                        saw_quiet: false,
                    });
                    continue;
                }
                result = pty::read(&master, &mut buf) => result,
            },
        };
        match read_result {
            Ok(0) => break FinishReason::Eof,
            Ok(n) => {
                if let Some(drain) = &mut post_exit {
                    drain.budget = drain.budget.saturating_sub(n);
                }
                fanout.deliver(&mut recorder, &buf[..n]).await;
            }
            // Post-exit WouldBlock never reaches here — the drain arm handles it with a quiet
            // re-check above.
            Err(e) if pty::is_eof_error(&e) => break FinishReason::Eof,
            Err(_) => break FinishReason::Cutoff,
        }
    };
    fanout.finish(&mut recorder, end).await;
}

/// After the leader exits, how long a quiet pipe is given before the drain ends. Pipes have no
/// flip-buffer race like the PTY, but a helper that inherited stdout or stderr may still be
/// writing; one quiet window this long is treated as drained (the byte budget bounds a chatty
/// helper).
const POST_EXIT_PIPE_QUIET: Duration = Duration::from_millis(20);

/// Reads one of a pipe-mode leader's output pipes until it ends: at EOF, or, once the leader has
/// exited, after a quiet window or the drain budget, which are cutoffs (a helper may still hold
/// the pipe). Stdout and stderr each drain through one, so both end before the exit is published.
struct PipeDrain<R> {
    reader: R,
    exited: watch::Receiver<bool>,
    budget: Option<usize>,
}

impl<R: AsyncRead + Unpin> PipeDrain<R> {
    fn new(reader: R, entry: &SessionEntry) -> Self {
        Self {
            reader,
            exited: entry.exit_watch(),
            budget: None,
        }
    }

    /// The next read's length, or how the pipe ended.
    async fn read(&mut self, buf: &mut [u8]) -> Result<usize, FinishReason> {
        let read = loop {
            match self.budget {
                Some(0) => return Err(FinishReason::Cutoff),
                Some(budget) => {
                    let read_size = budget.min(buf.len());
                    let read = tokio::time::timeout(
                        POST_EXIT_PIPE_QUIET,
                        self.reader.read(&mut buf[..read_size]),
                    );
                    match read.await {
                        Ok(read) => break read,
                        Err(_quiet) => return Err(FinishReason::Cutoff),
                    }
                }
                None => tokio::select! {
                    biased;
                    _ = self.exited.wait_for(|exited| *exited) => {
                        self.budget = Some(POST_EXIT_DRAIN_BUDGET);
                    }
                    read = self.reader.read(buf) => break read,
                },
            }
        };
        match read {
            Ok(0) => Err(FinishReason::Eof),
            Ok(n) => {
                if let Some(budget) = &mut self.budget {
                    *budget = budget.saturating_sub(n);
                }
                Ok(n)
            }
            Err(_) => Err(FinishReason::Cutoff),
        }
    }
}

/// Pipe-mode stdout reader: the same single-reader fan-out as the PTY path, reading the stdout
/// pipe.
async fn capture_pipe_output(stdout: ChildStdout, chunk_size: usize, fanout: Fanout) {
    let mut recorder = fanout.recorder(CaptureMethod::Pipe, StreamKind::Stdout);
    let mut drain = PipeDrain::new(stdout, &fanout.entry);
    let mut buf = vec![0u8; chunk_size.max(1)];
    let end = loop {
        match drain.read(&mut buf).await {
            Ok(n) => fanout.deliver(&mut recorder, &buf[..n]).await,
            Err(end) => break end,
        }
    };
    fanout.finish(&mut recorder, end).await;
}

/// Pipe-mode stderr reader: telemetry only. Diagnostics are recorded (redacted) as `stderr`
/// `IoChunk`s so the record keeps them, but they never enter the journal or the attach channel —
/// those carry the protocol stream alone.
async fn capture_stderr(stderr: ChildStderr, chunk_size: usize, fanout: Fanout) {
    let mut recorder = fanout.recorder(CaptureMethod::Pipe, StreamKind::Stderr);
    let mut drain = PipeDrain::new(stderr, &fanout.entry);
    let mut buf = vec![0u8; chunk_size.max(1)];
    let end = loop {
        match drain.read(&mut buf).await {
            Ok(n) => recorder.read(&buf[..n]),
            Err(end) => break end,
        }
    };
    recorder.end(end);
}

/// Replay a session's journal from `from` to its current end over `out_tx` (used for attaches to
/// exited sessions, where no live producer exists).
async fn replay_journal(
    entry: &Arc<SessionEntry>,
    channel_id: &ChannelId,
    out_tx: &mpsc::Sender<ServerMessage>,
    from: u64,
) {
    let upper = entry
        .journal
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .next_seq();
    replay_journal_until(entry, channel_id, out_tx, from, upper).await;
}

/// Replay journal records `[from, upper)` over `out_tx` in bounded batches. The journal lock is
/// held only while reading a batch, never across a send.
async fn replay_journal_until(
    entry: &Arc<SessionEntry>,
    channel_id: &ChannelId,
    out_tx: &mpsc::Sender<ServerMessage>,
    from: u64,
    upper: u64,
) {
    /// Per-batch payload budget for journal reads during replay.
    const REPLAY_BATCH_BYTES: u64 = 256 * 1024;
    let mut cursor = from;
    while cursor < upper {
        let chunks = {
            let journal = entry.journal.lock().unwrap_or_else(|e| e.into_inner());
            journal.read_from(cursor, REPLAY_BATCH_BYTES)
        };
        if chunks.is_empty() {
            break;
        }
        let mut progressed = false;
        for chunk in chunks {
            if chunk.sequence >= upper {
                return;
            }
            cursor = chunk.sequence + 1;
            progressed = true;
            let frame =
                StreamFrame::data(channel_id.clone(), chunk.sequence, chunk.data.as_slice());
            if out_tx.send(ServerMessage::Stream(frame)).await.is_err() {
                return;
            }
        }
        if !progressed {
            break;
        }
    }
}

#[cfg(test)]
mod tests {
    #![expect(clippy::disallowed_types, reason = "the tests read io.chunk events")]
    use super::*;
    use sealant_protocol::{EventEnvelope, EventPayload, IoChunk};
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
            extra_env: Arc::new(std::sync::Mutex::new(Vec::new())),
            redactor: Arc::new(Redactor::default()),
        }
    }

    fn session_args(args: &[&str], cols: u16, rows: u16) -> OpenSessionArgs {
        OpenSessionArgs {
            user: None,
            execution_id: None,
            shell: Some("/bin/sh".to_owned()),
            args: args.iter().map(|s| (*s).to_owned()).collect(),
            cwd: None,
            env: vec![],
            secret_env: vec![],
            cols,
            rows,
            term: None,
            mode: SessionMode::Pty,
        }
    }

    /// A session's process group, owned by the test (sealantd#183): a helper its leader started
    /// outlives the leader, and nothing else ends it. [`Self::end`] kills what is left and waits
    /// until the group is empty; dropping the guard does the same when the test fails first.
    struct GroupGuard {
        pgid: i32,
    }

    impl GroupGuard {
        /// Whether any process is left in the group (a zombie not yet reaped counts).
        fn alive(&self) -> bool {
            nix::sys::signal::killpg(Pid::from_raw(self.pgid), None).is_ok()
        }

        /// Kill every process left in the group and wait until none is; `false` when one is
        /// still there after ten seconds. A process the group's leader started is not this
        /// test's child: once killed, init reaps it. A leader is, and the runtime reaps it: on a
        /// single-threaded runtime it cannot while this waits, so end a live leader's group on
        /// a multi-threaded one.
        fn end(&self) -> bool {
            if self.alive() {
                let _ = nix::sys::signal::killpg(Pid::from_raw(self.pgid), NixSignal::SIGKILL);
            }
            let until = Instant::now() + Duration::from_secs(10);
            while self.alive() {
                if Instant::now() >= until {
                    return false;
                }
                std::thread::sleep(Duration::from_millis(10));
            }
            true
        }
    }

    impl Drop for GroupGuard {
        fn drop(&mut self) {
            let _ = self.end();
        }
    }

    /// One open descriptor of a process, as `/proc` names it: what it points at and the identity
    /// of its open file (mount, inode, `tty-index` of a PTY master).
    #[derive(Debug, Clone, PartialEq, Eq)]
    struct OpenFd {
        fd: u32,
        target: String,
        mnt_id: u64,
        ino: u64,
        tty_index: Option<u32>,
        /// The descriptor's `flags` (octal in fdinfo), `O_CLOEXEC` included.
        flags: u32,
    }

    impl OpenFd {
        /// A PTY master: `/dev/ptmx`, or its devpts alias `/dev/pts/ptmx`.
        fn is_master(&self) -> bool {
            self.target == "/dev/ptmx" || self.target.ends_with("/pts/ptmx")
        }

        /// Marked close-on-exec.
        fn close_on_exec(&self) -> bool {
            self.flags & 0o2_000_000 != 0
        }

        /// A PTY master or a PTY slave.
        fn is_terminal(&self) -> bool {
            self.is_master() || self.target.starts_with("/dev/pts/")
        }

        /// The same open file as `other`: the same target on the same mount and inode, and for a
        /// master the same PTY. The descriptor number may differ.
        fn same_file(&self, other: &Self) -> bool {
            self.target == other.target
                && self.mnt_id == other.mnt_id
                && self.ino == other.ino
                && self.tty_index == other.tty_index
        }
    }

    /// Every open descriptor of `pid`. A descriptor that cannot be read fails the test: it never
    /// reads as absent. One that is gone between the listing and its read (the process closed
    /// it meanwhile: the test process's other threads, a program starting up) makes the whole
    /// set be read again, up to a hundred times.
    fn open_fds(pid: i32) -> Vec<OpenFd> {
        for _ in 0..100 {
            if let Some(fds) = read_fds(pid) {
                return fds;
            }
            std::thread::sleep(Duration::from_millis(10));
        }
        panic!("the descriptors of {pid} kept changing while they were read");
    }

    /// One read of `pid`'s descriptors; `None` when one was gone before it could be read.
    fn read_fds(pid: i32) -> Option<Vec<OpenFd>> {
        let dir = format!("/proc/{pid}/fd");
        let mut fds = Vec::new();
        for entry in std::fs::read_dir(&dir).unwrap_or_else(|e| panic!("list {dir}: {e}")) {
            let entry = entry.unwrap_or_else(|e| panic!("list {dir}: {e}"));
            let name = entry.file_name();
            let fd: u32 = name
                .to_str()
                .and_then(|n| n.parse().ok())
                .unwrap_or_else(|| panic!("{dir}: {name:?} is not a descriptor"));
            let target = match std::fs::read_link(entry.path()) {
                Ok(target) => target.to_string_lossy().into_owned(),
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => return None,
                Err(e) => panic!("read {dir}/{fd}: {e}"),
            };
            let info = match std::fs::read_to_string(format!("/proc/{pid}/fdinfo/{fd}")) {
                Ok(info) => info,
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => return None,
                Err(e) => panic!("read /proc/{pid}/fdinfo/{fd}: {e}"),
            };
            let field = |key: &str| {
                info.lines()
                    .find_map(|line| line.strip_prefix(key))
                    .map(str::trim)
            };
            let number = |key: &str| -> u64 {
                field(key)
                    .and_then(|v| v.parse().ok())
                    .unwrap_or_else(|| panic!("/proc/{pid}/fdinfo/{fd} has no {key}: {info}"))
            };
            let flags = field("flags:")
                .and_then(|v| u32::from_str_radix(v, 8).ok())
                .unwrap_or_else(|| panic!("/proc/{pid}/fdinfo/{fd} has no flags: {info}"));
            let mut open = OpenFd {
                fd,
                mnt_id: number("mnt_id:"),
                ino: number("ino:"),
                tty_index: None,
                flags,
                target,
            };
            if open.is_master() {
                open.tty_index = Some(
                    field("tty-index:")
                        .and_then(|v| v.parse().ok())
                        .unwrap_or_else(|| panic!("master {dir}/{fd} has no tty-index: {info}")),
                );
            }
            fds.push(open);
        }
        Some(fds)
    }

    /// The terminal descriptors (PTY masters and slaves) `pid` holds.
    fn terminal_fds(pid: i32) -> Vec<OpenFd> {
        open_fds(pid)
            .into_iter()
            .filter(OpenFd::is_terminal)
            .collect()
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

    /// Collect attach-stream bytes from an `out_tx` receiver until the End frame, returning the
    /// reassembled output and the End's exit code. Asserts per-channel seq monotonicity.
    async fn attach_output_until_end(
        rx: &mut mpsc::Receiver<ServerMessage>,
        channel: &ChannelId,
    ) -> (Vec<u8>, Option<i32>) {
        let mut out = Vec::new();
        let mut last_seq: Option<u64> = None;
        loop {
            let msg = tokio::time::timeout(Duration::from_secs(10), rx.recv())
                .await
                .expect("no timeout")
                .expect("frame");
            if let ServerMessage::Stream(frame) = msg {
                assert_eq!(&frame.channel_id, channel);
                match frame.payload {
                    sealant_protocol::StreamPayload::Data { data } => {
                        // seq is per-channel monotonic for data frames.
                        if let Some(prev) = last_seq {
                            assert_eq!(frame.seq, prev + 1, "seq gap in attach stream");
                        }
                        last_seq = Some(frame.seq);
                        out.extend_from_slice(data.as_slice());
                    }
                    sealant_protocol::StreamPayload::End(end) => {
                        return (out, end.exit_code);
                    }
                    sealant_protocol::StreamPayload::WindowUpdate { .. } => {}
                }
            }
        }
    }

    #[tokio::test]
    async fn attach_streams_pty_output_losslessly_to_channel() {
        let rt = runtime();
        let channel = ChannelId::new("chan_attach_1");
        // Small queue + a deliberately slow consumer: the backpressured send must NOT drop bytes
        // (the entire point vs the lossy IoChunk broadcast). The shell prints a known marker.
        let (out_tx, mut out_rx) = mpsc::channel::<ServerMessage>(2);

        let opened = rt
            .open(session_args(
                &["-c", "printf 'LINE1\\nLINE2\\nDONE\\n'"],
                80,
                24,
            ))
            .expect("open");
        rt.attach(&opened.session_id, channel.clone(), out_tx, None)
            .await
            .expect("attach");

        let (bytes, _exit) = attach_output_until_end(&mut out_rx, &channel).await;
        let text = String::from_utf8_lossy(&bytes);
        assert!(text.contains("LINE1"), "got: {text:?}");
        assert!(text.contains("LINE2"), "got: {text:?}");
        assert!(text.contains("DONE"), "got: {text:?}");
    }

    #[tokio::test]
    async fn attach_ends_when_leader_exits_with_inherited_slave_open() {
        let rt = runtime();
        let channel = ChannelId::new("chan_inherited_slave");
        let (out_tx, mut out_rx) = mpsc::channel::<ServerMessage>(8);

        // The background process ignores the controlling-terminal hangup and keeps its inherited
        // stdout open after the shell (the session leader) exits. The attachment still belongs to
        // the leader and must not wait for that helper process to finish.
        let opened = rt
            .open(session_args(
                &[
                    "-c",
                    "trap '' HUP; sleep 5 & printf 'LEADER_DONE\\n'; exit 0",
                ],
                80,
                24,
            ))
            .expect("open");
        rt.attach(&opened.session_id, channel.clone(), out_tx, None)
            .await
            .expect("attach");

        let (bytes, exit_code) = tokio::time::timeout(
            Duration::from_secs(1),
            attach_output_until_end(&mut out_rx, &channel),
        )
        .await
        .expect("attach should end promptly when the session leader exits");

        assert!(
            String::from_utf8_lossy(&bytes).contains("LEADER_DONE"),
            "leader output should be drained before the attachment ends"
        );
        assert_eq!(exit_code, Some(0));
    }

    #[tokio::test]
    async fn attach_end_is_not_extended_by_a_writing_helper() {
        let rt = runtime();
        let channel = ChannelId::new("chan_writing_helper");
        let (out_tx, mut out_rx) = mpsc::channel::<ServerMessage>(8);

        let opened = rt
            .open(session_args(
                &["-c", "trap '' HUP; yes HELPER & sleep 0.1; exit 0"],
                80,
                24,
            ))
            .expect("open");
        // The helper ignores the hangup and may outlive the leader: the test ends it
        // (sealantd#183).
        let group = GroupGuard { pgid: opened.pid };
        rt.attach(&opened.session_id, channel.clone(), out_tx, None)
            .await
            .expect("attach");

        let exit_code = tokio::time::timeout(Duration::from_secs(1), async {
            loop {
                let message = out_rx.recv().await.expect("frame");
                if let ServerMessage::Stream(frame) = message {
                    assert_eq!(frame.channel_id, channel);
                    if let sealant_protocol::StreamPayload::End(end) = frame.payload {
                        return end.exit_code;
                    }
                }
            }
        })
        .await
        .expect("helper output must not extend the attachment after leader exit");

        assert_eq!(exit_code, Some(0));
        assert!(
            group.end(),
            "a process of the test's session is left over after it"
        );
    }

    /// The children of `pid`, from every process's parent in `/proc`.
    fn children(pid: i32) -> Vec<i32> {
        std::fs::read_dir("/proc")
            .expect("/proc")
            .filter_map(|entry| {
                let child: i32 = entry.ok()?.file_name().to_str()?.parse().ok()?;
                let stat = std::fs::read_to_string(format!("/proc/{child}/stat")).ok()?;
                // `pid (comm) state ppid …`: the comm may hold spaces, so read after its `)`.
                let ppid: i32 = stat
                    .rsplit_once(')')?
                    .1
                    .split_whitespace()
                    .nth(1)?
                    .parse()
                    .ok()?;
                (ppid == pid).then_some(child)
            })
            .collect()
    }

    /// Wait until `pid` runs `program` and sleeps in it: its exec has finished, and so has the
    /// program's start (which opens and closes files of its own). The kernel names the process
    /// (`comm`: the program, or the path it was run by) only after it has closed the descriptors
    /// marked close-on-exec, and a process read before that (a spawn can return as soon as the
    /// exec has replaced the child's memory) can still list a descriptor it is about to close.
    async fn exec_done(pid: i32, program: &str) {
        let until = Instant::now() + Duration::from_secs(10);
        loop {
            let comm = std::fs::read_to_string(format!("/proc/{pid}/comm"))
                .unwrap_or_else(|e| panic!("read /proc/{pid}/comm: {e}"));
            let stat = std::fs::read_to_string(format!("/proc/{pid}/stat"))
                .unwrap_or_else(|e| panic!("read /proc/{pid}/stat: {e}"));
            // `pid (comm) state …`: the state follows the comm's closing parenthesis.
            let sleeping = stat
                .rsplit_once(')')
                .and_then(|(_, rest)| rest.split_whitespace().next())
                == Some("S");
            if comm.trim_end().rsplit('/').next() == Some(program) && sleeping {
                return;
            }
            assert!(
                Instant::now() < until,
                "{pid} runs {program} and sleeps in it within ten seconds (comm {comm:?}, \
                 stat {stat:?})"
            );
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
    }

    /// Where a terminal descriptor a process holds comes from: a session's master or slave, one
    /// the test process held before it opened any session, or neither.
    fn origin(fd: &OpenFd, sessions: &[(&str, &OpenFd, &OpenFd)], before: &[OpenFd]) -> String {
        for (name, master, slave) in sessions {
            if fd.same_file(master) {
                return format!("the {name} session's master");
            }
            if fd.same_file(slave) {
                return format!("the {name} session's slave");
            }
        }
        if before.iter().any(|b| fd.same_file(b)) {
            return "a descriptor the test process held before it opened a session".to_owned();
        }
        "a terminal descriptor of no session of this test".to_owned()
    }

    /// A PTY's descriptors stay with the session it belongs to (sealantd#183). While sessions
    /// are open, no process sealantd starts holds a terminal descriptor beyond its stdin, stdout
    /// and stderr: not a session's leader (its own master included), nor what a leader runs, nor
    /// a command run as `exec` runs it, nor a git run as the capture engine runs it. The check
    /// holds whatever the descriptor is; each one found is named by where it came from: a
    /// session's master or slave (matched by mount, inode and PTY, not by PTY number alone),
    /// one the test process held before it opened a session, or neither.
    ///
    /// The order follows sealantd's: the start marking first, then a master opened without
    /// close-on-exec. Sessions and the command spawn the default way, which keeps that master
    /// from every child; the git spawns as a helper, which needs it marked first. A spawn that
    /// runs as a person or what a request names, misfiled as a helper, meets the unmarked master
    /// and the sweep's check fails the test.
    // Two workers: the leaders and the command are this test's children, and the runtime reaps
    // them on one while the guards wait on the other.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_ptys_descriptors_stay_with_its_session() {
        use sealant_process::spawn::CommandGateExt;

        // What sealantd does first: whatever its launcher left open is marked close-on-exec.
        sealant_process::spawn::mark_at_start().expect("the start marking");
        // A master opened after that without close-on-exec, as sealantd would open one that
        // lacked the flag. No child spawned the default way gets it (sealant_process::spawn).
        let own: i32 = std::process::id().try_into().expect("a pid");
        let unflagged =
            nix::pty::posix_openpt(nix::fcntl::OFlag::O_RDWR | nix::fcntl::OFlag::O_NOCTTY)
                .expect("open a master without close-on-exec");
        // What the test process holds before any session: whatever its launcher passed it, and
        // the master above.
        let before = open_fds(own);
        assert!(
            before
                .iter()
                .any(|fd| fd.is_master() && !fd.close_on_exec()),
            "the test process holds a master without close-on-exec before any session: {before:?}"
        );

        let rt = runtime();
        let first = rt
            .open(session_args(&["-c", "exec sleep 30"], 80, 24))
            .expect("open the first session");
        let first_group = GroupGuard { pgid: first.pid };
        let second = rt
            .open(session_args(&["-c", "sleep 30 & wait"], 80, 24))
            .expect("open the second session");
        let second_group = GroupGuard { pgid: second.pid };

        exec_done(first.pid, "sleep").await;
        exec_done(second.pid, "sh").await;
        // Each session's slave is its leader's stdin; its master is the one master the test
        // process holds now, on that PTY, that it did not hold before.
        let now = open_fds(own);
        let session = |leader: i32| {
            let slave = open_fds(leader)
                .into_iter()
                .find(|fd| fd.fd == 0)
                .expect("the leader's stdin");
            let index: u32 = slave
                .target
                .strip_prefix("/dev/pts/")
                .and_then(|n| n.parse().ok())
                .unwrap_or_else(|| panic!("the leader's stdin is a pty slave: {slave:?}"));
            let masters: Vec<&OpenFd> = now
                .iter()
                .filter(|fd| fd.is_master() && fd.tty_index == Some(index))
                .filter(|fd| !before.iter().any(|b| b.same_file(fd)))
                .collect();
            // The positive control: the oracle finds the master sealantd holds for the session,
            // and it is close-on-exec whatever a spawn does.
            assert_eq!(
                masters.len(),
                1,
                "the test process holds exactly one new master on /dev/pts/{index}: {now:?}"
            );
            assert!(
                masters[0].close_on_exec(),
                "the session's master is close-on-exec: {:?}",
                masters[0]
            );
            (masters[0].clone(), slave)
        };
        let (first_master, first_slave) = session(first.pid);
        let (second_master, second_slave) = session(second.pid);
        let sessions = [
            ("first", &first_master, &first_slave),
            ("second", &second_master, &second_slave),
        ];

        let until = Instant::now() + Duration::from_secs(10);
        let second_child = loop {
            if let Some(child) = children(second.pid).first() {
                break *child;
            }
            assert!(
                Instant::now() < until,
                "the second session's leader started its child"
            );
            tokio::time::sleep(Duration::from_millis(10)).await;
        };

        // A command, as `exec` runs one.
        let processes = sealant_process::ProcessRuntime {
            registry: Arc::new(sealant_process::ProcessRegistry::new()),
            bus: rt.bus.clone(),
            idgen: rt.idgen.clone(),
            status: rt.status.clone(),
            clock: rt.clock.clone(),
            config: rt.config.clone(),
            extra_env: Arc::new(std::sync::Mutex::new(Vec::new())),
            redactor: rt.redactor.clone(),
        };
        let command = processes
            .exec(
                sealant_protocol::ExecArgs {
                    execution_id: None,
                    session_id: None,
                    executable: "/bin/sleep".to_owned(),
                    args: vec!["30".to_owned()],
                    cwd: None,
                    env: vec![],
                    secret_env: vec![],
                    stdin: false,
                    attach: false,
                    timeout_millis: None,
                    background: false,
                    capture: None,
                    graceful_signal: None,
                    user: None,
                },
                None,
                None,
            )
            .expect("exec a command");
        let command_group = GroupGuard { pgid: command.pgid };

        for (pid, program) in [
            (first.pid, "sleep"),
            (second.pid, "sh"),
            (second_child, "sleep"),
            (command.pid, "sleep"),
        ] {
            exec_done(pid, program).await;
        }
        let held_by = |who: &str, pid: i32, slave: Option<&OpenFd>| -> Vec<String> {
            terminal_fds(pid)
                .into_iter()
                // A session's processes have its slave as stdin, stdout and stderr, nothing else.
                .filter(|fd| !(fd.fd <= 2 && slave.is_some_and(|s| fd.same_file(s))))
                .map(|fd| format!("{who} holds {}: {fd:?}", origin(&fd, &sessions, &before)))
                .collect()
        };
        let inherited: Vec<&OpenFd> = before.iter().filter(|fd| fd.is_terminal()).collect();
        let held: Vec<String> = [
            ("the first session's leader", first.pid, Some(&first_slave)),
            (
                "the second session's leader",
                second.pid,
                Some(&second_slave),
            ),
            (
                "the second session's leader's child",
                second_child,
                Some(&second_slave),
            ),
            ("a command run as exec runs it", command.pid, None),
        ]
        .into_iter()
        .flat_map(|(who, pid, slave)| held_by(who, pid, slave))
        .collect();
        assert!(
            held.is_empty(),
            "terminal descriptors where none belongs:\n{}\n(the test process held these \
             terminal descriptors before it opened a session: {inherited:?})",
            held.join("\n")
        );

        // A helper spawn needs every descriptor close-on-exec: in tests the sweep before it
        // panics on one without the flag. Marked now, the master stands for one sealantd opened
        // with it.
        nix::fcntl::fcntl(
            &unflagged,
            nix::fcntl::FcntlArg::F_SETFD(nix::fcntl::FdFlag::FD_CLOEXEC),
        )
        .expect("mark the master close-on-exec");
        // A git, as the capture engine runs one (a helper): blocked on its stdin until the test
        // closes it.
        let git = std::process::Command::new("git")
            .args(["hash-object", "--stdin"])
            .stdin(std::process::Stdio::piped())
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .spawn_helper()
            .expect("spawn git");
        exec_done(git.pid(), "git").await;
        let held = held_by("a git run as the capture engine runs it", git.pid(), None);
        assert!(
            held.is_empty(),
            "terminal descriptors where none belongs:\n{}",
            held.join("\n")
        );

        git.communicate(None)
            .expect("git ends once its stdin closes");
        processes
            .kill(&command.process_id)
            .expect("kill the command");
        rt.close(&first.session_id)
            .expect("close the first session");
        rt.close(&second.session_id)
            .expect("close the second session");
        drop(unflagged);
        assert!(command_group.end(), "the command is left over");
        assert!(first_group.end(), "the first session is left over");
        assert!(second_group.end(), "the second session is left over");
    }

    #[tokio::test]
    async fn attach_stream_is_lossless_under_load_with_slow_consumer() {
        let rt = runtime();
        let channel = ChannelId::new("chan_attach_load");
        // Tiny queue (1) forces the producer to await on nearly every chunk: this is the
        // backpressure path. A slow consumer (sleep between recvs) would drop frames on a broadcast;
        // here every byte must survive in order.
        let (out_tx, mut out_rx) = mpsc::channel::<ServerMessage>(1);

        // Emit a large, verifiable stream: 20000 numbered lines.
        let script = "i=0; while [ $i -lt 20000 ]; do echo $i; i=$((i+1)); done";
        let opened = rt
            .open(session_args(&["-c", script], 80, 24))
            .expect("open");
        rt.attach(&opened.session_id, channel.clone(), out_tx, None)
            .await
            .expect("attach");

        // Drain slowly: yield (and occasionally sleep) to keep the queue saturated.
        let mut out = Vec::new();
        let mut last_seq: Option<u64> = None;
        let mut count = 0u64;
        loop {
            let msg = tokio::time::timeout(Duration::from_secs(30), out_rx.recv())
                .await
                .expect("no timeout")
                .expect("frame");
            if let ServerMessage::Stream(frame) = msg {
                match frame.payload {
                    sealant_protocol::StreamPayload::Data { data } => {
                        if let Some(prev) = last_seq {
                            assert_eq!(frame.seq, prev + 1, "seq gap: drop detected");
                        }
                        last_seq = Some(frame.seq);
                        out.extend_from_slice(data.as_slice());
                        count += 1;
                        if count.is_multiple_of(7) {
                            tokio::time::sleep(Duration::from_millis(1)).await;
                        }
                    }
                    sealant_protocol::StreamPayload::End(_) => break,
                    sealant_protocol::StreamPayload::WindowUpdate { .. } => {}
                }
            }
        }

        // Reassemble and verify EVERY line 0..20000 is present in order — proof of zero loss.
        let text = String::from_utf8_lossy(&out);
        let numbers: Vec<u64> = text
            .split_whitespace()
            .filter_map(|s| s.parse::<u64>().ok())
            .collect();
        assert_eq!(
            numbers.len(),
            20000,
            "expected 20000 lines, got {}",
            numbers.len()
        );
        for (idx, &n) in numbers.iter().enumerate() {
            assert_eq!(n, idx as u64, "out-of-order or missing line at {idx}");
        }
    }

    #[tokio::test]
    async fn attach_emits_end_with_exit_code_on_leader_exit() {
        let rt = runtime();
        let channel = ChannelId::new("chan_attach_exit");
        let (out_tx, mut out_rx) = mpsc::channel::<ServerMessage>(8);
        let opened = rt
            .open(session_args(&["-c", "exit 7"], 80, 24))
            .expect("open");
        rt.attach(&opened.session_id, channel.clone(), out_tx, None)
            .await
            .expect("attach");
        let (_bytes, exit) = attach_output_until_end(&mut out_rx, &channel).await;
        assert_eq!(exit, Some(7), "End must carry the leader's exit code");
    }

    #[tokio::test]
    async fn attach_runs_in_parallel_with_iochunk_telemetry() {
        // The faithful attach stream and the lossy IoChunk telemetry tap must both see the output.
        let rt = runtime();
        let mut bus_rx = rt.bus.subscribe();
        let channel = ChannelId::new("chan_attach_parallel");
        let (out_tx, mut out_rx) = mpsc::channel::<ServerMessage>(16);
        let opened = rt
            .open(session_args(&["-c", "printf 'PARALLEL\\n'"], 80, 24))
            .expect("open");
        rt.attach(&opened.session_id, channel.clone(), out_tx, None)
            .await
            .expect("attach");

        let (attach_bytes, _exit) = attach_output_until_end(&mut out_rx, &channel).await;
        assert!(String::from_utf8_lossy(&attach_bytes).contains("PARALLEL"));

        // IoChunk telemetry should also have carried the same output in parallel.
        assert!(
            wait_for_output(&mut bus_rx, "PARALLEL", Duration::from_secs(4)).await,
            "IoChunk telemetry should still publish the same output"
        );
    }

    #[tokio::test]
    async fn detach_clears_the_attachment() {
        let rt = runtime();
        let channel = ChannelId::new("chan_detach");
        let (out_tx, mut out_rx) = mpsc::channel::<ServerMessage>(8);
        // A long-lived session so we can detach while it is still running.
        let opened = rt
            .open(session_args(&["-c", "sleep 30"], 80, 24))
            .expect("open");
        rt.attach(&opened.session_id, channel.clone(), out_tx, None)
            .await
            .expect("attach");
        rt.detach(&channel);
        // After detach, the session entry must have no attachment.
        let entry = rt.registry.get(&opened.session_id).expect("entry");
        assert!(
            entry
                .attached
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .is_none(),
            "detach should clear the attachment"
        );
        // Clean up the session.
        rt.close(&opened.session_id).expect("close");
        // Drain any residual frames without asserting (reader is aborted).
        let _ = tokio::time::timeout(Duration::from_millis(200), out_rx.recv()).await;
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
        // Budget covers the close() SIGKILL escalation (2s grace) plus loaded-machine margin —
        // an interactive shell at its prompt can absorb the HUP, so release may take the ladder.
        for _ in 0..500 {
            if rt.registry.is_empty() {
                released = true;
                break;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        assert!(released, "session resources should be released after close");
        assert_eq!(rt.status.counts().1, 0);
    }

    /// Poll `read_output` until its reassembled text contains `needle` (or time out).
    async fn journal_contains(rt: &SessionRuntime, id: &SessionId, needle: &str) -> bool {
        let deadline = Instant::now() + Duration::from_secs(5);
        while Instant::now() < deadline {
            let out = rt.read_output(id, 0, None).expect("read_output");
            let text: String = out
                .chunks
                .iter()
                .map(|c| String::from_utf8_lossy(c.data.as_slice()).to_string())
                .collect();
            if text.contains(needle) {
                return true;
            }
            tokio::time::sleep(Duration::from_millis(25)).await;
        }
        false
    }

    /// The product path: attach, disconnect, write more, reattach with `from_sequence: 0`, and
    /// receive the FULL scrollback (both markers) with contiguous journal sequences, then live
    /// output continues on the same channel.
    #[tokio::test]
    async fn reattach_replays_full_scrollback_from_sequence_zero() {
        let rt = runtime();
        let opened = rt.open(session_args(&[], 80, 24)).expect("open");

        // First client: live attach, produce a marker, then die (drop the receiver).
        let (tx1, rx1) = mpsc::channel::<ServerMessage>(64);
        rt.attach(&opened.session_id, ChannelId::new("c1"), tx1, None)
            .await
            .expect("attach 1");
        rt.write_input(&opened.session_id, b"echo FIRST_MARKER\n")
            .await
            .expect("write 1");
        assert!(
            journal_contains(&rt, &opened.session_id, "FIRST_MARKER").await,
            "first marker must reach the journal"
        );
        drop(rx1);

        // Output produced while nobody is attached must still land in the journal.
        rt.write_input(&opened.session_id, b"echo SECOND_MARKER\n")
            .await
            .expect("write 2");
        assert!(
            journal_contains(&rt, &opened.session_id, "SECOND_MARKER").await,
            "detached-window output must be journaled, not dropped"
        );

        // Reattach with full replay; then produce live output on the same channel.
        let (tx2, mut rx2) = mpsc::channel::<ServerMessage>(64);
        rt.attach(&opened.session_id, ChannelId::new("c2"), tx2, Some(0))
            .await
            .expect("reattach");
        rt.write_input(&opened.session_id, b"echo THIRD_MARKER\n")
            .await
            .expect("write 3");

        let mut text = String::new();
        let mut last_seq: Option<u64> = None;
        let deadline = Instant::now() + Duration::from_secs(10);
        while !text.contains("THIRD_MARKER") && Instant::now() < deadline {
            let Ok(Some(msg)) = tokio::time::timeout(Duration::from_secs(5), rx2.recv()).await
            else {
                break;
            };
            if let ServerMessage::Stream(frame) = msg
                && let sealant_protocol::StreamPayload::Data { data } = frame.payload
            {
                if let Some(prev) = last_seq {
                    assert_eq!(frame.seq, prev + 1, "replay+live must be contiguous");
                } else {
                    assert_eq!(frame.seq, 0, "replay must start at sequence 0");
                }
                last_seq = Some(frame.seq);
                text.push_str(&String::from_utf8_lossy(data.as_slice()));
            }
        }
        let first = text.find("FIRST_MARKER");
        let second = text.find("SECOND_MARKER");
        let third = text.find("THIRD_MARKER");
        assert!(
            first.is_some() && second.is_some() && third.is_some(),
            "all three markers must arrive on the reattached channel; got {text:?}"
        );
        assert!(first < second && second < third, "markers must be in order");

        rt.close(&opened.session_id).expect("close");
    }

    /// signalSession delivers to the group; the exited session stays observable as a tombstone
    /// (state, signal, scrollback) until an explicit close drops it.
    #[tokio::test]
    async fn signal_terminates_and_tombstone_reports_exit_and_scrollback() {
        let rt = runtime();
        let mut rx = rt.bus.subscribe();
        let opened = rt
            .open(session_args(&["-c", "echo READY; sleep 30"], 80, 24))
            .expect("open");
        assert!(
            wait_for_output(&mut rx, "READY", Duration::from_secs(4)).await,
            "session should print READY"
        );
        rt.signal(&opened.session_id, Signal::Term).expect("signal");

        // The waiter marks the exit; running set drains, tombstone appears.
        let deadline = Instant::now() + Duration::from_secs(5);
        while !rt.registry.is_empty() && Instant::now() < deadline {
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        assert!(
            rt.registry.is_empty(),
            "running set should drain after SIGTERM"
        );

        let out = rt
            .read_output(&opened.session_id, 0, None)
            .expect("tombstone must be readable");
        assert_eq!(out.state, SessionState::Exited);
        assert_eq!(out.signal, Some(libc::SIGTERM), "signal 15 expected");
        let text: String = out
            .chunks
            .iter()
            .map(|c| String::from_utf8_lossy(c.data.as_slice()).to_string())
            .collect();
        assert!(
            text.contains("READY"),
            "scrollback must survive exit: {text:?}"
        );

        let summaries = rt.list().sessions;
        let summary = summaries
            .iter()
            .find(|s| s.session_id == opened.session_id)
            .expect("tombstone listed");
        assert_eq!(summary.state, SessionState::Exited);

        // Close drops the tombstone.
        rt.close(&opened.session_id).expect("close tombstone");
        assert!(rt.registry.get(&opened.session_id).is_none());
        assert!(rt.read_output(&opened.session_id, 0, None).is_err());
    }

    /// Secrets are redacted before the journal (the readable surface), telemetry, and live sinks.
    #[tokio::test]
    async fn output_is_redacted_before_it_is_readable() {
        let mut rt = runtime();
        rt.redactor = Arc::new(Redactor::new(vec!["super-secret-value-123".to_owned()]));
        let mut rx = rt.bus.subscribe();
        let opened = rt
            .open(session_args(
                &["-c", "printf 'token=super-secret-value-123 end\n'"],
                80,
                24,
            ))
            .expect("open");
        let out_bytes = output_until_exit(&mut rx).await;
        let telemetry_text = String::from_utf8_lossy(&out_bytes);
        assert!(
            !telemetry_text.contains("super-secret-value-123"),
            "telemetry must be redacted"
        );

        let out = rt
            .read_output(&opened.session_id, 0, None)
            .expect("read journal");
        let journal_text: String = out
            .chunks
            .iter()
            .map(|c| String::from_utf8_lossy(c.data.as_slice()).to_string())
            .collect();
        assert!(
            !journal_text.contains("super-secret-value-123"),
            "journal must never hold raw secrets: {journal_text:?}"
        );
        assert!(
            journal_text.contains("***REDACTED***"),
            "journal should carry the mask: {journal_text:?}"
        );
    }

    const SPLIT_SECRET: &str = "split-secret-value-42";

    fn masking_runtime() -> SessionRuntime {
        let mut rt = runtime();
        rt.redactor = Arc::new(Redactor::new(vec![SPLIT_SECRET.to_owned()]));
        rt
    }

    /// Every `io.chunk` of `stream` published before the leader's exit.
    async fn chunks_until_exit(
        rx: &mut Receiver<EventEnvelope>,
        stream: StreamKind,
    ) -> Vec<IoChunk> {
        let mut chunks = Vec::new();
        loop {
            let env = tokio::time::timeout(Duration::from_secs(5), rx.recv())
                .await
                .expect("no timeout")
                .expect("event");
            match env.payload {
                EventPayload::IoChunk(c) if c.stream == stream => chunks.push(c),
                EventPayload::ProcessExited(_) => return chunks,
                _ => {}
            }
        }
    }

    /// Every `io.chunk` of `stream` until what they record holds `needle`.
    async fn chunks_until_recorded(
        rx: &mut Receiver<EventEnvelope>,
        stream: StreamKind,
        needle: &str,
    ) -> Vec<IoChunk> {
        let mut chunks = Vec::new();
        while !recorded(&chunks).contains(needle) {
            let env = tokio::time::timeout(Duration::from_secs(5), rx.recv())
                .await
                .expect("the chunk arrives")
                .expect("event");
            if let EventPayload::IoChunk(c) = env.payload
                && c.stream == stream
            {
                chunks.push(c);
            }
        }
        chunks
    }

    fn recorded(chunks: &[IoChunk]) -> String {
        chunks
            .iter()
            .map(|c| String::from_utf8_lossy(c.content.as_ref().expect("content").as_slice()))
            .collect()
    }

    /// A secret the leader writes in two parts reaches neither the journal nor the telemetry.
    /// The leader writes the second part only once the first was captured, so the split is real.
    #[tokio::test]
    async fn a_secret_split_across_reads_never_reaches_the_journal() {
        let rt = masking_runtime();
        let mut rx = rt.bus.subscribe();
        let opened = rt
            .open(session_args(
                &[
                    "-c",
                    "stty -echo; printf 'pw=split-secr'; read -r go; printf 'et-value-42 end'",
                ],
                80,
                24,
            ))
            .expect("open");
        let mut chunks = chunks_until_recorded(&mut rx, StreamKind::PtyOutput, "pw=").await;
        rt.write_input(&opened.session_id, b"\r").await.expect("go");
        chunks.extend(chunks_until_exit(&mut rx, StreamKind::PtyOutput).await);
        assert_eq!(recorded(&chunks), "pw=***REDACTED*** end");
        let offsets: Vec<u64> = chunks.iter().map(|c| c.stream_offset.get()).collect();
        assert_eq!(offsets, [0, 3]);
        let journal = rt
            .read_output(&opened.session_id, 0, None)
            .expect("read journal");
        let records: Vec<(u64, String)> = journal
            .chunks
            .iter()
            .map(|c| {
                (
                    c.sequence,
                    String::from_utf8_lossy(c.data.as_slice()).into_owned(),
                )
            })
            .collect();
        assert_eq!(
            records,
            [(0, "pw=".to_owned()), (1, "***REDACTED*** end".to_owned())]
        );
    }

    /// Read attach data frames into `shown` until it ends with `tail`, or two seconds pass.
    async fn shown_until(
        rx: &mut mpsc::Receiver<ServerMessage>,
        shown: &mut Vec<u8>,
        tail: &[u8],
    ) -> bool {
        let deadline = Instant::now() + Duration::from_secs(2);
        while !shown.ends_with(tail) {
            let remaining = deadline.saturating_duration_since(Instant::now());
            match tokio::time::timeout(remaining, rx.recv()).await {
                Ok(Some(ServerMessage::Stream(frame))) => {
                    if let sealant_protocol::StreamPayload::Data { data } = frame.payload {
                        shown.extend_from_slice(data.as_slice());
                    }
                }
                Ok(Some(_)) => {}
                _ => return false,
            }
        }
        true
    }

    /// The live terminal never waits on the token heuristic for bytes that are not yet a token:
    /// a frame that ends in cursor-up shows its last byte, and `ls` typed a byte at a time shows
    /// its `s` before the next keystroke.
    #[tokio::test]
    async fn the_live_terminal_shows_each_byte_without_waiting_for_the_next() {
        let rt = runtime();
        let (out_tx, mut out_rx) = mpsc::channel::<ServerMessage>(64);
        let opened = rt
            .open(session_args(
                &["-c", "printf 'frame\\033[2A'; read -r line"],
                80,
                24,
            ))
            .expect("open");
        rt.attach(
            &opened.session_id,
            ChannelId::new("chan_keys"),
            out_tx,
            Some(0),
        )
        .await
        .expect("attach");
        let mut shown = Vec::new();
        assert!(
            shown_until(&mut out_rx, &mut shown, b"frame\x1b[2A").await,
            "the frame's last byte is shown: {:?}",
            String::from_utf8_lossy(&shown)
        );
        for key in [&b"l"[..], b"s"] {
            rt.write_input(&opened.session_id, key).await.expect("type");
            assert!(
                shown_until(&mut out_rx, &mut shown, key).await,
                "{:?} is shown before the next keystroke: {:?}",
                String::from_utf8_lossy(key),
                String::from_utf8_lossy(&shown)
            );
        }
        rt.close(&opened.session_id).expect("close");
    }

    /// A terminal sends a multi-line secret's line ends as CR (Enter, a paste); the input record
    /// masks it as sent.
    #[tokio::test]
    async fn pty_input_masks_a_multiline_secret_sent_with_cr() {
        let mut rt = runtime();
        rt.redactor = Arc::new(Redactor::new(vec!["line-one\nline-two".to_owned()]));
        let mut rx = rt.bus.subscribe();
        let opened = rt
            .open(session_args(&["-c", "read -r a; read -r b"], 80, 24))
            .expect("open");
        rt.write_input(&opened.session_id, b"line-one\rline-two\r")
            .await
            .expect("type");
        let input = chunks_until_exit(&mut rx, StreamKind::PtyInput).await;
        assert_eq!(recorded(&input), "***REDACTED***\r");
    }

    /// A PTY writes a multi-line secret's line ends as CRLF; the record masks it as written.
    #[tokio::test]
    async fn a_multiline_secret_is_masked_as_the_terminal_writes_it() {
        let mut rt = runtime();
        rt.redactor = Arc::new(Redactor::new(vec!["line-one\nline-two".to_owned()]));
        let mut rx = rt.bus.subscribe();
        rt.open(session_args(
            &["-c", "printf 'pw=line-one\nline-two end'"],
            80,
            24,
        ))
        .expect("open");
        let chunks = chunks_until_exit(&mut rx, StreamKind::PtyOutput).await;
        assert_eq!(recorded(&chunks), "pw=***REDACTED*** end");
    }

    /// The drain after the leader's exit stops while a helper still holds stdout: what could
    /// still begin a secret is masked, not recorded as written.
    #[tokio::test]
    async fn a_drain_cutoff_masks_a_held_prefix_of_a_secret() {
        let rt = masking_runtime();
        let mut rx = rt.bus.subscribe();
        rt.open(pipe_args(&["-c", "sleep 2 & printf 'pw=split-secr'"]))
            .expect("open");
        let chunks = chunks_until_exit(&mut rx, StreamKind::Stdout).await;
        assert_eq!(recorded(&chunks), "pw=***REDACTED***");
    }

    /// Pipe stderr masks through its own state: a secret split across its writes is masked, and
    /// neither it nor its marker enters the stdout journal.
    #[tokio::test]
    async fn pipe_stderr_masks_its_own_stream_and_stays_out_of_the_journal() {
        let rt = masking_runtime();
        let mut rx = rt.bus.subscribe();
        let opened = rt
            .open(pipe_args(&[
                "-c",
                "printf 'split-secr' >&2; printf 'out-a '; sleep 0.2; \
                 printf 'et-value-42\n' >&2; printf 'out-b'",
            ]))
            .expect("open");
        let stderr = chunks_until_exit(&mut rx, StreamKind::Stderr).await;
        assert_eq!(recorded(&stderr), "***REDACTED***\n");
        let journal: String = rt
            .read_output(&opened.session_id, 0, None)
            .expect("read journal")
            .chunks
            .iter()
            .map(|c| String::from_utf8_lossy(c.data.as_slice()).into_owned())
            .collect();
        assert_eq!(journal, "out-a out-b");
    }

    /// Pipe stderr ends before the exit is published, even while a helper holds it open: its
    /// drain is bounded like stdout's, and a held prefix of a secret at that cutoff is masked.
    #[tokio::test]
    async fn pipe_stderr_ends_before_the_exit_while_a_helper_holds_it() {
        let rt = masking_runtime();
        let mut rx = rt.bus.subscribe();
        rt.open(pipe_args(&[
            "-c",
            "printf 'split-secr' >&2; sleep 0.1; sleep 2 &",
        ]))
        .expect("open");
        let stderr = chunks_until_exit(&mut rx, StreamKind::Stderr).await;
        assert_eq!(recorded(&stderr), "***REDACTED***");
    }

    /// Input is forwarded as it comes, and its record masks a secret typed across writes. The
    /// leader got the secret whole: its echo is masked in the output.
    #[tokio::test]
    async fn input_evidence_masks_a_secret_typed_across_writes() {
        let rt = masking_runtime();
        let mut rx = rt.bus.subscribe();
        let opened = rt.open(pipe_args(&["-c", ECHO_LOOP])).expect("open");
        rt.write_input(&opened.session_id, b"split-secr")
            .await
            .expect("first write");
        rt.write_input(&opened.session_id, b"et-value-42\n")
            .await
            .expect("second write");
        let mut input = Vec::new();
        let mut echoed = false;
        while !echoed {
            let env = tokio::time::timeout(Duration::from_secs(5), rx.recv())
                .await
                .expect("no timeout")
                .expect("event");
            match env.payload {
                EventPayload::IoChunk(c) if c.stream == StreamKind::Stdin => input.push(c),
                EventPayload::IoChunk(c) if c.stream == StreamKind::Stdout => {
                    let content = c.content.expect("content");
                    echoed = String::from_utf8_lossy(content.as_slice()).contains("***REDACTED***");
                }
                _ => {}
            }
        }
        assert_eq!(recorded(&input), "***REDACTED***\n");
        let offsets: Vec<u64> = input.iter().map(|c| c.stream_offset.get()).collect();
        assert_eq!(offsets, [0]);
        assert_eq!(
            input[0]
                .transform
                .as_ref()
                .and_then(|t| t.original_byte_count),
            Some(22)
        );
        rt.close(&opened.session_id).expect("close");
    }

    /// A write the leader cuts short records every part it took, masked, and never the part of a
    /// secret written before it: the leader reads the secret's line and exits while the rest of
    /// the write, more than a pipe holds, is still going in.
    #[tokio::test]
    async fn an_input_write_the_leader_cuts_short_records_no_raw_part_of_a_secret() {
        let rt = masking_runtime();
        let mut rx = rt.bus.subscribe();
        let opened = rt.open(pipe_args(&["-c", "read -r line"])).expect("open");
        rt.write_input(&opened.session_id, b"split-secr")
            .await
            .expect("first write");
        let mut rest = b"et-value-42\n".to_vec();
        rest.resize(rest.len() + 256 * 1024, b'x');
        assert!(
            rt.write_input(&opened.session_id, &rest).await.is_err(),
            "the leader exits before taking it all"
        );
        let input = recorded(&chunks_until_exit(&mut rx, StreamKind::Stdin).await);
        assert!(
            input.starts_with("***REDACTED***\nx"),
            "{:?}",
            &input[..input.len().min(40)]
        );
        assert!(!input.contains("split"), "no raw part of the secret");
    }

    /// A leader that exited takes no input while its output still drains: here an attach that
    /// stopped reading holds the drain open, and a helper holds the leader's stdin.
    #[tokio::test]
    async fn no_input_is_written_once_the_leader_exited() {
        let rt = runtime();
        let opened = rt
            .open(pipe_args(&[
                "-c",
                "exec 3<&0; sleep 5 <&3 & printf one; sleep 0.1; printf two; sleep 0.1; printf three",
            ]))
            .expect("open");
        let (out_tx, _out_rx) = mpsc::channel::<ServerMessage>(1);
        rt.attach(
            &opened.session_id,
            ChannelId::new("chan_stalled"),
            out_tx,
            Some(0),
        )
        .await
        .expect("attach");
        let entry = rt
            .registry
            .get_running(&opened.session_id)
            .expect("running");
        tokio::time::timeout(Duration::from_secs(5), entry.exit_watch().wait_for(|e| *e))
            .await
            .expect("the leader exits")
            .expect("exit watch");
        assert!(
            rt.registry.get_running(&opened.session_id).is_some(),
            "the output still drains"
        );
        assert!(rt.write_input(&opened.session_id, b"late\n").await.is_err());
    }

    /// The leader's exit cuts the input stream: what the record still holds, a prefix of a
    /// secret here, is masked before the exit, and the session takes no input after it.
    #[tokio::test]
    async fn held_input_is_recorded_before_the_exit() {
        let rt = masking_runtime();
        let mut rx = rt.bus.subscribe();
        let opened = rt.open(pipe_args(&["-c", "sleep 0.3"])).expect("open");
        rt.write_input(&opened.session_id, b"hello split-secr")
            .await
            .expect("write");
        let input = chunks_until_exit(&mut rx, StreamKind::Stdin).await;
        let records: Vec<(u64, String)> = input
            .iter()
            .map(|c| {
                let content = c.content.as_ref().expect("content");
                (
                    c.stream_offset.get(),
                    String::from_utf8_lossy(content.as_slice()).into_owned(),
                )
            })
            .collect();
        assert_eq!(
            records,
            [(0, "hello ".to_owned()), (6, "***REDACTED***".to_owned())]
        );
        assert!(rt.write_input(&opened.session_id, b"late").await.is_err());
    }

    // ---------- pipe mode ----------

    /// A stdin→stdout echo loop in shell builtins only (no `cat` on PATH is assumed).
    const ECHO_LOOP: &str = "while IFS= read -r line; do echo \"$line\"; done";

    fn pipe_args(args: &[&str]) -> OpenSessionArgs {
        OpenSessionArgs {
            user: None,
            mode: SessionMode::Pipe,
            ..session_args(args, 0, 0)
        }
    }

    /// Accumulate `stream` telemetry chunks until `needle` appears (or `within` elapses).
    async fn wait_for_stream(
        rx: &mut Receiver<EventEnvelope>,
        stream: StreamKind,
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
                        && c.stream == stream
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

    /// A pipe session has no controlling terminal; stdout reaches the attach channel and the
    /// journal, stderr reaches telemetry only, and the summary reports the mode.
    #[tokio::test]
    async fn pipe_session_has_no_tty_and_keeps_stderr_off_the_channel() {
        let rt = runtime();
        let mut rx = rt.bus.subscribe();
        let opened = rt
            .open(pipe_args(&[
                "-c",
                "if [ -t 1 ]; then echo tty; else echo notty; fi; echo DIAG >&2; echo DONE",
            ]))
            .expect("open pipe session");
        let (tx, mut out_rx) = mpsc::channel(64);
        let channel = ChannelId::new("chan_pipe_1");
        rt.attach(&opened.session_id, channel.clone(), tx, Some(0))
            .await
            .expect("attach");
        let (out, exit_code) = attach_output_until_end(&mut out_rx, &channel).await;
        let text = String::from_utf8_lossy(&out);
        assert!(
            text.contains("notty"),
            "no controlling tty expected: {text:?}"
        );
        assert!(
            text.contains("DONE"),
            "stdout must reach the channel: {text:?}"
        );
        assert!(
            !text.contains("DIAG"),
            "stderr must never enter the protocol stream: {text:?}"
        );
        assert_eq!(exit_code, Some(0));

        assert!(
            wait_for_stream(&mut rx, StreamKind::Stderr, "DIAG", Duration::from_secs(4)).await,
            "stderr must be recorded as telemetry"
        );

        let out = rt
            .read_output(&opened.session_id, 0, None)
            .expect("journal readable");
        let journal: String = out
            .chunks
            .iter()
            .map(|c| String::from_utf8_lossy(c.data.as_slice()).to_string())
            .collect();
        assert!(journal.contains("DONE") && !journal.contains("DIAG"));

        let summary = rt
            .list()
            .sessions
            .into_iter()
            .find(|s| s.session_id == opened.session_id)
            .expect("listed");
        assert_eq!(summary.mode, SessionMode::Pipe);
        assert_eq!((summary.cols, summary.rows), (0, 0));
    }

    /// stdin writes reach the leader and are recorded as `stdin`; resize is rejected; the
    /// tombstone keeps the scrollback.
    #[tokio::test]
    async fn pipe_session_stdin_round_trips_and_resize_is_rejected() {
        let rt = runtime();
        let mut rx = rt.bus.subscribe();
        let opened = rt.open(pipe_args(&["-c", ECHO_LOOP])).expect("open cat");

        rt.write_input(&opened.session_id, b"hello pipe\n")
            .await
            .expect("write stdin");
        assert!(
            wait_for_stream(
                &mut rx,
                StreamKind::Stdout,
                "hello pipe",
                Duration::from_secs(4)
            )
            .await,
            "stdin must be echoed back on stdout"
        );
        let mut rx2 = rt.bus.subscribe();
        rt.write_input(&opened.session_id, b"second\n")
            .await
            .expect("write stdin");
        assert!(
            wait_for_stream(
                &mut rx2,
                StreamKind::Stdin,
                "second",
                Duration::from_secs(4)
            )
            .await,
            "stdin must be recorded as evidence"
        );

        let err = rt
            .resize(&opened.session_id, 100, 40)
            .expect_err("pipe sessions have no terminal");
        assert!(err.message.contains("no terminal"), "{err:?}");

        rt.close(&opened.session_id).expect("close");
        let deadline = Instant::now() + Duration::from_secs(5);
        while !rt.registry.is_empty() && Instant::now() < deadline {
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        assert!(
            rt.registry.is_empty(),
            "running set should drain after close"
        );
        let out = rt
            .read_output(&opened.session_id, 0, None)
            .expect("tombstone readable");
        assert_eq!(out.state, SessionState::Exited);
        let text: String = out
            .chunks
            .iter()
            .map(|c| String::from_utf8_lossy(c.data.as_slice()).to_string())
            .collect();
        assert!(text.contains("hello pipe"), "scrollback survives: {text:?}");
    }

    /// Reattaching a pipe session from a sequence replays exactly once, then live-tails.
    #[tokio::test]
    async fn pipe_session_reattach_replays_then_tails() {
        let rt = runtime();
        let mut rx = rt.bus.subscribe();
        let opened = rt.open(pipe_args(&["-c", ECHO_LOOP])).expect("open cat");
        rt.write_input(&opened.session_id, b"one\n")
            .await
            .expect("write");
        assert!(wait_for_stream(&mut rx, StreamKind::Stdout, "one", Duration::from_secs(4)).await);

        let (tx, mut out_rx) = mpsc::channel(64);
        let channel = ChannelId::new("chan_pipe_2");
        rt.attach(&opened.session_id, channel.clone(), tx, Some(0))
            .await
            .expect("attach");
        rt.write_input(&opened.session_id, b"two\n")
            .await
            .expect("write");
        // Let the leader echo before hanging it up: close() ends the session, it does not flush
        // pending input through the shell.
        assert!(wait_for_stream(&mut rx, StreamKind::Stdout, "two", Duration::from_secs(4)).await);
        rt.close(&opened.session_id).expect("close");
        let (out, _) = attach_output_until_end(&mut out_rx, &channel).await;
        assert_eq!(String::from_utf8_lossy(&out), "one\ntwo\n");
    }
}
