//! The process-wide spawn↔reap gate: the record of which pids this process spawned.
//!
//! sealantd runs as the container's PID 1 (or a `PR_SET_CHILD_SUBREAPER`), so every orphan a
//! workspace process abandons is reparented to it and has to be reaped
//! ([`crate::platform::spawn_orphan_reaper`]). The reaper peeks at waitable children with
//! `waitid(P_ALL, WNOHANG | WNOWAIT)`, and at that point an adopted orphan and a child this
//! process spawned itself are indistinguishable: both name us as their parent. The only place the
//! difference can be recorded is the spawn itself, which is what this module is — a process-global
//! set of the pids we spawned and have not yet reaped.
//!
//! The rule the reaper follows is therefore: **reap only pids this process did not spawn**
//! ([`decide`]). Every spawn in the daemon goes through the helpers here, which insert the pid
//! while holding [`lock_gate`] — the same lock the reaper holds for a whole sweep — so a child
//! that exits between `spawn()` and its registration can never be observed as an orphan. The pid
//! leaves the set when its spawner has reaped it: [`SpawnedPid`] releases on drop, so a `wait()`
//! (or a dropped child that nobody will wait for) hands the pid back to the reaper.
//!
//! Spawning a child outside this gate is a bug: the reaper will eventually steal its exit status
//! and the spawner's own `wait()` fails with `ECHILD` ("No child process").

use std::collections::HashSet;
use std::io::{self, Read, Write};
use std::process::{Child, ChildStdin, ChildStdout, Command, ExitStatus, Output, Stdio};
use std::sync::mpsc;
use std::sync::{Arc, Condvar, Mutex, MutexGuard, OnceLock, PoisonError};
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

use crate::activity;

/// OS pids this process has spawned and not yet reaped.
pub type SpawnedPids = HashSet<i32>;

fn gate() -> &'static Mutex<SpawnedPids> {
    static GATE: OnceLock<Mutex<SpawnedPids>> = OnceLock::new();
    GATE.get_or_init(|| Mutex::new(SpawnedPids::new()))
}

/// Lock the gate — the spawn↔reap critical section.
///
/// A spawn path holds this guard from just before `spawn()` until the new pid is registered; the
/// orphan reaper holds it for a whole sweep. Prefer the helpers in this module over locking by
/// hand. The lock is never held across a `wait()`.
pub fn lock_gate() -> MutexGuard<'static, SpawnedPids> {
    // A panic inside the critical section can only leave the set as it was (insert/remove are the
    // only operations), so the poison is not meaningful here.
    gate().lock().unwrap_or_else(|e| e.into_inner())
}

/// What the orphan reaper must do with a pid it has peeked at.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReapDecision {
    /// An adopted orphan: nothing in this process is waiting for it, so the reaper must reap it
    /// or it lingers as a zombie.
    Reap,
    /// A child this process spawned: its spawner will `wait()` for it. Reaping it here would steal
    /// the exit status and fail that `wait()` with `ECHILD`.
    LeaveToSpawner,
}

/// The reaper's decision for `pid`, given the gate's contents.
///
/// This is the whole policy: a pid we spawned is never reaped by the reaper, whoever holds it;
/// every other waitable child was adopted (reparented to us as the subreaper) and is ours to reap.
#[must_use]
pub fn decide(spawned: &SpawnedPids, pid: i32) -> ReapDecision {
    if spawned.contains(&pid) {
        ReapDecision::LeaveToSpawner
    } else {
        ReapDecision::Reap
    }
}

/// A pid registered in the gate: while this guard is alive the orphan reaper leaves that pid
/// alone. Dropping it releases the pid, so hold it until the child has been reaped (`wait()`,
/// `wait_with_output()`, or Tokio's `kill_on_drop` queue) and drop it immediately after — a pid
/// held past its reaping can be reused by an unrelated process and stall a sweep.
#[derive(Debug)]
#[must_use = "dropping the guard hands the pid back to the orphan reaper"]
pub struct SpawnedPid(i32);

impl SpawnedPid {
    /// Register `pid` in a gate the caller holds.
    fn register(gate: &mut SpawnedPids, pid: i32) -> Self {
        gate.insert(pid);
        Self(pid)
    }

    /// The pid this guard holds.
    #[must_use]
    pub fn pid(&self) -> i32 {
        self.0
    }
}

impl Drop for SpawnedPid {
    fn drop(&mut self) {
        lock_gate().remove(&self.0);
    }
}

/// Spawn a [`std::process::Command`] under the gate.
///
/// # Errors
/// Returns whatever `Command::spawn` returns.
pub fn spawn_std(command: &mut Command) -> io::Result<(Child, SpawnedPid)> {
    let mut gate = lock_gate();
    let child = command.spawn()?;
    let guard = SpawnedPid::register(&mut gate, child.id() as i32);
    drop(gate);
    Ok((child, guard))
}

/// Spawn a [`tokio::process::Command`] under the gate. The caller must keep the guard until the
/// child has been reaped (usually: move it into the task that awaits `child.wait()`).
///
/// # Errors
/// Returns whatever `tokio::process::Command::spawn` returns.
pub fn spawn_tokio(
    command: &mut tokio::process::Command,
) -> io::Result<(tokio::process::Child, SpawnedPid)> {
    let mut gate = lock_gate();
    let child = command.spawn()?;
    let pid = child.id().map_or(-1, |p| p as i32);
    let guard = SpawnedPid::register(&mut gate, pid);
    drop(gate);
    Ok((child, guard))
}

/// How long a helper may run ([`GatedChild::bound`]): past `overdue` it is reported
/// ([`crate::activity::overdue`]) and logged; past `limit`, when there is one, it is killed
/// (`SIGKILL`) and its wait fails with [`io::ErrorKind::TimedOut`].
#[derive(Debug, Clone)]
pub struct Bound {
    /// What the helper is, for the report and the log (`git cat-file --batch-check`).
    pub label: String,
    /// How long it is expected to take at most.
    pub overdue: Duration,
    /// How long it may run before it is killed; `None`: never killed, only reported (a helper
    /// that writes something in place a kill could leave half-written).
    pub limit: Option<Duration>,
}

/// After a helper was killed, or its bound passed, how long its output may still take to end
/// (a process it started can hold the pipes after it is gone).
const OUTPUT_GRACE: Duration = Duration::from_secs(2);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Watch {
    /// The child runs; the watchdog may kill it.
    Running,
    /// The child exited and is about to be reaped: nothing may signal its pid any more.
    Reaping,
    /// The watchdog killed it.
    Killed,
}

/// Kills a helper that outlives its [`Bound`]. The kill is taken under the same lock the waiter
/// takes once it has seen the child exit and before it reaps it, so the pid signalled is always
/// this child's (alive, or a zombie nobody has reaped): never a pid the system gave to another
/// process since.
#[derive(Debug)]
struct Watchdog {
    shared: Arc<(Mutex<Watch>, Condvar)>,
    thread: Option<JoinHandle<()>>,
    started: Instant,
    bound: Bound,
    /// Registered for as long as the child runs (the thread holds the other handle).
    _step: Arc<activity::Step>,
}

impl Watchdog {
    fn arm(pid: i32, bound: Bound) -> Self {
        let step = Arc::new(activity::enter(&bound.label, bound.overdue));
        let shared = Arc::new((Mutex::new(Watch::Running), Condvar::new()));
        let started = Instant::now();
        let thread = {
            let shared = Arc::clone(&shared);
            let bound = bound.clone();
            let step = Arc::clone(&step);
            std::thread::Builder::new()
                .name("helper-watchdog".to_owned())
                .spawn(move || {
                    let (lock, cv) = &*shared;
                    let running = |w: &mut Watch| *w == Watch::Running;
                    let guard = lock.lock().unwrap_or_else(PoisonError::into_inner);
                    let (guard, _) = cv
                        .wait_timeout_while(guard, bound.overdue, running)
                        .unwrap_or_else(PoisonError::into_inner);
                    if *guard == Watch::Running {
                        step.report_if_overdue();
                    }
                    let Some(limit) = bound.limit else {
                        drop(
                            cv.wait_while(guard, running)
                                .unwrap_or_else(PoisonError::into_inner),
                        );
                        return;
                    };
                    let rest = limit.saturating_sub(started.elapsed());
                    let (mut guard, _) = cv
                        .wait_timeout_while(guard, rest, running)
                        .unwrap_or_else(PoisonError::into_inner);
                    if *guard == Watch::Running {
                        let _ = nix::sys::signal::kill(
                            nix::unistd::Pid::from_raw(pid),
                            nix::sys::signal::Signal::SIGKILL,
                        );
                        *guard = Watch::Killed;
                        tracing::error!(
                            pid,
                            helper = %bound.label,
                            limit_s = limit.as_secs(),
                            "a helper was still running at its limit; killed"
                        );
                    }
                })
                .ok()
        };
        Self {
            shared,
            thread,
            started,
            bound,
            _step: step,
        }
    }

    /// The child exited (not reaped yet): stop the watchdog. Whether it had killed it.
    fn disarm(&mut self) -> bool {
        let killed = {
            let (lock, cv) = &*self.shared;
            let mut watch = lock.lock().unwrap_or_else(PoisonError::into_inner);
            if *watch == Watch::Running {
                *watch = Watch::Reaping;
            }
            cv.notify_all();
            *watch == Watch::Killed
        };
        if let Some(thread) = self.thread.take() {
            let _ = thread.join();
        }
        killed
    }

    fn timed_out(&self) -> io::Error {
        io::Error::new(
            io::ErrorKind::TimedOut,
            format!(
                "{}: still running after {} s; killed",
                self.bound.label,
                self.bound.limit.unwrap_or_default().as_secs()
            ),
        )
    }

    /// How long the output of a child that exited may still take to end.
    fn output_wait(&self, killed: bool) -> Duration {
        match self.bound.limit {
            Some(_) if killed => OUTPUT_GRACE,
            Some(limit) => limit
                .saturating_sub(self.started.elapsed())
                .max(OUTPUT_GRACE),
            None => Duration::MAX,
        }
    }
}

impl Drop for Watchdog {
    /// A child dropped without a wait goes back to the orphan reaper, and its pid can be reused:
    /// the watchdog stops first ([`GatedChild`] drops it before the pid guard).
    fn drop(&mut self) {
        self.disarm();
    }
}

/// Wait until `pid` (a child of this process) has exited, without reaping it (`WNOWAIT`).
fn wait_exited(pid: i32) -> io::Result<()> {
    use nix::sys::wait::{Id, WaitPidFlag, waitid};
    loop {
        match waitid(
            Id::Pid(nix::unistd::Pid::from_raw(pid)),
            WaitPidFlag::WEXITED | WaitPidFlag::WNOWAIT,
        ) {
            Ok(_) => return Ok(()),
            Err(nix::errno::Errno::EINTR) => {}
            Err(errno) => return Err(io::Error::from(errno)),
        }
    }
}

/// Read `pipe` to its end on its own thread.
fn drain(mut pipe: impl Read + Send + 'static) -> mpsc::Receiver<io::Result<Vec<u8>>> {
    let (tx, rx) = mpsc::channel();
    std::thread::spawn(move || {
        let mut bytes = Vec::new();
        let _ = tx.send(pipe.read_to_end(&mut bytes).map(|_| bytes));
    });
    rx
}

/// A blocking child spawned under the gate. Reaping it (`wait`/`wait_with_output`) releases its
/// pid; so does dropping it without waiting, which is correct — nobody is left to `wait()`, so the
/// orphan reaper should collect the zombie.
#[derive(Debug)]
pub struct GatedChild {
    // Dropped first: a watchdog never outlives the pid guard.
    watchdog: Option<Watchdog>,
    child: Child,
    spawned: SpawnedPid,
}

impl GatedChild {
    /// The child's OS pid.
    #[must_use]
    pub fn pid(&self) -> i32 {
        self.spawned.pid()
    }

    /// Bound how long the child may run ([`Bound`]): reported once it runs past `overdue`,
    /// killed at `limit`, when its wait then fails with [`io::ErrorKind::TimedOut`]. A second
    /// call is ignored.
    pub fn bound(&mut self, bound: Bound) {
        if self.watchdog.is_none() {
            self.watchdog = Some(Watchdog::arm(self.spawned.pid(), bound));
        }
    }

    /// Take the child's stdin pipe (present only when the command asked for one).
    pub fn take_stdin(&mut self) -> Option<ChildStdin> {
        self.child.stdin.take()
    }

    /// Take the child's stdout pipe (present only when the command asked for one), to stream
    /// what it writes; [`Self::wait_with_output`] then collects stderr only.
    pub fn take_stdout(&mut self) -> Option<ChildStdout> {
        self.child.stdout.take()
    }

    /// Wait for the child, collecting its piped stdout/stderr. A stdin pipe still held is
    /// closed first.
    ///
    /// # Errors
    /// Spawning a reader, waiting, reading; [`io::ErrorKind::TimedOut`] when a [`Bound`] killed
    /// the child.
    pub fn wait_with_output(self) -> io::Result<Output> {
        self.communicate(None)
    }

    /// Write `input` to the child's stdin on a thread of its own while its stdout and stderr are
    /// read on two more, then reap it. Nothing here waits for one pipe while the child waits on
    /// another: written first and read after, a child whose answers fill its stdout pipe stops
    /// reading, its stdin pipe fills, and both sides wait for good (Docker end to end, round 8:
    /// `git cat-file --batch-check` with 8 KiB pipes). `None` (or no stdin pipe) closes stdin.
    ///
    /// # Errors
    /// Waiting, reading; [`io::ErrorKind::TimedOut`] when a [`Bound`] killed the child, or its
    /// output did not end within the bound after it exited.
    pub fn communicate(self, input: Option<Vec<u8>>) -> io::Result<Output> {
        let Self {
            mut child,
            spawned,
            mut watchdog,
        } = self;
        // Detached: once the child is gone its stdin is closed and the write ends (EPIPE).
        if let Some(mut pipe) = child.stdin.take()
            && let Some(input) = input
        {
            std::thread::spawn(move || {
                // A closed pipe (the child exited early) surfaces as its status.
                let _ = pipe.write_all(&input);
            });
        }
        let stdout = child.stdout.take().map(drain);
        let stderr = child.stderr.take().map(drain);
        let exited = wait_exited(spawned.pid());
        let killed = watchdog.as_mut().is_some_and(Watchdog::disarm);
        let status = child.wait();
        drop(spawned);
        exited?;
        let status = status?;
        let deadline = watchdog
            .as_ref()
            .and_then(|w| Instant::now().checked_add(w.output_wait(killed)));
        let collect = |rx: Option<mpsc::Receiver<io::Result<Vec<u8>>>>| -> io::Result<Vec<u8>> {
            let Some(rx) = rx else {
                return Ok(Vec::new());
            };
            match deadline {
                Some(deadline) => rx
                    .recv_timeout(deadline.saturating_duration_since(Instant::now()))
                    .map_err(|_| {
                        io::Error::new(
                            io::ErrorKind::TimedOut,
                            "a helper's output did not end after it exited",
                        )
                    })?,
                None => rx
                    .recv()
                    .map_err(|_| io::Error::other("a helper's output reader stopped"))?,
            }
        };
        let stdout = collect(stdout);
        let stderr = collect(stderr);
        if killed && let Some(watchdog) = &watchdog {
            return Err(watchdog.timed_out());
        }
        Ok(Output {
            status,
            stdout: stdout?,
            stderr: stderr?,
        })
    }

    /// Wait for the child.
    ///
    /// # Errors
    /// Returns whatever `Child::wait` returns; [`io::ErrorKind::TimedOut`] when a [`Bound`]
    /// killed the child.
    pub fn wait(self) -> io::Result<ExitStatus> {
        let Self {
            mut child,
            spawned,
            watchdog,
        } = self;
        let Some(mut watchdog) = watchdog else {
            let status = child.wait();
            drop(spawned);
            return status;
        };
        let exited = wait_exited(spawned.pid());
        let killed = watchdog.disarm();
        let status = child.wait();
        drop(spawned);
        exited?;
        if killed {
            return Err(watchdog.timed_out());
        }
        status
    }
}

/// Gated equivalents of the blocking [`std::process::Command`] terminators. Every daemon-internal
/// spawn uses these instead of `spawn`/`output`/`status` so the orphan reaper never mistakes the
/// child for an adopted orphan (see the module docs).
pub trait CommandGateExt {
    /// Like [`Command::spawn`], with the pid registered in the gate.
    ///
    /// # Errors
    /// Returns whatever `Command::spawn` returns.
    fn spawn_gated(&mut self) -> io::Result<GatedChild>;

    /// Like [`Command::output`] — stdout and stderr are captured — except that stdin is left as
    /// the command configured it (`Command::output` defaults it to null), so set it explicitly.
    ///
    /// # Errors
    /// Returns whatever spawning or waiting for the child returns.
    fn output_gated(&mut self) -> io::Result<Output>;

    /// Like [`Command::status`]: stdio is inherited unless the command says otherwise.
    ///
    /// # Errors
    /// Returns whatever spawning or waiting for the child returns.
    fn status_gated(&mut self) -> io::Result<ExitStatus>;
}

impl CommandGateExt for Command {
    fn spawn_gated(&mut self) -> io::Result<GatedChild> {
        let (child, spawned) = spawn_std(self)?;
        Ok(GatedChild {
            child,
            spawned,
            watchdog: None,
        })
    }

    fn output_gated(&mut self) -> io::Result<Output> {
        self.stdout(Stdio::piped()).stderr(Stdio::piped());
        self.spawn_gated()?.wait_with_output()
    }

    fn status_gated(&mut self) -> io::Result<ExitStatus> {
        self.spawn_gated()?.wait()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_spawned_pid_is_never_reaped_and_an_adopted_one_always_is() {
        let mut spawned = SpawnedPids::new();
        spawned.insert(4242);
        assert_eq!(decide(&spawned, 4242), ReapDecision::LeaveToSpawner);
        assert_eq!(decide(&spawned, 4243), ReapDecision::Reap);
        assert_eq!(decide(&SpawnedPids::new(), 4242), ReapDecision::Reap);
    }

    #[test]
    fn the_guard_registers_on_spawn_and_releases_on_reap() {
        let mut child = Command::new("/bin/sh")
            .args(["-c", "exit 7"])
            .spawn_gated()
            .expect("spawn");
        let pid = child.pid();
        assert_eq!(decide(&lock_gate(), pid), ReapDecision::LeaveToSpawner);
        assert!(child.take_stdin().is_none());
        let status = child.wait().expect("wait");
        assert_eq!(status.code(), Some(7));
        assert_eq!(
            decide(&lock_gate(), pid),
            ReapDecision::Reap,
            "a reaped child's pid must go back to the reaper"
        );
    }

    #[test]
    fn a_dropped_child_releases_its_pid_to_the_reaper() {
        let child = Command::new("/bin/sh")
            .args(["-c", "exit 0"])
            .spawn_gated()
            .expect("spawn");
        let pid = child.pid();
        drop(child);
        assert_eq!(decide(&lock_gate(), pid), ReapDecision::Reap);
    }

    /// Docker end to end, round 8 (F1): 4 MiB through `cat` is more than any pipe holds, in
    /// either direction. Written first and read after, both sides would wait for good.
    #[test]
    fn communicate_feeds_stdin_while_it_reads_stdout() {
        let input: Vec<u8> = (0..4 * 1024 * 1024u32).map(|i| (i % 251) as u8).collect();
        let child = Command::new("/bin/sh")
            .args(["-c", "cat; printf done >&2"])
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn_gated()
            .expect("spawn");
        let (tx, rx) = std::sync::mpsc::channel();
        let fed = input.clone();
        std::thread::spawn(move || {
            let _ = tx.send(child.communicate(Some(fed)));
        });
        let out = rx
            .recv_timeout(Duration::from_secs(60))
            .expect("no pipe deadlock")
            .expect("communicate");
        assert!(out.status.success());
        assert!(out.stdout == input, "every byte back, in order");
        assert_eq!(out.stderr, b"done");
    }

    /// A helper that outlives its bound is reported past `overdue`, killed at `limit`, reaped,
    /// and its wait says so; its pid goes back to the reaper.
    #[test]
    fn a_bounded_helper_is_reported_then_killed() {
        let mut child = Command::new("/bin/sh")
            .args(["-c", "exec sleep 30"])
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn_gated()
            .expect("spawn");
        let pid = child.pid();
        child.bound(Bound {
            label: "spawn-test sleep".to_owned(),
            overdue: Duration::from_millis(50),
            limit: Some(Duration::from_millis(600)),
        });
        let started = Instant::now();
        let (tx, rx) = std::sync::mpsc::channel();
        std::thread::spawn(move || {
            let _ = tx.send(child.wait_with_output());
        });
        std::thread::sleep(Duration::from_millis(250));
        let overdue = crate::activity::overdue().expect("reported past its bound");
        assert!(overdue.bound <= Duration::from_millis(600), "{overdue:?}");
        let waited = rx.recv_timeout(Duration::from_secs(20)).expect("killed");
        let error = waited.expect_err("a killed helper is an error");
        assert_eq!(error.kind(), io::ErrorKind::TimedOut, "{error}");
        assert!(error.to_string().contains("spawn-test sleep"), "{error}");
        assert!(started.elapsed() < Duration::from_secs(10));
        assert_eq!(decide(&lock_gate(), pid), ReapDecision::Reap);
        assert!(
            !std::path::Path::new(&format!("/proc/{pid}")).exists()
                || std::fs::read_to_string(format!("/proc/{pid}/stat"))
                    .is_ok_and(|s| !s.contains("sleep")),
            "the helper is gone"
        );
    }

    /// A bound does not change what a helper that finishes in time answers.
    #[test]
    fn a_bounded_helper_that_finishes_answers_as_before() {
        let mut child = Command::new("/bin/sh")
            .args(["-c", "printf hello; exit 3"])
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn_gated()
            .expect("spawn");
        child.bound(Bound {
            label: "spawn-test printf".to_owned(),
            overdue: Duration::from_secs(60),
            limit: Some(Duration::from_secs(120)),
        });
        let out = child.wait_with_output().expect("output");
        assert_eq!(out.status.code(), Some(3));
        assert_eq!(out.stdout, b"hello");
    }

    #[test]
    fn output_gated_captures_stdout() {
        let out = Command::new("/bin/sh")
            .args(["-c", "printf hello"])
            .stdin(Stdio::null())
            .output_gated()
            .expect("output");
        assert!(out.status.success());
        assert_eq!(out.stdout, b"hello");
    }
}
