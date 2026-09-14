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
use std::io;
use std::process::{Child, ChildStdin, Command, ExitStatus, Output, Stdio};
use std::sync::{Mutex, MutexGuard, OnceLock};

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

/// A blocking child spawned under the gate. Reaping it (`wait`/`wait_with_output`) releases its
/// pid; so does dropping it without waiting, which is correct — nobody is left to `wait()`, so the
/// orphan reaper should collect the zombie.
#[derive(Debug)]
pub struct GatedChild {
    child: Child,
    spawned: SpawnedPid,
}

impl GatedChild {
    /// The child's OS pid.
    #[must_use]
    pub fn pid(&self) -> i32 {
        self.spawned.pid()
    }

    /// Take the child's stdin pipe (present only when the command asked for one).
    pub fn take_stdin(&mut self) -> Option<ChildStdin> {
        self.child.stdin.take()
    }

    /// Wait for the child, collecting its piped stdout/stderr.
    ///
    /// # Errors
    /// Returns whatever `Child::wait_with_output` returns.
    pub fn wait_with_output(self) -> io::Result<Output> {
        let Self { child, spawned } = self;
        let out = child.wait_with_output();
        drop(spawned);
        out
    }

    /// Wait for the child.
    ///
    /// # Errors
    /// Returns whatever `Child::wait` returns.
    pub fn wait(self) -> io::Result<ExitStatus> {
        let Self { mut child, spawned } = self;
        let status = child.wait();
        drop(spawned);
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
        Ok(GatedChild { child, spawned })
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
