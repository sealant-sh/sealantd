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
//! and the spawner's own `wait()` fails with `ECHILD` ("No child process"). The workspace's
//! `clippy.toml` makes the bare `spawn`/`output`/`status` of both `Command`s a lint error.

use std::collections::HashSet;
use std::io::{self, Read, Write};
use std::process::{Child, ChildStdin, ChildStdout, Command, ExitStatus, Output, Stdio};
use std::sync::atomic::{AtomicBool, Ordering};
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

/// No process starts from a thread acting with a person's filesystem identity
/// ([`crate::identity::RunAs::as_fs_user`]): its child would run as root.
fn refuse_on_fs_user_thread() -> io::Result<()> {
    if crate::identity::on_fs_user_thread() {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "a process may not start from a thread acting as a person's filesystem identity \
             (it would run as root)",
        ));
    }
    Ok(())
}

/// Mark every descriptor from 3 up close-on-exec, leaving 0 to 2 as they are. Nothing here
/// allocates or takes a lock, so it may run between fork and exec.
///
/// `close_range(3, ~0U, CLOSE_RANGE_CLOEXEC)` does it in one system call on Linux 5.11 and later.
/// A kernel without it (`ENOSYS` before 5.9, `EINVAL` for the flag before 5.11: Debian 11,
/// Amazon Linux 2, RHEL 8) gets [`mark_by_walking`]: every descriptor `/proc/self/fd` lists, read
/// with `getdents64` into a buffer on the stack, marked with `fcntl`.
///
/// # Errors
/// When neither works: the walk's error.
pub fn mark_inherited_close_on_exec() -> io::Result<()> {
    match close_range_cloexec() {
        Err(error) if matches!(error.raw_os_error(), Some(libc::ENOSYS | libc::EINVAL)) => {
            mark_by_walking()
        }
        result => result,
    }
}

/// Whether this process has run its start marking ([`mark_at_start`]).
static STARTED: AtomicBool = AtomicBool::new(false);

/// What sealantd does first: mark every descriptor its launcher left open from 3 up close-on-exec
/// ([`mark_inherited_close_on_exec`]), and record that it did, for the check before a helper
/// spawn ([`sweep_before_helper_spawn`]).
///
/// # Errors
/// The marking's.
pub fn mark_at_start() -> io::Result<()> {
    mark_inherited_close_on_exec()?;
    STARTED.store(true, Ordering::Release);
    Ok(())
}

/// Before a helper spawn ([`spawn_helper_std`]), in the parent: every descriptor from 3 up is
/// marked close-on-exec, so the child needs no `pre_exec` and std starts it with `posix_spawn`
/// (any `pre_exec` makes std fork, and a fork copies the page tables: about 16 µs per resident
/// MiB, 0.37 s more for a small snap of a 900 MB capture).
///
/// It is a backstop for a missing flag, not a replacement for it. A descriptor another thread
/// opens without close-on-exec between this sweep and the spawn is still inherited, so every
/// open in sealantd must set `O_CLOEXEC`.
///
/// Test and debug builds check that first: once the start marking has run, a descriptor from 3
/// up without close-on-exec is a missing `O_CLOEXEC`, and the sweep panics naming it. Two kinds
/// are let through:
/// 1. Every descriptor, before this process's start marking has run: a process that never ran
///    sealantd's start (a test binary, whose launcher, cargo or a CI runner, may pass it pipes
///    without the flag) gets the start marking here instead, and nothing is checked.
/// 2. In this crate's own tests, the descriptors they plant without the flag on purpose.
///
/// # Errors
/// The marking's: no helper starts when it fails.
pub fn sweep_before_helper_spawn() -> io::Result<()> {
    if !cfg!(any(test, debug_assertions)) {
        return mark_inherited_close_on_exec();
    }
    // Held through the marking: a test checks that its plant is inheritable while it holds this.
    #[cfg(test)]
    let planted = PLANTED.lock().unwrap_or_else(PoisonError::into_inner);
    #[cfg(test)]
    let planted = |fd| planted.contains(&fd);
    #[cfg(not(test))]
    let planted = |_: i32| false;
    if STARTED.load(Ordering::Acquire) {
        assert_close_on_exec(planted)?;
    }
    mark_at_start()
}

/// Panic when a descriptor from 3 up of this process, not `planted`, lacks close-on-exec. One
/// gone before it is read is skipped; so is the listing's own, closed before any is read.
#[allow(
    unsafe_code,
    reason = "F_GETFD on a descriptor number this process may close meanwhile: EBADF then"
)]
fn assert_close_on_exec(planted: impl Fn(i32) -> bool) -> io::Result<()> {
    let mut fds = Vec::new();
    for entry in std::fs::read_dir("/proc/self/fd")? {
        if let Some(fd) = entry?
            .file_name()
            .to_str()
            .and_then(|n| n.parse::<i32>().ok())
        {
            fds.push(fd);
        }
    }
    for fd in fds.into_iter().filter(|&fd| fd >= 3 && !planted(fd)) {
        // SAFETY: F_GETFD reads a descriptor's flags and touches no memory of ours.
        let flags = unsafe { libc::fcntl(fd, libc::F_GETFD) };
        if flags < 0 || flags & libc::FD_CLOEXEC != 0 {
            continue;
        }
        let Ok(target) = std::fs::read_link(format!("/proc/self/fd/{fd}")) else {
            continue;
        };
        panic!(
            "fd {fd} ({}) is open without close-on-exec; a helper spawn would pass it on (open \
             it with O_CLOEXEC)",
            target.display()
        );
    }
    Ok(())
}

/// The descriptors this crate's tests plant without close-on-exec on purpose: the check before
/// a helper spawn lets them through, so tests that run at once do not trip it on each other's.
#[cfg(test)]
static PLANTED: std::sync::LazyLock<Mutex<HashSet<i32>>> =
    std::sync::LazyLock::new(|| Mutex::new(HashSet::new()));

#[cfg(test)]
thread_local! {
    /// What a test makes the marking do on its own thread, and in what that thread spawns (a
    /// child is a copy of the thread that forked it): 0 as it is, 1 as on a kernel without
    /// `close_range` (the walk), 2 also with a walk that cannot open `/proc/self/fd`.
    static PRETEND: std::cell::Cell<u8> = const { std::cell::Cell::new(0) };
}

#[cfg(test)]
fn pretend() -> u8 {
    PRETEND.with(std::cell::Cell::get)
}

#[cfg(not(test))]
fn pretend() -> u8 {
    0
}

fn close_range_cloexec() -> io::Result<()> {
    if pretend() > 0 {
        return Err(io::Error::from_raw_os_error(libc::ENOSYS));
    }
    #[allow(
        unsafe_code,
        reason = "a raw system call: libc has no close_range wrapper on musl"
    )]
    // SAFETY: close_range takes two descriptor numbers and flags, and touches no memory of ours.
    let result = unsafe {
        libc::syscall(
            libc::SYS_close_range,
            3 as libc::c_uint,
            libc::c_uint::MAX,
            libc::CLOSE_RANGE_CLOEXEC,
        )
    };
    if result == 0 {
        Ok(())
    } else {
        Err(io::Error::last_os_error())
    }
}

/// Mark every descriptor from 3 up that `/proc/self/fd` lists close-on-exec: the directory read
/// with raw `getdents64` into a buffer on the stack, each name parsed as a number in place, each
/// descriptor marked with `fcntl(F_SETFD, FD_CLOEXEC)`. No allocation, no lock: open, getdents64,
/// fcntl and close are all safe between fork and exec. The directory's own descriptor is opened
/// close-on-exec and closed before it returns.
///
/// # Errors
/// Opening or reading `/proc/self/fd`, or marking a descriptor it lists (one gone by then is
/// skipped).
#[allow(
    unsafe_code,
    reason = "raw system calls on a stack buffer: nothing here may allocate between fork and exec"
)]
fn mark_by_walking() -> io::Result<()> {
    let path: &std::ffi::CStr = if pretend() == 2 {
        c"/proc/self/sealant-no-such-directory"
    } else {
        c"/proc/self/fd"
    };
    // SAFETY: a NUL-terminated path and flags; the descriptor is closed on every path below.
    let dir = unsafe {
        libc::open(
            path.as_ptr(),
            libc::O_RDONLY | libc::O_DIRECTORY | libc::O_CLOEXEC,
        )
    };
    if dir < 0 {
        return Err(io::Error::last_os_error());
    }
    let result = walk(dir);
    // SAFETY: `dir` is the descriptor opened above, closed once.
    unsafe { libc::close(dir) };
    result
}

/// The walk of [`mark_by_walking`] over the open directory `dir`.
#[allow(
    unsafe_code,
    reason = "raw system calls on a stack buffer: nothing here may allocate between fork and exec"
)]
fn walk(dir: libc::c_int) -> io::Result<()> {
    // `struct linux_dirent64` needs 8-byte alignment: a buffer of u64.
    let mut buf = [0u64; 512];
    let size = std::mem::size_of_val(&buf);
    loop {
        // SAFETY: getdents64 writes at most `size` bytes into `buf`, which outlives the call.
        let read = unsafe { libc::syscall(libc::SYS_getdents64, dir, buf.as_mut_ptr(), size) };
        if read < 0 {
            return Err(io::Error::last_os_error());
        }
        if read == 0 {
            return Ok(());
        }
        let read = usize::try_from(read).unwrap_or(0).min(size);
        let bytes = buf.as_ptr().cast::<u8>();
        let mut offset = 0;
        // Each record: d_ino (u64), d_off (i64), d_reclen (u16), d_type (u8), d_name (NUL-ended).
        while offset + 19 < read {
            // SAFETY: `offset + 19 < read <= size`: the record's header lies inside the buffer.
            let reclen =
                usize::from(unsafe { bytes.add(offset + 16).cast::<u16>().read_unaligned() });
            if reclen == 0 || offset + reclen > read {
                return Err(io::Error::from_raw_os_error(libc::EIO));
            }
            let mut fd: libc::c_int = 0;
            let mut digits = 0;
            let mut name = offset + 19;
            while name < offset + reclen {
                // SAFETY: `name < offset + reclen <= read`: inside the record.
                let byte = unsafe { *bytes.add(name) };
                if !byte.is_ascii_digit() {
                    break;
                }
                fd = fd
                    .saturating_mul(10)
                    .saturating_add(libc::c_int::from(byte - b'0'));
                digits += 1;
                name += 1;
            }
            // `.` and `..` have no digits; every other name is a descriptor number.
            if digits > 0 && fd >= 3 && fd != dir {
                // SAFETY: F_SETFD on a descriptor number; a closed one answers EBADF.
                let marked = unsafe { libc::fcntl(fd, libc::F_SETFD, libc::FD_CLOEXEC) };
                if marked < 0 {
                    let error = io::Error::last_os_error();
                    if error.raw_os_error() != Some(libc::EBADF) {
                        return Err(error);
                    }
                }
            }
            offset += reclen;
        }
    }
}

/// A child gets its stdin, stdout and stderr, and no other descriptor of sealantd's: in the
/// child, after its stdio is in place and just before it execs, every descriptor from 3 up is
/// marked close-on-exec ([`mark_inherited_close_on_exec`]) — one sealantd opened without the
/// flag, or inherited from whatever started it, included (sealantd#183). The error pipe std
/// reports a failed exec through is already close-on-exec, and stays open until the exec. When the
/// marking fails (neither `close_range` nor the `/proc/self/fd` walk works), the spawn fails: no
/// child starts with descriptors it was not given.
fn close_inherited_on_exec(command: &mut Command) {
    use std::os::unix::process::CommandExt;
    #[allow(
        unsafe_code,
        reason = "pre_exec: the closure runs in the child between fork and exec"
    )]
    // SAFETY: the closure makes one system call and builds an `io::Error` from errno (no
    // allocation): nothing that is unsafe between fork and exec in a multithreaded process.
    unsafe {
        command.pre_exec(mark_inherited_close_on_exec);
    }
}

/// Spawn a [`std::process::Command`] under the gate. The child gets no descriptor of this
/// process beyond the stdio it is given ([`close_inherited_on_exec`]). This is the spawn for
/// anything that may run as a person, or whose program or arguments come from a request; only
/// sealantd's own helpers may use [`spawn_helper_std`].
///
/// # Errors
/// Returns whatever `Command::spawn` returns; `PermissionDenied` from a thread acting with a
/// person's filesystem identity.
pub fn spawn_std(command: &mut Command) -> io::Result<(Child, SpawnedPid)> {
    refuse_on_fs_user_thread()?;
    close_inherited_on_exec(command);
    spawn_registered(command)
}

/// Spawn one of sealantd's own helpers under the gate: a process sealantd runs as itself, with
/// no identity change (no uid, gid or groups set, no [`crate::identity::RunAs`]), and a program
/// and arguments sealantd chose. Anything else spawns with [`spawn_std`].
///
/// The child gets no `pre_exec`, so std starts it with `posix_spawn` instead of a fork; the
/// descriptors are marked close-on-exec in this process first instead
/// ([`sweep_before_helper_spawn`]).
///
/// # Errors
/// The sweep's, then whatever `Command::spawn` returns; `PermissionDenied` from a thread acting
/// with a person's filesystem identity.
pub fn spawn_helper_std(command: &mut Command) -> io::Result<(Child, SpawnedPid)> {
    refuse_on_fs_user_thread()?;
    sweep_before_helper_spawn()?;
    spawn_registered(command)
}

/// `command.spawn()`, its pid registered under the lock it is spawned under.
fn spawn_registered(command: &mut Command) -> io::Result<(Child, SpawnedPid)> {
    let mut gate = lock_gate();
    #[allow(
        clippy::disallowed_methods,
        reason = "the gate itself: the pid is registered under the lock it is spawned under"
    )]
    let child = command.spawn()?;
    let guard = SpawnedPid::register(&mut gate, child.id() as i32);
    drop(gate);
    Ok((child, guard))
}

/// Spawn a [`tokio::process::Command`] under the gate. The caller must keep the guard until the
/// child has been reaped (usually: move it into the task that awaits `child.wait()`). The child
/// gets no descriptor of this process beyond the stdio it is given ([`close_inherited_on_exec`]),
/// whoever it runs as and whatever it runs.
///
/// # Errors
/// Returns whatever `tokio::process::Command::spawn` returns; `PermissionDenied` from a thread
/// acting with a person's filesystem identity.
pub fn spawn_tokio(
    command: &mut tokio::process::Command,
) -> io::Result<(tokio::process::Child, SpawnedPid)> {
    refuse_on_fs_user_thread()?;
    close_inherited_on_exec(command.as_std_mut());
    let mut gate = lock_gate();
    #[allow(
        clippy::disallowed_methods,
        reason = "the gate itself: the pid is registered under the lock it is spawned under"
    )]
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
///
/// The `*_gated` ones ([`spawn_std`]) are the default, for anything that may run as a person or
/// whose program or arguments come from a request. The `*_helper` ones ([`spawn_helper_std`])
/// are only for a process sealantd runs as itself, with no identity change, and a program and
/// arguments sealantd chose.
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

    /// [`Self::spawn_gated`] for one of sealantd's own helpers ([`spawn_helper_std`]).
    ///
    /// # Errors
    /// The sweep's, or whatever `Command::spawn` returns.
    fn spawn_helper(&mut self) -> io::Result<GatedChild>;

    /// [`Self::output_gated`] for one of sealantd's own helpers ([`spawn_helper_std`]).
    ///
    /// # Errors
    /// Returns whatever spawning or waiting for the child returns.
    fn output_helper(&mut self) -> io::Result<Output>;

    /// [`Self::status_gated`] for one of sealantd's own helpers ([`spawn_helper_std`]).
    ///
    /// # Errors
    /// Returns whatever spawning or waiting for the child returns.
    fn status_helper(&mut self) -> io::Result<ExitStatus>;
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

    fn spawn_helper(&mut self) -> io::Result<GatedChild> {
        let (child, spawned) = spawn_helper_std(self)?;
        Ok(GatedChild {
            child,
            spawned,
            watchdog: None,
        })
    }

    fn output_helper(&mut self) -> io::Result<Output> {
        self.stdout(Stdio::piped()).stderr(Stdio::piped());
        self.spawn_helper()?.wait_with_output()
    }

    fn status_helper(&mut self) -> io::Result<ExitStatus> {
        self.spawn_helper()?.wait()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A descriptor of this process without close-on-exec, as a launcher may leave one (`dup`
    /// copies without the flag), and its number. It is registered as planted ([`PLANTED`]) until
    /// it is closed, under the same lock the check before a helper spawn holds, so that check
    /// never sees it unregistered and never marks it before it is checked here.
    fn inheritable_fd() -> (Planted, i32) {
        use std::os::fd::AsRawFd;
        let mut planted = PLANTED.lock().unwrap_or_else(PoisonError::into_inner);
        let null = std::fs::File::open("/dev/null").expect("open /dev/null");
        let fd = nix::unistd::dup(&null).expect("dup");
        let flags = nix::fcntl::fcntl(&fd, nix::fcntl::FcntlArg::F_GETFD).expect("F_GETFD");
        assert!(
            !nix::fcntl::FdFlag::from_bits_truncate(flags).contains(nix::fcntl::FdFlag::FD_CLOEXEC),
            "the planted descriptor is inheritable"
        );
        let n = fd.as_raw_fd();
        planted.insert(n);
        (Planted(Some(fd)), n)
    }

    /// A planted descriptor: closed and unregistered together, under the lock.
    struct Planted(Option<std::os::fd::OwnedFd>);

    impl std::os::fd::AsFd for Planted {
        fn as_fd(&self) -> std::os::fd::BorrowedFd<'_> {
            self.0.as_ref().expect("open until dropped").as_fd()
        }
    }

    impl Drop for Planted {
        fn drop(&mut self) {
            use std::os::fd::AsRawFd;
            let mut planted = PLANTED.lock().unwrap_or_else(PoisonError::into_inner);
            if let Some(fd) = self.0.take() {
                let n = fd.as_raw_fd();
                drop(fd);
                planted.remove(&n);
            }
        }
    }

    /// Whether `fd` is marked close-on-exec.
    fn close_on_exec(fd: &impl std::os::fd::AsFd) -> bool {
        let flags = nix::fcntl::fcntl(fd, nix::fcntl::FcntlArg::F_GETFD).expect("F_GETFD");
        nix::fcntl::FdFlag::from_bits_truncate(flags).contains(nix::fcntl::FdFlag::FD_CLOEXEC)
    }

    /// The marking in this process, under the plants' lock (see [`inheritable_fd`]).
    fn mark_here() -> io::Result<()> {
        let _planted = PLANTED.lock().unwrap_or_else(PoisonError::into_inner);
        mark_inherited_close_on_exec()
    }

    /// A shell that echoes its stdin to stdout, writes to stderr, and says whether it holds `fd`.
    fn probe(fd: i32) -> [String; 2] {
        [
            "-c".to_owned(),
            format!(
                "read line; echo \"out:$line\"; echo err >&2; \
                 if [ -e /proc/$$/fd/{fd} ]; then echo held; else echo gone; fi"
            ),
        ]
    }

    /// A child of `spawn_std` keeps its stdin, stdout and stderr, and gets no other descriptor of
    /// this process: not one without close-on-exec either (sealantd#183).
    #[test]
    fn a_std_child_gets_its_stdio_and_no_other_descriptor() {
        let (_fd, n) = inheritable_fd();
        let out = Command::new("/bin/sh")
            .args(probe(n))
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn_gated()
            .expect("spawn")
            .communicate(Some(b"in\n".to_vec()))
            .expect("run");
        assert!(out.status.success(), "{out:?}");
        assert_eq!(String::from_utf8_lossy(&out.stdout), "out:in\ngone\n");
        assert_eq!(String::from_utf8_lossy(&out.stderr), "err\n");
    }

    /// The same for a child of `spawn_tokio`.
    #[tokio::test]
    async fn a_tokio_child_gets_its_stdio_and_no_other_descriptor() {
        use tokio::io::AsyncWriteExt;
        let (_fd, n) = inheritable_fd();
        let mut command = tokio::process::Command::new("/bin/sh");
        command
            .args(probe(n))
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        let (mut child, _spawned) = spawn_tokio(&mut command).expect("spawn");
        let mut stdin = child.stdin.take().expect("stdin");
        stdin.write_all(b"in\n").await.expect("write");
        drop(stdin);
        let out = child.wait_with_output().await.expect("run");
        assert!(out.status.success(), "{out:?}");
        assert_eq!(String::from_utf8_lossy(&out.stdout), "out:in\ngone\n");
        assert_eq!(String::from_utf8_lossy(&out.stderr), "err\n");
    }

    /// On a kernel without `close_range` (pretended on this thread), the walk of `/proc/self/fd`
    /// marks a descriptor of this process, and children of both spawns get their stdio and no
    /// other descriptor (sealantd#183).
    #[test]
    fn without_close_range_the_walk_marks_every_descriptor() {
        PRETEND.with(|p| p.set(1));
        let (fd, n) = inheritable_fd();
        mark_here().expect("the walk");
        assert!(close_on_exec(&fd), "the walk marked fd {n}");
        drop(fd);

        let (_std_fd, n) = inheritable_fd();
        let out = Command::new("/bin/sh")
            .args(probe(n))
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn_gated()
            .expect("spawn")
            .communicate(Some(b"in\n".to_vec()))
            .expect("run");
        assert_eq!(
            String::from_utf8_lossy(&out.stdout),
            "out:in\ngone\n",
            "{out:?}"
        );
        assert_eq!(String::from_utf8_lossy(&out.stderr), "err\n");

        let (_tokio_fd, n) = inheritable_fd();
        let out = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("a runtime")
            .block_on(async {
                use tokio::io::AsyncWriteExt;
                let mut command = tokio::process::Command::new("/bin/sh");
                command
                    .args(probe(n))
                    .stdin(Stdio::piped())
                    .stdout(Stdio::piped())
                    .stderr(Stdio::piped());
                let (mut child, _spawned) = spawn_tokio(&mut command).expect("spawn");
                let mut stdin = child.stdin.take().expect("stdin");
                stdin.write_all(b"in\n").await.expect("write");
                drop(stdin);
                child.wait_with_output().await.expect("run")
            });
        assert_eq!(
            String::from_utf8_lossy(&out.stdout),
            "out:in\ngone\n",
            "{out:?}"
        );
        PRETEND.with(|p| p.set(0));
    }

    /// The sweep before a helper spawn, as release builds run it, marks a descriptor of this
    /// process that lacks close-on-exec.
    #[test]
    fn the_sweep_marks_a_descriptor_without_close_on_exec() {
        let (fd, n) = inheritable_fd();
        mark_here().expect("the sweep");
        assert!(close_on_exec(&fd), "the sweep marked fd {n}");
    }

    /// A child of a helper spawn keeps its stdin, stdout and stderr, and gets no other descriptor
    /// of this process: the sweep marked the one planted without close-on-exec.
    #[test]
    fn a_helper_gets_its_stdio_and_no_other_descriptor() {
        let (_fd, n) = inheritable_fd();
        let (child, spawned) = spawn_helper_std(
            Command::new("/bin/sh")
                .args(probe(n))
                .stdin(Stdio::piped())
                .stdout(Stdio::piped())
                .stderr(Stdio::piped()),
        )
        .expect("spawn");
        let out = GatedChild {
            child,
            spawned,
            watchdog: None,
        }
        .communicate(Some(b"in\n".to_vec()))
        .expect("run");
        assert!(out.status.success(), "{out:?}");
        assert_eq!(String::from_utf8_lossy(&out.stdout), "out:in\ngone\n");
        assert_eq!(String::from_utf8_lossy(&out.stderr), "err\n");

        let (_fd, n) = inheritable_fd();
        let out = Command::new("/bin/sh")
            .args([
                "-c",
                &format!("echo err >&2; [ -e /proc/$$/fd/{n} ] && echo held || echo gone"),
            ])
            .stdin(Stdio::null())
            .output_helper()
            .expect("run");
        assert!(out.status.success(), "{out:?}");
        assert_eq!(String::from_utf8_lossy(&out.stdout), "gone\n");
        assert_eq!(String::from_utf8_lossy(&out.stderr), "err\n");
    }

    /// When neither `close_range` nor the walk works, nothing is marked and nothing is spawned:
    /// the marking errs, and so do both spawns.
    #[test]
    fn when_the_walk_cannot_run_nothing_is_spawned() {
        PRETEND.with(|p| p.set(2));
        assert!(mark_inherited_close_on_exec().is_err(), "the marking errs");
        let std_spawn = spawn_std(Command::new("/bin/true").stdin(Stdio::null()));
        let helper_spawn = spawn_helper_std(Command::new("/bin/true").stdin(Stdio::null()));
        let tokio_spawn = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("a runtime")
            .block_on(async {
                spawn_tokio(&mut tokio::process::Command::new("/bin/true")).map(|_| ())
            });
        PRETEND.with(|p| p.set(0));
        assert!(std_spawn.is_err(), "spawn_std refused: {std_spawn:?}");
        assert!(
            helper_spawn.is_err(),
            "spawn_helper_std refused: {helper_spawn:?}"
        );
        assert!(tokio_spawn.is_err(), "spawn_tokio refused: {tokio_spawn:?}");
    }

    /// A program that cannot be run is still reported by the spawn, by every gate: the backstop
    /// keeps the pipe std reports a failed exec through, and `posix_spawn` reports it itself.
    #[tokio::test]
    async fn a_failed_exec_is_still_reported() {
        let missing = "/nonexistent/sealant-program";
        let std_error = spawn_std(&mut Command::new(missing)).expect_err("no such program");
        assert_eq!(std_error.kind(), io::ErrorKind::NotFound, "{std_error}");
        let helper_error =
            spawn_helper_std(&mut Command::new(missing)).expect_err("no such program");
        assert_eq!(
            helper_error.kind(),
            io::ErrorKind::NotFound,
            "{helper_error}"
        );
        let tokio_error =
            spawn_tokio(&mut tokio::process::Command::new(missing)).expect_err("no such program");
        assert_eq!(tokio_error.kind(), io::ErrorKind::NotFound, "{tokio_error}");
    }

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
