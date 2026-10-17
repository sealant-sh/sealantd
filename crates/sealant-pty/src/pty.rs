//! Pseudoterminal allocation, the controlling-terminal child spawn, and async master I/O.

use std::io;
use std::os::fd::{AsRawFd, OwnedFd};
use std::path::Path;
use std::process::Stdio;

use sealant_process::SpawnedPid;
use tokio::io::unix::AsyncFd;

fn to_io(errno: nix::errno::Errno) -> io::Error {
    io::Error::from_raw_os_error(errno as i32)
}

fn set_nonblocking(fd: std::os::fd::RawFd) -> io::Result<()> {
    // SAFETY: `fd` is a valid open descriptor; fcntl with F_GETFL/F_SETFL has no memory effects.
    let flags = unsafe { libc::fcntl(fd, libc::F_GETFL) };
    if flags < 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: as above; setting O_NONBLOCK on a valid descriptor.
    let result = unsafe { libc::fcntl(fd, libc::F_SETFL, flags | libc::O_NONBLOCK) };
    if result < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

/// Allocate a PTY pair with both ends close-on-exec from the moment they exist, its window size
/// set. The master stays open in sealantd for the session's life, and this slave descriptor until
/// the leader is spawned; a descriptor without the flag is inherited by every process sealantd
/// starts while it is open (sealantd#183). `openpty(3)` sets no flag, and setting one after it
/// would leave a window for a spawn on another thread. The leader gets the slave only as its
/// stdin, stdout and stderr, which the spawn duplicates without the flag.
fn open_pty(cols: u16, rows: u16) -> io::Result<(OwnedFd, OwnedFd)> {
    use nix::fcntl::OFlag;
    let flags = OFlag::O_RDWR | OFlag::O_NOCTTY | OFlag::O_CLOEXEC;
    let master = nix::pty::posix_openpt(flags).map_err(to_io)?;
    nix::pty::grantpt(&master).map_err(to_io)?;
    nix::pty::unlockpt(&master).map_err(to_io)?;
    let name = nix::pty::ptsname_r(&master).map_err(to_io)?;
    let slave =
        nix::fcntl::open(name.as_str(), flags, nix::sys::stat::Mode::empty()).map_err(to_io)?;
    set_window_size(slave.as_raw_fd(), cols, rows)?;
    Ok((OwnedFd::from(master), slave))
}

fn set_window_size(fd: std::os::fd::RawFd, cols: u16, rows: u16) -> io::Result<()> {
    let winsize = libc::winsize {
        ws_row: rows,
        ws_col: cols,
        ws_xpixel: 0,
        ws_ypixel: 0,
    };
    // SAFETY: `fd` is a valid PTY descriptor; `&winsize` is valid for the duration of the ioctl.
    let result = unsafe { libc::ioctl(fd, libc::TIOCSWINSZ, &winsize) };
    if result < 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(())
    }
}

/// A spawned PTY session: the (non-blocking) master, the child, and its OS pid.
#[derive(Debug)]
pub struct PtyChild {
    /// The PTY master, wrapped for async readiness.
    pub master: AsyncFd<OwnedFd>,
    /// The session-leader child.
    pub child: tokio::process::Child,
    /// The child's OS pid (also its session id / process-group id).
    pub pid: i32,
    /// Keeps the orphan reaper off this pid until the caller has waited for the child; drop it
    /// as soon as `child.wait()` returns (see `sealant_process::spawn`).
    pub spawned: SpawnedPid,
}

/// Allocate a PTY and start `shell` as a session leader with the slave as its controlling terminal.
///
/// # Errors
/// Returns an I/O error if the PTY cannot be allocated or the child cannot be spawned.
pub fn spawn(
    shell: &str,
    args: &[String],
    cwd: &Path,
    env: &[(String, String)],
    (cols, rows): (u16, u16),
    term: &str,
    run_as: Option<&sealant_process::identity::RunAs>,
) -> io::Result<PtyChild> {
    let (master, slave) = open_pty(cols, rows)?;
    set_nonblocking(master.as_raw_fd())?;
    // A leader that runs as a user owns its terminal, as a login gives one (`ttyname` and
    // `/dev/pts/N` opened by path work for it, `mesg` and GnuPG's pinentry included).
    // The mode first, while the terminal is root's, then the owner: changing the mode of a file
    // one does not own takes `CAP_FOWNER`.
    if let Some(user) = run_as {
        nix::sys::stat::fchmod(&slave, nix::sys::stat::Mode::from_bits_truncate(0o620))
            .map_err(to_io)?;
        std::os::unix::fs::fchown(&slave, Some(user.uid), None)?;
    }

    // The child gets three handles to the slave for stdin/stdout/stderr.
    let stdin = slave.try_clone()?;
    let stdout = slave.try_clone()?;
    let stderr = slave;

    let mut command = tokio::process::Command::new(shell);
    command.args(args);
    command.current_dir(cwd);
    command.env_clear();
    for (key, value) in env {
        command.env(key, value);
    }
    command.env("TERM", term);
    command.stdin(Stdio::from(stdin));
    command.stdout(Stdio::from(stdout));
    command.stderr(Stdio::from(stderr));
    command.kill_on_drop(true);

    // SAFETY: the pre-exec closure runs in the forked child before exec and calls only
    // async-signal-safe libc functions. `setsid` makes the child a session leader; `TIOCSCTTY` on
    // fd 0 (the slave, already dup'd by the stdio setup) makes it the controlling terminal.
    unsafe {
        command.pre_exec(|| {
            if libc::setsid() == -1 {
                return Err(io::Error::last_os_error());
            }
            if libc::ioctl(0, libc::TIOCSCTTY as _, 0) == -1 {
                return Err(io::Error::last_os_error());
            }
            Ok(())
        });
    }
    // The user last: the controlling terminal is taken as root, and the identity is the
    // leader's from exec on.
    if let Some(user) = run_as {
        user.apply(command.as_std_mut());
    }

    // Spawn through the process-wide gate: sealantd is PID 1 in the workspace and its orphan
    // reaper must not reap the leader out from under the session's own `wait()`.
    let (child, spawned) = sealant_process::spawn::spawn_tokio(&mut command)?;
    let pid = spawned.pid();
    // Parent's slave handles were moved into the command and are dropped after spawn, so the master
    // observes EOF/EIO once the child and every descendant that inherited the slave close it.
    let master = AsyncFd::new(master)?;
    Ok(PtyChild {
        master,
        child,
        pid,
        spawned,
    })
}

/// Read available bytes from the PTY master. `Ok(0)` (or an `EIO` after the slave closes) is EOF.
///
/// # Errors
/// Returns an I/O error other than `WouldBlock` (which is retried internally).
pub async fn read(master: &AsyncFd<OwnedFd>, buf: &mut [u8]) -> io::Result<usize> {
    loop {
        let mut guard = master.readable().await?;
        let result = guard.try_io(|inner| try_read(inner, buf));
        match result {
            Ok(io_result) => return io_result,
            Err(_would_block) => continue,
        }
    }
}

/// Read bytes currently available from the PTY master without waiting for readiness.
///
/// # Errors
/// Returns [`io::ErrorKind::WouldBlock`] when no bytes are currently buffered, or another I/O
/// error from `read(2)`.
pub fn try_read(master: &AsyncFd<OwnedFd>, buf: &mut [u8]) -> io::Result<usize> {
    let fd = master.get_ref().as_raw_fd();
    // SAFETY: `fd` is a valid non-blocking PTY master; `buf` is valid for `buf.len()` bytes.
    let n = unsafe { libc::read(fd, buf.as_mut_ptr().cast(), buf.len()) };
    if n < 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(n as usize)
    }
}

/// Return the number of bytes currently buffered for reading from the PTY master.
///
/// # Errors
/// Returns an I/O error when `FIONREAD` cannot inspect the master descriptor.
pub fn readable_bytes(master: &AsyncFd<OwnedFd>) -> io::Result<usize> {
    let fd = master.get_ref().as_raw_fd();
    let mut available: libc::c_int = 0;
    // SAFETY: `fd` is a valid PTY master and `available` is writable for the ioctl result.
    let result = unsafe { libc::ioctl(fd, libc::FIONREAD, &mut available) };
    if result < 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(usize::try_from(available).unwrap_or_default())
    }
}

/// Write all of `data` to the PTY master.
///
/// # Errors
/// Returns an I/O error if the write fails.
pub async fn write_all(master: &AsyncFd<OwnedFd>, mut data: &[u8]) -> io::Result<()> {
    while !data.is_empty() {
        let mut guard = master.writable().await?;
        let result = guard.try_io(|inner| {
            let fd = inner.get_ref().as_raw_fd();
            // SAFETY: `fd` is a valid PTY master; `data` is valid for `data.len()` bytes.
            let n = unsafe { libc::write(fd, data.as_ptr().cast(), data.len()) };
            if n < 0 {
                Err(io::Error::last_os_error())
            } else {
                Ok(n as usize)
            }
        });
        match result {
            Ok(io_result) => {
                let written = io_result?;
                if written == 0 {
                    return Err(io::ErrorKind::WriteZero.into());
                }
                data = &data[written..];
            }
            Err(_would_block) => continue,
        }
    }
    Ok(())
}

/// Apply a new terminal window size to the PTY master (`TIOCSWINSZ`).
///
/// # Errors
/// Returns an I/O error if the ioctl fails.
pub fn resize(master: &AsyncFd<OwnedFd>, cols: u16, rows: u16) -> io::Result<()> {
    set_window_size(master.get_ref().as_raw_fd(), cols, rows)
}

/// Whether an I/O error from [`read`] means the slave end has closed (end of session output).
#[must_use]
pub fn is_eof_error(error: &io::Error) -> bool {
    // After the last slave fd closes, Linux returns EIO on the master.
    error.raw_os_error() == Some(libc::EIO)
}

#[cfg(test)]
mod tests {
    use super::*;
    use nix::fcntl::{FcntlArg, FdFlag, fcntl};

    /// Both ends of a new PTY are close-on-exec from the moment they exist (sealantd#183): the
    /// flag is set by the open itself, whatever a spawn does with the descriptors it inherits.
    #[test]
    fn both_ends_of_a_new_pty_are_close_on_exec() {
        let (master, slave) = open_pty(80, 24).expect("open a pty");
        for (end, fd) in [("master", &master), ("slave", &slave)] {
            let flags = fcntl(fd, FcntlArg::F_GETFD).expect("F_GETFD");
            assert!(
                FdFlag::from_bits_truncate(flags).contains(FdFlag::FD_CLOEXEC),
                "the {end} is close-on-exec"
            );
        }
    }
}
