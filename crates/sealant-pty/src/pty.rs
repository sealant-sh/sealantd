//! Pseudoterminal allocation, the controlling-terminal child spawn, and async master I/O.

use std::io;
use std::os::fd::{AsRawFd, OwnedFd};
use std::path::Path;
use std::process::Stdio;

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

/// A spawned PTY session: the (non-blocking) master, the child, and its OS pid.
#[derive(Debug)]
pub struct PtyChild {
    /// The PTY master, wrapped for async readiness.
    pub master: AsyncFd<OwnedFd>,
    /// The session-leader child.
    pub child: tokio::process::Child,
    /// The child's OS pid (also its session id / process-group id).
    pub pid: i32,
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
    cols: u16,
    rows: u16,
    term: &str,
) -> io::Result<PtyChild> {
    let winsize = nix::pty::Winsize {
        ws_row: rows,
        ws_col: cols,
        ws_xpixel: 0,
        ws_ypixel: 0,
    };
    let pty = nix::pty::openpty(Some(&winsize), None).map_err(to_io)?;
    let master = pty.master;
    let slave = pty.slave;
    set_nonblocking(master.as_raw_fd())?;

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

    let child = command.spawn()?;
    let pid = child.id().map_or(-1, |p| p as i32);
    // Parent's slave handles were moved into the command and are dropped after spawn, so the master
    // observes EOF/EIO once the child closes its end.
    let master = AsyncFd::new(master)?;
    Ok(PtyChild { master, child, pid })
}

/// Read available bytes from the PTY master. `Ok(0)` (or an `EIO` after the slave closes) is EOF.
///
/// # Errors
/// Returns an I/O error other than `WouldBlock` (which is retried internally).
pub async fn read(master: &AsyncFd<OwnedFd>, buf: &mut [u8]) -> io::Result<usize> {
    loop {
        let mut guard = master.readable().await?;
        let result = guard.try_io(|inner| {
            let fd = inner.get_ref().as_raw_fd();
            // SAFETY: `fd` is a valid PTY master; `buf` is valid for `buf.len()` bytes.
            let n = unsafe { libc::read(fd, buf.as_mut_ptr().cast(), buf.len()) };
            if n < 0 {
                Err(io::Error::last_os_error())
            } else {
                Ok(n as usize)
            }
        });
        match result {
            Ok(io_result) => return io_result,
            Err(_would_block) => continue,
        }
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
    let winsize = libc::winsize {
        ws_row: rows,
        ws_col: cols,
        ws_xpixel: 0,
        ws_ypixel: 0,
    };
    let fd = master.get_ref().as_raw_fd();
    // SAFETY: `fd` is a valid PTY master; `&winsize` is valid for the duration of the ioctl.
    let result = unsafe { libc::ioctl(fd, libc::TIOCSWINSZ, &winsize) };
    if result < 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(())
    }
}

/// Whether an I/O error from [`read`] means the slave end has closed (end of session output).
#[must_use]
pub fn is_eof_error(error: &io::Error) -> bool {
    // After the last slave fd closes, Linux returns EIO on the master.
    error.raw_os_error() == Some(libc::EIO)
}
