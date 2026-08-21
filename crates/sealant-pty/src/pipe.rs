//! Plain-pipe leader spawn for pipe-mode sessions (no pseudoterminal).
//!
//! The child gets pipes for stdin/stdout/stderr and is made a session leader (`setsid`) so the
//! same process-group signalling as PTY sessions applies. There is no controlling terminal, no
//! `TERM`, and no window size: this is the shape for processes that speak a byte protocol over
//! stdio (JSON-RPC / NDJSON servers), where tty line discipline would corrupt the stream.

use std::io;
use std::path::Path;
use std::process::Stdio;

use tokio::process::{ChildStderr, ChildStdin, ChildStdout};

/// A spawned pipe-mode leader: the three pipes, the child, and its OS pid.
#[derive(Debug)]
pub struct PipeChild {
    /// The child's stdin (the session input path).
    pub stdin: ChildStdin,
    /// The child's stdout (the journaled, attachable output).
    pub stdout: ChildStdout,
    /// The child's stderr (recorded as telemetry only).
    pub stderr: ChildStderr,
    /// The session-leader child.
    pub child: tokio::process::Child,
    /// The child's OS pid (also its session id / process-group id).
    pub pid: i32,
}

/// Start `program` as a session leader with piped stdio.
///
/// # Errors
/// Returns an I/O error if the child cannot be spawned or a pipe handle is missing.
pub fn spawn(
    program: &str,
    args: &[String],
    cwd: &Path,
    env: &[(String, String)],
) -> io::Result<PipeChild> {
    let mut command = tokio::process::Command::new(program);
    command.args(args);
    command.current_dir(cwd);
    command.env_clear();
    for (key, value) in env {
        command.env(key, value);
    }
    command.stdin(Stdio::piped());
    command.stdout(Stdio::piped());
    command.stderr(Stdio::piped());
    command.kill_on_drop(true);

    // SAFETY: the pre-exec closure runs in the forked child before exec and calls only the
    // async-signal-safe `setsid`, making the child a session and process-group leader so
    // `killpg` on its pid reaches the whole tree (the same contract as PTY sessions).
    unsafe {
        command.pre_exec(|| {
            if libc::setsid() == -1 {
                return Err(io::Error::last_os_error());
            }
            Ok(())
        });
    }

    let mut child = command.spawn()?;
    let pid = child.id().map_or(-1, |p| p as i32);
    let stdin = child
        .stdin
        .take()
        .ok_or_else(|| io::Error::other("child stdin pipe missing"))?;
    let stdout = child
        .stdout
        .take()
        .ok_or_else(|| io::Error::other("child stdout pipe missing"))?;
    let stderr = child
        .stderr
        .take()
        .ok_or_else(|| io::Error::other("child stderr pipe missing"))?;
    Ok(PipeChild {
        stdin,
        stdout,
        stderr,
        child,
        pid,
    })
}
