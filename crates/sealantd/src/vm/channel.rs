//! The one vsock 1026 connection PID 1 holds for its lifetime ([`super::protocol`]).
//!
//! Opened once at boot, close-on-exec (no child inherits it), the boot config read from it
//! within [`BOOT_READ_WITHIN`] and never retried: a version mismatch or a malformed frame fails
//! the boot at once. While the daemon runs, a task reads the runner's later frames from a
//! duplicate of it and turns a [`RunnerFrame::Shutdown`] into the same graceful shutdown a
//! `SIGTERM` starts. On the way out the exit status goes back over it.

use std::sync::Arc;
use std::time::Duration;

use tokio::io::{AsyncBufRead, AsyncWrite};
use tokio::sync::{mpsc, watch};

use super::protocol::{
    self, ExitAck, GuestExitStatus, PROTOCOL_VERSION, RunnerFrame, VmBootConfig,
};
use crate::runtime::Runtime;

/// How long the whole boot read (connect, then the first line) may take.
pub const BOOT_READ_WITHIN: Duration = Duration::from_secs(30);
/// How long the guest waits for the runner's [`ExitAck`].
pub const EXIT_ACK_WITHIN: Duration = Duration::from_secs(5);

/// Wait on `reader` for the runner's shutdown frame. `true` when it came; `false` when the
/// connection ended or carried something else (logged): a closed connection is not a request
/// to shut down.
pub async fn await_shutdown<R: AsyncBufRead + Unpin>(reader: &mut R) -> bool {
    match protocol::read_frame::<_, RunnerFrame>(reader).await {
        Ok(RunnerFrame::Shutdown { .. }) => {
            tracing::info!("the runner asked for a shutdown");
            true
        }
        Err(protocol::FrameError::Closed) => {
            tracing::warn!("the runner's boot channel closed; no shutdown frame can arrive");
            false
        }
        Err(error) => {
            tracing::error!(%error, "the runner sent a frame that is not a shutdown");
            false
        }
    }
}

/// Write `status` and read the runner's acknowledgement: exactly an [`ExitAck`] of this version
/// with `accepted: true`, nothing else.
///
/// # Errors
/// The write failed, or what came back is not that acknowledgement.
pub async fn report_exit<R, W>(
    reader: &mut R,
    writer: &mut W,
    status: &GuestExitStatus,
) -> Result<(), String>
where
    R: AsyncBufRead + Unpin,
    W: AsyncWrite + Unpin,
{
    protocol::write_frame(writer, status)
        .await
        .map_err(|error| error.to_string())?;
    let ack: ExitAck = protocol::read_frame(reader)
        .await
        .map_err(|error| error.to_string())?;
    if ack.version != PROTOCOL_VERSION || !ack.accepted {
        return Err(format!(
            "the runner did not accept the exit status: {ack:?}"
        ));
    }
    Ok(())
}

/// The graceful shutdown a `SIGTERM` starts: the final flush, then the stop.
pub async fn graceful_shutdown(runtime: &Runtime) {
    runtime.shutdown_final_flush(None).await;
    runtime.shutdown().request_graceful(None);
}

/// Start what can ask the guest to shut down — the runner's shutdown frame on `runner` (the
/// duplicate of the boot channel and the bytes already read past the boot config) and the
/// power button — and run [`graceful_shutdown`] on the first of them. Ends with the daemon.
pub fn spawn_shutdown_watchers<S>(
    runtime: Arc<Runtime>,
    runner: Option<S>,
    power_button: bool,
    mut stopped: watch::Receiver<bool>,
) where
    S: AsyncBufRead + Unpin + Send + 'static,
{
    let (ask, mut asked) = mpsc::channel::<&'static str>(4);
    if let Some(mut runner) = runner {
        let ask = ask.clone();
        tokio::spawn(async move {
            if await_shutdown(&mut runner).await {
                let _ = ask.send("the runner's shutdown frame").await;
            }
        });
    }
    if power_button {
        super::power::spawn(ask.clone());
    }
    drop(ask);
    tokio::spawn(async move {
        tokio::select! {
            changed = stopped.changed() => {
                let _ = changed;
            }
            Some(why) = asked.recv() => {
                tracing::info!(why, "graceful shutdown");
                graceful_shutdown(&runtime).await;
            }
        }
    });
}

/// The boot channel itself (Linux).
#[cfg(target_os = "linux")]
#[derive(Debug)]
pub struct BootChannel {
    socket: socket2::Socket,
    /// Bytes read past the boot config (a shutdown frame that came right behind it).
    pending: Vec<u8>,
}

#[cfg(target_os = "linux")]
impl BootChannel {
    /// Connect once to the host's port 1026 and read the boot config, all within
    /// [`BOOT_READ_WITHIN`].
    ///
    /// # Errors
    /// The connect failed, the time ran out, or the frame was not a boot config of this version.
    pub fn open() -> Result<(Self, VmBootConfig), String> {
        use sealant_control::vsock::{BOOT_PORT, VMADDR_CID_HOST, VsockStream};
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .map_err(|error| format!("async runtime: {error}"))?;
        runtime.block_on(async {
            tokio::time::timeout(BOOT_READ_WITHIN, async {
                let stream = VsockStream::connect(VMADDR_CID_HOST, BOOT_PORT)
                    .await
                    .map_err(|error| format!("vsock {VMADDR_CID_HOST}:{BOOT_PORT}: {error}"))?;
                let mut reader = tokio::io::BufReader::new(stream);
                let boot: VmBootConfig = protocol::read_frame(&mut reader)
                    .await
                    .map_err(|error| error.to_string())?;
                let pending = reader.buffer().to_vec();
                let socket = reader.into_inner().into_socket();
                Ok((Self { socket, pending }, boot))
            })
            .await
            .map_err(|_| format!("no boot config within {BOOT_READ_WITHIN:?}"))?
        })
    }

    /// A duplicate of the connection (close-on-exec, as the original) and the bytes already
    /// read past the boot config, for the shutdown watcher; to wrap on the daemon's runtime
    /// with [`BootChannel::reader`].
    ///
    /// # Errors
    /// The descriptor could not be duplicated.
    pub fn watcher_half(&mut self) -> Result<(socket2::Socket, Vec<u8>), String> {
        let socket = self.socket.try_clone().map_err(|error| error.to_string())?;
        Ok((socket, std::mem::take(&mut self.pending)))
    }

    /// The watcher's reader, on the current runtime: the bytes read ahead first, then the
    /// connection.
    ///
    /// # Errors
    /// The socket could not be registered with the runtime.
    pub fn reader(
        socket: socket2::Socket,
        pending: Vec<u8>,
    ) -> std::io::Result<impl AsyncBufRead + Unpin + Send + 'static> {
        use tokio::io::AsyncReadExt as _;
        let stream = sealant_control::vsock::VsockStream::from_socket(socket)?;
        Ok(tokio::io::BufReader::new(
            std::io::Cursor::new(pending).chain(stream),
        ))
    }

    /// Send `status` and wait (up to [`EXIT_ACK_WITHIN`]) for the runner's acknowledgement.
    ///
    /// # Errors
    /// See [`report_exit`]; also when the time runs out.
    pub fn report(self, status: &GuestExitStatus) -> Result<(), String> {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .map_err(|error| error.to_string())?;
        runtime.block_on(async {
            let stream = sealant_control::vsock::VsockStream::from_socket(self.socket)
                .map_err(|error| error.to_string())?;
            let (read, mut write) = tokio::io::split(stream);
            let mut read = tokio::io::BufReader::new(read);
            tokio::time::timeout(EXIT_ACK_WITHIN, report_exit(&mut read, &mut write, status))
                .await
                .map_err(|_| "the runner did not acknowledge in time".to_owned())?
        })
    }
}

/// Off Linux there is no vsock: every call fails.
#[cfg(not(target_os = "linux"))]
#[derive(Debug)]
pub struct BootChannel;

#[cfg(not(target_os = "linux"))]
impl BootChannel {
    /// Always fails off Linux.
    ///
    /// # Errors
    /// Always.
    pub fn open() -> Result<(Self, VmBootConfig), String> {
        Err("vsock is Linux only".to_owned())
    }

    /// Always fails off Linux.
    ///
    /// # Errors
    /// Always.
    pub fn report(self, _status: &GuestExitStatus) -> Result<(), String> {
        Err("vsock is Linux only".to_owned())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::shutdown::ShutdownSignal;
    use sealant_runtime_core::{RuntimeConfig, new_runtime_id};
    use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};

    fn status() -> GuestExitStatus {
        GuestExitStatus {
            version: PROTOCOL_VERSION,
            exit_code: 0,
            synced: true,
            reason: None,
        }
    }

    /// The runner's shutdown frame on the held connection drives the daemon's graceful
    /// shutdown; the exit status then goes back on the same connection, and only a real
    /// acknowledgement is taken for one.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_shutdown_frame_drives_the_graceful_shutdown_and_the_exit_goes_back_on_the_same_connection()
     {
        let tmp = tempfile::tempdir().expect("tempdir");
        let mut config = RuntimeConfig::new(new_runtime_id());
        config.workspace_root = tmp.path().to_path_buf();
        let runtime = Runtime::new(config, Arc::new(ShutdownSignal::new(1_000)));
        runtime.mark_healthy();

        let (guest, runner) = tokio::io::duplex(4096);
        let (guest_read, mut guest_write) = tokio::io::split(guest);
        let (runner_read, mut runner_write) = tokio::io::split(runner);
        let mut runner_read = BufReader::new(runner_read);

        // The watcher reads the guest's half; the exit is written on the same connection.
        let (_stop, stopped) = watch::channel(false);
        let (reader_tx, reader_rx) = tokio::sync::oneshot::channel();
        let watched = runtime.clone();
        tokio::spawn(async move {
            let mut reader = BufReader::new(guest_read);
            let asked = await_shutdown(&mut reader).await;
            if asked {
                graceful_shutdown(&watched).await;
            }
            let _ = reader_tx.send((asked, reader));
        });
        let _ = stopped;

        runner_write
            .write_all(b"{\"version\":1,\"type\":\"shutdown\"}\n")
            .await
            .expect("shutdown frame");
        tokio::time::timeout(Duration::from_secs(10), runtime.shutdown().wait())
            .await
            .expect("the shutdown frame starts the graceful shutdown");
        let (asked, mut guest_read) = reader_rx.await.expect("watcher");
        assert!(asked);

        // A bogus acknowledgement (a boot frame) is refused…
        let exchange = tokio::spawn(async move {
            let mut line = String::new();
            runner_read.read_line(&mut line).await.expect("exit line");
            runner_write
                .write_all(b"{\"version\":1,\"mode\":\"normal\"}\n")
                .await
                .expect("bogus ack");
            (line, runner_read, runner_write)
        });
        assert!(
            report_exit(&mut guest_read, &mut guest_write, &status())
                .await
                .is_err()
        );
        let (line, mut runner_read, mut runner_write) = exchange.await.expect("runner");
        let sent: serde_json::Value = serde_json::from_str(&line).expect("exit json");
        assert_eq!(sent["type"], "exit");
        assert_eq!(sent["exitCode"], 0);
        assert_eq!(sent["synced"], true);

        // …and a real one is taken.
        let exchange = tokio::spawn(async move {
            let mut line = String::new();
            runner_read.read_line(&mut line).await.expect("exit line");
            runner_write
                .write_all(b"{\"version\":1,\"type\":\"exitAck\",\"accepted\":true}\n")
                .await
                .expect("ack");
        });
        report_exit(&mut guest_read, &mut guest_write, &status())
            .await
            .expect("acknowledged");
        exchange.await.expect("runner");
    }

    #[tokio::test]
    async fn a_closed_connection_or_another_frame_is_not_a_shutdown() {
        let mut closed = BufReader::new(&b""[..]);
        assert!(!await_shutdown(&mut closed).await);
        let mut other = BufReader::new(&b"{\"version\":1,\"mode\":\"normal\"}\n"[..]);
        assert!(!await_shutdown(&mut other).await);
    }

    #[tokio::test]
    async fn an_ack_that_does_not_accept_is_refused() {
        let mut reader =
            BufReader::new(&b"{\"version\":1,\"type\":\"exitAck\",\"accepted\":false}\n"[..]);
        let mut sink = Vec::new();
        assert!(
            report_exit(&mut reader, &mut sink, &status())
                .await
                .is_err()
        );
    }
}
