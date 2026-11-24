//! The four `virtio-vsock` channels (§6.1), over Cloud Hypervisor's hybrid vsock: the VMM exposes
//! the guest's vsock as one Unix socket (`--vsock cid=3,socket=/run/vm/vsock.sock`).
//!
//! - Host → guest: connect to that socket, write `CONNECT <port>\n`, read `OK <host_port>\n`, then
//!   the stream is the guest's connection on `<port>`.
//! - Guest → host: when the guest connects to host port `<port>`, the VMM connects to the Unix
//!   socket `<socket>_<port>`, which the runner listens on.
//!
//! | port | direction | runner side |
//! | :--- | :--- | :--- |
//! | 1024 | host → guest | `/run/sealant/control.sock`: each connection there is bridged to guest port 1024 |
//! | 1025 | guest → host | `vsock.sock_1025` → `/run/sealant/capture.sock` |
//! | 1026 | guest → host | `vsock.sock_1026`, answered in the runner, one connection only: boot config out, shutdown out, exit status in, ack out |
//! | 1027 | guest → host | `vsock.sock_1027` → `/run/sealant/session.sock`, normal boots only |

use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::time::Duration;

use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};
use tokio::net::{UnixListener, UnixStream};
use tokio::sync::{mpsc, watch};

use crate::exit::ExitRecorder;
use crate::protocol::{self, GuestExitStatus};
use crate::retry::after_accept_error;

pub const CONTROL_PORT: u32 = 1024;
pub const CAPTURE_PORT: u32 = 1025;
pub const BOOT_PORT: u32 = 1026;
pub const SESSION_PORT: u32 = 1027;

/// Longest handshake reply accepted (`OK 4294967295\n` is 14 bytes).
const MAX_REPLY: usize = 64;
/// Longest line accepted from the guest on the boot channel.
const MAX_FRAME: usize = 64 * 1024;
/// How long the VMM may take to answer `CONNECT`.
const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(5);

/// Cloud Hypervisor's vsock Unix socket.
#[derive(Debug, Clone)]
pub struct Mux {
    socket: PathBuf,
}

impl Mux {
    pub fn new(socket: impl Into<PathBuf>) -> Self {
        Self {
            socket: socket.into(),
        }
    }

    pub fn socket(&self) -> &Path {
        &self.socket
    }

    /// The Unix socket the VMM dials when the guest connects to host `port`.
    pub fn guest_listener_path(&self, port: u32) -> PathBuf {
        let mut name = self.socket.as_os_str().to_owned();
        name.push(format!("_{port}"));
        PathBuf::from(name)
    }

    /// Opens a stream to the guest's listener on `port`.
    pub async fn connect(&self, port: u32) -> std::io::Result<UnixStream> {
        let mut stream = UnixStream::connect(&self.socket).await?;
        stream
            .write_all(format!("CONNECT {port}\n").as_bytes())
            .await?;
        let reply = tokio::time::timeout(HANDSHAKE_TIMEOUT, read_reply(&mut stream))
            .await
            .map_err(|_| std::io::Error::new(std::io::ErrorKind::TimedOut, "vsock handshake"))??;
        match reply.strip_prefix("OK ") {
            Some(host_port) if host_port.parse::<u32>().is_ok() => Ok(stream),
            _ => Err(std::io::Error::new(
                std::io::ErrorKind::ConnectionRefused,
                format!("vsock CONNECT {port} answered {reply:?}"),
            )),
        }
    }
}

/// Reads the handshake reply byte by byte, so no byte of the guest's stream is consumed with it.
async fn read_reply(stream: &mut UnixStream) -> std::io::Result<String> {
    let mut line = Vec::with_capacity(16);
    loop {
        let byte = stream.read_u8().await?;
        if byte == b'\n' {
            break;
        }
        if line.len() == MAX_REPLY {
            return Err(std::io::Error::other("vsock handshake reply too long"));
        }
        line.push(byte);
    }
    String::from_utf8(line).map_err(std::io::Error::other)
}

/// Binds a Unix listener at `path`, replacing a stale socket left by an earlier run, with `mode`.
pub fn bind_unix(path: &Path, mode: u32) -> std::io::Result<UnixListener> {
    match std::fs::remove_file(path) {
        Ok(()) => {}
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
        Err(e) => return Err(e),
    }
    let listener = UnixListener::bind(path)?;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode))?;
    Ok(listener)
}

/// Port 1024: bridges each connection on `listener` (`control.sock`) to the guest's `port`. A
/// connection the guest is not ready for is closed; the client retries.
pub async fn serve_host_to_guest(
    listener: UnixListener,
    mux: Mux,
    port: u32,
) -> std::io::Result<()> {
    loop {
        let mut client = match listener.accept().await {
            Ok((client, _)) => client,
            Err(e) => {
                after_accept_error("control bridge", &e).await;
                continue;
            }
        };
        let mux = mux.clone();
        tokio::spawn(async move {
            match mux.connect(port).await {
                Ok(mut guest) => {
                    if let Err(e) = tokio::io::copy_bidirectional(&mut client, &mut guest).await {
                        tracing::debug!(port, "host→guest bridge ended: {e}");
                    }
                }
                Err(e) => tracing::warn!(port, "guest not reachable on vsock: {e}"),
            }
        });
    }
}

/// Ports 1025 and 1027: bridges each guest connection the VMM delivers on `listener` to the Unix
/// socket `target` (Mend's `capture.sock` or `session.sock`).
pub async fn serve_guest_to_host(listener: UnixListener, target: PathBuf) -> std::io::Result<()> {
    loop {
        let mut guest = match listener.accept().await {
            Ok((guest, _)) => guest,
            Err(e) => {
                after_accept_error("guest→host bridge", &e).await;
                continue;
            }
        };
        let target = target.clone();
        tokio::spawn(async move {
            match UnixStream::connect(&target).await {
                Ok(mut host) => {
                    if let Err(e) = tokio::io::copy_bidirectional(&mut guest, &mut host).await {
                        tracing::debug!(target = %target.display(), "guest→host bridge ended: {e}");
                    }
                }
                Err(e) => {
                    tracing::warn!(target = %target.display(), "host socket unreachable: {e}")
                }
            }
        });
    }
}

/// Port 1026. Accepts exactly one guest connection (PID 1's, at boot), then closes the listener
/// and unlinks `path`, so nothing else in the guest can reach this port. On that connection it
/// writes `boot_frame` (one [`crate::protocol::VmBootConfig`] line), sends a shutdown line when
/// `shutdown` turns true, and records each valid exit line the guest sends before acknowledging
/// it. Returns when the guest closes the connection.
pub async fn serve_boot(
    listener: UnixListener,
    path: PathBuf,
    boot_frame: String,
    exits: ExitRecorder,
    mut shutdown: watch::Receiver<bool>,
) -> std::io::Result<()> {
    let guest = loop {
        match listener.accept().await {
            Ok((guest, _)) => break guest,
            Err(e) => after_accept_error("boot channel", &e).await,
        }
    };
    drop(listener);
    match std::fs::remove_file(&path) {
        Ok(()) => {}
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
        Err(e) => tracing::warn!(path = %path.display(), "could not unlink the boot listener: {e}"),
    }

    let (read, mut write) = guest.into_split();
    write.write_all(boot_frame.as_bytes()).await?;
    write.flush().await?;

    // Lines are read on their own task: `read_line` loses data when a select! drops it midway.
    let (lines_tx, mut lines) = mpsc::channel::<std::io::Result<String>>(4);
    tokio::spawn(async move {
        let mut reader = BufReader::new(read);
        loop {
            let mut line = String::new();
            let read = (&mut reader)
                .take(MAX_FRAME as u64 + 1)
                .read_line(&mut line)
                .await;
            let done = match &read {
                Ok(0) => true,
                Ok(n) if *n > MAX_FRAME => {
                    let _ = lines_tx
                        .send(Err(std::io::Error::other("boot channel frame too long")))
                        .await;
                    true
                }
                Ok(_) => false,
                Err(_) => true,
            };
            if done {
                if let Err(e) = read {
                    let _ = lines_tx.send(Err(e)).await;
                }
                return;
            }
            if lines_tx.send(Ok(line)).await.is_err() {
                return;
            }
        }
    });

    let mut shutdown_pending = true;
    loop {
        tokio::select! {
            line = lines.recv() => {
                let line = match line {
                    None => return Ok(()),
                    Some(line) => line?,
                };
                if line.trim().is_empty() {
                    continue;
                }
                match GuestExitStatus::parse_frame(&line) {
                    Ok(status) => {
                        tracing::info!(
                            exit_code = status.exit_code,
                            synced = status.synced,
                            reason = status.reason.as_deref().unwrap_or(""),
                            "guest exit status"
                        );
                        // Recorded before the ack: once acknowledged the guest powers off.
                        exits.record(status);
                        write.write_all(protocol::exit_ack_line().as_bytes()).await?;
                        write.flush().await?;
                    }
                    Err(e) => tracing::warn!("ignoring a boot channel frame: {e}"),
                }
            }
            changed = shutdown.changed(), if shutdown_pending => {
                match changed {
                    Ok(()) if *shutdown.borrow() => {
                        shutdown_pending = false;
                        write.write_all(protocol::shutdown_line().as_bytes()).await?;
                        write.flush().await?;
                    }
                    Ok(()) => {}
                    Err(_) => shutdown_pending = false,
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::protocol::GuestExitStatus;

    /// A stand-in for Cloud Hypervisor's vsock socket: answers `CONNECT <port>` with `reply`,
    /// sends the port it saw on `seen`, then echoes.
    fn fake_vmm(path: &Path, reply: &'static str) -> tokio::sync::mpsc::UnboundedReceiver<String> {
        let listener = UnixListener::bind(path).unwrap();
        let (seen, rx) = tokio::sync::mpsc::unbounded_channel();
        tokio::spawn(async move {
            loop {
                let (mut s, _) = listener.accept().await.unwrap();
                let seen = seen.clone();
                tokio::spawn(async move {
                    let request = read_reply(&mut s).await.unwrap();
                    seen.send(request).unwrap();
                    s.write_all(reply.as_bytes()).await.unwrap();
                    let (mut r, mut w) = s.split();
                    let _ = tokio::io::copy(&mut r, &mut w).await;
                });
            }
        });
        rx
    }

    async fn echo_server(path: &Path) {
        let listener = UnixListener::bind(path).unwrap();
        tokio::spawn(async move {
            loop {
                let (mut s, _) = listener.accept().await.unwrap();
                tokio::spawn(async move {
                    let (mut r, mut w) = s.split();
                    let _ = tokio::io::copy(&mut r, &mut w).await;
                });
            }
        });
    }

    async fn round_trip(stream: &mut UnixStream, data: &[u8]) -> Vec<u8> {
        stream.write_all(data).await.unwrap();
        let mut back = vec![0u8; data.len()];
        tokio::time::timeout(Duration::from_secs(5), stream.read_exact(&mut back))
            .await
            .unwrap()
            .unwrap();
        back
    }

    #[test]
    fn guest_listeners_sit_beside_the_vmm_socket() {
        let mux = Mux::new("/run/vm/vsock.sock");
        assert_eq!(
            mux.guest_listener_path(1025),
            PathBuf::from("/run/vm/vsock.sock_1025")
        );
    }

    #[tokio::test]
    async fn control_connections_reach_guest_port_1024_through_the_handshake() {
        let tmp = tempfile::tempdir().unwrap();
        let vmm = tmp.path().join("vsock.sock");
        let mut seen = fake_vmm(&vmm, "OK 1073741824\n");
        let control = tmp.path().join("control.sock");
        let listener = bind_unix(&control, 0o660).unwrap();
        tokio::spawn(serve_host_to_guest(listener, Mux::new(&vmm), CONTROL_PORT));

        let mut client = UnixStream::connect(&control).await.unwrap();
        // Bytes sent straight after connecting must arrive after the handshake, not inside it.
        assert_eq!(round_trip(&mut client, b"ping").await, b"ping");
        assert_eq!(seen.recv().await.unwrap(), "CONNECT 1024");
        let mode = std::fs::metadata(&control).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o660);
    }

    #[tokio::test]
    async fn a_refused_handshake_closes_the_client() {
        let tmp = tempfile::tempdir().unwrap();
        let vmm = tmp.path().join("vsock.sock");
        let _seen = fake_vmm(&vmm, "ERR no listener\n");
        let err = Mux::new(&vmm).connect(CONTROL_PORT).await.unwrap_err();
        assert_eq!(err.kind(), std::io::ErrorKind::ConnectionRefused);

        let control = tmp.path().join("control.sock");
        tokio::spawn(serve_host_to_guest(
            bind_unix(&control, 0o660).unwrap(),
            Mux::new(&vmm),
            CONTROL_PORT,
        ));
        let mut client = UnixStream::connect(&control).await.unwrap();
        let mut buf = [0u8; 1];
        let n = tokio::time::timeout(Duration::from_secs(5), client.read(&mut buf))
            .await
            .unwrap()
            .unwrap_or(0);
        assert_eq!(n, 0);
    }

    #[tokio::test]
    async fn guest_connections_on_a_port_reach_the_host_socket() {
        let tmp = tempfile::tempdir().unwrap();
        let capture = tmp.path().join("capture.sock");
        echo_server(&capture).await;
        let mux = Mux::new(tmp.path().join("vsock.sock"));
        let listen_at = mux.guest_listener_path(CAPTURE_PORT);
        tokio::spawn(serve_guest_to_host(
            bind_unix(&listen_at, 0o600).unwrap(),
            capture.clone(),
        ));

        // What the VMM does when the guest connects to host port 1025.
        let mut from_guest = UnixStream::connect(&listen_at).await.unwrap();
        assert_eq!(
            round_trip(&mut from_guest, b"POST /capture").await,
            b"POST /capture"
        );
    }

    #[tokio::test]
    async fn a_stale_socket_file_is_replaced() {
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("control.sock");
        drop(std::os::unix::net::UnixListener::bind(&path).unwrap());
        assert!(path.exists());
        assert!(bind_unix(&path, 0o600).is_ok());
    }

    async fn next_line(
        lines: &mut tokio::io::Lines<BufReader<tokio::net::unix::OwnedReadHalf>>,
    ) -> Option<String> {
        tokio::time::timeout(Duration::from_secs(5), lines.next_line())
            .await
            .unwrap()
            .unwrap()
    }

    #[tokio::test]
    async fn the_boot_channel_serves_one_connection_and_acks_the_exit_status() {
        let tmp = tempfile::tempdir().unwrap();
        let mux = Mux::new(tmp.path().join("vsock.sock"));
        let path = mux.guest_listener_path(BOOT_PORT);
        let exits = ExitRecorder::default();
        let (shutdown_tx, shutdown_rx) = watch::channel(false);
        let task = tokio::spawn(serve_boot(
            bind_unix(&path, 0o600).unwrap(),
            path.clone(),
            "{\"version\":1,\"mode\":\"normal\"}\n".to_owned(),
            exits.clone(),
            shutdown_rx,
        ));

        // PID 1's connection gets the config at once.
        let (read, mut write) = UnixStream::connect(&path).await.unwrap().into_split();
        let mut lines = BufReader::new(read).lines();
        assert_eq!(
            next_line(&mut lines).await.unwrap(),
            "{\"version\":1,\"mode\":\"normal\"}"
        );

        // Nothing else in the guest can reach the port now: the listener is gone.
        let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
        while path.exists() && tokio::time::Instant::now() < deadline {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        assert!(!path.exists(), "the boot listener is still there");
        assert!(UnixStream::connect(&path).await.is_err());

        // SIGTERM reaches the guest as a shutdown line.
        shutdown_tx.send_replace(true);
        assert_eq!(
            next_line(&mut lines).await.unwrap(),
            "{\"version\":1,\"type\":\"shutdown\"}"
        );

        // Garbage, another version and the old untagged shape are ignored and not acked; a
        // valid exit frame is recorded, then acknowledged.
        write
            .write_all(
                b"not json\n{\"version\":2,\"type\":\"exit\",\"exitCode\":0,\"synced\":true}\n\
                  {\"version\":1,\"exit_code\":0,\"synced\":true}\n\
                  {\"version\":1,\"type\":\"exit\",\"exitCode\":76,\"synced\":true,\"reason\":\"never claimed\"}\n",
            )
            .await
            .unwrap();
        assert_eq!(
            next_line(&mut lines).await.unwrap(),
            "{\"version\":1,\"type\":\"exitAck\",\"accepted\":true}"
        );
        assert_eq!(
            exits.latest(),
            Some(GuestExitStatus {
                version: 1,
                exit_code: 76,
                synced: true,
                reason: Some("never claimed".to_owned())
            })
        );

        // The guest powering off closes the connection, and the channel ends.
        write.shutdown().await.unwrap();
        drop(write);
        tokio::time::timeout(Duration::from_secs(5), task)
            .await
            .unwrap()
            .unwrap()
            .unwrap();
    }
}
