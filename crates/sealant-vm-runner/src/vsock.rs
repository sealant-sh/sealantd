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
//! | 1026 | guest → host | `vsock.sock_1026`, answered in the runner: boot config out, exit status in |
//! | 1027 | guest → host | `vsock.sock_1027` → `/run/sealant/session.sock`, normal boots only |

use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};
use tokio::net::{UnixListener, UnixStream};

use crate::exit::ExitRecorder;
use crate::protocol::GuestExitStatus;

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
        let (mut client, _) = listener.accept().await?;
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
        let (mut guest, _) = listener.accept().await?;
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

/// Port 1026: on each guest connection, writes `boot_frame` (one [`crate::protocol::VmBootConfig`]
/// line), then records every valid [`GuestExitStatus`] line the guest sends until it closes.
pub async fn serve_boot(
    listener: UnixListener,
    boot_frame: Arc<String>,
    exits: ExitRecorder,
) -> std::io::Result<()> {
    loop {
        let (guest, _) = listener.accept().await?;
        let frame = Arc::clone(&boot_frame);
        let exits = exits.clone();
        tokio::spawn(async move {
            if let Err(e) = boot_session(guest, &frame, &exits).await {
                tracing::warn!("boot channel connection ended: {e}");
            }
        });
    }
}

async fn boot_session(guest: UnixStream, frame: &str, exits: &ExitRecorder) -> std::io::Result<()> {
    let (read, mut write) = guest.into_split();
    write.write_all(frame.as_bytes()).await?;
    write.flush().await?;
    let mut reader = BufReader::new(read);
    let mut line = String::new();
    loop {
        line.clear();
        let n = (&mut reader)
            .take(MAX_FRAME as u64 + 1)
            .read_line(&mut line)
            .await?;
        if n == 0 {
            return Ok(());
        }
        if n > MAX_FRAME {
            return Err(std::io::Error::other("boot channel frame too long"));
        }
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
                exits.record(status);
            }
            Err(e) => tracing::warn!("ignoring a boot channel frame: {e}"),
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

    #[tokio::test]
    async fn the_boot_channel_sends_the_config_and_records_the_exit_status() {
        let tmp = tempfile::tempdir().unwrap();
        let mux = Mux::new(tmp.path().join("vsock.sock"));
        let path = mux.guest_listener_path(BOOT_PORT);
        let exits = ExitRecorder::default();
        let frame = Arc::new("{\"version\":1,\"mode\":\"normal\"}\n".to_owned());
        tokio::spawn(serve_boot(
            bind_unix(&path, 0o600).unwrap(),
            frame,
            exits.clone(),
        ));

        // First connection: boot. The guest reads its config and closes.
        let guest = UnixStream::connect(&path).await.unwrap();
        let mut lines = BufReader::new(guest).lines();
        assert_eq!(
            lines.next_line().await.unwrap().unwrap(),
            "{\"version\":1,\"mode\":\"normal\"}"
        );
        drop(lines);

        // Second connection at shutdown: a garbage line and a wrong version are ignored, the
        // valid frame is recorded.
        let (read, mut write) = UnixStream::connect(&path).await.unwrap().into_split();
        let mut config = String::new();
        BufReader::new(read).read_line(&mut config).await.unwrap();
        assert!(config.ends_with('\n'));
        write
            .write_all(
                b"not json\n{\"version\":2,\"exit_code\":0,\"synced\":true}\n\
                  {\"version\":1,\"exit_code\":76,\"synced\":true,\"reason\":\"never claimed\"}\n",
            )
            .await
            .unwrap();
        write.shutdown().await.unwrap();
        let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
        while exits.latest().is_none() && tokio::time::Instant::now() < deadline {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        assert_eq!(
            exits.latest(),
            Some(GuestExitStatus {
                version: 1,
                exit_code: 76,
                synced: true,
                reason: Some("never claimed".to_owned())
            })
        );
    }
}
