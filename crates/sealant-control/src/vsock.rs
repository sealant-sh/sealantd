//! The control protocol over `virtio-vsock`, for a daemon that is PID 1 of a microVM
//! (`sealantd --vm`, the `host-vm` runtime).
//!
//! The runner on the host connects to the guest's port [`CONTROL_PORT`]; the guest answers only
//! the host. Every vsock peer carries the context id (CID) the hypervisor assigned it, and the
//! host is always [`VMADDR_CID_HOST`]: [`serve_vsock`] refuses any other CID before it reads a
//! byte, so a process inside the guest (CID 1, local loopback) or a sibling VM cannot drive the
//! daemon through this listener.
//!
//! The four ports of the guest's channels (architecture §6.1) are named here so the daemon and
//! its tests agree on them: [`CONTROL_PORT`] (host → guest control), [`CAPTURE_PORT`] (guest →
//! host capture relay), [`BOOT_PORT`] (boot configuration in, exit status out) and
//! [`SESSION_PORT`] (guest → host session channel).

use std::future::Future;
use std::sync::Arc;

use tokio::io::{AsyncRead, AsyncWrite};
use tokio::sync::watch;
use tokio::task::JoinSet;

use crate::server::{drain_connections, handle_connection};
use crate::service::ControlService;

/// The context id of the host (`VMADDR_CID_HOST`): the only peer [`serve_vsock`] accepts.
pub const VMADDR_CID_HOST: u32 = 2;
/// The context id of the local machine (`VMADDR_CID_LOCAL`, vsock loopback).
pub const VMADDR_CID_LOCAL: u32 = 1;
/// Any context id (`VMADDR_CID_ANY`): what a guest listener binds.
pub const VMADDR_CID_ANY: u32 = u32::MAX;

/// Host → guest: the control protocol.
pub const CONTROL_PORT: u32 = 1024;
/// Guest → host: the capture-only relay (`capture.sock` on the host).
pub const CAPTURE_PORT: u32 = 1025;
/// Both ways: the boot configuration in, the guest's exit status out.
pub const BOOT_PORT: u32 = 1026;
/// Guest → host: the normal session channel (`session.sock` on the host). Absent on recovery.
pub const SESSION_PORT: u32 = 1027;

/// Whether a vsock peer with context id `cid` may drive the control plane: the host only.
#[must_use]
pub fn peer_cid_allowed(cid: u32) -> bool {
    cid == VMADDR_CID_HOST
}

/// Something that hands over accepted connections with the vsock context id of their peer.
/// [`VsockListener`] in the daemon; an in-memory double in tests.
pub trait PeerAcceptor: Send {
    /// The connection type.
    type Stream: AsyncRead + AsyncWrite + Send + Unpin + 'static;

    /// The next connection and its peer's context id. Must be cancel-safe: the serve loop
    /// abandons it on shutdown.
    fn accept(&mut self) -> impl Future<Output = std::io::Result<(Self::Stream, u32)>> + Send;
}

/// Serve the control protocol over connections from `acceptor` until `shutdown`, dropping every
/// connection whose peer is not the host before reading from it. Returns once every live
/// connection has unwound (aborted after a short grace), as [`crate::serve_unix`] does.
///
/// # Errors
/// Never fails today; an accept error is logged and the loop goes on. The `Result` matches
/// the other frontends so a caller composes them alike.
pub async fn serve_peers<S, A>(
    service: Arc<S>,
    mut acceptor: A,
    mut shutdown: watch::Receiver<bool>,
) -> std::io::Result<()>
where
    S: ControlService,
    A: PeerAcceptor,
{
    let mut connections = JoinSet::new();
    loop {
        tokio::select! {
            changed = shutdown.changed() => {
                if changed.is_err() || *shutdown.borrow() {
                    break;
                }
            }
            Some(_) = connections.join_next(), if !connections.is_empty() => {}
            accepted = acceptor.accept() => match accepted {
                Ok((stream, cid)) => {
                    if !peer_cid_allowed(cid) {
                        tracing::warn!(
                            peer_cid = cid,
                            "rejected vsock control connection: only the host (CID 2) may connect"
                        );
                        drop(stream);
                        continue;
                    }
                    let service = service.clone();
                    let shutdown = shutdown.clone();
                    let (read_half, write_half) = tokio::io::split(stream);
                    connections.spawn(async move {
                        handle_connection(service, read_half, write_half, shutdown).await;
                    });
                }
                Err(error) => {
                    tracing::warn!(%error, "vsock accept failed");
                    // A listener that keeps failing (EMFILE) must not spin a core.
                    tokio::time::sleep(std::time::Duration::from_millis(50)).await;
                }
            }
        }
    }
    drain_connections(connections).await;
    tracing::info!("vsock control listener closed");
    Ok(())
}

/// Bind `AF_VSOCK` port `port` on every context id and serve the control protocol to the host
/// only ([`serve_peers`]).
///
/// # Errors
/// The listener could not be bound (no vsock transport in this kernel, the port taken).
#[cfg(target_os = "linux")]
pub async fn serve_vsock<S: ControlService>(
    service: Arc<S>,
    port: u32,
    shutdown: watch::Receiver<bool>,
) -> std::io::Result<()> {
    let listener = VsockListener::bind(VMADDR_CID_ANY, port)?;
    tracing::info!(port, "vsock control listener bound (host CID 2 only)");
    serve_peers(service, listener, shutdown).await
}

#[cfg(target_os = "linux")]
pub use linux::{VsockListener, VsockStream};

#[cfg(target_os = "linux")]
mod linux {
    use std::io::{self, Read, Write};
    use std::pin::Pin;
    use std::task::{Context, Poll, ready};

    use socket2::{Domain, SockAddr, Socket, Type};
    use tokio::io::unix::AsyncFd;
    use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

    /// A connected, non-blocking `AF_VSOCK` stream socket.
    #[derive(Debug)]
    pub struct VsockStream {
        fd: AsyncFd<Socket>,
    }

    impl VsockStream {
        /// Wrap a connected vsock socket (made non-blocking) on the current Tokio runtime.
        ///
        /// # Errors
        /// The socket could not be registered with the runtime.
        pub fn from_socket(socket: Socket) -> io::Result<Self> {
            socket.set_nonblocking(true)?;
            Ok(Self {
                fd: AsyncFd::new(socket)?,
            })
        }

        /// The socket back, deregistered from this runtime, to carry a connection from one
        /// runtime to another (it stays non-blocking).
        #[must_use]
        pub fn into_socket(self) -> Socket {
            self.fd.into_inner()
        }

        /// Connect to `port` on the machine with context id `cid`.
        ///
        /// # Errors
        /// The socket could not be made, or the connect failed.
        pub async fn connect(cid: u32, port: u32) -> io::Result<Self> {
            let socket = Socket::new(Domain::VSOCK, Type::STREAM, None)?;
            socket.set_nonblocking(true)?;
            let stream = Self {
                fd: AsyncFd::new(socket)?,
            };
            match stream.fd.get_ref().connect(&SockAddr::vsock(cid, port)) {
                Ok(()) => return Ok(stream),
                Err(error) if error.raw_os_error() == Some(libc_einprogress()) => {}
                Err(error) => return Err(error),
            }
            let _ready = stream.fd.writable().await?;
            match stream.fd.get_ref().take_error()? {
                None => Ok(stream),
                Some(error) => Err(error),
            }
        }

        /// The context id and port of the peer.
        ///
        /// # Errors
        /// The peer address could not be read, or is not a vsock address.
        pub fn peer_addr(&self) -> io::Result<(u32, u32)> {
            self.fd
                .get_ref()
                .peer_addr()?
                .as_vsock_address()
                .ok_or_else(|| io::Error::other("peer is not a vsock address"))
        }
    }

    impl std::os::fd::AsFd for VsockStream {
        fn as_fd(&self) -> std::os::fd::BorrowedFd<'_> {
            self.fd.get_ref().as_fd()
        }
    }

    /// `EINPROGRESS` without a `libc` dependency in this crate: the value is fixed on Linux for
    /// every architecture this daemon is built for.
    const fn libc_einprogress() -> i32 {
        115
    }

    impl AsyncRead for VsockStream {
        fn poll_read(
            self: Pin<&mut Self>,
            cx: &mut Context<'_>,
            buf: &mut ReadBuf<'_>,
        ) -> Poll<io::Result<()>> {
            loop {
                let mut guard = ready!(self.fd.poll_read_ready(cx))?;
                let unfilled = buf.initialize_unfilled();
                match guard.try_io(|inner| inner.get_ref().read(unfilled)) {
                    Ok(Ok(read)) => {
                        buf.advance(read);
                        return Poll::Ready(Ok(()));
                    }
                    Ok(Err(error)) => return Poll::Ready(Err(error)),
                    Err(_would_block) => {}
                }
            }
        }
    }

    impl AsyncWrite for VsockStream {
        fn poll_write(
            self: Pin<&mut Self>,
            cx: &mut Context<'_>,
            buf: &[u8],
        ) -> Poll<io::Result<usize>> {
            loop {
                let mut guard = ready!(self.fd.poll_write_ready(cx))?;
                match guard.try_io(|inner| inner.get_ref().write(buf)) {
                    Ok(result) => return Poll::Ready(result),
                    Err(_would_block) => {}
                }
            }
        }

        fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
            Poll::Ready(Ok(()))
        }

        fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
            Poll::Ready(self.fd.get_ref().shutdown(std::net::Shutdown::Write))
        }
    }

    /// A listening `AF_VSOCK` socket.
    #[derive(Debug)]
    pub struct VsockListener {
        fd: AsyncFd<Socket>,
    }

    impl VsockListener {
        /// Bind `port` on context id `cid` ([`super::VMADDR_CID_ANY`] for every one) and
        /// listen. The socket is close-on-exec, as every socket `socket2` makes is.
        ///
        /// # Errors
        /// The kernel has no vsock transport, or the port is taken.
        pub fn bind(cid: u32, port: u32) -> io::Result<Self> {
            let socket = Socket::new(Domain::VSOCK, Type::STREAM, None)?;
            socket.set_nonblocking(true)?;
            socket.bind(&SockAddr::vsock(cid, port))?;
            socket.listen(128)?;
            Ok(Self {
                fd: AsyncFd::new(socket)?,
            })
        }

        /// The next connection, with its peer's context id and port.
        ///
        /// # Errors
        /// The accept failed.
        pub async fn accept(&self) -> io::Result<(VsockStream, u32, u32)> {
            loop {
                let mut guard = self.fd.readable().await?;
                match guard.try_io(|inner| inner.get_ref().accept()) {
                    Ok(Ok((socket, addr))) => {
                        let (cid, port) = addr
                            .as_vsock_address()
                            .ok_or_else(|| io::Error::other("peer is not a vsock address"))?;
                        return Ok((VsockStream::from_socket(socket)?, cid, port));
                    }
                    Ok(Err(error)) => return Err(error),
                    Err(_would_block) => {}
                }
            }
        }
    }

    impl super::PeerAcceptor for VsockListener {
        type Stream = VsockStream;

        async fn accept(&mut self) -> io::Result<(VsockStream, u32)> {
            let (stream, cid, _port) = VsockListener::accept(self).await?;
            Ok((stream, cid))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::frame::{read_frame, write_frame};
    use crate::scope::{ControlScope, ScopedService};
    use crate::service::ConnHandle;
    use sealant_protocol::{
        CaptureFlushKind, ClientMessage, Command, CommandResult, ControlError, ControlRequest,
        ControlResponse, EventEnvelope, RequestId, ServerMessage,
    };
    use tokio::io::DuplexStream;
    use tokio::sync::{broadcast, mpsc};

    /// Answers every command `Accepted`, so whatever comes back refused was refused by the
    /// transport.
    struct AcceptAll {
        events: broadcast::Sender<EventEnvelope>,
    }

    impl ControlService for AcceptAll {
        async fn handle_on_connection(
            &self,
            request: ControlRequest,
            _conn: &ConnHandle,
        ) -> ControlResponse {
            ControlResponse::ok_with(request.request_id, CommandResult::Accepted)
        }
        fn subscribe_events(&self) -> broadcast::Receiver<EventEnvelope> {
            self.events.subscribe()
        }
        fn max_frame_bytes(&self) -> u32 {
            64 * 1024
        }
    }

    fn accept_all() -> Arc<AcceptAll> {
        Arc::new(AcceptAll {
            events: broadcast::channel(4).0,
        })
    }

    impl PeerAcceptor for mpsc::Receiver<(DuplexStream, u32)> {
        type Stream = DuplexStream;
        async fn accept(&mut self) -> std::io::Result<(DuplexStream, u32)> {
            match self.recv().await {
                Some(next) => Ok(next),
                None => std::future::pending().await,
            }
        }
    }

    async fn round_trip<C>(client: &mut C, command: Command) -> Option<ControlResponse>
    where
        C: AsyncRead + AsyncWrite + Unpin,
    {
        let request = ControlRequest::new(RequestId::new("req"), command);
        let body = sealant_protocol::encode_client(&ClientMessage::Request(request));
        write_frame(client, &body, 64 * 1024).await.ok()?;
        let reply = read_frame(client, 64 * 1024).await.ok()??;
        match sealant_protocol::decode_server(&reply).expect("decode") {
            ServerMessage::Response(response) => Some(response),
            other => panic!("expected a response, got {other:?}"),
        }
    }

    #[test]
    fn only_the_host_cid_is_allowed() {
        assert!(peer_cid_allowed(VMADDR_CID_HOST));
        for cid in [0, VMADDR_CID_LOCAL, 3, 4, 1000, VMADDR_CID_ANY] {
            assert!(!peer_cid_allowed(cid), "cid {cid}");
        }
    }

    #[tokio::test]
    async fn a_peer_that_is_not_the_host_is_dropped_before_it_is_answered() {
        let (connect, accepted) = mpsc::channel(4);
        let (stop, stopped) = watch::channel(false);
        let server = tokio::spawn(serve_peers(accept_all(), accepted, stopped));

        // A process inside the guest (vsock loopback) and a sibling VM.
        for cid in [VMADDR_CID_LOCAL, 3] {
            let (mut client, server_end) = tokio::io::duplex(64 * 1024);
            connect.send((server_end, cid)).await.expect("send");
            assert!(
                round_trip(&mut client, Command::RuntimeHealth)
                    .await
                    .is_none(),
                "cid {cid} must get no answer"
            );
        }

        // The host is answered on the same listener.
        let (mut client, server_end) = tokio::io::duplex(64 * 1024);
        connect
            .send((server_end, VMADDR_CID_HOST))
            .await
            .expect("send");
        let response = round_trip(&mut client, Command::RuntimeHealth)
            .await
            .expect("the host is answered");
        assert!(response.is_ok());

        stop.send(true).expect("stop");
        drop(client);
        server.await.expect("join").expect("serve");
    }

    fn final_flush() -> Command {
        Command::CaptureFlush {
            kind: CaptureFlushKind::Final,
            deadline_ms: None,
            grace_ms: None,
        }
    }

    #[tokio::test]
    async fn a_recovery_scope_answers_status_and_the_final_flush_and_refuses_the_rest() {
        let service = Arc::new(ScopedService::new(accept_all(), ControlScope::Recovery));
        let (connect, accepted) = mpsc::channel(1);
        let (_stop, stopped) = watch::channel(false);
        tokio::spawn(serve_peers(service, accepted, stopped));
        let (mut client, server_end) = tokio::io::duplex(64 * 1024);
        connect
            .send((server_end, VMADDR_CID_HOST))
            .await
            .expect("send");

        for command in [
            Command::RuntimeHealth,
            Command::CaptureStatus,
            Command::LeaseEpoch,
            final_flush(),
            Command::RuntimeGracefulShutdown { grace_millis: None },
        ] {
            let name = format!("{command:?}");
            let response = round_trip(&mut client, command).await.expect("answered");
            assert!(response.is_ok(), "{name} must pass");
        }

        let refused: Vec<Command> = vec![
            Command::Exec(
                serde_json::from_value(serde_json::json!({
                    "executable": "/bin/sh"
                }))
                .expect("exec args"),
            ),
            Command::OpenSession(
                serde_json::from_value(serde_json::json!({ "cols": 80, "rows": 24 }))
                    .expect("session"),
            ),
            Command::AttachSession(
                serde_json::from_value(serde_json::json!({ "sessionId": "s" })).expect("attach"),
            ),
            Command::OpenForward(
                serde_json::from_value(serde_json::json!({ "host": "127.0.0.1", "port": 3000 }))
                    .expect("forward"),
            ),
            Command::OpenSftp(serde_json::from_value(serde_json::json!({})).expect("sftp")),
            Command::CaptureFlush {
                kind: CaptureFlushKind::Suspend,
                deadline_ms: None,
                grace_ms: None,
            },
            Command::CaptureReplan,
            Command::RuntimeKill,
        ];
        for command in refused {
            let name = format!("{command:?}");
            let response = round_trip(&mut client, command).await.expect("answered");
            let sealant_protocol::ResponseOutcome::Error { error } = &response.outcome else {
                panic!("{name} must be refused");
            };
            let error: &ControlError = error;
            assert_eq!(
                error.code(),
                sealant_protocol::ControlErrorCode::PolicyDenied,
                "{name}"
            );
        }
    }

    /// The real `AF_VSOCK` listener, over the kernel's vsock loopback: the peer is this machine
    /// (CID 1), not the host, so the connection must be closed unanswered.
    #[cfg(target_os = "linux")]
    #[tokio::test]
    async fn a_real_vsock_loopback_peer_is_refused() {
        let required = std::env::var("SEALANTD_REQUIRE_VSOCK").as_deref() == Ok("1");
        // An unprivileged, unlikely-to-collide port above the guest's well-known ones.
        let port = 40_000 + (std::process::id() % 20_000);
        let listener = match VsockListener::bind(VMADDR_CID_ANY, port) {
            Ok(listener) => listener,
            Err(error) if !required => {
                eprintln!(
                    "SKIPPED: SEALANTD_REQUIRE_VSOCK is not 1 and AF_VSOCK is unavailable here \
                     ({error})"
                );
                return;
            }
            Err(error) => panic!("SEALANTD_REQUIRE_VSOCK=1 but AF_VSOCK is unavailable: {error}"),
        };
        let (stop, stopped) = watch::channel(false);
        let server = tokio::spawn(serve_peers(accept_all(), listener, stopped));
        let mut client = match VsockStream::connect(VMADDR_CID_LOCAL, port).await {
            Ok(client) => client,
            Err(error) if !required => {
                eprintln!(
                    "SKIPPED: SEALANTD_REQUIRE_VSOCK is not 1 and vsock loopback is unavailable \
                     here ({error})"
                );
                stop.send(true).expect("stop");
                return;
            }
            Err(error) => panic!("SEALANTD_REQUIRE_VSOCK=1 but vsock loopback failed: {error}"),
        };
        // Close-on-exec: no process the daemon starts inherits the connection.
        let flags = nix::fcntl::fcntl(&client, nix::fcntl::FcntlArg::F_GETFD).expect("F_GETFD");
        assert_ne!(flags & nix::fcntl::FdFlag::FD_CLOEXEC.bits(), 0);
        assert!(
            round_trip(&mut client, Command::RuntimeHealth)
                .await
                .is_none(),
            "a loopback (CID 1) peer must get no answer"
        );
        stop.send(true).expect("stop");
        server.await.expect("join").expect("serve");
    }
}
