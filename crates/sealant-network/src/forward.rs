//! Direct forwarding: open a TCP connection (or a connected UDP socket) from inside the container
//! to `host:port` and pump both ways over a reliable [`ChannelId`] conduit (gateway §1.B).
//!
//! UDP keeps datagram boundaries by construction: one [`StreamPayload::Data`] frame is EXACTLY one
//! datagram, in both directions. The conduit is already message-framed, so nothing re-chunks it.
//!
//! This is a *raw byte conduit*: payload never touches the telemetry `EventBus`. Outbound (socket →
//! gateway) bytes become [`StreamFrame::Data`] on the connection's backpressured `out_tx`; inbound
//! (gateway → socket) [`StreamPayload`] frames arrive on an mpsc fed by the control reader. Either
//! side's EOF/half-close maps to a [`StreamFrame::End`], mirroring `copy_bidirectional` semantics.

use std::collections::HashMap;
use std::sync::Mutex;

use std::sync::Arc;

use sealant_protocol::{
    ChannelId, ControlError, ControlErrorCode, ExecutionId, ForwardProtocol, ServerMessage,
    StreamEnd, StreamFrame, StreamPayload,
};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::tcp::OwnedReadHalf;
use tokio::net::{TcpStream, UdpSocket};
use tokio::sync::mpsc;

/// Read-buffer size for the socket→gateway pump (raw conduit; not a recorded stream).
const READ_BUF: usize = 64 * 1024;

/// One datagram is at most 65_507 payload bytes; a 64 KiB + header buffer never truncates.
const UDP_BUF: usize = 65_536;

/// A live forward: the two pump tasks driving one TCP connection.
#[derive(Debug)]
struct ForwardEntry {
    socket_to_gateway: tokio::task::JoinHandle<()>,
    gateway_to_socket: tokio::task::JoinHandle<()>,
}

impl ForwardEntry {
    fn abort(&self) {
        self.socket_to_gateway.abort();
        self.gateway_to_socket.abort();
    }
}

/// Registry of live forwards, keyed by channel id. Connection-scoped teardown drops the inbound
/// sinks (closing `gateway_to_socket`); [`ForwardRuntime::close`] aborts a single forward eagerly.
#[derive(Debug, Default)]
pub struct ForwardRuntime {
    inner: Mutex<HashMap<ChannelId, ForwardEntry>>,
}

impl ForwardRuntime {
    /// An empty forward runtime.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Open a forward to `host:port` bound to `channel_id`.
    ///
    /// On success returns the inbound sink (gateway → socket) the caller must register in the
    /// connection's channel registry so reader-routed `Stream` frames reach the socket. On connect
    /// failure returns a [`ControlError`] (the caller may also emit a `StreamFrame::End{error}`).
    ///
    /// # Errors
    /// Returns a [`ControlError`] with [`ControlErrorCode::InternalError`] when the TCP connect
    /// fails.
    pub async fn open(
        &self,
        channel_id: ChannelId,
        host: &str,
        port: u16,
        _execution_id: Option<ExecutionId>,
        protocol: ForwardProtocol,
        out_tx: mpsc::Sender<ServerMessage>,
    ) -> Result<mpsc::Sender<StreamPayload>, ControlError> {
        if protocol == ForwardProtocol::Udp {
            return self.open_udp(channel_id, host, port, out_tx).await;
        }
        // The exact connect used by the egress proxy (proxy.rs); resolves inside the container.
        let stream = TcpStream::connect((host, port)).await.map_err(|e| {
            ControlError::new(
                ControlErrorCode::InternalError,
                format!("forward connect to {host}:{port} failed: {e}"),
            )
        })?;
        let _ = stream.set_nodelay(true);
        let (read_half, mut write_half) = stream.into_split();

        // Inbound (gateway → socket): bounded so a slow socket backpressures the gateway.
        let (inbound_tx, mut inbound_rx) = mpsc::channel::<StreamPayload>(64);

        // socket → gateway: read raw bytes, push StreamFrame::Data (awaited = backpressure).
        let s2g_channel = channel_id.clone();
        let s2g_out = out_tx.clone();
        let socket_to_gateway = tokio::spawn(async move {
            pump_socket_to_gateway(read_half, s2g_channel, s2g_out).await;
        });

        // gateway → socket: write inbound Data; an inbound End half-closes the write side.
        let gateway_to_socket = tokio::spawn(async move {
            while let Some(payload) = inbound_rx.recv().await {
                match payload {
                    StreamPayload::Data { data } => {
                        if write_half.write_all(data.as_slice()).await.is_err() {
                            break;
                        }
                    }
                    // Flow-control credits are advisory; the mpsc depth already bounds us.
                    StreamPayload::WindowUpdate { .. } => {}
                    StreamPayload::End(_) => {
                        let _ = write_half.shutdown().await;
                        break;
                    }
                }
            }
            let _ = write_half.shutdown().await;
        });

        self.inner.lock().unwrap_or_else(|e| e.into_inner()).insert(
            channel_id,
            ForwardEntry {
                socket_to_gateway,
                gateway_to_socket,
            },
        );
        Ok(inbound_tx)
    }

    /// Open a connected-UDP forward to `host:port` bound to `channel_id`.
    ///
    /// `connect` pins the peer: sends need no address and receives only accept
    /// that peer's datagrams — the conduit stays point-to-point like the TCP
    /// path. UDP has no EOF, so the flow lives until an inbound `End` or an
    /// explicit close; transient ICMP-driven errors (nothing listening yet)
    /// never kill the pumps.
    ///
    /// # Errors
    /// Returns a [`ControlError`] with [`ControlErrorCode::InternalError`] when
    /// binding or resolving/connecting the socket fails.
    async fn open_udp(
        &self,
        channel_id: ChannelId,
        host: &str,
        port: u16,
        out_tx: mpsc::Sender<ServerMessage>,
    ) -> Result<mpsc::Sender<StreamPayload>, ControlError> {
        let socket = UdpSocket::bind(("0.0.0.0", 0)).await.map_err(|e| {
            ControlError::new(
                ControlErrorCode::InternalError,
                format!("udp forward bind failed: {e}"),
            )
        })?;
        socket.connect((host, port)).await.map_err(|e| {
            ControlError::new(
                ControlErrorCode::InternalError,
                format!("udp forward connect to {host}:{port} failed: {e}"),
            )
        })?;
        let socket = Arc::new(socket);

        // Inbound (gateway → socket): bounded so a fast gateway backpressures.
        let (inbound_tx, mut inbound_rx) = mpsc::channel::<StreamPayload>(64);

        // socket → gateway: every received datagram becomes exactly one Data frame.
        let s2g_channel = channel_id.clone();
        let s2g_out = out_tx.clone();
        let s2g_socket = Arc::clone(&socket);
        let socket_to_gateway = tokio::spawn(async move {
            let mut buf = vec![0u8; UDP_BUF];
            let mut seq: u64 = 0;
            loop {
                match s2g_socket.recv(&mut buf).await {
                    Ok(n) => {
                        let frame = StreamFrame::data(s2g_channel.clone(), seq, &buf[..n]);
                        seq = seq.wrapping_add(1);
                        if s2g_out.send(ServerMessage::Stream(frame)).await.is_err() {
                            return; // connection gone
                        }
                    }
                    // ECONNREFUSED after an ICMP just means nothing listens yet;
                    // Linux delivers it once per probe, so this cannot hot-loop.
                    Err(_) => continue,
                }
            }
        });

        // gateway → socket: one Data frame = one send(); End retires the flow.
        let gateway_to_socket = tokio::spawn(async move {
            while let Some(payload) = inbound_rx.recv().await {
                match payload {
                    StreamPayload::Data { data } => {
                        // A datagram is delivered whole or not at all — a send
                        // error (e.g. ICMP-driven refusal) drops that one
                        // datagram, exactly UDP's own contract.
                        let _ = socket.send(data.as_slice()).await;
                    }
                    StreamPayload::WindowUpdate { .. } => {}
                    StreamPayload::End(_) => break,
                }
            }
        });

        self.inner.lock().unwrap_or_else(|e| e.into_inner()).insert(
            channel_id,
            ForwardEntry {
                socket_to_gateway,
                gateway_to_socket,
            },
        );
        Ok(inbound_tx)
    }

    /// Close a forward eagerly, aborting both pumps. Idempotent.
    pub fn close(&self, channel_id: &ChannelId) {
        if let Some(entry) = self
            .inner
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .remove(channel_id)
        {
            entry.abort();
        }
    }

    /// Number of live forwards.
    #[must_use]
    pub fn len(&self) -> usize {
        self.inner.lock().unwrap_or_else(|e| e.into_inner()).len()
    }

    /// Whether there are no live forwards.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

/// Pump the socket read half to the gateway. On EOF/error, emit a final `StreamFrame::End` so the
/// gateway half-closes its SSH channel; on error the `End` carries the message.
async fn pump_socket_to_gateway(
    mut read_half: OwnedReadHalf,
    channel_id: ChannelId,
    out_tx: mpsc::Sender<ServerMessage>,
) {
    let mut buf = vec![0u8; READ_BUF];
    let mut seq: u64 = 0;
    let mut error: Option<String> = None;
    loop {
        match read_half.read(&mut buf).await {
            Ok(0) => break, // clean EOF / half-close from the far end
            Ok(n) => {
                let frame = StreamFrame::data(channel_id.clone(), seq, &buf[..n]);
                seq = seq.wrapping_add(1);
                if out_tx.send(ServerMessage::Stream(frame)).await.is_err() {
                    return; // connection gone; no point emitting End
                }
            }
            Err(e) => {
                error = Some(e.to_string());
                break;
            }
        }
    }
    let end = StreamFrame::end(
        channel_id,
        u64::MAX,
        StreamEnd {
            exit_code: None,
            signal: None,
            error,
        },
    );
    let _ = out_tx.send(ServerMessage::Stream(end)).await;
}

#[cfg(test)]
mod tests {
    use super::*;
    use sealant_protocol::Base64Bytes;
    use tokio::net::TcpListener;

    /// Loopback echo: open a forward to an echo server, send bytes inbound, read them back as
    /// outbound `StreamFrame::Data`, and confirm a clean `End` on far-end close.
    #[tokio::test]
    async fn forward_loopback_echo_round_trips() {
        // Echo server.
        let listener = TcpListener::bind(("127.0.0.1", 0)).await.expect("bind");
        let addr = listener.local_addr().expect("addr");
        tokio::spawn(async move {
            let (mut s, _) = listener.accept().await.expect("accept");
            let mut b = [0u8; 1024];
            loop {
                match s.read(&mut b).await {
                    Ok(0) | Err(_) => break,
                    Ok(n) => {
                        if s.write_all(&b[..n]).await.is_err() {
                            break;
                        }
                    }
                }
            }
        });

        let (out_tx, mut out_rx) = mpsc::channel::<ServerMessage>(256);
        let rt = ForwardRuntime::new();
        let channel = ChannelId::new("chan_fwd");
        let inbound = rt
            .open(
                channel.clone(),
                "127.0.0.1",
                addr.port(),
                None,
                ForwardProtocol::Tcp,
                out_tx,
            )
            .await
            .expect("open forward");
        assert_eq!(rt.len(), 1);

        // Send bytes inbound (gateway → socket).
        inbound
            .send(StreamPayload::data(Base64Bytes::new(b"hello".to_vec())))
            .await
            .expect("inbound send");

        // Read the echoed bytes back as outbound StreamFrame::Data.
        let mut got = Vec::new();
        while got.len() < 5 {
            match out_rx.recv().await.expect("out frame") {
                ServerMessage::Stream(StreamFrame {
                    payload: StreamPayload::Data { data },
                    channel_id,
                    ..
                }) => {
                    assert_eq!(channel_id, channel);
                    got.extend_from_slice(data.as_slice());
                }
                other => panic!("expected data frame, got {other:?}"),
            }
        }
        assert_eq!(&got, b"hello");

        // Half-close inbound → echo server sees EOF → far end closes → outbound End.
        inbound
            .send(StreamPayload::End(StreamEnd::default()))
            .await
            .expect("inbound end");
        loop {
            match out_rx.recv().await.expect("out frame") {
                ServerMessage::Stream(StreamFrame {
                    payload: StreamPayload::End(end),
                    ..
                }) => {
                    assert!(end.error.is_none(), "clean close, got {:?}", end.error);
                    break;
                }
                ServerMessage::Stream(StreamFrame {
                    payload: StreamPayload::Data { .. },
                    ..
                }) => {}
                other => panic!("expected end/data, got {other:?}"),
            }
        }

        rt.close(&channel);
        assert!(rt.is_empty());
    }

    /// An IDLE upstream (accepts, never writes) leaves the socket→gateway pump blocked on read().
    /// `close` must abort it and remove the map entry regardless — this is the teardown path that
    /// connection drop relies on. We also assert the upstream sees EOF, proving the FD was closed.
    #[tokio::test]
    async fn close_reaps_idle_forward_and_closes_socket() {
        let listener = TcpListener::bind(("127.0.0.1", 0)).await.expect("bind");
        let addr = listener.local_addr().expect("addr");
        let (eof_tx, eof_rx) = tokio::sync::oneshot::channel::<()>();
        tokio::spawn(async move {
            let (mut s, _) = listener.accept().await.expect("accept");
            // Never write; just wait for the peer (the daemon) to close, then signal EOF.
            let mut b = [0u8; 16];
            let n = s.read(&mut b).await.unwrap_or(0);
            assert_eq!(n, 0, "idle upstream must only see EOF");
            let _ = eof_tx.send(());
        });

        let (out_tx, _out_rx) = mpsc::channel::<ServerMessage>(8);
        let rt = ForwardRuntime::new();
        let channel = ChannelId::new("chan_idle");
        let _inbound = rt
            .open(
                channel.clone(),
                "127.0.0.1",
                addr.port(),
                None,
                ForwardProtocol::Tcp,
                out_tx,
            )
            .await
            .expect("open forward");
        assert_eq!(rt.len(), 1);

        // The socket→gateway pump is now blocked on read() (upstream never writes). close() must
        // still abort it and drop the entry — without depending on out_tx ever being observed.
        rt.close(&channel);
        assert!(rt.is_empty(), "close must remove the map entry");

        tokio::time::timeout(std::time::Duration::from_secs(5), eof_rx)
            .await
            .expect("upstream must see EOF once the aborted pump drops the socket")
            .expect("eof signal");
    }

    /// UDP loopback echo: datagram boundaries must survive both directions —
    /// two sends arrive as two frames, never coalesced into one.
    #[tokio::test]
    async fn udp_forward_round_trips_datagrams() {
        let server = tokio::net::UdpSocket::bind(("127.0.0.1", 0))
            .await
            .expect("bind udp echo");
        let addr = server.local_addr().expect("addr");
        tokio::spawn(async move {
            let mut b = [0u8; 2048];
            loop {
                let Ok((n, peer)) = server.recv_from(&mut b).await else {
                    break;
                };
                if server.send_to(&b[..n], peer).await.is_err() {
                    break;
                }
            }
        });

        let (out_tx, mut out_rx) = mpsc::channel::<ServerMessage>(256);
        let rt = ForwardRuntime::new();
        let channel = ChannelId::new("chan_udp");
        let inbound = rt
            .open(
                channel.clone(),
                "127.0.0.1",
                addr.port(),
                None,
                ForwardProtocol::Udp,
                out_tx,
            )
            .await
            .expect("open udp forward");
        assert_eq!(rt.len(), 1);

        // Two distinct datagrams must come back as two distinct Data frames.
        for payload in [b"ping".as_slice(), b"pong!".as_slice()] {
            inbound
                .send(StreamPayload::data(Base64Bytes::new(payload.to_vec())))
                .await
                .expect("inbound send");
            match out_rx.recv().await.expect("echo frame") {
                ServerMessage::Stream(StreamFrame {
                    payload: StreamPayload::Data { data },
                    channel_id,
                    ..
                }) => {
                    assert_eq!(channel_id, channel);
                    assert_eq!(data.as_slice(), payload, "boundary must hold");
                }
                other => panic!("expected data frame, got {other:?}"),
            }
        }

        rt.close(&channel);
        assert!(rt.is_empty());
    }

    #[tokio::test]
    async fn forward_connect_failure_is_an_error() {
        let (out_tx, _out_rx) = mpsc::channel::<ServerMessage>(8);
        let rt = ForwardRuntime::new();
        // Port 1 on loopback should refuse.
        let result = rt
            .open(
                ChannelId::new("chan_x"),
                "127.0.0.1",
                1,
                None,
                ForwardProtocol::Tcp,
                out_tx,
            )
            .await;
        assert!(result.is_err(), "connect to 127.0.0.1:1 should fail");
        assert!(rt.is_empty());
    }
}
