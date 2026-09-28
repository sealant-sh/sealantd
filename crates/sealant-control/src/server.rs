//! Connection acceptance and per-connection request/event pumping.

use std::os::unix::fs::{FileTypeExt, PermissionsExt};
use std::path::Path;
use std::sync::Arc;

use sealant_protocol::{
    ClientMessage, ControlError, ControlResponse, RequestId, SCHEMA_VERSION, ServerMessage,
    StreamFrame, decode_client, encode_server,
};
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::net::UnixListener;
use tokio::sync::{Mutex, broadcast, mpsc, watch};
use tokio::task::JoinSet;

use crate::frame::{FrameError, read_frame, write_frame};
use crate::service::{ChannelRegistry, CloserRegistry, ConnHandle, ControlService};

/// Per-connection outbound queue capacity (responses + forwarded events).
const OUTBOUND_CAPACITY: usize = 256;

/// Errors that terminate a connection.
#[derive(Debug, thiserror::Error)]
pub enum ConnError {
    /// A framing/transport error.
    #[error(transparent)]
    Frame(FrameError),
}

async fn write_message<W: AsyncWrite + Unpin>(
    writer: &mut W,
    message: &ServerMessage,
    max_frame_bytes: u32,
) -> Result<(), ConnError> {
    let body = encode_server(message);
    write_frame(writer, &body, max_frame_bytes)
        .await
        .map_err(ConnError::Frame)
}

/// A decoded inbound frame: a request to dispatch, an inbound stream frame to route, or an immediate
/// error response (boxed, as it is far larger than the other arms).
///
/// A malformed Protobuf frame cannot yield a correlated `requestId` (unlike the old salvageable
/// JSON), so it is answered with an `unknown` request id.
enum Inbound {
    Request(sealant_protocol::ControlRequest),
    Stream(StreamFrame),
    Error(Box<ControlResponse>),
}

fn decode_inbound(body: &[u8]) -> Inbound {
    match decode_client(body) {
        Ok(ClientMessage::Request(request)) => {
            if request.schema_version != SCHEMA_VERSION {
                return Inbound::Error(Box::new(ControlResponse::error(
                    request.request_id,
                    ControlError::new(
                        sealant_protocol::ControlErrorCode::UnsupportedVersion,
                        format!(
                            "schemaVersion {} is not supported (expected {SCHEMA_VERSION})",
                            request.schema_version
                        ),
                    ),
                )));
            }
            Inbound::Request(request)
        }
        Ok(ClientMessage::Stream(frame)) => Inbound::Stream(frame),
        Err(e) => Inbound::Error(Box::new(ControlResponse::error(
            RequestId::new("unknown"),
            ControlError::invalid_json(e.to_string()),
        ))),
    }
}

/// Route one inbound stream frame from the gateway to the registered far-end sink. `Data`/
/// `WindowUpdate` are forwarded; an `End` forwards then deregisters (half-close). Unknown channels
/// are dropped silently (the channel may have already torn down).
async fn route_inbound_stream(channels: &ChannelRegistry, frame: StreamFrame) {
    use sealant_protocol::StreamPayload;
    let is_end = matches!(frame.payload, StreamPayload::End(_));
    let sink = channels.lock().await.get(&frame.channel_id).cloned();
    if let Some(sink) = sink {
        // Awaiting send applies inbound backpressure toward the gateway via the bounded queue.
        let _ = sink.send(frame.payload).await;
    }
    if is_end {
        channels.lock().await.remove(&frame.channel_id);
    }
}

/// Drive one connection: read requests, dispatch, and pump responses + telemetry events.
///
/// Returns when the peer disconnects, a transport error occurs, or shutdown is signalled.
pub async fn handle_connection<S, R, W>(
    service: Arc<S>,
    mut reader: R,
    writer: W,
    mut shutdown: watch::Receiver<bool>,
) where
    S: ControlService,
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin + Send + 'static,
{
    let max_frame_bytes = service.max_frame_bytes();
    let (out_tx, mut out_rx) = mpsc::channel::<ServerMessage>(OUTBOUND_CAPACITY);

    // Per-connection channel registry: ChannelId -> inbound sink (gateway → far end). Owned here and
    // shared into the ConnHandle so streaming commands register their sink and so dropping it on
    // teardown closes every inbound pump task. Channels are connection-scoped: when this connection
    // drops, all its PTY attaches / forwards / sftp bridges die.
    let channels: ChannelRegistry = Arc::new(Mutex::new(std::collections::HashMap::new()));
    // Per-connection closer registry: ChannelId -> eager teardown action. Dropping the inbound sink
    // (above) only ends the inbound pump; an idle/never-writing upstream's *outbound* pump blocks on
    // read() and never observes the closed out_tx, so it must be aborted explicitly. Each streaming
    // command registers a closer that aborts both pumps AND reaps the runtime map entry; we drain and
    // invoke all of them on teardown so nothing leaks per disconnect.
    let closers: CloserRegistry = Arc::new(Mutex::new(std::collections::HashMap::new()));
    let conn = ConnHandle {
        out_tx: out_tx.clone(),
        channels: channels.clone(),
        closers: closers.clone(),
        shutdown: shutdown.clone(),
    };

    // Writer task: the single owner of the write half; drains responses and forwarded events.
    let writer_task = tokio::spawn(async move {
        let mut writer = writer;
        while let Some(message) = out_rx.recv().await {
            if let Err(e) = write_message(&mut writer, &message, max_frame_bytes).await {
                tracing::debug!(error = %e, "stopping connection writer");
                break;
            }
        }
    });

    // Forwarder task: fan telemetry events into the outbound queue for this connection.
    let mut events = service.subscribe_events();
    let event_tx = out_tx.clone();
    let forwarder = tokio::spawn(async move {
        loop {
            match events.recv().await {
                Ok(envelope) => {
                    if event_tx.send(ServerMessage::Event(envelope)).await.is_err() {
                        break;
                    }
                }
                Err(broadcast::error::RecvError::Lagged(dropped)) => {
                    // Drop accounting is the telemetry pipeline's responsibility; keep serving.
                    tracing::warn!(dropped, "event subscriber lagged");
                }
                Err(broadcast::error::RecvError::Closed) => break,
            }
        }
    });

    // Reader loop runs in the current task.
    loop {
        tokio::select! {
            changed = shutdown.changed() => {
                if changed.is_err() || *shutdown.borrow() {
                    break;
                }
            }
            frame = read_frame(&mut reader, max_frame_bytes) => {
                match frame {
                    Ok(Some(body)) => {
                        match decode_inbound(&body) {
                            Inbound::Request(request) => {
                                let response = service.handle_on_connection(request, &conn).await;
                                if out_tx.send(ServerMessage::Response(response)).await.is_err() {
                                    break;
                                }
                            }
                            // Inbound bytes/credits/close from the gateway: route to the far end.
                            // This never produces a response frame.
                            Inbound::Stream(frame) => {
                                route_inbound_stream(&channels, frame).await;
                            }
                            Inbound::Error(error_response) => {
                                if out_tx.send(ServerMessage::Response(*error_response)).await.is_err() {
                                    break;
                                }
                            }
                        }
                    }
                    Ok(None) => break,
                    Err(FrameError::TooLarge { len, max }) => {
                        // Stream is desynced past an oversized frame; report best-effort and close.
                        let response = ControlResponse::error(
                            RequestId::new("unknown"),
                            ControlError::frame_too_large(format!(
                                "frame length {len} exceeds maximum {max}"
                            )),
                        );
                        let _ = out_tx.send(ServerMessage::Response(response)).await;
                        break;
                    }
                    Err(FrameError::Io(e)) => {
                        tracing::debug!(error = %e, "connection read error");
                        break;
                    }
                }
            }
        }
    }

    // Tear down EVERY channel registered on this connection, eagerly. This is the load-bearing
    // half: draining the closer registry aborts both pumps of each forward/sftp/attach AND reaps its
    // runtime map entry — so an idle forward whose outbound pump is blocked on read() (and would
    // otherwise never observe the closed out_tx) is killed and unregistered, not leaked. We run the
    // closers before clearing the inbound-sink registry; clearing the latter then ends any inbound
    // pump that the closer did not already abort. Dropping out_tx + aborting the forwarder closes the
    // outbound queue so the writer drains and exits.
    let drained: Vec<_> = closers.lock().await.drain().map(|(_, c)| c).collect();
    for closer in drained {
        closer();
    }
    channels.lock().await.clear();
    drop(conn);
    drop(out_tx);
    forwarder.abort();
    let _ = writer_task.await;
}

/// Prepare a Unix socket path: remove a stale socket, but never blindly unlink arbitrary files.
fn prepare_socket_path(path: &Path) -> std::io::Result<()> {
    match std::fs::symlink_metadata(path) {
        Ok(meta) if meta.file_type().is_socket() => {
            // If something is still listening, refuse rather than stomp it.
            match std::os::unix::net::UnixStream::connect(path) {
                Ok(_) => {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::AddrInUse,
                        "another process is listening on the control socket",
                    ));
                }
                Err(_) => std::fs::remove_file(path)?,
            }
        }
        Ok(_) => {
            return Err(std::io::Error::new(
                std::io::ErrorKind::AlreadyExists,
                "control socket path is occupied by a non-socket file",
            ));
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
        Err(e) => return Err(e),
    }
    if let Some(parent) = path.parent()
        && !parent.as_os_str().is_empty()
    {
        std::fs::create_dir_all(parent)?;
    }
    Ok(())
}

/// How long live connections get to unwind after shutdown before they are aborted.
const CONNECTION_DRAIN: std::time::Duration = std::time::Duration::from_secs(2);

/// Bind the Unix control socket (mode `0600`) and serve connections until shutdown is signalled.
///
/// Returning is what lets the daemon exit, so this does not return while a connection still has
/// a reply queued: every live connection observes the same shutdown signal, flushes its writer
/// and ends, and those tasks are joined here (aborted after a short grace). Without the join, the
/// reply to the very command that asked for the shutdown raced the process exit, and the client
/// saw its connection close with the request still pending.
///
/// # Errors
/// Returns an I/O error if the socket cannot be prepared or bound.
pub async fn serve_unix<S: ControlService>(
    service: Arc<S>,
    path: &Path,
    allowed_peer_uids: Vec<u32>,
    mut shutdown: watch::Receiver<bool>,
) -> std::io::Result<()> {
    prepare_socket_path(path)?;
    let listener = UnixListener::bind(path)?;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))?;
    let self_uid = crate::peer::self_uid();
    tracing::info!(socket = %path.display(), "control socket listening");
    let mut connections = JoinSet::new();

    loop {
        tokio::select! {
            changed = shutdown.changed() => {
                if changed.is_err() || *shutdown.borrow() {
                    break;
                }
            }
            // Reap finished connection tasks so the set does not grow without bound.
            Some(_) = connections.join_next(), if !connections.is_empty() => {}
            accepted = listener.accept() => {
                match accepted {
                    Ok((stream, _addr)) => {
                        // Reject unauthorized peers (plan §18). The socket is already 0600; this
                        // adds an SO_PEERCRED uid check (Linux) and fails closed if unknown.
                        if !crate::peer::validate_peer(&stream, self_uid, &allowed_peer_uids) {
                            tracing::warn!("rejected control connection from unauthorized peer");
                            drop(stream);
                            continue;
                        }
                        let service = service.clone();
                        let shutdown = shutdown.clone();
                        let (read_half, write_half) = stream.into_split();
                        connections.spawn(async move {
                            handle_connection(service, read_half, write_half, shutdown).await;
                        });
                    }
                    Err(e) => tracing::warn!(error = %e, "accept failed"),
                }
            }
        }
    }

    // Stop accepting first, then drain: connections unwind on the signal they already hold.
    drop(listener);
    let _ = std::fs::remove_file(path);
    let grace = tokio::time::sleep(CONNECTION_DRAIN);
    tokio::pin!(grace);
    loop {
        tokio::select! {
            () = &mut grace => break,
            next = connections.join_next() => {
                if next.is_none() {
                    break;
                }
            }
        }
    }
    connections.abort_all();
    while connections.join_next().await.is_some() {}
    tracing::info!("control socket closed");
    Ok(())
}

/// Serve a single connection over stdio (protocol on stdin/stdout; diagnostics stay on stderr).
pub async fn serve_stdio<S: ControlService>(service: Arc<S>, shutdown: watch::Receiver<bool>) {
    let stdin = tokio::io::stdin();
    let stdout = tokio::io::stdout();
    handle_connection(service, stdin, stdout, shutdown).await;
}

#[cfg(test)]
mod tests {
    use super::*;
    use sealant_protocol::{
        CaptureMethod, ChannelId, Command, CommandResult, Confidence, ControlRequest,
        EventEnvelope, EventId, EventPayload, MonotonicNanos, RuntimeHeartbeat, RuntimeId,
        RuntimeState, Sequence, StreamFrame, StreamPayload, WallClockMicros, encode_client,
    };

    struct MockService {
        events: broadcast::Sender<EventEnvelope>,
    }

    impl ControlService for MockService {
        async fn handle_on_connection(
            &self,
            request: ControlRequest,
            _conn: &ConnHandle,
        ) -> ControlResponse {
            match request.command {
                Command::RuntimeHealth => {
                    ControlResponse::ok_with(request.request_id, CommandResult::Accepted)
                }
                _ => ControlResponse::error(
                    request.request_id,
                    ControlError::unknown_command("unsupported in mock"),
                ),
            }
        }
        fn subscribe_events(&self) -> broadcast::Receiver<EventEnvelope> {
            self.events.subscribe()
        }
        fn max_frame_bytes(&self) -> u32 {
            64 * 1024
        }
    }

    fn heartbeat(seq: u64) -> EventEnvelope {
        EventEnvelope {
            schema_version: SCHEMA_VERSION,
            event_id: EventId::new(format!("evt_{seq}")),
            runtime_id: RuntimeId::new("rt_test"),
            execution_id: None,
            session_id: None,
            process_id: None,
            request_id: None,
            sequence: Sequence(seq),
            observed_at: WallClockMicros(1),
            monotonic_timestamp: MonotonicNanos(seq),
            capture_method: CaptureMethod::Internal,
            confidence: Confidence::Observed,
            payload: EventPayload::RuntimeHeartbeat(RuntimeHeartbeat {
                state: RuntimeState::Healthy,
            }),
        }
    }

    #[tokio::test]
    async fn dispatches_request_and_streams_events() {
        let (events_tx, _) = broadcast::channel(16);
        let service = Arc::new(MockService {
            events: events_tx.clone(),
        });
        let (_sd_tx, sd_rx) = watch::channel(false);

        // Wire a duplex pipe as the "connection".
        let (mut client, server) = tokio::io::duplex(64 * 1024);
        let (server_read, server_write) = tokio::io::split(server);
        let conn = tokio::spawn(handle_connection(service, server_read, server_write, sd_rx));

        // Send a runtime.health request.
        let request = ControlRequest::new(RequestId::new("req_1"), Command::RuntimeHealth);
        let body = sealant_protocol::encode_client(&ClientMessage::Request(request));
        write_frame(&mut client, &body, 64 * 1024)
            .await
            .expect("write");

        // Read the response.
        let resp_body = read_frame(&mut client, 64 * 1024)
            .await
            .expect("read")
            .expect("some");
        let resp = sealant_protocol::decode_server(&resp_body).expect("de");
        match resp {
            ServerMessage::Response(r) => {
                assert_eq!(r.request_id, RequestId::new("req_1"));
                assert!(r.is_ok());
            }
            other => panic!("expected response first, got {other:?}"),
        }

        // Publish a telemetry event; it should arrive on the connection.
        events_tx.send(heartbeat(7)).expect("broadcast");
        let evt_body = read_frame(&mut client, 64 * 1024)
            .await
            .expect("read")
            .expect("some");
        let evt = sealant_protocol::decode_server(&evt_body).expect("de");
        match evt {
            ServerMessage::Event(e) => assert_eq!(e.sequence, Sequence(7)),
            other => panic!("expected event, got {other:?}"),
        }

        drop(client);
        let _ = conn.await;
    }

    /// A service that asks for shutdown from inside the request it is answering, as
    /// `runtime.gracefulShutdown` does.
    struct ShutdownService {
        events: broadcast::Sender<EventEnvelope>,
        stop: watch::Sender<bool>,
    }

    impl ControlService for ShutdownService {
        async fn handle_on_connection(
            &self,
            request: ControlRequest,
            _conn: &ConnHandle,
        ) -> ControlResponse {
            let _ = self.stop.send(true);
            // The rest of the daemon's shutdown runs on other workers and is quick on an idle
            // runtime. Holding the reply back makes that teardown win every time, not sometimes.
            tokio::time::sleep(std::time::Duration::from_millis(50)).await;
            ControlResponse::ok_with(request.request_id, CommandResult::Accepted)
        }
        fn subscribe_events(&self) -> broadcast::Receiver<EventEnvelope> {
            self.events.subscribe()
        }
        fn max_frame_bytes(&self) -> u32 {
            64 * 1024
        }
    }

    /// The daemon exits when `serve_unix` returns, which drops every task still running. The
    /// server runs on a runtime of its own here and that runtime is dropped the moment
    /// `serve_unix` returns, as a process exit would: the reply to the request that asked for the
    /// shutdown must already be on the wire.
    #[test]
    fn the_reply_to_a_shutdown_request_is_sent_before_serve_unix_returns() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("control.sock");
        let (stop, stopped) = watch::channel(false);
        let (events, _) = broadcast::channel(16);
        let service = Arc::new(ShutdownService { events, stop });

        let server_path = path.clone();
        let server = std::thread::spawn(move || {
            let runtime = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .expect("runtime");
            let uid = crate::peer::self_uid();
            let served = runtime.block_on(serve_unix(service, &server_path, vec![uid], stopped));
            drop(runtime);
            served
        });

        let client = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("runtime");
        client.block_on(async {
            let mut stream = loop {
                match tokio::net::UnixStream::connect(&path).await {
                    Ok(stream) => break stream,
                    Err(_) => tokio::time::sleep(std::time::Duration::from_millis(5)).await,
                }
            };
            let request = ControlRequest::new(
                RequestId::new("req_stop"),
                Command::RuntimeGracefulShutdown { grace_millis: None },
            );
            let body = sealant_protocol::encode_client(&ClientMessage::Request(request));
            write_frame(&mut stream, &body, 64 * 1024)
                .await
                .expect("write");
            let reply = read_frame(&mut stream, 64 * 1024)
                .await
                .expect("read")
                .expect("the reply must arrive before the connection closes");
            match sealant_protocol::decode_server(&reply).expect("decode") {
                ServerMessage::Response(response) => {
                    assert_eq!(response.request_id, RequestId::new("req_stop"));
                    assert!(response.is_ok());
                }
                other => panic!("expected the shutdown reply, got {other:?}"),
            }
        });
        server.join().expect("server thread").expect("serve_unix");
    }

    #[tokio::test]
    async fn malformed_frame_gets_error_response() {
        let (events_tx, _) = broadcast::channel(16);
        let service = Arc::new(MockService { events: events_tx });
        let (_sd_tx, sd_rx) = watch::channel(false);
        let (mut client, server) = tokio::io::duplex(4096);
        let (server_read, server_write) = tokio::io::split(server);
        let conn = tokio::spawn(handle_connection(service, server_read, server_write, sd_rx));

        // Not a valid protobuf ClientMessage. Protobuf cannot salvage a requestId, so the daemon
        // answers with an `unknown` request id and a decode error.
        let body = b"this is not a valid protobuf frame \xff\x00\xfe";
        write_frame(&mut client, body, 4096).await.expect("write");

        let resp_body = read_frame(&mut client, 4096)
            .await
            .expect("read")
            .expect("some");
        let resp = sealant_protocol::decode_server(&resp_body).expect("de");
        match resp {
            ServerMessage::Response(r) => {
                assert_eq!(r.request_id, RequestId::new("unknown"));
                assert!(!r.is_ok());
            }
            other => panic!("expected error response, got {other:?}"),
        }
        drop(client);
        let _ = conn.await;
    }

    /// A service whose `RuntimeHealth` opens a channel ("chan_echo") on the connection: it registers
    /// an inbound sink and spawns a pump that echoes every inbound `Data` frame back out as an
    /// outbound `StreamFrame::Data`. Proves the ConnHandle/registry wiring end-to-end.
    struct EchoChannelService {
        events: broadcast::Sender<EventEnvelope>,
    }

    impl ControlService for EchoChannelService {
        async fn handle_on_connection(
            &self,
            request: ControlRequest,
            conn: &ConnHandle,
        ) -> ControlResponse {
            let channel = ChannelId::new("chan_echo");
            let (in_tx, mut in_rx) = mpsc::channel::<StreamPayload>(8);
            conn.register_channel(channel.clone(), in_tx).await;
            let out_tx = conn.out_tx.clone();
            tokio::spawn(async move {
                let mut seq = 0u64;
                while let Some(payload) = in_rx.recv().await {
                    match payload {
                        StreamPayload::Data { data } => {
                            let frame = StreamFrame::data(channel.clone(), seq, data);
                            seq += 1;
                            if out_tx.send(ServerMessage::Stream(frame)).await.is_err() {
                                break;
                            }
                        }
                        StreamPayload::End(_) => break,
                        StreamPayload::WindowUpdate { .. } => {}
                    }
                }
            });
            ControlResponse::ok_with(request.request_id, CommandResult::Accepted)
        }
        fn subscribe_events(&self) -> broadcast::Receiver<EventEnvelope> {
            self.events.subscribe()
        }
        fn max_frame_bytes(&self) -> u32 {
            64 * 1024
        }
    }

    #[tokio::test]
    async fn inbound_stream_frames_route_to_registered_channel() {
        let (events_tx, _) = broadcast::channel(16);
        let service = Arc::new(EchoChannelService { events: events_tx });
        let (_sd_tx, sd_rx) = watch::channel(false);
        let (mut client, server) = tokio::io::duplex(64 * 1024);
        let (server_read, server_write) = tokio::io::split(server);
        let conn = tokio::spawn(handle_connection(service, server_read, server_write, sd_rx));

        // Open the echo channel via a request.
        let req = ControlRequest::new(RequestId::new("req_open"), Command::RuntimeHealth);
        let body = encode_client(&ClientMessage::Request(req));
        write_frame(&mut client, &body, 64 * 1024)
            .await
            .expect("write");
        // Drain the response.
        let resp = read_frame(&mut client, 64 * 1024)
            .await
            .expect("r")
            .expect("s");
        assert!(matches!(
            sealant_protocol::decode_server(&resp).expect("de"),
            ServerMessage::Response(_)
        ));

        // Send three inbound Data frames; they must echo back in order.
        for i in 0..3u8 {
            let frame = StreamFrame::data(ChannelId::new("chan_echo"), u64::from(i), vec![i; 4]);
            let body = encode_client(&ClientMessage::Stream(frame));
            write_frame(&mut client, &body, 64 * 1024).await.expect("w");
        }
        for i in 0..3u8 {
            let out = read_frame(&mut client, 64 * 1024)
                .await
                .expect("r")
                .expect("s");
            match sealant_protocol::decode_server(&out).expect("de") {
                ServerMessage::Stream(StreamFrame {
                    payload: StreamPayload::Data { data },
                    seq,
                    channel_id,
                }) => {
                    assert_eq!(channel_id, ChannelId::new("chan_echo"));
                    assert_eq!(seq, u64::from(i));
                    assert_eq!(data.as_slice(), &[i; 4]);
                }
                other => panic!("expected echoed data, got {other:?}"),
            }
        }

        drop(client);
        let _ = conn.await;
    }

    #[tokio::test]
    async fn dropping_connection_tears_down_channels() {
        // The echo pump holds the inbound receiver; when the connection drops, handle_connection
        // clears the registry, dropping the inbound sender so the pump's recv() returns None and the
        // task exits. We observe this by confirming handle_connection returns (joins) after the
        // client disconnects, which only happens once the writer task drains — i.e. all clones of
        // out_tx (including the pump's) are gone.
        let (events_tx, _) = broadcast::channel(16);
        let service = Arc::new(EchoChannelService { events: events_tx });
        let (_sd_tx, sd_rx) = watch::channel(false);
        let (mut client, server) = tokio::io::duplex(64 * 1024);
        let (server_read, server_write) = tokio::io::split(server);
        let conn = tokio::spawn(handle_connection(service, server_read, server_write, sd_rx));

        let req = ControlRequest::new(RequestId::new("req_open"), Command::RuntimeHealth);
        let body = encode_client(&ClientMessage::Request(req));
        write_frame(&mut client, &body, 64 * 1024)
            .await
            .expect("write");
        let _ = read_frame(&mut client, 64 * 1024)
            .await
            .expect("r")
            .expect("s");

        // Disconnect. handle_connection must return promptly (channels torn down, writer drained).
        drop(client);
        tokio::time::timeout(std::time::Duration::from_secs(5), conn)
            .await
            .expect("handle_connection should return after teardown")
            .expect("join");
    }
}
