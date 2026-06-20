//! Connection acceptance and per-connection request/event pumping.

use std::os::unix::fs::{FileTypeExt, PermissionsExt};
use std::path::Path;
use std::sync::Arc;

use sealant_protocol::{
    ClientMessage, ControlError, ControlResponse, RequestId, SCHEMA_VERSION, ServerMessage,
};
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::net::UnixListener;
use tokio::sync::{broadcast, mpsc, watch};

use crate::frame::{FrameError, read_frame, write_frame};
use crate::service::ControlService;

/// Per-connection outbound queue capacity (responses + forwarded events).
const OUTBOUND_CAPACITY: usize = 256;

/// Errors that terminate a connection.
#[derive(Debug, thiserror::Error)]
pub enum ConnError {
    /// Failed to encode a server message.
    #[error("encode error: {0}")]
    Encode(serde_json::Error),
    /// A framing/transport error.
    #[error(transparent)]
    Frame(FrameError),
}

async fn write_message<W: AsyncWrite + Unpin>(
    writer: &mut W,
    message: &ServerMessage,
    max_frame_bytes: u32,
) -> Result<(), ConnError> {
    let body = serde_json::to_vec(message).map_err(ConnError::Encode)?;
    write_frame(writer, &body, max_frame_bytes)
        .await
        .map_err(ConnError::Frame)
}

/// Best-effort extraction of a `requestId` from an unparseable request body, so even malformed
/// requests get a correlated error response.
fn salvage_request_id(body: &[u8]) -> RequestId {
    serde_json::from_slice::<serde_json::Value>(body)
        .ok()
        .and_then(|v| {
            v.get("requestId")
                .and_then(serde_json::Value::as_str)
                .map(RequestId::new)
        })
        .unwrap_or_else(|| RequestId::new("unknown"))
}

/// Turn a received frame body into either a request to dispatch or an immediate error response.
/// The error response is boxed because it is far larger than the request handle.
fn decode_request(body: &[u8]) -> Result<sealant_protocol::ControlRequest, Box<ControlResponse>> {
    match serde_json::from_slice::<ClientMessage>(body) {
        Ok(ClientMessage::Request(request)) => {
            if request.schema_version != SCHEMA_VERSION {
                return Err(Box::new(ControlResponse::error(
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
            Ok(request)
        }
        Err(e) => Err(Box::new(ControlResponse::error(
            salvage_request_id(body),
            ControlError::invalid_json(e.to_string()),
        ))),
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
                        let response = match decode_request(&body) {
                            Ok(request) => service.handle(request).await,
                            Err(error_response) => *error_response,
                        };
                        if out_tx.send(ServerMessage::Response(response)).await.is_err() {
                            break;
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

    // Tear down: dropping out_tx + aborting the forwarder closes the outbound queue so the writer
    // drains and exits.
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

/// Bind the Unix control socket (mode `0600`) and serve connections until shutdown is signalled.
///
/// # Errors
/// Returns an I/O error if the socket cannot be prepared or bound.
pub async fn serve_unix<S: ControlService>(
    service: Arc<S>,
    path: &Path,
    mut shutdown: watch::Receiver<bool>,
) -> std::io::Result<()> {
    prepare_socket_path(path)?;
    let listener = UnixListener::bind(path)?;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))?;
    tracing::info!(socket = %path.display(), "control socket listening");

    loop {
        tokio::select! {
            changed = shutdown.changed() => {
                if changed.is_err() || *shutdown.borrow() {
                    break;
                }
            }
            accepted = listener.accept() => {
                match accepted {
                    Ok((stream, _addr)) => {
                        let service = service.clone();
                        let shutdown = shutdown.clone();
                        let (read_half, write_half) = stream.into_split();
                        tokio::spawn(async move {
                            handle_connection(service, read_half, write_half, shutdown).await;
                        });
                    }
                    Err(e) => tracing::warn!(error = %e, "accept failed"),
                }
            }
        }
    }

    let _ = std::fs::remove_file(path);
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
        CaptureMethod, Command, CommandResult, Confidence, ControlRequest, EventEnvelope, EventId,
        EventPayload, MonotonicNanos, RuntimeHeartbeat, RuntimeId, RuntimeState, Sequence,
        WallClockMicros,
    };

    struct MockService {
        events: broadcast::Sender<EventEnvelope>,
    }

    impl ControlService for MockService {
        async fn handle(&self, request: ControlRequest) -> ControlResponse {
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
        let msg = ClientMessage::Request(request);
        let body = serde_json::to_vec(&msg).expect("ser");
        write_frame(&mut client, &body, 64 * 1024)
            .await
            .expect("write");

        // Read the response.
        let resp_body = read_frame(&mut client, 64 * 1024)
            .await
            .expect("read")
            .expect("some");
        let resp: ServerMessage = serde_json::from_slice(&resp_body).expect("de");
        match resp {
            ServerMessage::Response(r) => {
                assert_eq!(r.request_id, RequestId::new("req_1"));
                assert!(r.is_ok());
            }
            ServerMessage::Event(_) => panic!("expected response first"),
        }

        // Publish a telemetry event; it should arrive on the connection.
        events_tx.send(heartbeat(7)).expect("broadcast");
        let evt_body = read_frame(&mut client, 64 * 1024)
            .await
            .expect("read")
            .expect("some");
        let evt: ServerMessage = serde_json::from_slice(&evt_body).expect("de");
        match evt {
            ServerMessage::Event(e) => assert_eq!(e.sequence, Sequence(7)),
            ServerMessage::Response(_) => panic!("expected event"),
        }

        drop(client);
        let _ = conn.await;
    }

    #[tokio::test]
    async fn malformed_json_gets_correlated_error() {
        let (events_tx, _) = broadcast::channel(16);
        let service = Arc::new(MockService { events: events_tx });
        let (_sd_tx, sd_rx) = watch::channel(false);
        let (mut client, server) = tokio::io::duplex(4096);
        let (server_read, server_write) = tokio::io::split(server);
        let conn = tokio::spawn(handle_connection(service, server_read, server_write, sd_rx));

        // Not valid ClientMessage JSON, but carries a requestId we should salvage.
        let body = br#"{"kind":"request","requestId":"req_bad","garbage":true}"#;
        write_frame(&mut client, body, 4096).await.expect("write");

        let resp_body = read_frame(&mut client, 4096)
            .await
            .expect("read")
            .expect("some");
        let resp: ServerMessage = serde_json::from_slice(&resp_body).expect("de");
        match resp {
            ServerMessage::Response(r) => {
                assert_eq!(r.request_id, RequestId::new("req_bad"));
                assert!(!r.is_ok());
            }
            ServerMessage::Event(_) => panic!("expected error response"),
        }
        drop(client);
        let _ = conn.await;
    }
}
