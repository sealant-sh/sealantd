//! End-to-end Phase 1 acceptance tests.
//!
//! `in_process_*` drives the real [`Runtime`] over an in-memory duplex via the control server.
//! `binary_stdio_*` spawns the actual `sealantd` binary in `--stdio` mode and drives it over real
//! pipes, proving the binary wiring and that protocol output never mixes with diagnostics.

use std::process::Stdio;
use std::sync::Arc;
use std::time::Duration;

use sealant_control::{handle_connection, read_frame, write_frame};
use sealant_protocol::{
    AttachMode, AttachSessionArgs, ChannelId, ClientMessage, Command, CommandResult,
    ControlRequest, EventPayload, ExecArgs, Feature, OpenForwardArgs, OpenSessionArgs, RequestId,
    ResponseOutcome, ServerMessage, StreamFrame, StreamKind, StreamPayload,
};
use sealant_runtime_core::{RuntimeConfig, new_runtime_id};
use sealantd::Runtime;
use sealantd::shutdown::ShutdownSignal;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::sync::watch;

const MAX: u32 = 8 * 1024 * 1024;

fn exec_args(executable: &str, args: &[&str]) -> ExecArgs {
    ExecArgs {
        execution_id: None,
        session_id: None,
        executable: executable.to_owned(),
        args: args.iter().map(|s| (*s).to_owned()).collect(),
        cwd: None,
        env: vec![],
        stdin: false,
        attach: false,
        timeout_millis: None,
        background: false,
        capture: None,
        graceful_signal: None,
    }
}

async fn send_request<W: AsyncWrite + Unpin>(writer: &mut W, request: ControlRequest) {
    let body = sealant_protocol::encode_client(&ClientMessage::Request(request));
    write_frame(writer, &body, MAX).await.expect("write frame");
}

async fn recv_message<R: AsyncRead + Unpin>(reader: &mut R) -> ServerMessage {
    let body = read_frame(reader, MAX)
        .await
        .expect("read frame")
        .expect("frame present");
    sealant_protocol::decode_server(&body).expect("decode server message")
}

#[tokio::test]
async fn in_process_exec_streams_events_and_reports_exit() {
    let mut config = RuntimeConfig::new(new_runtime_id());
    config.workspace_root = std::env::temp_dir();
    let runtime = Runtime::new(config, Arc::new(ShutdownSignal::new(1000)));
    runtime.mark_healthy();

    let (_sd_tx, sd_rx) = watch::channel(false);
    let (mut client, server) = tokio::io::duplex(1 << 20);
    let (server_read, server_write) = tokio::io::split(server);
    let conn = tokio::spawn(handle_connection(
        runtime.clone(),
        server_read,
        server_write,
        sd_rx,
    ));

    // Health check first.
    send_request(
        &mut client,
        ControlRequest::new(RequestId::new("r1"), Command::RuntimeHealth),
    )
    .await;
    match recv_message(&mut client).await {
        ServerMessage::Response(r) => {
            assert_eq!(r.request_id, RequestId::new("r1"));
            assert!(r.is_ok());
        }
        other => panic!("expected health response, got {other:?}"),
    }

    // Exec a command and stream its lifecycle.
    send_request(
        &mut client,
        ControlRequest::new(
            RequestId::new("r2"),
            Command::Exec(exec_args("/bin/echo", &["hello"])),
        ),
    )
    .await;

    let mut accepted = false;
    let mut stdout = Vec::new();
    let mut exit_code = None;
    let collect = async {
        loop {
            match recv_message(&mut client).await {
                ServerMessage::Response(r) if r.request_id == RequestId::new("r2") => {
                    if let ResponseOutcome::Ok {
                        result: Some(CommandResult::ExecAccepted(_)),
                    } = r.outcome
                    {
                        accepted = true;
                    }
                }
                ServerMessage::Event(e) => match e.payload {
                    EventPayload::IoChunk(chunk) if chunk.stream == StreamKind::Stdout => {
                        if let Some(content) = chunk.content {
                            stdout.extend_from_slice(content.as_slice());
                        }
                    }
                    EventPayload::ProcessExited(p) => {
                        exit_code = p.exit_code;
                        break;
                    }
                    _ => {}
                },
                ServerMessage::Response(_) | ServerMessage::Stream(_) => {}
            }
        }
    };
    tokio::time::timeout(Duration::from_secs(10), collect)
        .await
        .expect("did not hang");

    assert!(accepted, "exec should be acknowledged");
    assert_eq!(stdout, b"hello\n");
    assert_eq!(exit_code, Some(0));

    // Graceful shutdown via command.
    send_request(
        &mut client,
        ControlRequest::new(
            RequestId::new("r3"),
            Command::RuntimeGracefulShutdown {
                grace_millis: Some(200),
            },
        ),
    )
    .await;
    let drain = async {
        loop {
            if let ServerMessage::Response(r) = recv_message(&mut client).await
                && r.request_id == RequestId::new("r3")
            {
                assert!(r.is_ok());
                break;
            }
        }
    };
    tokio::time::timeout(Duration::from_secs(5), drain)
        .await
        .expect("shutdown ack");

    drop(client);
    let _ = tokio::time::timeout(Duration::from_secs(5), conn).await;
}

#[tokio::test]
async fn binary_stdio_roundtrips_binary_unsafe_output_and_shuts_down() {
    let exe = env!("CARGO_BIN_EXE_sealantd");
    let mut child = tokio::process::Command::new(exe)
        .arg("--stdio")
        .arg("--workspace")
        .arg(std::env::temp_dir())
        .arg("--log-level")
        .arg("off")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .expect("spawn sealantd");

    let mut stdin = child.stdin.take().expect("stdin");
    let mut stdout = child.stdout.take().expect("stdout");

    // Emit bytes including NUL and a high byte; assert exact binary round-trip.
    send_request(
        &mut stdin,
        ControlRequest::new(
            RequestId::new("r1"),
            Command::Exec(exec_args("/bin/sh", &["-c", r"printf 'x\000y\377z'"])),
        ),
    )
    .await;

    let mut bytes = Vec::new();
    let mut exit_code = None;
    let collect = async {
        loop {
            match recv_message(&mut stdout).await {
                ServerMessage::Event(e) => match e.payload {
                    EventPayload::IoChunk(chunk) if chunk.stream == StreamKind::Stdout => {
                        if let Some(content) = chunk.content {
                            bytes.extend_from_slice(content.as_slice());
                        }
                    }
                    EventPayload::ProcessExited(p) => {
                        exit_code = p.exit_code;
                        break;
                    }
                    _ => {}
                },
                ServerMessage::Response(_) | ServerMessage::Stream(_) => {}
            }
        }
    };
    tokio::time::timeout(Duration::from_secs(10), collect)
        .await
        .expect("did not hang");

    assert_eq!(bytes, vec![b'x', 0x00, b'y', 0xff, b'z']);
    assert_eq!(exit_code, Some(0));

    // Closing stdin ends the stdio session, which triggers a graceful shutdown.
    drop(stdin);
    let status = tokio::time::timeout(Duration::from_secs(10), child.wait())
        .await
        .expect("daemon exits")
        .expect("wait");
    assert!(status.success());
}

async fn read_pty_until<R: AsyncRead + Unpin>(reader: &mut R, needle: &str) -> bool {
    let mut acc = String::new();
    let scan = async {
        loop {
            if let ServerMessage::Event(e) = recv_message(reader).await
                && let EventPayload::IoChunk(c) = &e.payload
                && c.stream == StreamKind::PtyOutput
                && let Some(content) = &c.content
            {
                acc.push_str(&String::from_utf8_lossy(content.as_slice()));
                if acc.contains(needle) {
                    return true;
                }
            }
        }
    };
    tokio::time::timeout(Duration::from_secs(8), scan)
        .await
        .unwrap_or(false)
}

#[tokio::test]
async fn in_process_session_open_write_resize_close() {
    let mut config = RuntimeConfig::new(new_runtime_id());
    config.workspace_root = std::env::temp_dir();
    config.default_shell = "/bin/sh".to_owned();
    let runtime = Runtime::new(config, Arc::new(ShutdownSignal::new(1000)));
    runtime.mark_healthy();

    let (_sd_tx, sd_rx) = watch::channel(false);
    let (mut client, server) = tokio::io::duplex(1 << 20);
    let (server_read, server_write) = tokio::io::split(server);
    let conn = tokio::spawn(handle_connection(
        runtime.clone(),
        server_read,
        server_write,
        sd_rx,
    ));

    // Open an interactive session.
    send_request(
        &mut client,
        ControlRequest::new(
            RequestId::new("s1"),
            Command::OpenSession(sealant_protocol::OpenSessionArgs {
                execution_id: None,
                shell: None,
                args: vec![],
                cwd: None,
                env: vec![],
                cols: 80,
                rows: 24,
                term: None,
            }),
        ),
    )
    .await;
    let session_id = {
        let find = async {
            loop {
                if let ServerMessage::Response(r) = recv_message(&mut client).await
                    && r.request_id == RequestId::new("s1")
                {
                    match r.outcome {
                        ResponseOutcome::Ok {
                            result: Some(CommandResult::SessionOpened(s)),
                        } => return s.session_id,
                        other => panic!("expected SessionOpened, got {other:?}"),
                    }
                }
            }
        };
        tokio::time::timeout(Duration::from_secs(5), find)
            .await
            .expect("session opened")
    };

    let type_line = |id: sealant_protocol::SessionId| {
        Command::WriteStdin(sealant_protocol::WriteStdinArgs {
            process_id: None,
            session_id: Some(id),
            data: sealant_protocol::Base64Bytes::new(b"stty size\n".to_vec()),
        })
    };

    send_request(
        &mut client,
        ControlRequest::new(RequestId::new("s2"), type_line(session_id.clone())),
    )
    .await;
    assert!(read_pty_until(&mut client, "24 80").await, "initial size");

    // Resize and confirm the session sees the new dimensions.
    send_request(
        &mut client,
        ControlRequest::new(
            RequestId::new("s3"),
            Command::ResizePty {
                session_id: session_id.clone(),
                cols: 132,
                rows: 50,
            },
        ),
    )
    .await;
    send_request(
        &mut client,
        ControlRequest::new(RequestId::new("s4"), type_line(session_id.clone())),
    )
    .await;
    assert!(read_pty_until(&mut client, "50 132").await, "resized size");

    // Close the session.
    send_request(
        &mut client,
        ControlRequest::new(
            RequestId::new("s5"),
            Command::CloseSession {
                session_id: session_id.clone(),
            },
        ),
    )
    .await;

    drop(client);
    let _ = tokio::time::timeout(Duration::from_secs(5), conn).await;
}

// ===================== gateway consolidation (§0 / §1.A / §1.B) =====================

/// Send a raw inbound stream frame from the "gateway" to the daemon.
async fn send_stream<W: AsyncWrite + Unpin>(writer: &mut W, frame: StreamFrame) {
    let body = sealant_protocol::encode_client(&ClientMessage::Stream(frame));
    write_frame(writer, &body, MAX)
        .await
        .expect("write stream frame");
}

/// Drive a real Runtime over the control server and return (client, conn join handle).
fn wire_runtime(runtime: Arc<Runtime>) -> (tokio::io::DuplexStream, tokio::task::JoinHandle<()>) {
    let (_sd_tx, sd_rx) = watch::channel(false);
    // Leak the shutdown sender so it lives for the connection (test-only).
    std::mem::forget(_sd_tx);
    let (client, server) = tokio::io::duplex(1 << 20);
    let (server_read, server_write) = tokio::io::split(server);
    let conn = tokio::spawn(handle_connection(runtime, server_read, server_write, sd_rx));
    (client, conn)
}

async fn open_session(
    client: &mut tokio::io::DuplexStream,
    rid: &str,
) -> sealant_protocol::SessionId {
    send_request(
        client,
        ControlRequest::new(
            RequestId::new(rid),
            Command::OpenSession(OpenSessionArgs {
                execution_id: None,
                shell: Some("/bin/sh".to_owned()),
                args: vec![],
                cwd: None,
                env: vec![],
                cols: 80,
                rows: 24,
                term: None,
            }),
        ),
    )
    .await;
    let want = RequestId::new(rid);
    let find = async {
        loop {
            if let ServerMessage::Response(r) = recv_message(client).await
                && r.request_id == want
                && let ResponseOutcome::Ok {
                    result: Some(CommandResult::SessionOpened(s)),
                } = r.outcome
            {
                return s.session_id;
            }
        }
    };
    tokio::time::timeout(Duration::from_secs(5), find)
        .await
        .expect("session opened")
}

/// §1.A end-to-end over the control socket: openSession → attachSession → reliable StreamFrame::Data
/// carrying PTY output (distinct from the IoChunk telemetry) → StreamEnd on leader exit.
#[tokio::test]
async fn in_process_attach_streams_pty_output_over_channel() {
    let mut config = RuntimeConfig::new(new_runtime_id());
    config.workspace_root = std::env::temp_dir();
    config.default_shell = "/bin/sh".to_owned();
    let runtime = Runtime::new(config, Arc::new(ShutdownSignal::new(1000)));
    runtime.mark_healthy();
    let (mut client, conn) = wire_runtime(runtime.clone());

    let session_id = open_session(&mut client, "o1").await;

    // Attach.
    send_request(
        &mut client,
        ControlRequest::new(
            RequestId::new("a1"),
            Command::AttachSession(AttachSessionArgs {
                session_id: session_id.clone(),
                mode: AttachMode::Interactive,
            }),
        ),
    )
    .await;
    let channel = {
        let find = async {
            loop {
                if let ServerMessage::Response(r) = recv_message(&mut client).await
                    && r.request_id == RequestId::new("a1")
                    && let ResponseOutcome::Ok {
                        result: Some(CommandResult::StreamAttached(s)),
                    } = r.outcome
                {
                    return s.channel_id;
                }
            }
        };
        tokio::time::timeout(Duration::from_secs(5), find)
            .await
            .expect("attached")
    };

    // Type a command into the PTY via writeStdin; its echoed output must arrive on the channel.
    send_request(
        &mut client,
        ControlRequest::new(
            RequestId::new("w1"),
            Command::WriteStdin(sealant_protocol::WriteStdinArgs {
                process_id: None,
                session_id: Some(session_id.clone()),
                data: sealant_protocol::Base64Bytes::new(b"echo CHANNEL_MARKER\n".to_vec()),
            }),
        ),
    )
    .await;

    // Read StreamFrame::Data frames on the attach channel until the marker appears.
    let mut acc = String::new();
    let scan = async {
        loop {
            if let ServerMessage::Stream(frame) = recv_message(&mut client).await
                && frame.channel_id == channel
                && let StreamPayload::Data { data } = frame.payload
            {
                acc.push_str(&String::from_utf8_lossy(data.as_slice()));
                if acc.contains("CHANNEL_MARKER") {
                    return true;
                }
            }
        }
    };
    assert!(
        tokio::time::timeout(Duration::from_secs(8), scan)
            .await
            .unwrap_or(false),
        "attach channel should carry PTY output; got {acc:?}"
    );

    drop(client);
    let _ = tokio::time::timeout(Duration::from_secs(5), conn).await;
}

/// §1.B end-to-end: openForward to a loopback echo server, pump bytes both ways over the channel.
#[tokio::test]
async fn in_process_open_forward_loopback_echo() {
    // Loopback echo server.
    let listener = tokio::net::TcpListener::bind(("127.0.0.1", 0))
        .await
        .expect("bind echo");
    let addr = listener.local_addr().expect("addr");
    tokio::spawn(async move {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
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

    let mut config = RuntimeConfig::new(new_runtime_id());
    config.workspace_root = std::env::temp_dir();
    let runtime = Runtime::new(config, Arc::new(ShutdownSignal::new(1000)));
    runtime.mark_healthy();
    let (mut client, conn) = wire_runtime(runtime.clone());

    // Forwarding is a gateway transport primitive, NOT gated on networkCollection telemetry — no
    // feature toggle here. (The default feature matrix leaves networkCollection OFF.)

    // Open the forward.
    send_request(
        &mut client,
        ControlRequest::new(
            RequestId::new("f1"),
            Command::OpenForward(OpenForwardArgs {
                host: "127.0.0.1".to_owned(),
                port: addr.port(),
                execution_id: None,
            }),
        ),
    )
    .await;
    let channel = {
        let find = async {
            loop {
                if let ServerMessage::Response(r) = recv_message(&mut client).await
                    && r.request_id == RequestId::new("f1")
                    && let ResponseOutcome::Ok {
                        result: Some(CommandResult::ForwardOpened(f)),
                    } = r.outcome
                {
                    return f.channel_id;
                }
            }
        };
        tokio::time::timeout(Duration::from_secs(5), find)
            .await
            .expect("forward opened")
    };

    // Send bytes inbound (gateway → socket); the echo must come back as StreamFrame::Data.
    send_stream(
        &mut client,
        StreamFrame::data(channel.clone(), 0, b"PINGPONG".to_vec()),
    )
    .await;

    let mut got = Vec::new();
    let scan = async {
        loop {
            if let ServerMessage::Stream(frame) = recv_message(&mut client).await
                && frame.channel_id == channel
                && let StreamPayload::Data { data } = frame.payload
            {
                got.extend_from_slice(data.as_slice());
                if got.len() >= 8 {
                    return true;
                }
            }
        }
    };
    assert!(
        tokio::time::timeout(Duration::from_secs(8), scan)
            .await
            .unwrap_or(false),
        "forward should echo bytes; got {got:?}"
    );
    assert_eq!(&got, b"PINGPONG");

    drop(client);
    let _ = tokio::time::timeout(Duration::from_secs(5), conn).await;
}

/// §1.B transport/telemetry decoupling: openForward must be ALLOWED even with the networkCollection
/// telemetry feature off (the default). Forwarding is the gateway's direct-tcpip substrate, not a
/// network-capture concern — so a tunnel may be opened regardless of that kill switch.
#[tokio::test]
async fn in_process_open_forward_allowed_when_feature_off() {
    // A loopback listener so the forward has a real upstream to connect to.
    let listener = tokio::net::TcpListener::bind(("127.0.0.1", 0))
        .await
        .expect("bind upstream");
    let addr = listener.local_addr().expect("addr");
    tokio::spawn(async move {
        // Accept once so the connect succeeds, then idle.
        let _ = listener.accept().await;
        std::future::pending::<()>().await;
    });

    let mut config = RuntimeConfig::new(new_runtime_id());
    config.workspace_root = std::env::temp_dir();
    // The default feature matrix leaves networkCollection OFF (see `default_feature_states`), so we
    // make NO SetFeatureState call here: a successful openForward proves the decoupling.
    let runtime = Runtime::new(config, Arc::new(ShutdownSignal::new(1000)));
    runtime.mark_healthy();
    let (mut client, conn) = wire_runtime(runtime.clone());

    send_request(
        &mut client,
        ControlRequest::new(
            RequestId::new("d1"),
            Command::OpenForward(OpenForwardArgs {
                host: "127.0.0.1".to_owned(),
                port: addr.port(),
                execution_id: None,
            }),
        ),
    )
    .await;
    let response = async {
        loop {
            if let ServerMessage::Response(r) = recv_message(&mut client).await
                && r.request_id == RequestId::new("d1")
            {
                return r;
            }
        }
    };
    let r = tokio::time::timeout(Duration::from_secs(5), response)
        .await
        .expect("response");
    match r.outcome {
        ResponseOutcome::Ok {
            result: Some(CommandResult::ForwardOpened(_)),
        } => {}
        other => panic!("expected ForwardOpened with networkCollection off, got {other:?}"),
    }

    drop(client);
    let _ = tokio::time::timeout(Duration::from_secs(5), conn).await;
}

/// §0.3 connection-scoped teardown: when the gateway connection drops, the daemon tears down all its
/// channels (the attach reader stops). We assert the session's attachment is cleared after the
/// connection closes — proving channels die with their connection.
#[tokio::test]
async fn in_process_connection_drop_tears_down_attachment() {
    let mut config = RuntimeConfig::new(new_runtime_id());
    config.workspace_root = std::env::temp_dir();
    config.default_shell = "/bin/sh".to_owned();
    let runtime = Runtime::new(config, Arc::new(ShutdownSignal::new(1000)));
    runtime.mark_healthy();
    let (mut client, conn) = wire_runtime(runtime.clone());

    // Open a long-lived session and attach to it.
    let session_id = open_session(&mut client, "t1").await;
    send_request(
        &mut client,
        ControlRequest::new(
            RequestId::new("t2"),
            Command::WriteStdin(sealant_protocol::WriteStdinArgs {
                process_id: None,
                session_id: Some(session_id.clone()),
                data: sealant_protocol::Base64Bytes::new(b"sleep 30\n".to_vec()),
            }),
        ),
    )
    .await;
    send_request(
        &mut client,
        ControlRequest::new(
            RequestId::new("t3"),
            Command::AttachSession(AttachSessionArgs {
                session_id: session_id.clone(),
                mode: AttachMode::Interactive,
            }),
        ),
    )
    .await;
    let _channel: ChannelId = {
        let find = async {
            loop {
                if let ServerMessage::Response(r) = recv_message(&mut client).await
                    && r.request_id == RequestId::new("t3")
                    && let ResponseOutcome::Ok {
                        result: Some(CommandResult::StreamAttached(s)),
                    } = r.outcome
                {
                    return s.channel_id;
                }
            }
        };
        tokio::time::timeout(Duration::from_secs(5), find)
            .await
            .expect("attached")
    };

    // Drop the connection: handle_connection must return, having torn down the connection's
    // channels (its out_tx clones are gone). The capture loop then observes a closed attach sink and
    // clears the attachment on its next chunk; force a chunk by typing into the PTY before drop.
    send_request(
        &mut client,
        ControlRequest::new(
            RequestId::new("t4"),
            Command::WriteStdin(sealant_protocol::WriteStdinArgs {
                process_id: None,
                session_id: Some(session_id.clone()),
                data: sealant_protocol::Base64Bytes::new(b"echo X\n".to_vec()),
            }),
        ),
    )
    .await;
    drop(client);
    tokio::time::timeout(Duration::from_secs(5), conn)
        .await
        .expect("handle_connection returns after gateway disconnect")
        .expect("join");

    // The control server cleared the connection's channel registry on teardown; once the capture
    // loop pushes a chunk to the now-closed attach sink, it clears the session attachment. Drive a
    // little more output and poll for the attachment to clear.
    use sealant_protocol::SessionId;
    let session_id: SessionId = session_id;
    let mut cleared = false;
    for _ in 0..100 {
        // Use the runtime's own session input path to keep producing output.
        let _ = runtime
            .session_runtime()
            .write_input(&session_id, b"echo Y\n")
            .await;
        if runtime.session_runtime().attachment_is_clear(&session_id) {
            cleared = true;
            break;
        }
        tokio::time::sleep(Duration::from_millis(30)).await;
    }
    assert!(
        cleared,
        "attachment should clear after the gateway connection drops"
    );
}

/// §0.3 BLOCKER — eager teardown of an IDLE forward. The old teardown only dropped inbound sinks;
/// an idle upstream that never writes leaves the socket→gateway pump blocked on read() forever
/// (it never calls out_tx.send, so never observes the closed queue), leaking the task, the socket
/// FD, and the un-reaped ForwardRuntime map entry per disconnect. This test opens a forward to an
/// upstream that accepts but NEVER writes, drops the control connection, and asserts:
///   1. handle_connection returns promptly (no hang, bounded),
///   2. the ForwardRuntime map entry is removed (the eager closer ran), and
///   3. the upstream socket is closed (the read pump was aborted, dropping the TcpStream → the
///      upstream's read() returns 0/EOF), proving the FD was reaped.
#[tokio::test]
async fn in_process_idle_forward_torn_down_on_connection_drop() {
    use tokio::io::AsyncReadExt;

    // Upstream that accepts one connection and NEVER writes — it only waits to observe its peer
    // close. This is the VSCode-Server idle steady state (an open forward with no traffic).
    let listener = tokio::net::TcpListener::bind(("127.0.0.1", 0))
        .await
        .expect("bind idle upstream");
    let addr = listener.local_addr().expect("addr");
    let (peer_closed_tx, peer_closed_rx) = tokio::sync::oneshot::channel::<()>();
    tokio::spawn(async move {
        let (mut s, _) = listener.accept().await.expect("accept");
        // Block reading; the daemon never sends anything either. When the daemon aborts its pumps,
        // its TcpStream drops and our read returns 0 (EOF) — the proof the FD was closed.
        let mut b = [0u8; 64];
        let n = s.read(&mut b).await.unwrap_or(0);
        assert_eq!(n, 0, "idle upstream should only ever see EOF, never bytes");
        let _ = peer_closed_tx.send(());
    });

    let mut config = RuntimeConfig::new(new_runtime_id());
    config.workspace_root = std::env::temp_dir();
    let runtime = Runtime::new(config, Arc::new(ShutdownSignal::new(1000)));
    runtime.mark_healthy();
    let (mut client, conn) = wire_runtime(runtime.clone());

    // Enable forwarding (gated behind networkCollection).
    send_request(
        &mut client,
        ControlRequest::new(
            RequestId::new("g0"),
            Command::SetFeatureState {
                feature: Feature::NetworkCollection,
                enabled: true,
            },
        ),
    )
    .await;
    loop {
        if let ServerMessage::Response(r) = recv_message(&mut client).await
            && r.request_id == RequestId::new("g0")
        {
            assert!(r.is_ok());
            break;
        }
    }

    // Open the forward to the idle upstream.
    send_request(
        &mut client,
        ControlRequest::new(
            RequestId::new("g1"),
            Command::OpenForward(OpenForwardArgs {
                host: "127.0.0.1".to_owned(),
                port: addr.port(),
                execution_id: None,
            }),
        ),
    )
    .await;
    let _channel: ChannelId = {
        let find = async {
            loop {
                if let ServerMessage::Response(r) = recv_message(&mut client).await
                    && r.request_id == RequestId::new("g1")
                    && let ResponseOutcome::Ok {
                        result: Some(CommandResult::ForwardOpened(f)),
                    } = r.outcome
                {
                    return f.channel_id;
                }
            }
        };
        tokio::time::timeout(Duration::from_secs(5), find)
            .await
            .expect("forward opened")
    };
    assert_eq!(runtime.forward_count(), 1, "forward should be registered");

    // Drop the control connection. The eager closer must abort BOTH pumps (including the idle,
    // read-blocked socket→gateway pump) and reap the ForwardRuntime map entry.
    drop(client);
    tokio::time::timeout(Duration::from_secs(5), conn)
        .await
        .expect("handle_connection must return promptly (no hang)")
        .expect("join");

    // (2) Map entry removed — no per-disconnect leak.
    let mut reaped = false;
    for _ in 0..100 {
        if runtime.forward_count() == 0 {
            reaped = true;
            break;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    assert!(
        reaped,
        "ForwardRuntime map entry must be removed on connection teardown"
    );

    // (3) Socket/FD closed — the upstream observed EOF, which only happens once the daemon's
    // TcpStream (both pump halves) is dropped by the abort.
    tokio::time::timeout(Duration::from_secs(5), peer_closed_rx)
        .await
        .expect("upstream must see EOF (socket FD closed by the aborted pump)")
        .expect("peer-closed signal");
}

/// §1.A exec-attach: run a command that emits a LARGE burst, attach via `exec{attach:true}`, and
/// assert lossless ordered delivery over the StreamFrame channel + End{exit_code}. Confirms it runs
/// alongside the unchanged IoChunk telemetry (both carry the full output).
#[tokio::test]
async fn in_process_exec_attach_streams_burst_losslessly_with_exit_code() {
    let mut config = RuntimeConfig::new(new_runtime_id());
    config.workspace_root = std::env::temp_dir();
    let runtime = Runtime::new(config, Arc::new(ShutdownSignal::new(1000)));
    runtime.mark_healthy();

    // Subscribe to telemetry BEFORE spawning so we can prove the IoChunk tap still sees the output.
    // Drain it in a CONCURRENT task: the attach channel is consumed slowly (to exercise
    // backpressure), so a non-draining telemetry subscriber would lag (broadcast overflow) and lose
    // chunks. Draining in parallel proves the always-on IoChunk tap carries the full output
    // independently of the attach stream's pacing.
    let mut telemetry = runtime.event_subscriber();
    let telemetry_task = tokio::spawn(async move {
        let mut tele = String::new();
        loop {
            match telemetry.recv().await {
                Ok(env) => match env.payload {
                    EventPayload::IoChunk(c) if c.stream == StreamKind::Stdout => {
                        if let Some(content) = c.content {
                            tele.push_str(&String::from_utf8_lossy(content.as_slice()));
                        }
                    }
                    EventPayload::ProcessExited(_) => break,
                    _ => {}
                },
                // A real lag would mean the tap lost data; surface it rather than silently passing.
                Err(tokio::sync::broadcast::error::RecvError::Lagged(n)) => {
                    panic!("telemetry subscriber lagged ({n} dropped) — tap lost data");
                }
                Err(tokio::sync::broadcast::error::RecvError::Closed) => break,
            }
        }
        tele
    });

    let (mut client, conn) = wire_runtime(runtime.clone());

    // A large, verifiable burst: 20000 numbered lines on stdout. The attach channel must deliver
    // every line in order despite our slow draining (backpressure), with a non-zero exit code.
    let script = "i=0; while [ $i -lt 20000 ]; do echo $i; i=$((i+1)); done; exit 3";
    let mut args = exec_args("/bin/sh", &["-c", script]);
    args.attach = true;

    send_request(
        &mut client,
        ControlRequest::new(RequestId::new("e1"), Command::Exec(args)),
    )
    .await;

    // The exec-attach result carries both the process id and the channel.
    let channel = {
        let find = async {
            loop {
                if let ServerMessage::Response(r) = recv_message(&mut client).await
                    && r.request_id == RequestId::new("e1")
                {
                    match r.outcome {
                        ResponseOutcome::Ok {
                            result: Some(CommandResult::ProcessAttached(p)),
                        } => return p.channel_id,
                        other => panic!("expected ProcessAttached, got {other:?}"),
                    }
                }
            }
        };
        tokio::time::timeout(Duration::from_secs(5), find)
            .await
            .expect("process attached")
    };

    // Drain the attach channel slowly; assert per-channel seq monotonicity (drop detection) and
    // reassemble every line, then read End{exit_code}.
    let mut out = Vec::new();
    let mut last_seq: Option<u64> = None;
    let mut exit_code = None;
    let mut count = 0u64;
    let collect = async {
        loop {
            if let ServerMessage::Stream(frame) = recv_message(&mut client).await
                && frame.channel_id == channel
            {
                match frame.payload {
                    StreamPayload::Data { data } => {
                        if let Some(prev) = last_seq {
                            assert_eq!(frame.seq, prev + 1, "seq gap: exec-attach dropped a frame");
                        }
                        last_seq = Some(frame.seq);
                        out.extend_from_slice(data.as_slice());
                        count += 1;
                        if count.is_multiple_of(11) {
                            tokio::time::sleep(Duration::from_millis(1)).await;
                        }
                    }
                    StreamPayload::End(end) => {
                        exit_code = Some(end.exit_code);
                        break;
                    }
                    StreamPayload::WindowUpdate { .. } => {}
                }
            }
        }
    };
    tokio::time::timeout(Duration::from_secs(30), collect)
        .await
        .expect("exec-attach delivers all output then End without hanging");

    // Lossless + ordered: every line 0..20000 present in order.
    let text = String::from_utf8_lossy(&out);
    let numbers: Vec<u64> = text
        .split_whitespace()
        .filter_map(|s| s.parse::<u64>().ok())
        .collect();
    assert_eq!(numbers.len(), 20000, "expected 20000 lines on the channel");
    for (idx, &n) in numbers.iter().enumerate() {
        assert_eq!(
            n, idx as u64,
            "out-of-order/missing exec-attach line at {idx}"
        );
    }
    assert_eq!(
        exit_code,
        Some(Some(3)),
        "End must carry the process exit code"
    );

    // The IoChunk telemetry tap must ALSO have carried the same output in parallel (proving the
    // attach is a distinct, additional path — not a replacement for the always-on telemetry).
    let tele = tokio::time::timeout(Duration::from_secs(10), telemetry_task)
        .await
        .expect("telemetry task should finish")
        .expect("telemetry task join");
    let tele_numbers = tele.split_whitespace().filter(|s| !s.is_empty()).count();
    assert_eq!(
        tele_numbers, 20000,
        "IoChunk telemetry must still carry the full output in parallel"
    );

    drop(client);
    let _ = tokio::time::timeout(Duration::from_secs(5), conn).await;
}
