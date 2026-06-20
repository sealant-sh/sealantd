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
    ClientMessage, Command, CommandResult, ControlRequest, EventPayload, ExecArgs, RequestId,
    ResponseOutcome, ServerMessage, StreamKind,
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
        timeout_millis: None,
        background: false,
        capture: None,
        graceful_signal: None,
    }
}

async fn send_request<W: AsyncWrite + Unpin>(writer: &mut W, request: ControlRequest) {
    let body = serde_json::to_vec(&ClientMessage::Request(request)).expect("encode request");
    write_frame(writer, &body, MAX).await.expect("write frame");
}

async fn recv_message<R: AsyncRead + Unpin>(reader: &mut R) -> ServerMessage {
    let body = read_frame(reader, MAX)
        .await
        .expect("read frame")
        .expect("frame present");
    serde_json::from_slice(&body).expect("decode server message")
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
                ServerMessage::Response(_) => {}
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
                ServerMessage::Response(_) => {}
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
