//! The real daemon joins a caller's trace and exports it, and a canary in a request's arguments,
//! its environment, its secret environment, the process's output and the daemon's own environment
//! reaches no exporter (SLNT-1351). `SEALANT_SENTRY_DSN` points the daemon at a loopback stand-in
//! for Sentry, which keeps every byte it is sent.

#[allow(dead_code)]
#[path = "../../sealant-observability/tests/support/collector.rs"]
mod collector;

use std::process::Stdio;
use std::time::{Duration, Instant};

use collector::{Collector, contains};
use sealant_control::{read_frame, write_frame};
use sealant_protocol::{
    ClientMessage, Command, ControlRequest, EnvVar, EventPayload, ExecArgs, ProcessId, RequestId,
    SecretEnvVar, ServerMessage, Signal, TraceContext,
};

const MAX: u32 = 8 * 1024 * 1024;
const CANARY: &str = "canary-d4e1b2c3a9f8";
const TRACE_ID: &str = "0af7651916cd43dd8448eb211c80319c";
const TRACEPARENT: &str = "00-0af7651916cd43dd8448eb211c80319c-b7ad6b7169203331-01";

fn hex(bytes: &str) -> Vec<u8> {
    (0..bytes.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&bytes[i..i + 2], 16).expect("hex"))
        .collect()
}

fn traced(id: &str, command: Command) -> ControlRequest {
    ControlRequest::new(RequestId::new(id), command).with_trace(TraceContext {
        traceparent: TRACEPARENT.to_owned(),
        tracestate: String::new(),
    })
}

#[tokio::test]
async fn a_traced_request_is_exported_in_the_callers_trace_and_no_canary_with_it() {
    let collector = Collector::start();
    let tmp = tempfile::tempdir().expect("tempdir");
    let log = std::fs::File::create(tmp.path().join("daemon.log")).expect("log file");
    let (mut child, _spawned) = sealant_process::spawn::spawn_tokio(
        tokio::process::Command::new(env!("CARGO_BIN_EXE_sealantd"))
            // `off`, as the TypeScript client spawns it: export must not depend on the log level.
            .args(["--stdio", "--log-level", "off", "--workspace"])
            .arg(tmp.path())
            .env_clear()
            .env("TMPDIR", tmp.path())
            .env("PATH", std::env::var("PATH").unwrap_or_default())
            .env("SEALANT_SENTRY_DSN", collector.dsn())
            .env("SEALANT_SENTRY_ENVIRONMENT", "test")
            .env("CANARY_IN_THE_DAEMONS_ENV", CANARY)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(log)
            .kill_on_drop(true),
    )
    .expect("spawn sealantd");
    let mut stdin = child.stdin.take().expect("stdin");
    let mut stdout = child.stdout.take().expect("stdout");
    let send = async |stdin: &mut tokio::process::ChildStdin, request: ControlRequest| {
        let body = sealant_protocol::encode_client(&ClientMessage::Request(request));
        write_frame(stdin, &body, MAX).await.expect("write frame");
    };

    send(
        &mut stdin,
        traced(
            "r1",
            Command::Exec(ExecArgs {
                user: None,
                execution_id: None,
                session_id: None,
                executable: "/bin/sh".to_owned(),
                args: vec![
                    "-c".to_owned(),
                    format!("echo {CANARY} \"$CANARY_ENV\" \"$CANARY_SECRET\""),
                ],
                cwd: None,
                env: vec![
                    EnvVar {
                        key: "PATH".to_owned(),
                        value: std::env::var("PATH").unwrap_or_default(),
                    },
                    EnvVar {
                        key: "CANARY_ENV".to_owned(),
                        value: CANARY.to_owned(),
                    },
                ],
                secret_env: vec![SecretEnvVar {
                    key: "CANARY_SECRET".to_owned(),
                    value: CANARY.to_owned(),
                }],
                stdin: false,
                attach: false,
                timeout_millis: None,
                background: false,
                capture: None,
                graceful_signal: None,
            }),
        ),
    )
    .await;
    // A request the daemon refuses: its span says so with the error code, nothing more.
    send(
        &mut stdin,
        traced(
            "r2",
            Command::SignalProcess {
                process_id: ProcessId::new(format!("proc_{CANARY}")),
                signal: Signal::Term,
            },
        ),
    )
    .await;

    let mut answered = 0;
    let mut exited = false;
    tokio::time::timeout(Duration::from_secs(30), async {
        while answered < 2 || !exited {
            let body = read_frame(&mut stdout, MAX)
                .await
                .expect("read frame")
                .expect("frame present");
            match sealant_protocol::decode_server(&body).expect("decode") {
                ServerMessage::Response(_) => answered += 1,
                ServerMessage::Event(event) => {
                    exited |= matches!(event.payload, EventPayload::ProcessExited(_));
                }
                ServerMessage::Stream(_) => {}
            }
        }
    })
    .await
    .expect("both answered and the process exited");

    // End of input ends the daemon, which sends what it holds before it exits.
    drop(stdin);
    let status = tokio::time::timeout(Duration::from_secs(20), child.wait())
        .await
        .expect("the daemon exits")
        .expect("wait");
    assert!(status.success(), "{status}");

    let deadline = Instant::now() + Duration::from_secs(5);
    let received = loop {
        let received = collector.received();
        let otlp: Vec<u8> = received.iter().flat_map(|r| r.body.clone()).collect();
        if contains(&otlp, b"sealantd.control.signalProcess") || Instant::now() > deadline {
            break received;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    };
    let otlp: Vec<u8> = received
        .iter()
        .filter(|r| r.path == "/api/10/integration/otlp/v1/traces")
        .flat_map(|r| r.body.clone())
        .collect();
    for name in [
        "sealantd.control.exec",
        "sealantd.process.spawn",
        "sealantd.control.signalProcess",
        "ProcessNotFound",
    ] {
        assert!(contains(&otlp, name.as_bytes()), "{name} was not exported");
    }
    assert!(
        contains(&otlp, &hex(TRACE_ID)),
        "the spans are not in the caller's trace"
    );
    for request in &received {
        assert!(
            !contains(&request.body, CANARY.as_bytes()),
            "the canary reached {}",
            request.path
        );
    }
}
