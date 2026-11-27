//! The real daemon joins a caller's trace and exports it, and a canary in a request's arguments,
//! its environment, its secret environment, the process's output and the daemon's own environment
//! reaches no exporter (SLNT-1351). `SEALANT_SENTRY_DSN` points the daemon at a loopback stand-in
//! for Sentry, which keeps every byte it is sent.

#[allow(dead_code)]
#[path = "../../sealant-observability/tests/support/collector.rs"]
mod collector;

use std::process::Stdio;
use std::time::{Duration, Instant};

use collector::{Collector, assert_sentry_shows, contains, exported_spans};
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

/// The real daemon over stdio, exporting to `collector`.
fn daemon(
    tmp: &std::path::Path,
    collector: &Collector,
) -> (
    tokio::process::Child,
    tokio::process::ChildStdin,
    tokio::process::ChildStdout,
) {
    let log = std::fs::File::create(tmp.join("daemon.log")).expect("log file");
    let (mut child, _spawned) = sealant_process::spawn::spawn_tokio(
        tokio::process::Command::new(env!("CARGO_BIN_EXE_sealantd"))
            // `off`, as the TypeScript client spawns it: export must not depend on the log level.
            .args(["--stdio", "--log-level", "off", "--workspace"])
            .arg(tmp)
            .env_clear()
            .env("TMPDIR", tmp)
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
    let stdin = child.stdin.take().expect("stdin");
    let stdout = child.stdout.take().expect("stdout");
    (child, stdin, stdout)
}

async fn send(stdin: &mut tokio::process::ChildStdin, request: ControlRequest) {
    let body = sealant_protocol::encode_client(&ClientMessage::Request(request));
    write_frame(stdin, &body, MAX).await.expect("write frame");
}

/// Wait for the response to each of `count` requests.
async fn answers(stdout: &mut tokio::process::ChildStdout, count: usize) {
    let mut answered = 0;
    tokio::time::timeout(Duration::from_secs(30), async {
        while answered < count {
            let body = read_frame(stdout, MAX)
                .await
                .expect("read frame")
                .expect("frame present");
            if let ServerMessage::Response(_) =
                sealant_protocol::decode_server(&body).expect("decode")
            {
                answered += 1;
            }
        }
    })
    .await
    .expect("every request answered");
}

#[tokio::test]
async fn a_traced_request_is_exported_in_the_callers_trace_and_no_canary_with_it() {
    let collector = Collector::start();
    let tmp = tempfile::tempdir().expect("tempdir");
    let (mut child, mut stdin, mut stdout) = daemon(tmp.path(), &collector);

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
        if contains(&otlp, b"sealantd.control.signal_process") || Instant::now() > deadline {
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
        "sealantd.control.signal_process",
    ] {
        assert!(contains(&otlp, name.as_bytes()), "{name} was not exported");
    }
    // Each span reads in Sentry as what it is, in the daemon's environment and runtime.
    let spans = exported_spans(&received);
    assert_sentry_shows(&spans);
    for span in &spans {
        assert_eq!(
            span.attribute("sentry.environment"),
            Some("test"),
            "{}",
            span.name
        );
        assert!(
            span.attribute("sealant.runtime_id")
                .is_some_and(|id| id.starts_with("rt_")),
            "{} names no runtime",
            span.name
        );
    }
    let span = |name: &str| {
        spans
            .iter()
            .find(|s| s.name == name)
            .unwrap_or_else(|| panic!("no {name} span"))
    };
    let exec = span("sealantd.control.exec");
    assert_eq!(exec.attribute("sentry.op"), Some("sealantd.control"));
    assert_eq!(exec.attribute("sentry.description"), Some("start process"));
    // The wire name stays in `rpc.method`.
    assert_eq!(exec.attribute("rpc.method"), Some("exec"));
    assert_eq!(exec.attribute("sealantd.request_id"), Some("r1"));
    assert_eq!(span("sealantd.process.spawn").parent_span_id, exec.span_id);
    // A refusal is coded on its span in the wire form the client reads.
    let refused = span("sealantd.control.signal_process");
    assert_eq!(refused.attribute("rpc.method"), Some("signalProcess"));
    assert_eq!(
        refused.attribute("sentry.description"),
        Some("signal process")
    );
    assert_eq!(
        refused.attribute("rpc.response.status_code"),
        Some("process-not-found")
    );
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

/// A health check, a capabilities probe or a stop with no caller trace sends no span (they
/// flooded Sentry's trace list, SLNT-1386); a health check inside a caller's trace is a span of it.
#[tokio::test]
async fn housekeeping_sends_a_span_only_inside_a_callers_trace() {
    let collector = Collector::start();
    let tmp = tempfile::tempdir().expect("tempdir");
    let (mut child, mut stdin, mut stdout) = daemon(tmp.path(), &collector);
    let plain = |id: &str, command| ControlRequest::new(RequestId::new(id), command);
    send(&mut stdin, plain("h1", Command::RuntimeHealth)).await;
    send(&mut stdin, plain("c1", Command::RuntimeGetCapabilities)).await;
    send(&mut stdin, traced("h2", Command::RuntimeHealth)).await;
    answers(&mut stdout, 3).await;
    send(
        &mut stdin,
        plain(
            "s1",
            Command::RuntimeGracefulShutdown {
                grace_millis: Some(5_000),
            },
        ),
    )
    .await;
    let status = tokio::time::timeout(Duration::from_secs(20), child.wait())
        .await
        .expect("the daemon exits")
        .expect("wait");
    drop(stdin);
    assert!(status.code().is_some(), "{status}");

    let deadline = Instant::now() + Duration::from_secs(5);
    let received = loop {
        let received = collector.received();
        if !exported_spans(&received).is_empty() || Instant::now() > deadline {
            break received;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    };
    let spans = exported_spans(&received);
    let names: Vec<&str> = spans.iter().map(|s| s.name.as_str()).collect();
    assert_eq!(names, ["sealantd.control.runtime_health"], "{spans:?}");
    let health = &spans[0];
    assert_eq!(health.attribute("sealantd.request_id"), Some("h2"));
    assert_eq!(health.trace_id, hex(TRACE_ID));
    assert_eq!(health.parent_span_id, hex(&TRACEPARENT[36..52]));
    assert_sentry_shows(&spans);
}
