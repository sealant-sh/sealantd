//! A process's arguments never leave the daemon as text: `process.started` carries their count and
//! each one's length in UTF-8 bytes, over the control connection and in the durable spool alike.
//! Arguments can carry secrets (a token a script writes, a file's bytes in base64).
//!
//! Each test spawns the real `sealantd` binary in `--stdio` mode with `--spool-dir`, so the bus is
//! the durable one a deployed daemon runs.

use std::path::Path;
use std::process::Stdio;
use std::time::Duration;

use sealant_control::{read_frame, write_frame};
use sealant_eventlog::{FsyncPolicy, Spool, SpoolConfig};
use sealant_protocol::{
    ClientMessage, Command, ControlRequest, EventEnvelope, EventId, EventPayload, ExecArgs,
    OpenSessionArgs, ProcessStarted, RequestId, RuntimeId, SCHEMA_VERSION, Sequence, ServerMessage,
    SessionMode, WallClockMicros,
};
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::process::{Child, ChildStdin, ChildStdout};

const MAX: u32 = 8 * 1024 * 1024;
const MARKER: &str = "withheld-marker-7f3a";

/// The marker, an empty argument, a whitespace-led one and a multi-line one with a two-byte
/// character, after `sh -c <script>` and `$0`.
fn marker_args(script: &str) -> Vec<String> {
    vec![
        "-c".to_owned(),
        script.to_owned(),
        "sh".to_owned(),
        MARKER.to_owned(),
        String::new(),
        "  whitespace-led".to_owned(),
        "multi\nline é".to_owned(),
    ]
}

fn expected_lengths(script: &str) -> Vec<u32> {
    vec![
        2,
        u32::try_from(script.len()).expect("short"),
        2,
        20,
        0,
        16,
        13,
    ]
}

fn contains_marker(bytes: &[u8]) -> bool {
    bytes.windows(MARKER.len()).any(|w| w == MARKER.as_bytes())
}

fn spool_bytes(dir: &Path) -> Vec<u8> {
    let mut all = Vec::new();
    for entry in std::fs::read_dir(dir).expect("spool dir") {
        all.extend(std::fs::read(entry.expect("entry").path()).expect("read segment"));
    }
    all
}

fn spool_config(dir: &Path) -> SpoolConfig {
    SpoolConfig {
        dir: dir.to_owned(),
        segment_bytes: 1 << 20,
        disk_limit_bytes: 1 << 30,
        max_payload_bytes: MAX,
        fsync: FsyncPolicy::Never,
    }
}

/// Every `process.started` stored in the spool.
fn spooled_starts(dir: &Path) -> Vec<ProcessStarted> {
    let spool = Spool::open(spool_config(dir)).expect("open spool");
    let mut starts = Vec::new();
    spool
        .replay(|record| {
            let env = sealant_protocol::decode_event(&record.payload).expect("decode spooled");
            if let EventPayload::ProcessStarted(started) = env.payload {
                starts.push(started);
            }
        })
        .expect("replay");
    starts
}

fn spawn_daemon(spool: &Path) -> (Child, ChildStdin, ChildStdout) {
    let mut child = tokio::process::Command::new(env!("CARGO_BIN_EXE_sealantd"))
        .arg("--stdio")
        .arg("--workspace")
        .arg(std::env::temp_dir())
        .arg("--spool-dir")
        .arg(spool)
        .arg("--log-level")
        .arg("off")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .expect("spawn sealantd");
    let stdin = child.stdin.take().expect("stdin");
    let stdout = child.stdout.take().expect("stdout");
    (child, stdin, stdout)
}

async fn send<W: AsyncWrite + Unpin>(writer: &mut W, id: &str, command: Command) {
    let request = ControlRequest::new(RequestId::new(id), command);
    let body = sealant_protocol::encode_client(&ClientMessage::Request(request));
    write_frame(writer, &body, MAX).await.expect("write frame");
}

/// Read frames until `want` `process.exited` events arrived. Asserts that no frame, of any kind,
/// carries the marker, and returns every `process.started` received.
async fn starts_until_exits<R: AsyncRead + Unpin>(
    reader: &mut R,
    want: usize,
) -> Vec<ProcessStarted> {
    let mut starts = Vec::new();
    let mut exits = 0;
    let collect = async {
        while exits < want {
            let body = read_frame(reader, MAX)
                .await
                .expect("read frame")
                .expect("frame present");
            assert!(!contains_marker(&body), "a frame carried argument text");
            if let ServerMessage::Event(env) =
                sealant_protocol::decode_server(&body).expect("decode")
            {
                match env.payload {
                    EventPayload::ProcessStarted(started) => starts.push(started),
                    EventPayload::ProcessExited(_) => exits += 1,
                    _ => {}
                }
            }
        }
    };
    tokio::time::timeout(Duration::from_secs(15), collect)
        .await
        .expect("events arrived");
    starts
}

async fn shut_down(mut child: Child, stdin: ChildStdin) {
    // Closing stdin ends the stdio session, which shuts the daemon down (flushing the spool).
    drop(stdin);
    let status = tokio::time::timeout(Duration::from_secs(10), child.wait())
        .await
        .expect("daemon exits")
        .expect("wait");
    assert!(status.success());
}

#[tokio::test]
async fn exec_and_session_publish_counts_never_argument_text() {
    let spool = tempfile::tempdir().expect("spool");
    let (child, mut stdin, mut stdout) = spawn_daemon(spool.path());

    let exec_script = "exit 0";
    send(
        &mut stdin,
        "exec",
        Command::Exec(ExecArgs {
            user: None,
            execution_id: None,
            session_id: None,
            executable: "/bin/sh".to_owned(),
            args: marker_args(exec_script),
            cwd: None,
            env: vec![],
            stdin: false,
            attach: false,
            timeout_millis: None,
            background: false,
            capture: None,
            graceful_signal: None,
        }),
    )
    .await;
    let session_script = "exit 3";
    assert_eq!(session_script.len(), exec_script.len());
    send(
        &mut stdin,
        "session",
        Command::OpenSession(OpenSessionArgs {
            user: None,
            execution_id: None,
            shell: Some("/bin/sh".to_owned()),
            args: marker_args(session_script),
            cwd: None,
            env: vec![],
            cols: 80,
            rows: 24,
            term: None,
            mode: SessionMode::Pty,
        }),
    )
    .await;

    let starts = starts_until_exits(&mut stdout, 2).await;
    assert_eq!(starts.len(), 2, "one process.started each: {starts:?}");
    for started in &starts {
        assert_eq!(started.executable, "/bin/sh");
        assert!(started.args.is_empty(), "{started:?}");
        assert_eq!(started.arg_count, 7);
        // Both scripts are six bytes long.
        assert_eq!(started.arg_lengths, expected_lengths(exec_script));
    }

    shut_down(child, stdin).await;

    // The spool holds the same events, and not the text.
    let on_disk = spool_bytes(spool.path());
    assert!(!on_disk.is_empty(), "events were spooled");
    assert!(
        !contains_marker(&on_disk),
        "a spool segment holds argument text"
    );
    let spooled = spooled_starts(spool.path());
    assert_eq!(spooled.len(), 2);
    assert!(
        spooled
            .iter()
            .all(|s| s.args.is_empty() && s.arg_count == 7)
    );
}

#[tokio::test]
async fn an_older_daemons_spooled_arguments_are_scrubbed_on_start() {
    let spool = tempfile::tempdir().expect("spool");
    // A spool left by a daemon that published argument text.
    {
        let mut seeded = Spool::open(spool_config(spool.path())).expect("seed spool");
        let envelope = EventEnvelope {
            schema_version: SCHEMA_VERSION,
            event_id: EventId::new("evt_old"),
            runtime_id: RuntimeId::new("rt_old"),
            execution_id: None,
            session_id: None,
            process_id: None,
            request_id: None,
            sequence: Sequence(0),
            observed_at: WallClockMicros(1),
            monotonic_timestamp: sealant_protocol::MonotonicNanos(1),
            capture_method: sealant_protocol::CaptureMethod::Internal,
            confidence: sealant_protocol::Confidence::Observed,
            payload: EventPayload::ProcessStarted(ProcessStarted {
                pid: 7,
                pgid: 7,
                pidfd: false,
                executable: "/bin/sh".to_owned(),
                args: marker_args("exit 0"),
                cwd: "/workspace".to_owned(),
                started_at: WallClockMicros(1),
                arg_count: 0,
                arg_lengths: vec![],
            }),
        };
        let bytes = sealant_protocol::encode_event(&envelope);
        seeded.append(0, 1, &bytes).expect("append");
        seeded.flush().expect("flush");
    }
    assert!(contains_marker(&spool_bytes(spool.path())));

    let (child, mut stdin, mut stdout) = spawn_daemon(spool.path());
    // The delivery task replays (and rewrites) the spool before it delivers anything new, so once
    // this exec's events arrived the old segment has been scrubbed. Any replayed event this
    // connection sees is checked for the marker with every other frame.
    send(
        &mut stdin,
        "exec",
        Command::Exec(ExecArgs {
            user: None,
            execution_id: None,
            session_id: None,
            executable: "/bin/sh".to_owned(),
            args: vec!["-c".to_owned(), "exit 0".to_owned()],
            cwd: None,
            env: vec![],
            stdin: false,
            attach: false,
            timeout_millis: None,
            background: false,
            capture: None,
            graceful_signal: None,
        }),
    )
    .await;
    let starts = starts_until_exits(&mut stdout, 1).await;
    assert!(starts.iter().all(|s| s.args.is_empty()));
    assert!(!contains_marker(&spool_bytes(spool.path())));

    shut_down(child, stdin).await;
    assert!(!contains_marker(&spool_bytes(spool.path())));
    // The old event is still there (unless acknowledged away), its arguments described instead.
    for started in spooled_starts(spool.path()) {
        assert!(started.args.is_empty());
        if started.cwd == "/workspace" {
            assert_eq!(started.arg_count, 7);
            assert_eq!(started.arg_lengths, expected_lengths("exit 0"));
        }
    }
}
