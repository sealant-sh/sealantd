//! A secret env (`process.secret-env.v1`) reaches the process it is addressed to, and its value
//! is nowhere the daemon records it: the events it sends, its spool and session journals on
//! disk, and its own log at `trace`. The real binary runs an exec (stdout and stderr), a PTY
//! session (output and typed input) and a pipe session (stdout, stderr and input). Each process
//! prints the value's length, which shows it got the exact value; the value itself is printed
//! too, and recorded masked.

use std::collections::HashMap;
use std::path::Path;
use std::process::Stdio;
use std::time::Duration;

use sealant_control::{read_frame, write_frame};
use sealant_protocol::{
    Base64Bytes, ClientMessage, Command, CommandResult, ControlRequest, EnvVar, EventPayload,
    ExecArgs, OpenSessionArgs, ProcessId, RequestId, ResponseOutcome, SecretEnvVar, ServerMessage,
    SessionId, SessionMode, StreamKind, WriteStdinArgs,
};

const MAX: u32 = 8 * 1024 * 1024;
const VALUE: &str = "fake-pg-password-5d1e";
const URL: &str = "postgres://developer:fake-pg-password-5d1e@db/worktree";
const MARKER: &[u8] = b"***REDACTED***";

fn contains(haystack: &[u8], needle: &[u8]) -> bool {
    haystack.windows(needle.len()).any(|w| w == needle)
}

/// Every file's bytes under `dir`, however deep.
fn tree_bytes(dir: &Path) -> Vec<u8> {
    let mut all = Vec::new();
    for entry in std::fs::read_dir(dir).expect("read dir") {
        let path = entry.expect("entry").path();
        if path.is_dir() {
            all.extend(tree_bytes(&path));
        } else {
            all.extend(std::fs::read(&path).expect("read file"));
        }
    }
    all
}

fn secret_env() -> Vec<SecretEnvVar> {
    [("PGPASSWORD", VALUE), ("DATABASE_URL", URL)]
        .map(|(key, value)| SecretEnvVar {
            key: key.to_owned(),
            value: value.to_owned(),
        })
        .to_vec()
}

fn path_env() -> Vec<EnvVar> {
    vec![EnvVar {
        key: "PATH".to_owned(),
        value: std::env::var("PATH").unwrap_or_default(),
    }]
}

/// Prints the value's length and the value, the URL to stderr (`>&2`) or stdout, waits for a
/// line of input, and prints that line's length.
fn script(stderr: &str) -> String {
    format!(
        r#"printf 'len=%s pw=%s end' "${{#PGPASSWORD}}" "$PGPASSWORD"; printf ' url=%s' "$DATABASE_URL" {stderr}; read -r typed; printf ' typed=%s' "${{#typed}}""#
    )
}

fn session(mode: SessionMode, script: String) -> Command {
    Command::OpenSession(OpenSessionArgs {
        user: None,
        execution_id: None,
        shell: Some("/bin/sh".to_owned()),
        args: vec!["-c".to_owned(), script],
        cwd: None,
        env: path_env(),
        secret_env: secret_env(),
        cols: 80,
        rows: 24,
        term: None,
        mode,
    })
}

/// What a process does next once its first output was recorded.
enum Input {
    Process(ProcessId),
    Session(SessionId, &'static str),
}

#[tokio::test]
async fn a_secret_env_reaches_its_process_and_no_record_holds_its_value() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let log = std::fs::File::create(tmp.path().join("daemon.log")).expect("log file");
    let (mut child, _spawned) = sealant_process::spawn::spawn_tokio(
        tokio::process::Command::new(env!("CARGO_BIN_EXE_sealantd"))
            .args(["--stdio", "--log-level", "trace", "--workspace"])
            .arg(tmp.path())
            .arg("--spool-dir")
            .arg(tmp.path().join("spool"))
            .env_clear()
            // The session journals go under the daemon's temporary directory.
            .env("TMPDIR", tmp.path())
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(log)
            .kill_on_drop(true),
    )
    .expect("spawn sealantd");
    let mut stdin = child.stdin.take().expect("stdin");
    let mut stdout = child.stdout.take().expect("stdout");
    let mut sent = 0;
    let mut send = async |stdin: &mut tokio::process::ChildStdin, command: Command| {
        sent += 1;
        let request = ControlRequest::new(RequestId::new(format!("r{sent}")), command);
        let body = sealant_protocol::encode_client(&ClientMessage::Request(request));
        write_frame(stdin, &body, MAX).await.expect("write frame");
    };

    send(
        &mut stdin,
        Command::Exec(ExecArgs {
            user: None,
            execution_id: None,
            session_id: None,
            executable: "/bin/sh".to_owned(),
            args: vec!["-c".to_owned(), script(">&2")],
            cwd: None,
            env: path_env(),
            secret_env: secret_env(),
            stdin: true,
            attach: false,
            timeout_millis: None,
            background: false,
            capture: None,
            graceful_signal: None,
        }),
    )
    .await;
    send(
        &mut stdin,
        session(SessionMode::Pty, format!("stty -echo; {}", script(""))),
    )
    .await;
    send(&mut stdin, session(SessionMode::Pipe, script(">&2"))).await;

    // Everything the daemon sent, as it crossed the wire, and each process's recorded streams.
    let mut wire = Vec::new();
    let mut recorded: HashMap<(ProcessId, StreamKind), Vec<u8>> = HashMap::new();
    let mut waiting: HashMap<ProcessId, Input> = HashMap::new();
    let mut exits = 0;
    let collect = async {
        while exits < 3 {
            let body = read_frame(&mut stdout, MAX)
                .await
                .expect("read frame")
                .expect("frame present");
            wire.extend_from_slice(&body);
            match sealant_protocol::decode_server(&body).expect("decode") {
                ServerMessage::Response(response) => match response.outcome.clone() {
                    ResponseOutcome::Ok {
                        result: Some(CommandResult::ExecAccepted(accepted)),
                    } => {
                        let input = Input::Process(accepted.process_id.clone());
                        waiting.insert(accepted.process_id, input);
                    }
                    ResponseOutcome::Ok {
                        result: Some(CommandResult::SessionOpened(opened)),
                    } => {
                        // A terminal sends Enter as CR; a pipe takes a line.
                        let pty = response.request_id == RequestId::new("r2");
                        let input =
                            Input::Session(opened.session_id, if pty { "\r" } else { "\n" });
                        waiting.insert(opened.process_id, input);
                    }
                    ResponseOutcome::Ok { .. } => {}
                    ResponseOutcome::Error { error } => panic!("refused: {}", error.message),
                },
                ServerMessage::Event(event) => match event.payload {
                    EventPayload::IoChunk(chunk) => {
                        let process = event.process_id.expect("a process's chunk");
                        let content = chunk.content.expect("full capture");
                        recorded
                            .entry((process, chunk.stream))
                            .or_default()
                            .extend_from_slice(content.as_slice());
                    }
                    EventPayload::ProcessExited(_) => exits += 1,
                    _ => {}
                },
                ServerMessage::Stream(_) => {}
            }
            // Input goes once both the response naming the process and its first output are in,
            // whichever came first.
            let ready: Vec<ProcessId> = waiting
                .keys()
                .filter(|process| {
                    [StreamKind::Stdout, StreamKind::PtyOutput]
                        .iter()
                        .any(|stream| {
                            recorded
                                .get(&((*process).clone(), *stream))
                                .is_some_and(|r| contains(r, b" end"))
                        })
                })
                .cloned()
                .collect();
            for process in ready {
                let (process_id, session_id, line) = match waiting.remove(&process) {
                    Some(Input::Process(id)) => (Some(id), None, format!("{VALUE}\n")),
                    Some(Input::Session(id, end)) => (None, Some(id), format!("{VALUE}{end}")),
                    None => continue,
                };
                let write = WriteStdinArgs {
                    process_id,
                    session_id,
                    data: Base64Bytes::new(line.into_bytes()),
                };
                send(&mut stdin, Command::WriteStdin(write)).await;
            }
        }
    };
    if tokio::time::timeout(Duration::from_secs(20), collect)
        .await
        .is_err()
    {
        let so_far: Vec<_> = recorded
            .iter()
            .map(|(key, bytes)| (key, String::from_utf8_lossy(bytes)))
            .collect();
        panic!("the three processes did not exit; recorded so far: {so_far:?}");
    }
    child.kill().await.expect("stop sealantd");

    // Each process got the exact values (their lengths), and each stream recorded them masked:
    // the URL as one span, though the password is inside it.
    let mut by_stream: HashMap<StreamKind, Vec<String>> = HashMap::new();
    for ((_, stream), bytes) in &recorded {
        by_stream
            .entry(*stream)
            .or_default()
            .push(String::from_utf8_lossy(bytes).into_owned());
    }
    let sorted = |stream| {
        let mut texts = by_stream.get(&stream).cloned().unwrap_or_default();
        texts.sort();
        texts
    };
    let printed = "len=21 pw=***REDACTED*** end";
    assert_eq!(
        sorted(StreamKind::Stdout),
        [format!("{printed} typed=21"), format!("{printed} typed=21")]
    );
    assert_eq!(sorted(StreamKind::Stderr), [" url=***REDACTED***"; 2]);
    assert_eq!(
        sorted(StreamKind::PtyOutput),
        [format!("{printed} url=***REDACTED*** typed=21")]
    );
    assert_eq!(sorted(StreamKind::PtyInput), ["***REDACTED***\r"]);
    assert_eq!(sorted(StreamKind::Stdin), ["***REDACTED***\n"]);

    let spool = tree_bytes(&tmp.path().join("spool"));
    let journal_dirs: Vec<_> = std::fs::read_dir(tmp.path())
        .expect("read the temporary directory")
        .map(|entry| entry.expect("entry").path())
        .filter(|path| {
            path.file_name()
                .is_some_and(|name| name.to_string_lossy().starts_with("sealantd-journals-"))
        })
        .collect();
    assert_eq!(
        journal_dirs.len(),
        1,
        "one journal directory: {journal_dirs:?}"
    );
    let journals = tree_bytes(&journal_dirs[0]);
    let everything = tree_bytes(tmp.path());
    let logged = std::fs::read(tmp.path().join("daemon.log")).expect("log");
    assert!(contains(&wire, MARKER), "the events hold the masked output");
    assert!(
        contains(&spool, MARKER),
        "the spool holds the masked output"
    );
    assert!(
        contains(&journals, MARKER),
        "the session journals hold the masked output"
    );
    assert!(!logged.is_empty(), "the daemon logged at trace");
    for (place, bytes) in [
        ("the events", &wire),
        ("the spool", &spool),
        ("the session journals", &journals),
        ("the temporary directory", &everything),
        ("the log", &logged),
    ] {
        assert!(!contains(bytes, VALUE.as_bytes()), "{place} hold the value");
    }
}
