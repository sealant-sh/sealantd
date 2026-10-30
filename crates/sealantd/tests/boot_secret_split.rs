//! A workspace secret a process writes in two parts, a read apart, never reaches the durable
//! spool or a session journal: not whole, and not either part. The real runtime, built from the
//! configuration boot hands it, runs an exec (stdout and stderr) and a PTY session over a control
//! connection, with the spool and the journals on disk. The script splits the value it reads from
//! its environment, so the secret's text appears in no argument.

use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

use sealant_control::{handle_connection, read_frame, write_frame};
use sealant_protocol::{
    ClientMessage, Command, ControlRequest, EnvVar, EventPayload, ExecArgs, OpenSessionArgs,
    RequestId, ServerMessage, SessionMode, StreamKind,
};
use sealant_runtime_core::{RuntimeConfig, new_runtime_id};
use sealantd::Runtime;
use sealantd::shutdown::ShutdownSignal;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::sync::watch;

const MAX: u32 = 8 * 1024 * 1024;
const SECRET: &str = "fake-boot-secret-7f3a91";
const FIRST: &str = "fake-boot-se";
const SECOND: &str = "cret-7f3a91";
const MARKER: &[u8] = b"***REDACTED***";

/// Writes `pw=<the value's first 12 bytes>`, waits, then `<the other 11> end`: to stdout, and
/// with `>&2` to stderr.
fn script(redirect: &str) -> String {
    format!(
        "printf 'pw=%s' \"${{DB_PASSWORD%???????????}}\" {redirect}; sleep 0.3; \
         printf '%s end' \"${{DB_PASSWORD#????????????}}\" {redirect}"
    )
}

fn contains(haystack: &[u8], needle: &[u8]) -> bool {
    haystack.windows(needle.len()).any(|w| w == needle)
}

fn files_bytes(dir: &Path) -> Vec<u8> {
    let mut all = Vec::new();
    for entry in std::fs::read_dir(dir).expect("read dir") {
        let path = entry.expect("entry").path();
        if path.is_file() {
            all.extend(std::fs::read(path).expect("read file"));
        }
    }
    all
}

async fn send<W: AsyncWrite + Unpin>(writer: &mut W, id: &str, command: Command) {
    let request = ControlRequest::new(RequestId::new(id), command);
    let body = sealant_protocol::encode_client(&ClientMessage::Request(request));
    write_frame(writer, &body, MAX).await.expect("write frame");
}

async fn recv<R: AsyncRead + Unpin>(reader: &mut R) -> ServerMessage {
    let body = read_frame(reader, MAX)
        .await
        .expect("read frame")
        .expect("frame present");
    sealant_protocol::decode_server(&body).expect("decode")
}

#[tokio::test]
async fn a_boot_secret_split_across_writes_never_reaches_the_spool_or_a_journal() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let spool = tmp.path().join("spool");
    let journals = tmp.path().join("journals");
    let mut config = RuntimeConfig::new(new_runtime_id());
    config.workspace_root = tmp.path().to_owned();
    config.spool_dir = Some(spool.clone());
    config.session_journal_dir = Some(journals.clone());
    config.child_env = vec![
        EnvVar {
            key: "PATH".to_owned(),
            value: std::env::var("PATH").unwrap_or_else(|_| "/usr/bin:/bin".to_owned()),
        },
        EnvVar {
            key: "DB_PASSWORD".to_owned(),
            value: SECRET.to_owned(),
        },
    ];
    // As boot sets it: every launcher-provided secret value, whatever its name.
    config.redact_literals = vec![SECRET.to_owned()];
    let runtime = Runtime::new(config, Arc::new(ShutdownSignal::new(1000)));
    runtime.start_telemetry();
    runtime.mark_healthy();
    let (_shutdown, shutdown_rx) = watch::channel(false);
    let (mut client, server) = tokio::io::duplex(1 << 20);
    let (server_read, server_write) = tokio::io::split(server);
    tokio::spawn(handle_connection(
        runtime.clone(),
        server_read,
        server_write,
        shutdown_rx,
    ));

    send(
        &mut client,
        "exec",
        Command::Exec(ExecArgs {
            user: None,
            execution_id: None,
            session_id: None,
            executable: "/bin/sh".to_owned(),
            args: vec![
                "-c".to_owned(),
                format!("{}; {}", script(""), script(">&2")),
            ],
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
    send(
        &mut client,
        "session",
        Command::OpenSession(OpenSessionArgs {
            user: None,
            execution_id: None,
            shell: Some("/bin/sh".to_owned()),
            args: vec!["-c".to_owned(), script("")],
            cwd: None,
            env: vec![],
            cols: 80,
            rows: 24,
            term: None,
            mode: SessionMode::Pty,
        }),
    )
    .await;

    let mut recorded: Vec<(StreamKind, Vec<u8>)> = Vec::new();
    let mut exits = 0;
    let collect = async {
        while exits < 2 {
            if let ServerMessage::Event(env) = recv(&mut client).await {
                match env.payload {
                    EventPayload::IoChunk(chunk) => {
                        let content = chunk.content.expect("full capture");
                        match recorded.iter_mut().find(|(s, _)| *s == chunk.stream) {
                            Some((_, bytes)) => bytes.extend_from_slice(content.as_slice()),
                            None => recorded.push((chunk.stream, content.as_slice().to_vec())),
                        }
                    }
                    EventPayload::ProcessExited(_) => exits += 1,
                    _ => {}
                }
            }
        }
    };
    tokio::time::timeout(Duration::from_secs(15), collect)
        .await
        .expect("both processes exited");

    // The positive control: each stream recorded the value, masked.
    for stream in [
        StreamKind::Stdout,
        StreamKind::Stderr,
        StreamKind::PtyOutput,
    ] {
        let bytes = recorded
            .iter()
            .find(|(s, _)| *s == stream)
            .map(|(_, b)| b.as_slice())
            .unwrap_or_default();
        assert_eq!(
            String::from_utf8_lossy(bytes),
            "pw=***REDACTED*** end",
            "{stream:?}"
        );
    }

    // The bus spools each event before it is broadcast, so the spool already holds them all.
    let spooled = files_bytes(&spool);
    let journaled = files_bytes(&journals);
    assert!(
        contains(&spooled, MARKER),
        "the spool holds the masked output"
    );
    assert!(
        contains(&journaled, MARKER),
        "the journal holds the masked output"
    );
    for part in [SECRET, FIRST, SECOND] {
        assert!(
            !contains(&spooled, part.as_bytes()),
            "the spool holds {part:?}"
        );
        assert!(
            !contains(&journaled, part.as_bytes()),
            "a journal holds {part:?}"
        );
    }
}
