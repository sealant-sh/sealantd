//! A workspace secret a process writes in two parts never reaches the durable spool or a session
//! journal: not whole, and not either part. The configuration comes from boot's own path (its
//! environment, its secret environment file, `into_runtime_config`), and the secret's name, DB_PW,
//! is one the secret-name heuristic does not catch, so only boot's seeding masks it. The real
//! runtime runs an exec (stdout and stderr) and a PTY session over a control connection, with the
//! spool and the journals on disk. Each process writes the second part only once the first was
//! captured, and the script splits the value it reads from its environment, so the secret's text
//! appears in no argument.

use std::collections::HashMap;
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

use sealant_control::{handle_connection, read_frame, write_frame};
use sealant_protocol::{
    Base64Bytes, ClientMessage, Command, CommandResult, ControlRequest, EventPayload, ExecArgs,
    OpenSessionArgs, RequestId, ResponseOutcome, ServerMessage, SessionMode, StreamKind,
    WriteStdinArgs,
};
use sealantd::Runtime;
use sealantd::boot::config::{BootConfig, EnvSource, load_secret_env};
use sealantd::boot::into_runtime_config;
use sealantd::shutdown::ShutdownSignal;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::sync::watch;

const MAX: u32 = 8 * 1024 * 1024;
const SECRET: &str = "fake-boot-secret-7f3a91";
const FIRST: &str = "fake-boot-se";
const SECOND: &str = "cret-7f3a91";
const MARKER: &[u8] = b"***REDACTED***";

struct Env(HashMap<String, String>);

impl EnvSource for Env {
    fn get(&self, key: &str) -> Option<String> {
        self.0.get(key).cloned()
    }
    fn entries(&self) -> Vec<(String, String)> {
        self.0.iter().map(|(k, v)| (k.clone(), v.clone())).collect()
    }
}

/// Writes `pw=<the value's first 12 bytes>` with each of `redirects` (`""` for stdout, `">&2"`
/// for stderr), waits for a line on its input, then writes `<the other 11> end` the same way.
fn script(redirects: &[&str]) -> String {
    let first: Vec<String> = redirects
        .iter()
        .map(|r| format!("printf 'pw=%s' \"${{DB_PW%???????????}}\" {r}"))
        .collect();
    let second: Vec<String> = redirects
        .iter()
        .map(|r| format!("printf '%s end' \"${{DB_PW#????????????}}\" {r}"))
        .collect();
    format!("{}; read -r go; {}", first.join("; "), second.join("; "))
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

/// The runtime a boot starts, from boot's environment and a secret environment file that
/// holds `DB_PW`.
fn boot_runtime(tmp: &Path) -> Arc<Runtime> {
    let secrets = tmp.join("secrets.json");
    std::fs::write(&secrets, format!(r#"{{"DB_PW":"{SECRET}"}}"#)).expect("secret env file");
    std::fs::create_dir_all(tmp.join("repo")).expect("working directory");
    let path = |name: &str| tmp.join(name).display().to_string();
    let env = Env(HashMap::from(
        [
            (
                "SEALANT_WORKSPACE_REPO_URL",
                "git@github.com:o/r.git".to_owned(),
            ),
            ("SEALANT_WORKSPACE_REPO_REF", "main".to_owned()),
            ("SEALANT_OS_FAMILY", "fedora".to_owned()),
            ("SEALANT_HARNESS_LAUNCH_COMMAND", "true".to_owned()),
            ("SEALANT_WORKSPACE_ROOT", tmp.display().to_string()),
            ("SEALANT_WORKING_DIRECTORY", path("repo")),
            ("SEALANT_CONTROL_SOCKET", path("control.sock")),
            ("SEALANT_SPOOL_DIR", path("spool")),
            ("SEALANT_SESSION_JOURNAL_DIR", path("journals")),
            ("SEALANT_SECRET_ENV_FILE", secrets.display().to_string()),
            (
                "PATH",
                std::env::var("PATH").unwrap_or_else(|_| "/usr/bin:/bin".to_owned()),
            ),
        ]
        .map(|(k, v)| (k.to_owned(), v)),
    ));
    let config = BootConfig::load(&env).expect("boot config");
    let secret_env = load_secret_env(&secrets).expect("secret env");
    let runtime = Runtime::new(
        into_runtime_config(&config, &secret_env),
        Arc::new(ShutdownSignal::new(1000)),
    );
    runtime.start_telemetry();
    runtime.mark_healthy();
    runtime
}

#[tokio::test]
async fn a_boot_secret_split_across_writes_never_reaches_the_spool_or_a_journal() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let runtime = boot_runtime(tmp.path());
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
            args: vec!["-c".to_owned(), script(&["", ">&2"])],
            cwd: None,
            env: vec![],
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
        &mut client,
        "session",
        Command::OpenSession(OpenSessionArgs {
            user: None,
            execution_id: None,
            shell: Some("/bin/sh".to_owned()),
            args: vec!["-c".to_owned(), format!("stty -echo; {}", script(&[""]))],
            cwd: None,
            env: vec![],
            cols: 80,
            rows: 24,
            term: None,
            mode: SessionMode::Pty,
        }),
    )
    .await;

    // Each stream's chunks; a process gets its go-ahead once its first parts were captured.
    let streams = [
        StreamKind::Stdout,
        StreamKind::Stderr,
        StreamKind::PtyOutput,
    ];
    let mut chunks: HashMap<StreamKind, Vec<(u64, Vec<u8>)>> = HashMap::new();
    let (mut process, mut session) = (None, None);
    let (mut exec_released, mut session_released, mut exits) = (false, false, 0);
    let collect = async {
        while exits < 2 {
            match recv(&mut client).await {
                ServerMessage::Response(response) => {
                    if let ResponseOutcome::Ok {
                        result: Some(result),
                    } = response.outcome
                    {
                        match result {
                            CommandResult::ExecAccepted(accepted) => {
                                process = Some(accepted.process_id);
                            }
                            CommandResult::SessionOpened(opened) => {
                                session = Some(opened.session_id);
                            }
                            _ => {}
                        }
                    }
                }
                ServerMessage::Event(env) => match env.payload {
                    EventPayload::IoChunk(chunk) => {
                        let content = chunk.content.expect("full capture").as_slice().to_vec();
                        chunks
                            .entry(chunk.stream)
                            .or_default()
                            .push((chunk.stream_offset.get(), content));
                    }
                    EventPayload::ProcessExited(_) => exits += 1,
                    _ => {}
                },
                _ => {}
            }
            let captured = |stream: StreamKind| chunks.get(&stream).is_some_and(|c| !c.is_empty());
            if !exec_released
                && captured(StreamKind::Stdout)
                && captured(StreamKind::Stderr)
                && let Some(process_id) = process.clone()
            {
                exec_released = true;
                let go = Command::WriteStdin(WriteStdinArgs {
                    process_id: Some(process_id),
                    session_id: None,
                    data: Base64Bytes::new(b"\n".to_vec()),
                });
                send(&mut client, "go-exec", go).await;
            }
            if !session_released
                && captured(StreamKind::PtyOutput)
                && let Some(session_id) = session.clone()
            {
                session_released = true;
                let go = Command::WriteStdin(WriteStdinArgs {
                    process_id: None,
                    session_id: Some(session_id),
                    data: Base64Bytes::new(b"\r".to_vec()),
                });
                send(&mut client, "go-session", go).await;
            }
        }
    };
    tokio::time::timeout(Duration::from_secs(15), collect)
        .await
        .expect("both processes exited");

    // The positive control: each stream recorded the value masked, in two chunks, the second
    // starting after `pw=`: the split happened.
    for stream in streams {
        let stream_chunks = chunks.get(&stream).cloned().unwrap_or_default();
        let recorded: Vec<u8> = stream_chunks.iter().flat_map(|(_, c)| c.clone()).collect();
        assert_eq!(
            String::from_utf8_lossy(&recorded),
            "pw=***REDACTED*** end",
            "{stream:?}"
        );
        let offsets: Vec<u64> = stream_chunks.iter().map(|(o, _)| *o).collect();
        assert_eq!(offsets, [0, 3], "{stream:?}");
    }

    // The bus spools each event before it is broadcast, so the spool already holds them all.
    let spooled = files_bytes(&tmp.path().join("spool"));
    let journaled = files_bytes(&tmp.path().join("journals"));
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
