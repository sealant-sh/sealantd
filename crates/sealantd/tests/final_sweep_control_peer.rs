//! The final capture's sweep and the connection that asked for it.
//!
//! In Docker, Core reaches sealantd through `docker exec … socat - UNIX-CONNECT:<control
//! socket>`. sealantd is PID 1 of the container's PID namespace there, so the sweep takes every
//! process in the namespace — the `socat` carrying the `capture.flush {kind: final}` included:
//! it was sent `SIGTERM` while the flush ran, and the reply was lost ("connection closed" on
//! every stop; the saved state was seen only on the next poll). The sweep now spares the
//! process at the far end of each live control connection (`SO_PEERCRED`) and its ancestors,
//! unless sealantd started it.
//!
//! Its own test binary: the relay must be orphaned before this process becomes a child
//! subreaper (`Runtime::new`), so it is not sealantd's descendant — as `docker exec`'s `socat`
//! is not — and the sweep here runs in the namespace scope, narrowed to this test's mark.

use std::io::Write as _;
use std::os::unix::process::CommandExt;
use std::path::Path;
use std::process::Command as Proc;
use std::sync::Arc;
use std::time::{Duration, Instant};

use sealant_capture::{
    BlobSink, CaptureConfig, CaptureEngine, InMemoryRegistrar, LocalDir, Registrar,
};
use sealant_control::{read_frame, write_frame};
use sealant_protocol::{
    CaptureFlushKind, ClientMessage, Command, CommandResult, ControlRequest, EnvVar, ExecArgs,
    RequestId, ResponseOutcome, ServerMessage, decode_server, encode_client,
};
use sealant_runtime_core::{RuntimeConfig, new_runtime_id};
use sealantd::boot::capture::{CaptureBoot, SourceLayout};
use sealantd::capture::CaptureRuntime;
use sealantd::runtime::SWEEP_MARK_ENV;
use sealantd::sweep::Scope;
use sealantd::{Runtime, ShutdownSignal};

/// Set in the relay process: `<control socket>\n<front socket>`.
const RELAY_ENV: &str = "SEALANTD_TEST_RELAY";

fn git(root: &Path, args: &[&str]) {
    let out = Proc::new("git")
        .current_dir(root)
        .env("GIT_OPTIONAL_LOCKS", "0")
        .args(args)
        .output()
        .expect("git");
    assert!(out.status.success(), "git {args:?}");
}

fn boot(base: &Path) -> CaptureBoot {
    let root = base.join("ws");
    std::fs::create_dir_all(root.join("src")).unwrap();
    git(&root, &["init", "-q", "-b", "main"]);
    git(&root, &["config", "user.email", "t@t"]);
    git(&root, &["config", "user.name", "t"]);
    std::fs::write(root.join("src/lib.rs"), "pub fn f() {}\n").unwrap();
    git(&root, &["add", "-A"]);
    git(&root, &["commit", "-q", "-m", "one"]);
    let registrar: Arc<dyn Registrar> = Arc::new(InMemoryRegistrar::new("wt-peer", 1, None));
    let sink: Arc<dyn BlobSink> = Arc::new(LocalDir::new(&base.join("store")).unwrap());
    let engine = CaptureEngine::open(CaptureConfig::new("wt-peer", 1, &root), None).unwrap();
    CaptureBoot {
        engine,
        sink,
        registrar,
        minter: None,
        worktree_id: "wt-peer".to_owned(),
        epoch: 1,
        layout: SourceLayout {
            workspace_root: base.to_path_buf(),
            working_directory: root.clone(),
            staging_dir: root.join(".sealantd/capture"),
        },
        resumed: false,
    }
}

/// Not a test of its own: the relay's body, run by this binary re-executed with [`RELAY_ENV`]
/// set (`socat - UNIX-CONNECT:…` in miniature). It connects to the front socket the test
/// listens on, then to the control socket (once it exists), and copies bytes both ways.
#[test]
fn relay_process() {
    let Ok(spec) = std::env::var(RELAY_ENV) else {
        return;
    };
    let (control, front) = spec.split_once('\n').expect("two paths");
    let connect = |path: &str| {
        let start = Instant::now();
        loop {
            match std::os::unix::net::UnixStream::connect(path) {
                Ok(stream) => return stream,
                Err(_) if start.elapsed() < Duration::from_secs(60) => {
                    std::thread::sleep(Duration::from_millis(20));
                }
                Err(error) => panic!("relay: connect {path}: {error}"),
            }
        }
    };
    let front = connect(front);
    let control = connect(control);
    let (mut front_in, mut control_out) =
        (front.try_clone().unwrap(), control.try_clone().unwrap());
    std::thread::spawn(move || {
        let _ = std::io::copy(&mut front_in, &mut control_out);
        let _ = control_out.shutdown(std::net::Shutdown::Write);
    });
    let (mut control_in, mut front_out) = (control, front);
    let _ = std::io::copy(&mut control_in, &mut front_out);
    let _ = front_out.flush();
    std::process::exit(0);
}

/// Kills what the test orphaned, whatever happened.
struct Reap(Vec<i32>);

impl Drop for Reap {
    fn drop(&mut self) {
        for pid in &self.0 {
            let _ = Proc::new("kill")
                .args(["-9", &pid.to_string()])
                .stderr(std::process::Stdio::null())
                .status();
        }
    }
}

fn alive(pid: i32) -> bool {
    std::fs::read_to_string(format!("/proc/{pid}/stat")).is_ok_and(|stat| {
        !matches!(
            stat.rsplit(')')
                .next()
                .and_then(|r| r.trim().chars().next()),
            Some('Z' | 'X')
        )
    })
}

fn ppid(pid: i32) -> i32 {
    let stat = std::fs::read_to_string(format!("/proc/{pid}/stat")).unwrap();
    stat.rsplit(')')
        .next()
        .unwrap()
        .split_whitespace()
        .nth(1)
        .unwrap()
        .parse()
        .unwrap()
}

/// Start `script` under `/bin/sh` in a process group of its own, orphaning what it puts in
/// the background (the shell exits at once), and return the pid it writes to `pid_file`.
fn orphan(script: &str, args: &[&Path], env: &[(&str, String)], pid_file: &Path) -> i32 {
    let mut cmd = Proc::new("/bin/sh");
    cmd.arg("-c").arg(script).args(args).process_group(0);
    for (key, value) in env {
        cmd.env(key, value);
    }
    assert!(cmd.status().unwrap().success());
    std::fs::read_to_string(pid_file)
        .unwrap()
        .trim()
        .parse()
        .unwrap()
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_final_flush_spares_the_relay_carrying_its_reply() {
    let tmp = tempfile::tempdir().unwrap();
    let base = tmp.path();
    let mark = format!("control-peer-{}", std::process::id());
    let control_sock = base.join("control.sock");
    let front_sock = base.join("front.sock");
    let front = std::os::unix::net::UnixListener::bind(&front_sock).unwrap();

    // Both orphaned before this process becomes a subreaper: neither is sealantd's descendant.
    let exe = std::env::current_exe().unwrap();
    let relay_pid_file = base.join("relay.pid");
    let relay = orphan(
        r#""$0" relay_process --exact --nocapture --test-threads=1 >/dev/null 2>&1 & echo $! > "$1""#,
        &[&exe, &relay_pid_file],
        &[
            (
                RELAY_ENV,
                format!("{}\n{}", control_sock.display(), front_sock.display()),
            ),
            (SWEEP_MARK_ENV, mark.clone()),
        ],
        &relay_pid_file,
    );
    // A bystander in the same scope, holding no control connection: the sweep stops it.
    let bystander_pid_file = base.join("bystander.pid");
    let bystander = orphan(
        r#"sleep 3600 & echo $! > "$0""#,
        &[&bystander_pid_file],
        &[(SWEEP_MARK_ENV, mark.clone())],
        &bystander_pid_file,
    );
    let _reap = Reap(vec![relay, bystander]);
    let me = i32::try_from(std::process::id()).unwrap();
    assert_ne!(ppid(relay), me, "the relay is not this process's child");
    let (front, _) = front.accept().unwrap();
    front.set_nonblocking(true).unwrap();
    let mut front = tokio::net::UnixStream::from_std(front).unwrap();

    let mut config = RuntimeConfig::new(new_runtime_id());
    config.workspace_root = base.join("ws");
    let runtime = Runtime::new(config, Arc::new(ShutdownSignal::new(5_000)));
    runtime.mark_healthy();
    runtime.set_sweep_mark(Some(mark));
    runtime.set_sweep_scope_for_test(Scope::Namespace);
    let capture = CaptureRuntime::new(boot(base));
    assert!(runtime.install_capture(capture.clone()));
    let harness = runtime
        .spawn_managed(ExecArgs {
            execution_id: None,
            session_id: None,
            executable: "/bin/sh".to_owned(),
            args: vec!["-c".to_owned(), "exec sleep 3600".to_owned()],
            cwd: Some(base.join("ws").display().to_string()),
            env: vec![EnvVar {
                key: "PATH".to_owned(),
                value: std::env::var("PATH").unwrap_or_default(),
            }],
            stdin: false,
            attach: false,
            timeout_millis: None,
            background: false,
            capture: None,
            graceful_signal: None,
        })
        .expect("spawn");
    capture.start(runtime.clone(), harness.process_id);
    let (_stop, stopped) = tokio::sync::watch::channel(false);
    let serving = runtime.clone();
    let socket = control_sock.clone();
    tokio::spawn(async move {
        sealant_control::serve_unix(serving, &socket, Vec::new(), stopped).await
    });

    let request = ControlRequest::new(
        RequestId::new("final"),
        Command::CaptureFlush {
            kind: CaptureFlushKind::Final,
            deadline_ms: None,
            grace_ms: Some(2_000),
        },
    );
    write_frame(
        &mut front,
        &encode_client(&ClientMessage::Request(request)),
        16 << 20,
    )
    .await
    .unwrap();
    let report = loop {
        let frame = tokio::time::timeout(Duration::from_secs(60), read_frame(&mut front, 16 << 20))
            .await
            .expect("an answer within a minute")
            .expect("a frame");
        let Some(body) = frame else {
            panic!("the connection carrying the final flush closed before its reply");
        };
        if let ServerMessage::Response(response) = decode_server(&body).unwrap() {
            match response.outcome {
                ResponseOutcome::Ok {
                    result: Some(CommandResult::CaptureStatus(report)),
                } => break report,
                other => panic!("capture.flush: {other:?}"),
            }
        }
    };
    assert!(report.complete, "{report:?}");
    assert!(alive(relay), "the relay carrying the reply was spared");
    assert!(
        !alive(bystander),
        "the sweep ran over the namespace: the bystander is stopped"
    );
    assert_eq!(runtime.health_report().active_processes, 0);
    drop(front);
    let start = Instant::now();
    while alive(relay) && start.elapsed() < Duration::from_secs(10) {
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    assert!(!alive(relay), "the relay ends once its connection closes");
}
