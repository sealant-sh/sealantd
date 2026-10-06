//! Running as a user (Mend's ADR 0016, step 5): `exec` and `openSession` with a `user` start the
//! process as exactly that user (uid, primary and supplementary groups, the passwd `HOME`,
//! `USER`, `LOGNAME` and `SHELL`, umask `0002`, a private `TMPDIR` and `XDG_RUNTIME_DIR`), and
//! every child inherits it; `dotfiles.apply` writes a person's dotfiles into their home as them
//! and answers before their `./install.sh` ends, which runs as them.
//!
//! These need root and real users: they add a group and two users to the passwd database, so
//! they run only with `SEALANTD_REQUIRE_ROOT_TESTS=1`, as root (CI runs them under sudo; locally,
//! in a container).

use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};
use std::process::Command as Std;
use std::sync::Arc;
use std::time::{Duration, Instant};

use sealant_control::{handle_connection, read_frame, write_frame};
use sealant_protocol::{
    ClientMessage, Command, CommandResult, ControlRequest, ControlResponse, DotfilesApplyArgs,
    ExecArgs, OpenSessionArgs, RequestId, ResponseOutcome, ServerMessage, SessionMode,
};
use sealant_runtime_core::{RuntimeConfig, new_runtime_id};
use sealantd::Runtime;
use sealantd::shutdown::ShutdownSignal;
use tokio::io::{DuplexStream, ReadHalf, WriteHalf};
use tokio::sync::watch;

const MAX: u32 = 8 * 1024 * 1024;
const GROUP: &str = "mtestgrp";
const GID: u32 = 40970;
const EXTRA_GROUP: &str = "mtestextra";
const EXTRA_GID: u32 = 40971;
const BOB: &str = "mtestbob";
const BOB_UID: u32 = 40972;

/// Whether these run here: as root with `SEALANTD_REQUIRE_ROOT_TESTS=1`. They make the test
/// group and users once.
fn ready() -> bool {
    if std::env::var("SEALANTD_REQUIRE_ROOT_TESTS").as_deref() != Ok("1") {
        eprintln!("SEALANTD_REQUIRE_ROOT_TESTS is not 1: run-as-user tests skipped");
        return false;
    }
    assert!(
        nix::unistd::geteuid().is_root(),
        "SEALANTD_REQUIRE_ROOT_TESTS=1 but not running as root"
    );
    static USERS: std::sync::Once = std::sync::Once::new();
    USERS.call_once(|| {
        let run = |args: &[&str]| {
            let out = Std::new(args[0]).args(&args[1..]).output().unwrap();
            let err = String::from_utf8_lossy(&out.stderr);
            assert!(
                out.status.success() || err.contains("already exists"),
                "{args:?}: {err}"
            );
        };
        run(&["groupadd", "-g", &GID.to_string(), GROUP]);
        run(&["groupadd", "-g", &EXTRA_GID.to_string(), EXTRA_GROUP]);
        run(&[
            "useradd",
            "-m",
            "-u",
            &BOB_UID.to_string(),
            "-g",
            GROUP,
            "-G",
            EXTRA_GROUP,
            "-s",
            "/bin/sh",
            BOB,
        ]);
    });
    true
}

struct Client {
    reader: ReadHalf<DuplexStream>,
    writer: WriteHalf<DuplexStream>,
    next: u32,
    /// Processes whose `process.exited` passed while a response was awaited.
    exited: std::collections::HashSet<sealant_protocol::ProcessId>,
    _conn: tokio::task::JoinHandle<()>,
}

impl Client {
    fn start(workspace: &Path) -> Self {
        Self::start_with(workspace, Vec::new())
    }

    /// With `child_env`: the daemon's child environment (the passthrough of PID 1's).
    fn start_with(workspace: &Path, child_env: Vec<sealant_protocol::EnvVar>) -> Self {
        let mut config = RuntimeConfig::new(new_runtime_id());
        config.workspace_root = workspace.to_path_buf();
        config.child_env = child_env;
        let runtime = Runtime::new(config, Arc::new(ShutdownSignal::new(1000)));
        runtime.mark_healthy();
        let (_sd_tx, sd_rx) = watch::channel(false);
        let (client, server) = tokio::io::duplex(1 << 20);
        let (server_read, server_write) = tokio::io::split(server);
        let conn = tokio::spawn(async move {
            let _keep = _sd_tx;
            handle_connection(runtime, server_read, server_write, sd_rx).await;
        });
        let (reader, writer) = tokio::io::split(client);
        Self {
            reader,
            writer,
            next: 0,
            exited: std::collections::HashSet::new(),
            _conn: conn,
        }
    }

    /// Send `command` and answer its response, passing over events.
    async fn request(&mut self, command: Command) -> ControlResponse {
        self.next += 1;
        let id = RequestId::new(format!("r{}", self.next));
        let body = sealant_protocol::encode_client(&ClientMessage::Request(ControlRequest::new(
            id.clone(),
            command,
        )));
        write_frame(&mut self.writer, &body, MAX).await.unwrap();
        let wait = async {
            loop {
                let body = read_frame(&mut self.reader, MAX).await.unwrap().unwrap();
                match sealant_protocol::decode_server(&body).unwrap() {
                    ServerMessage::Response(r) if r.request_id == id => return r,
                    ServerMessage::Event(e) => {
                        if let (sealant_protocol::EventPayload::ProcessExited(_), Some(p)) =
                            (&e.payload, e.process_id)
                        {
                            self.exited.insert(p);
                        }
                    }
                    _ => {}
                }
            }
        };
        tokio::time::timeout(Duration::from_secs(30), wait)
            .await
            .expect("a response")
    }
}

impl Client {
    /// Wait for `process`'s `process.exited`.
    async fn exited(&mut self, process: &sealant_protocol::ProcessId) {
        if self.exited.remove(process) {
            return;
        }
        loop {
            let body = read_frame(&mut self.reader, MAX).await.unwrap().unwrap();
            if let ServerMessage::Event(e) = sealant_protocol::decode_server(&body).unwrap()
                && let sealant_protocol::EventPayload::ProcessExited(_) = e.payload
                && e.process_id.as_ref() == Some(process)
            {
                return;
            }
        }
    }
}

fn ok(response: ControlResponse) -> Option<CommandResult> {
    match response.outcome {
        ResponseOutcome::Ok { result } => result,
        ResponseOutcome::Error { error } => panic!("refused: {error:?}"),
    }
}

/// The file `path` once something wrote it (polls for up to 20 s).
fn wait_for(path: &Path) -> String {
    let start = Instant::now();
    loop {
        if let Ok(text) = std::fs::read_to_string(path)
            && text.ends_with('\n')
        {
            return text;
        }
        assert!(
            start.elapsed() < Duration::from_secs(20),
            "{} never written",
            path.display()
        );
        std::thread::sleep(Duration::from_millis(20));
    }
}

/// A scratch directory every user can write into.
fn scratch() -> tempfile::TempDir {
    let dir = tempfile::tempdir().unwrap();
    std::fs::set_permissions(
        dir.path(),
        std::os::unix::fs::PermissionsExt::from_mode(0o1777),
    )
    .unwrap();
    dir
}

/// The identity a shell sees, one field per line, written to `out` by the process and by a
/// grandchild (what a child inherits).
fn identity_script(out: &Path) -> String {
    format!(
        "{{ id -u; id -g; id -G | tr ' ' '\\n' | sort -n | tr '\\n' ' '; echo; \
         echo \"$HOME|$USER|$LOGNAME|$SHELL|$TMPDIR|$XDG_RUNTIME_DIR\"; umask; \
         stat -c '%U %a' \"$TMPDIR\" \"$XDG_RUNTIME_DIR\"; sh -c 'id -u'; }} > {}.tmp && mv {0}.tmp {0}",
        out.display()
    )
}

fn expected_identity() -> String {
    format!(
        "{BOB_UID}\n{GID}\n{GID} {EXTRA_GID} \n/home/{BOB}|{BOB}|{BOB}|/bin/sh|/tmp/u-{BOB_UID}|/run/user/{BOB_UID}\n0002\n{BOB} 700\n{BOB} 700\n{BOB_UID}\n"
    )
}

fn exec(script: String, user: Option<&str>) -> ExecArgs {
    ExecArgs {
        user: user.map(str::to_owned),
        execution_id: None,
        session_id: None,
        executable: "/bin/sh".to_owned(),
        args: vec!["-c".to_owned(), script],
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

/// An execution with a user runs as exactly that user, by name or by uid, and its children
/// inherit it; one without runs as root; an unknown user or root is refused.
#[tokio::test]
async fn an_execution_runs_as_the_user_it_names() {
    if !ready() {
        return;
    }
    let dir = scratch();
    let mut client = Client::start(dir.path());
    for (name, user) in [("by-name", BOB.to_owned()), ("by-uid", BOB_UID.to_string())] {
        let out = dir.path().join(name);
        ok(client
            .request(Command::Exec(exec(identity_script(&out), Some(&user))))
            .await);
        assert_eq!(wait_for(&out), expected_identity(), "{name}");
    }
    let out = dir.path().join("as-root");
    ok(client
        .request(Command::Exec(exec(
            format!("id -u > {}", out.display()),
            None,
        )))
        .await);
    assert_eq!(wait_for(&out), "0\n");

    for refused in ["root", "0", "no-such-user-here"] {
        let response = client
            .request(Command::Exec(exec("true".to_owned(), Some(refused))))
            .await;
        assert!(
            matches!(response.outcome, ResponseOutcome::Error { .. }),
            "{refused} was not refused"
        );
    }
}

/// A session's leader runs as its user too, in both shapes; a PTY leader owns its terminal.
#[tokio::test]
async fn a_session_runs_as_the_user_it_names() {
    if !ready() {
        return;
    }
    let dir = scratch();
    let mut client = Client::start(dir.path());
    for (name, mode) in [("pipe", SessionMode::Pipe), ("pty", SessionMode::Pty)] {
        let out = dir.path().join(name);
        let tty = dir.path().join(format!("{name}-tty"));
        let script = match mode {
            SessionMode::Pty => format!(
                "stat -c %U \"$(tty)\" > {0}.tmp && mv {0}.tmp {0}; {1}",
                tty.display(),
                identity_script(&out)
            ),
            SessionMode::Pipe => identity_script(&out),
        };
        ok(client
            .request(Command::OpenSession(OpenSessionArgs {
                user: Some(BOB.to_owned()),
                execution_id: None,
                shell: Some("/bin/sh".to_owned()),
                args: vec!["-c".to_owned(), script],
                cwd: None,
                env: vec![],
                cols: 80,
                rows: 24,
                term: None,
                mode,
            }))
            .await);
        assert_eq!(wait_for(&out), expected_identity(), "{name}");
        if mode == SessionMode::Pty {
            assert_eq!(wait_for(&tty), format!("{BOB}\n"));
        }
    }
}

/// `dotfiles.apply` writes the files into the user's home as theirs, answers once they are
/// applied, and runs `./install.sh` after, as the user, as a managed process it names.
#[tokio::test]
async fn dotfiles_apply_as_the_user_and_answer_before_install_sh_ends() {
    if !ready() {
        return;
    }
    let dir = scratch();
    let home = PathBuf::from(format!("/home/{BOB}"));
    let _ = std::fs::remove_file(home.join(".mtest-zshrc"));
    let evidence = dir.path().join("install-ran");
    let gate = dir.path().join("install-may-finish");
    // A dotfiles tree with a file, a nested file, a symlink and an install.sh that waits.
    let tree = dir.path().join("tree");
    std::fs::create_dir_all(tree.join(".config/mtest")).unwrap();
    std::fs::write(tree.join(".mtest-zshrc"), "export A=1\n").unwrap();
    std::fs::write(tree.join(".config/mtest/conf"), "x\n").unwrap();
    std::os::unix::fs::symlink(".mtest-zshrc", tree.join(".mtest-link")).unwrap();
    std::fs::write(
        tree.join("install.sh"),
        format!(
            "#!/bin/sh\nwhile [ ! -e {gate} ]; do sleep 0.05; done\n\
             {{ id -u; echo \"$HOME\"; touch \"$HOME/.mtest-made-by-install\"; }} > {ev}.tmp && mv {ev}.tmp {ev}\n",
            gate = gate.display(),
            ev = evidence.display()
        ),
    )
    .unwrap();
    std::fs::set_permissions(
        tree.join("install.sh"),
        std::os::unix::fs::PermissionsExt::from_mode(0o755),
    )
    .unwrap();
    let archives = dir.path().join("archives");
    std::fs::create_dir_all(&archives).unwrap();
    assert!(
        Std::new("tar")
            .arg("-czf")
            .arg(archives.join("0.tar.gz"))
            .arg("-C")
            .arg(&tree)
            .arg(".")
            .status()
            .unwrap()
            .success()
    );
    std::fs::write(
        archives.join("manifest.json"),
        r#"{"archives":[{"file":"0.tar.gz","manager":"copy"}]}"#,
    )
    .unwrap();

    let mut client = Client::start(dir.path());
    let started = Instant::now();
    let applied = match ok(client
        .request(Command::DotfilesApply(Box::new(DotfilesApplyArgs {
            user: BOB.to_owned(),
            repository: None,
            archive_dir: Some(archives.display().to_string()),
            execution_id: None,
        })))
        .await)
    {
        Some(CommandResult::DotfilesApplied(applied)) => applied,
        other => panic!("expected dotfilesApplied, got {other:?}"),
    };
    // Answered with the files in place, while install.sh still waits.
    assert!(started.elapsed() < Duration::from_secs(15));
    assert_eq!(applied.user, BOB);
    assert_eq!(applied.home, home.display().to_string());
    assert!(applied.bootstrap.is_some(), "install.sh is named");
    assert!(!evidence.exists(), "the answer waited for install.sh");
    for path in [
        ".mtest-zshrc",
        ".config/mtest/conf",
        ".config/mtest",
        ".mtest-link",
    ] {
        let meta = std::fs::symlink_metadata(home.join(path)).unwrap();
        assert_eq!((meta.uid(), meta.gid()), (BOB_UID, GID), "{path}");
    }
    let staging = home.join(".local/share/sealant-dotfiles/0/install.sh");
    assert_eq!(std::fs::metadata(&staging).unwrap().uid(), BOB_UID);

    std::fs::write(&gate, "").unwrap();
    assert_eq!(
        wait_for(&evidence),
        format!("{BOB_UID}\n{}\n", home.display())
    );
    assert_eq!(
        std::fs::metadata(home.join(".mtest-made-by-install"))
            .unwrap()
            .uid(),
        BOB_UID
    );

    // A user the passwd database does not have, or neither source, is refused.
    for args in [
        DotfilesApplyArgs {
            user: "no-such-user-here".to_owned(),
            repository: None,
            archive_dir: Some(archives.display().to_string()),
            execution_id: None,
        },
        DotfilesApplyArgs {
            user: BOB.to_owned(),
            repository: None,
            archive_dir: None,
            execution_id: None,
        },
    ] {
        let response = client.request(Command::DotfilesApply(Box::new(args))).await;
        assert!(matches!(response.outcome, ResponseOutcome::Error { .. }));
    }
}

/// The spawn path's cost: `exec` of `/bin/true` to its `process.exited`, 300 times each, without
/// a user and as a user (the lookup, the private directories and the identity calls in the
/// child). A measurement, run by hand:
/// `SEALANTD_REQUIRE_ROOT_TESTS=1 run_as_user --ignored --nocapture spawn_timing`.
#[tokio::test]
#[ignore = "a measurement"]
async fn spawn_timing() {
    if !ready() {
        return;
    }
    let dir = scratch();
    let mut client = Client::start(dir.path());
    for round in 0..2 {
        for user in [None, Some(BOB)] {
            let mut times = Vec::new();
            for _ in 0..300 {
                let mut args = exec(String::new(), user);
                args.executable = "/bin/true".to_owned();
                args.args = Vec::new();
                let started = Instant::now();
                let Some(CommandResult::ExecAccepted(accepted)) =
                    ok(client.request(Command::Exec(args)).await)
                else {
                    panic!("not accepted");
                };
                client.exited(&accepted.process_id).await;
                times.push(started.elapsed().as_secs_f64() * 1000.0);
            }
            times.sort_by(f64::total_cmp);
            eprintln!(
                "round {round}, user {user:?}: median {:.2} ms, p90 {:.2} ms, min {:.2} ms",
                times[times.len() / 2],
                times[times.len() * 9 / 10],
                times[0]
            );
        }
    }
}

fn var(key: &str, value: &str) -> sealant_protocol::EnvVar {
    sealant_protocol::EnvVar {
        key: key.to_owned(),
        value: value.to_owned(),
    }
}

/// The daemon's environment carries the launcher's tokens and its own keys: a process run as a
/// person sees none of them (exec and session alike), keeps what is not a secret, and gets what
/// the caller names explicitly; a process run as root still gets them.
#[tokio::test]
async fn a_person_s_process_inherits_no_token_and_no_daemon_key() {
    if !ready() {
        return;
    }
    let dir = scratch();
    let leaks = [
        "GH_TOKEN",
        "GITHUB_TOKEN",
        "CLAUDE_CODE_OAUTH_TOKEN",
        "SEALANT_DOTFILES_HTTP_TOKEN",
        "SEALANT_CAPTURE_ENDPOINT",
        "NPM_TOKEN",
        "SSH_AUTH_SOCK",
        "XDG_CONFIG_HOME",
    ];
    let mut child_env: Vec<_> = leaks.iter().map(|k| var(k, "launcher-value")).collect();
    child_env.push(var("KEEP_ME", "1"));
    let mut client = Client::start_with(dir.path(), child_env);
    let dump = |out: &Path| {
        format!(
            "env > {0}.tmp && echo end >> {0}.tmp && mv {0}.tmp {0}",
            out.display()
        )
    };

    let mut args = exec(dump(&dir.path().join("person")), Some(BOB));
    args.env = vec![var("EXPLICIT", "1")];
    ok(client.request(Command::Exec(args)).await);
    let person = wait_for(&dir.path().join("person"));
    ok(client
        .request(Command::OpenSession(OpenSessionArgs {
            user: Some(BOB.to_owned()),
            execution_id: None,
            shell: Some("/bin/sh".to_owned()),
            args: vec!["-c".to_owned(), dump(&dir.path().join("session"))],
            cwd: None,
            env: vec![],
            cols: 80,
            rows: 24,
            term: None,
            mode: SessionMode::Pipe,
        }))
        .await);
    let session = wait_for(&dir.path().join("session"));
    for (name, env) in [("exec", &person), ("session", &session)] {
        for leak in leaks {
            assert!(
                !env.lines().any(|l| l.starts_with(&format!("{leak}="))),
                "{name}: {leak} reached the person:\n{env}"
            );
        }
        assert!(env.lines().any(|l| l == "KEEP_ME=1"), "{name}:\n{env}");
        assert!(env.lines().any(|l| l == format!("USER={BOB}")), "{name}");
    }
    assert!(person.lines().any(|l| l == "EXPLICIT=1"));

    ok(client
        .request(Command::Exec(exec(dump(&dir.path().join("root")), None)))
        .await);
    let root = wait_for(&dir.path().join("root"));
    assert!(
        root.lines().any(|l| l == "GH_TOKEN=launcher-value"),
        "{root}"
    );
}

/// The dotfiles commands a person's apply runs (here chezmoi, a stand-in that writes its
/// environment) get a clean environment: none of the daemon's own `SEALANT_*` secrets or the
/// launcher's tokens, from PID 1's environment.
#[tokio::test]
async fn a_person_s_dotfiles_commands_get_a_clean_environment() {
    if !ready() {
        return;
    }
    let dir = scratch();
    let evidence = dir.path().join("chezmoi-env");
    let bin = dir.path().join("bin");
    std::fs::create_dir_all(&bin).unwrap();
    std::fs::write(
        bin.join("chezmoi"),
        format!(
            "#!/bin/sh\nenv > {0}.tmp && id -u >> {0}.tmp && mv {0}.tmp {0}\n",
            evidence.display()
        ),
    )
    .unwrap();
    std::fs::set_permissions(
        bin.join("chezmoi"),
        std::os::unix::fs::PermissionsExt::from_mode(0o755),
    )
    .unwrap();
    // SAFETY: this binary runs its tests on one thread when root (scripts/ci-root-tests.sh), and
    // nothing else reads the environment while it is set.
    unsafe {
        std::env::set_var(
            "PATH",
            format!(
                "{}:{}",
                bin.display(),
                std::env::var("PATH").unwrap_or_default()
            ),
        );
        std::env::set_var("SEALANT_DOTFILES_HTTP_TOKEN", "daemon-secret");
        std::env::set_var("GH_TOKEN", "launcher-token");
    }
    let tree = dir.path().join("tree");
    std::fs::create_dir_all(&tree).unwrap();
    std::fs::write(tree.join("dot_mtestrc"), "x\n").unwrap();
    let archives = dir.path().join("archives");
    std::fs::create_dir_all(&archives).unwrap();
    assert!(
        Std::new("tar")
            .arg("-czf")
            .arg(archives.join("0.tar.gz"))
            .arg("-C")
            .arg(&tree)
            .arg(".")
            .status()
            .unwrap()
            .success()
    );
    std::fs::write(
        archives.join("manifest.json"),
        r#"{"archives":[{"file":"0.tar.gz","manager":"chezmoi","bootstrap":false}]}"#,
    )
    .unwrap();
    let mut client = Client::start(dir.path());
    ok(client
        .request(Command::DotfilesApply(Box::new(DotfilesApplyArgs {
            user: BOB.to_owned(),
            repository: None,
            archive_dir: Some(archives.display().to_string()),
            execution_id: None,
        })))
        .await);
    let env = std::fs::read_to_string(&evidence).expect("chezmoi ran");
    // SAFETY: as above.
    unsafe {
        std::env::remove_var("SEALANT_DOTFILES_HTTP_TOKEN");
        std::env::remove_var("GH_TOKEN");
    }
    assert!(
        env.ends_with(&format!("{BOB_UID}\n")),
        "chezmoi ran as the person:\n{env}"
    );
    assert!(!env.contains("daemon-secret"), "{env}");
    assert!(!env.contains("launcher-token"), "{env}");
    assert!(!env.lines().any(|l| l.starts_with("SEALANT_")), "{env}");
    assert!(
        env.lines().any(|l| l == format!("HOME=/home/{BOB}")),
        "{env}"
    );
}
