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
        Self::start_withholding(workspace, child_env, Vec::new())
    }

    /// With `child_env` and the injector's declared harness keys (`person_withheld`), as a
    /// per-person executor's daemon: no no-new-privileges (a boot under an owner map).
    fn start_withholding(
        workspace: &Path,
        child_env: Vec<sealant_protocol::EnvVar>,
        person_withheld: Vec<String>,
    ) -> Self {
        Self::start_posture(workspace, child_env, person_withheld, false)
    }

    /// With the daemon's no-new-privileges posture given (`true`: every executor but a
    /// per-person one). Setting it is irreversible on the calling thread.
    fn start_posture(
        workspace: &Path,
        child_env: Vec<sealant_protocol::EnvVar>,
        person_withheld: Vec<String>,
        no_new_privileges: bool,
    ) -> Self {
        let mut config = RuntimeConfig::new(new_runtime_id());
        config.workspace_root = workspace.to_path_buf();
        config.child_env = child_env;
        config.person_withheld = person_withheld;
        config.no_new_privileges = no_new_privileges;
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
    // Someone else (root here) made the user's private TMPDIR, and planted something in it: it
    // is emptied and given to the user.
    let squat = PathBuf::from(format!("/tmp/u-{BOB_UID}"));
    let _ = std::fs::remove_dir_all(&squat);
    std::fs::create_dir_all(&squat).unwrap();
    std::fs::write(squat.join("planted"), "x").unwrap();
    let mut client = Client::start(dir.path());
    for (name, user) in [("by-name", BOB.to_owned()), ("by-uid", BOB_UID.to_string())] {
        let out = dir.path().join(name);
        ok(client
            .request(Command::Exec(exec(identity_script(&out), Some(&user))))
            .await);
        assert_eq!(wait_for(&out), expected_identity(), "{name}");
    }
    assert!(!squat.join("planted").exists(), "a planted file stayed");
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
        "SSH_AUTH_SOCK",
        "XDG_CONFIG_HOME",
        "DECLARED_LOGIN",
    ];
    let mut child_env: Vec<_> = leaks.iter().map(|k| var(k, "launcher-value")).collect();
    child_env.push(var("KEEP_ME", "1"));
    // The project's secrets, as the launcher's secret environment puts them in the daemon's
    // child environment: the project's, so they reach every person.
    let project = [
        ("NPM_TOKEN", "npm-secret"),
        ("STRIPE_SECRET_KEY", "sk"),
        ("DATABASE_PASSWORD", "pw"),
    ];
    child_env.extend(project.iter().map(|(k, v)| var(k, v)));
    let mut client =
        Client::start_withholding(dir.path(), child_env, vec!["DECLARED_LOGIN".to_owned()]);
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
        for (key, value) in project {
            assert!(
                env.lines().any(|l| l == format!("{key}={value}")),
                "{name}: the project's {key} did not reach the person:\n{env}"
            );
        }
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

/// A person's process holds exactly one capability, `CAP_FOWNER`, ambient (so the programs it
/// runs keep it), and no secure-exec mode (the loader keeps `LD_LIBRARY_PATH`): it can `chmod` a
/// root-owned file in a shared worktree, as `sudo` already lets it. Under no-new-privileges,
/// where `sudo` cannot work and the capability would amount to root, it holds none, and
/// `runtime.getCapabilities` says why.
#[tokio::test]
async fn a_person_s_process_holds_cap_fowner_and_nothing_else() {
    if !ready() {
        return;
    }
    let dir = scratch();
    let owned = dir.path().join("roots-file");
    std::fs::write(&owned, "x").unwrap();
    std::fs::set_permissions(&owned, std::os::unix::fs::PermissionsExt::from_mode(0o644)).unwrap();
    let out = dir.path().join("caps");
    let mut args = exec(
        format!(
            "{{ grep -E '^Cap(Inh|Prm|Eff|Amb)' /proc/self/status; sh -c 'grep ^CapAmb /proc/self/status'; \
             chmod 664 {f} && echo chmod-ok; echo \"ld=$LD_LIBRARY_PATH\"; }} > {o}.tmp && mv {o}.tmp {o}",
            f = owned.display(),
            o = out.display()
        ),
        Some(BOB),
    );
    args.env = vec![var("LD_LIBRARY_PATH", "/opt/x")];
    let mut client = Client::start(dir.path());
    let caps = match ok(client.request(Command::RuntimeGetCapabilities).await) {
        Some(CommandResult::Capabilities(c)) => c,
        other => panic!("capabilities: {other:?}"),
    };
    ok(client.request(Command::Exec(args)).await);
    let seen = wait_for(&out);
    // The daemon reports what its children inherit: sealantd sets no-new-privileges on itself
    // (plan §18), as an orchestrator may, and then a person holds no CAP_FOWNER.
    if let Some(reason) = &caps.person_capabilities_withheld {
        assert!(caps.person_capabilities.is_empty(), "{caps:?}");
        assert!(reason.contains("no-new-privileges"), "{caps:?}");
        for line in [
            "CapInh:\t0000000000000000",
            "CapPrm:\t0000000000000000",
            "CapEff:\t0000000000000000",
            "CapAmb:\t0000000000000000",
        ] {
            assert!(seen.lines().any(|l| l == line), "{line} missing:\n{seen}");
        }
        assert!(!seen.lines().any(|l| l == "chmod-ok"), "{seen}");
        return;
    }
    assert_eq!(caps.person_capabilities, ["CAP_FOWNER"], "{caps:?}");
    assert_eq!(caps.person_capabilities_withheld, None);
    for line in [
        "CapInh:\t0000000000000008",
        "CapPrm:\t0000000000000008",
        "CapEff:\t0000000000000008",
        "CapAmb:\t0000000000000008",
    ] {
        assert!(seen.lines().any(|l| l == line), "{line} missing:\n{seen}");
    }
    assert_eq!(
        seen.lines()
            .filter(|l| *l == "CapAmb:\t0000000000000008")
            .count(),
        2,
        "a child keeps it:\n{seen}"
    );
    assert!(seen.lines().any(|l| l == "chmod-ok"), "{seen}");
    assert!(
        seen.lines().any(|l| l == "ld=/opt/x"),
        "secure-exec mode:\n{seen}"
    );
    assert_eq!(std::fs::metadata(&owned).unwrap().mode() & 0o777, 0o664);
}

/// The reason for `CAP_FOWNER`: in a restored worktree (its files root's, the group's to write)
/// a second person, not the change's owner, runs `pnpm install` after a lockfile change that
/// keeps a restored package with a bin (pnpm rewrites the shim and `chmod`s it), then
/// `pnpm install --force`, through sealantd's own exec as that person. Without the capability the
/// first fails with `ERR_PNPM_CMD_SHIM_CHMOD`, which is what a daemon under no-new-privileges
/// gives (sealantd sets it on itself, plan §18); `owner_map.rs` covers the capability's success
/// path without it. Needs network and pnpm.
#[tokio::test]
async fn pnpm_installs_as_a_second_person_in_a_restored_worktree() {
    use sealant_capture::{
        CaptureConfig, CaptureEngine, CaptureKind, Class, InMemoryRegistrar, LocalDir,
        MaterializeClass, MaterializeTargets, Materializer, SnapRequest,
    };
    if !ready() {
        return;
    }
    if Std::new("pnpm").arg("--version").output().is_err() {
        panic!("pnpm is required for this test (scripts/ci-root-tests.sh installs it)");
    }
    let dir = scratch();
    let base = dir.path();
    let git = |root: &Path, args: &[&str]| {
        let out = Std::new("git")
            .current_dir(root)
            .args(args)
            .output()
            .unwrap();
        assert!(out.status.success(), "git {args:?}");
    };
    // A store the group shares, as the images keep it under /var/cache.
    let store = base.join("pnpm-store");
    std::fs::create_dir_all(&store).unwrap();
    std::os::unix::fs::chown(&store, None, Some(GID)).unwrap();
    std::fs::set_permissions(&store, std::os::unix::fs::PermissionsExt::from_mode(0o2775)).unwrap();
    sealant_capture::owners::apply_default_acl(&[&store], GID).unwrap();

    // Installed by root under umask 022, as every capture before the per-person layout.
    let src = base.join("src");
    std::fs::create_dir_all(&src).unwrap();
    git(&src, &["init", "-q", "-b", "main"]);
    git(&src, &["config", "user.email", "t@t"]);
    git(&src, &["config", "user.name", "t"]);
    std::fs::write(src.join(".gitignore"), "node_modules/\n").unwrap();
    std::fs::write(
        src.join("package.json"),
        r#"{"name":"x","version":"1.0.0","dependencies":{"semver":"7.6.0"}}"#,
    )
    .unwrap();
    let pnpm = |flags: &str| {
        format!(
            "CI=1 pnpm install --no-frozen-lockfile --store-dir {} {flags}",
            store.display()
        )
    };
    let root_install = Std::new("sh")
        .arg("-c")
        .arg(format!("umask 022; cd {} && {}", src.display(), pnpm("")))
        .output()
        .unwrap();
    assert!(
        root_install.status.success(),
        "pnpm as root: {}",
        String::from_utf8_lossy(&root_install.stdout)
    );
    git(&src, &["add", "-A"]);
    git(&src, &["commit", "-q", "-m", "deps"]);

    // Captured, and restored under an owner map whose change owner is someone else.
    let sink = Arc::new(LocalDir::new(&base.join("cas")).unwrap());
    let registrar = Arc::new(InMemoryRegistrar::new("wt-pnpm", 1, None));
    let mut config = CaptureConfig::new("wt-pnpm", 1, &src);
    config.racy_window = Duration::ZERO;
    let mut engine = CaptureEngine::open(config, None).unwrap();
    for (seq, class) in [(1, Class::Small), (2, Class::Bulk)] {
        engine
            .snap(SnapRequest {
                kind: CaptureKind::Auto,
                class,
                seq,
            })
            .unwrap();
    }
    engine
        .shipper(sink.clone(), registrar.clone())
        .ship_pending()
        .unwrap();
    let owners = sealant_capture::owners::OwnerMap {
        gid: GID,
        worktree: BOB_UID + 1,
        people: std::collections::BTreeMap::new(),
    };
    let repo = base.join("restore/repo");
    owners.prepare_worktree_root(&repo).unwrap();
    sealant_capture::owners::apply_default_acl(&[&repo], GID).unwrap();
    let mut targets = MaterializeTargets::new(&repo, None);
    targets.owners = Some(owners);
    Materializer::new(sink.as_ref(), targets)
        .materialize(&registrar.head().unwrap().manifest, MaterializeClass::All)
        .unwrap();

    // The second person changes the lockfile, installs, and reinstalls by force.
    let out = base.join("pnpm-as-bob");
    let script = format!(
        "cd {r} && printf '%s' '{{\"name\":\"x\",\"version\":\"1.0.0\",\"dependencies\":{{\"semver\":\"7.6.0\",\"which\":\"4.0.0\"}}}}' > package.json \
         && {install} > {o}.log 2>&1 && {force} >> {o}.log 2>&1 && ./node_modules/.bin/semver 1.2.3 >> {o}.log 2>&1; \
         echo \"exit=$?\" > {o}.tmp && mv {o}.tmp {o}",
        r = repo.display(),
        install = pnpm(""),
        force = pnpm("--force"),
        o = out.display()
    );
    // Whether the environment itself imposes no-new-privileges, read before the daemon starts.
    let environment_nnp = sealant_process::platform::no_new_privs();
    // The daemon's child environment carries PATH, as boot's passthrough does (node and pnpm
    // may live outside the default PATH, as on CI runners).
    let mut client = Client::start_with(
        base,
        vec![var("PATH", &std::env::var("PATH").unwrap_or_default())],
    );
    let withheld = match ok(client.request(Command::RuntimeGetCapabilities).await) {
        Some(CommandResult::Capabilities(c)) => c.person_capabilities_withheld,
        other => panic!("capabilities: {other:?}"),
    };
    ok(client.request(Command::Exec(exec(script, Some(BOB)))).await);
    let status = wait_for(&out);
    let log = std::fs::read_to_string(base.join("pnpm-as-bob.log")).unwrap_or_default();
    if withheld.is_some() {
        // A per-person daemon withholds CAP_FOWNER only where the environment imposes
        // no-new-privileges (a container run with it): pnpm fails as it did before it.
        assert!(
            environment_nnp,
            "a per-person daemon withheld CAP_FOWNER: {withheld:?}"
        );
        // pnpm 12 says ERR_PNPM_CMD_SHIM_CHMOD; pnpm 9 a bare EPERM on the chmod.
        assert!(
            log.contains("ERR_PNPM_CMD_SHIM_CHMOD")
                || log.contains("EPERM: operation not permitted, chmod"),
            "{status}\n{log}"
        );
        return;
    }
    assert_eq!(status, "exit=0\n", "pnpm as a second person:\n{log}");
    assert!(repo.join("node_modules/which").exists(), "{log}");
}

/// Removes `/etc/sealant/person-env` when dropped (the test that writes it may fail).
struct PersonEnvFile;

impl Drop for PersonEnvFile {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(sealant_process::identity::PERSON_ENV_FILE);
    }
}

/// The image's `/etc/sealant/person-env` reaches every process run as a person (exec, session,
/// the dotfiles commands) and never root: `PATH_PREPEND` in front of the base `PATH`, its other
/// variables over the daemon's environment, under the caller's explicit ones; the version line,
/// malformed lines and names a person never gets are skipped.
#[tokio::test]
async fn the_image_s_person_environment_reaches_every_person_s_process_and_not_root() {
    if !ready() {
        return;
    }
    let dir = scratch();
    std::fs::create_dir_all("/etc/sealant").unwrap();
    let _file = PersonEnvFile;
    std::fs::write(
        sealant_process::identity::PERSON_ENV_FILE,
        "# person-env 1\nPATH_PREPEND=/opt/mise/shims\nMISE_DATA_DIR=/opt/mise\n\
         not a line\n1BAD=x\nHOME=/nope\nSEALANT_SNEAKY=y\nFROM_BOTH=file\nCALLER_WINS=file\n",
    )
    .unwrap();
    let dump = |out: &Path| {
        format!(
            "env > {0}.tmp && echo end >> {0}.tmp && mv {0}.tmp {0}",
            out.display()
        )
    };
    let mut client = Client::start_with(
        dir.path(),
        vec![var("PATH", "/usr/bin:/bin"), var("FROM_BOTH", "daemon")],
    );
    let mut args = exec(dump(&dir.path().join("exec")), Some(BOB));
    args.env = vec![var("CALLER_WINS", "caller")];
    ok(client.request(Command::Exec(args)).await);
    ok(client
        .request(Command::OpenSession(OpenSessionArgs {
            user: Some(BOB.to_owned()),
            execution_id: None,
            shell: Some("/bin/sh".to_owned()),
            args: vec!["-c".to_owned(), dump(&dir.path().join("session"))],
            cwd: None,
            env: vec![var("CALLER_WINS", "caller")],
            cols: 80,
            rows: 24,
            term: None,
            mode: SessionMode::Pipe,
        }))
        .await);
    for name in ["exec", "session"] {
        let env = wait_for(&dir.path().join(name));
        let has = |line: &str| env.lines().any(|l| l == line);
        assert!(has("PATH=/opt/mise/shims:/usr/bin:/bin"), "{name}:\n{env}");
        assert!(has("MISE_DATA_DIR=/opt/mise"), "{name}:\n{env}");
        assert!(
            has("FROM_BOTH=file"),
            "{name}: the file over the daemon:\n{env}"
        );
        assert!(
            has("CALLER_WINS=caller"),
            "{name}: the caller over the file:\n{env}"
        );
        assert!(
            has(&format!("HOME=/home/{BOB}")),
            "{name}: the identity wins:\n{env}"
        );
        assert!(!env.contains("SEALANT_SNEAKY"), "{name}:\n{env}");
        assert!(!env.contains("1BAD"), "{name}:\n{env}");
    }
    ok(client
        .request(Command::Exec(exec(dump(&dir.path().join("root")), None)))
        .await);
    let root = wait_for(&dir.path().join("root"));
    assert!(
        !root.contains("MISE_DATA_DIR"),
        "root got the person file:\n{root}"
    );
    assert!(root.lines().any(|l| l == "PATH=/usr/bin:/bin"), "{root}");

    // A version this sealantd does not read applies nothing.
    std::fs::write(
        sealant_process::identity::PERSON_ENV_FILE,
        "# person-env 2\nMISE_DATA_DIR=/opt/mise\nPATH_PREPEND=/opt/mise/shims\n",
    )
    .unwrap();
    ok(client
        .request(Command::Exec(exec(dump(&dir.path().join("v2")), Some(BOB))))
        .await);
    let v2 = wait_for(&dir.path().join("v2"));
    assert!(
        !v2.contains("MISE_DATA_DIR"),
        "a version 2 file applied:\n{v2}"
    );
    assert!(v2.lines().any(|l| l == "PATH=/usr/bin:/bin"), "{v2}");
    std::fs::write(
        sealant_process::identity::PERSON_ENV_FILE,
        "# person-env 1\nPATH_PREPEND=/opt/mise/shims\nMISE_DATA_DIR=/opt/mise\n",
    )
    .unwrap();

    // The dotfiles commands of a person's apply: chezmoi, a stand-in writing its environment.
    let evidence = dir.path().join("chezmoi-env");
    let bin = dir.path().join("bin");
    std::fs::create_dir_all(&bin).unwrap();
    std::fs::write(
        bin.join("chezmoi"),
        format!(
            "#!/bin/sh\nenv > {0}.tmp && mv {0}.tmp {0}\n",
            evidence.display()
        ),
    )
    .unwrap();
    std::fs::set_permissions(
        bin.join("chezmoi"),
        std::os::unix::fs::PermissionsExt::from_mode(0o755),
    )
    .unwrap();
    let old_path = std::env::var("PATH").unwrap_or_default();
    let daemon_path = format!("{}:{old_path}", bin.display());
    // SAFETY: this binary runs its tests on one thread when root (scripts/ci-root-tests.sh).
    unsafe { std::env::set_var("PATH", &daemon_path) };
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
    let applied = client
        .request(Command::DotfilesApply(Box::new(DotfilesApplyArgs {
            user: BOB.to_owned(),
            repository: None,
            archive_dir: Some(archives.display().to_string()),
            execution_id: None,
        })))
        .await;
    // SAFETY: as above.
    unsafe { std::env::set_var("PATH", &old_path) };
    ok(applied);
    let env = std::fs::read_to_string(&evidence).expect("chezmoi ran");
    assert!(
        env.lines()
            .any(|l| l == format!("PATH=/opt/mise/shims:{daemon_path}")),
        "{env}"
    );
    assert!(env.lines().any(|l| l == "MISE_DATA_DIR=/opt/mise"), "{env}");
    assert!(!env.contains("SEALANT_SNEAKY"), "{env}");
}

/// Removes the test's sudoers entry when dropped.
struct SudoersEntry;

impl SudoersEntry {
    const PATH: &str = "/etc/sudoers.d/mtest-sealantd";

    /// Passwordless sudo for the test person, as Core's images give the `mend` group.
    fn add() -> Self {
        std::fs::create_dir_all("/etc/sudoers.d").unwrap();
        std::fs::write(Self::PATH, format!("{BOB} ALL=(ALL) NOPASSWD: ALL\n")).unwrap();
        std::fs::set_permissions(
            Self::PATH,
            std::os::unix::fs::PermissionsExt::from_mode(0o440),
        )
        .unwrap();
        Self
    }
}

impl Drop for SudoersEntry {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(Self::PATH);
    }
}

/// `sudo -n true` as the person, through a daemon of the given posture, on a thread of its own
/// (no-new-privileges cannot be unset): its exit line, and what the daemon reports.
fn sudo_as_person(no_new_privileges: bool) -> (String, sealant_protocol::Capabilities) {
    std::thread::spawn(move || {
        let tokio = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        tokio.block_on(async move {
            let dir = scratch();
            let out = dir.path().join("sudo");
            let mut client = Client::start_posture(
                dir.path(),
                vec![var(
                    "PATH",
                    "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
                )],
                Vec::new(),
                no_new_privileges,
            );
            let caps = match ok(client.request(Command::RuntimeGetCapabilities).await) {
                Some(CommandResult::Capabilities(c)) => c,
                other => panic!("capabilities: {other:?}"),
            };
            ok(client
                .request(Command::Exec(exec(
                    format!(
                        "sudo -n true > {0}.log 2>&1; echo \"exit=$?\" > {0}.tmp && mv {0}.tmp {0}",
                        out.display()
                    ),
                    Some(BOB),
                )))
                .await);
            let status = wait_for(&out);
            let log = std::fs::read_to_string(dir.path().join("sudo.log")).unwrap_or_default();
            (format!("{status}{log}"), caps)
        })
    })
    .join()
    .unwrap()
}

/// In a per-person executor (a boot under an owner map), the daemon leaves no-new-privileges
/// unset: a person's passwordless `sudo` works (Mend's ADR 0016), the person holds `CAP_FOWNER`,
/// and `runtime.getCapabilities` says `noNewPrivileges: false`.
#[test]
fn in_a_per_person_executor_a_person_s_sudo_works() {
    if !ready() {
        return;
    }
    if sealant_process::platform::no_new_privs() {
        eprintln!("this environment sets no-new-privileges itself: sudo cannot work in it");
        return;
    }
    let _sudoers = SudoersEntry::add();
    let (seen, caps) = sudo_as_person(false);
    assert!(seen.starts_with("exit=0\n"), "sudo as a person:\n{seen}");
    assert!(!caps.no_new_privileges, "{caps:?}");
    assert_eq!(caps.person_capabilities, ["CAP_FOWNER"], "{caps:?}");
}

/// Every other executor keeps no-new-privileges (plan §18): the same `sudo -n true` is refused,
/// and the daemon says `noNewPrivileges: true`.
#[test]
fn elsewhere_no_new_privileges_stays_and_sudo_is_refused() {
    if !ready() {
        return;
    }
    let _sudoers = SudoersEntry::add();
    let (seen, caps) = sudo_as_person(true);
    assert!(
        !seen.starts_with("exit=0\n"),
        "sudo worked under no-new-privileges:\n{seen}"
    );
    assert!(seen.contains("no new privileges"), "{seen}");
    assert!(caps.no_new_privileges, "{caps:?}");
    assert!(caps.person_capabilities.is_empty(), "{caps:?}");
}
