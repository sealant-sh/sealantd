//! Running as a user (Mend's ADR 0016, step 5): `exec` and `openSession` with a `user` start the
//! process as exactly that user (uid, primary and supplementary groups, the passwd `HOME`,
//! `USER`, `LOGNAME` and `SHELL`, umask `0002`, a private `TMPDIR` and `XDG_RUNTIME_DIR`), and
//! every child inherits it; `dotfiles.apply` writes a person's dotfiles into their home as them
//! and answers before their `./install.sh` ends, which runs as them.
//!
//! A request names only a user the runtime's people admit: Mend's reserved range in its group,
//! and under an owner map also the map's people (most tests here run as a per-person executor
//! whose map names Bob and Cat); anyone else is refused before anything starts.
//!
//! These need root and real users: they add groups and users to the passwd database, so they
//! run only with `SEALANTD_REQUIRE_ROOT_TESTS=1`, as root (CI runs them under sudo; locally, in a
//! container).

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
use sealant_runtime_core::{PERSON_GID, People, RuntimeConfig, new_runtime_id};
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
/// A second person, in the same primary group as Mend's people share (`mend`), whose home is
/// 0700 as Mend makes every home.
const CAT: &str = "mtestcat";
const CAT_UID: u32 = 40973;
/// A person as Mend makes one without an owner map: a uid in its reserved range whose primary
/// group is [`PERSON_GID`] (`mend`; made here as `mtestmend` when the database lacks it).
const DAN: &str = "mtestdan";
const DAN_UID: u32 = 40974;
/// A host user in Mend's group but outside its reserved range: never one of its people.
const EVE: &str = "mtesteve";
const EVE_UID: u32 = 1500;

/// The people of the executor most tests here run as: an owner map naming Bob and Cat, in
/// [`GROUP`].
fn per_person() -> People {
    People::Listed {
        gid: GID,
        uids: vec![BOB_UID, CAT_UID],
    }
}

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
        SudoersEntry::sweep();
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
        run(&[
            "useradd",
            "-m",
            "-u",
            &CAT_UID.to_string(),
            "-g",
            GROUP,
            "-s",
            "/bin/sh",
            CAT,
        ]);
        let has_group = Std::new("getent")
            .args(["group", &PERSON_GID.to_string()])
            .output()
            .is_ok_and(|o| o.status.success());
        if !has_group {
            run(&["groupadd", "-g", &PERSON_GID.to_string(), "mtestmend"]);
        }
        for (user, uid) in [(DAN, DAN_UID), (EVE, EVE_UID)] {
            run(&[
                "useradd",
                "-m",
                "-u",
                &uid.to_string(),
                "-g",
                &PERSON_GID.to_string(),
                "-s",
                "/bin/sh",
                user,
            ]);
        }
        for user in [BOB, CAT, DAN, EVE] {
            std::fs::set_permissions(
                format!("/home/{user}"),
                std::os::unix::fs::PermissionsExt::from_mode(0o700),
            )
            .unwrap();
        }
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
        Self::start_posture(workspace, child_env, person_withheld, false, per_person())
    }

    /// With the daemon's no-new-privileges posture given (`true`: every executor but a
    /// per-person one), and the people a request may name. Setting no-new-privileges is
    /// irreversible on the calling thread.
    fn start_posture(
        workspace: &Path,
        child_env: Vec<sealant_protocol::EnvVar>,
        person_withheld: Vec<String>,
        no_new_privileges: bool,
        people: People,
    ) -> Self {
        let mut config = RuntimeConfig::new(new_runtime_id());
        config.workspace_root = workspace.to_path_buf();
        config.child_env = child_env;
        config.person_withheld = person_withheld;
        config.no_new_privileges = no_new_privileges;
        config.people = people;
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

/// `user` named by `exec`, by `openSession` (pipe and PTY) and by `dotfiles.apply`, each answered
/// with its refusal; `out` is what each would have written had it started.
async fn refused_everywhere(client: &mut Client, user: &str, out: &Path) -> Vec<String> {
    let script = format!("id -u > {0}.tmp && mv {0}.tmp {0}", out.display());
    let mut commands = vec![Command::Exec(exec(script.clone(), Some(user)))];
    for mode in [SessionMode::Pipe, SessionMode::Pty] {
        commands.push(Command::OpenSession(OpenSessionArgs {
            user: Some(user.to_owned()),
            execution_id: None,
            shell: Some("/bin/sh".to_owned()),
            args: vec!["-c".to_owned(), script.clone()],
            cwd: None,
            env: vec![],
            cols: 80,
            rows: 24,
            term: None,
            mode,
        }));
    }
    let archives = out.with_extension("archives");
    std::fs::create_dir_all(&archives).unwrap();
    commands.push(Command::DotfilesApply(Box::new(DotfilesApplyArgs {
        user: user.to_owned(),
        repository: None,
        archive_dir: Some(archives.display().to_string()),
        execution_id: None,
    })));
    let mut messages = Vec::new();
    for command in commands {
        match client.request(command).await.outcome {
            ResponseOutcome::Error { error } => {
                assert_eq!(
                    error.code,
                    sealant_protocol::ControlErrorCode::InvalidArgument,
                    "{user}: {error:?}"
                );
                messages.push(error.message);
            }
            ResponseOutcome::Ok { result } => panic!("{user} ran: {result:?}"),
        }
    }
    messages
}

/// Nothing of a refused request started: what it would have written is still not there.
fn never_written(out: &Path) {
    std::thread::sleep(Duration::from_millis(300));
    assert!(!out.exists(), "{} was written", out.display());
    assert!(!out.with_extension("tmp").exists());
}

/// `user` runs a process through `exec` and a PTY session through `openSession`, each writing
/// its uid under `dir`.
async fn runs_everywhere(client: &mut Client, user: &str, uid: u32, dir: &Path) {
    let out = dir.join(format!("{user}-exec"));
    ok(client
        .request(Command::Exec(exec(
            format!("id -u > {0}.tmp && mv {0}.tmp {0}", out.display()),
            Some(user),
        )))
        .await);
    assert_eq!(wait_for(&out), format!("{uid}\n"));
    let session = dir.join(format!("{user}-session"));
    ok(client
        .request(Command::OpenSession(OpenSessionArgs {
            user: Some(user.to_owned()),
            execution_id: None,
            shell: Some("/bin/sh".to_owned()),
            args: vec![
                "-c".to_owned(),
                format!("id -u > {0}.tmp && mv {0}.tmp {0}", session.display()),
            ],
            cwd: None,
            env: vec![],
            cols: 80,
            rows: 24,
            term: None,
            mode: SessionMode::Pty,
        }))
        .await);
    assert_eq!(wait_for(&session), format!("{uid}\n"));
}

/// Under an owner map, a request may name the map's people (and its change owner) in its group,
/// or any user in Mend's reserved range whose primary group is 40000: the map is read at boot,
/// and a person who joins the worktree after it (Dan here) is not on it. Anyone else is refused
/// by `exec`, `openSession` and `dotfiles.apply` alike, and nothing starts: a reserved uid in
/// another group (Cat), a host user outside the range (Eve, uid 1500; `nobody`) and root.
#[tokio::test]
async fn under_an_owner_map_its_people_and_mend_s_reserved_range_run() {
    if !ready() {
        return;
    }
    let dir = scratch();
    let only_bob = People::Listed {
        gid: GID,
        uids: vec![BOB_UID],
    };
    let mut client = Client::start_posture(dir.path(), Vec::new(), Vec::new(), false, only_bob);
    runs_everywhere(&mut client, BOB, BOB_UID, dir.path()).await;
    // Not on the map: one of Mend's people who joined after boot.
    runs_everywhere(&mut client, DAN, DAN_UID, dir.path()).await;

    let out = dir.path().join(CAT);
    for message in refused_everywhere(&mut client, CAT, &out).await {
        assert!(
            message.contains(&format!(
                "uid {CAT_UID} is not one of this executor's people (owner map) and has primary \
                 group {GID}, not the group of Mend's people ({PERSON_GID})"
            )),
            "{message}"
        );
    }
    never_written(&out);
    let out = dir.path().join(EVE);
    for message in refused_everywhere(&mut client, EVE, &out).await {
        assert!(
            message.contains(&format!(
                "uid {EVE_UID} is not one of this executor's people (owner map) and is outside \
                 the range of Mend's people (40001-49999)"
            )),
            "{message}"
        );
    }
    never_written(&out);
    if let Some(nobody) = nix::unistd::User::from_name("nobody").unwrap() {
        let out = dir.path().join("nobody");
        for message in refused_everywhere(&mut client, "nobody", &out).await {
            assert!(
                message.contains(&format!("uid {} is not one of", nobody.uid)),
                "{message}"
            );
        }
        never_written(&out);
    }
    for root in ["root", "0"] {
        let out = dir.path().join(format!("root-{root}"));
        for message in refused_everywhere(&mut client, root, &out).await {
            assert!(message.contains("is root"), "{message}");
        }
        never_written(&out);
    }

    // On the map, but its primary group is neither the map's nor Mend's: refused.
    let mut client = Client::start_posture(
        dir.path(),
        Vec::new(),
        Vec::new(),
        false,
        People::Listed {
            gid: PERSON_GID,
            uids: vec![BOB_UID],
        },
    );
    let out = dir.path().join("bob-other-group");
    for message in refused_everywhere(&mut client, &BOB_UID.to_string(), &out).await {
        assert!(
            message.contains(&format!("has primary group {GID}")),
            "{message}"
        );
    }
    never_written(&out);
}

/// Without an owner map, a request may name only a user in Mend's reserved range (40001-49999)
/// whose primary group is 40000: Dan runs; Bob (in the range, another primary group), Eve and
/// `nobody` (outside it) are refused, and nothing of theirs starts.
#[tokio::test]
async fn without_an_owner_map_only_mend_s_reserved_range_runs() {
    if !ready() {
        return;
    }
    let dir = scratch();
    let mut client =
        Client::start_posture(dir.path(), Vec::new(), Vec::new(), false, People::Reserved);
    let out = dir.path().join("dan");
    ok(client
        .request(Command::Exec(exec(
            format!("id -u > {0}.tmp && mv {0}.tmp {0}", out.display()),
            Some(DAN),
        )))
        .await);
    assert_eq!(wait_for(&out), format!("{DAN_UID}\n"));
    let session = dir.path().join("dan-session");
    ok(client
        .request(Command::OpenSession(OpenSessionArgs {
            user: Some(DAN_UID.to_string()),
            execution_id: None,
            shell: Some("/bin/sh".to_owned()),
            args: vec![
                "-c".to_owned(),
                format!("id -u > {0}.tmp && mv {0}.tmp {0}", session.display()),
            ],
            cwd: None,
            env: vec![],
            cols: 80,
            rows: 24,
            term: None,
            mode: SessionMode::Pty,
        }))
        .await);
    assert_eq!(wait_for(&session), format!("{DAN_UID}\n"));

    let out = dir.path().join("bob");
    for message in refused_everywhere(&mut client, BOB, &out).await {
        assert!(
            message.contains(&format!(
                "has primary group {GID}, not the group of Mend's people"
            )),
            "{message}"
        );
    }
    never_written(&out);
    let out = dir.path().join(EVE);
    for message in refused_everywhere(&mut client, EVE, &out).await {
        assert!(
            message.contains(&format!("uid {EVE_UID} is outside the range")),
            "{message}"
        );
    }
    never_written(&out);
    let nobody = nix::unistd::User::from_name("nobody").unwrap();
    if let Some(nobody) = nobody {
        let out = dir.path().join("nobody");
        for message in refused_everywhere(&mut client, "nobody", &out).await {
            assert!(
                message.contains(&format!("uid {} is outside the range", nobody.uid)),
                "{message}"
            );
        }
        never_written(&out);
    }
    let out = dir.path().join("root");
    for message in refused_everywhere(&mut client, "0", &out).await {
        assert!(message.contains("is root"), "{message}");
    }
    never_written(&out);
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
    let _ = std::fs::remove_file(home.join(".mtest-private"));
    let _ = std::fs::remove_dir_all(home.join(".mtest-bin"));
    // A dotfiles tree with a file, a private file, a nested file, a symlink, a directory of its
    // own mode and an install.sh that waits.
    let tree = dir.path().join("tree");
    std::fs::create_dir_all(tree.join(".config/mtest")).unwrap();
    std::fs::create_dir_all(tree.join(".mtest-bin")).unwrap();
    std::fs::write(tree.join(".mtest-zshrc"), "export A=1\n").unwrap();
    std::fs::write(tree.join(".mtest-private"), "secret\n").unwrap();
    std::fs::write(tree.join(".mtest-bin/hello"), "#!/bin/sh\necho hi\n").unwrap();
    std::fs::write(tree.join(".config/mtest/conf"), "x\n").unwrap();
    std::os::unix::fs::symlink(".mtest-zshrc", tree.join(".mtest-link")).unwrap();
    for (path, mode) in [
        (".mtest-zshrc", 0o644),
        (".mtest-private", 0o600),
        (".mtest-bin/hello", 0o755),
        (".mtest-bin", 0o750),
    ] {
        std::fs::set_permissions(
            tree.join(path),
            std::os::unix::fs::PermissionsExt::from_mode(mode),
        )
        .unwrap();
    }
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
    // The modes the archive carries, on files and in the tree; directories the copy makes in the
    // home take the daemon's umask, as they always have.
    let umask = daemon_umask();
    let mode = |path: &Path| std::fs::symlink_metadata(path).unwrap().mode() & 0o7777;
    for (path, expected) in [
        (".mtest-zshrc", 0o644),
        (".mtest-private", 0o600),
        (".mtest-bin/hello", 0o755),
        (".mtest-bin", 0o777 & !umask),
        (".config/mtest", 0o777 & !umask),
        (".local/share/sealant-dotfiles/0", 0o777 & !umask),
        (".local/share/sealant-dotfiles/0/.mtest-bin", 0o750),
        (".local/share/sealant-dotfiles/0/install.sh", 0o755),
    ] {
        assert_eq!(mode(&home.join(path)), expected, "{path}");
    }
    assert_eq!(
        std::fs::read_link(home.join(".mtest-link")).unwrap(),
        Path::new(".mtest-zshrc")
    );
    for path in [".local/share/sealant-dotfiles/0", ".mtest-bin/hello"] {
        let meta = std::fs::symlink_metadata(home.join(path)).unwrap();
        assert_eq!((meta.uid(), meta.gid()), (BOB_UID, GID), "{path}");
    }
    assert_staging_empty();

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

/// The daemon's umask (read and put back; these tests run on one thread).
fn daemon_umask() -> u32 {
    let mask = nix::sys::stat::umask(nix::sys::stat::Mode::from_bits_truncate(0o022));
    nix::sys::stat::umask(mask);
    mask.bits()
}

/// Nothing is left under the daemon's dotfiles staging directory once an apply answers.
fn assert_staging_empty() {
    let root = Path::new("/run/sealant/dotfiles-staging");
    let meta = std::fs::symlink_metadata(root).unwrap();
    assert!(meta.is_dir(), "the staging directory is a directory");
    assert_eq!((meta.uid(), meta.mode() & 0o7777), (0, 0o700));
    let left: Vec<_> = std::fs::read_dir(root).unwrap().flatten().collect();
    assert!(left.is_empty(), "staging left behind: {left:?}");
}

/// `tree` packed as `<archives>/0.tar.gz`, with a manifest applying it with `manager`, no
/// bootstrap. `flags` go to tar (`-P` keeps an absolute or `..` path).
fn pack_one(tree: &Path, archives: &Path, manager: &str, flags: &[&str], members: &[&str]) {
    std::fs::create_dir_all(archives).unwrap();
    assert!(
        Std::new("tar")
            .arg("-czf")
            .arg(archives.join("0.tar.gz"))
            .args(flags)
            .arg("-C")
            .arg(tree)
            .args(members)
            .status()
            .unwrap()
            .success()
    );
    std::fs::write(
        archives.join("manifest.json"),
        format!(
            r#"{{"archives":[{{"file":"0.tar.gz","manager":"{manager}","bootstrap":false}}]}}"#
        ),
    )
    .unwrap();
}

/// `dotfiles.apply` of `archives` for `user`, answered with its error.
async fn apply_refused(client: &mut Client, user: &str, archives: &Path) -> String {
    let response = client
        .request(Command::DotfilesApply(Box::new(DotfilesApplyArgs {
            user: user.to_owned(),
            repository: None,
            archive_dir: Some(archives.display().to_string()),
            execution_id: None,
        })))
        .await;
    match response.outcome {
        ResponseOutcome::Error { error } => error.message,
        ResponseOutcome::Ok { result } => panic!("applied: {result:?}"),
    }
}

/// The thread a person's dotfiles are written on (`RunAs::as_fs_user`) reaches the filesystem as
/// them, with their groups, and holds no capability; a file only root may read is out of its
/// reach, and it may start no process. The calling thread is root as before, and the process
/// as dumpable as it was.
#[test]
fn the_dotfiles_writer_thread_is_the_person_and_holds_nothing_of_root() {
    if !ready() {
        return;
    }
    let field = |status: &str, key: &str| -> Vec<String> {
        status
            .lines()
            .find(|l| l.starts_with(key))
            .unwrap_or_else(|| panic!("{key} in {status}"))
            .split_whitespace()
            .skip(1)
            .map(str::to_owned)
            .collect()
    };
    let dir = scratch();
    let roots = dir.path().join("roots-only");
    std::fs::write(&roots, "root's\n").unwrap();
    std::fs::set_permissions(&roots, std::os::unix::fs::PermissionsExt::from_mode(0o600)).unwrap();
    let user = sealant_process::identity::RunAs::resolve(BOB, &per_person()).unwrap();
    let dumpable = sealant_process::identity::process_dumpable();
    assert_eq!(dumpable, 1, "a root daemon starts dumpable");
    let (status, read, spawned) = user
        .as_fs_user(|| {
            use sealant_process::CommandGateExt;
            (
                std::fs::read_to_string("/proc/thread-self/status").unwrap(),
                std::fs::read_to_string(&roots).map_err(|e| e.kind()),
                // A child of this thread would run as root: the gate refuses it.
                Std::new("true").status_gated().map_err(|e| e.kind()),
            )
        })
        .unwrap();
    assert_eq!(spawned.err(), Some(std::io::ErrorKind::PermissionDenied));
    // The filesystem uid change made the process non-dumpable; the caller put it back.
    assert_eq!(sealant_process::identity::process_dumpable(), dumpable);
    // Real, effective, saved and filesystem ids: only the filesystem ones are the person's.
    assert_eq!(field(&status, "Uid:")[3], BOB_UID.to_string(), "{status}");
    assert_eq!(field(&status, "Gid:")[3], GID.to_string(), "{status}");
    let mut groups = field(&status, "Groups:");
    groups.sort();
    assert_eq!(groups, [GID.to_string(), EXTRA_GID.to_string()], "{status}");
    for set in ["CapInh:", "CapPrm:", "CapEff:", "CapAmb:"] {
        assert_eq!(field(&status, set), ["0000000000000000"], "{set} {status}");
    }
    assert_eq!(read, Err(std::io::ErrorKind::PermissionDenied));
    let mine = std::fs::read_to_string("/proc/thread-self/status").unwrap();
    assert_eq!(field(&mine, "Uid:")[3], "0", "{mine}");
    assert_ne!(field(&mine, "CapEff:"), ["0000000000000000"], "{mine}");
    assert_eq!(std::fs::read_to_string(&roots).unwrap(), "root's\n");
}

/// The review's attack (P2-1 on Core's #334): a person links a directory of their home into
/// another person's and has their dotfiles applied, with the copy manager. Nothing lands in the
/// other home, the apply names the path it could not reach, and the other person's files keep
/// their bytes and owner. The same for a link where the archives are staged in the home.
#[tokio::test]
async fn a_person_s_link_into_another_home_takes_none_of_their_dotfiles() {
    if !ready() {
        return;
    }
    let dir = scratch();
    let bob = PathBuf::from(format!("/home/{BOB}"));
    let cat = PathBuf::from(format!("/home/{CAT}"));
    // Cat's own files: a fish config and a staged tree of theirs.
    let cat_fish = cat.join(".config/fish/config.fish");
    let cat_staged = cat.join(".local/share/sealant-dotfiles/0/keep");
    for path in [&cat_fish, &cat_staged] {
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(path, "cat's own\n").unwrap();
    }
    assert!(
        Std::new("chown")
            .args(["-R", &format!("{CAT}:{GROUP}")])
            .arg(cat.join(".config"))
            .arg(cat.join(".local"))
            .status()
            .unwrap()
            .success()
    );
    let link = |at: &Path, to: &Path| {
        let _ = std::fs::remove_dir_all(at);
        let _ = std::fs::remove_file(at);
        std::fs::create_dir_all(at.parent().unwrap()).unwrap();
        std::os::unix::fs::symlink(to, at).unwrap();
        std::os::unix::fs::lchown(at, Some(BOB_UID), Some(GID)).unwrap();
    };
    let tree = dir.path().join("tree");
    std::fs::create_dir_all(tree.join(".config/fish")).unwrap();
    std::fs::write(tree.join(".config/fish/config.fish"), "bob's code\n").unwrap();
    let archives = dir.path().join("archives");
    pack_one(&tree, &archives, "copy", &[], &["."]);
    let mut client = Client::start(dir.path());

    // 1. `~/.config` -> the other home's `.config`, then the copy manager.
    link(&bob.join(".config"), &cat.join(".config"));
    let refused = apply_refused(&mut client, BOB, &archives).await;
    assert!(
        refused.contains(&format!("{}/.config", bob.display()))
            && refused.contains("Permission denied"),
        "{refused}"
    );
    // 2. `~/.local/share/sealant-dotfiles` -> the other home's staged trees.
    std::fs::remove_file(bob.join(".config")).unwrap();
    link(
        &bob.join(".local/share/sealant-dotfiles"),
        &cat.join(".local/share/sealant-dotfiles"),
    );
    let refused = apply_refused(&mut client, BOB, &archives).await;
    assert!(refused.contains("Permission denied"), "{refused}");
    std::fs::remove_file(bob.join(".local/share/sealant-dotfiles")).unwrap();

    for path in [&cat_fish, &cat_staged] {
        assert_eq!(std::fs::read_to_string(path).unwrap(), "cat's own\n");
        let meta = std::fs::metadata(path).unwrap();
        assert_eq!((meta.uid(), meta.mode() & 0o7777), (CAT_UID, 0o644));
    }
    let fish: Vec<_> = std::fs::read_dir(cat.join(".config/fish"))
        .unwrap()
        .flatten()
        .map(|e| e.file_name())
        .collect();
    assert_eq!(fish, ["config.fish"]);
    assert_staging_empty();

    // Without the links, the same archive applies.
    ok(client
        .request(Command::DotfilesApply(Box::new(DotfilesApplyArgs {
            user: BOB.to_owned(),
            repository: None,
            archive_dir: Some(archives.display().to_string()),
            execution_id: None,
        })))
        .await);
    assert_eq!(
        std::fs::read_to_string(bob.join(".config/fish/config.fish")).unwrap(),
        "bob's code\n"
    );
    assert_eq!(std::fs::read_to_string(&cat_fish).unwrap(), "cat's own\n");
    let _ = std::fs::remove_dir_all(bob.join(".config/fish"));
}

/// A person's stow tree: the packages are linked into their home from their own tree under
/// `~/.local/share/sealant-dotfiles`, and a top-level dot entry is copied, all theirs.
#[tokio::test]
async fn a_person_s_stow_tree_links_from_their_own_tree() {
    if !ready() {
        return;
    }
    let stow = Std::new("sh")
        .args(["-c", "command -v stow"])
        .output()
        .unwrap();
    if !stow.status.success() {
        eprintln!("SKIPPED: stow is not on PATH");
        return;
    }
    let dir = scratch();
    let home = PathBuf::from(format!("/home/{BOB}"));
    for path in [".mtest-stowed", ".mtest-dot"] {
        let _ = std::fs::remove_file(home.join(path));
    }
    let tree = dir.path().join("tree");
    std::fs::create_dir_all(tree.join("pkg")).unwrap();
    std::fs::write(tree.join("pkg/.mtest-stowed"), "stowed\n").unwrap();
    std::fs::write(tree.join(".mtest-dot"), "dot\n").unwrap();
    let archives = dir.path().join("archives");
    pack_one(&tree, &archives, "stow", &[], &["."]);
    let mut client = Client::start(dir.path());
    ok(client
        .request(Command::DotfilesApply(Box::new(DotfilesApplyArgs {
            user: BOB.to_owned(),
            repository: None,
            archive_dir: Some(archives.display().to_string()),
            execution_id: None,
        })))
        .await);
    let linked = home.join(".mtest-stowed");
    let meta = std::fs::symlink_metadata(&linked).unwrap();
    assert!(meta.is_symlink());
    assert_eq!(meta.uid(), BOB_UID);
    assert_eq!(std::fs::read_to_string(&linked).unwrap(), "stowed\n");
    assert_eq!(
        std::fs::canonicalize(&linked).unwrap(),
        home.join(".local/share/sealant-dotfiles/0/pkg/.mtest-stowed")
    );
    let dot = std::fs::symlink_metadata(home.join(".mtest-dot")).unwrap();
    assert!(dot.is_file());
    assert_eq!(dot.uid(), BOB_UID);
    assert_staging_empty();
}

/// A person's archive with an absolute entry or one with `..` is refused before anything of it
/// is written, and the apply says which entry.
#[tokio::test]
async fn a_person_s_archive_with_an_absolute_or_dotdot_entry_is_refused() {
    if !ready() {
        return;
    }
    let dir = scratch();
    let target = dir.path().join("target-file");
    std::fs::write(&target, "from the archive\n").unwrap();
    let inner = dir.path().join("a/b");
    std::fs::create_dir_all(&inner).unwrap();
    let absolute = dir.path().join("absolute");
    pack_one(
        &inner,
        &absolute,
        "copy",
        &["-P"],
        &[&target.display().to_string()],
    );
    let dotdot = dir.path().join("dotdot");
    pack_one(&inner, &dotdot, "copy", &["-P"], &["../../target-file"]);
    std::fs::write(&target, "untouched\n").unwrap();
    let mut client = Client::start(dir.path());
    for (archives, why) in [(&absolute, "absolute path"), (&dotdot, "`..`")] {
        let refused = apply_refused(&mut client, BOB, archives).await;
        assert!(refused.contains(why), "{refused}");
    }
    assert_eq!(std::fs::read_to_string(&target).unwrap(), "untouched\n");
    assert_staging_empty();
}

/// `len` bytes of text that compresses about as well as configuration does (words drawn from a
/// fixed pseudo-random sequence).
fn text(len: usize) -> String {
    const WORDS: &[&str] = &[
        "set",
        "export",
        "alias",
        "function",
        "end",
        "if",
        "then",
        "fi",
        "local",
        "return",
        "vim.o.number",
        "true",
        "false",
        "bind",
        "key",
        "color",
        "path",
        "~/.config",
        "--",
        "require",
        "plugin",
        "opts",
        "theme",
        "font",
        "size",
        "12",
        "0x1e1e2e",
        "mouse",
    ];
    let mut seed: u64 = len as u64 ^ 0x9e37_79b9_7f4a_7c15;
    let mut out = String::with_capacity(len + 16);
    while out.len() < len {
        seed = seed.wrapping_mul(6_364_136_223_846_793_005).wrapping_add(1);
        out.push_str(WORDS[(seed >> 33) as usize % WORDS.len()]);
        out.push(if seed.is_multiple_of(7) { '\n' } else { ' ' });
    }
    out.truncate(len);
    out
}

/// The cost of a person's apply of a typical dotfiles archive (the copy manager, no bootstrap):
/// `dotfiles.apply` to its answer, 40 times. A measurement, run by hand:
/// `SEALANTD_REQUIRE_ROOT_TESTS=1 run_as_user --ignored --nocapture dotfiles_apply_timing`.
#[tokio::test]
#[ignore = "a measurement"]
async fn dotfiles_apply_timing() {
    if !ready() {
        return;
    }
    let dir = scratch();
    let tree = dir.path().join("tree");
    // About 150 files in 20 directories, 1 MB: shell, editor, git, terminal and a few scripts.
    for (d, files, size) in [
        (".config/nvim/lua/plugins", 40, 2_000),
        (".config/nvim/after/ftplugin", 20, 500),
        (".config/fish/functions", 30, 800),
        (".config/fish/conf.d", 10, 400),
        (".config/git", 3, 300),
        (".config/alacritty", 2, 3_000),
        (".config/tmux/plugins", 10, 5_000),
        (".local/bin", 20, 1_500),
        (".ssh", 1, 200),
        (".config/zsh", 10, 2_000),
        (".", 4, 4_000),
    ] {
        std::fs::create_dir_all(tree.join(d)).unwrap();
        for i in 0..files {
            std::fs::write(tree.join(d).join(format!(".mtest-{i}.conf")), text(size)).unwrap();
        }
    }
    std::fs::write(tree.join(".config/mtest-blob"), text(600_000)).unwrap();
    let archives = dir.path().join("archives");
    pack_one(&tree, &archives, "copy", &[], &["."]);
    let size = std::fs::metadata(archives.join("0.tar.gz")).unwrap().len();
    let mut client = Client::start(dir.path());
    let mut times = Vec::new();
    for _ in 0..40 {
        let started = Instant::now();
        ok(client
            .request(Command::DotfilesApply(Box::new(DotfilesApplyArgs {
                user: BOB.to_owned(),
                repository: None,
                archive_dir: Some(archives.display().to_string()),
                execution_id: None,
            })))
            .await);
        times.push(started.elapsed().as_secs_f64() * 1000.0);
    }
    times.sort_by(f64::total_cmp);
    eprintln!(
        "dotfiles.apply ({size} B archive): median {:.2} ms, p90 {:.2} ms, min {:.2} ms",
        times[times.len() / 2],
        times[times.len() * 9 / 10],
        times[0]
    );
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
    let environment_nnp = sealant_process::platform::no_new_privs() != Some(false);
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
        // The root suite proves the per-person posture: an environment that imposes
        // no-new-privileges cannot, so it fails the suite rather than pass it unproven.
        assert!(
            std::env::var("SEALANTD_REQUIRE_ROOT_TESTS").as_deref() != Ok("1"),
            "SEALANTD_REQUIRE_ROOT_TESTS=1 in an environment that imposes no-new-privileges"
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

/// The test's sudoers entry, under a name of this process's own (two runs never share one), and
/// removed when dropped, a panic's unwinding included. One a killed run left behind is removed
/// by the next ([`SudoersEntry::sweep`], from `ready`). Root's work, on a CI runner or in a
/// container: it gives the test person passwordless root while it exists.
struct SudoersEntry {
    path: PathBuf,
}

impl SudoersEntry {
    const DIR: &str = "/etc/sudoers.d";
    const PREFIX: &str = "mtest-sealantd-";

    /// Passwordless sudo for the test person, as Core's images give the `mend` group.
    fn add() -> Self {
        std::fs::create_dir_all(Self::DIR).unwrap();
        let path = PathBuf::from(Self::DIR).join(format!("{}{}", Self::PREFIX, std::process::id()));
        std::fs::write(&path, format!("{BOB} ALL=(ALL) NOPASSWD: ALL\n")).unwrap();
        std::fs::set_permissions(&path, std::os::unix::fs::PermissionsExt::from_mode(0o440))
            .unwrap();
        Self { path }
    }

    /// Remove every entry an earlier run left (a run killed before its drop).
    fn sweep() {
        let Ok(entries) = std::fs::read_dir(Self::DIR) else {
            return;
        };
        for entry in entries.flatten() {
            if entry
                .file_name()
                .to_string_lossy()
                .starts_with(Self::PREFIX)
            {
                let _ = std::fs::remove_file(entry.path());
            }
        }
    }
}

impl Drop for SudoersEntry {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.path);
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
                per_person(),
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
    if sealant_process::platform::no_new_privs() != Some(false) {
        assert!(
            std::env::var("SEALANTD_REQUIRE_ROOT_TESTS").as_deref() != Ok("1"),
            "SEALANTD_REQUIRE_ROOT_TESTS=1 in an environment that imposes no-new-privileges"
        );
        eprintln!("this environment sets no-new-privileges itself: sudo cannot work in it");
        return;
    }
    let _sudoers = SudoersEntry::add();
    let (seen, caps) = sudo_as_person(false);
    assert!(seen.starts_with("exit=0\n"), "sudo as a person:\n{seen}");
    assert_eq!(caps.no_new_privileges, Some(false), "{caps:?}");
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
    assert_eq!(caps.no_new_privileges, Some(true), "{caps:?}");
    assert!(caps.person_capabilities.is_empty(), "{caps:?}");
}
