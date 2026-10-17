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
use sealant_process::CommandGateExt;
use sealant_protocol::{
    ClientMessage, Command, CommandResult, ControlRequest, ControlResponse, DotfilesApplyArgs,
    ExecArgs, OpenSessionArgs, OpenSftpArgs, RequestId, ResponseOutcome, ServerMessage,
    SessionMode, StreamFrame, StreamPayload,
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
            let out = Std::new(args[0])
                .args(&args[1..])
                .stdin(std::process::Stdio::null())
                .output_gated()
                .unwrap();
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
            .stdin(std::process::Stdio::null())
            .output_gated()
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

/// One SFTP packet: its length, its type, then its body.
fn sftp_packet(kind: u8, body: &[u8]) -> Vec<u8> {
    let mut packet = u32::try_from(body.len() + 1)
        .unwrap()
        .to_be_bytes()
        .to_vec();
    packet.push(kind);
    packet.extend_from_slice(body);
    packet
}

/// Send `bytes` on `channel` and answer the first SFTP packet the bridge sends back: its type and
/// its body.
async fn sftp_round_trip(
    client: &mut Client,
    channel: &sealant_protocol::ChannelId,
    seq: u64,
    bytes: Vec<u8>,
) -> (u8, Vec<u8>) {
    let body = sealant_protocol::encode_client(&ClientMessage::Stream(StreamFrame::data(
        channel.clone(),
        seq,
        bytes,
    )));
    write_frame(&mut client.writer, &body, MAX).await.unwrap();
    let mut got = Vec::new();
    let read = async {
        loop {
            let body = read_frame(&mut client.reader, MAX).await.unwrap().unwrap();
            if let ServerMessage::Stream(frame) = sealant_protocol::decode_server(&body).unwrap()
                && &frame.channel_id == channel
            {
                match frame.payload {
                    StreamPayload::Data { data } => got.extend_from_slice(data.as_slice()),
                    StreamPayload::End(end) => panic!("the sftp-server ended: {end:?}"),
                    StreamPayload::WindowUpdate { .. } => {}
                }
            }
            if got.len() >= 4 {
                let len = u32::from_be_bytes(got[..4].try_into().unwrap()) as usize;
                if got.len() >= 4 + len {
                    return (got[4], got[5..4 + len].to_vec());
                }
            }
        }
    };
    tokio::time::timeout(Duration::from_secs(20), read)
        .await
        .expect("an SFTP answer")
}

/// An SFTP bridge with a user runs its `sftp-server` as that user: a directory it makes is
/// theirs, and one in a home they cannot enter is refused. Needs the `sftp-server` (required).
#[tokio::test]
async fn an_sftp_bridge_runs_as_the_user_it_names() {
    if !ready() {
        return;
    }
    // `ready()` holds only with SEALANTD_REQUIRE_ROOT_TESTS=1, where a skip would pass a security
    // test that never ran: the image must carry the sftp-server (CI installs it).
    assert!(
        sealant_process::sftp::resolve_sftp_server().is_some(),
        "SEALANTD_REQUIRE_ROOT_TESTS=1 but no sftp-server here: install openssh-sftp-server"
    );
    let dir = scratch();
    let mut client = Client::start(dir.path());
    let Some(CommandResult::SftpOpened(opened)) = ok(client
        .request(Command::OpenSftp(OpenSftpArgs {
            execution_id: None,
            cwd: None,
            user: Some(BOB.to_owned()),
        }))
        .await)
    else {
        panic!("no SFTP channel");
    };
    let channel = opened.channel_id;
    // SSH_FXP_INIT, version 3: answered with SSH_FXP_VERSION.
    let (kind, _) = sftp_round_trip(
        &mut client,
        &channel,
        0,
        sftp_packet(1, &3u32.to_be_bytes()),
    )
    .await;
    assert_eq!(kind, 2, "no SSH_FXP_VERSION");
    // SSH_FXP_MKDIR: request id, path, attributes with no flags; answered with SSH_FXP_STATUS.
    let mkdir = |id: u32, path: &Path| {
        let path = path.display().to_string();
        let mut body = id.to_be_bytes().to_vec();
        body.extend_from_slice(&u32::try_from(path.len()).unwrap().to_be_bytes());
        body.extend_from_slice(path.as_bytes());
        body.extend_from_slice(&0u32.to_be_bytes());
        sftp_packet(14, &body)
    };
    let made = dir.path().join("made-over-sftp");
    let (kind, body) = sftp_round_trip(&mut client, &channel, 1, mkdir(7, &made)).await;
    assert_eq!(kind, 101, "no SSH_FXP_STATUS");
    assert_eq!(
        &body[4..8],
        &0u32.to_be_bytes(),
        "the mkdir failed: {body:?}"
    );
    let meta = std::fs::metadata(&made).unwrap();
    assert_eq!((meta.uid(), meta.gid()), (BOB_UID, GID), "not Bob's");
    // Cat's home is 0700 and Cat's: Bob's sftp-server cannot make anything in it.
    let (kind, body) = sftp_round_trip(
        &mut client,
        &channel,
        2,
        mkdir(8, &Path::new(&format!("/home/{CAT}")).join("from-bob")),
    )
    .await;
    assert_eq!(kind, 101, "no SSH_FXP_STATUS");
    assert_ne!(
        &body[4..8],
        &0u32.to_be_bytes(),
        "Bob made a directory in Cat's home"
    );
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

/// `user` named by `exec`, by `openSession` (pipe and PTY), by `dotfiles.apply` and by `openSftp`, each answered
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
    commands.push(Command::OpenSftp(OpenSftpArgs {
        execution_id: None,
        cwd: None,
        user: Some(user.to_owned()),
    }));
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
            .status_gated()
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
    // The modes the archive carries, on files and on directories, in the staged tree and on the
    // copies in the home alike; the staged tree itself (the archive's `./`) takes what a new
    // directory in the home takes, as it always has: the daemon's umask, under whatever default
    // ACL the home carries.
    let mode = |path: &Path| std::fs::symlink_metadata(path).unwrap().mode() & 0o7777;
    let tree_mode = mode(&tree);
    for (path, expected) in [
        (".mtest-zshrc", 0o644),
        (".mtest-private", 0o600),
        (".mtest-bin/hello", 0o755),
        (".mtest-bin", 0o750),
        (".config/mtest", mode(&tree.join(".config/mtest"))),
        (".local/share/sealant-dotfiles/0", tree_mode),
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

/// The mode a directory made in `home` by the daemon's process takes: `0o777` under the
/// process umask, or under the home's default ACL where it has one (a host's `setfacl -d` on
/// `/home` gives every new directory the group's write bit whatever the umask; the test homes
/// on GitHub's hosted Ubuntu runner carry one, sealantd#181). Measured on a directory made and
/// removed here, in the same process.
fn made_dir_mode(home: &Path) -> u32 {
    let probe = home.join(".mtest-mode-probe");
    let _ = std::fs::remove_dir(&probe);
    std::fs::create_dir(&probe).unwrap();
    let mode = std::fs::symlink_metadata(&probe).unwrap().mode() & 0o7777;
    std::fs::remove_dir(&probe).unwrap();
    mode
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

/// A directory the copy makes in the home takes the tree's mode and the mode a new directory
/// there takes, intersected, without set-id and sticky bits: under umask `022`, `002` and `077`,
/// and under a default ACL that gives new directories group write, and one whose mask gives them
/// nothing. In every case the mode is the tree's under the fresh mode, and never wider than the
/// fresh mode, what the copy left before. A `0555` directory keeps its mode and its file: it
/// gets the mode once the whole request is in.
#[tokio::test]
async fn dotfiles_directories_take_the_tree_s_mode_under_what_a_new_directory_takes() {
    if !ready() {
        return;
    }
    let dir = scratch();
    let home = PathBuf::from(format!("/home/{BOB}"));
    // (path, mode in the tree)
    let dir_modes = [
        (".mtest-ssh", 0o700),
        (".mtest-modes", 0o750),
        (".mtest-modes/open", 0o755),
        (".mtest-modes/open/private", 0o700),
        (".mtest-modes/readonly", 0o555),
        (".mtest-modes/wide", 0o775),
        (".mtest-modes/wider", 0o777),
        (".mtest-modes/suid", 0o4755),
        (".mtest-modes/sgid", 0o2755),
        (".mtest-modes/sticky", 0o1755),
    ];
    let files: Vec<(String, &str)> = dir_modes
        .iter()
        .map(|(path, _)| (format!("{path}/f"), "x\n"))
        .collect();
    let tree = write_tree(
        dir.path(),
        "tree",
        &files
            .iter()
            .map(|(p, b)| (p.as_str(), *b))
            .collect::<Vec<_>>(),
        &[(".mtest-ssh/f", 0o600), (".mtest-modes/readonly/f", 0o444)]
            .into_iter()
            .chain(dir_modes)
            .collect::<Vec<_>>(),
    );
    let archives = dir.path().join("archives");
    pack_one(&tree, &archives, "copy", &[], &["."]);
    let mut client = Client::start(dir.path());
    let mode = |path: &Path| std::fs::symlink_metadata(path).unwrap().mode() & 0o7777;
    let clear = || clear_bob_s_dotfiles(&home, &[".mtest-ssh", ".mtest-modes"]);

    let group_rwx = format!("u::rwx,g::rwx,g:{EXTRA_GID}:rwx,m::rwx,o::rx");
    let nothing = format!("u::rwx,g::---,g:{EXTRA_GID}:---,m::---,o::---");
    // (case, what a new directory in the home then takes)
    for (name, by, expected_fresh) in [
        ("umask 022", HomeDirsBy::Umask(0o022), 0o755),
        ("umask 002", HomeDirsBy::Umask(0o002), 0o775),
        ("umask 077", HomeDirsBy::Umask(0o077), 0o700),
        (
            "default ACL, group rwx",
            HomeDirsBy::Acl(group_rwx.as_str()),
            0o775,
        ),
        (
            "default ACL, mask ---",
            HomeDirsBy::Acl(nothing.as_str()),
            0o700,
        ),
    ] {
        let case = HomeDirsCase::start(by, &home, dir.path());
        clear();
        let fresh = made_dir_mode(&home);
        assert_eq!(fresh, expected_fresh, "{name}: what a new directory takes");

        ok(client
            .request(Command::DotfilesApply(Box::new(apply_bob(&archives))))
            .await)
        .unwrap();
        for (path, source) in dir_modes {
            let got = mode(&home.join(path));
            assert_eq!(got, source & fresh & 0o777, "{name}: {path}");
            assert_eq!(got & !fresh, 0, "{name}: {path} wider than a new directory");
            let meta = std::fs::symlink_metadata(home.join(path)).unwrap();
            assert_eq!((meta.uid(), meta.gid()), (BOB_UID, GID), "{name}: {path}");
        }
        assert_eq!(mode(&home.join(".mtest-ssh/f")), 0o600, "{name}");
        assert_eq!(mode(&home.join(".mtest-modes/readonly/f")), 0o444, "{name}");
        assert_eq!(
            std::fs::read_to_string(home.join(".mtest-modes/readonly/f")).unwrap(),
            "x\n",
            "{name}"
        );
        if let HomeDirsBy::Acl(_) = by {
            // The inherited entries stay; the mask is the mode's group bits, never wider than
            // the fresh mode's.
            for (path, source) in [(".mtest-ssh", 0o700), (".mtest-modes/wide", 0o775)] {
                let acl = getfacl(&home.join(path));
                let mask = format!("mask::{}", rwx((source & fresh) >> 3 & 0o7));
                assert!(
                    acl.contains(&mask) && acl.contains(&format!("group:{EXTRA_GROUP}:")),
                    "{name}: {path}: {acl}"
                );
            }
        }
        clear();
        drop(case);
    }
}

/// A directory already in the home keeps its mode and bits, whatever the tree says, and takes
/// the tree's files as it did before: one the person can only write and search (`0300`), and a
/// root-owned one they write through their group (`0570`). A read-only one with setgid that
/// they own but whose group is not theirs (`2555`) refuses the file, as before, and keeps its
/// bits: nothing is ever `chmod`ed to make room.
#[tokio::test]
async fn existing_directories_in_the_home_keep_their_modes_and_bits() {
    if !ready() {
        return;
    }
    let dir = scratch();
    let home = PathBuf::from(format!("/home/{BOB}"));
    let mode = |path: &Path| std::fs::symlink_metadata(path).unwrap().mode() & 0o7777;
    // Made with no ACL of its own (`setfacl -b`): under a default ACL on the home (GitHub's
    // runners give one, inherited from `/home`, with a named entry) the directory would carry a
    // mask, and a `chmod` then sets the mask, not the owning group's entry, so `bits` would not
    // be the mode the test means.
    let existing = |name: &str, uid: u32, gid: u32, bits: u32| {
        let path = home.join(name);
        let _ = std::fs::remove_dir_all(&path);
        std::fs::create_dir(&path).unwrap();
        assert!(
            Std::new("setfacl")
                .arg("-b")
                .arg(&path)
                .status_gated()
                .unwrap()
                .success(),
            "setfacl -b {name}"
        );
        std::os::unix::fs::chown(&path, Some(uid), Some(gid)).unwrap();
        std::fs::set_permissions(&path, std::os::unix::fs::PermissionsExt::from_mode(bits))
            .unwrap();
        assert_eq!(mode(&path), bits, "{name} as made");
    };
    existing(".mtest-ws", BOB_UID, GID, 0o300);
    existing(".mtest-grp", 0, GID, 0o570);
    existing(".mtest-sgid", BOB_UID, 0, 0o2555);
    let clear = || {
        clear_bob_s_dotfiles(&home, &[".mtest-ws", ".mtest-grp", ".mtest-sgid"]);
    };
    let mut client = Client::start(dir.path());

    let tree = write_tree(
        dir.path(),
        "writable",
        &[(".mtest-ws/f", "ws\n"), (".mtest-grp/f", "grp\n")],
        &[],
    );
    let archives = dir.path().join("archives-writable");
    pack_one(&tree, &archives, "copy", &[], &["."]);
    ok(client
        .request(Command::DotfilesApply(Box::new(apply_bob(&archives))))
        .await)
    .unwrap();
    assert_eq!(mode(&home.join(".mtest-ws")), 0o300);
    assert_eq!(mode(&home.join(".mtest-grp")), 0o570);
    assert_eq!(std::fs::metadata(home.join(".mtest-grp")).unwrap().uid(), 0);
    assert_eq!(
        std::fs::read_to_string(home.join(".mtest-ws/f")).unwrap(),
        "ws\n"
    );
    assert_eq!(
        std::fs::read_to_string(home.join(".mtest-grp/f")).unwrap(),
        "grp\n"
    );

    let tree = write_tree(dir.path(), "sgid", &[(".mtest-sgid/f", "sgid\n")], &[]);
    let archives = dir.path().join("archives-sgid");
    pack_one(&tree, &archives, "copy", &[], &["."]);
    let refused = apply_refused(&mut client, BOB, &archives).await;
    assert!(
        refused.contains(&format!("{}/.mtest-sgid/f", home.display()))
            && refused.contains("Permission denied"),
        "{refused}"
    );
    assert_eq!(mode(&home.join(".mtest-sgid")), 0o2555, "{refused}");
    clear();
}

/// A read-only directory of one archive (`0555`) takes a later archive's file in the same
/// request: it keeps the mode `mkdir` gave it until the request is in, and is `0555` after. A
/// request that fails part-way still gives every directory it made its mode: the `0555` one is
/// `0555`, with the first archive's file, and the error names what failed.
#[tokio::test]
async fn a_read_only_directory_of_one_archive_takes_the_next_archive_s_files() {
    if !ready() {
        return;
    }
    let dir = scratch();
    let home = PathBuf::from(format!("/home/{BOB}"));
    let mode = |path: &Path| std::fs::symlink_metadata(path).unwrap().mode() & 0o7777;
    let first = write_tree(
        dir.path(),
        "first",
        &[(".mtest-ro/f", "one\n"), (".mtest-ro/blocker", "a file\n")],
        &[(".mtest-ro", 0o555)],
    );
    // The same directory at 0755 in the tree: the mode is the first archive's, as `cp -a`
    // leaves the directory it made.
    let second = write_tree(dir.path(), "second", &[(".mtest-ro/f", "two\n")], &[]);
    let clear = || clear_bob_s_dotfiles(&home, &[".mtest-ro"]);
    let mut client = Client::start(dir.path());

    clear();
    let archives = dir.path().join("archives-merge");
    pack_many(&[&first, &second], &archives);
    ok(client
        .request(Command::DotfilesApply(Box::new(apply_bob(&archives))))
        .await)
    .unwrap();
    assert_eq!(
        std::fs::read_to_string(home.join(".mtest-ro/f")).unwrap(),
        "two\n"
    );
    assert_eq!(mode(&home.join(".mtest-ro")), 0o555);
    assert!(home.join(".mtest-ro/blocker").is_file());

    // `blocker` is a directory in the later tree and a file in the home: the copy fails there.
    clear();
    let third = write_tree(dir.path(), "third", &[(".mtest-ro/blocker/x", "x\n")], &[]);
    let archives = dir.path().join("archives-failing");
    pack_many(&[&first, &third], &archives);
    let refused = apply_refused(&mut client, BOB, &archives).await;
    assert!(
        refused.contains(&format!("{}/.mtest-ro/blocker", home.display())),
        "{refused}"
    );
    assert_eq!(mode(&home.join(".mtest-ro")), 0o555, "{refused}");
    assert_eq!(
        std::fs::read_to_string(home.join(".mtest-ro/f")).unwrap(),
        "one\n"
    );
    clear();
}

/// The copy gives a mode only to the directory it made: with the copy held between making
/// `.mtest-swap` and opening it (`SEALANTD_DOTFILES_TEST_HOLD`), the new directory is renamed
/// away and a directory of the person's with a file in it renamed into its place. The copy finds
/// the directory not empty, refuses the request naming it, and that directory keeps its `0700`
/// and its file. What the copy made is left where it was moved, at the mode `mkdir` gave it.
#[tokio::test]
async fn a_directory_replaced_before_the_copy_opens_it_is_refused() {
    if !ready() {
        return;
    }
    let dir = scratch();
    let home = PathBuf::from(format!("/home/{BOB}"));
    let mode = |path: &Path| std::fs::symlink_metadata(path).unwrap().mode() & 0o7777;
    let clear = || {
        clear_bob_s_dotfiles(&home, &[".mtest-swap", ".mtest-swap.moved", ".mtest-keep"]);
    };
    clear();
    let keep = home.join(".mtest-keep");
    std::fs::create_dir(&keep).unwrap();
    std::fs::write(keep.join("secret"), "mine\n").unwrap();
    for path in [&keep, &keep.join("secret")] {
        std::os::unix::fs::chown(path, Some(BOB_UID), Some(GID)).unwrap();
    }
    std::fs::set_permissions(&keep, std::os::unix::fs::PermissionsExt::from_mode(0o700)).unwrap();
    let tree = write_tree(
        dir.path(),
        "tree",
        &[(".mtest-swap/f", "x\n")],
        &[(".mtest-swap", 0o750)],
    );
    let archives = dir.path().join("archives");
    pack_one(&tree, &archives, "copy", &[], &["."]);
    let fresh = made_dir_mode(&home);

    let hold = Hold::at("made", ".mtest-swap", dir.path());
    let swap = hold.then({
        let home = home.clone();
        move || {
            std::fs::rename(home.join(".mtest-swap"), home.join(".mtest-swap.moved")).unwrap();
            std::fs::rename(home.join(".mtest-keep"), home.join(".mtest-swap")).unwrap();
        }
    });
    let mut client = Client::start(dir.path());
    let refused = apply_refused(&mut client, BOB, &archives).await;
    swap.join().unwrap();
    drop(hold);
    assert!(
        refused.contains(&format!("{}/.mtest-swap", home.display()))
            && refused.contains("not empty"),
        "{refused}"
    );
    assert_eq!(mode(&home.join(".mtest-swap")), 0o700);
    assert_eq!(
        std::fs::read_to_string(home.join(".mtest-swap/secret")).unwrap(),
        "mine\n"
    );
    assert!(!home.join(".mtest-swap/f").exists());
    assert_eq!(mode(&home.join(".mtest-swap.moved")), fresh);
    clear();
}

/// The mode goes on the directory the copy made, found again from the home root with no link
/// followed: with the copy held before `.mtest-swap` gets its mode, the directory is renamed
/// away and a link to a `0700` directory of the person's outside the home put in its place. The
/// walk refuses the link, the request fails naming the directory as left at the mode `mkdir`
/// gave it, and the directory outside stays `0700`.
#[tokio::test]
async fn a_swapped_pathname_does_not_take_the_copied_directory_s_mode() {
    if !ready() {
        return;
    }
    let dir = scratch();
    let home = PathBuf::from(format!("/home/{BOB}"));
    let mode = |path: &Path| std::fs::symlink_metadata(path).unwrap().mode() & 0o7777;
    let victim = dir.path().join("victim");
    std::fs::create_dir(&victim).unwrap();
    std::os::unix::fs::chown(&victim, Some(BOB_UID), Some(GID)).unwrap();
    std::fs::set_permissions(&victim, std::os::unix::fs::PermissionsExt::from_mode(0o700)).unwrap();
    let tree = write_tree(
        dir.path(),
        "tree",
        &[(".mtest-swap/f", "x\n")],
        &[(".mtest-swap", 0o750)],
    );
    let archives = dir.path().join("archives");
    pack_one(&tree, &archives, "copy", &[], &["."]);
    let clear = || {
        let _ = std::fs::remove_file(home.join(".mtest-swap"));
        clear_bob_s_dotfiles(&home, &[".mtest-swap", ".mtest-swap.moved"]);
    };
    clear();
    let fresh = made_dir_mode(&home);

    let hold = Hold::at("final", ".mtest-swap", dir.path());
    let swap = hold.then({
        let (home, victim) = (home.clone(), victim.clone());
        move || {
            std::fs::rename(home.join(".mtest-swap"), home.join(".mtest-swap.moved")).unwrap();
            std::os::unix::fs::symlink(&victim, home.join(".mtest-swap")).unwrap();
            std::os::unix::fs::lchown(home.join(".mtest-swap"), Some(BOB_UID), Some(GID)).unwrap();
        }
    });
    let mut client = Client::start(dir.path());
    let refused = apply_refused(&mut client, BOB, &archives).await;
    swap.join().unwrap();
    drop(hold);
    assert!(
        refused.contains("left at the mode a new directory takes")
            && refused.contains(&format!("{}/.mtest-swap", home.display())),
        "{refused}"
    );
    assert_eq!(
        mode(&victim),
        0o700,
        "the directory outside the home is untouched"
    );
    assert_eq!(mode(&home.join(".mtest-swap.moved")), fresh);
    assert!(
        std::fs::symlink_metadata(home.join(".mtest-swap"))
            .unwrap()
            .is_symlink()
    );
    clear();
}

/// The group-writable fixture puts the home's default ACL back as it was, so the tests after it
/// run under the ACL the suite started with (a default ACL on `/home` is inherited by the homes
/// the suite makes).
#[tokio::test]
async fn the_group_writable_fixture_restores_the_home_s_default_acl() {
    if !ready() {
        return;
    }
    let dir = scratch();
    let home = PathBuf::from(format!("/home/{BOB}"));
    let setfacl = |args: &[&str]| {
        assert!(
            Std::new("setfacl")
                .args(args)
                .arg(&home)
                .status_gated()
                .unwrap()
                .success(),
            "setfacl {args:?}"
        );
    };
    // The home as the suite found it (under a default ACL on `/home`, an inherited one), put
    // back at the end the same way.
    let original = dir.path().join("original-acl");
    std::fs::write(&original, getfacl(&home)).unwrap();
    setfacl(&["-k"]);
    setfacl(&[
        "-d",
        "-m",
        &format!("u::rwx,g::r-x,g:{EXTRA_GID}:r-x,m::r-x,o::---"),
    ]);
    let before = getfacl(&home);
    assert!(before.contains("default:mask::r-x"), "{before}");
    let entries = format!("u::rwx,g::rwx,g:{EXTRA_GID}:rwx,m::rwx,o::rx");
    let case = HomeDirsCase::start(HomeDirsBy::Acl(&entries), &home, dir.path());
    assert!(getfacl(&home).contains("default:mask::rwx"));
    drop(case);
    assert_eq!(getfacl(&home), before);
    setfacl(&["-k"]);
    assert!(!getfacl(&home).contains("default:"));
    assert!(
        Std::new("setfacl")
            .arg(format!("--restore={}", original.display()))
            .status_gated()
            .unwrap()
            .success()
    );
    assert_eq!(getfacl(&home), std::fs::read_to_string(&original).unwrap());
}

/// A tree 130 directories deep copies under a descriptor limit 200 above what the process has
/// open: the copy holds one descriptor per level, the directory it writes into, as `main`'s
/// `ReadDir` per level did, and the deepest directory gets its mode like any other.
#[tokio::test]
async fn a_deep_tree_copies_under_a_low_descriptor_limit() {
    if !ready() {
        return;
    }
    let dir = scratch();
    let home = PathBuf::from(format!("/home/{BOB}"));
    let mode = |path: &Path| std::fs::symlink_metadata(path).unwrap().mode() & 0o7777;
    let depth = 130;
    let mut rel = PathBuf::from(".mtest-deep");
    for _ in 0..depth {
        rel.push("d");
    }
    let tree = write_tree(
        dir.path(),
        "tree",
        &[(rel.join("f").to_str().unwrap(), "deep\n")],
        &[(rel.to_str().unwrap(), 0o700)],
    );
    let archives = dir.path().join("archives");
    pack_one(&tree, &archives, "copy", &[], &["."]);
    let clear = || clear_bob_s_dotfiles(&home, &[".mtest-deep"]);
    clear();
    let mut client = Client::start(dir.path());

    let open = std::fs::read_dir("/proc/self/fd").unwrap().count();
    let _limit = DescriptorLimit::lower_to(open + 200);
    let response = client
        .request(Command::DotfilesApply(Box::new(apply_bob(&archives))))
        .await;
    assert!(
        matches!(response.outcome, ResponseOutcome::Ok { .. }),
        "{depth} levels under {} descriptors: {:?}",
        open + 200,
        response.outcome
    );
    assert_eq!(
        std::fs::read_to_string(home.join(&rel).join("f")).unwrap(),
        "deep\n"
    );
    assert_eq!(mode(&home.join(&rel)), 0o700);
    clear();
}

/// `RLIMIT_NOFILE`'s soft limit lowered for this process, put back when dropped.
struct DescriptorLimit {
    before: (u64, u64),
}

impl DescriptorLimit {
    fn lower_to(limit: usize) -> Self {
        use nix::sys::resource::{Resource, getrlimit, setrlimit};
        let before = getrlimit(Resource::RLIMIT_NOFILE).unwrap();
        setrlimit(Resource::RLIMIT_NOFILE, limit as u64, before.1).unwrap();
        Self { before }
    }
}

impl Drop for DescriptorLimit {
    fn drop(&mut self) {
        use nix::sys::resource::{Resource, setrlimit};
        let _ = setrlimit(Resource::RLIMIT_NOFILE, self.before.0, self.before.1);
    }
}

/// `bits` (0 to 7) as `getfacl` writes them.
fn rwx(bits: u32) -> String {
    ["r", "w", "x"]
        .iter()
        .enumerate()
        .map(|(i, letter)| if bits & (4 >> i) != 0 { *letter } else { "-" })
        .collect()
}

/// `dotfiles.apply` of `archives` for Bob.
fn apply_bob(archives: &Path) -> DotfilesApplyArgs {
    DotfilesApplyArgs {
        user: BOB.to_owned(),
        repository: None,
        archive_dir: Some(archives.display().to_string()),
        execution_id: None,
    }
}

/// `<dir>/<name>`: `files` written (parents made), then `modes` set, in order.
fn write_tree(dir: &Path, name: &str, files: &[(&str, &str)], modes: &[(&str, u32)]) -> PathBuf {
    let tree = dir.join(name);
    for (path, bytes) in files {
        let path = tree.join(path);
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(&path, bytes).unwrap();
    }
    for (path, mode) in modes {
        std::fs::set_permissions(
            tree.join(path),
            std::os::unix::fs::PermissionsExt::from_mode(*mode),
        )
        .unwrap();
    }
    tree
}

/// `getfacl -p path`.
fn getfacl(path: &Path) -> String {
    let out = Std::new("getfacl")
        .arg("-p")
        .arg(path)
        .stdin(std::process::Stdio::null())
        .output_gated()
        .unwrap();
    assert!(out.status.success(), "getfacl {}", path.display());
    String::from_utf8(out.stdout).unwrap()
}

/// Removed as root, `tops` and the staged trees: the person could not, a `0555` directory
/// refusing the unlink of its file (what `rm -rf` as the owner refuses too), and that is what a
/// second apply's own removal of a staged tree runs into (a limit `main` has as well).
fn clear_bob_s_dotfiles(home: &Path, tops: &[&str]) {
    for top in tops {
        let _ = std::fs::remove_dir_all(home.join(top));
    }
    for index in ["0", "1"] {
        let _ = std::fs::remove_dir_all(home.join(".local/share/sealant-dotfiles").join(index));
    }
}

/// What a new directory in a home takes its mode from: the process umask, or a default ACL on
/// the home with these entries.
#[derive(Clone, Copy)]
enum HomeDirsBy<'a> {
    Umask(u32),
    Acl(&'a str),
}

/// One [`HomeDirsBy`] in effect, undone when dropped (a panic included): the umask put back, the
/// home's ACL put back as `getfacl` recorded it before (`setfacl --restore`). A umask case takes
/// the home's default ACL off meanwhile (the suite may run under one inherited from `/home`),
/// so the umask is what a new directory takes.
struct HomeDirsCase {
    umask: Option<nix::sys::stat::Mode>,
    acl: (PathBuf, PathBuf),
}

impl HomeDirsCase {
    fn start(by: HomeDirsBy<'_>, home: &Path, scratch: &Path) -> Self {
        let saved = scratch.join(format!("acl-{}", std::process::id()));
        std::fs::write(&saved, getfacl(home)).unwrap();
        let status = Std::new("setfacl")
            .args(["-k"])
            .arg(home)
            .status_gated()
            .unwrap();
        assert!(status.success(), "setfacl -k on {}", home.display());
        let umask = match by {
            HomeDirsBy::Umask(mask) => Some(nix::sys::stat::umask(
                nix::sys::stat::Mode::from_bits_truncate(mask),
            )),
            HomeDirsBy::Acl(entries) => {
                let status = Std::new("setfacl")
                    .args(["-d", "-m", entries])
                    .arg(home)
                    .status_gated()
                    .unwrap();
                assert!(status.success(), "setfacl -d on {}", home.display());
                None
            }
        };
        Self {
            umask,
            acl: (home.to_path_buf(), saved),
        }
    }
}

impl Drop for HomeDirsCase {
    fn drop(&mut self) {
        if let Some(before) = self.umask {
            nix::sys::stat::umask(before);
        }
        let (home, saved) = &self.acl;
        let _ = Std::new("setfacl").arg("-k").arg(home).status_gated();
        let _ = Std::new("setfacl")
            .arg(format!("--restore={}", saved.display()))
            .status_gated();
    }
}

/// The daemon held at `point` for the directory `name` (`sealantd::test_support`), set in this
/// process's environment (one thread: `--test-threads 1`) and removed when dropped.
struct Hold {
    gate: PathBuf,
}

impl Hold {
    fn at(point: &str, name: &str, scratch: &Path) -> Self {
        let gate = scratch.join(format!("gate-{point}"));
        unsafe {
            std::env::set_var(
                sealantd::test_support::DOTFILES_HOLD_ENV,
                format!("{point}:{name}={}", gate.display()),
            );
        }
        Self { gate }
    }

    /// Run `swap` once the daemon reaches the hold, then let it go.
    fn then(&self, swap: impl FnOnce() + Send + 'static) -> std::thread::JoinHandle<()> {
        let gate = self.gate.clone();
        let reached = PathBuf::from(format!("{}.reached", gate.display()));
        std::thread::spawn(move || {
            let until = Instant::now() + Duration::from_secs(10);
            while !reached.exists() && Instant::now() < until {
                std::thread::sleep(Duration::from_millis(5));
            }
            assert!(reached.exists(), "the copy never reached the hold");
            swap();
            std::fs::write(&gate, b"").unwrap();
        })
    }
}

impl Drop for Hold {
    fn drop(&mut self) {
        unsafe {
            std::env::remove_var(sealantd::test_support::DOTFILES_HOLD_ENV);
        }
    }
}

/// `trees` packed as `<archives>/<n>.tar.gz`, one manifest applying each with the copy manager,
/// no bootstrap, in order.
fn pack_many(trees: &[&Path], archives: &Path) {
    std::fs::create_dir_all(archives).unwrap();
    let mut entries = Vec::new();
    for (index, tree) in trees.iter().enumerate() {
        assert!(
            Std::new("tar")
                .arg("-czf")
                .arg(archives.join(format!("{index}.tar.gz")))
                .arg("-C")
                .arg(tree)
                .arg(".")
                .status_gated()
                .unwrap()
                .success()
        );
        entries.push(format!(
            r#"{{"file":"{index}.tar.gz","manager":"copy","bootstrap":false}}"#
        ));
    }
    std::fs::write(
        archives.join("manifest.json"),
        format!(r#"{{"archives":[{}]}}"#, entries.join(",")),
    )
    .unwrap();
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
            .status_gated()
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
        // Pinned: the check below is that the apply left the file as it was, not what the
        // home's umask or default ACL gave a new file.
        std::fs::set_permissions(path, std::os::unix::fs::PermissionsExt::from_mode(0o644))
            .unwrap();
    }
    assert!(
        Std::new("chown")
            .args(["-R", &format!("{CAT}:{GROUP}")])
            .arg(cat.join(".config"))
            .arg(cat.join(".local"))
            .status_gated()
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
    // Refused before the link is followed: a link where the tree has a directory is no
    // directory to merge into.
    assert!(
        refused.contains(&format!("{}/.config", bob.display()))
            && (refused.contains("Not a directory")
                || refused.contains("Too many levels of symbolic links")),
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
        .stdin(std::process::Stdio::null())
        .output_gated()
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
            .status_gated()
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
    if Std::new("pnpm")
        .arg("--version")
        .stdin(std::process::Stdio::null())
        .output_gated()
        .is_err()
    {
        panic!("pnpm is required for this test (scripts/ci-root-tests.sh installs it)");
    }
    let dir = scratch();
    let base = dir.path();
    let git = |root: &Path, args: &[&str]| {
        let out = Std::new("git")
            .current_dir(root)
            .args(args)
            .stdin(std::process::Stdio::null())
            .output_gated()
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
        .stdin(std::process::Stdio::null())
        .output_gated()
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
            .status_gated()
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
