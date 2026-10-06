//! The privilege posture boot takes (plan §18 as amended): the `sealantd boot` binary sets
//! no-new-privileges on itself at preparation, before the workspace is prepared, except as a
//! per-person executor (a root daemon whose capture source carries an owner map naming someone).
//! Read from the booted process's own `/proc/<pid>/status` while it waits on the capture channel:
//! a stub answers `plan.get` with `409 worktree-leased`, so the boot waits after preparation's
//! posture step and before any harness runs.
//!
//! Root's work (boot makes `/run/sealant` and `/root`): these run only with
//! `SEALANTD_REQUIRE_ROOT_TESTS=1`, as root (`scripts/ci-root-tests.sh`).

use std::io::{Read, Write};
use std::net::TcpListener;
use std::process::{Command, Stdio};
use std::sync::mpsc;
use std::time::{Duration, Instant};

/// Whether these run: as root with `SEALANTD_REQUIRE_ROOT_TESTS=1`.
fn ready() -> bool {
    if std::env::var("SEALANTD_REQUIRE_ROOT_TESTS").as_deref() != Ok("1") {
        eprintln!("SEALANTD_REQUIRE_ROOT_TESTS is not 1: boot posture tests skipped");
        return false;
    }
    assert!(
        nix::unistd::geteuid().is_root(),
        "SEALANTD_REQUIRE_ROOT_TESTS=1 but not running as root"
    );
    true
}

/// A capture channel that answers every request `409 worktree-leased` (another launch holds the
/// worktree: the boot waits and asks again). Says on `asked` when the first request arrives.
fn leased_channel() -> (String, mpsc::Receiver<()>) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let endpoint = format!("http://{}", listener.local_addr().unwrap());
    let (asked, first) = mpsc::channel();
    std::thread::spawn(move || {
        for stream in listener.incoming() {
            let Ok(mut stream) = stream else { continue };
            let mut request = [0u8; 8192];
            let _ = stream.read(&mut request);
            let body = br#"{"reason":"worktree-leased","message":"held"}"#;
            let _ = write!(
                stream,
                "HTTP/1.1 409 Conflict\r\nContent-Type: application/json\r\n\
                 Content-Length: {}\r\nConnection: close\r\n\r\n",
                body.len()
            );
            let _ = stream.write_all(body);
            let _ = asked.send(());
        }
    });
    (endpoint, first)
}

/// Boot the binary as a capture boot with `owner_map` (`None`: no map), wait until it asks the
/// channel for its plan (preparation's posture step is behind it), and answer the boot process's
/// `NoNewPrivs` and what it logged.
fn booted_posture(owner_map: Option<&str>) -> (String, String) {
    let tmp = tempfile::tempdir().unwrap();
    let base = tmp.path();
    let (endpoint, asked) = leased_channel();
    let secrets = base.join("secrets.json");
    std::fs::write(&secrets, r#"{"SEALANT_CAPTURE_TOKEN":"t"}"#).unwrap();
    // The binary cargo built; `SEALANTD_BIN` names another path for it (a container that runs
    // this test binary with the daemon mounted elsewhere).
    let bin =
        std::env::var("SEALANTD_BIN").unwrap_or_else(|_| env!("CARGO_BIN_EXE_sealantd").to_owned());
    let mut boot = Command::new(bin);
    boot.args(["boot", "--log-level", "info"])
        .env_clear()
        .env(
            "PATH",
            std::env::var("PATH").unwrap_or_else(|_| "/usr/bin:/bin".to_owned()),
        )
        .env("SEALANT_WORKSPACE_SOURCE", "capture")
        .env("SEALANT_CAPTURE_ENDPOINT", &endpoint)
        .env("SEALANT_CAPTURE_ALLOW_PLAINTEXT", "1")
        .env("SEALANT_SECRET_ENV_FILE", &secrets)
        .env("SEALANT_WORKSPACE_ROOT", base.join("ws"))
        .env("SEALANT_WORKING_DIRECTORY", base.join("ws/repo"))
        .env("SEALANT_CONTROL_SOCKET", base.join("run/control.sock"))
        .env("SEALANT_SESSION_JOURNAL_DIR", base.join("journals"))
        .env("SEALANT_OS_FAMILY", "ubuntu")
        .env("SEALANT_HARNESS_LAUNCH_COMMAND", "true")
        .stdout(Stdio::null())
        .stderr(Stdio::piped());
    if let Some(map) = owner_map {
        boot.env("SEALANT_CAPTURE_OWNER_MAP", map);
    }
    let mut child = boot.spawn().expect("spawn sealantd boot");
    let started = Instant::now();
    let waited = asked.recv_timeout(Duration::from_secs(20));
    let status =
        std::fs::read_to_string(format!("/proc/{}/status", child.id())).unwrap_or_default();
    let _ = child.kill();
    let mut log = String::new();
    if let Some(mut stderr) = child.stderr.take() {
        let _ = stderr.read_to_string(&mut log);
    }
    let _ = child.wait();
    assert!(
        waited.is_ok(),
        "the boot never asked for its plan within {:?}:\n{log}",
        started.elapsed()
    );
    let nnp = status
        .lines()
        .find(|l| l.starts_with("NoNewPrivs:"))
        .unwrap_or_else(|| panic!("no NoNewPrivs line:\n{status}"))
        .trim_start_matches("NoNewPrivs:")
        .trim()
        .to_owned();
    (nnp, log)
}

/// Without an owner map, the booted daemon has no-new-privileges, as every executor always had.
#[test]
fn a_boot_without_an_owner_map_sets_no_new_privileges() {
    if !ready() {
        return;
    }
    let (nnp, log) = booted_posture(None);
    assert_eq!(nnp, "1", "{log}");
    assert!(
        log.contains("privilege posture: no-new-privileges set"),
        "{log}"
    );
}

/// An owner map that names nobody is no per-person launch: it keeps no-new-privileges.
#[test]
fn a_boot_with_an_owner_map_naming_nobody_sets_no_new_privileges() {
    if !ready() {
        return;
    }
    let (nnp, log) = booted_posture(Some(r#"{"gid":40000,"worktree":40012}"#));
    assert_eq!(nnp, "1", "{log}");
}

/// A per-person executor (an owner map naming someone) boots without no-new-privileges, and says
/// so; where the environment imposed it, the log says no person's sudo will work.
#[test]
fn a_per_person_boot_leaves_no_new_privileges_unset() {
    if !ready() {
        return;
    }
    let imposed = nix::sys::prctl::get_no_new_privs().unwrap_or(true);
    let (nnp, log) = booted_posture(Some(
        r#"{"gid":40000,"worktree":40012,"people":{"acct_a":40012}}"#,
    ));
    if imposed {
        assert_eq!(nnp, "1", "{log}");
        assert!(log.contains("no person's sudo will work"), "{log}");
        return;
    }
    assert_eq!(nnp, "0", "a per-person boot set no-new-privileges:\n{log}");
    assert!(log.contains("so every person's sudo works"), "{log}");
}
