//! A recovery boot on the disk of a standby no session claimed and no writer was admitted on
//! (Docker end to end, round 8, F7) has nothing to save, and says so before it dials the
//! channel: exit 76 ([`sealantd::runtime::EXIT_NOTHING_TO_SAVE`]), `sealantd boot: nothing to
//! save: a standby no session claimed (…)` on stderr (the line Core's recovery reads), the disk
//! untouched. Before, the recovery resumed the placeholder's captures, which no registrar takes,
//! and exited 75: the platform kept the standby until someone discarded it. The same disk once
//! a writer was admitted (the marker gone) is not nothing: the recovery goes on and, here
//! without a session token, exits 75.

use std::path::Path;
use std::process::{Command, Output};

use sealantd::unclaimed::{self, Placeholder};

fn recover(base: &Path, disk: &Path) -> Output {
    Command::new(env!("CARGO_BIN_EXE_sealantd"))
        .args(["boot", "--recovery"])
        .env_clear()
        .env("SEALANT_WORKSPACE_SOURCE", "capture")
        .env("SEALANT_CAPTURE_ENDPOINT", "http://127.0.0.1:9/unused")
        .env("SEALANT_WORKSPACE_ROOT", base.join("workspace"))
        .env("SEALANT_WORKING_DIRECTORY", disk)
        .env("SEALANT_CONTROL_SOCKET", base.join("run/control.sock"))
        .env("SEALANT_SESSION_JOURNAL_DIR", base.join("journals"))
        .env("SEALANT_OS_FAMILY", "fedora")
        .env(
            "SEALANT_HARNESS_LAUNCH_COMMAND",
            "echo harness > harness-ran.txt",
        )
        .env("PATH", std::env::var("PATH").unwrap_or_default())
        .output()
        .expect("sealantd boot --recovery")
}

#[test]
fn a_standby_no_session_claimed_exits_76_and_a_claimed_one_75() {
    let tmp = tempfile::tempdir().unwrap();
    let base = tmp.path();
    // As a standby's boot left it: the base materialized, its own setup's files, captures of
    // them staged, and the marker.
    let disk = base.join("workspace/repo");
    drop(sealantd::boot::lock::DiskLock::acquire(&disk).unwrap());
    let staging = disk.join(".sealantd/capture");
    std::fs::create_dir_all(staging.join("queue")).unwrap();
    std::fs::write(staging.join("queue/1.json"), b"{}").unwrap();
    std::fs::create_dir_all(disk.join(".git")).unwrap();
    std::fs::write(disk.join("lib.rs"), "pub fn f() {}\n").unwrap();
    std::fs::create_dir_all(disk.join("warm")).unwrap();
    std::fs::write(disk.join("warm/cache.bin"), [7u8; 1024]).unwrap();
    unclaimed::record(
        &staging,
        &Placeholder {
            worktree_id: "standby-1".to_owned(),
            epoch: 7,
            launch: Some("standby:1".to_owned()),
        },
    )
    .unwrap();

    let out = recover(base, &disk);
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert_eq!(out.status.code(), Some(76), "{stderr}");
    assert!(
        stderr.contains("sealantd boot: nothing to save: a standby no session claimed"),
        "{stderr}"
    );
    assert!(stderr.contains("standby-1"), "{stderr}");
    assert_eq!(
        std::fs::read(disk.join("lib.rs")).unwrap(),
        b"pub fn f() {}\n"
    );
    assert!(staging.join("queue/1.json").exists(), "untouched");
    assert!(!disk.join("harness-ran.txt").exists());

    // A writer was admitted since: the marker is gone, and the recovery goes on (75 here).
    std::fs::remove_file(staging.join(unclaimed::FILE)).unwrap();
    let out = recover(base, &disk);
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert_eq!(out.status.code(), Some(75), "{stderr}");
    assert!(!stderr.contains("nothing to save"), "{stderr}");
    assert!(!disk.join("harness-ran.txt").exists());
}
