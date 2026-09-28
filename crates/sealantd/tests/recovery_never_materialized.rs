//! A recovery boot on a disk the daemon before it never materialized — it died at `plan.get`,
//! before anything was written there — has nothing to save, and says so: exit 76
//! ([`sealantd::runtime::EXIT_NOTHING_TO_SAVE`]), `nothing to save: never materialized` on
//! stderr, the disk untouched. Before, every recovery refused such a disk as "not this
//! executor's continuation" and exited 75, and the platform kept it forever (sixth end-to-end
//! run). A disk with anything on it still exits 75: the recovery goes on, and here cannot save
//! it (no session token).

use std::path::Path;
use std::process::{Command, Output};

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

/// Every path under `dir`, sorted.
fn listing(dir: &Path) -> Vec<String> {
    let mut all: Vec<String> = walkdir::WalkDir::new(dir)
        .into_iter()
        .flatten()
        .map(|e| e.path().strip_prefix(dir).unwrap().display().to_string())
        .collect();
    all.sort();
    all
}

#[test]
fn a_never_materialized_disk_exits_76_and_anything_else_75() {
    let tmp = tempfile::tempdir().unwrap();
    let base = tmp.path();

    // As the first daemon left it: it took the disk lock, then died at `plan.get`.
    let disk = base.join("workspace/repo");
    drop(sealantd::boot::lock::DiskLock::acquire(&disk).unwrap());
    let out = recover(base, &disk);
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert_eq!(out.status.code(), Some(76), "{stderr}");
    assert!(
        stderr.contains("nothing to save: never materialized"),
        "{stderr}"
    );
    assert_eq!(listing(&disk), ["", ".sealantd", ".sealantd/boot.lock"]);

    // The worktree never created at all.
    let absent = base.join("workspace/absent");
    let out = recover(base, &absent);
    assert_eq!(out.status.code(), Some(76));

    // Anything on the disk — here one file — is not provably nothing: 75, whatever else fails.
    std::fs::write(disk.join("draft.md"), "work").unwrap();
    let out = recover(base, &disk);
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert_eq!(out.status.code(), Some(75), "{stderr}");
    assert!(!stderr.contains("nothing to save"), "{stderr}");
    assert_eq!(std::fs::read(disk.join("draft.md")).unwrap(), b"work");
    assert!(!disk.join("harness-ran.txt").exists());
}
