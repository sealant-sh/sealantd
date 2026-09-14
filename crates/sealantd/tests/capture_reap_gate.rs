//! Linux-only regression: the orphan reaper must never steal a `git` child the capture engine
//! spawned.
//!
//! sealantd is PID 1 (child subreaper) in the workspace, and its reaper sweeps on every SIGCHLD
//! and every 2 s. The capture engine snaps with plain blocking `git` children (`rev-list`,
//! `pack-objects`, `index-pack`, `head_tree`, `stored_tips`). Before the spawn gate covered those
//! spawns, a `git` that exited while a sweep was running was reaped as if it were an adopted
//! orphan and the engine's own `wait()` failed with `ECHILD` — "No child process (os error 10)" —
//! which is how `capture.flush` was refused under load (Mend 0.27.3 acceptance, 1 run in 8 on a
//! 2-CPU daemon).
//!
//! The storm here is the same shape, made deterministic: a continuous supply of SIGCHLDs and real
//! adopted orphans while a capture-like burst of `git` children runs on a blocking thread. Every
//! child of the burst must be reaped by the burst, and every orphan must still be reaped by the
//! reaper.
#![cfg(target_os = "linux")]

use std::path::Path;
use std::process::Stdio;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU32, Ordering};
use std::time::Duration;

use sealant_capture::gitpack::{self, GitRepo};
use sealant_process::CommandGateExt;
use sealant_process::platform;

/// Rounds of the capture-like burst: four short-lived `git` children each, with the storm firing
/// a SIGCHLD sweep between them. Pre-fix this failed within the first dozen rounds, every run.
const ROUNDS: u32 = 150;

fn git(root: &Path, args: &[&str]) {
    let out = std::process::Command::new("git")
        .current_dir(root)
        .env("GIT_OPTIONAL_LOCKS", "0")
        .args(args)
        .stdin(Stdio::null())
        .output_gated()
        .expect("git runs");
    assert!(
        out.status.success(),
        "git {args:?}: {}",
        String::from_utf8_lossy(&out.stderr)
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn the_reaper_never_steals_a_capture_git_child() {
    assert!(
        platform::set_child_subreaper(),
        "subreaper should be settable on Linux"
    );
    platform::spawn_orphan_reaper();

    let tmp = tempfile::tempdir().expect("tempdir");
    let root = tmp.path().join("ws");
    std::fs::create_dir_all(root.join("src")).expect("mkdir");
    git(&root, &["init", "-q", "-b", "main"]);
    git(&root, &["config", "user.email", "t@t"]);
    git(&root, &["config", "user.name", "t"]);
    std::fs::write(root.join("src/a.txt"), b"a\n").expect("write");
    git(&root, &["add", "-A"]);
    git(&root, &["commit", "-q", "-m", "one"]);

    // SIGCHLD storm: each `sh` exits at once (one SIGCHLD, so one sweep) and leaves a backgrounded
    // `sleep` behind, which reparents to us as the subreaper and exits shortly after (a second
    // SIGCHLD, and a real adopted orphan for the reaper to collect).
    let stop = Arc::new(AtomicBool::new(false));
    let orphans = Arc::new(AtomicU32::new(0));
    let storm = tokio::spawn({
        let stop = stop.clone();
        let orphans = orphans.clone();
        async move {
            while !stop.load(Ordering::Relaxed) {
                let mut command = tokio::process::Command::new("/bin/sh");
                command
                    .args(["-c", "sleep 0.02 & exit 0"])
                    .stdin(Stdio::null())
                    .stdout(Stdio::null())
                    .stderr(Stdio::null());
                let Ok((mut child, spawned)) = sealant_process::spawn::spawn_tokio(&mut command)
                else {
                    break;
                };
                let status = child.wait().await;
                drop(spawned);
                assert!(
                    status.is_ok(),
                    "the storm's own child was reaped by the reaper: {status:?}"
                );
                orphans.fetch_add(1, Ordering::Relaxed);
            }
        }
    });

    // The capture-like burst: short-lived blocking `git` children, exactly as `gitpack` runs them.
    let burst_root = root.clone();
    let burst = tokio::task::spawn_blocking(move || -> Result<(), String> {
        let repo = GitRepo::open(&burst_root).map_err(|e| format!("open: {e}"))?;
        for round in 0..ROUNDS {
            let at = |what: &str, e: gitpack::GitError| format!("round {round} {what}: {e}");
            repo.refs().map_err(|e| at("refs", e))?;
            repo.head_tree().map_err(|e| at("head_tree", e))?;
            gitpack::stored_tips(&repo).map_err(|e| at("stored_tips", e))?;
            repo.run(&["rev-parse", "HEAD"])
                .map_err(|e| at("rev-parse", e))?;
        }
        Ok(())
    });

    let result = tokio::time::timeout(Duration::from_secs(120), burst)
        .await
        .expect("the git burst finishes")
        .expect("the git burst thread does not panic");
    stop.store(true, Ordering::Relaxed);
    let _ = storm.await;

    if let Err(error) = result {
        panic!(
            "a capture `git` child was reaped out from under the engine ({} storm rounds): {error}",
            orphans.load(Ordering::Relaxed)
        );
    }
    assert!(
        orphans.load(Ordering::Relaxed) > 0,
        "the storm must have produced SIGCHLDs and adopted orphans"
    );

    // The gate must not have switched adoption reaping off: an orphan is still collected.
    let mut command = tokio::process::Command::new("/bin/sh");
    command
        .args(["-c", "sleep 0.2 & echo $!"])
        .stdin(Stdio::null())
        .stdout(Stdio::piped());
    let (child, spawned) = sealant_process::spawn::spawn_tokio(&mut command).expect("spawn sh");
    let out = child.wait_with_output().await.expect("sh output");
    drop(spawned);
    let orphan_pid: i32 = String::from_utf8_lossy(&out.stdout)
        .trim()
        .parse()
        .expect("orphan pid");
    let mut reaped = false;
    for _ in 0..250 {
        if std::fs::read_to_string(format!("/proc/{orphan_pid}/stat")).is_err() {
            reaped = true;
            break;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    assert!(
        reaped,
        "adopted orphan {orphan_pid} must still be reaped (no lingering zombie)"
    );
}
