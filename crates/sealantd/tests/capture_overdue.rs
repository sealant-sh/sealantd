//! A snap that waits on a git past its bound says so in `capture.status`, and a git past its
//! limit is killed: the snap fails, is counted, and the next one captures.
//!
//! Docker end to end, round 8 (F1): a snap waited on `git cat-file --batch-check` for 17
//! minutes (a pipe deadlock) and every answer meanwhile read `status: running`, nothing pending,
//! no failed snap: nothing was failing, something was not finishing, and nothing said so. Here
//! the `git add` of a small snap hangs (a `git` on `PATH` that sleeps instead, while a marker
//! file exists), with bounds of a fraction of a second.
//!
//! One test in its own binary on purpose: it changes `PATH` and the capture's bounds, which are
//! process-wide.

#[allow(dead_code, reason = "this binary takes only the boot")]
mod support;

use std::path::Path;
use std::time::{Duration, Instant};

use sealant_capture::bounds::{self, Bounds};
use sealant_protocol::{CaptureClass, CaptureKind, CaptureStatusReport};
use sealantd::capture::CaptureRuntime;
use support::boot;

/// A `git` that execs `sleep` for `git add` while `mark` exists, and the real git otherwise.
fn stalling_git(dir: &Path, mark: &Path) {
    let real = String::from_utf8(
        std::process::Command::new("sh")
            .args(["-c", "command -v git"])
            .output()
            .unwrap()
            .stdout,
    )
    .unwrap()
    .trim()
    .to_owned();
    assert!(real.starts_with('/'), "git on PATH: {real:?}");
    let script = format!(
        // The lock is what a git killed while it wrote the index leaves behind.
        "#!/bin/sh\nif [ \"$1\" = add ] && [ -e '{}' ]; then\n  [ -n \"$GIT_INDEX_FILE\" ] && : > \"$GIT_INDEX_FILE.lock\"\n  exec sleep 30\nfi\nexec '{real}' \"$@\"\n",
        mark.display()
    );
    let git = dir.join("git");
    std::fs::write(&git, script).unwrap();
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(&git, std::fs::Permissions::from_mode(0o755)).unwrap();
}

fn small(status: &CaptureStatusReport) -> &sealant_protocol::CaptureClassSnaps {
    status
        .snaps
        .iter()
        .find(|s| s.class == CaptureClass::Small)
        .expect("the small class is reported")
}

#[test]
fn a_snap_waiting_on_a_git_past_its_bound_is_reported_and_the_git_is_killed_at_its_limit() {
    let tmp = tempfile::tempdir().unwrap();
    let bin = tmp.path().join("bin");
    std::fs::create_dir_all(&bin).unwrap();
    let mark = tmp.path().join("stall");
    stalling_git(&bin, &mark);
    let path = format!(
        "{}:{}",
        bin.display(),
        std::env::var("PATH").unwrap_or_default()
    );
    // SAFETY: the first thing this binary's only test does, before it starts a thread or
    // runs anything that reads the environment.
    unsafe { std::env::set_var("PATH", path) };
    bounds::set(Bounds {
        git_overdue: Duration::from_millis(300),
        git_limit: Duration::from_secs(3),
        snap_overdue: Duration::from_secs(600),
    });

    let (boot, _registrar) = boot(tmp.path(), |sink| sink);
    let capture = CaptureRuntime::new(boot);
    assert!(capture.status().overdue.is_none(), "nothing runs yet");

    std::fs::write(&mark, b"").unwrap();
    std::fs::write(tmp.path().join("ws/src/lib.rs"), "pub fn f() { g() }\n").unwrap();
    let started = Instant::now();
    let snapping = {
        let capture = capture.clone();
        std::thread::spawn(move || capture.snap(CaptureKind::Auto))
    };
    let overdue = loop {
        if let Some(overdue) = capture.status().overdue {
            break overdue;
        }
        assert!(
            started.elapsed() < Duration::from_secs(3),
            "no overdue step reported while the snap waits on git"
        );
        std::thread::sleep(Duration::from_millis(50));
    };
    assert_eq!(overdue.step, "small snap › git add -A", "{overdue:?}");
    assert_eq!(overdue.bound_ms, 300);
    // Overdue once it has run longer than its bound; `running_ms` is whole milliseconds,
    // truncated, so a step 300.4 ms in reads 300.
    assert!(overdue.running_ms >= overdue.bound_ms, "{overdue:?}");
    assert!(overdue.started_unix_ms > 0);

    let snapped = snapping.join().unwrap();
    let error = snapped.expect_err("a snap whose git was killed fails");
    assert!(error.message.contains("killed"), "{error:?}");
    assert!(
        started.elapsed() < Duration::from_secs(15),
        "killed at its limit"
    );
    let status = capture.status();
    assert!(status.overdue.is_none(), "{:?}", status.overdue);
    let failed = small(&status);
    assert!(failed.snaps_failed >= 1, "{failed:?}");
    assert!(
        failed
            .last_snap_error
            .as_deref()
            .is_some_and(|e| e.contains("git add") && e.contains("killed")),
        "{failed:?}"
    );

    // The killed git left nothing behind that the next snap trips over (its scratch index's
    // lock included): it captures.
    std::fs::remove_file(&mark).unwrap();
    let staged = capture
        .snap(CaptureKind::Auto)
        .expect("the next snap captures");
    assert!(!staged.unchanged);
    let status = capture.status();
    assert!(small(&status).last_snap_error.is_none(), "{status:?}");
    assert!(status.overdue.is_none());
}
