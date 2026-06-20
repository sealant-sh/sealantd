//! Linux-only: a subreaper must reap adopted orphans so they do not linger as zombies (plan §10.4).
//!
//! Lives in its own test binary so `PR_SET_CHILD_SUBREAPER` and the global reaper do not affect
//! other tests sharing a process.
#![cfg(target_os = "linux")]

use std::sync::Arc;
use std::time::Duration;

use sealant_process::ProcessRegistry;
use sealant_process::platform;

#[tokio::test]
async fn subreaper_reaps_adopted_orphan() {
    assert!(
        platform::set_child_subreaper(),
        "subreaper should be settable on Linux"
    );
    let registry = Arc::new(ProcessRegistry::new());
    platform::spawn_orphan_reaper(registry.clone());

    // sh backgrounds a brief sleep, prints its pid, and exits — orphaning the sleep, which
    // reparents to us (the subreaper). The sleep is NOT a Tokio child, so only our reaper can reap
    // the zombie it becomes.
    let output = tokio::process::Command::new("/bin/sh")
        .args(["-c", "sleep 0.3 & echo $!"])
        .output()
        .await
        .expect("spawn sh");
    let orphan_pid: i32 = String::from_utf8_lossy(&output.stdout)
        .trim()
        .parse()
        .expect("orphan pid");

    // Once reaped, /proc/<pid> disappears. A broken reaper would leave a 'Z' (zombie) entry that
    // persists for the lifetime of this process.
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
        "adopted orphan {orphan_pid} must be reaped by the subreaper (no lingering zombie)"
    );
}
