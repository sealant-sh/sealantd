//! Linux-only: a subreaper must reap adopted orphans so they do not linger as zombies (plan §10.4).
//!
//! Lives in its own test binary so `PR_SET_CHILD_SUBREAPER` and the global reaper do not affect
//! other tests sharing a process.
#![cfg(target_os = "linux")]

use std::time::Duration;

use sealant_process::{platform, spawn};

#[tokio::test]
async fn subreaper_reaps_adopted_orphan() {
    assert!(
        platform::set_child_subreaper(),
        "subreaper should be settable on Linux"
    );
    platform::spawn_orphan_reaper();

    // sh backgrounds a brief sleep, prints its pid, and exits — orphaning the sleep, which
    // reparents to us (the subreaper). The sleep is NOT a Tokio child, so only our reaper can reap
    // the zombie it becomes. sh itself is spawned through the spawn↔reap gate, as every spawn in
    // the daemon is: outside it the reaper can take sh's exit status first, and the wait for it
    // fails with ECHILD ("No child processes"; seen on a loaded CI runner).
    let mut command = tokio::process::Command::new("/bin/sh");
    command
        .args(["-c", "sleep 0.3 & echo $!"])
        .stdout(std::process::Stdio::piped());
    let (child, gate) = spawn::spawn_tokio(&mut command).expect("spawn sh");
    let output = child.wait_with_output().await.expect("wait for sh");
    // sh is reaped: hand its pid back to the reaper.
    drop(gate);
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
