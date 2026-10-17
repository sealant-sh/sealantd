//! Linux-only. Diagnosis for sealantd#178: a child spawned with a bare `std::process::Command`
//! while the orphan reaper runs in the same process is indistinguishable from an adopted orphan
//! (it is not in the spawn gate), so the reaper reaps it and the spawner's own `wait()` fails
//! with `ECHILD`. The same child spawned through the gate keeps its exit status. Own test
//! binary: it starts the process-global reaper (the isolation rule of `orphan_reaping.rs`).
#![cfg(target_os = "linux")]

use std::path::Path;
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

use sealant_process::platform;
use sealant_process::spawn::CommandGateExt;

const ECHILD: i32 = 10;
const DEADLINE: Duration = Duration::from_secs(10);
const POLL: Duration = Duration::from_millis(10);

/// A child outside the gate: what this test exists to show losing its exit status.
#[allow(
    clippy::disallowed_methods,
    reason = "the ungated child is the subject of this test (sealantd#178)"
)]
fn spawn_ungated(command: &mut Command) -> Child {
    command.spawn().expect("spawn an ungated child")
}

/// Until `pid` has been reaped: its `/proc` entry goes when it is reaped, not when it exits.
async fn until_reaped(pid: u32) {
    let entry = format!("/proc/{pid}");
    let deadline = Instant::now() + DEADLINE;
    while Path::new(&entry).exists() {
        assert!(Instant::now() < deadline, "the reaper never reaped {entry}");
        tokio::time::sleep(POLL).await;
    }
}

/// Until `pid` is a zombie (exited, reaped by nobody yet): `/proc/<pid>/stat` state `Z`.
async fn until_zombie(pid: i32) {
    let deadline = Instant::now() + DEADLINE;
    loop {
        let stat = std::fs::read_to_string(format!("/proc/{pid}/stat"))
            .unwrap_or_else(|e| panic!("{pid} was reaped before its spawner waited: {e}"));
        // `pid (comm) state ...`; comm may hold spaces and parentheses, so read after the last `)`.
        let state = stat[stat.rfind(')').expect("a stat line") + 1..]
            .trim_start()
            .chars()
            .next();
        if state == Some('Z') {
            return;
        }
        assert!(Instant::now() < deadline, "{pid} never exited: {stat}");
        tokio::time::sleep(POLL).await;
    }
}

#[tokio::test]
async fn an_ungated_child_loses_its_exit_status_to_the_reaper_and_a_gated_one_does_not() {
    platform::spawn_orphan_reaper();

    // As `recovery_reboot.rs:220` spawned the second `sealantd boot --recovery`: no gate. Wait for
    // the reaping instead of guessing a delay, so a loaded machine cannot let our own wait win the
    // race this test exists to show (the window the test on box-150 lost).
    let mut ungated = spawn_ungated(Command::new("true").stdout(Stdio::null()));
    until_reaped(ungated.id()).await;
    let stolen = ungated.wait().expect_err("the reaper took the exit status");
    assert_eq!(stolen.raw_os_error(), Some(ECHILD), "{stolen}");

    // The same child through the gate. A sweep has to run while it is an unreaped zombie, or the
    // wait below collects it whatever the gate says. A sweep peeks at children in the order they
    // were spawned and stops at the first one the gate holds, so the probe that proves a sweep ran
    // is spawned first, blocked on its stdin, and released only once the gated child is a zombie:
    // the sweep that reaps the probe peeks at the gated zombie next.
    let mut probe = spawn_ungated(
        Command::new("cat")
            .stdin(Stdio::piped())
            .stdout(Stdio::null()),
    );
    let gated = Command::new("true")
        .stdout(Stdio::null())
        .spawn_gated()
        .expect("spawn gated true");
    until_zombie(gated.pid()).await;
    drop(probe.stdin.take());
    until_reaped(probe.id()).await;
    let stolen = probe
        .wait()
        .expect_err("the reaper took the probe's exit status");
    assert_eq!(stolen.raw_os_error(), Some(ECHILD), "{stolen}");

    let status = gated.wait().expect("our own wait reaps it");
    assert!(status.success(), "{status}");
}
