//! Linux-only. Diagnosis for sealantd#178: a child spawned with a bare `std::process::Command`
//! while the orphan reaper runs in the same process is indistinguishable from an adopted orphan
//! (it is not in the spawn gate), so the reaper reaps it and the spawner's own `wait()` fails
//! with `ECHILD`. The same child spawned through the gate keeps its exit status. Own test
//! binary: it starts the process-global reaper (the isolation rule of `orphan_reaping.rs`).
#![cfg(target_os = "linux")]

use std::process::{Command, Stdio};
use std::time::Duration;

use sealant_process::platform;
use sealant_process::spawn::CommandGateExt;

const ECHILD: i32 = 10;

#[tokio::test]
async fn an_ungated_child_loses_its_exit_status_to_the_reaper_and_a_gated_one_does_not() {
    platform::spawn_orphan_reaper();

    // As `recovery_reboot.rs:220` spawns the second `sealantd boot --recovery`: no gate.
    let mut ungated = Command::new("true")
        .stdout(Stdio::null())
        .spawn()
        .expect("spawn true");
    // The child exits at once and the reaper reaps it: its /proc entry goes when it is reaped, not
    // when it exits. Wait for that instead of guessing a delay, so a loaded machine cannot let our
    // own wait win the race this test exists to show (the window the test on box-150 lost).
    let proc_entry = format!("/proc/{}", ungated.id());
    let deadline = std::time::Instant::now() + Duration::from_secs(10);
    while std::path::Path::new(&proc_entry).exists() {
        assert!(
            std::time::Instant::now() < deadline,
            "the reaper never reaped {proc_entry}"
        );
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    let stolen = ungated.wait().expect_err("the reaper took the exit status");
    assert_eq!(stolen.raw_os_error(), Some(ECHILD), "{stolen}");

    // The same child through the gate: the reaper leaves it to us.
    let gated = Command::new("true")
        .stdout(Stdio::null())
        .spawn_gated()
        .expect("spawn gated true");
    tokio::time::sleep(Duration::from_millis(500)).await;
    let status = gated.wait().expect("our own wait reaps it");
    assert!(status.success(), "{status}");
}
