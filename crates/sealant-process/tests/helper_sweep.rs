//! The check before a helper spawn (`sealant_process::spawn::sweep_before_helper_spawn`), in a
//! binary of its own: no other test sees the descriptor planted here.

use std::os::fd::AsRawFd;
use std::process::{Command, Stdio};

use sealant_process::CommandGateExt;

/// Once sealantd's start marking has run, a descriptor opened without close-on-exec stops the
/// next helper spawn in a test or debug build, which names it. Closed, the spawn runs.
#[test]
fn a_descriptor_without_close_on_exec_stops_a_helper_spawn_and_is_named() {
    sealant_process::spawn::mark_at_start().expect("the start marking");
    let null = std::fs::File::open("/dev/null").expect("open /dev/null");
    let planted = nix::unistd::dup(&null).expect("dup");
    let n = planted.as_raw_fd();

    let spawned = std::panic::catch_unwind(|| {
        Command::new("/bin/true")
            .stdin(Stdio::null())
            .status_helper()
    });
    let payload = spawned.expect_err("the helper spawn panics");
    let message = payload
        .downcast_ref::<String>()
        .cloned()
        .or_else(|| payload.downcast_ref::<&str>().map(|s| (*s).to_owned()))
        .expect("a panic message");
    assert!(message.contains(&format!("fd {n} ")), "{message}");
    assert!(message.contains("/dev/null"), "{message}");

    drop(planted);
    let status = Command::new("/bin/true")
        .stdin(Stdio::null())
        .status_helper()
        .expect("the helper spawn runs once the descriptor is closed");
    assert!(status.success(), "{status:?}");
}
