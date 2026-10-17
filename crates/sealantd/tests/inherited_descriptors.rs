//! A descriptor whatever started sealantd left open without close-on-exec is marked
//! close-on-exec as sealantd starts, so nothing sealantd runs inherits it (sealantd#183). Each
//! spawn marks them again (`sealant_process::spawn`); this is the start's own marking.

use std::process::Stdio;
use std::time::{Duration, Instant};

use sealant_process::CommandGateExt;

#[test]
fn a_descriptor_sealantd_starts_with_is_marked_close_on_exec() {
    let exe = env!("CARGO_BIN_EXE_sealantd");
    let dir = tempfile::tempdir().expect("a scratch directory");
    let socket = dir.path().join("control.sock");
    // The shell opens fd 9 itself, after its own exec, and execs sealantd: sealantd starts with
    // an inheritable descriptor its launcher left open.
    let launcher = std::process::Command::new("/bin/sh")
        .args([
            "-c",
            r#"exec 9</dev/null; exec "$0" --socket "$1" --workspace "$2""#,
            exe,
            socket.to_str().expect("a UTF-8 path"),
            dir.path().to_str().expect("a UTF-8 path"),
        ])
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn_gated()
        .expect("start sealantd");
    let pid = launcher.pid();

    // It serves once its start has run.
    let until = Instant::now() + Duration::from_secs(10);
    while !socket.exists() {
        assert!(
            Instant::now() < until,
            "sealantd listens within ten seconds"
        );
        std::thread::sleep(Duration::from_millis(20));
    }
    let target = std::fs::read_link(format!("/proc/{pid}/fd/9")).expect("sealantd holds fd 9");
    let info = std::fs::read_to_string(format!("/proc/{pid}/fdinfo/9")).expect("fd 9's fdinfo");
    let flags = info
        .lines()
        .find_map(|line| line.strip_prefix("flags:"))
        .and_then(|v| u32::from_str_radix(v.trim(), 8).ok())
        .unwrap_or_else(|| panic!("fd 9 has flags: {info}"));

    nix::sys::signal::kill(
        nix::unistd::Pid::from_raw(pid),
        nix::sys::signal::Signal::SIGTERM,
    )
    .expect("stop sealantd");
    let _ = launcher.wait();

    assert_eq!(
        target,
        std::path::Path::new("/dev/null"),
        "fd 9 is the launcher's"
    );
    assert_ne!(
        flags & 0o2_000_000,
        0,
        "sealantd marked the descriptor it started with close-on-exec: {info}"
    );
}
