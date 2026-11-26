//! A container boot is one trace under the launcher's span (`SEALANT_TRACEPARENT`): a
//! `sealantd.boot` span with a child per stage, and an error during the boot linked to it
//! (SLNT-1351). `SEALANT_SENTRY_DSN` points the real `sealantd boot` at a loopback stand-in for
//! Sentry, which keeps every byte it is sent.
//!
//! Root's work (boot makes `/run/sealant`): these run only with `SEALANTD_REQUIRE_ROOT_TESTS=1`,
//! as root (`scripts/ci-root-tests.sh`).

#[allow(dead_code)]
#[path = "../../sealant-observability/tests/support/collector.rs"]
mod collector;

use std::path::Path;
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

use collector::{Collector, Received, assert_sentry_shows, contains, exported_spans};
use sealant_process::spawn::CommandGateExt as _;

const TRACE_ID: &str = "5b8aa5a2d2c872e8321cf37308d69df2";
const TRACEPARENT: &str = "00-5b8aa5a2d2c872e8321cf37308d69df2-051581bf3cb55c13-01";

/// Whether these run: as root with `SEALANTD_REQUIRE_ROOT_TESTS=1`.
fn ready() -> bool {
    if std::env::var("SEALANTD_REQUIRE_ROOT_TESTS").as_deref() != Ok("1") {
        eprintln!("SEALANTD_REQUIRE_ROOT_TESTS is not 1: boot telemetry tests skipped");
        return false;
    }
    assert!(
        nix::unistd::geteuid().is_root(),
        "SEALANTD_REQUIRE_ROOT_TESTS=1 but not running as root"
    );
    true
}

fn hex(bytes: &str) -> Vec<u8> {
    (0..bytes.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&bytes[i..i + 2], 16).expect("hex"))
        .collect()
}

/// Boot a workspace whose working directory is already a repository (the clone is skipped),
/// with `setup` as its setup steps, and wait for it to exit: its status, and its log.
fn boot(tmp: &Path, collector: &Collector, setup: &str) -> (std::process::ExitStatus, String) {
    let repo = tmp.join("ws/repo");
    std::fs::create_dir_all(&repo).expect("working directory");
    let git = Command::new("git")
        .args(["init", "-q"])
        .current_dir(&repo)
        .output_gated()
        .expect("git init");
    assert!(git.status.success());
    let log = tmp.join("boot.log");
    let mut boot = Command::new(env!("CARGO_BIN_EXE_sealantd"));
    boot
        // `off`, as a launcher may set it: export must not depend on the log level. The log
        // file gets the boot's own errors, printed when it fails.
        .args(["boot", "--log-level", "off"])
        .env_clear()
        .env("PATH", std::env::var("PATH").unwrap_or_default())
        .env("HOME", tmp)
        .env("SEALANT_WORKSPACE_REPO_URL", "https://example.com/o/r.git")
        .env("SEALANT_WORKSPACE_REPO_REF", "main")
        .env("SEALANT_OS_FAMILY", "ubuntu")
        .env("SEALANT_LOGIN_SHELL_PATH", "/bin/bash")
        .env("SEALANT_HARNESS_LAUNCH_COMMAND", "true")
        .env("SEALANT_LIFECYCLE_SETUP_JSON", setup)
        .env("SEALANT_WORKSPACE_ROOT", tmp.join("ws"))
        .env("SEALANT_WORKING_DIRECTORY", &repo)
        .env("SEALANT_CONTROL_SOCKET", tmp.join("control.sock"))
        .env("SEALANT_SPOOL_DIR", tmp.join("spool"))
        .env("SEALANT_SESSION_JOURNAL_DIR", tmp.join("journals"))
        .env("SEALANT_SENTRY_DSN", collector.dsn())
        .env("SEALANT_TRACEPARENT", TRACEPARENT)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(std::fs::File::create(&log).expect("log file"));
    let (mut child, _spawned) =
        sealant_process::spawn::spawn_std(&mut boot).expect("spawn sealantd boot");
    let deadline = Instant::now() + Duration::from_secs(60);
    loop {
        if let Some(status) = child.try_wait().expect("wait") {
            return (status, std::fs::read_to_string(&log).unwrap_or_default());
        }
        assert!(Instant::now() < deadline, "the boot did not exit");
        std::thread::sleep(Duration::from_millis(50));
    }
}

/// Everything the collector holds once `until` is in it (or after five seconds).
fn collected(collector: &Collector, until: &[u8]) -> Vec<Received> {
    let deadline = Instant::now() + Duration::from_secs(5);
    loop {
        let received = collector.received();
        let all: Vec<u8> = received.iter().flat_map(|r| r.body.clone()).collect();
        if contains(&all, until) || Instant::now() > deadline {
            return received;
        }
        std::thread::sleep(Duration::from_millis(50));
    }
}

fn otlp(received: &[Received]) -> Vec<u8> {
    received
        .iter()
        .filter(|r| r.path == "/api/10/integration/otlp/v1/traces")
        .flat_map(|r| r.body.clone())
        .collect()
}

#[test]
fn a_boot_is_one_trace_with_a_span_per_stage() {
    if !ready() {
        return;
    }
    let collector = Collector::start();
    let tmp = tempfile::tempdir().expect("tempdir");
    let (status, log) = boot(tmp.path(), &collector, "[]");
    assert!(status.success(), "{status}: {log}");
    let received = collected(&collector, b"sealantd.boot.harness_started");
    let spans = otlp(&received);
    for name in [
        "sealantd.boot",
        "sealantd.boot.clone",
        "sealantd.boot.healthy",
        "sealantd.boot.control_ready",
        "sealantd.boot.harness_started",
        "sealant.boot.stage",
    ] {
        assert!(contains(&spans, name.as_bytes()), "{name} was not exported");
    }
    assert!(
        contains(&spans, &hex(TRACE_ID)),
        "the boot is not in the launcher's trace"
    );
    // Sentry shows the boot and each stage under it as what they are.
    let spans = exported_spans(&received);
    assert_sentry_shows(&spans);
    let root = spans
        .iter()
        .find(|s| s.name == "sealantd.boot")
        .expect("the boot's span");
    assert_eq!(root.attribute("sentry.op"), Some("sealantd.boot"));
    assert!(!root.failed);
    let healthy = spans
        .iter()
        .find(|s| s.name == "sealantd.boot.healthy")
        .expect("the healthy stage");
    assert_eq!(healthy.attribute("sentry.op"), Some("sealantd.boot.stage"));
    assert_eq!(
        healthy.attribute("sentry.description"),
        Some("runtime healthy")
    );
    assert_eq!(healthy.parent_span_id, root.span_id);
}

#[test]
fn an_error_during_the_boot_is_linked_to_its_trace() {
    if !ready() {
        return;
    }
    let collector = Collector::start();
    let tmp = tempfile::tempdir().expect("tempdir");
    let (status, _) = boot(tmp.path(), &collector, r#"[{"run":"exit 3"}]"#);
    assert!(!status.success(), "a failed setup step fails the boot");
    let received = collected(&collector, b"lifecycle step failed");
    let events: Vec<u8> = received
        .iter()
        .filter(|r| r.path == "/api/10/envelope/")
        .flat_map(|r| r.body.clone())
        .collect();
    let events = String::from_utf8_lossy(&events);
    assert!(
        events.contains("lifecycle step failed"),
        "the error did not reach Sentry: {events}"
    );
    assert!(
        events.contains(TRACE_ID),
        "the error is not linked to the boot's trace: {events}"
    );
    let spans = otlp(&received);
    assert!(contains(&spans, b"sealantd.boot"));
    assert!(
        !contains(&spans, b"sealantd.boot.harness_started"),
        "no harness started"
    );
    let spans = exported_spans(&received);
    assert_sentry_shows(&spans);
    assert!(
        spans.iter().any(|s| s.name == "sealantd.boot" && s.failed),
        "the boot's span is not marked failed"
    );
}
