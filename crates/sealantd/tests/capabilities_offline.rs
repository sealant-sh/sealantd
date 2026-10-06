//! `sealantd capabilities --json` prints, without booting, what a booted daemon reports in
//! `runtime.getCapabilities`: an image build records it, and Mend decides the per-person layout
//! from it before any executor starts (its ADR 0016).

use std::process::Stdio;
use std::time::Duration;

use sealant_control::{read_frame, write_frame};
use sealant_protocol::{
    ClientMessage, Command, CommandResult, ControlRequest, RequestId, ResponseOutcome,
    ServerMessage,
};

const MAX: u32 = 8 * 1024 * 1024;

#[tokio::test]
async fn the_offline_report_is_the_booted_one() {
    let exe = env!("CARGO_BIN_EXE_sealantd");
    let offline = std::process::Command::new(exe)
        .args(["capabilities", "--json"])
        .env_clear()
        .output()
        .expect("run sealantd capabilities");
    assert!(offline.status.success());
    let offline: serde_json::Value =
        serde_json::from_slice(&offline.stdout).expect("one JSON object");

    let mut child = tokio::process::Command::new(exe)
        .args(["--stdio", "--log-level", "off", "--workspace"])
        .arg(std::env::temp_dir())
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .kill_on_drop(true)
        .spawn()
        .expect("spawn sealantd");
    let mut stdin = child.stdin.take().expect("stdin");
    let mut stdout = child.stdout.take().expect("stdout");
    let body = sealant_protocol::encode_client(&ClientMessage::Request(ControlRequest::new(
        RequestId::new("caps"),
        Command::RuntimeGetCapabilities,
    )));
    write_frame(&mut stdin, &body, MAX).await.expect("write");
    let booted = tokio::time::timeout(Duration::from_secs(10), async {
        loop {
            let body = read_frame(&mut stdout, MAX).await.unwrap().unwrap();
            if let ServerMessage::Response(r) = sealant_protocol::decode_server(&body).unwrap()
                && let ResponseOutcome::Ok {
                    result: Some(CommandResult::Capabilities(c)),
                } = r.outcome
            {
                return c;
            }
        }
    })
    .await
    .expect("capabilities answered");

    let supports: Vec<String> = serde_json::from_value(offline["supports"].clone()).unwrap();
    assert_eq!(supports, booted.supports);
    for name in ["exec.user", "dotfiles.user", "restore.owner_map"] {
        assert!(supports.iter().any(|s| s == name), "{name} missing");
    }
    assert_eq!(offline["daemonVersion"], booted.daemon_version);
    assert_eq!(offline["schemaVersion"], booted.schema_version);
    assert_eq!(offline["os"], booted.os);
    assert_eq!(offline["arch"], booted.arch);

    // One name per line without `--json`.
    let lines = std::process::Command::new(exe)
        .arg("capabilities")
        .output()
        .expect("run sealantd capabilities");
    assert_eq!(
        String::from_utf8_lossy(&lines.stdout)
            .lines()
            .collect::<Vec<_>>(),
        booted.supports
    );
}
