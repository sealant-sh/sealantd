//! The final capture stops the workspace daemon's containers through the Engine API
//! (`POST /containers/{id}/stop`), and a container's restart policy does not bring it back: a
//! stop asked for is not an exit the policy answers. On a MicroVM the agent names `dockerd` in
//! its exempt list (itself only, not its descendants), so the sweep leaves the daemon running
//! and this stop is what ends a container that could write the worktree (review 2026-09-28,
//! fourth pass, #4).
//!
//! It needs a Docker daemon it may stop every container of — never a host's own: set
//! `SEALANTD_TEST_WORKSPACE_DOCKER_HOST` to a disposable one (a `docker:dind` container's
//! `tcp://127.0.0.1:<port>`) with `busybox` loaded, and the `docker` CLI on `PATH`. Without it
//! the test says so and passes.

use std::process::{Command, Output};
use std::time::Duration;

use sealantd::docker::{DockerEndpoint, stop_all};

fn docker(host: &str, args: &[&str]) -> Output {
    let out = Command::new("docker")
        .arg("-H")
        .arg(host)
        .args(args)
        .output()
        .expect("docker");
    assert!(
        out.status.success(),
        "docker {args:?}: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    out
}

fn inspect(host: &str, name: &str, format: &str) -> String {
    String::from_utf8(docker(host, &["inspect", "-f", format, name]).stdout)
        .unwrap()
        .trim()
        .to_owned()
}

#[tokio::test]
async fn a_final_stop_is_not_undone_by_a_restart_policy() {
    let Ok(host) = std::env::var("SEALANTD_TEST_WORKSPACE_DOCKER_HOST") else {
        eprintln!("skipped: SEALANTD_TEST_WORKSPACE_DOCKER_HOST names no disposable daemon");
        return;
    };
    let always = format!("sealantd-restart-always-{}", std::process::id());
    let control = format!("sealantd-restart-control-{}", std::process::id());
    docker(
        &host,
        &[
            "run",
            "-d",
            "--name",
            &always,
            "--restart=always",
            "busybox",
            "sh",
            "-c",
            "trap 'exit 0' TERM; while true; do sleep 1; done",
        ],
    );
    assert_eq!(inspect(&host, &always, "{{.State.Running}}"), "true");

    let stopped = stop_all(&DockerEndpoint::parse(&host), Duration::from_secs(2))
        .await
        .expect("the daemon answers");
    assert!(stopped.containers >= 1, "{stopped:?}");
    assert_eq!(stopped.running, 0, "{stopped:?}");

    // The policy is live in this daemon: a container that exits on its own is restarted.
    docker(
        &host,
        &[
            "run",
            "-d",
            "--name",
            &control,
            "--restart=always",
            "busybox",
            "sh",
            "-c",
            "sleep 1; exit 1",
        ],
    );
    tokio::time::sleep(Duration::from_secs(6)).await;
    let restarts: u64 = inspect(&host, &control, "{{.RestartCount}}")
        .parse()
        .unwrap();
    assert!(
        restarts >= 1,
        "the control container was restarted by its policy"
    );

    // The stopped one was not.
    assert_eq!(
        inspect(&host, &always, "{{.HostConfig.RestartPolicy.Name}}"),
        "always"
    );
    assert_eq!(inspect(&host, &always, "{{.State.Running}}"), "false");
    assert_eq!(inspect(&host, &always, "{{.RestartCount}}"), "0");
    docker(&host, &["rm", "-f", &always, &control]);
}
