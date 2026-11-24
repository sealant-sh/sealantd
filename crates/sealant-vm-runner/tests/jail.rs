//! The runner end to end as a container would run it: root in a fresh network namespace, with a
//! stand-in for Cloud Hypervisor. The stand-in records the credentials, arguments and descriptors
//! it was started with, then waits while the test plays the guest on the boot channel.
//!
//! What these prove that the unit tests cannot: the privilege drop really empties all five
//! capability sets and leaves UID/GID 65532 with only the KVM group in the process that becomes
//! the VMM; `tap0` is up at `10.200.0.1/30`; the nftables table is installed in the runner's
//! netns; only the TAP descriptor crosses `exec`; and exit 76 needs both a synced guest frame and a
//! clean VMM exit.
//!
//! Root's work (a network namespace, `tap0`, nftables, `setresuid`): these run only with
//! `SEALANTD_REQUIRE_ROOT_TESTS=1`, as root (`scripts/ci-root-tests.sh`), and need `unshare`,
//! `nsenter`, `ip` and `nft`.

#![allow(
    clippy::disallowed_methods,
    reason = "no orphan reaper runs in this test binary; the runner and its tools are ordinary children"
)]

use std::io::{BufRead, BufReader, Write};
use std::os::unix::fs::PermissionsExt;
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

const KVM_GID: u32 = 4242;

fn ready() -> bool {
    if std::env::var("SEALANTD_REQUIRE_ROOT_TESTS").as_deref() != Ok("1") {
        eprintln!("SEALANTD_REQUIRE_ROOT_TESTS is not 1: vm-runner jail tests skipped");
        return false;
    }
    assert!(
        nix::unistd::geteuid().is_root(),
        "SEALANTD_REQUIRE_ROOT_TESTS=1 but not running as root"
    );
    true
}

fn nft_bin() -> String {
    ["/usr/sbin/nft", "/sbin/nft", "/usr/bin/nft"]
        .into_iter()
        .find(|p| Path::new(p).exists())
        .unwrap_or("nft")
        .to_owned()
}

/// A directory tree laid out like the runner container's mounts, readable by UID 65532.
struct Layout {
    _tmp: tempfile::TempDir,
    root: PathBuf,
}

impl Layout {
    fn new(vmm_tail: &str) -> Self {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path().to_owned();
        std::fs::set_permissions(&root, std::fs::Permissions::from_mode(0o755)).unwrap();
        for dir in ["images", "data", "run-sealant", "run-vm", "out"] {
            std::fs::create_dir(root.join(dir)).unwrap();
        }
        // The runner's writable dirs belong to 65532, as the container's tmpfs and volume do.
        for dir in ["run-sealant", "run-vm", "out"] {
            nix::unistd::chown(
                &root.join(dir),
                Some(nix::unistd::Uid::from_raw(65532)),
                Some(nix::unistd::Gid::from_raw(65532)),
            )
            .unwrap();
        }
        std::fs::write(
            root.join("images/sha256-test.config.json"),
            r#"{"Env":["PATH=/usr/bin"],"WorkingDir":"/workspace"}"#,
        )
        .unwrap();
        std::fs::write(
            root.join("run-sealant/boot-env.json"),
            r#"{"bootEnv":{"MEND_X":"1"},"secretEnv":{"TOKEN":"t"}}"#,
        )
        .unwrap();
        for file in [
            "images/sha256-test.config.json",
            "run-sealant/boot-env.json",
        ] {
            std::fs::set_permissions(root.join(file), std::fs::Permissions::from_mode(0o644))
                .unwrap();
        }
        // The stand-in VMM: records what it was given, then runs `vmm_tail` once the test
        // creates `out/go`.
        let out = root.join("out");
        let script = format!(
            "#!/bin/sh\n\
             cat /proc/self/status > {out}/status\n\
             printf '%s\\n' \"$@\" > {out}/args\n\
             for fd in /proc/self/fd/*; do echo \"${{fd##*/}} $(readlink \"$fd\")\"; done > {out}/fds\n\
             touch {out}/started\n\
             while [ ! -e {out}/go ]; do sleep 0.05; done\n\
             {vmm_tail}\n",
            out = out.display()
        );
        let vmm = root.join("cloud-hypervisor");
        std::fs::write(&vmm, script).unwrap();
        std::fs::set_permissions(&vmm, std::fs::Permissions::from_mode(0o755)).unwrap();
        Self { _tmp: tmp, root }
    }

    fn path(&self, rel: &str) -> PathBuf {
        self.root.join(rel)
    }

    /// Starts the runner in a new network namespace.
    fn start(&self) -> Child {
        let p = |rel: &str| self.path(rel).display().to_string();
        Command::new("unshare")
            .arg("--net")
            .arg(env!("CARGO_BIN_EXE_sealant-vm-runner"))
            .args(["--proxy-ip", "192.0.2.10", "--image-digest", "sha256-test"])
            .args(["--kvm-gid", &KVM_GID.to_string()])
            .args(["--mac", "02:00:00:00:00:2a"])
            .args(["--images-dir", &p("images"), "--data-dir", &p("data")])
            .args([
                "--sealant-run-dir",
                &p("run-sealant"),
                "--vm-run-dir",
                &p("run-vm"),
            ])
            .args(["--kernel", &p("images/vmlinux"), "--nft", &nft_bin()])
            .args(["--cloud-hypervisor", &p("cloud-hypervisor")])
            .args(["--shutdown-grace-secs", "2"])
            .stdin(Stdio::null())
            .spawn()
            .unwrap()
    }

    fn wait_for(&self, rel: &str, runner: &mut Child) {
        let deadline = Instant::now() + Duration::from_secs(30);
        while !self.path(rel).exists() {
            if let Some(status) = runner.try_wait().unwrap() {
                panic!("the runner exited ({status}) before {rel} appeared");
            }
            assert!(Instant::now() < deadline, "{rel} never appeared");
            std::thread::sleep(Duration::from_millis(20));
        }
    }

    fn read(&self, rel: &str) -> String {
        std::fs::read_to_string(self.path(rel)).unwrap()
    }
}

fn in_netns(pid: u32, cmd: &[&str]) -> String {
    let out = Command::new("nsenter")
        .args(["-t", &pid.to_string(), "-n"])
        .args(cmd)
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "{cmd:?}: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    String::from_utf8_lossy(&out.stdout).into_owned()
}

/// Plays the guest on `vsock:1026`: reads the boot config line, sends `frame`.
fn guest_exit(layout: &Layout, frame: &str) -> serde_json::Value {
    let mut stream = UnixStream::connect(layout.path("run-vm/vsock.sock_1026")).unwrap();
    stream
        .set_read_timeout(Some(Duration::from_secs(10)))
        .unwrap();
    let mut line = String::new();
    BufReader::new(&stream).read_line(&mut line).unwrap();
    stream.write_all(frame.as_bytes()).unwrap();
    stream.shutdown(std::net::Shutdown::Write).unwrap();
    // Wait for the runner to close its side: the frame has been read.
    let mut rest = String::new();
    let _ = BufReader::new(&stream).read_line(&mut rest);
    serde_json::from_str(&line).unwrap()
}

fn wait_exit(runner: &mut Child) -> i32 {
    let deadline = Instant::now() + Duration::from_secs(30);
    loop {
        if let Some(status) = runner.try_wait().unwrap() {
            return status.code().unwrap_or(-1);
        }
        assert!(Instant::now() < deadline, "the runner did not exit");
        std::thread::sleep(Duration::from_millis(20));
    }
}

#[test]
fn the_vmm_runs_jailed_behind_tap0_and_nftables_and_a_synced_76_exits_76() {
    if !ready() {
        return;
    }
    let layout = Layout::new("exit 0");
    let mut runner = layout.start();
    layout.wait_for("out/started", &mut runner);

    // The process that became the VMM holds the jail.
    let status = layout.read("out/status");
    let field = |name: &str| {
        status
            .lines()
            .find_map(|l| l.strip_prefix(&format!("{name}:")))
            .unwrap_or_else(|| panic!("no {name} in\n{status}"))
            .trim()
            .to_owned()
    };
    assert_eq!(
        field("Uid").split_whitespace().collect::<Vec<_>>(),
        ["65532"; 4]
    );
    assert_eq!(
        field("Gid").split_whitespace().collect::<Vec<_>>(),
        ["65532"; 4]
    );
    assert_eq!(field("Groups"), KVM_GID.to_string());
    assert_eq!(field("NoNewPrivs"), "1");
    for set in ["CapInh", "CapPrm", "CapEff", "CapBnd", "CapAmb"] {
        assert_eq!(field(set), "0000000000000000", "{set}");
    }

    // Its command line carries the TAP descriptor, and that descriptor (and only a TUN one) is
    // open in it.
    let args = layout.read("out/args");
    let net = args
        .lines()
        .skip_while(|l| *l != "--net")
        .nth(1)
        .unwrap()
        .to_owned();
    assert_eq!(net.split(',').nth(1), Some("mac=02:00:00:00:00:2a"));
    let tap_fd = net
        .strip_prefix("fd=")
        .and_then(|r| r.split(',').next())
        .unwrap()
        .to_owned();
    let fds = layout.read("out/fds");
    assert!(
        fds.lines().any(|l| l == format!("{tap_fd} /dev/net/tun")),
        "fd {tap_fd} is not the TAP queue:\n{fds}"
    );
    assert_eq!(
        fds.lines().filter(|l| l.ends_with("/dev/net/tun")).count(),
        1,
        "{fds}"
    );
    assert!(args.lines().any(|l| l == "--seccomp") && args.lines().any(|l| l == "--landlock"));

    // tap0 and the table live in the runner's own netns.
    let pid = runner.id();
    let addr = in_netns(pid, &["ip", "-4", "-o", "addr", "show", "dev", "tap0"]);
    assert!(addr.contains("inet 10.200.0.1/30"), "{addr}");
    let table = in_netns(pid, &[&nft_bin(), "list", "table", "inet", "sealant_vm"]);
    assert!(table.contains("policy drop"), "{table}");
    assert!(table.contains("redirect to :15444"), "{table}");
    // The forwarders listen on the tap address.
    let listening = in_netns(pid, &["ss", "-ltnu"]);
    for port in ["10.200.0.1:15053", "10.200.0.1:15100", "10.200.0.1:15444"] {
        assert!(
            listening.contains(port),
            "{port} not listening:\n{listening}"
        );
    }

    // The guest gets its config and reports a synced 76; the VMM then exits cleanly.
    let config = guest_exit(
        &layout,
        "{\"version\":1,\"exit_code\":76,\"synced\":true,\"reason\":\"never claimed\"}\n",
    );
    assert_eq!(config["version"], 1);
    assert_eq!(config["mode"], "normal");
    assert_eq!(config["config"]["WorkingDir"], "/workspace");
    assert_eq!(config["networkConfig"]["mac"], "02:00:00:00:00:2a");
    std::fs::write(layout.path("out/go"), "").unwrap();
    assert_eq!(wait_exit(&mut runner), 76);
}

#[test]
fn a_vmm_killed_after_a_synced_76_is_not_76() {
    if !ready() {
        return;
    }
    let layout = Layout::new("kill -9 $$");
    let mut runner = layout.start();
    layout.wait_for("out/started", &mut runner);
    guest_exit(
        &layout,
        "{\"version\":1,\"exit_code\":76,\"synced\":true}\n",
    );
    std::fs::write(layout.path("out/go"), "").unwrap();
    assert_eq!(wait_exit(&mut runner), 137);
}

#[test]
fn an_unsynced_76_is_not_76() {
    if !ready() {
        return;
    }
    let layout = Layout::new("exit 0");
    let mut runner = layout.start();
    layout.wait_for("out/started", &mut runner);
    guest_exit(
        &layout,
        "{\"version\":1,\"exit_code\":76,\"synced\":false}\n",
    );
    std::fs::write(layout.path("out/go"), "").unwrap();
    let code = wait_exit(&mut runner);
    assert_ne!(code, 76);
    assert_eq!(code, 4);
}

#[test]
fn sigterm_presses_the_power_button_then_kills_the_vmm_after_the_grace() {
    if !ready() {
        return;
    }
    // A VMM with no API socket that never exits by itself: the press fails, the grace (2 s)
    // runs out, and the VMM is killed.
    let layout = Layout::new("sleep 600");
    let mut runner = layout.start();
    layout.wait_for("out/started", &mut runner);
    std::fs::write(layout.path("out/go"), "").unwrap();
    nix::sys::signal::kill(
        nix::unistd::Pid::from_raw(runner.id() as i32),
        nix::sys::signal::Signal::SIGTERM,
    )
    .unwrap();
    let started = Instant::now();
    assert_eq!(wait_exit(&mut runner), 137);
    assert!(started.elapsed() >= Duration::from_secs(2));
}
