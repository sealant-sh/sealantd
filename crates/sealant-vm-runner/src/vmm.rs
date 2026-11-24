//! Cloud Hypervisor (v54), started and supervised by the jailed runner (§4.1, §4.2 step 5).
//!
//! The VMM inherits the runner's credentials (UID/GID `65532`, only `/dev/kvm`'s group, no
//! capabilities, no-new-privileges) and adds its own per-thread seccomp filters and a Landlock
//! ruleset. Of the runner's descriptors only the TAP queue survives `exec`.

use std::ffi::OsString;
use std::os::fd::AsFd;
use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::UnixStream;
use tokio::process::{Child, Command};
use tokio::signal::unix::{SignalKind, signal};

use crate::exit::VmmExit;
use crate::protocol::BootMode;
use crate::tap::Tap;

/// `sealantd` as PID 1, where managed workspace images install it.
pub const GUEST_INIT: &str = "/usr/local/bin/sealantd";
/// The vsock CID the guest gets (2 is the host).
pub const GUEST_CID: u32 = 3;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Arch {
    X86_64,
    Aarch64,
}

impl Arch {
    /// The architecture this runner was built for: the VM is always the host's.
    pub fn host() -> Self {
        if cfg!(target_arch = "aarch64") {
            Arch::Aarch64
        } else {
            Arch::X86_64
        }
    }

    /// The guest's serial console: an 8250 UART on x86_64, a PL011 on aarch64.
    pub fn serial_console(self) -> &'static str {
        match self {
            Arch::X86_64 => "ttyS0",
            Arch::Aarch64 => "ttyAMA0",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Access {
    Read,
    ReadWrite,
}

/// One `--landlock-rules` entry.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LandlockRule {
    pub path: PathBuf,
    pub access: Access,
}

impl LandlockRule {
    fn arg(&self) -> String {
        let access = match self.access {
            Access::Read => "r",
            Access::ReadWrite => "rw",
        };
        format!("path={},access={access}", self.path.display())
    }
}

/// The guest NIC: the pre-opened TAP descriptor's number in the child, and the guest MAC.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NetFd {
    pub fd: i32,
    pub mac: String,
}

/// Everything the Cloud Hypervisor command line is built from.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VmmSpec {
    pub binary: PathBuf,
    pub kernel: PathBuf,
    pub arch: Arch,
    pub mode: BootMode,
    pub vcpus: u32,
    pub memory_mib: u64,
    pub net: Option<NetFd>,
    pub vsock_socket: PathBuf,
    pub api_socket: PathBuf,
    /// `vda`: the image's read-only ext4 base.
    pub base_image: PathBuf,
    /// `vdb`: this executor's writable data disk.
    pub data_image: PathBuf,
    pub landlock_rules: Vec<LandlockRule>,
}

impl VmmSpec {
    /// The guest kernel command line: no initramfs, the read-only base as root, `sealantd` as init.
    pub fn cmdline(&self) -> String {
        format!(
            "console={} root=/dev/vda ro init={GUEST_INIT} sealantd.mode={}",
            self.arch.serial_console(),
            self.mode.as_str()
        )
    }

    pub fn args(&self) -> Vec<OsString> {
        let mut args: Vec<OsString> = Vec::new();
        let mut push = |parts: &[&str]| args.extend(parts.iter().map(OsString::from));
        push(&["--kernel", &self.kernel.display().to_string()]);
        push(&["--cmdline", &self.cmdline()]);
        push(&["--cpus", &format!("boot={}", self.vcpus)]);
        push(&["--memory", &format!("size={}M", self.memory_mib)]);
        push(&["--seccomp", "true"]);
        push(&["--landlock"]);
        if !self.landlock_rules.is_empty() {
            push(&["--landlock-rules"]);
            let rules: Vec<String> = self.landlock_rules.iter().map(LandlockRule::arg).collect();
            push(&rules.iter().map(String::as_str).collect::<Vec<_>>());
        }
        if let Some(net) = &self.net {
            push(&["--net", &format!("fd={},mac={}", net.fd, net.mac)]);
        }
        push(&[
            "--vsock",
            &format!("cid={GUEST_CID},socket={}", self.vsock_socket.display()),
        ]);
        push(&[
            "--disk",
            &format!(
                "path={},readonly=on,image_type=raw",
                self.base_image.display()
            ),
            &format!("path={},image_type=raw", self.data_image.display()),
        ]);
        push(&["--balloon", "size=0,free_page_reporting=on"]);
        push(&["--rng", "src=/dev/urandom"]);
        push(&["--serial", "tty"]);
        push(&["--console", "off"]);
        push(&[
            "--api-socket",
            &format!("path={}", self.api_socket.display()),
        ]);
        args
    }
}

/// Starts Cloud Hypervisor with `spec`. The guest's serial console goes to the runner's stderr.
/// The child has its own process group, so a terminal's Ctrl-C reaches only the runner, which
/// shuts the guest down in order.
pub fn spawn(spec: &VmmSpec, tap: Option<&Tap>) -> std::io::Result<Child> {
    let mut cmd = Command::new(&spec.binary);
    cmd.args(spec.args())
        .stdin(Stdio::null())
        .stdout(Stdio::from(std::io::stderr().as_fd().try_clone_to_owned()?))
        .stderr(Stdio::inherit())
        .process_group(0)
        .kill_on_drop(true);
    if let Some(tap) = tap {
        crate::sys::inherit_fd_in_child(&mut cmd, tap.raw_fd());
    }
    #[allow(
        clippy::disallowed_methods,
        reason = "the runner is its own binary with no orphan reaper, which is what the spawn gate protects against; the gate would also close the TAP descriptor the VMM must inherit"
    )]
    cmd.spawn()
}

/// Asks the guest to shut down: an ACPI power-button press through the VMM's API socket.
pub async fn press_power_button(api_socket: &Path) -> std::io::Result<()> {
    let mut stream = UnixStream::connect(api_socket).await?;
    stream
        .write_all(
            b"PUT /api/v1/vm.power-button HTTP/1.1\r\nHost: localhost\r\n\
              Content-Length: 0\r\nConnection: close\r\n\r\n",
        )
        .await?;
    let mut reply = Vec::new();
    tokio::time::timeout(Duration::from_secs(5), stream.read_to_end(&mut reply))
        .await
        .map_err(|_| std::io::Error::new(std::io::ErrorKind::TimedOut, "API reply"))??;
    let status_line = String::from_utf8_lossy(&reply)
        .lines()
        .next()
        .unwrap_or("")
        .to_owned();
    if status_line
        .split_whitespace()
        .nth(1)
        .is_some_and(|code| code.starts_with('2'))
    {
        Ok(())
    } else {
        Err(std::io::Error::other(format!(
            "power-button refused: {status_line:?}"
        )))
    }
}

/// Waits for the VMM to exit. On SIGTERM or SIGINT, presses the guest's power button and gives
/// it `grace` to power off; a second signal, or the grace running out, kills the VMM.
pub async fn supervise(
    child: &mut Child,
    api_socket: &Path,
    grace: Duration,
) -> std::io::Result<VmmExit> {
    let mut term = signal(SignalKind::terminate())?;
    let mut int = signal(SignalKind::interrupt())?;
    tokio::select! {
        status = child.wait() => return Ok(status?.into()),
        _ = term.recv() => tracing::info!("SIGTERM: shutting the guest down"),
        _ = int.recv() => tracing::info!("SIGINT: shutting the guest down"),
    }
    if let Err(e) = press_power_button(api_socket).await {
        tracing::warn!("could not press the guest's power button: {e}");
    }
    tokio::select! {
        status = child.wait() => return Ok(status?.into()),
        _ = tokio::time::sleep(grace) => tracing::warn!(?grace, "guest did not power off in time; killing the VMM"),
        _ = term.recv() => tracing::warn!("second signal: killing the VMM"),
        _ = int.recv() => tracing::warn!("second signal: killing the VMM"),
    }
    child.start_kill()?;
    Ok(child.wait().await?.into())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn spec(mode: BootMode) -> VmmSpec {
        VmmSpec {
            binary: "/usr/local/bin/cloud-hypervisor".into(),
            kernel: "/usr/share/sealant/vm/vmlinux".into(),
            arch: Arch::X86_64,
            mode,
            vcpus: 4,
            memory_mib: 8192,
            net: Some(NetFd {
                fd: 3,
                mac: "02:aa:bb:cc:dd:ee".into(),
            }),
            vsock_socket: "/run/vm/vsock.sock".into(),
            api_socket: "/run/vm/ch-api.sock".into(),
            base_image: "/var/lib/sealant/images/sha256-abc.img".into(),
            data_image: "/var/lib/sealant/data/data.img".into(),
            landlock_rules: vec![
                LandlockRule {
                    path: "/var/lib/sealant/images".into(),
                    access: Access::Read,
                },
                LandlockRule {
                    path: "/run/vm".into(),
                    access: Access::ReadWrite,
                },
            ],
        }
    }

    fn args(spec: &VmmSpec) -> Vec<String> {
        spec.args()
            .into_iter()
            .map(|a| a.into_string().unwrap())
            .collect()
    }

    /// The values that follow `flag`, up to the next `--flag`.
    fn values<'a>(args: &'a [String], flag: &str) -> Vec<&'a str> {
        let at = args
            .iter()
            .position(|a| a == flag)
            .unwrap_or_else(|| panic!("no {flag} in {args:?}"));
        args[at + 1..]
            .iter()
            .take_while(|a| !a.starts_with("--"))
            .map(String::as_str)
            .collect()
    }

    #[test]
    fn the_command_line_jails_the_vmm_and_keeps_the_base_read_only() {
        let a = args(&spec(BootMode::Normal));
        assert_eq!(values(&a, "--seccomp"), ["true"]);
        assert!(a.contains(&"--landlock".to_owned()));
        assert_eq!(
            values(&a, "--landlock-rules"),
            [
                "path=/var/lib/sealant/images,access=r",
                "path=/run/vm,access=rw"
            ]
        );
        assert_eq!(
            values(&a, "--disk"),
            [
                "path=/var/lib/sealant/images/sha256-abc.img,readonly=on,image_type=raw",
                "path=/var/lib/sealant/data/data.img,image_type=raw"
            ]
        );
        assert_eq!(values(&a, "--net"), ["fd=3,mac=02:aa:bb:cc:dd:ee"]);
        assert_eq!(values(&a, "--vsock"), ["cid=3,socket=/run/vm/vsock.sock"]);
        assert_eq!(values(&a, "--balloon"), ["size=0,free_page_reporting=on"]);
        assert_eq!(values(&a, "--rng"), ["src=/dev/urandom"]);
        assert_eq!(values(&a, "--cpus"), ["boot=4"]);
        assert_eq!(values(&a, "--memory"), ["size=8192M"]);
        assert_eq!(values(&a, "--serial"), ["tty"]);
        assert_eq!(values(&a, "--kernel"), ["/usr/share/sealant/vm/vmlinux"]);
    }

    #[test]
    fn the_kernel_command_line_names_the_mode_and_the_arch_console() {
        assert_eq!(
            spec(BootMode::Normal).cmdline(),
            "console=ttyS0 root=/dev/vda ro init=/usr/local/bin/sealantd sealantd.mode=normal"
        );
        let mut recover = spec(BootMode::Recover);
        recover.arch = Arch::Aarch64;
        assert_eq!(
            recover.cmdline(),
            "console=ttyAMA0 root=/dev/vda ro init=/usr/local/bin/sealantd sealantd.mode=recover"
        );
        let a = args(&recover);
        assert_eq!(values(&a, "--cmdline"), [recover.cmdline().as_str()]);
    }

    #[test]
    fn without_a_tap_there_is_no_net_device() {
        let mut s = spec(BootMode::Recover);
        s.net = None;
        assert!(!args(&s).contains(&"--net".to_owned()));
    }

    #[tokio::test]
    async fn the_power_button_is_a_put_on_the_api_socket() {
        let tmp = tempfile::tempdir().unwrap();
        let api = tmp.path().join("api.sock");
        let listener = tokio::net::UnixListener::bind(&api).unwrap();
        let server = tokio::spawn(async move {
            let (mut s, _) = listener.accept().await.unwrap();
            let mut buf = vec![0u8; 1024];
            let n = s.read(&mut buf).await.unwrap();
            s.write_all(b"HTTP/1.1 204 No Content\r\n\r\n")
                .await
                .unwrap();
            String::from_utf8_lossy(&buf[..n]).into_owned()
        });
        press_power_button(&api).await.unwrap();
        let request = server.await.unwrap();
        assert!(
            request.starts_with("PUT /api/v1/vm.power-button HTTP/1.1\r\n"),
            "{request}"
        );
    }

    #[tokio::test]
    #[allow(
        clippy::disallowed_methods,
        reason = "the runner is its own binary with no orphan reaper, which is what the spawn gate protects against; the gate would also close the TAP descriptor the VMM must inherit"
    )]
    async fn the_child_inherits_the_tap_descriptor_and_no_other() {
        // A stand-in VMM that lists its open descriptors. The runner's own descriptors are all
        // close-on-exec; the hook clears it for the one named descriptor only.
        let kept = std::fs::File::open("/dev/null").unwrap();
        let other = std::fs::File::open("/dev/null").unwrap();
        let kept_fd = std::os::fd::AsRawFd::as_raw_fd(&kept);
        let other_fd = std::os::fd::AsRawFd::as_raw_fd(&other);
        let probe = |fd: i32| {
            let mut cmd = Command::new("sh");
            cmd.arg("-c")
                .arg(format!("test -e /proc/self/fd/{fd}"))
                .stdin(Stdio::null());
            crate::sys::inherit_fd_in_child(&mut cmd, kept_fd);
            cmd
        };
        assert!(
            probe(kept_fd).status().await.unwrap().success(),
            "{kept_fd} was not inherited"
        );
        assert!(
            !probe(other_fd).status().await.unwrap().success(),
            "{other_fd} leaked into the child"
        );
    }
}
