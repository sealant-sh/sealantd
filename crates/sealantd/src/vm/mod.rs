//! `sealantd --vm`: PID 1 of a workspace microVM (the `host-vm` runtime, architecture §§5.3,
//! 6.1, 6.2).
//!
//! The runner boots the guest kernel with `init=/usr/local/bin/sealantd -- --vm` and
//! `sealantd.mode=normal|recover`. As PID 1 this:
//!
//! 1. mounts the kernel and runtime filesystems, then the two-disk layout for the mode
//!    ([`layout`]): an overlay root over the base disk with the data disk's workspace, home
//!    and Docker storage bound past it, or for a recovery the clean base disk with the
//!    workspace and home bound in;
//! 2. reads the runner's [`protocol::VmBootConfig`] on vsock port 1026;
//! 3. on a normal boot, configures the network ([`net`]), writes the combined CA bundle, binds
//!    the loopback session endpoint ([`session`]) and starts the guest `dockerd` when asked;
//! 4. runs the same supervisor `sealantd boot` runs in a container ([`crate::boot`]), with the
//!    control protocol on vsock port 1024 (status and final flush only on a recovery) and the
//!    capture traffic on vsock port 1025;
//! 5. on its way out, whatever the exit, syncs the data disk, sends the runner a
//!    [`protocol::GuestExitStatus`] and powers the machine off.
//!
//! Outside PID 1 (`sealantd --vm` run by hand) the layout and the power-off are skipped.

pub mod env;
pub mod layout;
pub mod net;
pub mod protocol;
pub mod reclaim;
pub mod session;

use std::path::Path;
use std::process::ExitCode;
use std::sync::Arc;
use std::time::Duration;

use protocol::{GuestExitStatus, PROTOCOL_VERSION, VmBootConfig, VmMode};

use crate::boot::{BootConfig, BootExtras};
use crate::runtime::{EXIT_CAPTURE_INCOMPLETE, Runtime};

/// How long the guest keeps dialling the runner's boot port.
const BOOT_DIAL_FOR: Duration = Duration::from_secs(30);
/// How long the guest waits for the runner to acknowledge its exit status.
const EXIT_ACK_WITHIN: Duration = Duration::from_secs(5);

/// The number an [`ExitCode`] carries (it has no getter; it compares).
#[must_use]
pub fn exit_code_number(code: ExitCode) -> u8 {
    (0..=u8::MAX)
        .find(|n| ExitCode::from(*n) == code)
        .unwrap_or(1)
}

/// What a boot came to before the exit protocol.
#[derive(Debug)]
struct Ended {
    code: u8,
    reason: Option<String>,
}

impl Ended {
    fn failed(mode: VmMode, reason: String) -> Self {
        tracing::error!(%reason, "vm boot failed");
        Self {
            // A recovery that could not run has not saved what the disk holds.
            code: if mode == VmMode::Recover {
                EXIT_CAPTURE_INCOMPLETE
            } else {
                1
            },
            reason: Some(reason),
        }
    }
}

/// Entry point for `sealantd --vm`. `cli_mode` (`--vm-mode`) wins over the kernel command line.
pub fn run(cli_mode: Option<VmMode>, log_level: &str) -> ExitCode {
    crate::boot::init_tracing(log_level);
    let pid1 = std::process::id() == 1;
    let (mode, ended) = boot(cli_mode, pid1);
    finish(mode, ended, pid1)
}

fn boot(cli_mode: Option<VmMode>, pid1: bool) -> (VmMode, Ended) {
    if pid1 && let Err(error) = apply_layout(&layout::early()) {
        // Without /proc there is no command line to read: say which boot failed as best known.
        let mode = cli_mode.unwrap_or_default();
        return (mode, Ended::failed(mode, error));
    }
    let mode = cli_mode
        .or_else(|| {
            std::fs::read_to_string("/proc/cmdline")
                .ok()
                .and_then(|cmdline| env::mode_from_cmdline(&cmdline))
        })
        .unwrap_or_default();
    tracing::info!(?mode, pid1, "sealantd --vm starting");
    (mode, boot_mode(mode, pid1))
}

fn apply_layout(steps: &[layout::Step]) -> Result<(), String> {
    #[cfg(target_os = "linux")]
    {
        layout::apply(steps).map_err(|error| error.to_string())
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = steps;
        Err("the vm layout is Linux only".to_owned())
    }
}

fn boot_mode(mode: VmMode, pid1: bool) -> Ended {
    if pid1 {
        let steps = match mode {
            VmMode::Normal => layout::normal(),
            VmMode::Recover => layout::recovery(),
        };
        if let Err(error) = apply_layout(&steps) {
            return Ended::failed(mode, format!("filesystem layout: {error}"));
        }
    } else {
        tracing::warn!("not PID 1: the filesystem layout is left as it is");
    }

    let boot = match fetch_boot_config() {
        Ok(boot) => boot,
        Err(error) => return Ended::failed(mode, error),
    };
    if boot.mode != mode {
        return Ended::failed(
            mode,
            format!(
                "the runner's boot config says {:?} but the kernel booted {:?}",
                boot.mode, mode
            ),
        );
    }
    tracing::info!(?boot, "boot config received");

    let mut extras = env::Extras::default();
    if let Some(pem) = &boot.executor_ca_pem {
        match env::write_bundle(Path::new(env::CA_BUNDLE_PATH), pem) {
            Ok(path) => extras.ca_bundle = Some(path),
            // TLS through the egress proxy's inspected hosts fails without it; nothing else does.
            Err(error) => tracing::error!(%error, "the combined CA bundle could not be written"),
        }
    }

    let mut session_listener = None;
    if mode == VmMode::Normal {
        configure_network(&boot);
        match bind_session_listener() {
            Ok((listener, endpoint)) => {
                extras.session_endpoint = Some(endpoint);
                session_listener = Some(listener);
            }
            Err(error) => tracing::error!(%error, "the session endpoint could not be bound"),
        }
        if let Some(archive) = &boot.dotfiles_archive {
            match env::write_dotfiles(Path::new(env::DOTFILES_ARCHIVE_DIR), archive) {
                Ok(dir) => extras.dotfiles_dir = Some(dir),
                Err(error) => return Ended::failed(mode, error),
            }
        }
    }

    let vm_env = env::assemble(&boot, &extras);
    let config = match BootConfig::load(&vm_env) {
        Ok(config) => env::clear_recovery_docker(config, mode),
        Err(error) => return Ended::failed(mode, format!("boot configuration: {error}")),
    };
    if let Some(dir) = boot
        .config
        .working_dir
        .as_deref()
        .filter(|dir| Path::new(dir).is_dir())
    {
        let _ = std::env::set_current_dir(dir);
    }

    let extras = BootExtras {
        vsock_control_port: Some(sealant_control::vsock::CONTROL_PORT),
        on_healthy: match mode {
            VmMode::Normal => Some(guest_services(&boot, &vm_env, session_listener, pid1)),
            VmMode::Recover => None,
        },
    };
    let secret_env = env::secret_env(&boot);
    drop(boot);
    let code = crate::boot::boot_with(config, secret_env, extras);
    Ended {
        code: exit_code_number(code),
        reason: None,
    }
}

/// Dial the runner's boot port and read the boot config, retrying while the runner is not yet
/// listening.
fn fetch_boot_config() -> Result<VmBootConfig, String> {
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|error| format!("async runtime: {error}"))?;
    runtime.block_on(async {
        let deadline = tokio::time::Instant::now() + BOOT_DIAL_FOR;
        loop {
            match read_boot_config().await {
                Ok(boot) => return Ok(boot),
                Err(error) if tokio::time::Instant::now() < deadline => {
                    tracing::debug!(%error, "boot config not yet available; retrying");
                    tokio::time::sleep(Duration::from_millis(200)).await;
                }
                Err(error) => return Err(format!("boot config: {error}")),
            }
        }
    })
}

#[cfg(target_os = "linux")]
async fn read_boot_config() -> Result<VmBootConfig, String> {
    use sealant_control::vsock::{BOOT_PORT, VMADDR_CID_HOST, VsockStream};
    let stream = VsockStream::connect(VMADDR_CID_HOST, BOOT_PORT)
        .await
        .map_err(|error| format!("vsock {VMADDR_CID_HOST}:{BOOT_PORT}: {error}"))?;
    let mut reader = tokio::io::BufReader::new(stream);
    protocol::read_frame(&mut reader)
        .await
        .map_err(|error| error.to_string())
}

#[cfg(not(target_os = "linux"))]
async fn read_boot_config() -> Result<VmBootConfig, String> {
    Err("vsock is Linux only".to_owned())
}

fn configure_network(boot: &VmBootConfig) {
    let config = boot.network_config.clone().unwrap_or_default();
    #[cfg(target_os = "linux")]
    {
        match net::Netlink::open()
            .map_err(|error| error.to_string())
            .and_then(|mut netlink| {
                netlink
                    .configure(&config, Path::new("/etc/resolv.conf"))
                    .map_err(|error| error.to_string())
            }) {
            // The control plane, terminals and saving work ride vsock: a guest without a
            // network still works, so this is logged, not fatal.
            Err(error) => tracing::error!(%error, "guest network configuration failed"),
            Ok(()) => tracing::info!(address = %config.address, "guest network configured"),
        }
    }
    #[cfg(not(target_os = "linux"))]
    let _ = config;
}

fn bind_session_listener() -> std::io::Result<(std::net::TcpListener, String)> {
    let listener = std::net::TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, 0))?;
    listener.set_nonblocking(true)?;
    let endpoint = format!("http://{}", listener.local_addr()?);
    Ok((listener, endpoint))
}

/// The normal guest's services, started on the daemon's runtime once it is healthy.
fn guest_services(
    boot: &VmBootConfig,
    vm_env: &env::VmEnv,
    session_listener: Option<std::net::TcpListener>,
    pid1: bool,
) -> crate::boot::OnHealthy {
    let dockerd = boot.dockerd.then(|| find_dockerd(vm_env));
    Box::new(move |runtime, shutdown| {
        if let Some(listener) = session_listener {
            match tokio::net::TcpListener::from_std(listener) {
                #[cfg(target_os = "linux")]
                Ok(listener) => {
                    tokio::spawn(session::forward_to_host(listener, shutdown.clone()));
                }
                #[cfg(not(target_os = "linux"))]
                Ok(_) => {}
                Err(error) => tracing::error!(%error, "the session endpoint could not start"),
            }
        }
        match dockerd {
            Some(Some(path)) => start_dockerd(&runtime, &path),
            Some(None) => tracing::error!("dockerd was asked for but is not on the image's PATH"),
            None => {}
        }
        if pid1 {
            tokio::spawn(reclaim::run(
                runtime,
                reclaim::Policy::default(),
                reclaim::SystemActions {
                    data_mount: layout::DATA_MOUNT.into(),
                },
                shutdown,
            ));
        }
    })
}

fn find_dockerd(vm_env: &env::VmEnv) -> Option<String> {
    use crate::boot::config::EnvSource as _;
    let path = vm_env
        .get("PATH")
        .unwrap_or_else(|| "/usr/local/bin:/usr/bin:/bin".to_owned());
    path.split(':')
        .map(|dir| Path::new(dir).join("dockerd"))
        .find(|candidate| candidate.is_file())
        .map(|found| found.display().to_string())
}

/// The guest `dockerd`, a managed process of the daemon: its output is on the event bus, and
/// the final flush stops its containers through it, then terminates it with every other writer.
fn start_dockerd(runtime: &Arc<Runtime>, executable: &str) {
    let args = sealant_protocol::ExecArgs {
        user: None,
        execution_id: runtime.default_execution_id(),
        session_id: None,
        executable: executable.to_owned(),
        args: vec![format!("--host={}", env::GUEST_DOCKER_HOST)],
        cwd: Some("/".to_owned()),
        env: vec![],
        secret_env: vec![],
        stdin: false,
        attach: false,
        timeout_millis: None,
        background: true,
        capture: None,
        graceful_signal: None,
    };
    match runtime.spawn_managed(args) {
        Ok(accepted) => tracing::info!(pid = accepted.pid, "guest dockerd started"),
        Err(error) => tracing::error!(%error, "guest dockerd failed to start"),
    }
}

/// Sync the data disk, report the exit to the runner, and power off when PID 1.
fn finish(mode: VmMode, ended: Ended, pid1: bool) -> ExitCode {
    let synced = sync_data_disk();
    let status = GuestExitStatus {
        version: PROTOCOL_VERSION,
        exit_code: i32::from(ended.code),
        synced,
        reason: ended.reason,
    };
    tracing::info!(?mode, ?status, "guest exiting");
    if let Err(error) = send_exit_status(&status) {
        tracing::error!(%error, "the exit status could not be sent to the runner");
    }
    if pid1 {
        power_off();
    }
    ExitCode::from(ended.code)
}

/// `sync()`, then `syncfs` on the workspace and the data disk so their journals are on the
/// device: what the runner's 76 or the recovery's save relies on.
fn sync_data_disk() -> bool {
    nix::unistd::sync();
    let mut synced = true;
    for path in ["/workspace", layout::DATA_MOUNT] {
        let Ok(dir) = std::fs::File::open(path) else {
            continue;
        };
        if let Err(error) = nix::unistd::syncfs(&dir) {
            tracing::warn!(path, %error, "syncfs failed");
            synced = false;
        }
    }
    synced
}

fn send_exit_status(status: &GuestExitStatus) -> Result<(), String> {
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|error| error.to_string())?;
    runtime.block_on(async {
        tokio::time::timeout(EXIT_ACK_WITHIN, exchange_exit_status(status))
            .await
            .map_err(|_| "the runner did not acknowledge in time".to_owned())?
    })
}

#[cfg(target_os = "linux")]
async fn exchange_exit_status(status: &GuestExitStatus) -> Result<(), String> {
    use sealant_control::vsock::{BOOT_PORT, VMADDR_CID_HOST, VsockStream};
    let stream = VsockStream::connect(VMADDR_CID_HOST, BOOT_PORT)
        .await
        .map_err(|error| error.to_string())?;
    report_exit(stream, status).await
}

#[cfg(not(target_os = "linux"))]
async fn exchange_exit_status(_status: &GuestExitStatus) -> Result<(), String> {
    Err("vsock is Linux only".to_owned())
}

/// Write `status` on `stream` and wait for the runner's [`protocol::ExitAck`].
async fn report_exit<S>(stream: S, status: &GuestExitStatus) -> Result<(), String>
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
{
    let mut stream = tokio::io::BufReader::new(stream);
    protocol::write_frame(stream.get_mut(), status)
        .await
        .map_err(|error| error.to_string())?;
    let _ack: protocol::ExitAck = protocol::read_frame(&mut stream)
        .await
        .map_err(|error| error.to_string())?;
    Ok(())
}

/// Power the machine off. PID 1 must never return: if the kernel refuses, wait forever.
fn power_off() -> ! {
    #[cfg(target_os = "linux")]
    {
        use nix::sys::reboot::{RebootMode, reboot};
        let Err(error) = reboot(RebootMode::RB_POWER_OFF);
        tracing::error!(%error, "power off failed");
    }
    loop {
        std::thread::sleep(Duration::from_secs(3600));
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};

    #[test]
    fn an_exit_code_reads_back_as_its_number() {
        for n in [0u8, 1, 75, 76, 78, 255] {
            assert_eq!(exit_code_number(ExitCode::from(n)), n);
        }
        assert_eq!(exit_code_number(ExitCode::SUCCESS), 0);
        assert_eq!(exit_code_number(ExitCode::FAILURE), 1);
    }

    #[test]
    fn a_failed_recovery_is_unsaved_work_and_a_failed_normal_boot_is_a_failure() {
        assert_eq!(
            Ended::failed(VmMode::Recover, "x".to_owned()).code,
            EXIT_CAPTURE_INCOMPLETE
        );
        assert_eq!(Ended::failed(VmMode::Normal, "x".to_owned()).code, 1);
    }

    #[tokio::test]
    async fn the_exit_status_is_written_before_the_ack_is_awaited() {
        let (guest, runner) = tokio::io::duplex(4096);
        let status = GuestExitStatus {
            version: PROTOCOL_VERSION,
            exit_code: 76,
            synced: true,
            reason: None,
        };
        let runner = tokio::spawn(async move {
            let mut runner = BufReader::new(runner);
            let mut line = String::new();
            runner.read_line(&mut line).await.expect("line");
            runner
                .get_mut()
                .write_all(b"{\"version\":1}\n")
                .await
                .expect("ack");
            line
        });
        report_exit(guest, &status).await.expect("acknowledged");
        let line = runner.await.expect("runner");
        assert_eq!(
            serde_json::from_str::<GuestExitStatus>(&line).expect("status"),
            status
        );
    }

    #[tokio::test]
    async fn a_runner_that_closes_without_an_ack_is_an_error() {
        let (guest, runner) = tokio::io::duplex(4096);
        tokio::spawn(async move {
            let mut runner = BufReader::new(runner);
            let mut line = String::new();
            let _ = runner.read_line(&mut line).await;
        });
        let status = GuestExitStatus {
            version: PROTOCOL_VERSION,
            exit_code: 0,
            synced: true,
            reason: None,
        };
        assert!(report_exit(guest, &status).await.is_err());
    }
}
