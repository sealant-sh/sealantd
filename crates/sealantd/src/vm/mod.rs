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
//! 2. opens its one connection to the runner on vsock port 1026 ([`channel`]), reads the
//!    [`protocol::VmBootConfig`] from it and holds it for its lifetime;
//! 3. sets the image's `PATH` and the daemon's own settings in its process environment;
//! 4. on a normal boot, configures the network ([`net`]), writes the combined CA bundle and
//!    `/etc/hosts` when missing, binds the loopback session endpoint ([`session`]) and starts
//!    the guest `dockerd` (and `nix-daemon` on a Nix image);
//! 5. runs the same supervisor `sealantd boot` runs in a container ([`crate::boot`]), with the
//!    control protocol on vsock port 1024 (status and final flush only on a recovery), the
//!    capture traffic on vsock port 1025, and a graceful shutdown on the runner's shutdown
//!    frame or the power button ([`power`]);
//! 6. on its way out, whatever the exit, syncs the data disk, sends the runner a
//!    [`protocol::GuestExitStatus`] on the held connection and powers the machine off.
//!
//! Outside PID 1 (`sealantd --vm` run by hand) the layout and the power-off are skipped.

pub mod channel;
pub mod env;
pub mod layout;
pub mod net;
pub mod power;
pub mod protocol;
pub mod reclaim;
pub mod session;

use std::path::Path;
use std::process::ExitCode;
use std::sync::Arc;
use std::time::Duration;

use channel::BootChannel;
use protocol::{GuestExitStatus, PROTOCOL_VERSION, VmBootConfig, VmMode};

use crate::boot::{BootConfig, BootExtras};
use crate::runtime::{EXIT_CAPTURE_INCOMPLETE, Runtime};

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
    let (mode, ended, channel) = boot(cli_mode, pid1);
    finish(mode, ended, channel, pid1)
}

fn boot(cli_mode: Option<VmMode>, pid1: bool) -> (VmMode, Ended, Option<BootChannel>) {
    if pid1 && let Err(error) = apply_layout(&layout::early()) {
        // Without /proc there is no command line to read: say which boot failed as best known.
        let mode = cli_mode.unwrap_or_default();
        return (mode, Ended::failed(mode, error), None);
    }
    let mode = cli_mode
        .or_else(|| {
            std::fs::read_to_string("/proc/cmdline")
                .ok()
                .and_then(|cmdline| env::mode_from_cmdline(&cmdline))
        })
        .unwrap_or_default();
    tracing::info!(?mode, pid1, "sealantd --vm starting");
    let (ended, channel) = boot_mode(mode, pid1);
    (mode, ended, channel)
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

fn boot_mode(mode: VmMode, pid1: bool) -> (Ended, Option<BootChannel>) {
    if pid1 {
        let steps = match mode {
            VmMode::Normal => layout::normal(),
            VmMode::Recover => layout::recovery(),
        };
        if let Err(error) = apply_layout(&steps) {
            return (
                Ended::failed(mode, format!("filesystem layout: {error}")),
                None,
            );
        }
    } else {
        tracing::warn!("not PID 1: the filesystem layout is left as it is");
    }

    // One connection, once: a version mismatch or a malformed frame fails the boot at once.
    let (mut channel, boot) = match BootChannel::open() {
        Ok(opened) => opened,
        Err(error) => return (Ended::failed(mode, format!("boot config: {error}")), None),
    };
    let ended = boot_with_config(mode, pid1, &mut channel, boot);
    (ended, Some(channel))
}

fn boot_with_config(
    mode: VmMode,
    pid1: bool,
    channel: &mut BootChannel,
    boot: VmBootConfig,
) -> Ended {
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
    let mut session_listener = None;
    if mode == VmMode::Normal {
        // Normal only: a recovery boot runs on the read-only base and writes nothing to it.
        if let Some(pem) = &boot.executor_ca_pem {
            match env::write_bundle(Path::new(env::CA_BUNDLE_PATH), pem) {
                Ok(path) => extras.ca_bundle = Some(path),
                // TLS through the egress proxy's inspected hosts fails without it; nothing else.
                Err(error) => {
                    tracing::error!(%error, "the combined CA bundle could not be written")
                }
            }
        }
        match env::ensure_hosts(Path::new("/etc/hosts")) {
            Ok(true) => tracing::info!("/etc/hosts was missing or empty; wrote localhost"),
            Ok(false) => {}
            Err(error) => tracing::warn!(%error, "/etc/hosts could not be written"),
        }
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
    // Before any thread exists (the boot read's runtime is gone, the daemon's not yet made):
    // the image's PATH and the daemon's own settings, which the kernel never gave PID 1.
    if let Err(error) =
        sealant_process::process_env::set_while_single_threaded(&env::process_env(&vm_env))
    {
        tracing::warn!(%error, "the image's PATH could not be set on the daemon");
    }
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

    let watcher = watcher_half(channel);
    let services = (mode == VmMode::Normal).then(|| GuestServices {
        dockerd: boot.dockerd.then(|| find_on_path(&vm_env, "dockerd")),
        nix_daemon: nix_daemon(&vm_env),
        session_listener,
        reclaim: pid1,
    });
    let extras = BootExtras {
        vsock_control_port: Some(sealant_control::vsock::CONTROL_PORT),
        on_healthy: Some(on_healthy(watcher, pid1, services)),
    };
    let secret_env = env::secret_env(&boot);
    drop(boot);
    let code = crate::boot::boot_with(config, secret_env, extras);
    Ended {
        code: exit_code_number(code),
        reason: None,
    }
}

#[cfg(target_os = "linux")]
type WatcherHalf = Option<(socket2::Socket, Vec<u8>)>;
#[cfg(not(target_os = "linux"))]
type WatcherHalf = Option<()>;

#[cfg(target_os = "linux")]
fn watcher_half(channel: &mut BootChannel) -> WatcherHalf {
    match channel.watcher_half() {
        Ok(half) => Some(half),
        Err(error) => {
            tracing::error!(%error, "the runner's shutdown frame cannot be watched");
            None
        }
    }
}

#[cfg(not(target_os = "linux"))]
fn watcher_half(_channel: &mut BootChannel) -> WatcherHalf {
    None
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

/// What a normal guest starts beside the daemon.
#[derive(Debug)]
struct GuestServices {
    /// `Some(path)` when asked for (`Some(None)`: asked for and not found).
    dockerd: Option<Option<String>>,
    /// The image's `nix-daemon`, on a Nix image.
    nix_daemon: Option<String>,
    session_listener: Option<std::net::TcpListener>,
    reclaim: bool,
}

/// What runs on the daemon's runtime once it is healthy: in every mode the shutdown watchers
/// (the runner's shutdown frame, the power button); in normal mode the guest's services.
fn on_healthy(
    watcher: WatcherHalf,
    pid1: bool,
    services: Option<GuestServices>,
) -> crate::boot::OnHealthy {
    Box::new(move |runtime, shutdown| {
        #[cfg(target_os = "linux")]
        let runner = watcher.and_then(|(socket, pending)| {
            BootChannel::reader(socket, pending)
                .map_err(|error| tracing::error!(%error, "the boot channel cannot be watched"))
                .ok()
        });
        #[cfg(not(target_os = "linux"))]
        let runner: Option<tokio::io::BufReader<&'static [u8]>> = {
            let _ = watcher;
            None
        };
        channel::spawn_shutdown_watchers(runtime.clone(), runner, pid1, shutdown.clone());
        let Some(services) = services else {
            return;
        };
        if let Some(listener) = services.session_listener {
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
        match services.dockerd {
            Some(Some(path)) => start_dockerd(&runtime, &path),
            Some(None) => tracing::error!("dockerd was asked for but is not on the image's PATH"),
            None => {}
        }
        if let Some(path) = services.nix_daemon {
            tokio::spawn(supervise_nix_daemon(
                runtime.clone(),
                path,
                shutdown.clone(),
            ));
        }
        if services.reclaim {
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

fn find_on_path(vm_env: &env::VmEnv, program: &str) -> Option<String> {
    use crate::boot::config::EnvSource as _;
    let path = vm_env
        .get("PATH")
        .unwrap_or_else(|| "/usr/local/bin:/usr/bin:/bin".to_owned());
    path.split(':')
        .map(|dir| Path::new(dir).join(program))
        .find(|candidate| candidate.is_file())
        .map(|found| found.display().to_string())
}

/// The image's `nix-daemon` on a managed Nix layout (`/nix/var/nix` present): on the image's
/// `PATH`, else the default profile's.
fn nix_daemon(vm_env: &env::VmEnv) -> Option<String> {
    nix_daemon_in(vm_env, Path::new("/"))
}

fn nix_daemon_in(vm_env: &env::VmEnv, root: &Path) -> Option<String> {
    if !root.join("nix/var/nix").is_dir() {
        return None;
    }
    find_on_path(vm_env, "nix-daemon").or_else(|| {
        let profile = root.join("nix/var/nix/profiles/default/bin/nix-daemon");
        profile.is_file().then(|| profile.display().to_string())
    })
}

/// The guest `dockerd`, a service of the daemon ([`Runtime::start_docker_service`]): the final
/// flush stops its containers through it twice, sparing it until then, and stops it last.
fn start_dockerd(runtime: &Arc<Runtime>, executable: &str) {
    let mut command = tokio::process::Command::new(executable);
    command
        .arg(format!("--host={}", env::GUEST_DOCKER_HOST))
        .current_dir("/")
        .stdin(std::process::Stdio::null());
    match runtime.start_docker_service(&mut command) {
        Ok(pid) => tracing::info!(pid, "guest dockerd started"),
        Err(error) => tracing::error!(%error, "guest dockerd failed to start"),
    }
}

/// How many times `nix-daemon` is restarted after it exits on its own.
const NIX_DAEMON_RESTARTS: u32 = 5;

/// Run the image's `nix-daemon` (per-person `nix` commands talk to it), restarting it if it
/// exits on its own, until the daemon stops or a final flush closes admission (whose sweep
/// stops it with every other process).
async fn supervise_nix_daemon(
    runtime: Arc<Runtime>,
    executable: String,
    mut shutdown: tokio::sync::watch::Receiver<bool>,
) {
    for attempt in 0..=NIX_DAEMON_RESTARTS {
        if runtime.admission_is_closed() || *shutdown.borrow() {
            return;
        }
        let mut command = tokio::process::Command::new(&executable);
        command
            .current_dir("/")
            .stdin(std::process::Stdio::null())
            .process_group(0)
            .kill_on_drop(true);
        let (mut child, _gate) = match sealant_process::spawn::spawn_tokio(&mut command) {
            Ok(spawned) => spawned,
            Err(error) => {
                tracing::error!(%error, "nix-daemon failed to start");
                return;
            }
        };
        tracing::info!(pid = child.id(), attempt, "nix-daemon started");
        tokio::select! {
            status = child.wait() => {
                tracing::warn!(?status, "nix-daemon exited");
            }
            _ = shutdown.changed() => return,
        }
        tokio::time::sleep(Duration::from_secs(1)).await;
    }
    tracing::error!("nix-daemon keeps exiting; not restarted again");
}

/// Sync the data disk, report the exit to the runner on the held connection, and power off
/// when PID 1.
fn finish(mode: VmMode, ended: Ended, channel: Option<BootChannel>, pid1: bool) -> ExitCode {
    let synced = sync_data_disk(Path::new(layout::DATA_MOUNT), &[Path::new("/workspace")]);
    let status = GuestExitStatus {
        version: PROTOCOL_VERSION,
        exit_code: i32::from(ended.code),
        synced,
        reason: ended.reason,
    };
    tracing::info!(?mode, ?status, "guest exiting");
    match channel {
        Some(channel) => {
            if let Err(error) = channel.report(&status) {
                tracing::error!(%error, "the exit status could not be sent to the runner");
            }
        }
        None => tracing::error!("no boot channel: the runner gets no exit status"),
    }
    if pid1 {
        power_off();
    }
    ExitCode::from(ended.code)
}

/// `sync()`, then `syncfs` on `data` (the data disk) and on each of `also`. `true` only when
/// the data disk's own `syncfs` completed: what the runner's 76 relies on. A failure on one of
/// `also` is logged.
fn sync_data_disk(data: &Path, also: &[&Path]) -> bool {
    nix::unistd::sync();
    for path in also {
        if let Ok(dir) = std::fs::File::open(path)
            && let Err(error) = nix::unistd::syncfs(&dir)
        {
            tracing::warn!(path = %path.display(), %error, "syncfs failed");
        }
    }
    match std::fs::File::open(data) {
        Ok(dir) => match nix::unistd::syncfs(&dir) {
            Ok(()) => true,
            Err(error) => {
                tracing::error!(path = %data.display(), %error, "syncfs of the data disk failed");
                false
            }
        },
        Err(error) => {
            tracing::error!(path = %data.display(), %error, "the data disk cannot be opened to sync");
            false
        }
    }
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

    #[test]
    fn synced_is_claimed_only_when_the_data_disks_syncfs_completed() {
        let dir = tempfile::tempdir().expect("tempdir");
        assert!(sync_data_disk(dir.path(), &[]));
        // A data mount that cannot be opened is not synced, whatever else synced.
        assert!(!sync_data_disk(&dir.path().join("absent"), &[dir.path()]));
        // A failure on another path does not change the data disk's answer.
        assert!(sync_data_disk(dir.path(), &[&dir.path().join("absent")]));
    }

    #[test]
    fn nix_daemon_runs_only_on_a_nix_layout() {
        let root = tempfile::tempdir().expect("tempdir");
        let bin = root.path().join("bin");
        std::fs::create_dir_all(&bin).expect("bin");
        std::fs::write(bin.join("nix-daemon"), b"").expect("daemon");
        let vm_env = env::VmEnv(std::collections::BTreeMap::from([(
            "PATH".to_owned(),
            bin.display().to_string(),
        )]));
        assert_eq!(nix_daemon_in(&vm_env, root.path()), None, "no /nix/var/nix");
        std::fs::create_dir_all(root.path().join("nix/var/nix")).expect("nix");
        assert_eq!(
            nix_daemon_in(&vm_env, root.path()),
            Some(bin.join("nix-daemon").display().to_string())
        );
        // Off the PATH, the default profile's.
        let profile = root.path().join("nix/var/nix/profiles/default/bin");
        std::fs::create_dir_all(&profile).expect("profile");
        std::fs::write(profile.join("nix-daemon"), b"").expect("daemon");
        let empty = env::VmEnv(std::collections::BTreeMap::from([(
            "PATH".to_owned(),
            "/nonexistent".to_owned(),
        )]));
        assert_eq!(
            nix_daemon_in(&empty, root.path()),
            Some(profile.join("nix-daemon").display().to_string())
        );
    }
}
