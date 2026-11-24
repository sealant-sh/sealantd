//! `sealant-vm-runner`: see the library docs for the sequence. Everything privileged happens in
//! [`setup`], on the only thread, before the async runtime exists.
#![cfg_attr(not(test), deny(clippy::unwrap_used, clippy::expect_used))]
#![forbid(unsafe_code)]

use std::net::{IpAddr, SocketAddr};
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::time::Duration;

use clap::{Parser, ValueEnum};
use tokio::net::{TcpListener, UdpSocket};

use sealant_vm_runner::exit::{self, EXIT_SETUP_FAILED, ExitRecorder};
use sealant_vm_runner::net::{
    DNS_PORT, HOST_IP, HTTP_PORT, HTTPS_PORT, MTU, PREFIX_LEN, RESOURCE_PORT, TAP_NAME, TCP_PORT,
    Upstreams,
};
use sealant_vm_runner::nft::{self, Egress, Policy};
use sealant_vm_runner::protocol::{self, BootMode, GuestNetworkConfig, StagedFiles, VmBootConfig};
use sealant_vm_runner::tap::{self, Tap};
use sealant_vm_runner::vmm::{self, Access, Arch, LandlockRule, NetFd, VmmSpec};
use sealant_vm_runner::vsock::{self, Mux};
use sealant_vm_runner::{forward, jail, selftest};

type Error = Box<dyn std::error::Error + Send + Sync>;

/// How long the boot channel may take to finish after the VMM exits.
const BOOT_CHANNEL_DRAIN: Duration = Duration::from_secs(2);
/// The descriptor ceiling the runner asks for: every forwarded connection holds two.
const NOFILE_TARGET: u64 = 65_536;

#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
enum EgressMode {
    Standard,
    Restricted,
}

/// Runs one workspace microVM inside its host-vm container.
#[derive(Debug, Parser)]
#[command(name = "sealant-vm-runner", version)]
struct Args {
    /// Check KVM, TUN, nftables, Landlock and Cloud Hypervisor, print a JSON report, and exit.
    #[arg(long)]
    self_test: bool,

    /// `normal`, or `recover` (clean base, flush and status only, no session channel, no egress).
    #[arg(long, value_enum, default_value = "normal")]
    mode: BootMode,
    /// The worktree's Access policy network mode.
    #[arg(long, value_enum, default_value = "standard")]
    egress: EgressMode,
    /// A TCP port the restricted policy allows besides 80 and 443 (repeatable).
    #[arg(long = "allow-tcp-port", value_name = "PORT")]
    allow_tcp_ports: Vec<u16>,
    /// `<name>-proxy`'s address on the workspace's egress network. Required in normal mode.
    #[arg(long)]
    proxy_ip: Option<IpAddr>,

    /// The base image digest: the disk is `<images-dir>/<digest>.img`.
    #[arg(long)]
    image_digest: Option<String>,
    /// The guest kernel (`vmlinux` on x86_64, `Image` on aarch64).
    #[arg(long, default_value = "/usr/share/sealant/vm/kernel")]
    kernel: PathBuf,
    #[arg(long, default_value = "2")]
    vcpus: u32,
    #[arg(long, default_value = "2048")]
    memory_mib: u64,
    /// The guest's MAC; a random locally administered one by default.
    #[arg(long, value_parser = sealant_vm_runner::net::parse_mac)]
    mac: Option<String>,
    /// `/dev/kvm`'s group, when `stat` inside the container does not show the host's.
    #[arg(long)]
    kvm_gid: Option<u32>,
    /// How long the guest has to power off after SIGTERM before the VMM is killed.
    #[arg(long, default_value = "20")]
    shutdown_grace_secs: u64,

    #[arg(long, default_value = "/var/lib/sealant/images")]
    images_dir: PathBuf,
    #[arg(long, default_value = "/var/lib/sealant/data")]
    data_dir: PathBuf,
    /// The `mend-control` subpath: staged launch files and Mend's sockets.
    #[arg(long, default_value = "/run/sealant")]
    sealant_run_dir: PathBuf,
    /// The runner's tmpfs for the VMM's sockets.
    #[arg(long, default_value = "/run/vm")]
    vm_run_dir: PathBuf,
    #[arg(long, default_value = "/dev/kvm")]
    kvm: PathBuf,
    #[arg(long, default_value = "/dev/net/tun")]
    tun: PathBuf,
    #[arg(long, default_value = "/usr/sbin/nft")]
    nft: String,
    #[arg(long, default_value = "/usr/local/bin/cloud-hypervisor")]
    cloud_hypervisor: PathBuf,
}

fn main() -> ExitCode {
    tracing_subscriber::fmt()
        .with_writer(std::io::stderr)
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .init();
    let args = Args::parse();

    if args.self_test {
        let report = selftest::run(&selftest::Probes {
            kvm: args.kvm.clone(),
            tun: args.tun.clone(),
            nft: args.nft.clone(),
            cloud_hypervisor: args.cloud_hypervisor.clone(),
        });
        match serde_json::to_string(&report) {
            Ok(json) => println!("{json}"),
            Err(e) => {
                tracing::error!("cannot encode the report: {e}");
                return ExitCode::from(EXIT_SETUP_FAILED);
            }
        }
        return if report.ok {
            ExitCode::SUCCESS
        } else {
            ExitCode::from(EXIT_SETUP_FAILED)
        };
    }

    match setup(&args).and_then(|ready| run(&args, ready)) {
        Ok(code) => ExitCode::from(code),
        Err(e) => {
            tracing::error!("{e}");
            ExitCode::from(EXIT_SETUP_FAILED)
        }
    }
}

/// What the privileged phase hands the unprivileged one.
struct Ready {
    tap: Tap,
    mac: String,
    kvm_gid: u32,
    policy: Policy,
    digest: String,
    upstreams: Option<Upstreams>,
}

/// The privileged phase, on the only thread: tap0, nftables, the drop, and its proof.
fn setup(args: &Args) -> Result<Ready, Error> {
    let digest = args
        .image_digest
        .clone()
        .ok_or("--image-digest is required")?;
    validate_digest(&digest)?;
    let upstreams = match (args.mode, args.proxy_ip) {
        (BootMode::Normal, Some(ip)) => Some(Upstreams::new(ip)),
        (BootMode::Normal, None) => return Err("--proxy-ip is required in normal mode".into()),
        (BootMode::Recover, _) => None,
    };
    let policy = Policy {
        mode: args.mode,
        egress: match args.egress {
            EgressMode::Standard => Egress::Standard,
            EgressMode::Restricted => Egress::Restricted {
                extra_tcp_ports: args.allow_tcp_ports.clone(),
            },
        },
    };
    let kvm_gid = match args.kvm_gid {
        Some(gid) => jail::validate_kvm_gid(gid)?,
        None => jail::kvm_gid(&args.kvm)?,
    };
    let mac = match &args.mac {
        Some(mac) => mac.clone(),
        None => sealant_vm_runner::net::random_guest_mac()?,
    };

    let tap = tap::create(&args.tun, TAP_NAME, HOST_IP, PREFIX_LEN, MTU)
        .map_err(|e| format!("creating {TAP_NAME}: {e}"))?;
    nft::apply(&args.nft, &nft::script(&policy))
        .map_err(|e| format!("installing the nftables ruleset: {e}"))?;
    tracing::info!(
        mode = args.mode.as_str(),
        egress = ?policy.egress,
        "{TAP_NAME} up at {HOST_IP}/{PREFIX_LEN}, nftables table {} installed",
        nft::TABLE
    );

    raise_nofile();
    jail::drop_privileges(kvm_gid)?;
    let status = jail::verify(Path::new("/proc/self/status"), kvm_gid)?;
    tracing::info!(
        uid = status.uid[0],
        gid = status.gid[0],
        groups = ?status.groups,
        "privileges dropped: no capabilities, no-new-privileges"
    );
    Ok(Ready {
        tap,
        mac,
        kvm_gid,
        policy,
        digest,
        upstreams,
    })
}

/// Raises the soft `RLIMIT_NOFILE` to the hard limit, up to [`NOFILE_TARGET`]. Best effort: the
/// runner works at the default, it only accepts fewer connections at once.
fn raise_nofile() {
    use nix::sys::resource::{Resource, getrlimit, setrlimit};
    match getrlimit(Resource::RLIMIT_NOFILE) {
        Ok((soft, hard)) => {
            let target = hard.min(NOFILE_TARGET);
            if soft < target
                && let Err(e) = setrlimit(Resource::RLIMIT_NOFILE, target, hard)
            {
                tracing::warn!("could not raise RLIMIT_NOFILE to {target}: {e}");
            }
        }
        Err(e) => tracing::warn!("could not read RLIMIT_NOFILE: {e}"),
    }
}

/// A digest names files in the images directory: no path separators, no leading dot.
fn validate_digest(digest: &str) -> Result<(), Error> {
    let ok = !digest.is_empty()
        && !digest.starts_with('.')
        && digest
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, ':' | '-' | '_' | '.'));
    if ok {
        Ok(())
    } else {
        Err(format!("--image-digest {digest:?} is not a digest").into())
    }
}

/// The unprivileged phase: load the boot config, start the forwarders and vsock bridges, run the
/// VMM, and answer the runner's exit code.
fn run(args: &Args, ready: Ready) -> Result<u8, Error> {
    let files = StagedFiles::new(
        &args.sealant_run_dir,
        &args.images_dir,
        &ready.digest,
        args.mode,
    );
    let boot = protocol::load_boot_config(
        &files,
        args.mode,
        Some(GuestNetworkConfig::for_mac(&ready.mac)),
    )?;
    tracing::info!(?boot, "boot config loaded");
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()?;
    runtime.block_on(serve(args, ready, boot))
}

async fn serve(args: &Args, ready: Ready, boot: VmBootConfig) -> Result<u8, Error> {
    if let Some(upstreams) = ready.upstreams {
        start_forwarders(&ready.policy, upstreams).await?;
    }

    let mux = Mux::new(args.vm_run_dir.join("vsock.sock"));
    let api_socket = args.vm_run_dir.join("ch-api.sock");
    for stale in [mux.socket(), api_socket.as_path()] {
        match std::fs::remove_file(stale) {
            Ok(()) => {}
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(e) => return Err(format!("removing stale {}: {e}", stale.display()).into()),
        }
    }

    let control = vsock::bind_unix(&args.sealant_run_dir.join("control.sock"), 0o660)?;
    spawn_logged(
        "control bridge (vsock:1024)",
        vsock::serve_host_to_guest(control, mux.clone(), vsock::CONTROL_PORT),
    );
    let capture = vsock::bind_unix(&mux.guest_listener_path(vsock::CAPTURE_PORT), 0o600)?;
    spawn_logged(
        "capture bridge (vsock:1025)",
        vsock::serve_guest_to_host(capture, args.sealant_run_dir.join("capture.sock")),
    );
    let exits = ExitRecorder::default();
    let (shutdown, shutdown_rx) = tokio::sync::watch::channel(false);
    let boot_path = mux.guest_listener_path(vsock::BOOT_PORT);
    let boot_listener = vsock::bind_unix(&boot_path, 0o600)?;
    let boot_channel = tokio::spawn(vsock::serve_boot(
        boot_listener,
        boot_path,
        boot.to_frame()?,
        exits.clone(),
        shutdown_rx,
    ));
    // Recovery has no session channel at all: nothing listens on 1027.
    if args.mode == BootMode::Normal {
        let session = vsock::bind_unix(&mux.guest_listener_path(vsock::SESSION_PORT), 0o600)?;
        spawn_logged(
            "session bridge (vsock:1027)",
            vsock::serve_guest_to_host(session, args.sealant_run_dir.join("session.sock")),
        );
    }

    let base_image = args.images_dir.join(format!("{}.img", ready.digest));
    let spec = VmmSpec {
        binary: args.cloud_hypervisor.clone(),
        kernel: args.kernel.clone(),
        arch: Arch::host(),
        mode: args.mode,
        vcpus: args.vcpus,
        memory_mib: args.memory_mib,
        net: Some(NetFd {
            fd: ready.tap.raw_fd(),
            mac: ready.mac.clone(),
        }),
        vsock_socket: mux.socket().to_owned(),
        api_socket: api_socket.clone(),
        base_image: base_image.clone(),
        data_image: args.data_dir.join("data.img"),
        // The VMM reads only this executor's base image, not its siblings.
        landlock_rules: vec![
            rule(&base_image, Access::Read),
            rule(&args.data_dir, Access::ReadWrite),
            rule(&args.vm_run_dir, Access::ReadWrite),
            rule(&args.kvm, Access::ReadWrite),
        ],
    };
    let mut child = vmm::spawn(&spec, Some(&ready.tap))?;
    // The tap descriptor now lives in the VMM; the runner's copy is no longer needed.
    drop(ready.tap);
    if let Some(pid) = child.id() {
        if let Err(e) = jail::verify(Path::new(&format!("/proc/{pid}/status")), ready.kvm_gid) {
            child.start_kill()?;
            let _ = child.wait().await;
            return Err(format!("the VMM is not jailed: {e}").into());
        }
        tracing::info!(pid, "cloud-hypervisor started");
    }
    let vmm_exit = vmm::supervise(
        &mut child,
        &api_socket,
        Duration::from_secs(args.shutdown_grace_secs),
        &shutdown,
    )
    .await?;
    // The guest's exit line is acknowledged before it powers off, so it is normally recorded
    // already; let the channel finish reading what the closed connection still holds.
    match tokio::time::timeout(BOOT_CHANNEL_DRAIN, boot_channel).await {
        Ok(Ok(Ok(()))) => {}
        Ok(Ok(Err(e))) => tracing::warn!("boot channel ended: {e}"),
        Ok(Err(e)) => tracing::warn!("boot channel task failed: {e}"),
        Err(_) => tracing::warn!(
            ?BOOT_CHANNEL_DRAIN,
            "boot channel still open after the VM ended"
        ),
    }
    let guest = exits.latest();
    let code = exit::runner_exit_code(vmm_exit, guest.as_ref());
    tracing::info!(?vmm_exit, ?guest, code, "VM ended");
    Ok(code)
}

fn rule(path: &Path, access: Access) -> LandlockRule {
    LandlockRule {
        path: path.to_owned(),
        access,
    }
}

async fn start_forwarders(policy: &Policy, upstreams: Upstreams) -> Result<(), Error> {
    for port in policy.forwarder_ports() {
        let local = SocketAddr::new(HOST_IP.into(), port);
        let listener = TcpListener::bind(local)
            .await
            .map_err(|e| format!("binding {local}: {e}"))?;
        match port {
            DNS_PORT => {
                let udp = UdpSocket::bind(local)
                    .await
                    .map_err(|e| format!("binding udp {local}: {e}"))?;
                let upstream = upstreams.addr(upstreams.dns);
                spawn_logged("dns/udp forwarder", forward::serve_dns_udp(udp, upstream));
                spawn_logged(
                    "dns/tcp forwarder",
                    forward::serve_dns_tcp(listener, upstream),
                );
            }
            HTTP_PORT | HTTPS_PORT | TCP_PORT | RESOURCE_PORT => {
                let upstream = upstreams.addr(match port {
                    HTTP_PORT => upstreams.http,
                    HTTPS_PORT => upstreams.https,
                    RESOURCE_PORT => upstreams.resources,
                    _ => upstreams.tcp,
                });
                spawn_logged(
                    "tcp forwarder",
                    forward::serve_tcp(listener, upstream, forward::original_dst),
                );
            }
            other => return Err(format!("no forwarder for port {other}").into()),
        }
    }
    Ok(())
}

/// Runs `task`; logs if it ever stops. A stopped forwarder fails closed: its traffic is refused.
fn spawn_logged<F>(name: &'static str, task: F)
where
    F: std::future::Future<Output = std::io::Result<()>> + Send + 'static,
{
    tokio::spawn(async move {
        if let Err(e) = task.await {
            tracing::error!("{name} stopped: {e}");
        }
    });
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn digests_cannot_escape_the_images_directory() {
        assert!(validate_digest("sha256:0123abcd").is_ok());
        assert!(validate_digest("sha256-0123abcd").is_ok());
        assert!(validate_digest("../etc/passwd").is_err());
        assert!(validate_digest("a/b").is_err());
        assert!(validate_digest(".hidden").is_err());
        assert!(validate_digest("").is_err());
    }

    #[test]
    fn the_cli_parses_a_restricted_launch() {
        let args = Args::try_parse_from([
            "sealant-vm-runner",
            "--egress",
            "restricted",
            "--allow-tcp-port",
            "22",
            "--allow-tcp-port",
            "5432",
            "--proxy-ip",
            "172.30.0.3",
            "--image-digest",
            "sha256:ab",
        ])
        .unwrap();
        assert_eq!(args.egress, EgressMode::Restricted);
        assert_eq!(args.allow_tcp_ports, vec![22, 5432]);
        assert_eq!(args.mode, BootMode::Normal);
        assert!(Args::try_parse_from(["sealant-vm-runner", "--mac", "01:00:00:00:00:00"]).is_err());
    }
}
