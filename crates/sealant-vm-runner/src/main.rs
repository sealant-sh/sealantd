//! `sealant-vm-runner`: see the library docs for the sequence. Everything privileged happens in
//! [`setup`], on the only thread, before the async runtime exists.
#![cfg_attr(not(test), deny(clippy::unwrap_used, clippy::expect_used))]
#![forbid(unsafe_code)]

use std::net::{IpAddr, SocketAddr, ToSocketAddrs};
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::time::{Duration, SystemTime};

use clap::{Parser, ValueEnum};
use sealant_observability::BootTrace;
use tokio::net::{TcpListener, UdpSocket};

use sealant_vm_runner::exit::{self, EXIT_SETUP_FAILED, ExitRecorder};
use sealant_vm_runner::mac_vmd::{self, DEFAULT_MAC_MTU, MacVmdConfig};
use sealant_vm_runner::net::{
    DNS_PORT, HOST_IP, HTTP_PORT, HTTPS_PORT, MTU, PREFIX_LEN, RESOURCE_PORT, TAP_NAME, TCP_PORT,
    Upstreams,
};
use sealant_vm_runner::nft::{self, Egress, Policy, VmdOutputLock};
use sealant_vm_runner::protocol::{self, BootMode, GuestNetworkConfig, StagedFiles, VmBootConfig};
use sealant_vm_runner::tap::{self, Tap};
use sealant_vm_runner::vmm::{self, Access, Arch, LandlockRule, NetFd, VmmSpec};
use sealant_vm_runner::vsock::{self, Mux};
use sealant_vm_runner::{forward, jail, selftest};

type Error = Box<dyn std::error::Error + Send + Sync>;

/// The release this build reports when `SENTRY_RELEASE` is unset (`sealantd@<version>`).
const RELEASE: Option<&str> = option_env!("SENTRY_RELEASE");

/// Sends the queued spans and errors when `main` returns, after its last log line.
struct Flush;

impl Drop for Flush {
    fn drop(&mut self) {
        sealant_observability::shutdown();
    }
}

/// How long the boot channel may take to finish after the VMM exits.
const BOOT_CHANNEL_DRAIN: Duration = Duration::from_secs(2);
/// The descriptor ceiling the runner asks for: every forwarded connection holds two.
const NOFILE_TARGET: u64 = 65_536;

#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
enum EgressMode {
    Standard,
    Restricted,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
enum VmmBackend {
    /// Local Linux KVM Cloud Hypervisor (default).
    CloudHypervisor,
    /// Remote macOS `sealant-vmd` -> `sealant-vz-worker` over authenticated TCP Upgrade.
    MacVmd,
}

/// Runs one workspace microVM inside its host-vm container.
#[derive(Debug, Parser)]
#[command(name = "sealant-vm-runner", version)]
struct Args {
    /// Check KVM, TUN, nftables, Landlock and Cloud Hypervisor, print a JSON report, and exit.
    #[arg(long)]
    self_test: bool,

    /// Which VMM backend runs the microVM (`cloud-hypervisor` on Linux KVM, `mac-vmd` on macOS).
    #[arg(long, value_enum, default_value = "cloud-hypervisor")]
    vmm_backend: VmmBackend,

    /// `sealant-vmd` hostname (mac-vmd backend only).
    #[arg(long, default_value = "host.docker.internal")]
    vmd_host: String,
    /// `sealant-vmd` loopback port (required for `--vmm-backend mac-vmd`).
    #[arg(long)]
    vmd_port: Option<u16>,
    /// Path to the read-only `vmd-token` bearer secret (read before privilege drop).
    #[arg(long)]
    vmd_token_file: Option<PathBuf>,
    /// Container interface attached to `mend-vmd-link` locked in nftables `chain output`.
    #[arg(long)]
    vmd_interface: Option<String>,
    /// Workspace VM name under `vm/<installId>/data/<vm-name>/data.img` (mac-vmd backend).
    #[arg(long)]
    vm_name: Option<String>,
    /// Guest `eth0` / `tap0` MTU (defaults to 1500 for cloud-hypervisor, 65520 for mac-vmd).
    #[arg(long)]
    mtu: Option<u32>,

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
    let started = SystemTime::now();
    // No thread yet: the privileged phase needs to be the only one. Spans are held until `run`.
    sealant_observability::install(
        "sealant-vm-runner",
        tracing_subscriber::EnvFilter::try_from_default_env()
            .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
    );
    let _flush = Flush;
    let args = Args::parse();

    if args.self_test {
        let probes = selftest::Probes {
            kvm: args.kvm.clone(),
            tun: args.tun.clone(),
            nft: args.nft.clone(),
            cloud_hypervisor: args.cloud_hypervisor.clone(),
        };
        let report = match args.vmm_backend {
            VmmBackend::CloudHypervisor => selftest::run(&probes),
            VmmBackend::MacVmd => selftest::run_mac_vmd(&probes),
        };
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

    match setup(&args).and_then(|ready| run(&args, ready, started)) {
        Ok(code) => ExitCode::from(code),
        Err(e) => {
            tracing::error!("{e}");
            ExitCode::from(EXIT_SETUP_FAILED)
        }
    }
}

/// What the privileged phase hands the unprivileged one.
struct Ready {
    tap: Option<Tap>,
    mac: String,
    mtu: u32,
    kvm_gid: Option<u32>,
    policy: Policy,
    digest: String,
    upstreams: Option<Upstreams>,
    mac_vmd: Option<MacVmdConfig>,
    /// When the privileged phase ran.
    setup: (SystemTime, SystemTime),
}

/// The privileged phase, on the only thread: tap0, nftables, the drop, and its proof.
fn setup(args: &Args) -> Result<Ready, Error> {
    let setup_started = SystemTime::now();
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
    let mtu = args.mtu.unwrap_or(match args.vmm_backend {
        VmmBackend::CloudHypervisor => MTU,
        VmmBackend::MacVmd => DEFAULT_MAC_MTU,
    });
    let mac = match &args.mac {
        Some(mac) => mac.clone(),
        None => sealant_vm_runner::net::random_guest_mac()?,
    };

    let (kvm_gid, vmd_output, mac_vmd) = match args.vmm_backend {
        VmmBackend::CloudHypervisor => {
            let gid = match args.kvm_gid {
                Some(gid) => jail::validate_kvm_gid(gid)?,
                None => jail::kvm_gid(&args.kvm)?,
            };
            (Some(gid), None, None)
        }
        VmmBackend::MacVmd => {
            let port = args
                .vmd_port
                .ok_or("--vmd-port is required for --vmm-backend mac-vmd")?;
            let token_file = args
                .vmd_token_file
                .as_ref()
                .ok_or("--vmd-token-file is required for --vmm-backend mac-vmd")?;
            let vm_name = args
                .vm_name
                .clone()
                .ok_or("--vm-name is required for --vmm-backend mac-vmd")?;
            // Read bearer token into memory BEFORE privilege drop so the bind mount can stay 0400.
            let bearer_token = std::fs::read_to_string(token_file)
                .map_err(|e| format!("reading {}: {e}", token_file.display()))?
                .trim()
                .to_owned();
            if bearer_token.is_empty() {
                return Err("vmd-token file is empty".into());
            }
            let host_ip = resolve_vmd_host(&args.vmd_host, port)?;
            let vmd_iface = args.vmd_interface.clone().unwrap_or_else(|| {
                if args.mode == BootMode::Normal {
                    "eth1".to_owned()
                } else {
                    "eth0".to_owned()
                }
            });
            let lock = VmdOutputLock {
                interface: vmd_iface,
                host_ip,
                port,
            };
            let cfg = MacVmdConfig {
                host: args.vmd_host.clone(),
                host_ip,
                port,
                bearer_token,
                vm_name,
                mode: args.mode,
                base_image_key: digest.clone(),
                vcpus: args.vcpus,
                memory_bytes: args.memory_mib.saturating_mul(1024 * 1024),
                mac: (args.mode == BootMode::Normal).then(|| mac.clone()),
                mtu,
                sealant_run_dir: args.sealant_run_dir.clone(),
                shutdown_grace: Duration::from_secs(args.shutdown_grace_secs),
            };
            (None, Some(lock), Some(cfg))
        }
    };

    let policy = Policy {
        mode: args.mode,
        egress: match args.egress {
            EgressMode::Standard => Egress::Standard,
            EgressMode::Restricted => Egress::Restricted {
                extra_tcp_ports: args.allow_tcp_ports.clone(),
            },
        },
        vmd_output,
    };

    let tap = match (args.vmm_backend, args.mode) {
        (VmmBackend::CloudHypervisor, _) => Some(
            tap::create(&args.tun, TAP_NAME, HOST_IP, PREFIX_LEN, mtu)
                .map_err(|e| format!("creating {TAP_NAME}: {e}"))?,
        ),
        (VmmBackend::MacVmd, BootMode::Normal) => Some(
            tap::create_raw(&args.tun, TAP_NAME, HOST_IP, PREFIX_LEN, mtu)
                .map_err(|e| format!("creating {TAP_NAME}: {e}"))?,
        ),
        // Recovery on mac-vmd has zero network devices (no tap0 needed).
        (VmmBackend::MacVmd, BootMode::Recover) => None,
    };
    nft::apply(&args.nft, &nft::script(&policy))
        .map_err(|e| format!("installing the nftables ruleset: {e}"))?;
    tracing::info!(
        mode = args.mode.as_str(),
        backend = ?args.vmm_backend,
        egress = ?policy.egress,
        mtu,
        "{TAP_NAME} up at {HOST_IP}/{PREFIX_LEN}, nftables table {} installed",
        nft::TABLE
    );

    raise_nofile();
    let expected_groups: Vec<u32> = kvm_gid.into_iter().collect();
    jail::drop_privileges_with_groups(&expected_groups)?;
    let status = jail::verify_with_groups(Path::new("/proc/self/status"), &expected_groups)?;
    tracing::info!(
        uid = status.uid[0],
        gid = status.gid[0],
        groups = ?status.groups,
        "privileges dropped: no capabilities, no-new-privileges"
    );
    Ok(Ready {
        tap,
        mac,
        mtu,
        kvm_gid,
        policy,
        digest,
        upstreams,
        mac_vmd,
        setup: (setup_started, SystemTime::now()),
    })
}

fn resolve_vmd_host(host: &str, port: u16) -> Result<IpAddr, Error> {
    if let Ok(ip) = host.parse::<IpAddr>() {
        return Ok(ip);
    }
    let mut addrs = (host, port)
        .to_socket_addrs()
        .map_err(|e| format!("resolving --vmd-host {host:?}: {e}"))?;
    // Prefer IPv4 when both v4 and v6 are returned (OrbStack/Docker Desktop both resolve v4).
    let mut first = None;
    for addr in &mut addrs {
        if addr.ip().is_ipv4() {
            return Ok(addr.ip());
        }
        first.get_or_insert(addr.ip());
    }
    first.ok_or_else(|| format!("--vmd-host {host:?} resolved to no addresses").into())
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
fn run(args: &Args, ready: Ready, started: SystemTime) -> Result<u8, Error> {
    // Privileges are dropped: the exporter's and Sentry's threads may start.
    sealant_observability::start(
        &sealant_observability::Config::from_env().with_default_release(RELEASE),
    );
    let files = StagedFiles::new(
        &args.sealant_run_dir,
        &args.images_dir,
        &ready.digest,
        args.mode,
    );
    let loading = SystemTime::now();
    let mut boot = protocol::load_boot_config(
        &files,
        args.mode,
        Some(GuestNetworkConfig::for_mac_with_mtu(&ready.mac, ready.mtu)),
    )?;
    // The launch, under the launcher's span; the guest's boot, under the launch.
    let staged = boot.telemetry.take().unwrap_or_default();
    let launch = BootTrace::begin(
        sealant_observability::VM_LAUNCH,
        started,
        staged
            .traceparent
            .as_deref()
            .map(|parent| (parent, staged.tracestate.as_deref().unwrap_or_default())),
    );
    if let Some(launch) = &launch {
        launch.stage("setup", ready.setup.0, ready.setup.1);
        launch.stage("boot_config", loading, SystemTime::now());
    }
    boot.telemetry = Some(staged.for_guest(
        launch.as_ref().and_then(BootTrace::traceparent),
        |key| std::env::var(key).ok(),
        RELEASE,
    ));
    tracing::info!(?boot, "boot config loaded");
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()?;
    runtime.block_on(serve(args, ready, boot, launch))
}

async fn serve(
    args: &Args,
    ready: Ready,
    boot: VmBootConfig,
    launch: Option<BootTrace>,
) -> Result<u8, Error> {
    if let Some(upstreams) = ready.upstreams {
        start_forwarders(&ready.policy, upstreams).await?;
    }

    if let Some(mac_cfg) = ready.mac_vmd {
        let exits = ExitRecorder::default();
        if let Some(launch) = &launch {
            launch.reached("vmm_started");
            launch.end(true);
        }
        let vmm_exit =
            mac_vmd::run_vm(&mac_cfg, ready.tap, boot.to_frame()?, exits.clone()).await?;
        let guest = exits.latest();
        let code = exit::runner_exit_code(vmm_exit, guest.as_ref());
        tracing::info!(?vmm_exit, ?guest, code, "mac-vmd VM ended");
        return Ok(code);
    }

    let tap = ready.tap.ok_or("missing tap0 for cloud-hypervisor")?;
    let kvm_gid = ready
        .kvm_gid
        .ok_or("missing kvm_gid for cloud-hypervisor")?;

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
            fd: tap.raw_fd(),
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
    let mut child = vmm::spawn(&spec, Some(&tap))?;
    // The tap descriptor now lives in the VMM; the runner's copy is no longer needed.
    drop(tap);
    if let Some(pid) = child.id() {
        if let Err(e) = jail::verify(Path::new(&format!("/proc/{pid}/status")), kvm_gid) {
            child.start_kill()?;
            let _ = child.wait().await;
            if let Some(launch) = &launch {
                launch.end(false);
            }
            return Err(format!("the VMM is not jailed: {e}").into());
        }
        tracing::info!(pid, "cloud-hypervisor started");
    }
    // Launched: the guest's boot carries on in its own trace span, under this one.
    if let Some(launch) = &launch {
        launch.reached("vmm_started");
        launch.end(true);
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
