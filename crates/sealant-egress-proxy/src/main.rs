//! The `sealant-egress-proxy` binary: one per isolated workspace, as `<name>-proxy`.
#![deny(clippy::unwrap_used, clippy::expect_used)]
#![forbid(unsafe_code)]

use std::net::SocketAddr;
use std::path::PathBuf;
use std::process::ExitCode;

use clap::Parser;
use sealant_egress_proxy::{ProxyConfig, start};

#[derive(Debug, Parser)]
#[command(
    name = "sealant-egress-proxy",
    version,
    about = "Per-workspace egress guard"
)]
struct Args {
    /// Control-plane socket Sealant drives the policy through.
    #[arg(long, default_value = "/run/sealant/proxy-admin.sock")]
    admin_socket: PathBuf,
    /// Explicit HTTP(S) proxy listener (`docker` runtime).
    #[arg(long, default_value = "0.0.0.0:8080")]
    http_proxy: SocketAddr,
    /// Transparent HTTP listener (PROXY v2 from sealant-vm-runner).
    #[arg(long, default_value = "0.0.0.0:15080")]
    transparent_http: SocketAddr,
    /// Transparent HTTPS listener.
    #[arg(long, default_value = "0.0.0.0:15443")]
    transparent_https: SocketAddr,
    /// Transparent general TCP listener.
    #[arg(long, default_value = "0.0.0.0:15444")]
    transparent_tcp: SocketAddr,
    /// Transparent worktree-resource listener (10.201.0.0/16).
    #[arg(long, default_value = "0.0.0.0:15100")]
    transparent_resource: SocketAddr,
    /// Validating DNS listener, UDP and TCP. Port 53 needs
    /// `net.ipv4.ip_unprivileged_port_start=53` when running as non-root.
    #[arg(long, default_value = "0.0.0.0:53")]
    dns: SocketAddr,
    /// Upstream resolver. Defaults to the first `nameserver` in /etc/resolv.conf.
    #[arg(long)]
    upstream_dns: Option<SocketAddr>,
}

fn resolv_conf_nameserver() -> Option<SocketAddr> {
    let text = std::fs::read_to_string("/etc/resolv.conf").ok()?;
    text.lines().find_map(|line| {
        let mut parts = line.split_whitespace();
        (parts.next()? == "nameserver")
            .then(|| parts.next())
            .flatten()
            .and_then(|ip| ip.parse().ok())
            .map(|ip| SocketAddr::new(ip, 53))
    })
}

/// The release this build reports when `SENTRY_RELEASE` is unset (`sealantd@<version>`).
const RELEASE: Option<&str> = option_env!("SENTRY_RELEASE");

/// Sends the queued spans and errors when `main` returns, after its last log line.
struct Flush;

impl Drop for Flush {
    fn drop(&mut self) {
        sealant_observability::shutdown();
    }
}

#[tokio::main]
async fn main() -> ExitCode {
    sealant_observability::install(
        "sealant-egress-proxy",
        tracing_subscriber::EnvFilter::try_from_default_env()
            .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
    );
    sealant_observability::start(
        &sealant_observability::Config::from_env().with_default_release(RELEASE),
    );
    let _flush = Flush;
    let args = Args::parse();
    let Some(upstream_dns) = args.upstream_dns.or_else(resolv_conf_nameserver) else {
        tracing::error!("no upstream DNS: pass --upstream-dns or provide /etc/resolv.conf");
        return ExitCode::from(2);
    };
    let mut config = ProxyConfig::new(args.admin_socket, upstream_dns);
    config.explicit_http = Some(args.http_proxy);
    config.transparent_http = Some(args.transparent_http);
    config.transparent_https = Some(args.transparent_https);
    config.transparent_tcp = Some(args.transparent_tcp);
    config.transparent_resource = Some(args.transparent_resource);
    config.dns = Some(args.dns);
    let proxy = match start(config).await {
        Ok(proxy) => proxy,
        Err(e) => {
            tracing::error!(error = %e, "failed to start");
            return ExitCode::FAILURE;
        }
    };
    tracing::info!(addrs = ?proxy.addrs, upstream_dns = %upstream_dns, "started closed; waiting for PUT /v1/policy");
    let mut term = match tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate()) {
        Ok(s) => s,
        Err(e) => {
            tracing::error!(error = %e, "signal handler");
            return ExitCode::FAILURE;
        }
    };
    tokio::select! {
        _ = term.recv() => {}
        _ = tokio::signal::ctrl_c() => {}
        () = proxy.wait() => {}
    }
    ExitCode::SUCCESS
}
