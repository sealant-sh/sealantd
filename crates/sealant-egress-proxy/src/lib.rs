//! `sealant-egress-proxy`: one workspace's egress guard (workspace isolation architecture §7).
//!
//! It starts closed and stays closed until Sealant loads a policy over the admin socket. Then it:
//!
//! - refuses every hard-blocked destination (loopback, link-local, cloud metadata, the Azure
//!   wireserver, NAT64, CGNAT, RFC 1918, the host's own public addresses, ...), with narrow
//!   operator, mirror and worktree-resource exceptions ([`ip`]);
//! - answers the workspace's DNS, filtering blocked addresses, and under Restricted egress answers
//!   only A/AAAA for allowlisted names;
//! - relays HTTP, HTTPS and raw TCP from the explicit proxy (`docker` runtime) and from the
//!   transparent listeners `sealant-vm-runner` feeds with PROXY v2 headers (`host-vm`);
//! - terminates TLS only for brokered and `inspectTls` hosts, and there swaps a placeholder for the
//!   real secret in exactly one configured header, after checking `SNI == Host == bindHost` and
//!   verifying the upstream against public roots;
//! - closes matching live streams, WebSockets included, before a revocation is acknowledged, and
//!   closes brokered and Restricted streams when the 120 s disconnected lease lapses.
#![cfg_attr(not(test), deny(clippy::unwrap_used, clippy::expect_used))]
#![forbid(unsafe_code)]

mod admin;
mod der;
mod dns;
mod events;
mod http1;
mod ingress;
mod io;
pub mod ip;
pub mod policy;
pub mod proxyproto;
mod session;
mod state;
pub mod tls;

use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use rustls::RootCertStore;
use tokio::net::TcpListener;
use tokio::task::JoinHandle;

pub use events::Event;

/// Where the proxy listens and what it trusts.
#[derive(Debug, Clone)]
pub struct ProxyConfig {
    pub admin_socket: PathBuf,
    /// Explicit HTTP(S) proxy (`HTTP(S)_PROXY`), `:8080` in the image.
    pub explicit_http: Option<SocketAddr>,
    /// Transparent HTTP from the runner, `:15080`.
    pub transparent_http: Option<SocketAddr>,
    /// Transparent HTTPS from the runner, `:15443`.
    pub transparent_https: Option<SocketAddr>,
    /// Transparent general TCP from the runner, `:15444`.
    pub transparent_tcp: Option<SocketAddr>,
    /// Transparent worktree-resource TCP (`10.201.0.0/16`) from the runner, `:15100`.
    pub transparent_resource: Option<SocketAddr>,
    /// The validating DNS server (UDP and TCP), `:53`.
    pub dns: Option<SocketAddr>,
    /// The resolver the proxy asks (Docker's embedded DNS in the container).
    pub upstream_dns: SocketAddr,
    /// The roots brokered and inspected upstreams must chain to. Never the executor CA.
    pub upstream_roots: Arc<RootCertStore>,
    pub connect_timeout: Duration,
}

impl ProxyConfig {
    /// Every listener off, public roots, a 10 s connect timeout.
    pub fn new(admin_socket: impl Into<PathBuf>, upstream_dns: SocketAddr) -> Self {
        Self {
            admin_socket: admin_socket.into(),
            explicit_http: None,
            transparent_http: None,
            transparent_https: None,
            transparent_tcp: None,
            transparent_resource: None,
            dns: None,
            upstream_dns,
            upstream_roots: Arc::new(tls::public_roots()),
            connect_timeout: Duration::from_secs(10),
        }
    }
}

/// The addresses the running proxy bound (useful when a config asked for port 0).
#[derive(Debug, Clone, Default)]
pub struct BoundAddrs {
    pub explicit_http: Option<SocketAddr>,
    pub transparent_http: Option<SocketAddr>,
    pub transparent_https: Option<SocketAddr>,
    pub transparent_tcp: Option<SocketAddr>,
    pub transparent_resource: Option<SocketAddr>,
    pub dns: Option<SocketAddr>,
}

#[derive(Debug, thiserror::Error)]
pub enum StartError {
    #[error("bind {what}: {source}")]
    Bind {
        what: &'static str,
        source: std::io::Error,
    },
    #[error("upstream TLS config: {0}")]
    Tls(#[from] rustls::Error),
}

/// A running proxy. Dropping it stops every listener.
#[derive(Debug)]
pub struct RunningProxy {
    pub addrs: BoundAddrs,
    tasks: Vec<JoinHandle<()>>,
}

impl RunningProxy {
    /// Wait until a task ends (they run forever unless the runtime shuts down).
    pub async fn wait(mut self) {
        if let Some(task) = self.tasks.pop() {
            let _ = task.await;
        }
    }
}

impl Drop for RunningProxy {
    fn drop(&mut self) {
        for task in &self.tasks {
            task.abort();
        }
    }
}

const LEASE_TICK: Duration = Duration::from_millis(100);

/// Bind every configured listener and start serving. Traffic is refused until a policy loads.
pub async fn start(config: ProxyConfig) -> Result<RunningProxy, StartError> {
    let upstream_tls = tls::upstream_client_config(config.upstream_roots.clone())?;
    let shared = Arc::new(state::Shared::new(
        dns::resolver::Resolver::new(config.upstream_dns),
        upstream_tls,
        config.upstream_roots.clone(),
        config.connect_timeout,
    ));
    let mut tasks = Vec::new();
    let mut addrs = BoundAddrs::default();

    let admin = admin::bind(&config.admin_socket).map_err(|source| StartError::Bind {
        what: "admin socket",
        source,
    })?;
    tasks.push(tokio::spawn(admin::serve(shared.clone(), admin)));

    if let Some(addr) = config.dns {
        let (udp, tcp) = dns::bind(addr).await.map_err(|source| StartError::Bind {
            what: "dns",
            source,
        })?;
        addrs.dns = udp.local_addr().ok();
        tasks.push(tokio::spawn(dns::serve_udp(shared.clone(), udp)));
        tasks.push(tokio::spawn(dns::serve_tcp(shared.clone(), tcp)));
    }

    let permits = ingress::connection_permits();
    macro_rules! listen {
        ($field:ident, $what:literal, $handler:path) => {
            if let Some(addr) = config.$field {
                let listener =
                    TcpListener::bind(addr)
                        .await
                        .map_err(|source| StartError::Bind {
                            what: $what,
                            source,
                        })?;
                addrs.$field = listener.local_addr().ok();
                tasks.push(tokio::spawn(ingress::accept_loop(
                    listener,
                    shared.clone(),
                    permits.clone(),
                    $handler,
                )));
            }
        };
    }
    listen!(explicit_http, "explicit proxy", ingress::handle_explicit);
    listen!(
        transparent_http,
        "transparent http",
        ingress::handle_transparent_http
    );
    listen!(
        transparent_https,
        "transparent https",
        ingress::handle_transparent_https
    );
    listen!(
        transparent_tcp,
        "transparent tcp",
        ingress::handle_transparent_tcp
    );
    listen!(
        transparent_resource,
        "transparent resource",
        ingress::handle_transparent_resource
    );

    let lease = shared.clone();
    tasks.push(tokio::spawn(async move {
        let mut tick = tokio::time::interval(LEASE_TICK);
        tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        loop {
            tick.tick().await;
            lease.expire_lease_if_due().await;
        }
    }));

    Ok(RunningProxy { addrs, tasks })
}
