//! The traffic listeners: the explicit HTTP(S) proxy (`docker` runtime) and the four transparent
//! listeners `sealant-vm-runner` relays redirected guest connections to with a PROXY v2 header.

use std::future::Future;
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

use tokio::io::{AsyncWriteExt, ReadHalf, WriteHalf};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::Semaphore;
use tokio_rustls::TlsAcceptor;

use crate::events::Event;
use crate::http1::{HttpReader, parse_request, simple_response};
use crate::io::{Prefixed, connect_any, linger, splice};
use crate::ip::BlockReason;
use crate::policy::{Mode, Policy, split_host_port, synthetic_resource_net};
use crate::proxyproto;
use crate::session::{self, SessionSpec, to_origin_form};
use crate::state::{ConnGuard, ConnKind, ConnTags, Ingress, Shared};
use crate::tls::{HELLO_TIMEOUT, Hello, peek_client_hello};

const MAX_CONNECTIONS: usize = 4096;
const HEADER_TIMEOUT: Duration = Duration::from_secs(10);
const FIRST_HEAD_TIMEOUT: Duration = Duration::from_secs(30);

/// Accept connections and hand each to `handler`, up to a global connection cap.
pub(crate) async fn accept_loop<F, Fut>(
    listener: TcpListener,
    shared: Arc<Shared>,
    permits: Arc<Semaphore>,
    handler: F,
) where
    F: Fn(Arc<Shared>, TcpStream) -> Fut + Send + Sync + 'static,
    Fut: Future<Output = ()> + Send + 'static,
{
    loop {
        let (stream, _) = match listener.accept().await {
            Ok(x) => x,
            Err(e) => {
                tracing::debug!(error = %e, "accept");
                tokio::time::sleep(Duration::from_millis(20)).await;
                continue;
            }
        };
        let Ok(permit) = permits.clone().try_acquire_owned() else {
            drop(stream);
            continue;
        };
        let _ = stream.set_nodelay(true);
        let fut = handler(shared.clone(), stream);
        tokio::spawn(async move {
            fut.await;
            drop(permit);
        });
    }
}

pub(crate) fn connection_permits() -> Arc<Semaphore> {
    Arc::new(Semaphore::new(MAX_CONNECTIONS))
}

/// Where a decision allows a connection to go.
struct Target {
    addrs: Vec<SocketAddr>,
    /// The first validated address, recorded so a later policy can re-judge it.
    ip: Option<IpAddr>,
    /// The mirror host, when the destination is allowed only because it is a mirror.
    mirror: Option<String>,
}

fn deny(
    shared: &Shared,
    ingress: Ingress,
    host: Option<&str>,
    port: u16,
    ip: Option<IpAddr>,
    reason: &str,
) {
    shared.events.emit(Event {
        ingress: Some(ingress.as_str()),
        host: host.map(str::to_string),
        port: Some(port),
        ip: ip.map(|ip| ip.to_string()),
        reason: Some(reason.to_string()),
        ..Event::new("deny")
    });
}

fn blocked(reason: BlockReason) -> String {
    format!("blocked:{reason}")
}

/// Resolve `host` with the proxy's own DNS and keep only addresses the policy allows.
async fn resolve_host(
    shared: &Shared,
    policy: &Policy,
    host: &str,
    port: u16,
) -> Result<Target, String> {
    let mirror = policy.mirror_for(host, port).map(|m| m.host.clone());
    let ips = shared
        .resolver
        .lookup_ips(host)
        .await
        .map_err(|e| format!("resolve_failed:{e}"))?;
    let mut first_block = None;
    let mut addrs = Vec::new();
    for ip in ips {
        let verdict = if mirror.is_some() {
            policy.addresses.private_target_verdict(ip)
        } else {
            policy.addresses.verdict(ip)
        };
        match verdict {
            Ok(ip) => addrs.push(SocketAddr::new(ip, port)),
            Err(reason) => {
                first_block.get_or_insert(reason);
            }
        }
    }
    if addrs.is_empty() {
        return Err(first_block.map_or_else(|| "no_address".to_string(), blocked));
    }
    Ok(Target {
        ip: addrs.first().map(SocketAddr::ip),
        addrs,
        mirror,
    })
}

/// Validate a guest-supplied original destination (Standard only).
async fn validate_destination(
    shared: &Shared,
    policy: &Policy,
    dst: SocketAddr,
) -> Result<Target, String> {
    match policy.addresses.verdict(dst.ip()) {
        Ok(ip) => Ok(Target {
            addrs: vec![SocketAddr::new(ip, dst.port())],
            ip: Some(ip),
            mirror: None,
        }),
        Err(reason) => {
            if let Some(target) = mirror_at(shared, policy, dst).await {
                return Ok(target);
            }
            Err(blocked(reason))
        }
    }
}

/// The mirror, if any, that `dst` is: one of its resolved addresses on its port.
async fn mirror_at(shared: &Shared, policy: &Policy, dst: SocketAddr) -> Option<Target> {
    let ip = crate::ip::normalize(dst.ip()).ok()?;
    for mirror in policy.mirrors.iter().filter(|m| m.port == dst.port()) {
        let Ok(ips) = shared.resolver.lookup_ips(&mirror.host).await else {
            continue;
        };
        let matches = ips.iter().any(|candidate| {
            crate::ip::normalize(*candidate).ok() == Some(ip)
                && policy.addresses.private_target_verdict(*candidate).is_ok()
        });
        if matches {
            return Some(Target {
                addrs: vec![SocketAddr::new(ip, dst.port())],
                ip: Some(ip),
                mirror: Some(mirror.host.clone()),
            });
        }
    }
    None
}

fn tags_for(
    policy: &Policy,
    kind: ConnKind,
    host: Option<String>,
    port: u16,
    target: &Target,
) -> ConnTags {
    let mirror = target.mirror.is_some();
    let host = host.or_else(|| target.mirror.clone());
    let mut tags = ConnTags::new(policy, kind, host, port);
    tags.ip = target.ip;
    tags.mirror = mirror;
    tags
}

// ---------------------------------------------------------------------------------------------
// Explicit proxy (:8080)

pub(crate) async fn handle_explicit(shared: Arc<Shared>, stream: TcpStream) {
    let mut reader = HttpReader::new(stream, Vec::new());
    let head = match tokio::time::timeout(FIRST_HEAD_TIMEOUT, reader.read_head()).await {
        Ok(Ok(Some(head))) => head,
        _ => return,
    };
    let (mut stream, leftover) = reader.into_parts();
    let respond = |status: u16, body: &str| simple_response(status, body);
    let Ok(mut req) = parse_request(&head) else {
        let _ = stream.write_all(&respond(400, "malformed request")).await;
        return;
    };
    let Some(snapshot) = shared.snapshot() else {
        deny(&shared, Ingress::Explicit, None, 0, None, "not_initialized");
        let _ = stream
            .write_all(&respond(503, "egress proxy not initialized"))
            .await;
        linger(&mut stream).await;
        return;
    };
    let policy = snapshot.policy.clone();
    let restricted = policy.mode == Mode::Restricted;

    if req.method.eq_ignore_ascii_case("CONNECT") {
        let Some((host, Some(port))) = split_host_port(&req.target) else {
            let _ = stream
                .write_all(&respond(400, "CONNECT needs host:port"))
                .await;
            return;
        };
        if policy.host_denied(&host) || (restricted && !policy.restricted_allows(&host, port)) {
            let reason = if policy.host_denied(&host) {
                "revoked"
            } else {
                "not_allowlisted"
            };
            deny(&shared, Ingress::Explicit, Some(&host), port, None, reason);
            let _ = stream.write_all(&respond(403, reason)).await;
            linger(&mut stream).await;
            return;
        }
        let target = match resolve_host(&shared, &policy, &host, port).await {
            Ok(t) => t,
            Err(reason) => {
                deny(&shared, Ingress::Explicit, Some(&host), port, None, &reason);
                let _ = stream.write_all(&respond(403, &reason)).await;
                linger(&mut stream).await;
                return;
            }
        };
        let inspect = policy.inspects(&host);
        let kind = if inspect {
            ConnKind::Mitm
        } else {
            ConnKind::Passthrough
        };
        let tags = tags_for(&policy, kind, Some(host.clone()), port, &target);
        let secret_ids = tags.secret_ids.clone();
        let guard = match shared.admit(tags) {
            Ok(guard) => guard,
            Err(denial) => {
                deny(
                    &shared,
                    Ingress::Explicit,
                    Some(&host),
                    port,
                    target.ip,
                    denial.as_str(),
                );
                let _ = stream.write_all(&respond(403, denial.as_str())).await;
                linger(&mut stream).await;
                return;
            }
        };
        if inspect {
            if stream
                .write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n")
                .await
                .is_err()
            {
                return;
            }
            let client = Prefixed::new(leftover, stream);
            guard
                .run(mitm(
                    shared.clone(),
                    Ingress::Explicit,
                    client,
                    host,
                    port,
                    target,
                    secret_ids,
                ))
                .await;
            return;
        }
        let upstream = match connect_any(&target.addrs, shared.connect_timeout).await {
            Ok(s) => s,
            Err(e) => {
                deny(
                    &shared,
                    Ingress::Explicit,
                    Some(&host),
                    port,
                    target.ip,
                    &format!("upstream_connect:{e}"),
                );
                let _ = stream
                    .write_all(&respond(502, "upstream unavailable"))
                    .await;
                return;
            }
        };
        if stream
            .write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n")
            .await
            .is_err()
        {
            return;
        }
        shared.events.emit(Event {
            ingress: Some(Ingress::Explicit.as_str()),
            host: Some(host.clone()),
            port: Some(port),
            ip: target.ip.map(|ip| ip.to_string()),
            ..Event::new("connect")
        });
        let client = Prefixed::new(leftover, stream);
        let shared2 = shared.clone();
        guard
            .run(async move {
                passthrough_checking_sni(&shared2, client, upstream, &host, port).await;
            })
            .await;
        return;
    }

    // Plain HTTP in absolute form: `GET http://host[:port]/path HTTP/1.1`.
    let Some((authority, path_and_query)) =
        split_absolute_http(&req.target).map(|(a, p)| (a.to_string(), p.to_string()))
    else {
        let _ = stream
            .write_all(&respond(400, "expected an absolute http:// URL"))
            .await;
        return;
    };
    let Some((host, port)) = split_host_port(&authority).map(|(h, p)| (h, p.unwrap_or(80))) else {
        let _ = stream.write_all(&respond(400, "bad URL authority")).await;
        return;
    };
    if let Some(header_host) = req
        .header("host")
        .and_then(|v| std::str::from_utf8(v).ok())
        .and_then(split_host_port)
        .map(|(h, _)| h)
        && header_host != host
    {
        deny(
            &shared,
            Ingress::Explicit,
            Some(&host),
            port,
            None,
            "host_mismatch",
        );
        let _ = stream
            .write_all(&respond(400, "Host header does not match the URL"))
            .await;
        return;
    }
    if policy.host_denied(&host) || (restricted && !policy.restricted_allows(&host, port)) {
        let reason = if policy.host_denied(&host) {
            "revoked"
        } else {
            "not_allowlisted"
        };
        deny(&shared, Ingress::Explicit, Some(&host), port, None, reason);
        let _ = stream.write_all(&respond(403, reason)).await;
        linger(&mut stream).await;
        return;
    }
    let target = match resolve_host(&shared, &policy, &host, port).await {
        Ok(t) => t,
        Err(reason) => {
            deny(&shared, Ingress::Explicit, Some(&host), port, None, &reason);
            let _ = stream.write_all(&respond(403, &reason)).await;
            linger(&mut stream).await;
            return;
        }
    };
    let tags = tags_for(
        &policy,
        ConnKind::PlainHttp,
        Some(host.clone()),
        port,
        &target,
    );
    let guard = match shared.admit(tags) {
        Ok(guard) => guard,
        Err(denial) => {
            deny(
                &shared,
                Ingress::Explicit,
                Some(&host),
                port,
                target.ip,
                denial.as_str(),
            );
            let _ = stream.write_all(&respond(403, denial.as_str())).await;
            return;
        }
    };
    to_origin_form(&mut req, path_and_query);
    if req.header("host").is_none() {
        req.set("Host", authority.as_bytes());
    }
    let spec = SessionSpec {
        ingress: Ingress::Explicit,
        host,
        port,
        addrs: target.addrs,
        inspect: false,
        secret_ids: Vec::new(),
        single_request: true,
    };
    guard
        .run(session::run(
            shared.clone(),
            spec,
            stream,
            leftover,
            Some(req),
        ))
        .await;
}

fn split_absolute_http(target: &str) -> Option<(&str, &str)> {
    let rest = target
        .get(..7)
        .filter(|scheme| scheme.eq_ignore_ascii_case("http://"))
        .map(|_| &target[7..])?;
    let end = rest.find(['/', '?']).unwrap_or(rest.len());
    let (authority, path) = rest.split_at(end);
    if authority.is_empty() || authority.contains('@') {
        return None;
    }
    Some((authority, if path.is_empty() { "/" } else { path }))
}

/// Terminate client TLS for an inspected host and run the request session.
async fn mitm<S: crate::io::Stream + 'static>(
    shared: Arc<Shared>,
    ingress: Ingress,
    mut client: S,
    host: String,
    port: u16,
    target: Target,
    secret_ids: Vec<String>,
) {
    let mut buf = Vec::new();
    let hello = tokio::time::timeout(HELLO_TIMEOUT, peek_client_hello(&mut client, &mut buf)).await;
    match hello {
        Ok(Ok(Hello::Tls { sni: Some(sni) })) if sni == host => {}
        Ok(Ok(Hello::Tls { sni })) => {
            violation(
                &shared,
                ingress,
                &host,
                port,
                &format!("sni_mismatch:{}", sni.unwrap_or_default()),
            );
            return;
        }
        Ok(Ok(Hello::NotTls)) => {
            deny(&shared, ingress, Some(&host), port, target.ip, "not_tls");
            return;
        }
        _ => return,
    }
    serve_mitm(
        shared,
        ingress,
        Prefixed::new(buf, client),
        host,
        port,
        target,
        secret_ids,
    )
    .await;
}

/// Accept TLS (the ClientHello is in `client`'s prefix) and run the inspected session.
async fn serve_mitm<S: crate::io::Stream + 'static>(
    shared: Arc<Shared>,
    ingress: Ingress,
    client: S,
    host: String,
    port: u16,
    target: Target,
    secret_ids: Vec<String>,
) {
    let Some(ca) = shared.snapshot().and_then(|s| s.policy.ca.clone()) else {
        deny(&shared, ingress, Some(&host), port, None, "no_ca");
        return;
    };
    let config = match ca.server_config(&host) {
        Ok(config) => config,
        Err(e) => {
            deny(
                &shared,
                ingress,
                Some(&host),
                port,
                None,
                &format!("leaf:{e}"),
            );
            return;
        }
    };
    let tls =
        match tokio::time::timeout(HELLO_TIMEOUT, TlsAcceptor::from(config).accept(client)).await {
            Ok(Ok(tls)) => tls,
            _ => return,
        };
    let spec = SessionSpec {
        ingress,
        host,
        port,
        addrs: target.addrs,
        inspect: true,
        secret_ids,
        single_request: false,
    };
    session::run(shared, spec, tls, Vec::new(), None).await;
}

fn violation(shared: &Shared, ingress: Ingress, host: &str, port: u16, reason: &str) {
    shared.events.emit(Event {
        ingress: Some(ingress.as_str()),
        host: Some(host.to_string()),
        port: Some(port),
        reason: Some(reason.to_string()),
        ..Event::new("violation")
    });
}

/// Splice a CONNECT tunnel, checking a TLS ClientHello's SNI against the CONNECT host as it
/// passes. Server-first protocols are not held up: upstream bytes flow from the start.
async fn passthrough_checking_sni<C>(
    shared: &Shared,
    client: C,
    upstream: TcpStream,
    host: &str,
    port: u16,
) where
    C: crate::io::Stream,
{
    let (mut cr, mut cw): (ReadHalf<C>, WriteHalf<C>) = tokio::io::split(client);
    let (mut ur, mut uw) = tokio::io::split(upstream);
    let forward = async {
        let mut buf = Vec::new();
        match peek_client_hello(&mut cr, &mut buf).await {
            Ok(Hello::Tls { sni: Some(sni) }) if sni != host => {
                violation(
                    shared,
                    Ingress::Explicit,
                    host,
                    port,
                    &format!("sni_mismatch:{sni}"),
                );
                return Err(std::io::Error::other("sni mismatch"));
            }
            Ok(_) => {}
            Err(e) => return Err(e),
        }
        uw.write_all(&buf).await?;
        tokio::io::copy(&mut cr, &mut uw).await?;
        uw.shutdown().await
    };
    let backward = async {
        tokio::io::copy(&mut ur, &mut cw).await?;
        cw.shutdown().await
    };
    let _ = tokio::try_join!(forward, backward);
}

// ---------------------------------------------------------------------------------------------
// Transparent listeners (PROXY protocol v2 from sealant-vm-runner)

async fn read_proxy_header(stream: &mut TcpStream) -> Option<SocketAddr> {
    match tokio::time::timeout(HEADER_TIMEOUT, proxyproto::read_header(stream)).await {
        Ok(Ok(header)) => Some(header.destination),
        _ => None,
    }
}

/// Admit, dial and splice a raw connection whose first bytes are already in `prefix`.
async fn admit_and_splice(
    shared: &Arc<Shared>,
    ingress: Ingress,
    tags: ConnTags,
    target: &Target,
    stream: TcpStream,
    prefix: Vec<u8>,
) {
    let host = tags.host.clone();
    let port = tags.port;
    let guard: ConnGuard = match shared.admit(tags) {
        Ok(guard) => guard,
        Err(denial) => {
            deny(
                shared,
                ingress,
                host.as_deref(),
                port,
                target.ip,
                denial.as_str(),
            );
            return;
        }
    };
    let addrs = target.addrs.clone();
    let shared2 = shared.clone();
    guard
        .run(async move {
            let mut upstream = match connect_any(&addrs, shared2.connect_timeout).await {
                Ok(s) => s,
                Err(e) => {
                    deny(
                        &shared2,
                        ingress,
                        host.as_deref(),
                        port,
                        addrs.first().map(SocketAddr::ip),
                        &format!("upstream_connect:{e}"),
                    );
                    return;
                }
            };
            shared2.events.emit(Event {
                ingress: Some(ingress.as_str()),
                host: host.clone(),
                port: Some(port),
                ip: addrs.first().map(|a| a.ip().to_string()),
                ..Event::new("connect")
            });
            if !prefix.is_empty() && upstream.write_all(&prefix).await.is_err() {
                return;
            }
            let _ = splice(stream, upstream).await;
        })
        .await;
}

pub(crate) async fn handle_transparent_http(shared: Arc<Shared>, mut stream: TcpStream) {
    let ingress = Ingress::TransparentHttp;
    let Some(dst) = read_proxy_header(&mut stream).await else {
        return;
    };
    let Some(snapshot) = shared.snapshot() else {
        deny(
            &shared,
            ingress,
            None,
            dst.port(),
            Some(dst.ip()),
            "not_initialized",
        );
        return;
    };
    let mut reader = HttpReader::new(stream, Vec::new());
    let head = match tokio::time::timeout(FIRST_HEAD_TIMEOUT, reader.read_head()).await {
        Ok(Ok(Some(head))) => head,
        _ => return,
    };
    let (mut stream, leftover) = reader.into_parts();
    let Ok(req) = parse_request(&head) else {
        let _ = stream
            .write_all(&simple_response(400, "malformed request"))
            .await;
        return;
    };
    let policy = snapshot.policy.clone();
    let host = req
        .header("host")
        .and_then(|v| std::str::from_utf8(v).ok())
        .and_then(split_host_port)
        .map(|(h, _)| h);
    let port = dst.port();
    let decision = match (&host, policy.mode) {
        (Some(h), _) if policy.host_denied(h) => Err("revoked".to_string()),
        (Some(h), Mode::Restricted) if policy.restricted_allows(h, port) => {
            resolve_host(&shared, &policy, h, port).await
        }
        (_, Mode::Restricted) => Err("not_allowlisted".to_string()),
        (_, Mode::Standard) => validate_destination(&shared, &policy, dst).await,
    };
    let target = match decision {
        Ok(t) => t,
        Err(reason) => {
            deny(
                &shared,
                ingress,
                host.as_deref(),
                port,
                Some(dst.ip()),
                &reason,
            );
            let _ = stream.write_all(&simple_response(403, &reason)).await;
            linger(&mut stream).await;
            return;
        }
    };
    let tags = tags_for(&policy, ConnKind::PlainHttp, host.clone(), port, &target);
    let guard = match shared.admit(tags) {
        Ok(guard) => guard,
        Err(denial) => {
            deny(
                &shared,
                ingress,
                host.as_deref(),
                port,
                target.ip,
                denial.as_str(),
            );
            let _ = stream
                .write_all(&simple_response(403, denial.as_str()))
                .await;
            return;
        }
    };
    let spec = SessionSpec {
        ingress,
        host: host.unwrap_or_else(|| dst.ip().to_string()),
        port,
        addrs: target.addrs,
        inspect: false,
        secret_ids: Vec::new(),
        single_request: true,
    };
    guard
        .run(session::run(
            shared.clone(),
            spec,
            stream,
            leftover,
            Some(req),
        ))
        .await;
}

pub(crate) async fn handle_transparent_https(shared: Arc<Shared>, mut stream: TcpStream) {
    let ingress = Ingress::TransparentHttps;
    let Some(dst) = read_proxy_header(&mut stream).await else {
        return;
    };
    let port = dst.port();
    if shared.snapshot().is_none() {
        deny(
            &shared,
            ingress,
            None,
            port,
            Some(dst.ip()),
            "not_initialized",
        );
        return;
    }
    let mut buf = Vec::new();
    let sni =
        match tokio::time::timeout(HELLO_TIMEOUT, peek_client_hello(&mut stream, &mut buf)).await {
            Ok(Ok(Hello::Tls { sni })) => sni,
            Ok(Ok(Hello::NotTls)) => {
                deny(&shared, ingress, None, port, Some(dst.ip()), "not_tls");
                return;
            }
            _ => return,
        };
    // Re-read the policy after the (possibly slow) ClientHello.
    let Some(snapshot) = shared.snapshot() else {
        return;
    };
    let policy = snapshot.policy.clone();
    let restricted = policy.mode == Mode::Restricted;
    if let Some(host) = &sni
        && policy.host_denied(host)
    {
        deny(
            &shared,
            ingress,
            Some(host),
            port,
            Some(dst.ip()),
            "revoked",
        );
        return;
    }
    if restricted
        && !sni
            .as_deref()
            .is_some_and(|h| policy.restricted_allows(h, port))
    {
        let reason = if sni.is_some() {
            "not_allowlisted"
        } else {
            "no_sni"
        };
        deny(
            &shared,
            ingress,
            sni.as_deref(),
            port,
            Some(dst.ip()),
            reason,
        );
        return;
    }
    if let Some(host) = sni.clone().filter(|h| policy.inspects(h)) {
        // Inspected: the proxy's own DNS decides the destination, never the guest's address.
        let target = match resolve_host(&shared, &policy, &host, port).await {
            Ok(t) => t,
            Err(reason) => {
                deny(&shared, ingress, Some(&host), port, None, &reason);
                return;
            }
        };
        let tags = tags_for(&policy, ConnKind::Mitm, Some(host.clone()), port, &target);
        let secret_ids = tags.secret_ids.clone();
        let guard = match shared.admit(tags) {
            Ok(guard) => guard,
            Err(denial) => {
                deny(
                    &shared,
                    ingress,
                    Some(&host),
                    port,
                    target.ip,
                    denial.as_str(),
                );
                return;
            }
        };
        let client = Prefixed::new(buf, stream);
        guard
            .run(serve_mitm(
                shared.clone(),
                ingress,
                client,
                host,
                port,
                target,
                secret_ids,
            ))
            .await;
        return;
    }
    let decision = match (&sni, restricted) {
        (Some(host), true) => resolve_host(&shared, &policy, host, port).await,
        _ => validate_destination(&shared, &policy, dst).await,
    };
    let target = match decision {
        Ok(t) => t,
        Err(reason) => {
            deny(
                &shared,
                ingress,
                sni.as_deref(),
                port,
                Some(dst.ip()),
                &reason,
            );
            return;
        }
    };
    let tags = tags_for(&policy, ConnKind::Passthrough, sni, port, &target);
    admit_and_splice(&shared, ingress, tags, &target, stream, buf).await;
}

pub(crate) async fn handle_transparent_tcp(shared: Arc<Shared>, mut stream: TcpStream) {
    let ingress = Ingress::TransparentTcp;
    let Some(dst) = read_proxy_header(&mut stream).await else {
        return;
    };
    let port = dst.port();
    let Some(snapshot) = shared.snapshot() else {
        deny(
            &shared,
            ingress,
            None,
            port,
            Some(dst.ip()),
            "not_initialized",
        );
        return;
    };
    let policy = snapshot.policy.clone();
    let (host, target) = match policy.mode {
        Mode::Standard => match validate_destination(&shared, &policy, dst).await {
            Ok(target) => (None, target),
            Err(reason) => {
                deny(&shared, ingress, None, port, Some(dst.ip()), &reason);
                return;
            }
        },
        Mode::Restricted => match restricted_tcp_rule(&shared, &policy, dst).await {
            Some(found) => found,
            None => {
                deny(
                    &shared,
                    ingress,
                    None,
                    port,
                    Some(dst.ip()),
                    "not_allowlisted",
                );
                return;
            }
        },
    };
    let tags = tags_for(&policy, ConnKind::RawTcp, host, port, &target);
    admit_and_splice(&shared, ingress, tags, &target, stream, Vec::new()).await;
}

/// Under Restricted egress, raw TCP is allowed only to an allowlisted host on one of its ports
/// (the address must be one the proxy itself resolved for it) or to a mirror.
async fn restricted_tcp_rule(
    shared: &Shared,
    policy: &Policy,
    dst: SocketAddr,
) -> Option<(Option<String>, Target)> {
    let ip = crate::ip::normalize(dst.ip()).ok()?;
    for rule in policy
        .allow_hosts
        .iter()
        .filter(|h| h.ports.contains(&dst.port()) && !policy.host_denied(&h.host))
    {
        let Ok(ips) = shared.resolver.lookup_ips(&rule.host).await else {
            continue;
        };
        let resolved = ips
            .iter()
            .any(|c| crate::ip::normalize(*c).ok() == Some(ip));
        if resolved && policy.addresses.verdict(ip).is_ok() {
            let target = Target {
                addrs: vec![SocketAddr::new(ip, dst.port())],
                ip: Some(ip),
                mirror: None,
            };
            return Some((Some(rule.host.clone()), target));
        }
    }
    mirror_at(shared, policy, dst).await.map(|t| (None, t))
}

pub(crate) async fn handle_transparent_resource(shared: Arc<Shared>, mut stream: TcpStream) {
    let ingress = Ingress::TransparentResource;
    let Some(dst) = read_proxy_header(&mut stream).await else {
        return;
    };
    let port = dst.port();
    let Some(snapshot) = shared.snapshot() else {
        deny(
            &shared,
            ingress,
            None,
            port,
            Some(dst.ip()),
            "not_initialized",
        );
        return;
    };
    let policy = snapshot.policy.clone();
    let guest_ip = match crate::ip::normalize(dst.ip()) {
        Ok(IpAddr::V4(v4)) if synthetic_resource_net().contains(IpAddr::V4(v4)) => v4,
        _ => {
            deny(
                &shared,
                ingress,
                None,
                port,
                Some(dst.ip()),
                "not_a_resource_address",
            );
            return;
        }
    };
    let Some(resource) = policy.resource_at(guest_ip, port).cloned() else {
        deny(
            &shared,
            ingress,
            None,
            port,
            Some(dst.ip()),
            "no_such_resource",
        );
        return;
    };
    let ips = match shared.resolver.lookup_ips(&resource.host).await {
        Ok(ips) => ips,
        Err(e) => {
            deny(
                &shared,
                ingress,
                Some(&resource.name),
                port,
                None,
                &format!("resolve_failed:{e}"),
            );
            return;
        }
    };
    let addrs: Vec<SocketAddr> = ips
        .into_iter()
        .filter_map(|ip| policy.addresses.private_target_verdict(ip).ok())
        .map(|ip| SocketAddr::new(ip, resource.port))
        .collect();
    if addrs.is_empty() {
        deny(
            &shared,
            ingress,
            Some(&resource.name),
            port,
            None,
            "no_address",
        );
        return;
    }
    let target = Target {
        ip: addrs.first().map(SocketAddr::ip),
        addrs,
        mirror: None,
    };
    let mut tags = ConnTags::new(
        &policy,
        ConnKind::Resource,
        Some(resource.name.clone()),
        port,
    );
    tags.ip = target.ip;
    admit_and_splice(&shared, ingress, tags, &target, stream, Vec::new()).await;
}
