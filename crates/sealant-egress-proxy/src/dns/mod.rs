//! The validating DNS server the workspace resolves through (UDP and TCP).
//!
//! - Worktree resources are answered here with their synthetic `10.201.0.x` address (A only).
//! - Mirrors are answered with the mirror's address on the attached network.
//! - `Standard`: A/AAAA/SRV/TXT (and CNAME/MX) go upstream; blocked addresses are filtered out of
//!   A/AAAA answers. ANY and other types are refused.
//! - `Restricted egress`: only A/AAAA, only for exactly allowlisted names; everything else is
//!   refused without ever reaching upstream, so a name cannot carry data out.

pub(crate) mod resolver;
pub(crate) mod wire;

use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream, UdpSocket};
use tokio::sync::Semaphore;

use crate::events::Event;
use crate::policy::{Mode, Policy};
use crate::state::{Ingress, Shared};
use wire::{
    CLASS_IN, EDNS_UDP_SIZE, Question, RCODE_FORMERR, RCODE_NOERROR, RCODE_NOTIMP, RCODE_NXDOMAIN,
    RCODE_REFUSED, RCODE_SERVFAIL, RData, Record, Reply, TYPE_A, TYPE_AAAA, TYPE_CNAME, TYPE_HTTPS,
    TYPE_MX, TYPE_SRV, TYPE_SVCB, TYPE_TXT,
};

const RESOURCE_TTL: u32 = 5;
const MAX_INFLIGHT: usize = 512;
const TCP_IDLE: Duration = Duration::from_secs(10);

pub(crate) async fn serve_udp(shared: Arc<Shared>, socket: UdpSocket) {
    let socket = Arc::new(socket);
    let permits = Arc::new(Semaphore::new(MAX_INFLIGHT));
    let mut buf = vec![0u8; 4096];
    loop {
        let (n, peer) = match socket.recv_from(&mut buf).await {
            Ok(x) => x,
            Err(e) => {
                tracing::debug!(error = %e, "dns udp recv");
                continue;
            }
        };
        let Ok(permit) = permits.clone().try_acquire_owned() else {
            continue; // Overloaded: drop, the client retries.
        };
        let query = buf[..n].to_vec();
        let shared = shared.clone();
        let socket = socket.clone();
        tokio::spawn(async move {
            if let Some(reply) = answer(&shared, &query, true).await {
                let _ = socket.send_to(&reply, peer).await;
            }
            drop(permit);
        });
    }
}

pub(crate) async fn serve_tcp(shared: Arc<Shared>, listener: TcpListener) {
    let permits = Arc::new(Semaphore::new(MAX_INFLIGHT));
    loop {
        let Ok((stream, _)) = listener.accept().await else {
            continue;
        };
        let Ok(permit) = permits.clone().try_acquire_owned() else {
            continue;
        };
        let shared = shared.clone();
        tokio::spawn(async move {
            let _ = serve_tcp_conn(&shared, stream).await;
            drop(permit);
        });
    }
}

async fn serve_tcp_conn(shared: &Shared, mut stream: TcpStream) -> std::io::Result<()> {
    loop {
        let Ok(len) = tokio::time::timeout(TCP_IDLE, stream.read_u16()).await else {
            return Ok(());
        };
        let len = usize::from(len?);
        let mut query = vec![0u8; len];
        tokio::time::timeout(TCP_IDLE, stream.read_exact(&mut query))
            .await
            .map_err(|_| std::io::Error::from(std::io::ErrorKind::TimedOut))??;
        let Some(reply) = answer(shared, &query, false).await else {
            return Ok(());
        };
        let mut framed = Vec::with_capacity(reply.len() + 2);
        framed.extend_from_slice(&(reply.len() as u16).to_be_bytes());
        framed.extend_from_slice(&reply);
        stream.write_all(&framed).await?;
    }
}

struct Ctx<'a> {
    id: u16,
    rd: bool,
    edns: bool,
    limit: usize,
    question: &'a Question,
}

impl Ctx<'_> {
    fn reply(&self, rcode: u8, answers: &[Record]) -> Vec<u8> {
        Reply {
            id: self.id,
            recursion_desired: self.rd,
            rcode,
            question: Some(self.question),
            answers,
            edns: self.edns,
        }
        .encode(self.limit)
    }
}

fn deny(shared: &Shared, name: Option<&str>, qtype: u16, reason: &str) {
    shared.events.emit(Event {
        ingress: Some(Ingress::Dns.as_str()),
        host: name.map(str::to_string),
        qtype: Some(qtype),
        reason: Some(reason.to_string()),
        ..Event::new("dns_denied")
    });
}

/// Answer one query. `None` means send nothing (a response, or bytes with no ID).
pub(crate) async fn answer(shared: &Shared, query: &[u8], udp: bool) -> Option<Vec<u8>> {
    let msg = match wire::parse(query) {
        Ok(msg) => msg,
        Err(_) => {
            let id = wire::peek_id(query)?;
            return Some(
                Reply {
                    id,
                    recursion_desired: false,
                    rcode: RCODE_FORMERR,
                    question: None,
                    answers: &[],
                    edns: false,
                }
                .encode(512),
            );
        }
    };
    if msg.is_response() {
        return None;
    }
    let limit = if udp {
        msg.edns_udp_size
            .map_or(512, |size| usize::from(size.min(EDNS_UDP_SIZE)))
    } else {
        usize::from(u16::MAX)
    };
    let bare = |rcode| {
        Some(
            Reply {
                id: msg.id,
                recursion_desired: msg.recursion_desired(),
                rcode,
                question: msg.questions.first(),
                answers: &[],
                edns: msg.edns_udp_size.is_some(),
            }
            .encode(limit),
        )
    };
    if msg.opcode() != 0 {
        return bare(RCODE_NOTIMP);
    }
    let [question] = msg.questions.as_slice() else {
        return bare(RCODE_FORMERR);
    };
    let ctx = Ctx {
        id: msg.id,
        rd: msg.recursion_desired(),
        edns: msg.edns_udp_size.is_some(),
        limit,
        question,
    };
    let qtype = question.qtype;
    let Some(snapshot) = shared.snapshot() else {
        deny(
            shared,
            question.name.hostname().as_deref(),
            qtype,
            "not_initialized",
        );
        return Some(ctx.reply(RCODE_REFUSED, &[]));
    };
    let policy = &snapshot.policy;
    if question.qclass != CLASS_IN {
        return Some(ctx.reply(RCODE_REFUSED, &[]));
    }
    let Some(name) = question.name.hostname() else {
        deny(shared, None, qtype, "bad_name");
        return Some(ctx.reply(RCODE_REFUSED, &[]));
    };
    let restricted = policy.mode == Mode::Restricted;
    if restricted && !snapshot.lease_ok {
        deny(shared, Some(&name), qtype, "lease_expired");
        return Some(ctx.reply(RCODE_REFUSED, &[]));
    }
    if policy.host_denied(&name) {
        deny(shared, Some(&name), qtype, "revoked");
        return Some(ctx.reply(RCODE_REFUSED, &[]));
    }

    if let Some(resource) = policy.resource_named(&name) {
        let answers = match qtype {
            TYPE_A => vec![Record {
                name: question.name.clone(),
                rtype: TYPE_A,
                class: CLASS_IN,
                ttl: RESOURCE_TTL,
                data: RData::A(resource.guest_ip),
            }],
            _ => Vec::new(),
        };
        return Some(ctx.reply(RCODE_NOERROR, &answers));
    }

    if let Some(mirror) = policy.mirror_named(&name) {
        if !matches!(qtype, TYPE_A | TYPE_AAAA) {
            return Some(ctx.reply(RCODE_NOERROR, &[]));
        }
        let host = mirror.host.clone();
        return Some(address_answer(shared, policy, &ctx, &host, true).await);
    }

    if restricted {
        if !matches!(qtype, TYPE_A | TYPE_AAAA) {
            deny(shared, Some(&name), qtype, "record_type");
            return Some(ctx.reply(RCODE_REFUSED, &[]));
        }
        if !policy.restricted_dns_name(&name) {
            deny(shared, Some(&name), qtype, "not_allowlisted");
            return Some(ctx.reply(RCODE_REFUSED, &[]));
        }
        return Some(address_answer(shared, policy, &ctx, &name, false).await);
    }

    match qtype {
        TYPE_A | TYPE_AAAA => Some(address_answer(shared, policy, &ctx, &name, false).await),
        TYPE_CNAME | TYPE_MX | TYPE_SRV | TYPE_TXT => {
            Some(forward_filtered(shared, policy, &ctx, &name).await)
        }
        // Clients fall back to A/AAAA; HTTPS records' address hints would bypass the filter.
        TYPE_HTTPS | TYPE_SVCB => Some(ctx.reply(RCODE_NOERROR, &[])),
        _ => {
            deny(shared, Some(&name), qtype, "record_type");
            Some(ctx.reply(RCODE_REFUSED, &[]))
        }
    }
}

/// Answer A/AAAA for `lookup_host` from the proxy's cache, dropping blocked addresses.
async fn address_answer(
    shared: &Shared,
    policy: &Policy,
    ctx: &Ctx<'_>,
    lookup_host: &str,
    private_ok: bool,
) -> Vec<u8> {
    let qtype = ctx.question.qtype;
    let lookup = match shared.resolver.lookup(lookup_host, qtype).await {
        Ok(lookup) => lookup,
        Err(e) => {
            tracing::debug!(host = lookup_host, error = %e, "dns lookup failed");
            return ctx.reply(RCODE_SERVFAIL, &[]);
        }
    };
    if lookup.rcode == RCODE_NXDOMAIN {
        return ctx.reply(RCODE_NXDOMAIN, &[]);
    }
    let mut answers = Vec::with_capacity(lookup.ips.len());
    let mut filtered = 0;
    for ip in lookup.ips {
        let verdict = if private_ok {
            policy.addresses.private_target_verdict(ip)
        } else {
            policy.addresses.verdict(ip)
        };
        if verdict.is_err() {
            filtered += 1;
            continue;
        }
        let data = match ip {
            IpAddr::V4(v4) => RData::A(v4),
            IpAddr::V6(v6) => RData::Aaaa(v6),
        };
        answers.push(Record {
            name: ctx.question.name.clone(),
            rtype: qtype,
            class: CLASS_IN,
            ttl: lookup.ttl,
            data,
        });
    }
    if filtered > 0 {
        deny(shared, Some(lookup_host), qtype, "blocked_address_filtered");
    }
    ctx.reply(RCODE_NOERROR, &answers)
}

/// Forward a Standard-mode SRV/TXT/CNAME/MX query and filter what comes back.
async fn forward_filtered(shared: &Shared, policy: &Policy, ctx: &Ctx<'_>, name: &str) -> Vec<u8> {
    let reply = match shared.resolver.exchange(ctx.question).await {
        Ok(reply) => reply,
        Err(e) => {
            tracing::debug!(host = name, error = %e, "dns forward failed");
            return ctx.reply(RCODE_SERVFAIL, &[]);
        }
    };
    let rcode = reply.rcode();
    if rcode != RCODE_NOERROR && rcode != RCODE_NXDOMAIN {
        return ctx.reply(RCODE_SERVFAIL, &[]);
    }
    let answers: Vec<Record> = reply
        .answers
        .into_iter()
        .filter(|r| r.class == CLASS_IN)
        .filter(|r| match &r.data {
            RData::A(ip) => policy.addresses.verdict(IpAddr::V4(*ip)).is_ok(),
            RData::Aaaa(ip) => policy.addresses.verdict(IpAddr::V6(*ip)).is_ok(),
            _ => matches!(r.rtype, TYPE_CNAME | TYPE_MX | TYPE_SRV | TYPE_TXT),
        })
        .collect();
    ctx.reply(rcode, &answers)
}

/// Bind the UDP and TCP sockets on the same address (the same port when `addr` names port 0).
pub(crate) async fn bind(addr: SocketAddr) -> std::io::Result<(UdpSocket, TcpListener)> {
    let udp = UdpSocket::bind(addr).await?;
    let tcp = TcpListener::bind(udp.local_addr()?).await?;
    Ok((udp, tcp))
}
