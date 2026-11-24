//! The proxy's own resolver: it asks the upstream server, caches what it learns, and is the only
//! source of addresses the proxy connects to by name.
//!
//! Guest DNS answers for A/AAAA come from the same cache, so the address a guest was given is the
//! address the proxy later validates and dials: a name cannot rebind between the two lookups.

use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
use std::sync::Mutex;
use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpStream, UdpSocket};
use tokio::time::{Instant, timeout};

use super::wire::{
    self, CLASS_IN, Message, Name, Question, RCODE_NOERROR, RCODE_NXDOMAIN, RData, TYPE_A,
    TYPE_AAAA,
};

const UDP_TIMEOUT: Duration = Duration::from_secs(2);
const TCP_TIMEOUT: Duration = Duration::from_secs(5);
const MIN_TTL: u32 = 5;
const MAX_TTL: u32 = 300;
const NEGATIVE_TTL: u32 = 5;
const MAX_CACHE: usize = 4096;

#[derive(Debug, thiserror::Error)]
pub(crate) enum ResolveError {
    #[error("upstream DNS: {0}")]
    Io(#[from] std::io::Error),
    #[error("upstream DNS timed out")]
    Timeout,
    #[error("upstream DNS: {0}")]
    Wire(#[from] wire::WireError),
    #[error("upstream DNS answered rcode {0}")]
    Rcode(u8),
    #[error("`{0}` is not a resolvable name")]
    BadName(String),
}

#[derive(Clone, Debug)]
pub(crate) struct Lookup {
    pub(crate) rcode: u8,
    pub(crate) ips: Vec<IpAddr>,
    pub(crate) ttl: u32,
}

struct Cached {
    rcode: u8,
    ips: Vec<IpAddr>,
    expires: Instant,
}

pub(crate) struct Resolver {
    upstream: SocketAddr,
    cache: Mutex<HashMap<(String, u16), Cached>>,
}

impl Resolver {
    pub(crate) fn new(upstream: SocketAddr) -> Self {
        Self {
            upstream,
            cache: Mutex::new(HashMap::new()),
        }
    }

    /// A or AAAA records for `host`, cached for their TTL (clamped to 5-300 s).
    pub(crate) async fn lookup(&self, host: &str, qtype: u16) -> Result<Lookup, ResolveError> {
        let key = (host.to_string(), qtype);
        let now = Instant::now();
        if let Ok(cache) = self.cache.lock()
            && let Some(hit) = cache.get(&key)
            && hit.expires > now
        {
            let ttl = u32::try_from((hit.expires - now).as_secs())
                .unwrap_or(MAX_TTL)
                .max(1);
            return Ok(Lookup {
                rcode: hit.rcode,
                ips: hit.ips.clone(),
                ttl,
            });
        }
        let question = Question {
            name: Name::from_hostname(host).map_err(|_| ResolveError::BadName(host.into()))?,
            qtype,
            qclass: CLASS_IN,
        };
        let reply = self.exchange(&question).await?;
        let lookup = match reply.rcode() {
            RCODE_NOERROR => {
                let mut ips = Vec::new();
                let mut ttl = MAX_TTL;
                for record in &reply.answers {
                    let ip = match (&record.data, qtype) {
                        (RData::A(ip), TYPE_A) => IpAddr::V4(*ip),
                        (RData::Aaaa(ip), TYPE_AAAA) => IpAddr::V6(*ip),
                        _ => continue,
                    };
                    ttl = ttl.min(record.ttl);
                    if !ips.contains(&ip) {
                        ips.push(ip);
                    }
                }
                let ttl = if ips.is_empty() {
                    NEGATIVE_TTL
                } else {
                    ttl.clamp(MIN_TTL, MAX_TTL)
                };
                Lookup {
                    rcode: RCODE_NOERROR,
                    ips,
                    ttl,
                }
            }
            RCODE_NXDOMAIN => Lookup {
                rcode: RCODE_NXDOMAIN,
                ips: Vec::new(),
                ttl: NEGATIVE_TTL,
            },
            other => return Err(ResolveError::Rcode(other)),
        };
        if let Ok(mut cache) = self.cache.lock() {
            if cache.len() >= MAX_CACHE {
                cache.retain(|_, v| v.expires > now);
                if cache.len() >= MAX_CACHE {
                    cache.clear();
                }
            }
            cache.insert(
                key,
                Cached {
                    rcode: lookup.rcode,
                    ips: lookup.ips.clone(),
                    expires: now + Duration::from_secs(u64::from(lookup.ttl)),
                },
            );
        }
        Ok(lookup)
    }

    /// Every address for `host`, IPv4 first. An IP literal resolves to itself.
    pub(crate) async fn lookup_ips(&self, host: &str) -> Result<Vec<IpAddr>, ResolveError> {
        if let Ok(ip) = host.parse::<IpAddr>() {
            return Ok(vec![ip]);
        }
        let (v4, v6) = tokio::join!(self.lookup(host, TYPE_A), self.lookup(host, TYPE_AAAA));
        let mut ips = Vec::new();
        let mut first_err = None;
        for result in [v4, v6] {
            match result {
                Ok(lookup) => ips.extend(lookup.ips),
                Err(e) => {
                    first_err.get_or_insert(e);
                }
            }
        }
        match (ips.is_empty(), first_err) {
            (true, Some(e)) => Err(e),
            _ => Ok(ips),
        }
    }

    /// Ask upstream one question over UDP, retrying once and falling back to TCP on truncation.
    pub(crate) async fn exchange(&self, question: &Question) -> Result<Message, ResolveError> {
        let mut last = ResolveError::Timeout;
        for _ in 0..2 {
            match self.exchange_udp(question).await {
                Ok(msg) if msg.truncated() => return self.exchange_tcp(question).await,
                Ok(msg) => return Ok(msg),
                Err(e) => last = e,
            }
        }
        Err(last)
    }

    async fn exchange_udp(&self, question: &Question) -> Result<Message, ResolveError> {
        let id = random_id();
        let query = wire::build_query(id, question);
        let bind: SocketAddr = if self.upstream.is_ipv4() {
            "0.0.0.0:0".parse().unwrap_or_else(|_| unreachable!())
        } else {
            "[::]:0".parse().unwrap_or_else(|_| unreachable!())
        };
        let socket = UdpSocket::bind(bind).await?;
        socket.connect(self.upstream).await?;
        socket.send(&query).await?;
        let deadline = Instant::now() + UDP_TIMEOUT;
        let mut buf = vec![0u8; 4096];
        loop {
            let n = match tokio::time::timeout_at(deadline, socket.recv(&mut buf)).await {
                Ok(n) => n?,
                Err(_) => return Err(ResolveError::Timeout),
            };
            let Ok(msg) = wire::parse(&buf[..n]) else {
                continue;
            };
            if msg.id == id && msg.is_response() && matches_question(&msg, question) {
                return Ok(msg);
            }
        }
    }

    async fn exchange_tcp(&self, question: &Question) -> Result<Message, ResolveError> {
        let id = random_id();
        let query = wire::build_query(id, question);
        let run = async {
            let mut stream = TcpStream::connect(self.upstream).await?;
            let mut framed = Vec::with_capacity(query.len() + 2);
            framed.extend_from_slice(&(query.len() as u16).to_be_bytes());
            framed.extend_from_slice(&query);
            stream.write_all(&framed).await?;
            let len = usize::from(stream.read_u16().await?);
            let mut buf = vec![0u8; len];
            stream.read_exact(&mut buf).await?;
            Ok::<_, ResolveError>(buf)
        };
        let buf = timeout(TCP_TIMEOUT, run)
            .await
            .map_err(|_| ResolveError::Timeout)??;
        let msg = wire::parse(&buf)?;
        if msg.id != id || !msg.is_response() || !matches_question(&msg, question) {
            return Err(ResolveError::Wire(wire::WireError("mismatched TCP answer")));
        }
        Ok(msg)
    }
}

fn matches_question(msg: &Message, question: &Question) -> bool {
    msg.questions.first().is_some_and(|q| {
        q.qtype == question.qtype
            && q.qclass == question.qclass
            && q.name.0.len() == question.name.0.len()
            && q.name
                .0
                .iter()
                .zip(&question.name.0)
                .all(|(a, b)| a.eq_ignore_ascii_case(b))
    })
}

fn random_id() -> u16 {
    let mut bytes = [0u8; 2];
    // A failed read leaves zeros; the question match still guards the answer.
    let _ = getrandom::getrandom(&mut bytes);
    u16::from_be_bytes(bytes)
}
