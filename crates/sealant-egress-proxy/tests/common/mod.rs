//! A real proxy on loopback, with real upstreams: a fake authoritative DNS server, HTTPS and
//! plain HTTP echo servers, a WebSocket server, a TCP echo server, and rustls clients.
#![allow(dead_code)]

use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use futures::{SinkExt, StreamExt};
use rcgen::{
    BasicConstraints, CertificateParams, DistinguishedName, DnType, IsCa, KeyPair, KeyUsagePurpose,
};
use rustls::pki_types::{PrivateKeyDer, PrivatePkcs8KeyDer, ServerName};
use rustls::{ClientConfig, RootCertStore, ServerConfig};
use sealant_egress_proxy::{ProxyConfig, RunningProxy, start};
use serde_json::{Value, json};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream, UdpSocket, UnixStream};
use tokio_rustls::{TlsAcceptor, TlsConnector};

pub(crate) const PLACEHOLDER: &str = "mend_sec_0123456789abcdefghijklmn";
pub(crate) const SECRET: &str = "real-secret-value-7f3a";
pub(crate) const WS_PLACEHOLDER: &str = "mend_sec_wswswswswswswswswswsws";
pub(crate) const WS_SECRET: &str = "real-ws-secret-91c2";

fn provider() -> Arc<rustls::crypto::CryptoProvider> {
    Arc::new(rustls::crypto::ring::default_provider())
}

// ---------------------------------------------------------------------------------------------
// Certificates

pub(crate) struct Ca {
    pub(crate) cert: rcgen::Certificate,
    pub(crate) key: KeyPair,
}

impl Ca {
    pub(crate) fn new(name: &str) -> Self {
        let key = KeyPair::generate().unwrap();
        let mut params = CertificateParams::default();
        let mut dn = DistinguishedName::new();
        dn.push(DnType::CommonName, name);
        params.distinguished_name = dn;
        params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        params.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];
        let cert = params.self_signed(&key).unwrap();
        Self { cert, key }
    }

    pub(crate) fn cert_pem(&self) -> String {
        self.cert.pem()
    }

    pub(crate) fn key_pem(&self) -> String {
        self.key.serialize_pem()
    }

    pub(crate) fn roots(&self) -> RootCertStore {
        let mut roots = RootCertStore::empty();
        roots.add(self.cert.der().clone()).unwrap();
        roots
    }

    pub(crate) fn server_config(&self, names: &[&str]) -> Arc<ServerConfig> {
        let key = KeyPair::generate().unwrap();
        let params =
            CertificateParams::new(names.iter().map(|n| n.to_string()).collect::<Vec<_>>())
                .unwrap();
        let cert = params.signed_by(&key, &self.cert, &self.key).unwrap();
        let mut config = ServerConfig::builder_with_provider(provider())
            .with_safe_default_protocol_versions()
            .unwrap()
            .with_no_client_auth()
            .with_single_cert(
                vec![cert.der().clone()],
                PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(key.serialize_der())),
            )
            .unwrap();
        config.alpn_protocols = vec![b"http/1.1".to_vec()];
        Arc::new(config)
    }
}

pub(crate) fn client_config(roots: RootCertStore) -> Arc<ClientConfig> {
    let mut config = ClientConfig::builder_with_provider(provider())
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_root_certificates(roots)
        .with_no_client_auth();
    config.alpn_protocols = vec![b"http/1.1".to_vec()];
    Arc::new(config)
}

pub(crate) async fn tls_connect<S: AsyncRead + AsyncWrite + Unpin>(
    stream: S,
    roots: RootCertStore,
    sni: &str,
) -> std::io::Result<tokio_rustls::client::TlsStream<S>> {
    TlsConnector::from(client_config(roots))
        .connect(ServerName::try_from(sni.to_string()).unwrap(), stream)
        .await
}

// ---------------------------------------------------------------------------------------------
// Fake authoritative DNS (independent of the proxy's own wire code)

#[derive(Clone, Debug)]
pub(crate) enum Rec {
    A(Ipv4Addr),
    Aaaa(std::net::Ipv6Addr),
    Txt(&'static str),
    Srv(u16, &'static str),
}

pub(crate) struct FakeDns {
    pub(crate) addr: SocketAddr,
    pub(crate) queries: Arc<Mutex<Vec<(String, u16)>>>,
}

fn encode_name(name: &str, out: &mut Vec<u8>) {
    for label in name.trim_end_matches('.').split('.') {
        out.push(label.len() as u8);
        out.extend_from_slice(label.as_bytes());
    }
    out.push(0);
}

fn read_name(buf: &[u8], mut pos: usize) -> Option<(String, usize)> {
    let mut labels = Vec::new();
    loop {
        let len = *buf.get(pos)? as usize;
        pos += 1;
        if len == 0 {
            break;
        }
        labels.push(String::from_utf8_lossy(buf.get(pos..pos + len)?).to_ascii_lowercase());
        pos += len;
    }
    Some((labels.join("."), pos))
}

fn fake_answer(records: &HashMap<String, Vec<Rec>>, query: &[u8]) -> Option<Vec<u8>> {
    let id = &query[..2];
    let (name, pos) = read_name(query, 12)?;
    let qtype = u16::from_be_bytes([*query.get(pos)?, *query.get(pos + 1)?]);
    let question = &query[12..pos + 4];
    let (rcode, answers): (u16, Vec<&Rec>) = match records.get(&name) {
        None => (3, Vec::new()),
        Some(recs) => (
            0,
            recs.iter()
                .filter(|r| {
                    matches!(
                        (r, qtype),
                        (Rec::A(_), 1)
                            | (Rec::Aaaa(_), 28)
                            | (Rec::Txt(_), 16)
                            | (Rec::Srv(..), 33)
                    )
                })
                .collect(),
        ),
    };
    let mut out = Vec::new();
    out.extend_from_slice(id);
    out.extend_from_slice(&(0x8180u16 | rcode).to_be_bytes());
    out.extend_from_slice(&1u16.to_be_bytes());
    out.extend_from_slice(&(answers.len() as u16).to_be_bytes());
    out.extend_from_slice(&[0, 0, 0, 0]);
    out.extend_from_slice(question);
    for rec in answers {
        out.extend_from_slice(&[0xc0, 12]);
        let (rtype, rdata): (u16, Vec<u8>) = match rec {
            Rec::A(ip) => (1, ip.octets().to_vec()),
            Rec::Aaaa(ip) => (28, ip.octets().to_vec()),
            Rec::Txt(text) => {
                let mut d = vec![text.len() as u8];
                d.extend_from_slice(text.as_bytes());
                (16, d)
            }
            Rec::Srv(port, target) => {
                let mut d = vec![0, 10, 0, 5];
                d.extend_from_slice(&port.to_be_bytes());
                encode_name(target, &mut d);
                (33, d)
            }
        };
        out.extend_from_slice(&rtype.to_be_bytes());
        out.extend_from_slice(&1u16.to_be_bytes());
        out.extend_from_slice(&60u32.to_be_bytes());
        out.extend_from_slice(&(rdata.len() as u16).to_be_bytes());
        out.extend_from_slice(&rdata);
    }
    Some(out)
}

impl FakeDns {
    pub(crate) async fn start(records: HashMap<String, Vec<Rec>>) -> Self {
        let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let addr = socket.local_addr().unwrap();
        let queries = Arc::new(Mutex::new(Vec::new()));
        let seen = queries.clone();
        tokio::spawn(async move {
            let mut buf = vec![0u8; 4096];
            loop {
                let Ok((n, peer)) = socket.recv_from(&mut buf).await else {
                    continue;
                };
                if let Some((name, pos)) = read_name(&buf[..n], 12) {
                    let qtype = u16::from_be_bytes([buf[pos], buf[pos + 1]]);
                    seen.lock().unwrap().push((name, qtype));
                }
                if let Some(reply) = fake_answer(&records, &buf[..n]) {
                    let _ = socket.send_to(&reply, peer).await;
                }
            }
        });
        Self { addr, queries }
    }

    pub(crate) fn asked(&self, name: &str) -> bool {
        self.queries.lock().unwrap().iter().any(|(n, _)| n == name)
    }
}

/// A DNS client for the proxy's server: returns (rcode, answers as (type, rdata)).
pub(crate) async fn dns_query(
    server: SocketAddr,
    name: &str,
    qtype: u16,
) -> (u8, Vec<(u16, Vec<u8>)>) {
    let mut q = vec![0xab, 0xcd, 0x01, 0x00, 0, 1, 0, 0, 0, 0, 0, 0];
    encode_name(name, &mut q);
    q.extend_from_slice(&qtype.to_be_bytes());
    q.extend_from_slice(&1u16.to_be_bytes());
    let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    socket.send_to(&q, server).await.unwrap();
    let mut buf = vec![0u8; 4096];
    let n = tokio::time::timeout(Duration::from_secs(5), socket.recv(&mut buf))
        .await
        .expect("dns reply")
        .unwrap();
    parse_dns_reply(&buf[..n])
}

pub(crate) async fn dns_query_tcp(
    server: SocketAddr,
    name: &str,
    qtype: u16,
) -> (u8, Vec<(u16, Vec<u8>)>) {
    let mut q = vec![0xab, 0xce, 0x01, 0x00, 0, 1, 0, 0, 0, 0, 0, 0];
    encode_name(name, &mut q);
    q.extend_from_slice(&qtype.to_be_bytes());
    q.extend_from_slice(&1u16.to_be_bytes());
    let mut stream = TcpStream::connect(server).await.unwrap();
    stream.write_u16(q.len() as u16).await.unwrap();
    stream.write_all(&q).await.unwrap();
    let len = stream.read_u16().await.unwrap() as usize;
    let mut buf = vec![0u8; len];
    stream.read_exact(&mut buf).await.unwrap();
    parse_dns_reply(&buf)
}

fn parse_dns_reply(buf: &[u8]) -> (u8, Vec<(u16, Vec<u8>)>) {
    let rcode = buf[3] & 0x0f;
    let an = u16::from_be_bytes([buf[6], buf[7]]);
    let (_, mut pos) = read_name(buf, 12).unwrap();
    pos += 4;
    let mut answers = Vec::new();
    for _ in 0..an {
        let (_, after) = read_name(buf, pos).unwrap();
        pos = after;
        let rtype = u16::from_be_bytes([buf[pos], buf[pos + 1]]);
        let rdlen = u16::from_be_bytes([buf[pos + 8], buf[pos + 9]]) as usize;
        pos += 10;
        answers.push((rtype, buf[pos..pos + rdlen].to_vec()));
        pos += rdlen;
    }
    (rcode, answers)
}

// ---------------------------------------------------------------------------------------------
// Upstream servers

/// What an upstream saw: each request head as text.
pub(crate) type Seen = Arc<Mutex<Vec<String>>>;

async fn read_head<S: AsyncRead + Unpin>(stream: &mut S) -> Option<String> {
    let mut head = Vec::new();
    let mut byte = [0u8; 1];
    while !head.ends_with(b"\r\n\r\n") {
        match stream.read(&mut byte).await {
            Ok(1) => head.push(byte[0]),
            _ => return None,
        }
    }
    Some(String::from_utf8_lossy(&head).into_owned())
}

async fn echo_http<S: AsyncRead + AsyncWrite + Unpin>(mut stream: S, seen: Seen) {
    while let Some(head) = read_head(&mut stream).await {
        seen.lock().unwrap().push(head.clone());
        let body = head.into_bytes();
        let response = format!(
            "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: {}\r\n\r\n",
            body.len()
        );
        if stream.write_all(response.as_bytes()).await.is_err()
            || stream.write_all(&body).await.is_err()
        {
            return;
        }
    }
}

/// An HTTPS server that echoes each request head back as the body.
pub(crate) async fn https_echo(config: Arc<ServerConfig>) -> (u16, Seen) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let seen: Seen = Arc::default();
    let seen2 = seen.clone();
    tokio::spawn(async move {
        let acceptor = TlsAcceptor::from(config);
        loop {
            let Ok((stream, _)) = listener.accept().await else {
                continue;
            };
            let acceptor = acceptor.clone();
            let seen = seen2.clone();
            tokio::spawn(async move {
                if let Ok(tls) = acceptor.accept(stream).await {
                    echo_http(tls, seen).await;
                }
            });
        }
    });
    (port, seen)
}

/// A plain HTTP server that echoes each request head back as the body.
pub(crate) async fn http_echo() -> (u16, Seen) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let seen: Seen = Arc::default();
    let seen2 = seen.clone();
    tokio::spawn(async move {
        loop {
            let Ok((stream, _)) = listener.accept().await else {
                continue;
            };
            tokio::spawn(echo_http(stream, seen2.clone()));
        }
    });
    (port, seen)
}

/// A raw TCP echo server.
pub(crate) async fn tcp_echo() -> u16 {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    tokio::spawn(async move {
        loop {
            let Ok((mut stream, _)) = listener.accept().await else {
                continue;
            };
            tokio::spawn(async move {
                let (mut r, mut w) = stream.split();
                let _ = tokio::io::copy(&mut r, &mut w).await;
            });
        }
    });
    port
}

/// A WSS echo server that records each handshake's Authorization header.
pub(crate) async fn wss_echo(config: Arc<ServerConfig>) -> (u16, Seen) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let seen: Seen = Arc::default();
    let seen2 = seen.clone();
    tokio::spawn(async move {
        let acceptor = TlsAcceptor::from(config);
        loop {
            let Ok((stream, _)) = listener.accept().await else {
                continue;
            };
            let acceptor = acceptor.clone();
            let seen = seen2.clone();
            tokio::spawn(async move {
                let Ok(tls) = acceptor.accept(stream).await else {
                    return;
                };
                let record = seen.clone();
                #[allow(clippy::result_large_err)]
                let callback = move |req: &tokio_tungstenite::tungstenite::handshake::server::Request,
                                     resp: tokio_tungstenite::tungstenite::handshake::server::Response| {
                    let auth = req
                        .headers()
                        .get("authorization")
                        .map(|v| v.to_str().unwrap_or("").to_string())
                        .unwrap_or_default();
                    record.lock().unwrap().push(auth);
                    Ok(resp)
                };
                let Ok(mut ws) = tokio_tungstenite::accept_hdr_async(tls, callback).await else {
                    return;
                };
                while let Some(Ok(msg)) = ws.next().await {
                    if msg.is_text() || msg.is_binary() {
                        if ws.send(msg).await.is_err() {
                            return;
                        }
                    } else if msg.is_close() {
                        return;
                    }
                }
            });
        }
    });
    (port, seen)
}

// ---------------------------------------------------------------------------------------------
// The proxy and its admin socket

pub(crate) struct Harness {
    pub(crate) proxy: RunningProxy,
    pub(crate) admin: PathBuf,
    pub(crate) dns: FakeDns,
    _dir: tempfile::TempDir,
}

impl Harness {
    pub(crate) async fn start(
        records: HashMap<String, Vec<Rec>>,
        upstream_roots: RootCertStore,
    ) -> Self {
        let dir = tempfile::tempdir().unwrap();
        let admin = dir.path().join("proxy-admin.sock");
        let dns = FakeDns::start(records).await;
        let any: SocketAddr = "127.0.0.1:0".parse().unwrap();
        let mut config = ProxyConfig::new(&admin, dns.addr);
        config.explicit_http = Some(any);
        config.transparent_http = Some(any);
        config.transparent_https = Some(any);
        config.transparent_tcp = Some(any);
        config.transparent_resource = Some(any);
        config.dns = Some(any);
        config.upstream_roots = Arc::new(upstream_roots);
        config.connect_timeout = Duration::from_secs(3);
        let proxy = start(config).await.unwrap();
        Self {
            proxy,
            admin,
            dns,
            _dir: dir,
        }
    }

    pub(crate) fn explicit(&self) -> SocketAddr {
        self.proxy.addrs.explicit_http.unwrap()
    }
    pub(crate) fn dns_addr(&self) -> SocketAddr {
        self.proxy.addrs.dns.unwrap()
    }

    pub(crate) async fn admin(
        &self,
        method: &str,
        path: &str,
        body: Option<&Value>,
    ) -> (u16, Value) {
        let mut stream = UnixStream::connect(&self.admin).await.unwrap();
        let body = body.map(|b| b.to_string()).unwrap_or_default();
        let request = format!(
            "{method} {path} HTTP/1.1\r\nHost: proxy\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{body}",
            body.len()
        );
        stream.write_all(request.as_bytes()).await.unwrap();
        let mut response = Vec::new();
        stream.read_to_end(&mut response).await.unwrap();
        let text = String::from_utf8(response).unwrap();
        let status: u16 = text[9..12].parse().unwrap();
        let body = text.split_once("\r\n\r\n").map(|(_, b)| b).unwrap_or("");
        let value = if path.starts_with("/v1/events") {
            Value::String(body.to_string())
        } else {
            serde_json::from_str(body).unwrap_or(Value::Null)
        };
        (status, value)
    }

    pub(crate) async fn put_policy(&self, policy: &Value) -> (u16, Value) {
        self.admin("PUT", "/v1/policy", Some(policy)).await
    }

    pub(crate) async fn health(&self) -> Value {
        self.admin("GET", "/v1/health", None).await.1
    }
}

/// A Standard policy that lets loopback through (every test upstream lives there).
pub(crate) fn base_policy(watermark: u64) -> Value {
    json!({
        "mode": "standard",
        "policyHash": format!("hash-{watermark}"),
        "revocationWatermark": watermark,
        "operatorAllowedPrivateCidrs": ["127.0.0.0/8"],
    })
}

pub(crate) fn with_broker(mut policy: Value, ca: &Ca, secrets: Value) -> Value {
    policy["executorCaCertPem"] = ca.cert_pem().into();
    policy["executorCaKeyPem"] = ca.key_pem().into();
    policy["brokeredSecrets"] = secrets;
    policy
}

/// Name the ports TLS to each host is inspected (and brokered) on: 443 is the default, and the
/// test upstreams listen on ephemeral ports.
pub(crate) fn on_ports(ports: &[(&str, u16)], mut policy: Value) -> Value {
    let mut entries = policy["allowHosts"].as_array().cloned().unwrap_or_default();
    for (host, port) in ports {
        entries.push(json!({ "host": host, "ports": [port] }));
    }
    policy["allowHosts"] = Value::Array(entries);
    policy
}

pub(crate) fn secret(
    id: &str,
    placeholder: &str,
    value: &str,
    header: &str,
    hosts: &[&str],
) -> Value {
    json!({
        "secretId": id,
        "name": id.to_uppercase(),
        "placeholder": placeholder,
        "value": value,
        "headerName": header,
        "bindHosts": hosts,
    })
}

// ---------------------------------------------------------------------------------------------
// Clients

/// Send `CONNECT host:port` and return the stream and the proxy's status code.
pub(crate) async fn connect_tunnel(proxy: SocketAddr, host: &str, port: u16) -> (TcpStream, u16) {
    let mut stream = TcpStream::connect(proxy).await.unwrap();
    let req = format!("CONNECT {host}:{port} HTTP/1.1\r\nHost: {host}:{port}\r\n\r\n");
    stream.write_all(req.as_bytes()).await.unwrap();
    let head = read_head(&mut stream).await.unwrap_or_default();
    let status = head.get(9..12).and_then(|s| s.parse().ok()).unwrap_or(0);
    (stream, status)
}

/// Send one request and read one response (by Content-Length). Returns (status, body).
pub(crate) async fn http_exchange<S: AsyncRead + AsyncWrite + Unpin>(
    stream: &mut S,
    request: &str,
) -> std::io::Result<(u16, String)> {
    stream.write_all(request.as_bytes()).await?;
    let head = read_head(stream)
        .await
        .ok_or_else(|| std::io::Error::new(std::io::ErrorKind::UnexpectedEof, "no response"))?;
    let status: u16 = head[9..12].parse().unwrap();
    let length = head
        .lines()
        .find_map(|l| {
            let (k, v) = l.split_once(':')?;
            k.eq_ignore_ascii_case("content-length")
                .then(|| v.trim().parse::<usize>().ok())?
        })
        .unwrap_or(0);
    let mut body = vec![0u8; length];
    stream.read_exact(&mut body).await?;
    Ok((status, String::from_utf8_lossy(&body).into_owned()))
}

/// Whether the peer has closed `stream` (EOF or reset) within `wait`.
pub(crate) async fn closed_within<S: AsyncRead + Unpin>(stream: &mut S, wait: Duration) -> bool {
    let mut buf = [0u8; 64];
    matches!(
        tokio::time::timeout(wait, stream.read(&mut buf)).await,
        Ok(Ok(0)) | Ok(Err(_))
    )
}

pub(crate) fn proxy_v2(dst: SocketAddr) -> Vec<u8> {
    sealant_egress_proxy::proxyproto::encode("10.200.0.2:40000".parse().unwrap(), dst)
}

pub(crate) fn loopback(port: u16) -> SocketAddr {
    SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), port)
}

pub(crate) fn records(entries: &[(&str, Vec<Rec>)]) -> HashMap<String, Vec<Rec>> {
    entries
        .iter()
        .map(|(name, recs)| (name.to_string(), recs.clone()))
        .collect()
}

pub(crate) fn localhost() -> Vec<Rec> {
    vec![Rec::A(Ipv4Addr::LOCALHOST)]
}
