//! The session channel over real TLS: a certificate is verified against the roots the launcher
//! named, a name or an issuer that does not verify is refused, and a redirect is never followed.
use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Duration;

use rcgen::{
    BasicConstraints, CertificateParams, DnType, ExtendedKeyUsagePurpose, IsCa, KeyPair,
    KeyUsagePurpose,
};
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use sealant_capture::registrar::HeartbeatRequest;
use sealant_capture::sink::{BlobSource, SinkError};
use sealant_capture::{
    BlobSink, ChannelTransport, HttpRegistrar, PresignedHttp, Registrar, RegistrarError, UrlMinter,
};

const TIMEOUT: Duration = Duration::from_secs(5);

fn ca(name: &str) -> (rcgen::Certificate, KeyPair) {
    let key = KeyPair::generate().expect("ca key");
    let mut params = CertificateParams::new(Vec::<String>::new()).expect("params");
    params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    params.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];
    params.distinguished_name.push(DnType::CommonName, name);
    let cert = params.self_signed(&key).expect("ca cert");
    (cert, key)
}

fn leaf(issuer: &(rcgen::Certificate, KeyPair), san: &str) -> (String, String) {
    let key = KeyPair::generate().expect("leaf key");
    let mut params = CertificateParams::new(vec![san.to_owned()]).expect("params");
    params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth];
    params.key_usages = vec![KeyUsagePurpose::DigitalSignature];
    params.distinguished_name.push(DnType::CommonName, san);
    let cert = params
        .signed_by(&key, &issuer.0, &issuer.1)
        .expect("sign leaf");
    (cert.pem(), key.serialize_pem())
}

/// What one server saw: how many requests completed a handshake and arrived, and their heads.
#[derive(Default)]
struct Seen {
    requests: AtomicUsize,
    heads: Mutex<Vec<String>>,
}

fn read_head(stream: &mut impl Read) -> Option<String> {
    let mut head = Vec::new();
    let mut byte = [0u8; 1];
    while !head.ends_with(b"\r\n\r\n") {
        match stream.read(&mut byte) {
            Ok(1) => head.push(byte[0]),
            _ => return None,
        }
    }
    Some(String::from_utf8_lossy(&head).into_owned())
}

/// Read the whole request (head, then `Content-Length` bytes) before answering: closing a socket
/// with unread bytes resets it, and the client would see the reset instead of the answer.
fn answer(stream: &mut (impl Read + Write), seen: &Seen, response: &str) {
    let Some(head) = read_head(stream) else {
        return;
    };
    let length = head
        .lines()
        .find_map(|line| {
            let (name, value) = line.split_once(':')?;
            name.eq_ignore_ascii_case("content-length")
                .then(|| value.trim().parse::<usize>().ok())?
        })
        .unwrap_or(0);
    let mut body = vec![0u8; length];
    if stream.read_exact(&mut body).is_err() {
        return;
    }
    seen.requests.fetch_add(1, Ordering::SeqCst);
    seen.heads.lock().expect("heads").push(head);
    let _ = stream.write_all(response.as_bytes());
    let _ = stream.flush();
}

/// An HTTPS server on loopback answering every request with `response`.
fn tls_server(cert_pem: &str, key_pem: &str, response: &'static str) -> (u16, Arc<Seen>) {
    let certs: Vec<CertificateDer<'static>> = rustls_pemfile::certs(&mut cert_pem.as_bytes())
        .collect::<Result<_, _>>()
        .expect("certs");
    let key: PrivateKeyDer<'static> = rustls_pemfile::private_key(&mut key_pem.as_bytes())
        .expect("key")
        .expect("one key");
    let config = Arc::new(
        rustls::ServerConfig::builder_with_provider(Arc::new(
            rustls::crypto::ring::default_provider(),
        ))
        .with_safe_default_protocol_versions()
        .expect("versions")
        .with_no_client_auth()
        .with_single_cert(certs, key)
        .expect("server config"),
    );
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
    let port = listener.local_addr().expect("addr").port();
    let seen = Arc::new(Seen::default());
    let observed = Arc::clone(&seen);
    thread::spawn(move || {
        for stream in listener.incoming() {
            let Ok(stream) = stream else { continue };
            let Ok(connection) = rustls::ServerConnection::new(Arc::clone(&config)) else {
                continue;
            };
            let mut tls = rustls::StreamOwned::new(connection, stream);
            answer(&mut tls, &observed, response);
            tls.conn.send_close_notify();
            let _ = tls.flush();
        }
    });
    (port, seen)
}

/// A plain HTTP server on loopback: where a followed redirect would land.
fn plain_server(response: &'static str) -> (u16, Arc<Seen>) {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
    let port = listener.local_addr().expect("addr").port();
    let seen = Arc::new(Seen::default());
    let observed = Arc::clone(&seen);
    thread::spawn(move || {
        for stream in listener.incoming() {
            let Ok(mut stream): Result<TcpStream, _> = stream else {
                continue;
            };
            answer(&mut stream, &observed, response);
            let _ = stream.shutdown(std::net::Shutdown::Write);
        }
    });
    (port, seen)
}

const HEARTBEAT_OK: &str = "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: 22\r\nConnection: close\r\n\r\n{\"expires_in_secs\":30}";

fn heartbeat(registrar: &HttpRegistrar) -> Result<u64, RegistrarError> {
    registrar
        .lease_heartbeat(&HeartbeatRequest {
            worktree_id: "w".to_owned(),
            epoch: 1,
        })
        .map(|answer| answer.expires_in_secs)
}

#[test]
fn a_channel_behind_the_named_ca_is_dialled_with_the_token() {
    let authority = ca("the operator's CA");
    let (cert, key) = leaf(&authority, "127.0.0.1");
    let (port, seen) = tls_server(&cert, &key, HEARTBEAT_OK);
    let transport = ChannelTransport::verified()
        .with_channel_ca_pem(&authority.0.pem())
        .expect("ca bundle");
    let registrar = HttpRegistrar::new(
        &format!("https://127.0.0.1:{port}/channel"),
        "session-token",
        TIMEOUT,
        &transport,
    )
    .expect("https is dialled");

    assert_eq!(heartbeat(&registrar).expect("heartbeat"), 30);
    let heads = seen.heads.lock().expect("heads");
    assert!(
        heads[0].starts_with("POST /channel/lease.heartbeat "),
        "{heads:?}"
    );
    assert!(
        heads[0]
            .to_lowercase()
            .contains("authorization: bearer session-token"),
        "{heads:?}"
    );
}

#[test]
fn an_issuer_outside_the_roots_is_refused_before_the_token_is_sent() {
    let authority = ca("the operator's CA");
    let (cert, key) = leaf(&authority, "127.0.0.1");
    let (port, seen) = tls_server(&cert, &key, HEARTBEAT_OK);
    let endpoint = format!("https://127.0.0.1:{port}/channel");

    // The public roots do not know this CA.
    let public = HttpRegistrar::new(
        &endpoint,
        "session-token",
        TIMEOUT,
        &ChannelTransport::verified(),
    )
    .expect("https is dialled");
    assert!(matches!(
        heartbeat(&public),
        Err(RegistrarError::Transport(_))
    ));

    // Neither does a bundle naming someone else's CA.
    let foreign = ChannelTransport::verified()
        .with_channel_ca_pem(&ca("someone else's CA").0.pem())
        .expect("ca bundle");
    let pinned = HttpRegistrar::new(&endpoint, "session-token", TIMEOUT, &foreign)
        .expect("https is dialled");
    assert!(matches!(
        heartbeat(&pinned),
        Err(RegistrarError::Transport(_))
    ));

    // The plaintext exception is not a verification exception.
    let lax = ChannelTransport::verified().allow_plaintext(true);
    let relaxed =
        HttpRegistrar::new(&endpoint, "session-token", TIMEOUT, &lax).expect("https is dialled");
    assert!(matches!(
        heartbeat(&relaxed),
        Err(RegistrarError::Transport(_))
    ));

    assert_eq!(
        seen.requests.load(Ordering::SeqCst),
        0,
        "no request may arrive"
    );
}

#[test]
fn a_certificate_for_another_name_is_refused() {
    let authority = ca("the operator's CA");
    let (cert, key) = leaf(&authority, "channel.example");
    let (port, seen) = tls_server(&cert, &key, HEARTBEAT_OK);
    let transport = ChannelTransport::verified()
        .with_channel_ca_pem(&authority.0.pem())
        .expect("ca bundle");
    let registrar = HttpRegistrar::new(
        &format!("https://127.0.0.1:{port}/channel"),
        "session-token",
        TIMEOUT,
        &transport,
    )
    .expect("https is dialled");

    assert!(matches!(
        heartbeat(&registrar),
        Err(RegistrarError::Transport(_))
    ));
    assert_eq!(seen.requests.load(Ordering::SeqCst), 0);
}

#[test]
fn a_redirect_is_an_answer_never_a_destination() {
    let (elsewhere, elsewhere_seen) = plain_server(HEARTBEAT_OK);
    let location: &'static str = Box::leak(
        format!(
            "HTTP/1.1 307 Temporary Redirect\r\nLocation: http://127.0.0.1:{elsewhere}/channel/lease.heartbeat\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
        )
        .into_boxed_str(),
    );
    let authority = ca("the operator's CA");
    let (cert, key) = leaf(&authority, "127.0.0.1");
    let (port, seen) = tls_server(&cert, &key, location);
    let transport = ChannelTransport::verified()
        .with_channel_ca_pem(&authority.0.pem())
        .expect("ca bundle");
    let registrar = HttpRegistrar::new(
        &format!("https://127.0.0.1:{port}/channel"),
        "session-token",
        TIMEOUT,
        &transport,
    )
    .expect("https is dialled");

    match heartbeat(&registrar) {
        Err(RegistrarError::Protocol(reason)) => assert!(reason.contains("307"), "{reason}"),
        other => panic!("expected the 307 as a protocol error, got {other:?}"),
    }
    assert_eq!(seen.requests.load(Ordering::SeqCst), 1);
    assert_eq!(
        elsewhere_seen.requests.load(Ordering::SeqCst),
        0,
        "the redirect was followed"
    );
}

#[test]
fn plain_http_beyond_loopback_is_refused_at_construction() {
    let refusal = HttpRegistrar::new(
        "http://mend-api:3106/channel",
        "session-token",
        TIMEOUT,
        &ChannelTransport::verified(),
    )
    .expect_err("refused");
    assert!(
        refusal
            .to_string()
            .contains("SEALANT_CAPTURE_ALLOW_PLAINTEXT")
    );

    HttpRegistrar::new(
        "http://mend-api:3106/channel",
        "session-token",
        TIMEOUT,
        &ChannelTransport::verified().allow_plaintext(true),
    )
    .expect("the explicit exception dials it");
}

/// A minter answering one fixed URL for every key, as a hostile or misconfigured registrar might.
struct FixedUrl(String);

impl UrlMinter for FixedUrl {
    fn put_url(&self, _key: &str, _size: u64) -> Result<String, SinkError> {
        Ok(self.0.clone())
    }

    fn get_url(&self, _key: &str) -> Result<String, SinkError> {
        Ok(self.0.clone())
    }
}

#[test]
fn an_object_url_the_policy_does_not_dial_is_never_sent_bytes() {
    let sink = PresignedHttp::new(
        Box::new(FixedUrl(
            "http://bucket.internal/captures/w/pack?X-Amz-Signature=secret".to_owned(),
        )),
        TIMEOUT,
    );
    let refusal = sink
        .put_if_absent("captures/w/pack", BlobSource::Bytes(b"bytes"))
        .expect_err("refused");
    match refusal {
        SinkError::NoUrl { reason, .. } => {
            assert!(reason.contains("bucket.internal"), "{reason}");
            assert!(!reason.contains("secret"), "{reason}");
        }
        other => panic!("expected NoUrl, got {other:?}"),
    }
}

const OBJECT_OK: &str = "HTTP/1.1 200 OK\r\nContent-Length: 0\r\nConnection: close\r\n\r\n";

#[test]
fn an_object_store_is_verified_against_its_own_roots_not_the_channels() {
    let channel_ca = ca("the channel's CA");
    let object_ca = ca("the object store's CA");
    let (cert, key) = leaf(&object_ca, "127.0.0.1");
    let (port, seen) = tls_server(&cert, &key, OBJECT_OK);
    let url = format!("https://127.0.0.1:{port}/pack");

    // The channel's CA says nothing about object URLs.
    let channel_only = ChannelTransport::verified()
        .with_channel_ca_pem(&channel_ca.0.pem())
        .expect("ca bundle");
    let sink =
        PresignedHttp::with_transport(Box::new(FixedUrl(url.clone())), TIMEOUT, &channel_only);
    let refusal = sink
        .put_if_absent("captures/w/pack", BlobSource::Bytes(b"bytes"))
        .expect_err("unknown issuer");
    assert!(
        matches!(refusal, SinkError::Transport { .. }),
        "{refusal:?}"
    );
    assert_eq!(seen.requests.load(Ordering::SeqCst), 0);

    // The object store's own bundle does.
    let with_object_ca = channel_only
        .with_object_ca_pem(&object_ca.0.pem())
        .expect("ca bundle");
    let sink = PresignedHttp::with_transport(Box::new(FixedUrl(url)), TIMEOUT, &with_object_ca);
    sink.put_if_absent("captures/w/pack", BlobSource::Bytes(b"bytes"))
        .expect("verified against the object roots");
    assert_eq!(seen.requests.load(Ordering::SeqCst), 1);
}

#[test]
fn an_object_redirect_is_not_followed() {
    let (elsewhere, elsewhere_seen) =
        plain_server("HTTP/1.1 200 OK\r\nContent-Length: 0\r\nConnection: close\r\n\r\n");
    let location: &'static str = Box::leak(
        format!(
            "HTTP/1.1 307 Temporary Redirect\r\nLocation: http://127.0.0.1:{elsewhere}/pack\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
        )
        .into_boxed_str(),
    );
    let (port, seen) = plain_server(location);
    let sink = PresignedHttp::new(
        Box::new(FixedUrl(format!("http://127.0.0.1:{port}/pack"))),
        TIMEOUT,
    );
    let refusal = sink
        .put_if_absent("captures/w/pack", BlobSource::Bytes(b"bytes"))
        .expect_err("a 307 is not success");
    assert!(
        matches!(refusal, SinkError::Http { status: 307, .. }),
        "{refusal:?}"
    );
    assert_eq!(seen.requests.load(Ordering::SeqCst), 1);
    assert_eq!(
        elsewhere_seen.requests.load(Ordering::SeqCst),
        0,
        "the redirect was followed"
    );
}
