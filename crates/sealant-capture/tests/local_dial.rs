//! Capture traffic over a local socket ([`Dial`]): a Unix socket on the `docker` runtime, vsock to
//! the host on `host-vm`. The relay behind the socket forwards each request to the host it names,
//! and a presigned URL's signature covers that host, so what arrives must be the request as the
//! URL spells it: the same path and query, and the `Host` header of the URL, not of the socket.
use std::io::{Read, Write};
use std::os::unix::net::UnixListener;
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Duration;

use sealant_capture::registrar::HeartbeatRequest;
use sealant_capture::sink::{BlobSource, SinkError};
use sealant_capture::{
    BlobSink, ChannelTransport, Dial, HttpRegistrar, PresignedHttp, Registrar, UrlMinter,
};

const TIMEOUT: Duration = Duration::from_secs(5);

const HEARTBEAT_OK: &str = "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: 22\r\nConnection: close\r\n\r\n{\"expires_in_secs\":30}";
const OBJECT_OK: &str = "HTTP/1.1 200 OK\r\nContent-Length: 0\r\nConnection: close\r\n\r\n";

type Heads = Arc<Mutex<Vec<String>>>;

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

/// Read the whole request (head, then `Content-Length` bytes), record its head, answer.
fn answer(stream: &mut (impl Read + Write), heads: &Heads, response: &str) {
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
    heads.lock().expect("heads").push(head);
    let _ = stream.write_all(response.as_bytes());
    let _ = stream.flush();
}

/// A plain HTTP server on a Unix socket, answering every request with `response`: the relay.
fn unix_server(dir: &tempfile::TempDir, response: &'static str) -> (std::path::PathBuf, Heads) {
    let path = dir.path().join("capture.sock");
    let listener = UnixListener::bind(&path).expect("bind");
    let heads: Heads = Arc::default();
    let seen = Arc::clone(&heads);
    thread::spawn(move || {
        for stream in listener.incoming() {
            let Ok(mut stream) = stream else { continue };
            answer(&mut stream, &seen, response);
            let _ = stream.shutdown(std::net::Shutdown::Write);
        }
    });
    (path, heads)
}

/// The `Host` header values of a request head (there must be exactly one).
fn host_headers(head: &str) -> Vec<String> {
    head.lines()
        .filter_map(|line| {
            let (name, value) = line.split_once(':')?;
            name.eq_ignore_ascii_case("host")
                .then(|| value.trim().to_owned())
        })
        .collect()
}

fn heartbeat(registrar: &HttpRegistrar) -> u64 {
    registrar
        .lease_heartbeat(&HeartbeatRequest {
            worktree_id: "w".to_owned(),
            epoch: 1,
        })
        .expect("heartbeat")
        .expires_in_secs
}

#[test]
fn the_session_channel_over_a_unix_socket_keeps_the_urls_host() {
    let dir = tempfile::tempdir().expect("tempdir");
    let (socket, heads) = unix_server(&dir, HEARTBEAT_OK);
    // No plaintext exception: plain HTTP to a local socket's relay needs none.
    let transport = ChannelTransport::verified().dial_via(Dial::Unix(socket));
    let registrar = HttpRegistrar::new(
        "http://mend:3106/channel",
        "session-token",
        TIMEOUT,
        &transport,
    )
    .expect("plain http over a local socket is dialled");

    assert_eq!(heartbeat(&registrar), 30);
    let heads = heads.lock().expect("heads");
    assert_eq!(heads.len(), 1, "{heads:?}");
    assert!(
        heads[0].starts_with("POST /channel/lease.heartbeat HTTP/1.1\r\n"),
        "{heads:?}"
    );
    assert_eq!(host_headers(&heads[0]), ["mend:3106"], "{heads:?}");
    assert!(
        heads[0]
            .to_lowercase()
            .contains("authorization: bearer session-token"),
        "{heads:?}"
    );
}

/// A minter answering one fixed presigned URL for every key.
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
fn a_presigned_upload_over_a_unix_socket_arrives_as_signed() {
    let dir = tempfile::tempdir().expect("tempdir");
    let (socket, heads) = unix_server(&dir, OBJECT_OK);
    let target = "/captures/w/pack?X-Amz-Algorithm=AWS4-HMAC-SHA256&X-Amz-Credential=GK%2F20261124%2Fgarage%2Fs3%2Faws4_request&X-Amz-SignedHeaders=host&X-Amz-Signature=0123abcd";
    let transport = ChannelTransport::verified().dial_via(Dial::Unix(socket));
    let sink = PresignedHttp::with_transport(
        Box::new(FixedUrl(format!("http://garage:3900{target}"))),
        TIMEOUT,
        &transport,
    );
    sink.put_if_absent("captures/w/pack", BlobSource::Bytes(b"bytes"))
        .expect("uploaded over the socket");

    let heads = heads.lock().expect("heads");
    assert!(!heads.is_empty(), "nothing arrived");
    for head in heads.iter() {
        let request_line = head.lines().next().unwrap_or_default();
        let mut parts = request_line.split(' ');
        let _method = parts.next();
        assert_eq!(parts.next(), Some(target), "{head}");
        assert_eq!(host_headers(head), ["garage:3900"], "{head}");
    }
    assert!(
        heads.iter().any(|head| head.starts_with("PUT ")),
        "{heads:?}"
    );
}

#[test]
fn without_a_local_dial_plain_http_beyond_loopback_is_still_refused() {
    let refusal = HttpRegistrar::new(
        "http://mend:3106/channel",
        "session-token",
        TIMEOUT,
        &ChannelTransport::verified(),
    )
    .expect_err("refused");
    assert!(
        refusal.to_string().contains("plain http to mend"),
        "{refusal}"
    );
}

#[test]
fn a_unix_socket_nobody_serves_is_a_transport_error() {
    let dir = tempfile::tempdir().expect("tempdir");
    let transport =
        ChannelTransport::verified().dial_via(Dial::Unix(dir.path().join("absent.sock")));
    let registrar = HttpRegistrar::new(
        "http://mend:3106/channel",
        "session-token",
        TIMEOUT,
        &transport,
    )
    .expect("dialled");
    assert!(
        registrar
            .lease_heartbeat(&HeartbeatRequest {
                worktree_id: "w".to_owned(),
                epoch: 1,
            })
            .is_err()
    );
}

/// The same over real `AF_VSOCK`, through the kernel's vsock loopback (CID 1) standing in for
/// the host's relay (CID 2, port 1025).
#[cfg(target_os = "linux")]
#[test]
fn the_session_channel_over_vsock_keeps_the_urls_host() {
    use socket2::{Domain, SockAddr, Socket, Type};

    let required = std::env::var("SEALANTD_REQUIRE_VSOCK").as_deref() == Ok("1");
    let port = 30_000 + (std::process::id() % 10_000);
    let listener = Socket::new(Domain::VSOCK, Type::STREAM, None).and_then(|socket| {
        socket.bind(&SockAddr::vsock(u32::MAX, port))?;
        socket.listen(8)?;
        Ok(socket)
    });
    let listener = match listener {
        Ok(listener) => listener,
        Err(error) if !required => {
            eprintln!(
                "SKIPPED: SEALANTD_REQUIRE_VSOCK is not 1 and AF_VSOCK is unavailable here \
                 ({error})"
            );
            return;
        }
        Err(error) => panic!("SEALANTD_REQUIRE_VSOCK=1 but AF_VSOCK is unavailable: {error}"),
    };
    let heads: Heads = Arc::default();
    let seen = Arc::clone(&heads);
    thread::spawn(move || {
        while let Ok((socket, _)) = listener.accept() {
            let mut stream = SocketStream(socket);
            answer(&mut stream, &seen, HEARTBEAT_OK);
            let _ = stream.0.shutdown(std::net::Shutdown::Write);
        }
    });

    let transport = ChannelTransport::verified().dial_via(Dial::Vsock { cid: 1, port });
    let registrar = HttpRegistrar::new(
        "http://mend:3106/channel",
        "session-token",
        TIMEOUT,
        &transport,
    )
    .expect("dialled");
    match registrar.lease_heartbeat(&HeartbeatRequest {
        worktree_id: "w".to_owned(),
        epoch: 1,
    }) {
        Ok(answer) => assert_eq!(answer.expires_in_secs, 30),
        Err(error) if !required => {
            eprintln!(
                "SKIPPED: SEALANTD_REQUIRE_VSOCK is not 1 and vsock loopback is unavailable \
                 here ({error})"
            );
            return;
        }
        Err(error) => panic!("SEALANTD_REQUIRE_VSOCK=1 but the vsock request failed: {error}"),
    }
    let heads = heads.lock().expect("heads");
    assert_eq!(host_headers(&heads[0]), ["mend:3106"], "{heads:?}");

    struct SocketStream(Socket);
    impl Read for SocketStream {
        fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
            (&self.0).read(buf)
        }
    }
    impl Write for SocketStream {
        fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
            (&self.0).write(buf)
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }
}
