//! Integration coverage for the secure WebSocket frontend (ADR-0013) next to the Unix socket.
//!
//! A throwaway PKI (rcgen) mints: a control-plane CA, a server certificate for `localhost`, a
//! `clientAuth` client certificate, a client certificate from an unrelated CA, and a
//! `serverAuth`-only certificate signed by the real CA (what a workspace can read from its own
//! TLS Secret). The daemon must accept exactly the first client and refuse every other shape
//! before any protocol byte is dispatched.

use std::net::SocketAddr;
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

use futures::{SinkExt, StreamExt};
use rcgen::{
    BasicConstraints, CertificateParams, DnType, ExtendedKeyUsagePurpose, IsCa, KeyPair,
    KeyUsagePurpose,
};
use rustls_pki_types::{CertificateDer, PrivateKeyDer, ServerName};
use sealant_control::{CONTROL_PATH, ConnHandle, ControlService, WssConfig, WssListener};
use sealant_protocol::{
    ChannelId, ClientMessage, Command, CommandResult, ControlError, ControlErrorCode,
    ControlRequest, ControlResponse, EventEnvelope, RequestId, ResponseOutcome, ServerMessage,
    StreamFrame, StreamPayload, decode_server, encode_client,
};
use tokio::io::AsyncWriteExt;
use tokio::sync::{broadcast, mpsc, watch};
use tokio_rustls::TlsConnector;
use tokio_tungstenite::tungstenite::Message;
use tokio_tungstenite::tungstenite::client::IntoClientRequest;

const MAX: u32 = 64 * 1024;

// ---------------------------------------------------------------------------------------------
// Mock service: health + an echo channel (same shape as the server.rs unit tests).
// ---------------------------------------------------------------------------------------------

struct EchoService {
    events: broadcast::Sender<EventEnvelope>,
}

impl ControlService for EchoService {
    async fn handle_on_connection(
        &self,
        request: ControlRequest,
        conn: &ConnHandle,
    ) -> ControlResponse {
        match request.command {
            Command::RuntimeHealth => {
                ControlResponse::ok_with(request.request_id, CommandResult::Accepted)
            }
            Command::ListSessions => {
                // "Open" an echo channel named after the request id.
                let channel = ChannelId::new(format!("chan_{}", request.request_id.as_str()));
                let (in_tx, mut in_rx) = mpsc::channel::<StreamPayload>(8);
                conn.register_channel(channel.clone(), in_tx).await;
                let out_tx = conn.out_tx.clone();
                tokio::spawn(async move {
                    let mut seq = 0u64;
                    while let Some(payload) = in_rx.recv().await {
                        match payload {
                            StreamPayload::Data { data } => {
                                let frame = StreamFrame::data(channel.clone(), seq, data);
                                seq += 1;
                                if out_tx.send(ServerMessage::Stream(frame)).await.is_err() {
                                    break;
                                }
                            }
                            StreamPayload::End(_) => break,
                            StreamPayload::WindowUpdate { .. } => {}
                        }
                    }
                });
                ControlResponse::ok_with(request.request_id, CommandResult::Accepted)
            }
            _ => ControlResponse::error(
                request.request_id,
                ControlError::unknown_command("unsupported in mock"),
            ),
        }
    }
    fn subscribe_events(&self) -> broadcast::Receiver<EventEnvelope> {
        self.events.subscribe()
    }
    fn max_frame_bytes(&self) -> u32 {
        MAX
    }
}

fn response_error(response: &ControlResponse) -> Option<&ControlError> {
    match &response.outcome {
        ResponseOutcome::Ok { .. } => None,
        ResponseOutcome::Error { error } => Some(error),
    }
}

// ---------------------------------------------------------------------------------------------
// Throwaway PKI
// ---------------------------------------------------------------------------------------------

struct Pki {
    dir: tempfile::TempDir,
    client_pem: String,
    client_key_pem: String,
    foreign_client_pem: String,
    foreign_client_key_pem: String,
    server_only_pem: String,
    server_only_key_pem: String,
    ca_pem: String,
}

fn ca(name: &str) -> (rcgen::Certificate, KeyPair) {
    let key = KeyPair::generate().expect("ca key");
    let mut params = CertificateParams::new(Vec::<String>::new()).expect("params");
    params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    params.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];
    params.distinguished_name.push(DnType::CommonName, name);
    let cert = params.self_signed(&key).expect("ca cert");
    (cert, key)
}

fn leaf(
    issuer: &(rcgen::Certificate, KeyPair),
    sans: Vec<String>,
    usages: Vec<ExtendedKeyUsagePurpose>,
    cn: &str,
) -> (String, String) {
    let key = KeyPair::generate().expect("leaf key");
    let mut params = CertificateParams::new(sans).expect("params");
    params.extended_key_usages = usages;
    params.key_usages = vec![KeyUsagePurpose::DigitalSignature];
    params.distinguished_name.push(DnType::CommonName, cn);
    let cert = params
        .signed_by(&key, &issuer.0, &issuer.1)
        .expect("sign leaf");
    (cert.pem(), key.serialize_pem())
}

fn pki() -> Pki {
    let dir = tempfile::tempdir().expect("tempdir");
    let control_ca = ca("sealant control-plane CA");
    let foreign_ca = ca("someone else's CA");

    let (server_pem, server_key_pem) = leaf(
        &control_ca,
        vec!["localhost".to_owned()],
        vec![ExtendedKeyUsagePurpose::ServerAuth],
        "ws-run-1.ns.svc",
    );
    let (client_pem, client_key_pem) = leaf(
        &control_ca,
        vec!["sealant-worker".to_owned()],
        vec![ExtendedKeyUsagePurpose::ClientAuth],
        "sealant-worker",
    );
    let (foreign_client_pem, foreign_client_key_pem) = leaf(
        &foreign_ca,
        vec!["intruder".to_owned()],
        vec![ExtendedKeyUsagePurpose::ClientAuth],
        "intruder",
    );
    // The workspace's own server certificate: same CA, serverAuth only.
    let (server_only_pem, server_only_key_pem) = leaf(
        &control_ca,
        vec!["ws-run-2.ns.svc".to_owned()],
        vec![ExtendedKeyUsagePurpose::ServerAuth],
        "ws-run-2.ns.svc",
    );

    let ca_pem = control_ca.0.pem();
    std::fs::write(dir.path().join("ca.pem"), &ca_pem).expect("write ca");
    std::fs::write(dir.path().join("server.pem"), server_pem).expect("write server");
    std::fs::write(dir.path().join("server.key"), server_key_pem).expect("write key");

    Pki {
        dir,
        client_pem,
        client_key_pem,
        foreign_client_pem,
        foreign_client_key_pem,
        server_only_pem,
        server_only_key_pem,
        ca_pem,
    }
}

fn config_for(pki: &Pki) -> WssConfig {
    let mut config = WssConfig::new(
        "127.0.0.1:0".parse().expect("addr"),
        pki.dir.path().join("server.pem"),
        pki.dir.path().join("server.key"),
        pki.dir.path().join("ca.pem"),
    );
    config.handshake_timeout = Duration::from_secs(5);
    config
}

// ---------------------------------------------------------------------------------------------
// Server + client helpers
// ---------------------------------------------------------------------------------------------

async fn start(
    service: Arc<EchoService>,
    config: WssConfig,
) -> (SocketAddr, watch::Sender<bool>, tokio::task::JoinHandle<()>) {
    let listener = WssListener::bind(&config).await.expect("bind");
    let addr = listener.local_addr().expect("addr");
    let (tx, rx) = watch::channel(false);
    let task = tokio::spawn(listener.serve(service, rx));
    (addr, tx, task)
}

fn pem_certs(pem: &str) -> Vec<CertificateDer<'static>> {
    rustls_pemfile::certs(&mut pem.as_bytes())
        .collect::<Result<_, _>>()
        .expect("certs")
}

fn pem_key(pem: &str) -> PrivateKeyDer<'static> {
    rustls_pemfile::private_key(&mut pem.as_bytes())
        .expect("key")
        .expect("key present")
}

type Ws =
    tokio_tungstenite::WebSocketStream<tokio_rustls::client::TlsStream<tokio::net::TcpStream>>;

/// TLS + upgrade. `identity` is the (cert, key) PEM pair to present, or `None` for anonymous.
async fn connect(
    addr: SocketAddr,
    ca_pem: &str,
    identity: Option<(&str, &str)>,
    path: &str,
) -> Result<Ws, String> {
    let mut roots = rustls::RootCertStore::empty();
    for cert in pem_certs(ca_pem) {
        roots.add(cert).expect("root");
    }
    let builder = rustls::ClientConfig::builder().with_root_certificates(roots);
    let client_config = match identity {
        Some((cert, key)) => builder
            .with_client_auth_cert(pem_certs(cert), pem_key(key))
            .expect("client auth"),
        None => builder.with_no_client_auth(),
    };
    let connector = TlsConnector::from(Arc::new(client_config));
    let tcp = tokio::net::TcpStream::connect(addr)
        .await
        .map_err(|e| format!("tcp: {e}"))?;
    let tls = connector
        .connect(ServerName::try_from("localhost").expect("name"), tcp)
        .await
        .map_err(|e| format!("tls: {e}"))?;
    let request = format!("wss://localhost:{}{}", addr.port(), path)
        .into_client_request()
        .expect("request");
    let (ws, _) = tokio_tungstenite::client_async(request, tls)
        .await
        .map_err(|e| format!("upgrade: {e}"))?;
    Ok(ws)
}

fn framed(body: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(body.len() + 4);
    out.extend_from_slice(&u32::try_from(body.len()).expect("len").to_be_bytes());
    out.extend_from_slice(body);
    out
}

async fn send(ws: &mut Ws, message: &ClientMessage) {
    let body = encode_client(message);
    ws.send(Message::Binary(framed(&body).into()))
        .await
        .expect("send");
}

/// Read binary messages until one full length-prefixed frame is available; returns the body.
async fn recv(ws: &mut Ws, buffer: &mut Vec<u8>) -> Option<ServerMessage> {
    loop {
        if buffer.len() >= 4 {
            let len = u32::from_be_bytes([buffer[0], buffer[1], buffer[2], buffer[3]]) as usize;
            if buffer.len() >= 4 + len {
                let body: Vec<u8> = buffer.drain(..4 + len).skip(4).collect();
                return Some(decode_server(&body).expect("decode"));
            }
        }
        match ws.next().await {
            Some(Ok(Message::Binary(bytes))) => buffer.extend_from_slice(&bytes),
            Some(Ok(Message::Close(_))) | None => return None,
            Some(Ok(_)) => {}
            Some(Err(_)) => return None,
        }
    }
}

async fn recv_response(ws: &mut Ws, buffer: &mut Vec<u8>) -> ControlResponse {
    loop {
        match recv(ws, buffer).await.expect("message before close") {
            ServerMessage::Response(response) => return response,
            ServerMessage::Event(_) | ServerMessage::Stream(_) => {}
        }
    }
}

fn health(id: &str) -> ClientMessage {
    ClientMessage::Request(ControlRequest::new(
        RequestId::new(id),
        Command::RuntimeHealth,
    ))
}

fn service() -> Arc<EchoService> {
    let (events, _) = broadcast::channel(16);
    Arc::new(EchoService { events })
}

/// True when the connection attempt never yields a dispatched response.
async fn never_dispatches(attempt: Result<Ws, String>, request_id: &str) -> bool {
    match attempt {
        Err(_) => true,
        // rustls may surface the server's alert only on the first read/write.
        Ok(mut ws) => {
            let _ = ws
                .send(Message::Binary(
                    framed(&encode_client(&health(request_id))).into(),
                ))
                .await;
            let mut buffer = Vec::new();
            recv(&mut ws, &mut buffer).await.is_none()
        }
    }
}

// ---------------------------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------------------------

#[tokio::test]
async fn authenticated_client_gets_the_same_protocol() {
    let pki = pki();
    let (addr, shutdown, task) = start(service(), config_for(&pki)).await;

    let mut ws = connect(
        addr,
        &pki.ca_pem,
        Some((&pki.client_pem, &pki.client_key_pem)),
        CONTROL_PATH,
    )
    .await
    .expect("connect");
    let mut buffer = Vec::new();
    send(&mut ws, &health("req_1")).await;
    let response = recv_response(&mut ws, &mut buffer).await;
    assert_eq!(response.request_id, RequestId::new("req_1"));
    assert!(
        response_error(&response).is_none(),
        "health must succeed: {response:?}"
    );

    let _ = shutdown.send(true);
    task.await.expect("serve task");
}

#[tokio::test]
async fn anonymous_client_is_rejected_at_the_handshake() {
    let pki = pki();
    let (addr, shutdown, task) = start(service(), config_for(&pki)).await;

    let attempt = connect(addr, &pki.ca_pem, None, CONTROL_PATH).await;
    assert!(
        never_dispatches(attempt, "req_anon").await,
        "anonymous client must never reach the dispatcher"
    );

    let _ = shutdown.send(true);
    task.await.expect("serve task");
}

#[tokio::test]
async fn client_certificate_from_another_ca_is_rejected() {
    let pki = pki();
    let (addr, shutdown, task) = start(service(), config_for(&pki)).await;

    let attempt = connect(
        addr,
        &pki.ca_pem,
        Some((&pki.foreign_client_pem, &pki.foreign_client_key_pem)),
        CONTROL_PATH,
    )
    .await;
    assert!(never_dispatches(attempt, "req_foreign").await);

    let _ = shutdown.send(true);
    task.await.expect("serve task");
}

#[tokio::test]
async fn workspace_server_certificate_cannot_authenticate_as_a_client() {
    let pki = pki();
    let (addr, shutdown, task) = start(service(), config_for(&pki)).await;

    // Same CA as the trusted client, but serverAuth-only: the EKU check must refuse it.
    let attempt = connect(
        addr,
        &pki.ca_pem,
        Some((&pki.server_only_pem, &pki.server_only_key_pem)),
        CONTROL_PATH,
    )
    .await;
    assert!(
        never_dispatches(attempt, "req_ws_cert").await,
        "a serverAuth-only certificate must not pass client verification"
    );

    let _ = shutdown.send(true);
    task.await.expect("serve task");
}

#[tokio::test]
async fn wrong_path_is_refused() {
    let pki = pki();
    let (addr, shutdown, task) = start(service(), config_for(&pki)).await;

    let attempt = connect(
        addr,
        &pki.ca_pem,
        Some((&pki.client_pem, &pki.client_key_pem)),
        "/not-control",
    )
    .await;
    let error = attempt.expect_err("upgrade must fail");
    assert!(
        error.contains("404"),
        "expected a 404 refusal, got: {error}"
    );

    let _ = shutdown.send(true);
    task.await.expect("serve task");
}

#[tokio::test]
async fn multiple_clients_stream_independent_channels() {
    let pki = pki();
    let (addr, shutdown, task) = start(service(), config_for(&pki)).await;

    let mut handles = Vec::new();
    for n in 0..4u8 {
        let ca = pki.ca_pem.clone();
        let cert = pki.client_pem.clone();
        let key = pki.client_key_pem.clone();
        handles.push(tokio::spawn(async move {
            let mut ws = connect(addr, &ca, Some((&cert, &key)), CONTROL_PATH)
                .await
                .expect("connect");
            let mut buffer = Vec::new();
            let id = format!("open_{n}");
            send(
                &mut ws,
                &ClientMessage::Request(ControlRequest::new(
                    RequestId::new(id.clone()),
                    Command::ListSessions,
                )),
            )
            .await;
            let response = recv_response(&mut ws, &mut buffer).await;
            assert!(response_error(&response).is_none());
            let channel = ChannelId::new(format!("chan_{id}"));
            for i in 0..3u8 {
                let payload = vec![n * 10 + i; 1024];
                send(
                    &mut ws,
                    &ClientMessage::Stream(StreamFrame::data(
                        channel.clone(),
                        u64::from(i),
                        payload,
                    )),
                )
                .await;
            }
            let mut got = 0u8;
            while got < 3 {
                if let ServerMessage::Stream(StreamFrame {
                    channel_id,
                    seq,
                    payload: StreamPayload::Data { data },
                }) = recv(&mut ws, &mut buffer).await.expect("frame")
                {
                    assert_eq!(channel_id, channel);
                    assert_eq!(seq, u64::from(got));
                    assert_eq!(data, vec![n * 10 + got; 1024].into());
                    got += 1;
                }
            }
            ws.close(None).await.ok();
        }));
    }
    for handle in handles {
        handle.await.expect("client");
    }

    let _ = shutdown.send(true);
    task.await.expect("serve task");
}

#[tokio::test]
async fn oversized_frame_is_reported_then_closed() {
    let pki = pki();
    let (addr, shutdown, task) = start(service(), config_for(&pki)).await;

    let mut ws = connect(
        addr,
        &pki.ca_pem,
        Some((&pki.client_pem, &pki.client_key_pem)),
        CONTROL_PATH,
    )
    .await
    .expect("connect");
    // A length prefix claiming more than max_frame_bytes, in a message that itself fits.
    let mut bogus = (MAX + 1).to_be_bytes().to_vec();
    bogus.extend_from_slice(&[0u8; 16]);
    ws.send(Message::Binary(bogus.into())).await.expect("send");

    let mut buffer = Vec::new();
    let mut saw_error = false;
    while let Some(message) = recv(&mut ws, &mut buffer).await {
        if let ServerMessage::Response(response) = message
            && let Some(error) = response_error(&response)
        {
            assert_eq!(error.code, ControlErrorCode::FrameTooLarge);
            saw_error = true;
        }
    }
    assert!(
        saw_error,
        "daemon must answer an oversized frame before closing"
    );

    let _ = shutdown.send(true);
    task.await.expect("serve task");
}

#[tokio::test]
async fn message_larger_than_the_cap_closes_without_dispatch() {
    let pki = pki();
    let (addr, shutdown, task) = start(service(), config_for(&pki)).await;

    let mut ws = connect(
        addr,
        &pki.ca_pem,
        Some((&pki.client_pem, &pki.client_key_pem)),
        CONTROL_PATH,
    )
    .await
    .expect("connect");
    let huge = vec![0u8; MAX as usize + 4 + 1];
    // Either the send fails (peer closed) or the read sees the close — both are "refused".
    let _ = ws.send(Message::Binary(huge.into())).await;
    let mut buffer = Vec::new();
    let closed = tokio::time::timeout(Duration::from_secs(5), async {
        while recv(&mut ws, &mut buffer).await.is_some() {}
    })
    .await;
    assert!(
        closed.is_ok(),
        "connection must close after an over-cap message"
    );

    let _ = shutdown.send(true);
    task.await.expect("serve task");
}

#[tokio::test]
async fn shutdown_closes_listener_and_live_connections() {
    let pki = pki();
    let (addr, shutdown, task) = start(service(), config_for(&pki)).await;

    let mut ws = connect(
        addr,
        &pki.ca_pem,
        Some((&pki.client_pem, &pki.client_key_pem)),
        CONTROL_PATH,
    )
    .await
    .expect("connect");
    let mut buffer = Vec::new();
    send(&mut ws, &health("req_pre")).await;
    let _ = recv_response(&mut ws, &mut buffer).await;

    let _ = shutdown.send(true);
    tokio::time::timeout(Duration::from_secs(5), task)
        .await
        .expect("serve task ends")
        .expect("join");

    // The live connection was torn down...
    let ended = tokio::time::timeout(Duration::from_secs(5), async {
        while recv(&mut ws, &mut buffer).await.is_some() {}
    })
    .await;
    assert!(ended.is_ok(), "client must observe the close");
    // ...and the listener is gone.
    assert!(tokio::net::TcpStream::connect(addr).await.is_err());
}

#[tokio::test]
async fn connection_limit_refuses_excess_clients() {
    let pki = pki();
    let mut config = config_for(&pki);
    config.max_connections = 1;
    let (addr, shutdown, task) = start(service(), config).await;

    let mut first = connect(
        addr,
        &pki.ca_pem,
        Some((&pki.client_pem, &pki.client_key_pem)),
        CONTROL_PATH,
    )
    .await
    .expect("first");
    let mut buffer = Vec::new();
    send(&mut first, &health("req_first")).await;
    let _ = recv_response(&mut first, &mut buffer).await;

    let second = connect(
        addr,
        &pki.ca_pem,
        Some((&pki.client_pem, &pki.client_key_pem)),
        CONTROL_PATH,
    )
    .await;
    assert!(
        never_dispatches(second, "req_second").await,
        "second client must be refused while the first holds the permit"
    );

    let _ = shutdown.send(true);
    task.await.expect("serve task");
}

#[tokio::test]
async fn missing_tls_material_is_a_bind_error() {
    let pki = pki();
    let mut config = config_for(&pki);
    config.cert_path = Path::new("/nonexistent/server.pem").to_path_buf();
    let error = WssListener::bind(&config).await.expect_err("bind fails");
    assert!(error.to_string().contains("wss certificate"));
}

#[test]
fn from_parts_is_off_without_listen_and_strict_with_it() {
    assert!(
        WssConfig::from_parts(None, Some("/c"), Some("/k"), Some("/ca"), None)
            .expect("ok")
            .is_none()
    );
    assert!(
        WssConfig::from_parts(Some("0.0.0.0:7443"), None, Some("/k"), Some("/ca"), None).is_err()
    );
    assert!(
        WssConfig::from_parts(
            Some("not-an-addr"),
            Some("/c"),
            Some("/k"),
            Some("/ca"),
            None
        )
        .is_err()
    );
    assert!(
        WssConfig::from_parts(
            Some("0.0.0.0:7443"),
            Some("/c"),
            Some("/k"),
            Some("/ca"),
            Some("0")
        )
        .is_err()
    );
    let config = WssConfig::from_parts(
        Some("0.0.0.0:7443"),
        Some("/c"),
        Some("/k"),
        Some("/ca"),
        Some("8"),
    )
    .expect("ok")
    .expect("some");
    assert_eq!(config.max_connections, 8);
    assert_eq!(config.listen.port(), 7443);
}

// ---------------------------------------------------------------------------------------------
// Unix socket regression: the existing frontend still serves the same protocol.
// ---------------------------------------------------------------------------------------------

#[tokio::test]
async fn unix_socket_frontend_still_serves_health() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("control.sock");
    let (tx, rx) = watch::channel(false);
    let serve_path = path.clone();
    let task = tokio::spawn(async move {
        sealant_control::serve_unix(service(), &serve_path, Vec::new(), rx).await
    });

    let mut stream = None;
    for _ in 0..50 {
        if let Ok(s) = tokio::net::UnixStream::connect(&path).await {
            stream = Some(s);
            break;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    let mut stream = stream.expect("socket accepts");
    let body = encode_client(&health("req_unix"));
    stream.write_all(&framed(&body)).await.expect("write");
    let frame = sealant_control::read_frame(&mut stream, MAX)
        .await
        .expect("read")
        .expect("frame");
    match decode_server(&frame).expect("decode") {
        ServerMessage::Response(response) => {
            assert_eq!(response.request_id, RequestId::new("req_unix"));
        }
        other => panic!("unexpected {other:?}"),
    }

    let _ = tx.send(true);
    task.await.expect("join").expect("serve");
    assert!(!path.exists(), "socket file is removed on shutdown");
}
