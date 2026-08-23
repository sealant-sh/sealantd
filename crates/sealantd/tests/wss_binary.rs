//! Binary-level check of the `--wss-listen` wiring (ADR-0013): the real daemon, started with the
//! Unix socket AND the WSS frontend, answers `runtime.health` over mutual TLS and still serves the
//! Unix socket. The PKI is throwaway (rcgen). `sealant-control`'s own tests cover the security
//! matrix in depth; this one proves the flags reach the listener.

use std::process::Stdio;
use std::sync::Arc;
use std::time::Duration;

use futures::{SinkExt, StreamExt};
use rcgen::{
    BasicConstraints, CertificateParams, DnType, ExtendedKeyUsagePurpose, IsCa, KeyPair,
    KeyUsagePurpose,
};
use rustls_pki_types::ServerName;
use sealant_protocol::{
    ClientMessage, Command, ControlRequest, RequestId, ResponseOutcome, ServerMessage,
    decode_server, encode_client,
};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio_rustls::TlsConnector;
use tokio_tungstenite::tungstenite::Message;
use tokio_tungstenite::tungstenite::client::IntoClientRequest;

fn framed(body: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(body.len() + 4);
    out.extend_from_slice(&u32::try_from(body.len()).expect("len").to_be_bytes());
    out.extend_from_slice(body);
    out
}

fn free_port() -> u16 {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind");
    listener.local_addr().expect("addr").port()
}

#[tokio::test]
async fn binary_serves_health_over_wss_and_unix_socket() {
    let dir = tempfile::tempdir().expect("tempdir");

    // Throwaway PKI.
    let ca_key = KeyPair::generate().expect("ca key");
    let mut ca_params = CertificateParams::new(Vec::<String>::new()).expect("params");
    ca_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    ca_params.key_usages = vec![KeyUsagePurpose::KeyCertSign];
    ca_params
        .distinguished_name
        .push(DnType::CommonName, "test CA");
    let ca_cert = ca_params.self_signed(&ca_key).expect("ca");

    let server_key = KeyPair::generate().expect("server key");
    let mut server_params = CertificateParams::new(vec!["localhost".to_owned()]).expect("params");
    server_params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth];
    let server_cert = server_params
        .signed_by(&server_key, &ca_cert, &ca_key)
        .expect("server cert");

    let client_key = KeyPair::generate().expect("client key");
    let mut client_params = CertificateParams::new(vec!["worker".to_owned()]).expect("params");
    client_params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ClientAuth];
    let client_cert = client_params
        .signed_by(&client_key, &ca_cert, &ca_key)
        .expect("client cert");

    let ca_path = dir.path().join("ca.pem");
    let cert_path = dir.path().join("server.pem");
    let key_path = dir.path().join("server.key");
    std::fs::write(&ca_path, ca_cert.pem()).expect("ca");
    std::fs::write(&cert_path, server_cert.pem()).expect("cert");
    std::fs::write(&key_path, server_key.serialize_pem()).expect("key");

    let port = free_port();
    let socket = dir.path().join("control.sock");
    let exe = env!("CARGO_BIN_EXE_sealantd");
    let mut child = tokio::process::Command::new(exe)
        .arg("--socket")
        .arg(&socket)
        .arg("--workspace")
        .arg(dir.path())
        .arg("--log-level")
        .arg("off")
        .arg("--wss-listen")
        .arg(format!("127.0.0.1:{port}"))
        .arg("--wss-cert")
        .arg(&cert_path)
        .arg("--wss-key")
        .arg(&key_path)
        .arg("--wss-client-ca")
        .arg(&ca_path)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("spawn sealantd");

    // Unix socket: still the readiness signal.
    let mut unix = None;
    for _ in 0..100 {
        if let Ok(stream) = tokio::net::UnixStream::connect(&socket).await {
            unix = Some(stream);
            break;
        }
        tokio::time::sleep(Duration::from_millis(25)).await;
    }
    let mut unix = unix.expect("unix socket accepts");
    let request = ClientMessage::Request(ControlRequest::new(
        RequestId::new("unix"),
        Command::RuntimeHealth,
    ));
    unix.write_all(&framed(&encode_client(&request)))
        .await
        .expect("write");
    let mut prefix = [0u8; 4];
    unix.read_exact(&mut prefix).await.expect("prefix");
    let mut body = vec![0u8; u32::from_be_bytes(prefix) as usize];
    unix.read_exact(&mut body).await.expect("body");
    match decode_server(&body).expect("decode") {
        ServerMessage::Response(response) => {
            assert_eq!(response.request_id, RequestId::new("unix"));
            assert!(matches!(response.outcome, ResponseOutcome::Ok { .. }));
        }
        other => panic!("unexpected {other:?}"),
    }

    // WSS with the client certificate.
    let mut roots = rustls::RootCertStore::empty();
    for cert in rustls_pemfile::certs(&mut ca_cert.pem().as_bytes()) {
        roots.add(cert.expect("cert")).expect("root");
    }
    let client_config = rustls::ClientConfig::builder()
        .with_root_certificates(roots)
        .with_client_auth_cert(
            rustls_pemfile::certs(&mut client_cert.pem().as_bytes())
                .collect::<Result<_, _>>()
                .expect("client certs"),
            rustls_pemfile::private_key(&mut client_key.serialize_pem().as_bytes())
                .expect("key")
                .expect("present"),
        )
        .expect("client config");
    let connector = TlsConnector::from(Arc::new(client_config));
    let tcp = tokio::net::TcpStream::connect(("127.0.0.1", port))
        .await
        .expect("tcp");
    let tls = connector
        .connect(ServerName::try_from("localhost").expect("name"), tcp)
        .await
        .expect("tls");
    let request = format!("wss://localhost:{port}/control")
        .into_client_request()
        .expect("request");
    let (mut ws, _) = tokio_tungstenite::client_async(request, tls)
        .await
        .expect("upgrade");

    let request = ClientMessage::Request(ControlRequest::new(
        RequestId::new("wss"),
        Command::RuntimeHealth,
    ));
    ws.send(Message::Binary(framed(&encode_client(&request)).into()))
        .await
        .expect("send");
    let mut buffer = Vec::new();
    let response = tokio::time::timeout(Duration::from_secs(10), async {
        loop {
            if buffer.len() >= 4 {
                let len = u32::from_be_bytes([buffer[0], buffer[1], buffer[2], buffer[3]]) as usize;
                if buffer.len() >= 4 + len {
                    let body: Vec<u8> = buffer.drain(..4 + len).skip(4).collect();
                    if let ServerMessage::Response(response) = decode_server(&body).expect("decode")
                    {
                        return response;
                    }
                    continue;
                }
            }
            if let Message::Binary(bytes) = ws.next().await.expect("message").expect("ok") {
                buffer.extend_from_slice(&bytes);
            }
        }
    })
    .await
    .expect("wss response");
    assert_eq!(response.request_id, RequestId::new("wss"));
    assert!(matches!(response.outcome, ResponseOutcome::Ok { .. }));

    child.kill().await.expect("kill");
    let _ = child.wait().await;
}

#[tokio::test]
async fn binary_refuses_partial_wss_configuration() {
    let exe = env!("CARGO_BIN_EXE_sealantd");
    let output = tokio::process::Command::new(exe)
        .arg("--workspace")
        .arg(std::env::temp_dir())
        .arg("--wss-listen")
        .arg("127.0.0.1:1")
        .output()
        .await
        .expect("run");
    assert!(!output.status.success(), "partial wss flags must fail fast");
}
