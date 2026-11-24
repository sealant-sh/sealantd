//! Request-ambiguity, port, tombstone, lease and keep-alive cases from the first review.

mod common;

use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use common::*;
use serde_json::{Value, json};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio_rustls::TlsAcceptor;

const REFUSED: u8 = 5;

fn brokered(watermark: u64, executor: &Ca, port: u16) -> Value {
    on_ports(
        &[("api.test", port)],
        with_broker(
            base_policy(watermark),
            executor,
            json!([secret(
                "s1",
                PLACEHOLDER,
                SECRET,
                "Authorization",
                &["api.test"]
            )]),
        ),
    )
}

/// A proxy brokering `s1` for api.test on the HTTPS echo's port.
async fn brokered_harness() -> (Harness, Ca, Ca, u16, Seen) {
    let public = Ca::new("public");
    let executor = Ca::new("executor");
    let (port, seen) = https_echo(public.server_config(&["api.test", "evil.test"])).await;
    let h = Harness::start(records(&[("api.test", localhost())]), public.roots()).await;
    assert_eq!(h.put_policy(&brokered(1, &executor, port)).await.0, 200);
    (h, public, executor, port, seen)
}

async fn brokered_request(
    h: &Harness,
    executor: &Ca,
    port: u16,
    request: &str,
) -> std::io::Result<(u16, String)> {
    let (tunnel, status) = connect_tunnel(h.explicit(), "api.test", port).await;
    assert_eq!(status, 200);
    let mut tls = tls_connect(tunnel, executor.roots(), "api.test").await?;
    http_exchange(&mut tls, request).await
}

#[tokio::test]
async fn inspected_requests_need_origin_form_and_one_host() {
    let (h, _public, executor, port, seen) = brokered_harness().await;
    for request in [
        format!(
            "GET HTTPS://evil.test/steal HTTP/1.1\r\nHost: api.test\r\nAuthorization: Bearer {PLACEHOLDER}\r\n\r\n"
        ),
        format!(
            "GET https://api.test/ok HTTP/1.1\r\nHost: api.test\r\nAuthorization: Bearer {PLACEHOLDER}\r\n\r\n"
        ),
        format!(
            "GET foo://evil.test/steal HTTP/1.1\r\nHost: api.test\r\nAuthorization: Bearer {PLACEHOLDER}\r\n\r\n"
        ),
        format!(
            "GET / HTTP/1.1\r\nHost: api.test\r\nHost: evil.test\r\nAuthorization: Bearer {PLACEHOLDER}\r\n\r\n"
        ),
        format!("GET / HTTP/1.1\r\nAuthorization: Bearer {PLACEHOLDER}\r\n\r\n"),
        format!(
            "GET / HTTP/1.1\r\nHost: api.test@evil.test\r\nAuthorization: Bearer {PLACEHOLDER}\r\n\r\n"
        ),
    ] {
        let (status, _) = brokered_request(&h, &executor, port, &request)
            .await
            .unwrap();
        assert_eq!(status, 400, "{request}");
    }
    assert!(seen.lock().unwrap().is_empty(), "nothing reached upstream");
}

#[tokio::test]
async fn a_head_ended_by_bare_line_feeds_is_refused() {
    let (h, _public, executor, port, seen) = brokered_harness().await;
    let request = "GET /a HTTP/1.1\nHost: api.test\n\nGET /b HTTP/1.1\r\nHost: api.test\r\n\r\n";
    let (status, _) = brokered_request(&h, &executor, port, request)
        .await
        .unwrap();
    assert_eq!(status, 400);
    assert!(seen.lock().unwrap().is_empty());
}

#[tokio::test]
async fn host_rules_bound_methods_and_paths_on_brokered_hosts() {
    let public = Ca::new("public");
    let executor = Ca::new("executor");
    let (port, seen) = https_echo(public.server_config(&["api.test"])).await;
    let h = Harness::start(records(&[("api.test", localhost())]), public.roots()).await;
    let mut policy = with_broker(
        base_policy(1),
        &executor,
        json!([secret(
            "s1",
            PLACEHOLDER,
            SECRET,
            "Authorization",
            &["api.test"]
        )]),
    );
    // No `inspectTls`: the brokered secret turns inspection on, and the host rule still applies.
    policy["allowHosts"] = json!([{ "host": "api.test", "ports": [port], "methods": ["GET"], "pathPrefixes": ["/v1/"] }]);
    assert_eq!(h.put_policy(&policy).await.0, 200);
    let auth = format!("Authorization: Bearer {PLACEHOLDER}");
    for (line, expected) in [
        ("POST /v1/x", 403),
        ("GET /v2/x", 403),
        ("GET /v1/..;/admin", 403),
        ("GET /v1/x", 200),
    ] {
        let request =
            format!("{line} HTTP/1.1\r\nHost: api.test\r\n{auth}\r\nContent-Length: 0\r\n\r\n");
        let (status, _) = brokered_request(&h, &executor, port, &request)
            .await
            .unwrap();
        assert_eq!(status, expected, "{line}");
    }
    let heads = seen.lock().unwrap().clone();
    assert_eq!(heads.len(), 1);
    assert!(heads[0].starts_with("GET /v1/x") && heads[0].contains(SECRET));
}

#[tokio::test]
async fn connect_to_a_brokered_host_on_an_unnamed_port_is_never_brokered() {
    let public = Ca::new("public");
    let executor = Ca::new("executor");
    let (port, seen) = https_echo(public.server_config(&["api.test"])).await;
    let h = Harness::start(records(&[("api.test", localhost())]), public.roots()).await;
    // Bound to api.test with no allowHosts entry: brokered on 443 only.
    let policy = with_broker(
        base_policy(1),
        &executor,
        json!([secret(
            "s1",
            PLACEHOLDER,
            SECRET,
            "Authorization",
            &["api.test"]
        )]),
    );
    assert_eq!(h.put_policy(&policy).await.0, 200);
    let (tunnel, status) = connect_tunnel(h.explicit(), "api.test", port).await;
    assert_eq!(status, 200);
    // Passed through: the client sees the upstream's own certificate, not a minted leaf.
    assert!(
        tls_connect(tunnel, executor.roots(), "api.test")
            .await
            .is_err()
    );
    let (tunnel, _) = connect_tunnel(h.explicit(), "api.test", port).await;
    let mut tls = tls_connect(tunnel, public.roots(), "api.test")
        .await
        .unwrap();
    let request =
        format!("GET / HTTP/1.1\r\nHost: api.test\r\nAuthorization: Bearer {PLACEHOLDER}\r\n\r\n");
    assert_eq!(http_exchange(&mut tls, &request).await.unwrap().0, 200);
    let heads = seen.lock().unwrap().clone();
    assert!(heads[0].contains(PLACEHOLDER) && !heads[0].contains(SECRET));
}

#[tokio::test]
async fn standard_host_vm_brokering_on_15443_and_revoked_hosts() {
    let public = Ca::new("public");
    let executor = Ca::new("executor");
    let (port, seen) = https_echo(public.server_config(&["api.test"])).await;
    let h = Harness::start(records(&[("api.test", localhost())]), public.roots()).await;
    assert_eq!(h.put_policy(&brokered(1, &executor, port)).await.0, 200);
    let https = h.proxy.addrs.transparent_https.unwrap();
    // The guest's destination address is ignored; the proxy resolves api.test itself.
    let guest_dst = SocketAddr::new("203.0.113.9".parse().unwrap(), port);

    let mut s = TcpStream::connect(https).await.unwrap();
    s.write_all(&proxy_v2(guest_dst)).await.unwrap();
    let mut tls = tls_connect(s, executor.roots(), "api.test").await.unwrap();
    let request =
        format!("GET / HTTP/1.1\r\nHost: api.test\r\nAuthorization: Bearer {PLACEHOLDER}\r\n\r\n");
    assert_eq!(http_exchange(&mut tls, &request).await.unwrap().0, 200);
    assert!(seen.lock().unwrap()[0].contains(SECRET));

    let (status, body) = h
        .admin(
            "POST",
            "/v1/revoke",
            Some(&json!({ "revocationWatermark": 2, "revokeHosts": ["api.test"] })),
        )
        .await;
    assert_eq!(status, 200, "{body}");
    assert_eq!(body["closed"], 1);
    assert!(closed_within(&mut tls, Duration::from_millis(500)).await);

    // Revoked in every mode: no new TLS, no DNS answer.
    let mut s = TcpStream::connect(https).await.unwrap();
    s.write_all(&proxy_v2(guest_dst)).await.unwrap();
    assert!(tls_connect(s, public.roots(), "api.test").await.is_err());
    let (rcode, _) = dns_query(h.dns_addr(), "api.test", 1).await;
    assert_eq!(rcode, REFUSED);
}

#[tokio::test]
async fn a_custom_inspected_tls_port_on_15444_is_brokered() {
    let public = Ca::new("public");
    let executor = Ca::new("executor");
    let (port, seen) = https_echo(public.server_config(&["api.test", "other.test"])).await;
    let h = Harness::start(records(&[("api.test", localhost())]), public.roots()).await;
    assert_eq!(h.put_policy(&brokered(1, &executor, port)).await.0, 200);
    let tcp = h.proxy.addrs.transparent_tcp.unwrap();

    // The bindHost on its configured port arrives at the general listener: brokered.
    let mut s = TcpStream::connect(tcp).await.unwrap();
    s.write_all(&proxy_v2(loopback(port))).await.unwrap();
    let mut tls = tls_connect(s, executor.roots(), "api.test").await.unwrap();
    let request =
        format!("GET / HTTP/1.1\r\nHost: api.test\r\nAuthorization: Bearer {PLACEHOLDER}\r\n\r\n");
    assert_eq!(http_exchange(&mut tls, &request).await.unwrap().0, 200);
    assert!(seen.lock().unwrap()[0].contains(SECRET));

    // Another SNI on the same port: the ClientHello is replayed into a raw splice.
    let mut s = TcpStream::connect(tcp).await.unwrap();
    s.write_all(&proxy_v2(loopback(port))).await.unwrap();
    let mut tls = tls_connect(s, public.roots(), "other.test").await.unwrap();
    let request = "GET / HTTP/1.1\r\nHost: other.test\r\n\r\n";
    assert_eq!(http_exchange(&mut tls, request).await.unwrap().0, 200);
}

#[tokio::test]
async fn a_policy_replayed_at_the_revoke_watermark_cannot_restore_what_was_revoked() {
    let public = Ca::new("public");
    let executor = Ca::new("executor");
    let (port, seen) = https_echo(public.server_config(&["api.test", "web.test"])).await;
    let h = Harness::start(
        records(&[("api.test", localhost()), ("web.test", localhost())]),
        public.roots(),
    )
    .await;
    assert_eq!(h.put_policy(&brokered(1, &executor, port)).await.0, 200);
    let (status, _) = h
        .admin(
            "POST",
            "/v1/revoke",
            Some(&json!({ "revocationWatermark": 1, "revokeSecretIds": ["s1"], "revokeHosts": ["web.test"] })),
        )
        .await;
    assert_eq!(status, 200);
    // The same pre-revoke policy again, at the same watermark (a retry).
    assert_eq!(h.put_policy(&brokered(1, &executor, port)).await.0, 200);

    let (tunnel, status) = connect_tunnel(h.explicit(), "api.test", port).await;
    assert_eq!(status, 200);
    let mut tls = tls_connect(tunnel, public.roots(), "api.test")
        .await
        .unwrap();
    let request =
        format!("GET / HTTP/1.1\r\nHost: api.test\r\nAuthorization: Bearer {PLACEHOLDER}\r\n\r\n");
    assert_eq!(http_exchange(&mut tls, &request).await.unwrap().0, 200);
    assert!(
        !seen
            .lock()
            .unwrap()
            .iter()
            .any(|head| head.contains(SECRET))
    );
    let (_, status) = connect_tunnel(h.explicit(), "web.test", port).await;
    assert_eq!(
        status, 403,
        "a revoked host stays revoked, even under Standard"
    );
}

#[tokio::test]
async fn a_restarted_proxy_enforces_the_tombstones_sealant_sends() {
    let public = Ca::new("public");
    let executor = Ca::new("executor");
    let (port, seen) = https_echo(public.server_config(&["api.test", "web.test"])).await;
    // A fresh proxy (a restart) loaded with the policy plus Sealant's durable tombstones.
    let h = Harness::start(
        records(&[("api.test", localhost()), ("web.test", localhost())]),
        public.roots(),
    )
    .await;
    let mut policy = brokered(5, &executor, port);
    policy["revokedSecretIds"] = json!(["s1"]);
    policy["revokedHosts"] = json!(["web.test"]);
    assert_eq!(h.put_policy(&policy).await.0, 200);

    let (tunnel, _) = connect_tunnel(h.explicit(), "api.test", port).await;
    let mut tls = tls_connect(tunnel, public.roots(), "api.test")
        .await
        .unwrap();
    let request =
        format!("GET / HTTP/1.1\r\nHost: api.test\r\nAuthorization: Bearer {PLACEHOLDER}\r\n\r\n");
    assert_eq!(http_exchange(&mut tls, &request).await.unwrap().0, 200);
    assert!(
        !seen
            .lock()
            .unwrap()
            .iter()
            .any(|head| head.contains(SECRET))
    );
    let (_, status) = connect_tunnel(h.explicit(), "web.test", port).await;
    assert_eq!(status, 403);
}

#[tokio::test]
async fn the_lease_is_capped_and_a_heartbeat_must_name_its_watermark() {
    let h = Harness::start(records(&[]), Ca::new("public").roots()).await;
    let mut policy = base_policy(1);
    policy["leaseTtlSecs"] = json!(300);
    assert_eq!(h.put_policy(&policy).await.0, 400);
    assert_eq!(h.put_policy(&base_policy(1)).await.0, 200);
    assert!(h.health().await["leaseRemainingMs"].as_u64().unwrap() <= 120_000);
    let (status, _) = h.admin("POST", "/v1/heartbeat", Some(&json!({}))).await;
    assert_eq!(status, 400);
    let (status, _) = h.admin("POST", "/v1/heartbeat", None).await;
    assert_eq!(status, 400);
    let (status, _) = h
        .admin(
            "POST",
            "/v1/heartbeat",
            Some(&json!({ "revocationWatermark": 1 })),
        )
        .await;
    assert_eq!(status, 200);
}

/// An upstream that keeps connections alive but closes them after 200 ms idle, as real servers
/// do. A client reusing its connection after that must still get answers.
#[tokio::test]
async fn a_kept_alive_client_survives_its_upstream_closing_while_idle() {
    let public = Ca::new("public");
    let executor = Ca::new("executor");
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let config = public.server_config(&["api.test"]);
    let accepted = Arc::new(AtomicUsize::new(0));
    let accepted2 = accepted.clone();
    tokio::spawn(async move {
        let acceptor = TlsAcceptor::from(config);
        while let Ok((stream, _)) = listener.accept().await {
            accepted2.fetch_add(1, Ordering::SeqCst);
            let acceptor = acceptor.clone();
            tokio::spawn(async move {
                let Ok(mut tls) = acceptor.accept(stream).await else {
                    return;
                };
                loop {
                    let mut head = Vec::new();
                    let mut byte = [0u8; 1];
                    let read = async {
                        while !head.ends_with(b"\r\n\r\n") {
                            match tls.read(&mut byte).await {
                                Ok(1) => head.push(byte[0]),
                                _ => return false,
                            }
                        }
                        true
                    };
                    if !matches!(
                        tokio::time::timeout(Duration::from_millis(200), read).await,
                        Ok(true)
                    ) {
                        let _ = tls.shutdown().await;
                        return;
                    }
                    let _ = tls
                        .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok")
                        .await;
                }
            });
        }
    });
    let h = Harness::start(records(&[("api.test", localhost())]), public.roots()).await;
    assert_eq!(h.put_policy(&brokered(1, &executor, port)).await.0, 200);
    let (tunnel, _) = connect_tunnel(h.explicit(), "api.test", port).await;
    let mut tls = tls_connect(tunnel, executor.roots(), "api.test")
        .await
        .unwrap();
    let request = format!(
        "POST /v1 HTTP/1.1\r\nHost: api.test\r\nAuthorization: Bearer {PLACEHOLDER}\r\nContent-Length: 0\r\n\r\n"
    );
    assert_eq!(http_exchange(&mut tls, &request).await.unwrap().0, 200);
    tokio::time::sleep(Duration::from_millis(700)).await;
    let second = http_exchange(&mut tls, &request).await;
    assert_eq!(second.as_ref().map(|r| r.0).ok(), Some(200), "{second:?}");
    assert_eq!(
        accepted.load(Ordering::SeqCst),
        2,
        "the proxy redialed once"
    );
}

#[tokio::test]
async fn restricted_plain_http_cannot_be_fronted_through_an_allowed_host() {
    let (http_port, seen) = http_echo().await;
    let h = Harness::start(
        records(&[("allowed.test", localhost())]),
        Ca::new("public").roots(),
    )
    .await;
    let policy = json!({
        "mode": "restricted",
        "policyHash": "r",
        "revocationWatermark": 1,
        "operatorAllowedPrivateCidrs": ["127.0.0.0/8"],
        "allowHosts": [{ "host": "allowed.test", "ports": [http_port] }],
    });
    assert_eq!(h.put_policy(&policy).await.0, 200);
    let http = h.proxy.addrs.transparent_http.unwrap();
    for request in [
        "GET / HTTP/1.1\r\nHost: allowed.test\r\nHost: evil.test\r\n\r\n",
        "GET http://evil.test/ HTTP/1.1\r\nHost: allowed.test\r\n\r\n",
        "GET / HTTP/1.1\r\n\r\n",
    ] {
        let mut s = TcpStream::connect(http).await.unwrap();
        s.write_all(&proxy_v2(loopback(http_port))).await.unwrap();
        let (status, _) = http_exchange(&mut s, request).await.unwrap();
        assert_eq!(status, 400, "{request}");
    }
    assert!(seen.lock().unwrap().is_empty());

    // Explicit proxy: a second Host header is refused too.
    let mut s = TcpStream::connect(h.explicit()).await.unwrap();
    let request = format!(
        "GET http://allowed.test:{http_port}/ HTTP/1.1\r\nHost: allowed.test:{http_port}\r\nHost: evil.test\r\n\r\n"
    );
    assert_eq!(http_exchange(&mut s, &request).await.unwrap().0, 400);

    let mut s = TcpStream::connect(http).await.unwrap();
    s.write_all(&proxy_v2(loopback(http_port))).await.unwrap();
    let (status, _) = http_exchange(&mut s, "GET /ok HTTP/1.1\r\nHost: allowed.test\r\n\r\n")
        .await
        .unwrap();
    assert_eq!(status, 200);
}
