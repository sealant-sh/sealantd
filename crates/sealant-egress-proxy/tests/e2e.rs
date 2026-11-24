//! End-to-end: a real proxy, real upstreams on loopback, real rustls clients.

mod common;

use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr};
use std::time::Duration;

use common::*;
use futures::{SinkExt, StreamExt};
use serde_json::json;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio_tungstenite::tungstenite::Message;
use tokio_tungstenite::tungstenite::client::IntoClientRequest;

const A: u16 = 1;
const TXT: u16 = 16;
const AAAA: u16 = 28;
const SRV: u16 = 33;
const ANY: u16 = 255;
const NOERROR: u8 = 0;
const NXDOMAIN: u8 = 3;
const REFUSED: u8 = 5;

async fn echo_roundtrip(stream: &mut TcpStream, payload: &[u8]) -> bool {
    if stream.write_all(payload).await.is_err() {
        return false;
    }
    let mut buf = vec![0u8; payload.len()];
    matches!(
        tokio::time::timeout(Duration::from_secs(2), stream.read_exact(&mut buf)).await,
        Ok(Ok(_))
    ) && buf == payload
}

#[tokio::test]
async fn starts_closed_and_opens_once_a_policy_loads() {
    let echo = tcp_echo().await;
    let h = Harness::start(
        records(&[("echo.test", localhost())]),
        Ca::new("public").roots(),
    )
    .await;

    let health = h.health().await;
    assert_eq!(health["initialized"], false);

    // Explicit proxy: refused with 503.
    let (_, status) = connect_tunnel(h.explicit(), "echo.test", echo).await;
    assert_eq!(status, 503);
    // DNS: refused, and nothing reaches upstream.
    let (rcode, _) = dns_query(h.dns_addr(), "echo.test", A).await;
    assert_eq!(rcode, REFUSED);
    assert!(!h.dns.asked("echo.test"));
    // Transparent TCP: closed without relaying.
    let mut raw = TcpStream::connect(h.proxy.addrs.transparent_tcp.unwrap())
        .await
        .unwrap();
    raw.write_all(&proxy_v2(loopback(echo))).await.unwrap();
    assert!(closed_within(&mut raw, Duration::from_secs(2)).await);

    let (status, body) = h.put_policy(&base_policy(1)).await;
    assert_eq!(status, 200, "{body}");
    assert_eq!(h.health().await["initialized"], true);

    let (mut tunnel, status) = connect_tunnel(h.explicit(), "echo.test", echo).await;
    assert_eq!(status, 200);
    assert!(echo_roundtrip(&mut tunnel, b"ping").await);
    let (rcode, answers) = dns_query(h.dns_addr(), "echo.test", A).await;
    assert_eq!(rcode, NOERROR);
    assert_eq!(answers, vec![(A, vec![127, 0, 0, 1])]);
}

#[tokio::test]
async fn standard_dns_forwards_common_types_and_filters_blocked_addresses() {
    let v6: Ipv6Addr = "2606:4700::1111".parse().unwrap();
    let h = Harness::start(
        records(&[
            (
                "public.test",
                vec![
                    Rec::A(Ipv4Addr::new(93, 184, 216, 34)),
                    Rec::A(Ipv4Addr::new(10, 0, 0, 5)),
                    Rec::A(Ipv4Addr::new(169, 254, 169, 254)),
                    Rec::Aaaa(v6),
                    Rec::Aaaa("::ffff:192.168.1.1".parse().unwrap()),
                ],
            ),
            (
                "_mongodb._tcp.cluster.test",
                vec![Rec::Srv(27017, "shard.cluster.test")],
            ),
            ("cluster.test", vec![Rec::Txt("authSource=admin")]),
        ]),
        Ca::new("public").roots(),
    )
    .await;
    let mut policy = base_policy(1);
    policy["operatorAllowedPrivateCidrs"] = json!([]);
    assert_eq!(h.put_policy(&policy).await.0, 200);

    let (rcode, answers) = dns_query(h.dns_addr(), "public.test", A).await;
    assert_eq!(rcode, NOERROR);
    assert_eq!(answers, vec![(A, vec![93, 184, 216, 34])]);
    let (_, answers) = dns_query(h.dns_addr(), "public.test", AAAA).await;
    assert_eq!(answers, vec![(AAAA, v6.octets().to_vec())]);
    let (rcode, answers) = dns_query(h.dns_addr(), "_mongodb._tcp.cluster.test", SRV).await;
    assert_eq!(rcode, NOERROR);
    assert_eq!(answers.len(), 1);
    assert_eq!(&answers[0].1[4..6], &27017u16.to_be_bytes());
    let (_, answers) = dns_query_tcp(h.dns_addr(), "cluster.test", TXT).await;
    assert_eq!(answers, vec![(TXT, b"\x10authSource=admin".to_vec())]);
    let (rcode, _) = dns_query(h.dns_addr(), "public.test", ANY).await;
    assert_eq!(rcode, REFUSED);
    let (rcode, _) = dns_query(h.dns_addr(), "missing.test", A).await;
    assert_eq!(rcode, NXDOMAIN);
}

#[tokio::test]
async fn restricted_dns_answers_only_allowlisted_addresses() {
    let h = Harness::start(
        records(&[
            (
                "api.allowed.test",
                vec![
                    Rec::A(Ipv4Addr::new(93, 184, 216, 34)),
                    Rec::A(Ipv4Addr::new(192, 168, 0, 9)),
                ],
            ),
            ("exfil.attacker.test", vec![Rec::Txt("data")]),
        ]),
        Ca::new("public").roots(),
    )
    .await;
    let policy = json!({
        "mode": "restricted",
        "policyHash": "r1",
        "revocationWatermark": 1,
        "allowHosts": [{ "host": "api.allowed.test" }],
        "allowResources": [{ "name": "db", "host": "db-real.test", "port": 5432, "guestIp": "10.201.0.7" }],
    });
    assert_eq!(h.put_policy(&policy).await.0, 200);

    let (rcode, answers) = dns_query(h.dns_addr(), "api.allowed.test", A).await;
    assert_eq!(rcode, NOERROR);
    assert_eq!(
        answers,
        vec![(A, vec![93, 184, 216, 34])],
        "the private answer is filtered"
    );
    let (rcode, _) = dns_query(h.dns_addr(), "api.allowed.test", TXT).await;
    assert_eq!(rcode, REFUSED);
    let (rcode, _) = dns_query(h.dns_addr(), "api.allowed.test", SRV).await;
    assert_eq!(rcode, REFUSED);
    let (rcode, _) = dns_query(h.dns_addr(), "exfil.attacker.test", A).await;
    assert_eq!(rcode, REFUSED);
    let (rcode, _) = dns_query_tcp(h.dns_addr(), "exfil.attacker.test", TXT).await;
    assert_eq!(rcode, REFUSED);
    assert!(
        !h.dns.asked("exfil.attacker.test"),
        "refused names never reach upstream"
    );

    let (rcode, answers) = dns_query(h.dns_addr(), "db", A).await;
    assert_eq!(rcode, NOERROR);
    assert_eq!(answers, vec![(A, vec![10, 201, 0, 7])]);
    let (rcode, answers) = dns_query(h.dns_addr(), "db", AAAA).await;
    assert_eq!(rcode, NOERROR);
    assert!(answers.is_empty());
}

#[tokio::test]
async fn explicit_proxy_relays_plain_http_and_refuses_blocked_destinations() {
    let (port, seen) = http_echo().await;
    let h = Harness::start(
        records(&[("web.test", localhost())]),
        Ca::new("public").roots(),
    )
    .await;
    assert_eq!(h.put_policy(&base_policy(1)).await.0, 200);

    let mut stream = TcpStream::connect(h.explicit()).await.unwrap();
    let req = format!(
        "GET http://web.test:{port}/hello?x=1 HTTP/1.1\r\nHost: web.test:{port}\r\nProxy-Connection: keep-alive\r\nAuthorization: Bearer {PLACEHOLDER}\r\n\r\n"
    );
    let (status, body) = http_exchange(&mut stream, &req).await.unwrap();
    assert_eq!(status, 200);
    assert!(body.starts_with("GET /hello?x=1 HTTP/1.1\r\n"), "{body}");
    assert!(!body.to_ascii_lowercase().contains("proxy-connection"));
    // Plain HTTP never carries a substituted secret.
    assert!(seen.lock().unwrap()[0].contains(PLACEHOLDER));

    // Without the operator's loopback carve-out the same destination is blocked.
    let mut policy = base_policy(2);
    policy["operatorAllowedPrivateCidrs"] = json!([]);
    assert_eq!(h.put_policy(&policy).await.0, 200);
    let mut stream = TcpStream::connect(h.explicit()).await.unwrap();
    let (status, body) = http_exchange(&mut stream, &req).await.unwrap();
    assert_eq!(status, 403);
    assert!(body.contains("blocked:loopback"), "{body}");

    // Cloud metadata stays blocked even when the operator allows everything.
    policy["operatorAllowedPrivateCidrs"] = json!(["0.0.0.0/0", "::/0"]);
    policy["revocationWatermark"] = json!(3);
    assert_eq!(h.put_policy(&policy).await.0, 200);
    for target in [
        "169.254.169.254",
        "[::ffff:169.254.169.254]",
        "168.63.129.16",
    ] {
        let mut stream = TcpStream::connect(h.explicit()).await.unwrap();
        let req =
            format!("GET http://{target}/latest/meta-data/ HTTP/1.1\r\nHost: {target}\r\n\r\n");
        let (status, body) = http_exchange(&mut stream, &req).await.unwrap();
        assert_eq!(status, 403, "{target}: {body}");
    }
}

#[tokio::test]
async fn connect_passes_unbrokered_tls_through_and_checks_sni_against_the_connect_host() {
    let public = Ca::new("public");
    let (port, seen) = https_echo(public.server_config(&["other.test", "api.test"])).await;
    let h = Harness::start(
        records(&[("other.test", localhost()), ("api.test", localhost())]),
        public.roots(),
    )
    .await;
    let executor = Ca::new("executor");
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

    // Not a bindHost: passthrough, so the client sees the upstream's own certificate.
    let (tunnel, status) = connect_tunnel(h.explicit(), "other.test", port).await;
    assert_eq!(status, 200);
    let mut tls = tls_connect(tunnel, public.roots(), "other.test")
        .await
        .unwrap();
    let req = format!(
        "GET / HTTP/1.1\r\nHost: other.test\r\nAuthorization: Bearer {PLACEHOLDER}\r\n\r\n"
    );
    let (status, _) = http_exchange(&mut tls, &req).await.unwrap();
    assert_eq!(status, 200);
    assert!(
        seen.lock().unwrap()[0].contains(PLACEHOLDER),
        "no substitution off bindHosts"
    );

    // A ClientHello naming another host than the CONNECT target is cut off.
    let (tunnel, status) = connect_tunnel(h.explicit(), "other.test", port).await;
    assert_eq!(status, 200);
    assert!(
        tls_connect(tunnel, public.roots(), "api.test")
            .await
            .is_err()
    );
}

#[tokio::test]
async fn brokered_secret_is_substituted_only_in_its_header_on_its_host() {
    let public = Ca::new("public");
    let executor = Ca::new("executor");
    let (port, seen) = https_echo(public.server_config(&["api.test", "other.test"])).await;
    let (evil_port, evil_seen) = https_echo(executor.server_config(&["evil.test"])).await;
    let h = Harness::start(
        records(&[
            ("api.test", localhost()),
            ("other.test", localhost()),
            ("evil.test", localhost()),
        ]),
        public.roots(),
    )
    .await;
    let policy = on_ports(
        &[("api.test", port), ("evil.test", evil_port)],
        with_broker(
            base_policy(1),
            &executor,
            json!([
                secret("s1", PLACEHOLDER, SECRET, "Authorization", &["api.test"]),
                secret(
                    "s2",
                    "mend_sec_evilevilevilevilevil",
                    "evil-real",
                    "Authorization",
                    &["evil.test"]
                ),
            ]),
        ),
    );
    assert_eq!(h.put_policy(&policy).await.0, 200);

    let (tunnel, status) = connect_tunnel(h.explicit(), "api.test", port).await;
    assert_eq!(status, 200);
    // The client trusts only the executor CA: the proxy presents a minted leaf for api.test.
    let mut tls = tls_connect(tunnel, executor.roots(), "api.test")
        .await
        .unwrap();

    let req = format!(
        "GET /v1/me?token={PLACEHOLDER} HTTP/1.1\r\nHost: API.test\r\nAuthorization: Bearer {PLACEHOLDER}\r\nX-Other: {PLACEHOLDER}\r\n\r\n"
    );
    let (status, _) = http_exchange(&mut tls, &req).await.unwrap();
    assert_eq!(status, 200);
    let head = seen.lock().unwrap().last().unwrap().clone();
    assert!(
        head.contains(&format!("Authorization: Bearer {SECRET}")),
        "{head}"
    );
    assert!(head.contains(&format!("X-Other: {PLACEHOLDER}")), "{head}");
    assert!(head.contains(&format!("token={PLACEHOLDER}")), "{head}");

    // Same connection, a request without the placeholder in the header: nothing injected.
    let req = format!("GET /v1/x HTTP/1.1\r\nHost: api.test\r\nX-Api-Key: {PLACEHOLDER}\r\n\r\n");
    let (status, _) = http_exchange(&mut tls, &req).await.unwrap();
    assert_eq!(status, 200);
    let head = seen.lock().unwrap().last().unwrap().clone();
    assert!(!head.contains(SECRET), "{head}");

    // SNI api.test, Host other.test: refused with 403 before anything goes upstream.
    let before = seen.lock().unwrap().len();
    let req = format!(
        "GET / HTTP/1.1\r\nHost: other.test\r\nAuthorization: Bearer {PLACEHOLDER}\r\n\r\n"
    );
    let (status, body) = http_exchange(&mut tls, &req).await.unwrap();
    assert_eq!(status, 403);
    assert!(body.contains("sni_host_mismatch"), "{body}");
    assert_eq!(seen.lock().unwrap().len(), before);

    // An upstream that presents a certificate from the executor CA is not trusted.
    let (tunnel, status) = connect_tunnel(h.explicit(), "evil.test", evil_port).await;
    assert_eq!(status, 200);
    let mut tls = tls_connect(tunnel, executor.roots(), "evil.test")
        .await
        .unwrap();
    let req = "GET / HTTP/1.1\r\nHost: evil.test\r\nAuthorization: Bearer mend_sec_evilevilevilevilevil\r\n\r\n";
    let (status, _) = http_exchange(&mut tls, req).await.unwrap();
    assert_eq!(status, 502);
    assert!(evil_seen.lock().unwrap().is_empty());

    // Telemetry names the secret ID and never its value.
    let (_, events) = h.admin("GET", "/v1/events?follow=0", None).await;
    let events = events.as_str().unwrap();
    assert!(events.contains("\"secretIds\":[\"s1\"]"), "{events}");
    assert!(events.contains("sni_host_mismatch"));
    assert!(!events.contains(SECRET) && !events.contains("evil-real"));
}

#[tokio::test]
async fn transparent_listeners_relay_by_the_proxy_v2_destination() {
    let public = Ca::new("public");
    let executor = Ca::new("executor");
    let (http_port, _) = http_echo().await;
    let (tls_port, seen) = https_echo(public.server_config(&["other.test", "api.test"])).await;
    let echo = tcp_echo().await;
    let h = Harness::start(
        records(&[("api.test", localhost()), ("db-real.test", localhost())]),
        public.roots(),
    )
    .await;
    let mut policy = on_ports(
        &[("api.test", tls_port)],
        with_broker(
            base_policy(1),
            &executor,
            json!([secret(
                "s1",
                PLACEHOLDER,
                SECRET,
                "Authorization",
                &["api.test"]
            )]),
        ),
    );
    policy["allowResources"] =
        json!([{ "name": "db", "host": "db-real.test", "port": echo, "guestIp": "10.201.0.7" }]);
    assert_eq!(h.put_policy(&policy).await.0, 200);
    let addrs = h.proxy.addrs.clone();

    // :15080 plain HTTP to the original destination.
    let mut s = TcpStream::connect(addrs.transparent_http.unwrap())
        .await
        .unwrap();
    s.write_all(&proxy_v2(loopback(http_port))).await.unwrap();
    let (status, body) = http_exchange(&mut s, "GET /t HTTP/1.1\r\nHost: web.test\r\n\r\n")
        .await
        .unwrap();
    assert_eq!(status, 200);
    assert!(body.starts_with("GET /t HTTP/1.1"));

    // :15443 passthrough for an unbrokered SNI.
    let mut s = TcpStream::connect(addrs.transparent_https.unwrap())
        .await
        .unwrap();
    s.write_all(&proxy_v2(loopback(tls_port))).await.unwrap();
    let mut tls = tls_connect(s, public.roots(), "other.test").await.unwrap();
    let (status, _) = http_exchange(&mut tls, "GET / HTTP/1.1\r\nHost: other.test\r\n\r\n")
        .await
        .unwrap();
    assert_eq!(status, 200);

    // :15443 for a bindHost is inspected; the guest's destination address is ignored and the
    // proxy's own DNS picks the upstream.
    let mut s = TcpStream::connect(addrs.transparent_https.unwrap())
        .await
        .unwrap();
    s.write_all(&proxy_v2(SocketAddr::new(
        "203.0.113.9".parse().unwrap(),
        tls_port,
    )))
    .await
    .unwrap();
    let mut tls = tls_connect(s, executor.roots(), "api.test").await.unwrap();
    let req =
        format!("GET / HTTP/1.1\r\nHost: api.test\r\nAuthorization: Bearer {PLACEHOLDER}\r\n\r\n");
    let (status, _) = http_exchange(&mut tls, &req).await.unwrap();
    assert_eq!(status, 200);
    assert!(seen.lock().unwrap().last().unwrap().contains(SECRET));

    // :15444 raw TCP to an allowed address; metadata is dropped.
    let mut s = TcpStream::connect(addrs.transparent_tcp.unwrap())
        .await
        .unwrap();
    s.write_all(&proxy_v2(loopback(echo))).await.unwrap();
    assert!(echo_roundtrip(&mut s, b"raw tcp").await);
    let mut s = TcpStream::connect(addrs.transparent_tcp.unwrap())
        .await
        .unwrap();
    s.write_all(&proxy_v2("169.254.169.254:80".parse().unwrap()))
        .await
        .unwrap();
    assert!(closed_within(&mut s, Duration::from_secs(2)).await);

    // :15100 synthetic resource address to the resource's real host and port.
    let mut s = TcpStream::connect(addrs.transparent_resource.unwrap())
        .await
        .unwrap();
    s.write_all(&proxy_v2(SocketAddr::new(
        "10.201.0.7".parse().unwrap(),
        echo,
    )))
    .await
    .unwrap();
    assert!(echo_roundtrip(&mut s, b"resource").await);
    let mut s = TcpStream::connect(addrs.transparent_resource.unwrap())
        .await
        .unwrap();
    s.write_all(&proxy_v2(SocketAddr::new(
        "10.201.0.8".parse().unwrap(),
        echo,
    )))
    .await
    .unwrap();
    assert!(closed_within(&mut s, Duration::from_secs(2)).await);
}

#[tokio::test]
async fn restricted_raw_tcp_needs_a_policy_mapped_host_and_port() {
    let echo = tcp_echo().await;
    let other = tcp_echo().await;
    let h = Harness::start(
        records(&[("echo.test", localhost())]),
        Ca::new("public").roots(),
    )
    .await;
    let policy = json!({
        "mode": "restricted",
        "policyHash": "r",
        "revocationWatermark": 1,
        "operatorAllowedPrivateCidrs": ["127.0.0.0/8"],
        "allowHosts": [{ "host": "echo.test", "ports": [echo] }],
    });
    assert_eq!(h.put_policy(&policy).await.0, 200);
    let tcp = h.proxy.addrs.transparent_tcp.unwrap();

    let mut s = TcpStream::connect(tcp).await.unwrap();
    s.write_all(&proxy_v2(loopback(echo))).await.unwrap();
    assert!(echo_roundtrip(&mut s, b"mapped").await);
    let mut s = TcpStream::connect(tcp).await.unwrap();
    s.write_all(&proxy_v2(loopback(other))).await.unwrap();
    assert!(closed_within(&mut s, Duration::from_secs(2)).await);
}

#[tokio::test]
async fn revoke_closes_a_live_websocket_before_it_answers() {
    let public = Ca::new("public");
    let executor = Ca::new("executor");
    let (port, auth_seen) = wss_echo(public.server_config(&["ws.test"])).await;
    let h = Harness::start(records(&[("ws.test", localhost())]), public.roots()).await;
    let policy = on_ports(
        &[("ws.test", port)],
        with_broker(
            base_policy(1),
            &executor,
            json!([secret(
                "ws-secret",
                WS_PLACEHOLDER,
                WS_SECRET,
                "Authorization",
                &["ws.test"]
            )]),
        ),
    );
    assert_eq!(h.put_policy(&policy).await.0, 200);

    let (tunnel, status) = connect_tunnel(h.explicit(), "ws.test", port).await;
    assert_eq!(status, 200);
    let tls = tls_connect(tunnel, executor.roots(), "ws.test")
        .await
        .unwrap();
    let mut request = format!("wss://ws.test:{port}/stream")
        .into_client_request()
        .unwrap();
    request.headers_mut().insert(
        "authorization",
        format!("Bearer {WS_PLACEHOLDER}").parse().unwrap(),
    );
    let (mut ws, response) = tokio_tungstenite::client_async(request, tls).await.unwrap();
    assert_eq!(response.status(), 101);
    assert_eq!(auth_seen.lock().unwrap()[0], format!("Bearer {WS_SECRET}"));

    ws.send(Message::text("hello")).await.unwrap();
    let echoed = tokio::time::timeout(Duration::from_secs(2), ws.next())
        .await
        .unwrap()
        .unwrap()
        .unwrap();
    assert_eq!(echoed.into_text().unwrap(), "hello");
    assert_eq!(h.health().await["activeConnections"], 1);

    let (status, body) = h
        .admin(
            "POST",
            "/v1/revoke",
            Some(&json!({ "revocationWatermark": 2, "revokeSecretIds": ["ws-secret"] })),
        )
        .await;
    assert_eq!(status, 200, "{body}");
    assert_eq!(body["closed"], 1);
    // By the time revoke answered, the stream was already gone from the registry...
    assert_eq!(h.health().await["activeConnections"], 0);
    // ...and the client sees the close at once.
    let next = tokio::time::timeout(Duration::from_millis(500), ws.next())
        .await
        .expect("closed promptly");
    assert!(!matches!(next, Some(Ok(Message::Text(_)))), "{next:?}");

    // A new connection to the host no longer carries the secret.
    let (tunnel, _) = connect_tunnel(h.explicit(), "ws.test", port).await;
    let tls = tls_connect(tunnel, public.roots(), "ws.test").await;
    assert!(
        tls.is_ok(),
        "now passthrough: the upstream's own certificate"
    );
}

#[tokio::test]
async fn lease_expiry_closes_brokered_streams_while_standard_ones_ride_through() {
    let public = Ca::new("public");
    let executor = Ca::new("executor");
    let (port, _) = https_echo(public.server_config(&["api.test"])).await;
    let echo = tcp_echo().await;
    let h = Harness::start(
        records(&[("api.test", localhost()), ("echo.test", localhost())]),
        public.roots(),
    )
    .await;
    let mut policy = on_ports(
        &[("api.test", port)],
        with_broker(
            base_policy(1),
            &executor,
            json!([secret(
                "s1",
                PLACEHOLDER,
                SECRET,
                "Authorization",
                &["api.test"]
            )]),
        ),
    );
    policy["leaseTtlSecs"] = json!(1);
    assert_eq!(h.put_policy(&policy).await.0, 200);

    let (tunnel, _) = connect_tunnel(h.explicit(), "api.test", port).await;
    let mut brokered = tls_connect(tunnel, executor.roots(), "api.test")
        .await
        .unwrap();
    let req =
        format!("GET / HTTP/1.1\r\nHost: api.test\r\nAuthorization: Bearer {PLACEHOLDER}\r\n\r\n");
    assert_eq!(http_exchange(&mut brokered, &req).await.unwrap().0, 200);
    let (mut public_stream, status) = connect_tunnel(h.explicit(), "echo.test", echo).await;
    assert_eq!(status, 200);
    assert!(echo_roundtrip(&mut public_stream, b"before").await);

    tokio::time::sleep(Duration::from_millis(1600)).await;

    assert!(
        closed_within(&mut brokered, Duration::from_secs(1)).await,
        "brokered stream closed"
    );
    assert!(
        echo_roundtrip(&mut public_stream, b"after").await,
        "standard stream alive"
    );
    let (_, status) = connect_tunnel(h.explicit(), "api.test", port).await;
    assert_eq!(status, 403, "new brokered connections refused");
    let health = h.health().await;
    assert_eq!(health["leaseExpired"], true);

    // A heartbeat renews the lease and brokered traffic flows again.
    let (status, _) = h
        .admin(
            "POST",
            "/v1/heartbeat",
            Some(&json!({ "revocationWatermark": 1 })),
        )
        .await;
    assert_eq!(status, 200);
    let (_, status) = connect_tunnel(h.explicit(), "api.test", port).await;
    assert_eq!(status, 200);
}

#[tokio::test]
async fn lease_expiry_closes_restricted_streams() {
    let echo = tcp_echo().await;
    let h = Harness::start(
        records(&[("echo.test", localhost())]),
        Ca::new("public").roots(),
    )
    .await;
    let policy = json!({
        "mode": "restricted",
        "policyHash": "r",
        "revocationWatermark": 1,
        "leaseTtlSecs": 1,
        "operatorAllowedPrivateCidrs": ["127.0.0.0/8"],
        "allowHosts": [{ "host": "echo.test", "ports": [echo] }],
    });
    assert_eq!(h.put_policy(&policy).await.0, 200);
    let (mut stream, status) = connect_tunnel(h.explicit(), "echo.test", echo).await;
    assert_eq!(status, 200);
    assert!(echo_roundtrip(&mut stream, b"x").await);
    let (_, status) = connect_tunnel(h.explicit(), "elsewhere.test", echo).await;
    assert_eq!(status, 403, "not allowlisted");

    tokio::time::sleep(Duration::from_millis(1600)).await;
    assert!(closed_within(&mut stream, Duration::from_secs(1)).await);
    let (_, status) = connect_tunnel(h.explicit(), "echo.test", echo).await;
    assert_eq!(status, 403);
    let (rcode, _) = dns_query(h.dns_addr(), "echo.test", A).await;
    assert_eq!(rcode, REFUSED, "restricted DNS fails closed too");
}

#[tokio::test]
async fn revocation_watermark_never_rolls_back() {
    let public = Ca::new("public");
    let executor = Ca::new("executor");
    let (port, _) = https_echo(public.server_config(&["api.test"])).await;
    let h = Harness::start(records(&[("api.test", localhost())]), public.roots()).await;
    let policy = |wm: u64| {
        on_ports(
            &[("api.test", port)],
            with_broker(
                base_policy(wm),
                &executor,
                json!([secret(
                    "s1",
                    PLACEHOLDER,
                    SECRET,
                    "Authorization",
                    &["api.test"]
                )]),
            ),
        )
    };
    assert_eq!(h.put_policy(&policy(5)).await.0, 200);
    let (status, body) = h.put_policy(&policy(4)).await;
    assert_eq!(status, 409);
    assert_eq!(body["error"], "watermark_rollback");
    let (status, _) = h
        .admin(
            "POST",
            "/v1/revoke",
            Some(&json!({ "revocationWatermark": 3, "revokeAll": true })),
        )
        .await;
    assert_eq!(status, 409);
    let (status, _) = h
        .admin(
            "POST",
            "/v1/heartbeat",
            Some(&json!({ "revocationWatermark": 4 })),
        )
        .await;
    assert_eq!(status, 409);
    let health = h.health().await;
    assert_eq!(health["revocationWatermark"], 5);
    assert_eq!(health["policyHash"], "hash-5");

    // A heartbeat naming a watermark the proxy has not seen keeps brokered traffic closed until
    // Sealant sends the policy at that watermark.
    let (status, body) = h
        .admin(
            "POST",
            "/v1/heartbeat",
            Some(&json!({ "revocationWatermark": 6 })),
        )
        .await;
    assert_eq!(status, 200);
    assert_eq!(body["resyncRequired"], true);
    let (_, status) = connect_tunnel(h.explicit(), "api.test", port).await;
    assert_eq!(status, 403);
    assert_eq!(h.put_policy(&policy(6)).await.0, 200);
    let (_, status) = connect_tunnel(h.explicit(), "api.test", port).await;
    assert_eq!(status, 200);

    // A revocation at 7 sticks: replaying the policy at 6 cannot bring the secret back.
    let (status, _) = h
        .admin(
            "POST",
            "/v1/revoke",
            Some(&json!({ "revocationWatermark": 7, "revokeSecretIds": ["s1"] })),
        )
        .await;
    assert_eq!(status, 200);
    assert_eq!(h.put_policy(&policy(6)).await.0, 409);
    assert_eq!(h.health().await["revocationWatermark"], 7);
}

#[tokio::test]
async fn a_policy_that_drops_a_secret_closes_its_streams() {
    let public = Ca::new("public");
    let executor = Ca::new("executor");
    let (port, _) = https_echo(public.server_config(&["api.test"])).await;
    let h = Harness::start(records(&[("api.test", localhost())]), public.roots()).await;
    let policy = on_ports(
        &[("api.test", port)],
        with_broker(
            base_policy(1),
            &executor,
            json!([secret(
                "s1",
                PLACEHOLDER,
                SECRET,
                "Authorization",
                &["api.test"]
            )]),
        ),
    );
    assert_eq!(h.put_policy(&policy).await.0, 200);
    let (tunnel, _) = connect_tunnel(h.explicit(), "api.test", port).await;
    let mut tls = tls_connect(tunnel, executor.roots(), "api.test")
        .await
        .unwrap();
    let req =
        format!("GET / HTTP/1.1\r\nHost: api.test\r\nAuthorization: Bearer {PLACEHOLDER}\r\n\r\n");
    assert_eq!(http_exchange(&mut tls, &req).await.unwrap().0, 200);

    let mut without = base_policy(1);
    without["executorCaCertPem"] = executor.cert_pem().into();
    without["executorCaKeyPem"] = executor.key_pem().into();
    let (status, body) = h.put_policy(&without).await;
    assert_eq!(status, 200);
    assert_eq!(body["closed"], 1);
    assert!(closed_within(&mut tls, Duration::from_millis(500)).await);
}

#[tokio::test]
async fn refuses_a_policy_whose_executor_ca_is_trusted_upstream() {
    let executor = Ca::new("executor");
    let h = Harness::start(records(&[]), executor.roots()).await;
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
    let (status, body) = h.put_policy(&policy).await;
    assert_eq!(status, 400);
    assert!(
        body["message"]
            .as_str()
            .unwrap()
            .contains("never be trusted upstream")
    );
    assert_eq!(h.health().await["initialized"], false);
}
