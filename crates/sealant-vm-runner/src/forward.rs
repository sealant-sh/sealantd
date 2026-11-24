//! The unprivileged egress forwarders on `10.200.0.1` (§4.2 step 4). nftables redirects guest
//! traffic here; each forwarder relays it to `<name>-proxy`, which decides what may leave.
//!
//! - DNS (`:15053`, UDP and TCP): plain relay to the proxy's resolver.
//! - TCP (`:15080`, `:15443`, `:15444`, `:15100`): the guest's original destination is read with
//!   `SO_ORIGINAL_DST` and sent ahead of the stream in a PROXY protocol v2 header. A connection
//!   whose destination cannot be read is dropped, never relayed blind.

use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV4, SocketAddrV6};
use std::sync::Arc;
use std::time::Duration;

use tokio::io::AsyncWriteExt;
use tokio::net::{TcpListener, TcpStream, UdpSocket};
use tokio::sync::Semaphore;

use crate::proxy_v2;

/// How long one DNS query over UDP waits for the proxy's answer.
const DNS_TIMEOUT: Duration = Duration::from_secs(10);
/// DNS queries over UDP in flight at once; more are dropped (the guest resolver retries).
const DNS_IN_FLIGHT: usize = 256;
/// The largest DNS message over UDP (EDNS0 allows up to 64 KiB).
const DNS_MAX: usize = 65_535;
/// How long connecting to the proxy may take before the guest connection is dropped.
const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);

/// Reads the destination the guest dialled, before nftables redirected it here.
pub type OriginalDst = fn(&TcpStream) -> std::io::Result<SocketAddr>;

/// `SO_ORIGINAL_DST` (IPv4) or `IP6T_SO_ORIGINAL_DST` (IPv6) from conntrack's NAT record.
pub fn original_dst(stream: &TcpStream) -> std::io::Result<SocketAddr> {
    use nix::sys::socket::{getsockopt, sockopt};
    match stream.local_addr()? {
        SocketAddr::V4(_) => {
            let sin = getsockopt(stream, sockopt::OriginalDst)?;
            Ok(SocketAddr::V4(SocketAddrV4::new(
                Ipv4Addr::from(u32::from_be(sin.sin_addr.s_addr)),
                u16::from_be(sin.sin_port),
            )))
        }
        SocketAddr::V6(_) => {
            let sin6 = getsockopt(stream, sockopt::Ip6tOriginalDst)?;
            Ok(SocketAddr::V6(SocketAddrV6::new(
                Ipv6Addr::from(sin6.sin6_addr.s6_addr),
                u16::from_be(sin6.sin6_port),
                sin6.sin6_flowinfo,
                sin6.sin6_scope_id,
            )))
        }
    }
}

/// Accepts guest connections on `listener` and relays each to `upstream`, behind a PROXY v2
/// header naming the guest's source and its original destination. Runs until the listener fails.
pub async fn serve_tcp(
    listener: TcpListener,
    upstream: SocketAddr,
    lookup: OriginalDst,
) -> std::io::Result<()> {
    let local = listener.local_addr()?;
    loop {
        let (guest, peer) = listener.accept().await?;
        tokio::spawn(async move {
            if let Err(e) = relay_tcp(guest, peer, local, upstream, lookup).await {
                tracing::debug!(%peer, %local, "tcp relay ended: {e}");
            }
        });
    }
}

async fn relay_tcp(
    mut guest: TcpStream,
    peer: SocketAddr,
    local: SocketAddr,
    upstream: SocketAddr,
    lookup: OriginalDst,
) -> std::io::Result<()> {
    let dst = lookup(&guest)?;
    // Not redirected (the guest dialled the forwarder itself): there is no destination to name,
    // and relaying it would point the proxy at the runner.
    if dst == local {
        return Err(std::io::Error::other("connection was not redirected"));
    }
    let mut proxy = tokio::time::timeout(CONNECT_TIMEOUT, TcpStream::connect(upstream))
        .await
        .map_err(|_| std::io::Error::new(std::io::ErrorKind::TimedOut, "proxy connect"))??;
    proxy.set_nodelay(true)?;
    guest.set_nodelay(true)?;
    proxy.write_all(&proxy_v2::encode(peer, dst)).await?;
    tokio::io::copy_bidirectional(&mut guest, &mut proxy).await?;
    Ok(())
}

/// Relays DNS over TCP: each guest connection to one connection to the proxy's resolver.
pub async fn serve_dns_tcp(listener: TcpListener, upstream: SocketAddr) -> std::io::Result<()> {
    loop {
        let (mut guest, peer) = listener.accept().await?;
        tokio::spawn(async move {
            let result = async {
                let mut proxy = tokio::time::timeout(CONNECT_TIMEOUT, TcpStream::connect(upstream))
                    .await
                    .map_err(|_| std::io::Error::other("proxy connect timed out"))??;
                tokio::io::copy_bidirectional(&mut guest, &mut proxy).await
            }
            .await;
            if let Err(e) = result {
                tracing::debug!(%peer, "dns/tcp relay ended: {e}");
            }
        });
    }
}

/// Relays DNS over UDP: each query goes out on its own connected socket, so the answer that
/// comes back can only be the proxy's answer to that query.
pub async fn serve_dns_udp(socket: UdpSocket, upstream: SocketAddr) -> std::io::Result<()> {
    let socket = Arc::new(socket);
    let slots = Arc::new(Semaphore::new(DNS_IN_FLIGHT));
    let mut buf = vec![0u8; DNS_MAX];
    loop {
        let (len, peer) = socket.recv_from(&mut buf).await?;
        let Ok(permit) = Arc::clone(&slots).try_acquire_owned() else {
            tracing::debug!(%peer, "dns/udp: too many queries in flight, dropping one");
            continue;
        };
        let query = buf[..len].to_vec();
        let socket = Arc::clone(&socket);
        tokio::spawn(async move {
            let _permit = permit;
            if let Err(e) = relay_dns_query(&socket, peer, &query, upstream).await {
                tracing::debug!(%peer, "dns/udp query dropped: {e}");
            }
        });
    }
}

async fn relay_dns_query(
    socket: &UdpSocket,
    peer: SocketAddr,
    query: &[u8],
    upstream: SocketAddr,
) -> std::io::Result<()> {
    let bind: SocketAddr = match upstream {
        SocketAddr::V4(_) => (Ipv4Addr::UNSPECIFIED, 0).into(),
        SocketAddr::V6(_) => (Ipv6Addr::UNSPECIFIED, 0).into(),
    };
    let out = UdpSocket::bind(bind).await?;
    out.connect(upstream).await?;
    out.send(query).await?;
    let mut answer = vec![0u8; DNS_MAX];
    let len = tokio::time::timeout(DNS_TIMEOUT, out.recv(&mut answer))
        .await
        .map_err(|_| std::io::Error::new(std::io::ErrorKind::TimedOut, "no answer"))??;
    socket.send_to(&answer[..len], peer).await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::AsyncReadExt;

    /// Reads a PROXY v2 TCP header from `stream`, as `<name>-proxy` does: answers `(src, dst)`.
    async fn read_proxy_v2<R: AsyncReadExt + Unpin>(
        stream: &mut R,
    ) -> std::io::Result<(SocketAddr, SocketAddr)> {
        let mut head = [0u8; 16];
        stream.read_exact(&mut head).await?;
        if head[..12] != proxy_v2::SIGNATURE || head[12] != 0x21 {
            return Err(std::io::Error::other("not a PROXY v2 header"));
        }
        let len = u16::from_be_bytes([head[14], head[15]]) as usize;
        let mut body = vec![0u8; len];
        stream.read_exact(&mut body).await?;
        let port = |at: usize| u16::from_be_bytes([body[at], body[at + 1]]);
        match (head[13], len) {
            (0x11, 12) => {
                let ip =
                    |at: usize| Ipv4Addr::new(body[at], body[at + 1], body[at + 2], body[at + 3]);
                Ok((
                    SocketAddr::new(ip(0).into(), port(8)),
                    SocketAddr::new(ip(4).into(), port(10)),
                ))
            }
            (0x21, 36) => {
                let ip = |at: usize| {
                    let mut o = [0u8; 16];
                    o.copy_from_slice(&body[at..at + 16]);
                    Ipv6Addr::from(o)
                };
                Ok((
                    SocketAddr::new(ip(0).into(), port(32)),
                    SocketAddr::new(ip(16).into(), port(34)),
                ))
            }
            _ => Err(std::io::Error::other("unsupported PROXY v2 family")),
        }
    }

    /// A stand-in destination lookup for streams that were never NATed: the guest "dialled"
    /// 203.0.113.7:5432.
    fn fixed_dst(_: &TcpStream) -> std::io::Result<SocketAddr> {
        Ok("203.0.113.7:5432".parse().unwrap())
    }

    fn not_redirected(stream: &TcpStream) -> std::io::Result<SocketAddr> {
        stream.local_addr()
    }

    #[tokio::test]
    async fn tcp_streams_reach_the_proxy_behind_a_header_naming_the_original_destination() {
        let proxy = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let proxy_addr = proxy.local_addr().unwrap();
        let forwarder = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let forwarder_addr = forwarder.local_addr().unwrap();
        tokio::spawn(serve_tcp(forwarder, proxy_addr, fixed_dst));

        let mut guest = TcpStream::connect(forwarder_addr).await.unwrap();
        let guest_addr = guest.local_addr().unwrap();
        guest.write_all(b"hello").await.unwrap();

        let (mut upstream, _) = proxy.accept().await.unwrap();
        let (src, dst) = read_proxy_v2(&mut upstream).await.unwrap();
        assert_eq!(src, guest_addr);
        assert_eq!(dst, "203.0.113.7:5432".parse().unwrap());
        let mut got = [0u8; 5];
        upstream.read_exact(&mut got).await.unwrap();
        assert_eq!(&got, b"hello");

        upstream.write_all(b"world").await.unwrap();
        let mut back = [0u8; 5];
        guest.read_exact(&mut back).await.unwrap();
        assert_eq!(&back, b"world");
    }

    #[tokio::test]
    async fn a_connection_that_was_not_redirected_is_dropped() {
        let proxy = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let proxy_addr = proxy.local_addr().unwrap();
        let forwarder = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let forwarder_addr = forwarder.local_addr().unwrap();
        tokio::spawn(serve_tcp(forwarder, proxy_addr, not_redirected));

        let mut guest = TcpStream::connect(forwarder_addr).await.unwrap();
        let mut buf = [0u8; 1];
        let n = tokio::time::timeout(Duration::from_secs(5), guest.read(&mut buf))
            .await
            .unwrap()
            .unwrap_or(0);
        assert_eq!(n, 0, "the forwarder kept a connection it could not name");
        let accepted = tokio::time::timeout(Duration::from_millis(200), proxy.accept()).await;
        assert!(
            accepted.is_err(),
            "the proxy was dialled for an unredirected connection"
        );
    }

    #[tokio::test]
    async fn dns_over_udp_answers_come_back_to_the_asking_guest() {
        // A resolver that answers each query with the query reversed.
        let resolver = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let resolver_addr = resolver.local_addr().unwrap();
        tokio::spawn(async move {
            let mut buf = [0u8; 512];
            loop {
                let (n, from) = resolver.recv_from(&mut buf).await.unwrap();
                let mut answer = buf[..n].to_vec();
                answer.reverse();
                resolver.send_to(&answer, from).await.unwrap();
            }
        });
        let forwarder = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let forwarder_addr = forwarder.local_addr().unwrap();
        tokio::spawn(serve_dns_udp(forwarder, resolver_addr));

        let a = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let b = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        a.send_to(b"abc", forwarder_addr).await.unwrap();
        b.send_to(b"xyz", forwarder_addr).await.unwrap();
        let mut buf = [0u8; 16];
        let (n, _) = tokio::time::timeout(Duration::from_secs(5), a.recv_from(&mut buf))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(&buf[..n], b"cba");
        let (n, _) = tokio::time::timeout(Duration::from_secs(5), b.recv_from(&mut buf))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(&buf[..n], b"zyx");
    }

    #[tokio::test]
    async fn dns_over_tcp_is_relayed_unchanged() {
        let resolver = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let resolver_addr = resolver.local_addr().unwrap();
        let forwarder = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let forwarder_addr = forwarder.local_addr().unwrap();
        tokio::spawn(serve_dns_tcp(forwarder, resolver_addr));

        let mut guest = TcpStream::connect(forwarder_addr).await.unwrap();
        guest.write_all(&[0, 3, b'q', b'r', b'y']).await.unwrap();
        let (mut upstream, _) = resolver.accept().await.unwrap();
        let mut got = [0u8; 5];
        upstream.read_exact(&mut got).await.unwrap();
        assert_eq!(
            got,
            [0, 3, b'q', b'r', b'y'],
            "DNS/TCP must not carry a PROXY header"
        );
    }
}
