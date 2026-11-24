//! PROXY protocol v2: how `sealant-vm-runner` tells the transparent listeners where a redirected
//! guest connection was originally going.

use std::io;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

use tokio::io::{AsyncRead, AsyncReadExt};

pub(crate) const SIGNATURE: [u8; 12] = *b"\r\n\r\n\0\r\nQUIT\n";
const MAX_ADDRESS_BLOCK: usize = 1024;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct ProxyHeader {
    pub(crate) source: SocketAddr,
    pub(crate) destination: SocketAddr,
}

fn bad(what: &str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, format!("PROXY v2: {what}"))
}

/// Read exactly one PROXY v2 header and nothing after it.
pub(crate) async fn read_header<R: AsyncRead + Unpin>(reader: &mut R) -> io::Result<ProxyHeader> {
    let mut fixed = [0u8; 16];
    reader.read_exact(&mut fixed).await?;
    let len = usize::from(u16::from_be_bytes([fixed[14], fixed[15]]));
    if len > MAX_ADDRESS_BLOCK {
        return Err(bad("address block too long"));
    }
    let mut block = vec![0u8; len];
    reader.read_exact(&mut block).await?;
    parse(&fixed, &block)
}

/// Parse the 16-byte fixed part and the address block that follows it.
pub(crate) fn parse(fixed: &[u8; 16], block: &[u8]) -> io::Result<ProxyHeader> {
    if fixed[..12] != SIGNATURE {
        return Err(bad("missing signature"));
    }
    let version = fixed[12] >> 4;
    let command = fixed[12] & 0x0f;
    if version != 2 {
        return Err(bad("unsupported version"));
    }
    if command != 1 {
        // LOCAL carries no original destination; the runner only ever sends PROXY.
        return Err(bad("not a PROXY command"));
    }
    match fixed[13] {
        0x11 => {
            if block.len() < 12 {
                return Err(bad("short IPv4 address block"));
            }
            let src = Ipv4Addr::new(block[0], block[1], block[2], block[3]);
            let dst = Ipv4Addr::new(block[4], block[5], block[6], block[7]);
            let sport = u16::from_be_bytes([block[8], block[9]]);
            let dport = u16::from_be_bytes([block[10], block[11]]);
            Ok(ProxyHeader {
                source: SocketAddr::new(IpAddr::V4(src), sport),
                destination: SocketAddr::new(IpAddr::V4(dst), dport),
            })
        }
        0x21 => {
            if block.len() < 36 {
                return Err(bad("short IPv6 address block"));
            }
            let mut src = [0u8; 16];
            let mut dst = [0u8; 16];
            src.copy_from_slice(&block[..16]);
            dst.copy_from_slice(&block[16..32]);
            let sport = u16::from_be_bytes([block[32], block[33]]);
            let dport = u16::from_be_bytes([block[34], block[35]]);
            Ok(ProxyHeader {
                source: SocketAddr::new(IpAddr::V6(Ipv6Addr::from(src)), sport),
                destination: SocketAddr::new(IpAddr::V6(Ipv6Addr::from(dst)), dport),
            })
        }
        _ => Err(bad("only TCP over IPv4 or IPv6 is supported")),
    }
}

/// Encode a PROXY v2 header, as the runner does. Used by tests and by any in-process relay.
pub fn encode(source: SocketAddr, destination: SocketAddr) -> Vec<u8> {
    let mut out = SIGNATURE.to_vec();
    out.push(0x21);
    match (source, destination) {
        (SocketAddr::V4(s), SocketAddr::V4(d)) => {
            out.push(0x11);
            out.extend_from_slice(&12u16.to_be_bytes());
            out.extend_from_slice(&s.ip().octets());
            out.extend_from_slice(&d.ip().octets());
            out.extend_from_slice(&s.port().to_be_bytes());
            out.extend_from_slice(&d.port().to_be_bytes());
        }
        (s, d) => {
            let v6 = |a: SocketAddr| match a.ip() {
                IpAddr::V4(v4) => v4.to_ipv6_mapped(),
                IpAddr::V6(v6) => v6,
            };
            out.push(0x21);
            out.extend_from_slice(&36u16.to_be_bytes());
            out.extend_from_slice(&v6(s).octets());
            out.extend_from_slice(&v6(d).octets());
            out.extend_from_slice(&s.port().to_be_bytes());
            out.extend_from_slice(&d.port().to_be_bytes());
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn round_trips_ipv4_and_ipv6_and_reads_nothing_more() {
        for (src, dst) in [
            ("10.200.0.2:40000", "93.184.216.34:443"),
            ("[fd00::2]:40000", "[2606:4700::1111]:443"),
        ] {
            let (src, dst): (SocketAddr, SocketAddr) = (src.parse().unwrap(), dst.parse().unwrap());
            let mut bytes = encode(src, dst);
            bytes.extend_from_slice(b"payload");
            let mut reader = &bytes[..];
            let header = read_header(&mut reader).await.unwrap();
            assert_eq!(header.source, src);
            assert_eq!(header.destination, dst);
            assert_eq!(reader, b"payload");
        }
    }

    #[tokio::test]
    async fn rejects_bad_signatures_commands_and_families() {
        let good = encode(
            "10.0.0.1:1".parse().unwrap(),
            "1.1.1.1:443".parse().unwrap(),
        );
        let mut cases = Vec::new();
        let mut sig = good.clone();
        sig[0] = b'X';
        cases.push(sig);
        let mut local = good.clone();
        local[12] = 0x20;
        cases.push(local);
        let mut udp = good.clone();
        udp[13] = 0x12;
        cases.push(udp);
        let mut v1 = good.clone();
        v1[12] = 0x11;
        cases.push(v1);
        cases.push(good[..20].to_vec());
        for case in cases {
            let mut reader = &case[..];
            assert!(read_header(&mut reader).await.is_err());
        }
    }
}
