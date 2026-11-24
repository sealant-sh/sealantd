//! PROXY protocol v2 headers (haproxy `proxy-protocol.txt` §2.2), which the TCP forwarders write
//! ahead of each guest stream so `<name>-proxy` learns the guest's source and its original
//! destination (`SO_ORIGINAL_DST`), not the forwarder's own addresses.

use std::net::{IpAddr, Ipv6Addr, SocketAddr};

/// The 12-byte signature every v2 header starts with.
pub const SIGNATURE: [u8; 12] = [
    0x0d, 0x0a, 0x0d, 0x0a, 0x00, 0x0d, 0x0a, 0x51, 0x55, 0x49, 0x54, 0x0a,
];
/// Version 2, command PROXY.
const VERSION_PROXY: u8 = 0x21;
/// AF_INET over STREAM.
const TCP_OVER_IPV4: u8 = 0x11;
/// AF_INET6 over STREAM.
const TCP_OVER_IPV6: u8 = 0x21;

/// The header for a TCP stream from `src` to `dst`. When the two families differ, both are sent
/// as IPv6 (an IPv4 address as `::ffff:a.b.c.d`), the only form v2 has for a mixed pair.
pub fn encode(src: SocketAddr, dst: SocketAddr) -> Vec<u8> {
    let mut out = Vec::with_capacity(16 + 36);
    out.extend_from_slice(&SIGNATURE);
    out.push(VERSION_PROXY);
    match (src.ip(), dst.ip()) {
        (IpAddr::V4(s), IpAddr::V4(d)) => {
            out.push(TCP_OVER_IPV4);
            out.extend_from_slice(&12u16.to_be_bytes());
            out.extend_from_slice(&s.octets());
            out.extend_from_slice(&d.octets());
        }
        (s, d) => {
            out.push(TCP_OVER_IPV6);
            out.extend_from_slice(&36u16.to_be_bytes());
            out.extend_from_slice(&as_v6(s).octets());
            out.extend_from_slice(&as_v6(d).octets());
        }
    }
    out.extend_from_slice(&src.port().to_be_bytes());
    out.extend_from_slice(&dst.port().to_be_bytes());
    out
}

fn as_v6(ip: IpAddr) -> Ipv6Addr {
    match ip {
        IpAddr::V4(v4) => v4.to_ipv6_mapped(),
        IpAddr::V6(v6) => v6,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ipv4_header_bytes() {
        let src: SocketAddr = "10.200.0.2:40000".parse().unwrap();
        let dst: SocketAddr = "93.184.216.34:443".parse().unwrap();
        let expected: Vec<u8> = [
            &SIGNATURE[..],
            &[0x21, 0x11, 0x00, 0x0c],
            &[10, 200, 0, 2],
            &[93, 184, 216, 34],
            &[0x9c, 0x40], // 40000
            &[0x01, 0xbb], // 443
        ]
        .concat();
        assert_eq!(encode(src, dst), expected);
        assert_eq!(expected.len(), 28);
    }

    #[test]
    fn ipv6_header_bytes() {
        let src: SocketAddr = "[fd00::2]:5000".parse().unwrap();
        let dst: SocketAddr = "[2606:2800:220:1::1]:22".parse().unwrap();
        let header = encode(src, dst);
        assert_eq!(header.len(), 16 + 36);
        assert_eq!(&header[..12], &SIGNATURE);
        assert_eq!(&header[12..16], &[0x21, 0x21, 0x00, 0x24]);
        assert_eq!(
            &header[16..32],
            &"fd00::2".parse::<Ipv6Addr>().unwrap().octets()
        );
        assert_eq!(
            &header[32..48],
            &"2606:2800:220:1::1".parse::<Ipv6Addr>().unwrap().octets()
        );
        assert_eq!(&header[48..52], &[0x13, 0x88, 0x00, 0x16]);
    }

    #[test]
    fn a_mixed_pair_is_sent_as_ipv6_with_the_ipv4_side_mapped() {
        let src: SocketAddr = "10.200.0.2:1".parse().unwrap();
        let dst: SocketAddr = "[2001:db8::1]:2".parse().unwrap();
        let header = encode(src, dst);
        assert_eq!(header[13], 0x21);
        assert_eq!(
            &header[16..32],
            &"::ffff:10.200.0.2".parse::<Ipv6Addr>().unwrap().octets()
        );
    }
}
