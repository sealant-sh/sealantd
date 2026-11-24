//! The guest link's fixed addressing and the runner's local forwarder ports (§4.2).

use std::net::{IpAddr, Ipv4Addr, SocketAddr};

/// The host end of the guest link, inside the container's netns.
pub const TAP_NAME: &str = "tap0";
/// `tap0`'s address: the guest's gateway, DNS server and every forwarder's bind address.
pub const HOST_IP: Ipv4Addr = Ipv4Addr::new(10, 200, 0, 1);
/// The guest's `eth0` address.
pub const GUEST_IP: Ipv4Addr = Ipv4Addr::new(10, 200, 0, 2);
/// `/30`: the link holds exactly the host and the guest.
pub const PREFIX_LEN: u8 = 30;
pub const MTU: u32 = 1500;
/// Synthetic guest IPs `<name>-proxy` answers for worktree resources (`db`, `cache`), ADR 0019.
pub const RESOURCE_NET: Ipv4Addr = Ipv4Addr::new(10, 201, 0, 0);
pub const RESOURCE_PREFIX_LEN: u8 = 16;

/// DNS over UDP and TCP; unprivileged, so the runner needs no `CAP_NET_BIND_SERVICE`.
pub const DNS_PORT: u16 = 15053;
/// Restricted egress: guest TCP to port 80.
pub const HTTP_PORT: u16 = 15080;
/// Worktree resources (`10.201.0.0/16`), any port.
pub const RESOURCE_PORT: u16 = 15100;
/// Restricted egress: guest TCP to port 443.
pub const HTTPS_PORT: u16 = 15443;
/// Standard: every other guest TCP connection. Restricted: the policy's extra TCP ports.
pub const TCP_PORT: u16 = 15444;

/// Where each forwarder relays on `<name>-proxy`. The TCP listeners there take a PROXY protocol
/// v2 header carrying the guest's original destination; DNS is plain DNS.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Upstreams {
    pub proxy_ip: IpAddr,
    pub dns: u16,
    pub http: u16,
    pub https: u16,
    pub tcp: u16,
    pub resources: u16,
}

impl Upstreams {
    /// The proxy's default layout: DNS on 53, and each transparent TCP listener on the same port
    /// number as the runner's local forwarder that feeds it.
    pub fn new(proxy_ip: IpAddr) -> Self {
        Self {
            proxy_ip,
            dns: 53,
            http: HTTP_PORT,
            https: HTTPS_PORT,
            tcp: TCP_PORT,
            resources: RESOURCE_PORT,
        }
    }

    pub fn addr(&self, port: u16) -> SocketAddr {
        SocketAddr::new(self.proxy_ip, port)
    }
}

/// A locally administered, unicast MAC for the guest's `eth0`.
pub fn random_guest_mac() -> std::io::Result<String> {
    let mut bytes = [0u8; 6];
    getrandom::getrandom(&mut bytes).map_err(|e| std::io::Error::other(e.to_string()))?;
    bytes[0] = (bytes[0] | 0x02) & 0xfe;
    Ok(format_mac(bytes))
}

pub fn format_mac(bytes: [u8; 6]) -> String {
    bytes
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect::<Vec<_>>()
        .join(":")
}

/// Accepts `aa:bb:cc:dd:ee:ff` naming a unicast address (a multicast MAC is refused by the guest
/// driver and would leave the VM without a link).
pub fn parse_mac(text: &str) -> Result<String, String> {
    let parts: Vec<&str> = text.split(':').collect();
    if parts.len() != 6 {
        return Err(format!("MAC {text:?} must be six colon-separated octets"));
    }
    let mut bytes = [0u8; 6];
    for (slot, part) in bytes.iter_mut().zip(&parts) {
        if part.len() != 2 {
            return Err(format!(
                "MAC {text:?} has an octet that is not two hex digits"
            ));
        }
        *slot = u8::from_str_radix(part, 16)
            .map_err(|_| format!("MAC {text:?} has an octet that is not hex"))?;
    }
    if bytes[0] & 0x01 != 0 {
        return Err(format!("MAC {text:?} is multicast"));
    }
    Ok(format_mac(bytes))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn random_macs_are_unicast_and_locally_administered() {
        for _ in 0..64 {
            let mac = random_guest_mac().unwrap();
            let first = u8::from_str_radix(&mac[..2], 16).unwrap();
            assert_eq!(first & 0x01, 0, "{mac} is multicast");
            assert_eq!(first & 0x02, 0x02, "{mac} is not locally administered");
            assert_eq!(parse_mac(&mac).unwrap(), mac);
        }
    }

    #[test]
    fn a_multicast_or_malformed_mac_is_refused() {
        assert!(parse_mac("01:00:5e:00:00:01").is_err());
        assert!(parse_mac("52:54:00:12:34").is_err());
        assert!(parse_mac("52:54:00:12:34:zz").is_err());
        assert_eq!(parse_mac("52:54:00:AB:cd:01").unwrap(), "52:54:00:ab:cd:01");
    }
}
