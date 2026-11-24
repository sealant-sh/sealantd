//! The guest's network, configured by PID 1 over rtnetlink: no `ip`, no shell, no `unsafe`.
//!
//! `lo` up with `127.0.0.1/8`; the guest interface up with its address (`10.200.0.2/30`), a
//! default route through the runner's `tap0` (`10.200.0.1`) and `/etc/resolv.conf` naming it.
//! Every request asks for an acknowledgement and is idempotent (`NLM_F_REPLACE`), so a second
//! boot on the same kernel, or an address the kernel already set, is not an error.

use std::net::Ipv4Addr;
use std::path::Path;

use super::protocol::NetworkConfig;

const NLMSG_ERROR: u16 = 2;
const RTM_NEWLINK: u16 = 16;
const RTM_NEWADDR: u16 = 20;
const RTM_NEWROUTE: u16 = 24;

const NLM_F_REQUEST: u16 = 0x1;
const NLM_F_ACK: u16 = 0x4;
const NLM_F_REPLACE: u16 = 0x100;
const NLM_F_CREATE: u16 = 0x400;

const AF_UNSPEC: u8 = 0;
const AF_INET: u8 = 2;
const IFF_UP: u32 = 0x1;
const IFLA_MTU: u16 = 4;
const IFA_ADDRESS: u16 = 1;
const IFA_LOCAL: u16 = 2;
const RTA_OIF: u16 = 4;
const RTA_GATEWAY: u16 = 5;
const RT_TABLE_MAIN: u8 = 254;
const RTPROT_BOOT: u8 = 3;
const RT_SCOPE_UNIVERSE: u8 = 0;
const RT_SCOPE_HOST: u8 = 254;
const RTN_UNICAST: u8 = 1;
const EEXIST: i32 = 17;

/// An address with its prefix length.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Cidr {
    /// The address.
    pub address: Ipv4Addr,
    /// The prefix length.
    pub prefix: u8,
}

impl Cidr {
    /// Parse `a.b.c.d/n`.
    #[must_use]
    pub fn parse(text: &str) -> Option<Self> {
        let (address, prefix) = text.trim().split_once('/')?;
        let prefix: u8 = prefix.parse().ok()?;
        (prefix <= 32).then_some(Self {
            address: address.parse().ok()?,
            prefix,
        })
    }
}

/// One netlink message: header, fixed body, attributes.
#[derive(Debug, Default)]
pub struct Message {
    kind: u16,
    flags: u16,
    seq: u32,
    body: Vec<u8>,
}

fn align4(len: usize) -> usize {
    (len + 3) & !3
}

impl Message {
    fn new(kind: u16, flags: u16, seq: u32) -> Self {
        Self {
            kind,
            flags: NLM_F_REQUEST | NLM_F_ACK | flags,
            seq,
            body: Vec::new(),
        }
    }

    fn push(&mut self, bytes: &[u8]) {
        self.body.extend_from_slice(bytes);
    }

    fn attr(&mut self, kind: u16, payload: &[u8]) {
        let len = 4 + payload.len();
        let len16 = u16::try_from(len).unwrap_or(u16::MAX);
        self.body.extend_from_slice(&len16.to_ne_bytes());
        self.body.extend_from_slice(&kind.to_ne_bytes());
        self.body.extend_from_slice(payload);
        self.body.resize(align4(self.body.len()), 0);
    }

    /// The message as the kernel reads it.
    #[must_use]
    pub fn encode(&self) -> Vec<u8> {
        let len = 16 + self.body.len();
        let mut out = Vec::with_capacity(len);
        out.extend_from_slice(&u32::try_from(len).unwrap_or(u32::MAX).to_ne_bytes());
        out.extend_from_slice(&self.kind.to_ne_bytes());
        out.extend_from_slice(&self.flags.to_ne_bytes());
        out.extend_from_slice(&self.seq.to_ne_bytes());
        out.extend_from_slice(&0u32.to_ne_bytes());
        out.extend_from_slice(&self.body);
        out
    }
}

/// `RTM_NEWLINK`: set `index` up (and its MTU).
#[must_use]
pub fn link_up(seq: u32, index: u32, mtu: Option<u32>) -> Message {
    let mut message = Message::new(RTM_NEWLINK, 0, seq);
    // struct ifinfomsg { u8 family, u8 pad, u16 type, i32 index, u32 flags, u32 change }
    message.push(&[AF_UNSPEC, 0]);
    message.push(&0u16.to_ne_bytes());
    message.push(&(index as i32).to_ne_bytes());
    message.push(&IFF_UP.to_ne_bytes());
    message.push(&IFF_UP.to_ne_bytes());
    if let Some(mtu) = mtu {
        message.attr(IFLA_MTU, &mtu.to_ne_bytes());
    }
    message
}

/// `RTM_NEWADDR`: give `index` the address `cidr`.
#[must_use]
pub fn add_address(seq: u32, index: u32, cidr: Cidr) -> Message {
    let mut message = Message::new(RTM_NEWADDR, NLM_F_CREATE | NLM_F_REPLACE, seq);
    let scope = if cidr.address.is_loopback() {
        RT_SCOPE_HOST
    } else {
        RT_SCOPE_UNIVERSE
    };
    // struct ifaddrmsg { u8 family, u8 prefixlen, u8 flags, u8 scope, u32 index }
    message.push(&[AF_INET, cidr.prefix, 0, scope]);
    message.push(&index.to_ne_bytes());
    message.attr(IFA_LOCAL, &cidr.address.octets());
    message.attr(IFA_ADDRESS, &cidr.address.octets());
    message
}

/// `RTM_NEWROUTE`: the default route through `gateway` on `index`.
#[must_use]
pub fn default_route(seq: u32, index: u32, gateway: Ipv4Addr) -> Message {
    let mut message = Message::new(RTM_NEWROUTE, NLM_F_CREATE | NLM_F_REPLACE, seq);
    // struct rtmsg { family, dst_len, src_len, tos, table, protocol, scope, type; u32 flags }
    message.push(&[
        AF_INET,
        0,
        0,
        0,
        RT_TABLE_MAIN,
        RTPROT_BOOT,
        RT_SCOPE_UNIVERSE,
        RTN_UNICAST,
    ]);
    message.push(&0u32.to_ne_bytes());
    message.attr(RTA_GATEWAY, &gateway.octets());
    message.attr(RTA_OIF, &index.to_ne_bytes());
    message
}

/// The errno an `NLMSG_ERROR` acknowledgement for `seq` carries (`0`: success), or `None` when
/// `reply` holds no acknowledgement for it.
#[must_use]
pub fn ack_errno(reply: &[u8], seq: u32) -> Option<i32> {
    let mut at = 0;
    while at + 16 <= reply.len() {
        let len = u32::from_ne_bytes(reply[at..at + 4].try_into().ok()?) as usize;
        if len < 16 || at + len > reply.len() {
            return None;
        }
        let kind = u16::from_ne_bytes(reply[at + 4..at + 6].try_into().ok()?);
        let got = u32::from_ne_bytes(reply[at + 8..at + 12].try_into().ok()?);
        if kind == NLMSG_ERROR && got == seq && len >= 20 {
            let error = i32::from_ne_bytes(reply[at + 16..at + 20].try_into().ok()?);
            return Some(-error);
        }
        at += align4(len);
    }
    None
}

/// The resolver file for `dns`.
#[must_use]
pub fn resolv_conf(dns: &[String]) -> String {
    dns.iter()
        .filter(|server| server.parse::<std::net::IpAddr>().is_ok())
        .map(|server| format!("nameserver {server}\n"))
        .collect()
}

/// The interface index of `name` in this network namespace (`if_nametoindex`; sysfs would
/// answer for whichever namespace mounted it).
///
/// # Errors
/// The interface does not exist.
pub fn interface_index(name: &str) -> std::io::Result<u32> {
    nix::net::if_::if_nametoindex(name).map_err(std::io::Error::from)
}

/// Why the network could not be configured.
#[derive(Debug, thiserror::Error)]
pub enum NetError {
    /// A setting that does not parse.
    #[error("network config: {0}")]
    Config(String),
    /// The netlink socket or a request failed.
    #[error("netlink {what}: {source}")]
    Netlink {
        /// The request.
        what: String,
        /// The failure.
        #[source]
        source: std::io::Error,
    },
}

/// A route netlink socket that sends requests and waits for their acknowledgements.
#[cfg(target_os = "linux")]
#[derive(Debug)]
pub struct Netlink {
    socket: socket2::Socket,
    seq: u32,
}

#[cfg(target_os = "linux")]
impl Netlink {
    /// Open a `NETLINK_ROUTE` socket.
    ///
    /// # Errors
    /// The socket could not be made.
    pub fn open() -> std::io::Result<Self> {
        const AF_NETLINK: i32 = 16;
        const NETLINK_ROUTE: i32 = 0;
        let socket = socket2::Socket::new(
            socket2::Domain::from(AF_NETLINK),
            socket2::Type::RAW,
            Some(socket2::Protocol::from(NETLINK_ROUTE)),
        )?;
        socket.set_read_timeout(Some(std::time::Duration::from_secs(5)))?;
        Ok(Self { socket, seq: 1 })
    }

    fn next_seq(&mut self) -> u32 {
        self.seq = self.seq.wrapping_add(1);
        self.seq
    }

    /// Send `message` and wait for its acknowledgement; `EEXIST` counts as done.
    fn request(&mut self, what: &str, message: &Message) -> Result<(), NetError> {
        use std::io::Read as _;
        let fail = |source: std::io::Error| NetError::Netlink {
            what: what.to_owned(),
            source,
        };
        self.socket.send(&message.encode()).map_err(fail)?;
        let mut reply = vec![0u8; 8192];
        loop {
            let read = (&self.socket).read(&mut reply).map_err(fail)?;
            match ack_errno(&reply[..read], message.seq) {
                Some(0 | EEXIST) => return Ok(()),
                Some(errno) => return Err(fail(std::io::Error::from_raw_os_error(errno))),
                None => continue,
            }
        }
    }

    /// `lo` up with `127.0.0.1/8`.
    ///
    /// # Errors
    /// A request the kernel refused.
    pub fn configure_loopback(&mut self) -> Result<(), NetError> {
        let lo = interface_index("lo").map_err(|source| NetError::Netlink {
            what: "lo index".to_owned(),
            source,
        })?;
        let seq = self.next_seq();
        self.request("lo up", &link_up(seq, lo, None))?;
        let seq = self.next_seq();
        let loopback = Cidr {
            address: Ipv4Addr::LOCALHOST,
            prefix: 8,
        };
        self.request("lo address", &add_address(seq, lo, loopback))
    }

    /// Configure `lo` and the guest interface as `config` says, and write `resolv_path`.
    ///
    /// # Errors
    /// A setting that does not parse, or a request the kernel refused.
    pub fn configure(
        &mut self,
        config: &NetworkConfig,
        resolv_path: &Path,
    ) -> Result<(), NetError> {
        let cidr = Cidr::parse(&config.address)
            .ok_or_else(|| NetError::Config(format!("address {:?}", config.address)))?;
        let gateway: Ipv4Addr = config
            .gateway
            .parse()
            .map_err(|_| NetError::Config(format!("gateway {:?}", config.gateway)))?;
        let index_of = |name: &str| {
            interface_index(name).map_err(|source| NetError::Netlink {
                what: format!("{name} index"),
                source,
            })
        };

        self.configure_loopback()?;

        let eth = index_of(&config.interface)?;
        let seq = self.next_seq();
        self.request("link up", &link_up(seq, eth, config.mtu))?;
        let seq = self.next_seq();
        self.request("address", &add_address(seq, eth, cidr))?;
        let seq = self.next_seq();
        self.request("default route", &default_route(seq, eth, gateway))?;

        // A symlink (a resolver stub's) is replaced by a file of our own.
        let _ = std::fs::remove_file(resolv_path);
        std::fs::write(resolv_path, resolv_conf(&config.dns)).map_err(|source| {
            NetError::Netlink {
                what: format!("write {}", resolv_path.display()),
                source,
            }
        })?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn u16_at(bytes: &[u8], at: usize) -> u16 {
        u16::from_ne_bytes(bytes[at..at + 2].try_into().unwrap())
    }
    fn u32_at(bytes: &[u8], at: usize) -> u32 {
        u32::from_ne_bytes(bytes[at..at + 4].try_into().unwrap())
    }

    #[test]
    fn an_address_request_is_laid_out_as_the_kernel_reads_it() {
        let cidr = Cidr::parse("10.200.0.2/30").expect("cidr");
        let bytes = add_address(7, 3, cidr).encode();
        // nlmsghdr
        assert_eq!(u32_at(&bytes, 0) as usize, bytes.len());
        assert_eq!(u16_at(&bytes, 4), RTM_NEWADDR);
        assert_eq!(
            u16_at(&bytes, 6),
            NLM_F_REQUEST | NLM_F_ACK | NLM_F_CREATE | NLM_F_REPLACE
        );
        assert_eq!(u32_at(&bytes, 8), 7);
        // ifaddrmsg
        assert_eq!(&bytes[16..20], &[AF_INET, 30, 0, RT_SCOPE_UNIVERSE]);
        assert_eq!(u32_at(&bytes, 20), 3);
        // IFA_LOCAL then IFA_ADDRESS, each 8 bytes (4 header + 4 address).
        assert_eq!(u16_at(&bytes, 24), 8);
        assert_eq!(u16_at(&bytes, 26), IFA_LOCAL);
        assert_eq!(&bytes[28..32], &[10, 200, 0, 2]);
        assert_eq!(u16_at(&bytes, 34), IFA_ADDRESS);
        assert_eq!(&bytes[36..40], &[10, 200, 0, 2]);
        assert_eq!(bytes.len(), 40);
    }

    #[test]
    fn loopback_gets_host_scope() {
        let bytes = add_address(
            1,
            1,
            Cidr {
                address: Ipv4Addr::LOCALHOST,
                prefix: 8,
            },
        )
        .encode();
        assert_eq!(&bytes[16..20], &[AF_INET, 8, 0, RT_SCOPE_HOST]);
    }

    #[test]
    fn a_link_and_a_route_request_carry_their_fields() {
        let link = link_up(2, 5, Some(1500)).encode();
        assert_eq!(u16_at(&link, 4), RTM_NEWLINK);
        assert_eq!(u32_at(&link, 20), 5); // index
        assert_eq!(u32_at(&link, 24), IFF_UP); // flags
        assert_eq!(u32_at(&link, 28), IFF_UP); // change
        assert_eq!(u16_at(&link, 34), IFLA_MTU);
        assert_eq!(u32_at(&link, 36), 1500);

        let route = default_route(3, 5, Ipv4Addr::new(10, 200, 0, 1)).encode();
        assert_eq!(u16_at(&route, 4), RTM_NEWROUTE);
        assert_eq!(
            &route[16..24],
            &[
                AF_INET,
                0,
                0,
                0,
                RT_TABLE_MAIN,
                RTPROT_BOOT,
                RT_SCOPE_UNIVERSE,
                RTN_UNICAST
            ]
        );
        assert_eq!(u16_at(&route, 30), RTA_GATEWAY);
        assert_eq!(&route[32..36], &[10, 200, 0, 1]);
        assert_eq!(u16_at(&route, 38), RTA_OIF);
        assert_eq!(u32_at(&route, 40), 5);
    }

    fn ack(seq: u32, errno: i32) -> Vec<u8> {
        let mut out = Vec::new();
        out.extend_from_slice(&36u32.to_ne_bytes());
        out.extend_from_slice(&NLMSG_ERROR.to_ne_bytes());
        out.extend_from_slice(&0u16.to_ne_bytes());
        out.extend_from_slice(&seq.to_ne_bytes());
        out.extend_from_slice(&0u32.to_ne_bytes());
        out.extend_from_slice(&(-errno).to_ne_bytes());
        out.extend_from_slice(&[0u8; 16]); // the echoed request header
        out
    }

    #[test]
    fn an_acknowledgement_is_found_by_sequence() {
        let mut reply = ack(4, 0);
        reply.extend(ack(5, EEXIST));
        assert_eq!(ack_errno(&reply, 4), Some(0));
        assert_eq!(ack_errno(&reply, 5), Some(EEXIST));
        assert_eq!(ack_errno(&reply, 6), None);
        assert_eq!(ack_errno(&reply[..10], 4), None);
    }

    /// Against the kernel, in a network namespace of its own where `lo` starts down:
    /// `unshare -rn cargo test -p sealantd --lib -- --ignored loopback_comes_up`. Ignored in a
    /// normal run, which has no namespace of its own to change.
    #[cfg(target_os = "linux")]
    #[test]
    #[ignore = "needs a network namespace of its own (unshare -rn)"]
    fn loopback_comes_up_in_a_fresh_namespace() {
        let mut netlink = Netlink::open().expect("netlink");
        netlink.configure_loopback().expect("lo configured");
        // Twice: a second boot on the same kernel is not an error.
        netlink.configure_loopback().expect("idempotent");
        // Down, a connect to 127.0.0.1 is "network unreachable"; up, it reaches the listener.
        let listener = std::net::TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).expect("bind");
        std::net::TcpStream::connect(listener.local_addr().expect("addr"))
            .expect("127.0.0.1 is reachable");
    }

    /// Against the kernel, with an `eth0` made by hand in a namespace of its own:
    /// `unshare -rn sh -c 'ip link add eth0 type dummy && <test binary> --ignored guest_interface'`.
    #[cfg(target_os = "linux")]
    #[test]
    #[ignore = "needs a network namespace of its own with an eth0 (unshare -rn, ip link add)"]
    fn the_guest_interface_comes_up_with_its_address_and_default_route() {
        let dir = tempfile::tempdir().expect("tempdir");
        let resolv = dir.path().join("resolv.conf");
        let config = NetworkConfig::default();
        let mut netlink = Netlink::open().expect("netlink");
        netlink.configure(&config, &resolv).expect("configured");
        netlink.configure(&config, &resolv).expect("idempotent");
        // A gateway route is only accepted on a link that is up with the gateway on its subnet.
        let routes = std::fs::read_to_string("/proc/net/route").expect("routes");
        // The default route (destination 0) through 10.200.0.1, little-endian hex.
        assert!(
            routes
                .lines()
                .any(|line| line.starts_with("eth0\t00000000\t0100C80A")),
            "{routes}"
        );
        assert_eq!(
            std::fs::read_to_string(&resolv).expect("resolv"),
            "nameserver 10.200.0.1\n"
        );
    }

    #[test]
    fn cidrs_and_resolvers_parse_strictly() {
        assert_eq!(
            Cidr::parse("10.200.0.2/30"),
            Some(Cidr {
                address: Ipv4Addr::new(10, 200, 0, 2),
                prefix: 30
            })
        );
        for bad in ["10.200.0.2", "10.200.0.2/33", "host/30", ""] {
            assert_eq!(Cidr::parse(bad), None, "{bad}");
        }
        assert_eq!(
            resolv_conf(&[
                "10.200.0.1".to_owned(),
                "not an ip\nnameserver 6.6.6.6".to_owned()
            ]),
            "nameserver 10.200.0.1\n"
        );
    }
}
