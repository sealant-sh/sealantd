//! Hard-blocked destination addresses.
//!
//! Every address the proxy might connect to, or hand back in a DNS answer, goes through
//! [`AddressRules::verdict`]. An address is first normalized: an IPv4-mapped IPv6 address
//! (`::ffff:a.b.c.d`) becomes the IPv4 address it carries, and the deprecated IPv6 forms that embed
//! an IPv4 address some other way (IPv4-compatible `::a.b.c.d`, SIIT, 6to4, Teredo) are refused
//! outright rather than unpacked. The normalized address is then checked against the fixed block
//! list, the host's own public addresses and the operator's configured blocks.
//!
//! The operator's private-egress allowlist can lift some blocks (a corporate VPC, a tailnet, an
//! opt-in `host.docker.internal`), but never the ones no workspace should ever reach: cloud
//! metadata, the Azure wireserver, unspecified, multicast, broadcast, NAT64, reserved ranges and
//! the deprecated IPv4-embedding forms.

use std::fmt;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

/// Why an address is refused.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum BlockReason {
    Unspecified,
    Loopback,
    LinkLocal,
    CloudMetadata,
    AzureWireserver,
    Nat64,
    /// IPv4-compatible, SIIT, 6to4 or Teredo: an IPv4 address embedded in a deprecated IPv6 form.
    DeprecatedIpv6,
    HostPublicIp,
    CarrierGradeNat,
    Multicast,
    Broadcast,
    /// Documentation, benchmarking, IETF-reserved and other non-global ranges.
    Reserved,
    Private,
    /// A Docker bridge gateway or container subnet the operator configured.
    ConfiguredBlock,
}

impl BlockReason {
    /// Whether the operator's private-egress allowlist may lift this block.
    pub fn operator_carvable(self) -> bool {
        matches!(
            self,
            Self::Loopback
                | Self::LinkLocal
                | Self::HostPublicIp
                | Self::CarrierGradeNat
                | Self::Private
                | Self::ConfiguredBlock
        )
    }

    /// Whether a mirror or worktree resource, which lives on a private Docker network by design,
    /// may sit at an address with this block.
    pub(crate) fn private_network(self) -> bool {
        matches!(
            self,
            Self::Private | Self::ConfiguredBlock | Self::CarrierGradeNat
        )
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Self::Unspecified => "unspecified",
            Self::Loopback => "loopback",
            Self::LinkLocal => "link_local",
            Self::CloudMetadata => "cloud_metadata",
            Self::AzureWireserver => "azure_wireserver",
            Self::Nat64 => "nat64",
            Self::DeprecatedIpv6 => "deprecated_ipv6",
            Self::HostPublicIp => "host_public_ip",
            Self::CarrierGradeNat => "carrier_grade_nat",
            Self::Multicast => "multicast",
            Self::Broadcast => "broadcast",
            Self::Reserved => "reserved",
            Self::Private => "private",
            Self::ConfiguredBlock => "configured_block",
        }
    }
}

impl fmt::Display for BlockReason {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// An IPv4 or IPv6 network in CIDR notation.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct Cidr {
    addr: IpAddr,
    prefix: u8,
}

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum CidrError {
    #[error("`{0}` is not an IP address or CIDR")]
    Syntax(String),
    #[error("prefix /{prefix} is too long for `{addr}`")]
    Prefix { addr: IpAddr, prefix: u8 },
}

impl Cidr {
    pub fn new(addr: IpAddr, prefix: u8) -> Result<Self, CidrError> {
        // An IPv4-mapped network is the IPv4 network it maps, so `::ffff:10.0.0.0/104` and
        // `10.0.0.0/8` mean the same thing to `contains`, which only sees normalized addresses.
        let (addr, prefix) = match addr {
            IpAddr::V6(v6) => match v6.to_ipv4_mapped() {
                Some(v4) if prefix >= 96 => (IpAddr::V4(v4), prefix - 96),
                _ => (addr, prefix),
            },
            IpAddr::V4(_) => (addr, prefix),
        };
        let max = if addr.is_ipv4() { 32 } else { 128 };
        if prefix > max {
            return Err(CidrError::Prefix { addr, prefix });
        }
        Ok(Self {
            addr: mask(addr, prefix),
            prefix,
        })
    }

    pub fn parse(text: &str) -> Result<Self, CidrError> {
        let text = text.trim();
        let syntax = || CidrError::Syntax(text.to_string());
        let (addr, prefix) = match text.split_once('/') {
            Some((addr, prefix)) => {
                let addr: IpAddr = addr.parse().map_err(|_| syntax())?;
                let prefix: u8 = prefix.parse().map_err(|_| syntax())?;
                (addr, prefix)
            }
            None => {
                let addr: IpAddr = text.parse().map_err(|_| syntax())?;
                (addr, if addr.is_ipv4() { 32 } else { 128 })
            }
        };
        Self::new(addr, prefix)
    }

    /// Whether `ip`, which the caller has normalized, falls inside this network.
    pub fn contains(&self, ip: IpAddr) -> bool {
        match (self.addr, ip) {
            (IpAddr::V4(_), IpAddr::V4(_)) | (IpAddr::V6(_), IpAddr::V6(_)) => {
                mask(ip, self.prefix) == self.addr
            }
            _ => false,
        }
    }
}

impl fmt::Display for Cidr {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}/{}", self.addr, self.prefix)
    }
}

fn mask(ip: IpAddr, prefix: u8) -> IpAddr {
    match ip {
        IpAddr::V4(v4) => {
            let bits = u32::from(v4);
            let mask = if prefix == 0 {
                0
            } else {
                u32::MAX << (32 - u32::from(prefix))
            };
            IpAddr::V4(Ipv4Addr::from(bits & mask))
        }
        IpAddr::V6(v6) => {
            let bits = u128::from(v6);
            let mask = if prefix == 0 {
                0
            } else {
                u128::MAX << (128 - u32::from(prefix))
            };
            IpAddr::V6(Ipv6Addr::from(bits & mask))
        }
    }
}

const fn v4(a: u8, b: u8, c: u8, d: u8, prefix: u8, reason: BlockReason) -> Rule {
    Rule {
        net: Net::V4(u32::from_be_bytes([a, b, c, d]), prefix),
        reason,
    }
}

const fn v6(bits: u128, prefix: u8, reason: BlockReason) -> Rule {
    Rule {
        net: Net::V6(bits, prefix),
        reason,
    }
}

#[derive(Clone, Copy)]
enum Net {
    V4(u32, u8),
    V6(u128, u8),
}

#[derive(Clone, Copy)]
struct Rule {
    net: Net,
    reason: BlockReason,
}

impl Rule {
    fn matches(&self, ip: IpAddr) -> bool {
        match (self.net, ip) {
            (Net::V4(net, prefix), IpAddr::V4(ip)) => {
                let mask = if prefix == 0 {
                    0
                } else {
                    u32::MAX << (32 - u32::from(prefix))
                };
                u32::from(ip) & mask == net
            }
            (Net::V6(net, prefix), IpAddr::V6(ip)) => {
                let mask = if prefix == 0 {
                    0
                } else {
                    u128::MAX << (128 - u32::from(prefix))
                };
                u128::from(ip) & mask == net
            }
            _ => false,
        }
    }
}

use BlockReason as R;

/// The fixed block list, most specific first: the first match names the reason.
const BLOCKED: &[Rule] = &[
    // IPv4
    v4(169, 254, 169, 254, 32, R::CloudMetadata),
    // AWS ECS task metadata and EKS Pod Identity.
    v4(169, 254, 170, 2, 32, R::CloudMetadata),
    v4(169, 254, 170, 23, 32, R::CloudMetadata),
    // Alibaba Cloud metadata, inside CGNAT: an operator allowing a tailnet must not open it.
    v4(100, 100, 100, 200, 32, R::CloudMetadata),
    v4(168, 63, 129, 16, 32, R::AzureWireserver),
    v4(255, 255, 255, 255, 32, R::Broadcast),
    v4(0, 0, 0, 0, 8, R::Unspecified),
    v4(127, 0, 0, 0, 8, R::Loopback),
    v4(169, 254, 0, 0, 16, R::LinkLocal),
    v4(100, 64, 0, 0, 10, R::CarrierGradeNat),
    v4(10, 0, 0, 0, 8, R::Private),
    v4(172, 16, 0, 0, 12, R::Private),
    v4(192, 168, 0, 0, 16, R::Private),
    v4(224, 0, 0, 0, 4, R::Multicast),
    v4(240, 0, 0, 0, 4, R::Reserved),
    v4(192, 0, 0, 0, 24, R::Reserved),
    v4(192, 0, 2, 0, 24, R::Reserved),
    v4(198, 51, 100, 0, 24, R::Reserved),
    v4(203, 0, 113, 0, 24, R::Reserved),
    v4(198, 18, 0, 0, 15, R::Reserved),
    v4(192, 88, 99, 0, 24, R::DeprecatedIpv6),
    // IPv6
    v6(0, 128, R::Unspecified),
    v6(1, 128, R::Loopback),
    v6(
        0xfd00_0ec2_0000_0000_0000_0000_0000_0254,
        128,
        R::CloudMetadata,
    ),
    v6(
        0xfd00_0ec2_0000_0000_0000_0000_0000_0023,
        128,
        R::CloudMetadata,
    ),
    // GCP metadata over IPv6.
    v6(
        0xfd20_00ce_0000_0000_0000_0000_0000_0254,
        128,
        R::CloudMetadata,
    ),
    v6(0x0064_ff9b_0000_0000_0000_0000_0000_0000, 96, R::Nat64),
    v6(0x0064_ff9b_0001_0000_0000_0000_0000_0000, 48, R::Nat64),
    v6(0xfe80 << 112, 10, R::LinkLocal),
    v6(0xfec0 << 112, 10, R::Private),
    v6(0xfc00 << 112, 7, R::Private),
    v6(0xff00 << 112, 8, R::Multicast),
    v6(0x2002 << 112, 16, R::DeprecatedIpv6),
    v6(0x2001_0000 << 96, 32, R::DeprecatedIpv6),
    v6(0x2001_0db8 << 96, 32, R::Reserved),
    v6(0x2001_0002 << 96, 48, R::Reserved),
    v6(0x2001_0010 << 96, 28, R::Reserved),
    v6(0x2001_0020 << 96, 28, R::Reserved),
    v6(0x3fff << 112, 20, R::Reserved),
    v6(0x0100 << 112, 64, R::Reserved),
    v6(0x5f00 << 112, 16, R::Reserved),
];

/// Normalize an address before any check: IPv4-mapped IPv6 becomes IPv4, and the deprecated forms
/// that embed an IPv4 address any other way are refused.
pub fn normalize(ip: IpAddr) -> Result<IpAddr, BlockReason> {
    let IpAddr::V6(v6) = ip else {
        return Ok(ip);
    };
    if let Some(mapped) = v6.to_ipv4_mapped() {
        return Ok(IpAddr::V4(mapped));
    }
    let s = v6.segments();
    let high_96_zero = s[..6].iter().all(|seg| *seg == 0);
    if high_96_zero && !v6.is_unspecified() && !v6.is_loopback() {
        // IPv4-compatible `::a.b.c.d` (RFC 4291 §2.5.5.1, deprecated).
        return Err(BlockReason::DeprecatedIpv6);
    }
    if s[..4].iter().all(|seg| *seg == 0) && s[4] == 0xffff && s[5] == 0 {
        // SIIT IPv4-translated `::ffff:0:a.b.c.d` (RFC 2765).
        return Err(BlockReason::DeprecatedIpv6);
    }
    Ok(ip)
}

/// The fixed block-list reason for a normalized address, if any.
pub fn classify(ip: IpAddr) -> Option<BlockReason> {
    if let Some(rule) = BLOCKED.iter().find(|rule| rule.matches(ip)) {
        return Some(rule.reason);
    }
    match ip {
        // Everything outside global unicast 2000::/3 is unassigned or special-purpose.
        IpAddr::V6(v6) if (v6.segments()[0] & 0xe000) != 0x2000 => Some(BlockReason::Reserved),
        _ => None,
    }
}

/// The per-policy address rules: the fixed block list plus what the operator configured.
#[derive(Clone, Debug, Default)]
pub struct AddressRules {
    pub operator_allowed: Vec<Cidr>,
    pub host_public: Vec<Cidr>,
    pub configured_blocked: Vec<Cidr>,
}

impl AddressRules {
    /// The reason `ip` (normalized) is blocked before any exception is applied.
    fn block_reason(&self, ip: IpAddr) -> Option<BlockReason> {
        let fixed = classify(ip);
        if let Some(reason) = fixed
            && !reason.operator_carvable()
        {
            return Some(reason);
        }
        if self.host_public.iter().any(|net| net.contains(ip)) {
            return Some(BlockReason::HostPublicIp);
        }
        if fixed.is_none() && self.configured_blocked.iter().any(|net| net.contains(ip)) {
            return Some(BlockReason::ConfiguredBlock);
        }
        fixed
    }

    /// Whether the proxy may connect to, or answer DNS with, `ip`. Returns the normalized address.
    pub fn verdict(&self, ip: IpAddr) -> Result<IpAddr, BlockReason> {
        let ip = normalize(ip)?;
        match self.block_reason(ip) {
            None => Ok(ip),
            Some(reason) if reason.operator_carvable() && self.operator_allows(ip) => Ok(ip),
            Some(reason) => Err(reason),
        }
    }

    /// The verdict for a mirror or worktree resource address, which may also sit on a private
    /// Docker network. Metadata, loopback and the other never-carvable blocks still apply.
    pub fn private_target_verdict(&self, ip: IpAddr) -> Result<IpAddr, BlockReason> {
        match self.verdict(ip) {
            Ok(ip) => Ok(ip),
            Err(reason) if reason.private_network() => normalize(ip),
            Err(reason) => Err(reason),
        }
    }

    fn operator_allows(&self, ip: IpAddr) -> bool {
        self.operator_allowed.iter().any(|net| net.contains(ip))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ip(text: &str) -> IpAddr {
        text.parse().unwrap()
    }

    fn rules() -> AddressRules {
        AddressRules {
            operator_allowed: vec![Cidr::parse("10.20.0.0/16").unwrap()],
            host_public: vec![Cidr::parse("203.0.114.7").unwrap()],
            configured_blocked: vec![Cidr::parse("45.0.0.0/24").unwrap()],
        }
    }

    #[test]
    fn blocks_every_hard_range_with_its_reason() {
        let rules = AddressRules::default();
        let cases = [
            ("127.0.0.1", R::Loopback),
            ("::1", R::Loopback),
            ("0.0.0.0", R::Unspecified),
            ("0.1.2.3", R::Unspecified),
            ("::", R::Unspecified),
            ("169.254.10.1", R::LinkLocal),
            ("fe80::1", R::LinkLocal),
            ("169.254.169.254", R::CloudMetadata),
            ("fd00:ec2::254", R::CloudMetadata),
            ("168.63.129.16", R::AzureWireserver),
            ("64:ff9b::a9fe:a9fe", R::Nat64),
            ("64:ff9b:1::1", R::Nat64),
            ("100.64.0.1", R::CarrierGradeNat),
            ("100.127.255.254", R::CarrierGradeNat),
            ("224.0.0.251", R::Multicast),
            ("ff02::1", R::Multicast),
            ("255.255.255.255", R::Broadcast),
            ("240.0.0.1", R::Reserved),
            ("192.0.2.10", R::Reserved),
            ("198.18.0.1", R::Reserved),
            ("2001:db8::1", R::Reserved),
            ("10.0.0.1", R::Private),
            ("172.16.0.1", R::Private),
            ("172.31.255.255", R::Private),
            ("192.168.1.1", R::Private),
            ("fc00::1", R::Private),
            ("fd12:3456::1", R::Private),
            ("2002:a9fe:a9fe::1", R::DeprecatedIpv6),
            ("2001:0:4136:e378::1", R::DeprecatedIpv6),
            ("4000::1", R::Reserved),
        ];
        for (text, reason) in cases {
            assert_eq!(rules.verdict(ip(text)), Err(reason), "{text}");
        }
    }

    #[test]
    fn allows_public_addresses_next_to_blocked_ranges() {
        let rules = AddressRules::default();
        for text in [
            "1.1.1.1",
            "172.32.0.1",
            "100.128.0.1",
            "169.255.0.1",
            "168.63.129.17",
            "2606:4700::1111",
            "2001:4860:4860::8888",
        ] {
            assert_eq!(rules.verdict(ip(text)), Ok(ip(text)), "{text}");
        }
    }

    #[test]
    fn mapped_ipv6_is_judged_as_the_ipv4_it_carries() {
        let rules = AddressRules::default();
        assert_eq!(
            rules.verdict(ip("::ffff:169.254.169.254")),
            Err(R::CloudMetadata)
        );
        assert_eq!(rules.verdict(ip("::ffff:10.1.2.3")), Err(R::Private));
        assert_eq!(rules.verdict(ip("::ffff:127.0.0.1")), Err(R::Loopback));
        assert_eq!(rules.verdict(ip("::ffff:1.1.1.1")), Ok(ip("1.1.1.1")));
    }

    #[test]
    fn deprecated_ipv4_embeddings_are_refused_not_unpacked() {
        let rules = AddressRules::default();
        // IPv4-compatible and SIIT forms of a public address are still refused.
        assert_eq!(rules.verdict(ip("::1.1.1.1")), Err(R::DeprecatedIpv6));
        assert_eq!(
            rules.verdict(ip("::169.254.169.254")),
            Err(R::DeprecatedIpv6)
        );
        assert_eq!(
            rules.verdict(ip("::ffff:0:1.1.1.1")),
            Err(R::DeprecatedIpv6)
        );
    }

    #[test]
    fn host_public_ip_and_configured_blocks_apply() {
        let rules = rules();
        assert_eq!(rules.verdict(ip("203.0.114.7")), Err(R::HostPublicIp));
        assert_eq!(
            rules.verdict(ip("::ffff:203.0.114.7")),
            Err(R::HostPublicIp)
        );
        assert_eq!(rules.verdict(ip("203.0.114.8")), Ok(ip("203.0.114.8")));
        assert_eq!(rules.verdict(ip("45.0.0.1")), Err(R::ConfiguredBlock));
    }

    #[test]
    fn operator_allowlist_lifts_private_blocks_but_never_metadata() {
        let mut rules = rules();
        assert_eq!(rules.verdict(ip("10.20.1.2")), Ok(ip("10.20.1.2")));
        assert_eq!(rules.verdict(ip("10.21.1.2")), Err(R::Private));
        // An operator CIDR that covers metadata, wireserver or NAT64 never opens them.
        rules.operator_allowed = vec![
            Cidr::parse("169.254.0.0/16").unwrap(),
            Cidr::parse("168.63.0.0/16").unwrap(),
            Cidr::parse("64:ff9b::/96").unwrap(),
            Cidr::parse("0.0.0.0/0").unwrap(),
        ];
        assert_eq!(rules.verdict(ip("169.254.1.1")), Ok(ip("169.254.1.1")));
        assert_eq!(rules.verdict(ip("169.254.169.254")), Err(R::CloudMetadata));
        assert_eq!(rules.verdict(ip("168.63.129.16")), Err(R::AzureWireserver));
        assert_eq!(rules.verdict(ip("64:ff9b::a9fe:a9fe")), Err(R::Nat64));
        // Every provider's metadata address stays blocked, including Alibaba's inside the
        // CGNAT range a tailnet allowlist opens.
        rules
            .operator_allowed
            .push(Cidr::parse("100.64.0.0/10").unwrap());
        rules
            .operator_allowed
            .push(Cidr::parse("fc00::/7").unwrap());
        assert_eq!(rules.verdict(ip("100.100.1.1")), Ok(ip("100.100.1.1")));
        for text in [
            "100.100.100.200",
            "169.254.170.2",
            "169.254.170.23",
            "fd00:ec2::23",
            "fd20:ce::254",
            "::ffff:100.100.100.200",
        ] {
            assert_eq!(rules.verdict(ip(text)), Err(R::CloudMetadata), "{text}");
        }
        assert_eq!(rules.verdict(ip("255.255.255.255")), Err(R::Broadcast));
        assert_eq!(rules.verdict(ip("0.0.0.0")), Err(R::Unspecified));
    }

    #[test]
    fn private_targets_allow_docker_networks_only() {
        let rules = AddressRules::default();
        assert_eq!(
            rules.private_target_verdict(ip("172.18.0.3")),
            Ok(ip("172.18.0.3"))
        );
        assert_eq!(
            rules.private_target_verdict(ip("127.0.0.1")),
            Err(R::Loopback)
        );
        assert_eq!(
            rules.private_target_verdict(ip("169.254.169.254")),
            Err(R::CloudMetadata)
        );
    }

    #[test]
    fn cidr_parsing_masks_and_normalizes() {
        assert_eq!(Cidr::parse("10.1.2.3/8").unwrap().to_string(), "10.0.0.0/8");
        assert_eq!(
            Cidr::parse("::ffff:10.0.0.0/104").unwrap(),
            Cidr::parse("10.0.0.0/8").unwrap()
        );
        assert!(Cidr::parse("10.0.0.0/33").is_err());
        assert!(Cidr::parse("nope").is_err());
        let all = Cidr::parse("0.0.0.0/0").unwrap();
        assert!(all.contains(ip("8.8.8.8")));
        assert!(!all.contains(ip("::1")));
    }
}
