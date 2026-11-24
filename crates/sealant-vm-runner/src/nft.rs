//! The container-netns firewall between `tap0` and everything else (§4.2 step 2).
//!
//! One `inet` table, installed in a single `nft -f -` transaction (the table is created, deleted
//! and redefined in the same batch, so a rerun replaces it atomically and a failure leaves the old
//! state). The runner refuses to start the VM when `nft` fails: no guest packet may reach the
//! container's `eth0` other than through a forwarder.
//!
//! - `forward` has policy `drop`: nothing is routed between `tap0` and `eth0` at L3.
//! - `prerouting` redirects guest DNS and TCP into the local forwarders on `10.200.0.1`.
//! - `input` accepts from `tap0` only redirected packets (`ct status dnat`) from the guest's own
//!   address to those forwarder ports, and rejects everything else: a guest dialling a forwarder
//!   port directly, or spoofing another source, is refused.

use std::io::Write;
use std::process::{Command, Stdio};

use crate::net::{
    DNS_PORT, GUEST_IP, HOST_IP, HTTP_PORT, HTTPS_PORT, RESOURCE_NET, RESOURCE_PORT,
    RESOURCE_PREFIX_LEN, TAP_NAME, TCP_PORT,
};
use crate::protocol::BootMode;

/// The runner's table. A name of its own, so Docker's tables in the same netns are untouched.
pub const TABLE: &str = "sealant_vm";

/// How guest TCP leaves the VM, from the worktree's Access policy.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Egress {
    /// Every public TCP port: 80 and 443 through their own forwarders (so HTTPS reaches the
    /// proxy's brokering and inspection), every other port through the general forwarder.
    Standard,
    /// Ports 80 and 443 through their own forwarders, plus the policy's extra TCP ports through
    /// the general one; every other port is rejected.
    Restricted { extra_tcp_ports: Vec<u16> },
}

/// What the ruleset is built from.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Policy {
    pub mode: BootMode,
    pub egress: Egress,
}

impl Policy {
    /// The local forwarder ports the guest may reach, and so the ones the runner listens on.
    /// Empty in recovery: `<name>-proxy` is stopped, so nothing leaves the VM by IP.
    pub fn forwarder_ports(&self) -> Vec<u16> {
        if self.mode == BootMode::Recover {
            return Vec::new();
        }
        let mut ports = vec![DNS_PORT, RESOURCE_PORT, HTTP_PORT, HTTPS_PORT];
        match &self.egress {
            Egress::Standard => ports.push(TCP_PORT),
            Egress::Restricted { .. } => {
                if !self.extra_tcp_ports().is_empty() {
                    ports.push(TCP_PORT);
                }
            }
        }
        ports.sort_unstable();
        ports
    }

    /// The restricted policy's extra ports, sorted and deduplicated, without the ones that already
    /// have a forwarder of their own (53, 80, 443) or are not a port (0).
    pub fn extra_tcp_ports(&self) -> Vec<u16> {
        let Egress::Restricted { extra_tcp_ports } = &self.egress else {
            return Vec::new();
        };
        let mut ports: Vec<u16> = extra_tcp_ports
            .iter()
            .copied()
            .filter(|p| !matches!(p, 0 | 53 | 80 | 443))
            .collect();
        ports.sort_unstable();
        ports.dedup();
        ports
    }
}

/// The table definition for `policy`, without the replace preamble [`script`] adds.
pub fn ruleset(policy: &Policy) -> String {
    let tap = TAP_NAME;
    let mut prerouting = Vec::new();
    if policy.mode == BootMode::Normal {
        let v4 = format!("iifname \"{tap}\" meta nfproto ipv4");
        prerouting.push(format!("{v4} udp dport 53 redirect to :{DNS_PORT}"));
        prerouting.push(format!("{v4} tcp dport 53 redirect to :{DNS_PORT}"));
        prerouting.push(format!(
            "{v4} ip daddr {RESOURCE_NET}/{RESOURCE_PREFIX_LEN} meta l4proto tcp redirect to :{RESOURCE_PORT}"
        ));
        prerouting.push(format!("{v4} tcp dport 80 redirect to :{HTTP_PORT}"));
        prerouting.push(format!("{v4} tcp dport 443 redirect to :{HTTPS_PORT}"));
        match &policy.egress {
            Egress::Standard => {
                prerouting.push(format!("{v4} meta l4proto tcp redirect to :{TCP_PORT}"));
            }
            Egress::Restricted { .. } => {
                let extra = policy.extra_tcp_ports();
                if !extra.is_empty() {
                    prerouting.push(format!(
                        "{v4} tcp dport {} redirect to :{TCP_PORT}",
                        nft_set(&extra)
                    ));
                }
            }
        }
    }

    let mut input = Vec::new();
    let ports = policy.forwarder_ports();
    let redirected =
        format!("iifname \"{tap}\" ip saddr {GUEST_IP} ip daddr {HOST_IP} ct status dnat");
    if ports.contains(&DNS_PORT) {
        input.push(format!("{redirected} udp dport {DNS_PORT} accept"));
    }
    if !ports.is_empty() {
        input.push(format!("{redirected} tcp dport {} accept", nft_set(&ports)));
    }
    input.push(format!(
        "iifname \"{tap}\" meta l4proto tcp reject with tcp reset"
    ));
    input.push(format!("iifname \"{tap}\" reject"));

    let mut out = String::new();
    out.push_str(&format!("table inet {TABLE} {{\n"));
    out.push_str(
        "\tchain prerouting {\n\t\ttype nat hook prerouting priority dstnat; policy accept;\n",
    );
    for rule in &prerouting {
        out.push_str(&format!("\t\t{rule}\n"));
    }
    out.push_str("\t}\n");
    out.push_str("\tchain input {\n\t\ttype filter hook input priority filter; policy accept;\n");
    for rule in &input {
        out.push_str(&format!("\t\t{rule}\n"));
    }
    out.push_str("\t}\n");
    out.push_str("\tchain forward {\n\t\ttype filter hook forward priority 0; policy drop;\n\t}\n");
    out.push_str("}\n");
    out
}

/// The whole `nft -f -` batch: create-if-missing, delete, define. One transaction, so the table is
/// replaced atomically or not at all.
pub fn script(policy: &Policy) -> String {
    format!(
        "add table inet {TABLE}\ndelete table inet {TABLE}\n{}",
        ruleset(policy)
    )
}

fn nft_set(ports: &[u16]) -> String {
    if let [one] = ports {
        return one.to_string();
    }
    let list: Vec<String> = ports.iter().map(u16::to_string).collect();
    format!("{{ {} }}", list.join(", "))
}

#[derive(Debug, thiserror::Error)]
pub enum NftError {
    #[error("could not run {bin}: {source}")]
    Spawn { bin: String, source: std::io::Error },
    #[error("{bin} refused the batch ({status}): {stderr}")]
    Refused {
        bin: String,
        status: std::process::ExitStatus,
        stderr: String,
    },
}

/// Feeds `batch` to `nft -f -`. Any failure is an error the caller must treat as fatal.
pub fn apply(nft_bin: &str, batch: &str) -> Result<(), NftError> {
    run(nft_bin, &["-f", "-"], Some(batch)).map(|_| ())
}

/// Runs `nft` with `args`, optionally writing `stdin`, and answers its stdout.
pub fn run(nft_bin: &str, args: &[&str], stdin: Option<&str>) -> Result<String, NftError> {
    let spawn_err = |source| NftError::Spawn {
        bin: nft_bin.to_owned(),
        source,
    };
    #[allow(
        clippy::disallowed_methods,
        reason = "the runner is its own binary with no orphan reaper, which is what the spawn gate protects against; the gate would also close the TAP descriptor the VMM must inherit"
    )]
    let mut child = Command::new(nft_bin)
        .args(args)
        .stdin(if stdin.is_some() {
            Stdio::piped()
        } else {
            Stdio::null()
        })
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(spawn_err)?;
    if let (Some(text), Some(mut pipe)) = (stdin, child.stdin.take()) {
        pipe.write_all(text.as_bytes()).map_err(spawn_err)?;
    }
    let output = child.wait_with_output().map_err(spawn_err)?;
    if !output.status.success() {
        return Err(NftError::Refused {
            bin: nft_bin.to_owned(),
            status: output.status,
            stderr: String::from_utf8_lossy(&output.stderr).trim().to_owned(),
        });
    }
    Ok(String::from_utf8_lossy(&output.stdout).into_owned())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn policy(mode: BootMode, egress: Egress) -> Policy {
        Policy { mode, egress }
    }

    /// The rules of one chain, trimmed, without its `type ... hook` header line.
    fn chain(ruleset: &str, name: &str) -> Vec<String> {
        let start = ruleset
            .find(&format!("chain {name} {{"))
            .unwrap_or_else(|| panic!("no chain {name} in\n{ruleset}"));
        let body = &ruleset[start..];
        let end = body.find("\n\t}").unwrap();
        body[..end]
            .lines()
            .skip(2)
            .map(|l| l.trim().to_owned())
            .collect()
    }

    fn header(ruleset: &str, name: &str) -> String {
        let start = ruleset.find(&format!("chain {name} {{")).unwrap();
        ruleset[start..].lines().nth(1).unwrap().trim().to_owned()
    }

    fn assert_forward_drops(ruleset: &str) {
        assert_eq!(
            header(ruleset, "forward"),
            "type filter hook forward priority 0; policy drop;"
        );
        assert!(
            chain(ruleset, "forward").is_empty(),
            "forward has rules:\n{ruleset}"
        );
    }

    const V4: &str = "iifname \"tap0\" meta nfproto ipv4";
    const REDIRECTED: &str =
        "iifname \"tap0\" ip saddr 10.200.0.2 ip daddr 10.200.0.1 ct status dnat";

    #[test]
    fn standard_sends_http_and_https_to_their_forwarders_and_every_other_tcp_port_to_15444() {
        let rules = ruleset(&policy(BootMode::Normal, Egress::Standard));
        assert_forward_drops(&rules);
        // 80 and 443 come before the catch-all: HTTPS must reach the proxy's :15443 handler
        // (brokering, inspection, revocation), not the plain TCP relay.
        assert_eq!(
            chain(&rules, "prerouting"),
            vec![
                format!("{V4} udp dport 53 redirect to :15053"),
                format!("{V4} tcp dport 53 redirect to :15053"),
                format!("{V4} ip daddr 10.201.0.0/16 meta l4proto tcp redirect to :15100"),
                format!("{V4} tcp dport 80 redirect to :15080"),
                format!("{V4} tcp dport 443 redirect to :15443"),
                format!("{V4} meta l4proto tcp redirect to :15444"),
            ]
        );
        assert_eq!(
            chain(&rules, "input"),
            vec![
                format!("{REDIRECTED} udp dport 15053 accept"),
                format!("{REDIRECTED} tcp dport {{ 15053, 15080, 15100, 15443, 15444 }} accept"),
                "iifname \"tap0\" meta l4proto tcp reject with tcp reset".to_owned(),
                "iifname \"tap0\" reject".to_owned(),
            ]
        );
    }

    #[test]
    fn restricted_redirects_only_80_and_443_and_rejects_other_ports() {
        let rules = ruleset(&policy(
            BootMode::Normal,
            Egress::Restricted {
                extra_tcp_ports: vec![],
            },
        ));
        assert_forward_drops(&rules);
        assert_eq!(
            chain(&rules, "prerouting"),
            vec![
                format!("{V4} udp dport 53 redirect to :15053"),
                format!("{V4} tcp dport 53 redirect to :15053"),
                format!("{V4} ip daddr 10.201.0.0/16 meta l4proto tcp redirect to :15100"),
                format!("{V4} tcp dport 80 redirect to :15080"),
                format!("{V4} tcp dport 443 redirect to :15443"),
            ]
        );
        let input = chain(&rules, "input");
        assert_eq!(
            input[1],
            format!("{REDIRECTED} tcp dport {{ 15053, 15080, 15100, 15443 }} accept")
        );
        assert!(
            !rules.contains("15444"),
            "restricted without extra ports opened 15444:\n{rules}"
        );
        assert_eq!(input.last().unwrap(), "iifname \"tap0\" reject");
    }

    #[test]
    fn restricted_extra_ports_go_to_the_general_forwarder() {
        let p = policy(
            BootMode::Normal,
            Egress::Restricted {
                extra_tcp_ports: vec![5432, 22, 443, 22, 0, 53],
            },
        );
        assert_eq!(p.extra_tcp_ports(), vec![22, 5432]);
        let rules = ruleset(&p);
        let prerouting = chain(&rules, "prerouting");
        assert_eq!(
            prerouting.last().unwrap(),
            &format!("{V4} tcp dport {{ 22, 5432 }} redirect to :15444")
        );
        assert!(
            !prerouting
                .iter()
                .any(|r| r.contains("meta l4proto tcp redirect to :15444")),
            "restricted has a catch-all TCP redirect:\n{rules}"
        );
        assert_eq!(
            chain(&rules, "input")[1],
            format!("{REDIRECTED} tcp dport {{ 15053, 15080, 15100, 15443, 15444 }} accept")
        );

        let one = ruleset(&policy(
            BootMode::Normal,
            Egress::Restricted {
                extra_tcp_ports: vec![22],
            },
        ));
        assert!(one.contains(&format!("{V4} tcp dport 22 redirect to :15444")));
    }

    #[test]
    fn recovery_redirects_nothing_and_rejects_everything_from_tap0() {
        for egress in [
            Egress::Standard,
            Egress::Restricted {
                extra_tcp_ports: vec![22],
            },
        ] {
            let p = policy(BootMode::Recover, egress);
            assert!(p.forwarder_ports().is_empty());
            let rules = ruleset(&p);
            assert_forward_drops(&rules);
            assert!(chain(&rules, "prerouting").is_empty(), "{rules}");
            assert_eq!(
                chain(&rules, "input"),
                vec![
                    "iifname \"tap0\" meta l4proto tcp reject with tcp reset".to_owned(),
                    "iifname \"tap0\" reject".to_owned(),
                ]
            );
        }
    }

    #[test]
    fn the_batch_replaces_the_table_in_one_transaction() {
        let batch = script(&policy(BootMode::Normal, Egress::Standard));
        let mut lines = batch.lines();
        assert_eq!(lines.next(), Some("add table inet sealant_vm"));
        assert_eq!(lines.next(), Some("delete table inet sealant_vm"));
        assert_eq!(lines.next(), Some("table inet sealant_vm {"));
    }

    #[test]
    fn a_refusing_nft_is_an_error() {
        let err = apply("false", "table inet x {}\n").unwrap_err();
        assert!(matches!(err, NftError::Refused { .. }), "{err}");
        let err = apply("/nonexistent/nft", "").unwrap_err();
        assert!(matches!(err, NftError::Spawn { .. }), "{err}");
    }
}
