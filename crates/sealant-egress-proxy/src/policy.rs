//! The policy Sealant loads over `PUT /v1/policy`, and its validated in-memory form.

use std::collections::BTreeSet;
use std::fmt;
use std::net::{IpAddr, Ipv4Addr};
use std::sync::Arc;
use std::time::Duration;

use serde::Deserialize;

use crate::ip::{AddressRules, Cidr};
use crate::tls::MitmAuthority;

/// The disconnected lease when the policy names none (architecture §7.3).
pub const DEFAULT_LEASE_TTL_SECS: u64 = 120;
/// The lease never outlasts the architecture's 120 s bound: a dead control plane fails closed
/// within two minutes whatever a policy asks for.
const MAX_LEASE_TTL_SECS: u64 = DEFAULT_LEASE_TTL_SECS;

/// The synthetic guest range worktree resources are answered from.
pub(crate) fn synthetic_resource_net() -> Cidr {
    Cidr::new(IpAddr::V4(Ipv4Addr::new(10, 201, 0, 0)), 16).unwrap_or_else(|_| unreachable!())
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum Mode {
    Standard,
    Restricted,
}

impl Mode {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Standard => "standard",
            Self::Restricted => "restricted",
        }
    }
}

/// A real secret value. Its `Debug` never prints it.
#[derive(Clone, Deserialize)]
#[serde(transparent)]
pub struct SecretValue(String);

impl SecretValue {
    pub(crate) fn expose(&self) -> &str {
        &self.0
    }
}

impl PartialEq for SecretValue {
    fn eq(&self, other: &Self) -> bool {
        self.0 == other.0
    }
}

impl fmt::Debug for SecretValue {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("<redacted>")
    }
}

/// The body of `PUT /v1/policy`, as Sealant sends it.
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PolicyDocument {
    pub mode: Mode,
    pub policy_hash: String,
    pub revocation_watermark: u64,
    #[serde(default)]
    pub lease_ttl_secs: Option<u64>,
    #[serde(default)]
    pub operator_allowed_private_cidrs: Vec<String>,
    #[serde(default)]
    pub host_public_ips: Vec<String>,
    /// Docker bridge gateways and container subnets to block (configured by the orchestrator).
    #[serde(default)]
    pub blocked_cidrs: Vec<String>,
    #[serde(default)]
    pub allow_hosts: Vec<AllowHostDocument>,
    #[serde(default)]
    pub allow_mirrors: Vec<MirrorDocument>,
    #[serde(default)]
    pub allow_resources: Vec<ResourceDocument>,
    #[serde(default)]
    pub brokered_secrets: Vec<BrokeredSecretDocument>,
    #[serde(default)]
    pub executor_ca_cert_pem: Option<String>,
    #[serde(default)]
    pub executor_ca_key_pem: Option<SecretValue>,
    /// Durable host tombstones Sealant holds: refused in every mode, whatever else the policy says.
    #[serde(default)]
    pub revoked_hosts: Vec<String>,
    /// Durable secret tombstones Sealant holds: never loaded, whatever else the policy says.
    #[serde(default)]
    pub revoked_secret_ids: Vec<String>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AllowHostDocument {
    pub host: String,
    #[serde(default)]
    pub ports: Option<Vec<u16>>,
    #[serde(default)]
    pub inspect_tls: bool,
    #[serde(default)]
    pub methods: Option<Vec<String>>,
    #[serde(default)]
    pub path_prefixes: Option<Vec<String>>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct MirrorDocument {
    pub name: String,
    pub host: String,
    pub port: u16,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ResourceDocument {
    pub name: String,
    pub host: String,
    pub port: u16,
    pub guest_ip: Ipv4Addr,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct BrokeredSecretDocument {
    pub secret_id: String,
    #[serde(default)]
    pub name: Option<String>,
    pub placeholder: String,
    /// The real secret, resolved by Sealant for this proxy only.
    pub value: SecretValue,
    pub header_name: String,
    pub bind_hosts: Vec<String>,
    #[serde(default)]
    pub methods: Option<Vec<String>>,
    #[serde(default)]
    pub path_prefixes: Option<Vec<String>>,
}

#[derive(Debug, thiserror::Error)]
pub enum PolicyError {
    #[error("{0}")]
    Invalid(String),
    #[error("executor CA: {0}")]
    Ca(String),
}

fn invalid(message: impl Into<String>) -> PolicyError {
    PolicyError::Invalid(message.into())
}

/// A host the policy allows, with its ports and inspection rules.
#[derive(Clone, Debug)]
pub struct AllowHost {
    pub host: String,
    pub ports: Vec<u16>,
    pub inspect_tls: bool,
    pub methods: Option<Vec<String>>,
    pub path_prefixes: Option<Vec<String>>,
}

#[derive(Clone, Debug)]
pub struct Mirror {
    pub name: String,
    pub host: String,
    pub port: u16,
}

#[derive(Clone, Debug)]
pub struct Resource {
    pub name: String,
    pub host: String,
    pub port: u16,
    pub guest_ip: Ipv4Addr,
}

#[derive(Clone, Debug)]
pub struct BrokeredSecret {
    pub secret_id: String,
    pub placeholder: String,
    pub value: SecretValue,
    /// Lowercased.
    pub header_name: String,
    pub bind_hosts: Vec<String>,
    pub methods: Option<Vec<String>>,
    pub path_prefixes: Option<Vec<String>>,
}

impl BrokeredSecret {
    pub(crate) fn permits(&self, method: &str, path: &str) -> bool {
        scope_permits(
            self.methods.as_deref(),
            self.path_prefixes.as_deref(),
            method,
            path,
        )
    }
}

pub(crate) fn scope_permits(
    methods: Option<&[String]>,
    path_prefixes: Option<&[String]>,
    method: &str,
    path: &str,
) -> bool {
    let method_ok = methods.is_none_or(|methods| methods.iter().any(|m| m == method));
    let path_ok =
        path_prefixes.is_none_or(|prefixes| prefixes.iter().any(|p| path.starts_with(p.as_str())));
    method_ok && path_ok
}

/// The validated policy the proxy enforces.
#[derive(Clone, Debug)]
pub struct Policy {
    pub mode: Mode,
    pub policy_hash: String,
    pub revocation_watermark: u64,
    pub lease_ttl: Duration,
    pub addresses: AddressRules,
    pub allow_hosts: Vec<AllowHost>,
    pub mirrors: Vec<Mirror>,
    pub resources: Vec<Resource>,
    pub secrets: Vec<BrokeredSecret>,
    /// Hosts revoked since this policy loaded; refused in every mode until the next policy.
    pub denied_hosts: BTreeSet<String>,
    pub ca: Option<Arc<MitmAuthority>>,
    /// The PEM the CA was built from, so an unchanged CA keeps its minted-leaf cache.
    pub(crate) ca_source: Option<(String, SecretValue)>,
}

impl Policy {
    /// Validate a document. `previous` lends its CA when the PEM is unchanged.
    pub fn from_document(
        doc: PolicyDocument,
        previous: Option<&Policy>,
    ) -> Result<Self, PolicyError> {
        let lease_ttl_secs = doc.lease_ttl_secs.unwrap_or(DEFAULT_LEASE_TTL_SECS);
        if lease_ttl_secs == 0 || lease_ttl_secs > MAX_LEASE_TTL_SECS {
            return Err(invalid(format!(
                "leaseTtlSecs must be between 1 and {MAX_LEASE_TTL_SECS}"
            )));
        }
        if doc.policy_hash.trim().is_empty() {
            return Err(invalid("policyHash is required"));
        }
        let cidrs = |field: &str, items: &[String]| -> Result<Vec<Cidr>, PolicyError> {
            items
                .iter()
                .map(|text| Cidr::parse(text).map_err(|e| invalid(format!("{field}: {e}"))))
                .collect()
        };
        let addresses = AddressRules {
            operator_allowed: cidrs(
                "operatorAllowedPrivateCidrs",
                &doc.operator_allowed_private_cidrs,
            )?,
            host_public: cidrs("hostPublicIps", &doc.host_public_ips)?,
            configured_blocked: cidrs("blockedCidrs", &doc.blocked_cidrs)?,
        };

        let mut allow_hosts = Vec::with_capacity(doc.allow_hosts.len());
        for entry in doc.allow_hosts {
            let host = policy_host("allowHosts", &entry.host)?;
            let ports = entry.ports.unwrap_or_else(|| vec![443]);
            if ports.is_empty() || ports.contains(&0) {
                return Err(invalid(format!(
                    "allowHosts `{host}`: ports must be 1-65535"
                )));
            }
            allow_hosts.push(AllowHost {
                host,
                ports,
                inspect_tls: entry.inspect_tls,
                methods: methods("allowHosts", entry.methods)?,
                path_prefixes: path_prefixes("allowHosts", entry.path_prefixes)?,
            });
        }

        let mut mirrors = Vec::with_capacity(doc.allow_mirrors.len());
        for entry in doc.allow_mirrors {
            if entry.port == 0 {
                return Err(invalid("allowMirrors: port must be 1-65535"));
            }
            mirrors.push(Mirror {
                name: entry.name,
                host: policy_host("allowMirrors", &entry.host)?,
                port: entry.port,
            });
        }

        let synthetic = synthetic_resource_net();
        let mut resources: Vec<Resource> = Vec::with_capacity(doc.allow_resources.len());
        for entry in doc.allow_resources {
            if !synthetic.contains(IpAddr::V4(entry.guest_ip)) {
                return Err(invalid(format!(
                    "allowResources `{}`: guestIp {} is outside {synthetic}",
                    entry.name, entry.guest_ip
                )));
            }
            if entry.port == 0 {
                return Err(invalid("allowResources: port must be 1-65535"));
            }
            let name = policy_host("allowResources", &entry.name)?;
            if resources
                .iter()
                .any(|r| r.guest_ip == entry.guest_ip && r.port == entry.port)
            {
                return Err(invalid(format!(
                    "allowResources: {}:{} is assigned twice",
                    entry.guest_ip, entry.port
                )));
            }
            resources.push(Resource {
                name,
                host: policy_host("allowResources", &entry.host)?,
                port: entry.port,
                guest_ip: entry.guest_ip,
            });
        }

        let mut secrets: Vec<BrokeredSecret> = Vec::with_capacity(doc.brokered_secrets.len());
        for entry in doc.brokered_secrets {
            let id = entry.secret_id.trim().to_string();
            if id.is_empty() {
                return Err(invalid("brokeredSecrets: secretId is required"));
            }
            if secrets.iter().any(|s| s.secret_id == id) {
                return Err(invalid(format!("brokeredSecrets: `{id}` appears twice")));
            }
            if entry.placeholder.len() < 8 || !entry.placeholder.bytes().all(is_visible_ascii) {
                return Err(invalid(format!(
                    "brokeredSecrets `{id}`: placeholder must be at least 8 visible ASCII characters"
                )));
            }
            let value = entry.value.expose();
            if value.is_empty()
                || value
                    .bytes()
                    .any(|b| b == b'\r' || b == b'\n' || b == 0 || (b < 0x20 && b != b'\t'))
            {
                return Err(invalid(format!(
                    "brokeredSecrets `{id}`: value must be a non-empty single-line header value"
                )));
            }
            if FORBIDDEN_SECRET_HEADERS
                .iter()
                .any(|h| h.eq_ignore_ascii_case(entry.header_name.trim()))
            {
                return Err(invalid(format!(
                    "brokeredSecrets `{id}`: headerName `{}` frames or routes the request and cannot carry a secret",
                    entry.header_name
                )));
            }
            if !is_header_token(&entry.header_name) {
                return Err(invalid(format!(
                    "brokeredSecrets `{id}`: headerName must be one HTTP header name"
                )));
            }
            if entry.bind_hosts.is_empty() {
                return Err(invalid(format!(
                    "brokeredSecrets `{id}`: bindHosts must name at least one host"
                )));
            }
            let bind_hosts = entry
                .bind_hosts
                .iter()
                .map(|host| policy_host("brokeredSecrets.bindHosts", host))
                .collect::<Result<Vec<_>, _>>()?;
            if bind_hosts.iter().any(|h| h.parse::<IpAddr>().is_ok()) {
                return Err(invalid(format!(
                    "brokeredSecrets `{id}`: bindHosts must be hostnames, not IP addresses"
                )));
            }
            secrets.push(BrokeredSecret {
                secret_id: id,
                placeholder: entry.placeholder,
                value: entry.value,
                header_name: entry.header_name.to_ascii_lowercase(),
                bind_hosts,
                methods: methods("brokeredSecrets", entry.methods)?,
                path_prefixes: path_prefixes("brokeredSecrets", entry.path_prefixes)?,
            });
        }

        let needs_ca = !secrets.is_empty() || allow_hosts.iter().any(|h| h.inspect_tls);
        let (ca, ca_source) = match (doc.executor_ca_cert_pem, doc.executor_ca_key_pem) {
            (Some(cert), Some(key)) => {
                let source = (cert, key);
                let reused = previous.and_then(|p| match (&p.ca, &p.ca_source) {
                    (Some(ca), Some(prev)) if *prev == source => Some(ca.clone()),
                    _ => None,
                });
                let ca = match reused {
                    Some(ca) => ca,
                    None => Arc::new(
                        MitmAuthority::from_pem(&source.0, source.1.expose())
                            .map_err(|e| PolicyError::Ca(e.to_string()))?,
                    ),
                };
                (Some(ca), Some(source))
            }
            (None, None) => (None, None),
            _ => {
                return Err(invalid(
                    "executorCaCertPem and executorCaKeyPem must be given together",
                ));
            }
        };
        if needs_ca && ca.is_none() {
            return Err(invalid(
                "brokered secrets and inspectTls hosts need executorCaCertPem and executorCaKeyPem",
            ));
        }

        let mut policy = Self {
            mode: doc.mode,
            policy_hash: doc.policy_hash,
            revocation_watermark: doc.revocation_watermark,
            lease_ttl: Duration::from_secs(lease_ttl_secs),
            addresses,
            allow_hosts,
            mirrors,
            resources,
            secrets,
            denied_hosts: BTreeSet::new(),
            ca,
            ca_source,
        };
        for id in &doc.revoked_secret_ids {
            policy.revoke_secret(id.trim());
        }
        for host in &doc.revoked_hosts {
            let host = normalize_host(host)
                .ok_or_else(|| invalid(format!("revokedHosts: `{host}` is not a hostname")))?;
            policy.revoke_host(&host);
        }
        Ok(policy)
    }

    pub(crate) fn host_denied(&self, host: &str) -> bool {
        self.denied_hosts.contains(host)
    }

    /// Whether Restricted egress allows `(host, port)`.
    pub(crate) fn restricted_allows(&self, host: &str, port: u16) -> bool {
        if self.host_denied(host) {
            return false;
        }
        self.allow_hosts
            .iter()
            .any(|h| h.host == host && h.ports.contains(&port))
            || self
                .mirrors
                .iter()
                .any(|m| m.host == host && m.port == port)
            || (port == 443
                && self
                    .secrets
                    .iter()
                    .any(|s| s.bind_hosts.iter().any(|b| b == host)))
    }

    /// Whether Restricted egress answers DNS for `name`.
    pub(crate) fn restricted_dns_name(&self, name: &str) -> bool {
        !self.host_denied(name)
            && (self.allow_hosts.iter().any(|h| h.host == name)
                || self.mirrors.iter().any(|m| m.host == name)
                || self.resources.iter().any(|r| r.name == name)
                || self
                    .secrets
                    .iter()
                    .any(|s| s.bind_hosts.iter().any(|b| b == name)))
    }

    /// Whether HTTPS to `host` is terminated and inspected rather than passed through.
    pub(crate) fn inspects(&self, host: &str) -> bool {
        self.secrets
            .iter()
            .any(|s| s.bind_hosts.iter().any(|b| b == host))
            || self
                .allow_hosts
                .iter()
                .any(|h| h.host == host && h.inspect_tls)
    }

    /// The ports TLS to an inspected `host` is terminated on: its `allowHosts` ports, else 443.
    fn inspection_ports(&self, host: &str) -> Vec<u16> {
        let configured: Vec<u16> = self
            .allow_hosts
            .iter()
            .filter(|h| h.host == host)
            .flat_map(|h| h.ports.iter().copied())
            .collect();
        if configured.is_empty() {
            vec![443]
        } else {
            configured
        }
    }

    /// Whether TLS to `(host, port)` is terminated and inspected. A brokered host on a port the
    /// policy never named is passed through untouched, so no secret goes to an arbitrary port.
    pub(crate) fn inspects_on(&self, host: &str, port: u16) -> bool {
        self.inspects(host) && self.inspection_ports(host).contains(&port)
    }

    /// Whether any inspected host is inspected on `port`.
    pub(crate) fn inspects_any_on(&self, port: u16) -> bool {
        self.secrets
            .iter()
            .flat_map(|s| s.bind_hosts.iter())
            .chain(
                self.allow_hosts
                    .iter()
                    .filter(|h| h.inspect_tls)
                    .map(|h| &h.host),
            )
            .any(|host| self.inspects_on(host, port))
    }

    pub(crate) fn secrets_for<'a>(
        &'a self,
        host: &'a str,
    ) -> impl Iterator<Item = &'a BrokeredSecret> + 'a {
        self.secrets
            .iter()
            .filter(move |s| s.bind_hosts.iter().any(|b| b == host))
    }

    pub(crate) fn secret_ids_for(&self, host: &str) -> Vec<String> {
        let mut ids: Vec<String> = self
            .secrets_for(host)
            .map(|s| s.secret_id.clone())
            .collect();
        ids.sort();
        ids
    }

    /// The `allowHosts` rule for an inspected `(host, port)`, whether inspection comes from
    /// `inspectTls` or from a brokered secret, so its methods and path prefixes always apply.
    pub(crate) fn inspect_rule(&self, host: &str, port: u16) -> Option<&AllowHost> {
        self.allow_hosts
            .iter()
            .find(|h| h.host == host && h.ports.contains(&port))
    }

    pub(crate) fn mirror_for(&self, host: &str, port: u16) -> Option<&Mirror> {
        self.mirrors
            .iter()
            .find(|m| m.host == host && m.port == port)
    }

    pub(crate) fn mirror_named(&self, host: &str) -> Option<&Mirror> {
        self.mirrors.iter().find(|m| m.host == host)
    }

    pub(crate) fn resource_named(&self, name: &str) -> Option<&Resource> {
        self.resources.iter().find(|r| r.name == name)
    }

    pub(crate) fn resource_at(&self, guest_ip: Ipv4Addr, port: u16) -> Option<&Resource> {
        self.resources
            .iter()
            .find(|r| r.guest_ip == guest_ip && r.port == port)
    }

    /// Remove a revoked secret. Returns whether it was present.
    pub(crate) fn revoke_secret(&mut self, id: &str) -> bool {
        let before = self.secrets.len();
        self.secrets.retain(|s| s.secret_id != id);
        before != self.secrets.len()
    }

    /// Revoke a host: drop its grants and refuse it in every mode until the next policy.
    pub(crate) fn revoke_host(&mut self, host: &str) {
        self.allow_hosts.retain(|h| h.host != host);
        self.mirrors.retain(|m| m.host != host);
        self.resources.retain(|r| r.name != host && r.host != host);
        for secret in &mut self.secrets {
            secret.bind_hosts.retain(|b| b != host);
        }
        self.secrets.retain(|s| !s.bind_hosts.is_empty());
        self.denied_hosts.insert(host.to_string());
    }

    /// Revoke every grant: brokered secrets, allowed hosts, mirrors and resources.
    pub(crate) fn revoke_all(&mut self) {
        let hosts: Vec<String> = self
            .allow_hosts
            .iter()
            .map(|h| h.host.clone())
            .chain(self.secrets.iter().flat_map(|s| s.bind_hosts.clone()))
            .collect();
        self.denied_hosts.extend(hosts);
        self.allow_hosts.clear();
        self.mirrors.clear();
        self.resources.clear();
        self.secrets.clear();
    }
}

/// Headers that frame, route or authenticate the request to the proxy itself.
const FORBIDDEN_SECRET_HEADERS: &[&str] = &[
    "host",
    "content-length",
    "transfer-encoding",
    "connection",
    "upgrade",
    "te",
    "trailer",
    "keep-alive",
    "proxy-authorization",
    "proxy-connection",
];

fn is_visible_ascii(b: u8) -> bool {
    (0x21..=0x7e).contains(&b)
}

pub(crate) fn is_header_token(name: &str) -> bool {
    !name.is_empty()
        && name.bytes().all(|b| {
            b.is_ascii_alphanumeric()
                || matches!(
                    b,
                    b'!' | b'#'
                        | b'$'
                        | b'%'
                        | b'&'
                        | b'\''
                        | b'*'
                        | b'+'
                        | b'-'
                        | b'.'
                        | b'^'
                        | b'_'
                        | b'`'
                        | b'|'
                        | b'~'
                )
        })
}

fn methods(field: &str, methods: Option<Vec<String>>) -> Result<Option<Vec<String>>, PolicyError> {
    let Some(methods) = methods else {
        return Ok(None);
    };
    methods
        .into_iter()
        .map(|m| {
            let upper = m.trim().to_ascii_uppercase();
            if is_header_token(&upper) {
                Ok(upper)
            } else {
                Err(invalid(format!("{field}: `{m}` is not an HTTP method")))
            }
        })
        .collect::<Result<Vec<_>, _>>()
        .map(Some)
}

fn path_prefixes(
    field: &str,
    prefixes: Option<Vec<String>>,
) -> Result<Option<Vec<String>>, PolicyError> {
    let Some(prefixes) = prefixes else {
        return Ok(None);
    };
    for prefix in &prefixes {
        if !prefix.starts_with('/') {
            return Err(invalid(format!(
                "{field}: path prefix `{prefix}` must start with `/`"
            )));
        }
    }
    Ok(Some(prefixes))
}

/// A policy hostname: an exact name or IP literal, never a wildcard.
fn policy_host(field: &str, host: &str) -> Result<String, PolicyError> {
    if host.contains('*') {
        return Err(invalid(format!(
            "{field}: `{host}` is a wildcard; name exact hosts"
        )));
    }
    normalize_host(host).ok_or_else(|| invalid(format!("{field}: `{host}` is not a hostname")))
}

/// Lowercase a hostname, drop a trailing dot and an IPv6 literal's brackets, and refuse anything
/// that is not a DNS name or an IP literal.
pub fn normalize_host(host: &str) -> Option<String> {
    let host = host.trim();
    let host = host.strip_suffix('.').unwrap_or(host);
    if let Some(inner) = host.strip_prefix('[').and_then(|h| h.strip_suffix(']')) {
        return inner
            .parse::<std::net::Ipv6Addr>()
            .ok()
            .map(|ip| ip.to_string());
    }
    if let Ok(ip) = host.parse::<IpAddr>() {
        return Some(ip.to_string());
    }
    if host.is_empty() || host.len() > 253 {
        return None;
    }
    let lower = host.to_ascii_lowercase();
    let labels_ok = lower.split('.').all(|label| {
        !label.is_empty()
            && label.len() <= 63
            && label
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
    });
    labels_ok.then_some(lower)
}

/// Split `host[:port]` (with `[v6]:port` support) into a normalized host and optional port.
pub fn split_host_port(authority: &str) -> Option<(String, Option<u16>)> {
    let authority = authority.trim();
    if let Some(rest) = authority.strip_prefix('[') {
        let (inner, after) = rest.split_once(']')?;
        let host = normalize_host(&format!("[{inner}]"))?;
        return match after.strip_prefix(':') {
            Some(port) => Some((host, Some(port.parse().ok()?))),
            None if after.is_empty() => Some((host, None)),
            None => None,
        };
    }
    match authority.rsplit_once(':') {
        Some((host, port)) if !host.contains(':') => {
            Some((normalize_host(host)?, Some(port.parse().ok()?)))
        }
        Some(_) => None,
        None => Some((normalize_host(authority)?, None)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn doc(json: serde_json::Value) -> PolicyDocument {
        serde_json::from_value(json).unwrap()
    }

    #[test]
    fn hosts_normalize_and_reject_wildcards() {
        assert_eq!(
            normalize_host("API.Example.com."),
            Some("api.example.com".into())
        );
        assert_eq!(normalize_host("[::1]"), Some("::1".into()));
        assert_eq!(normalize_host("bad host"), None);
        assert_eq!(normalize_host(""), None);
        assert_eq!(
            split_host_port("Api.Example.com:8443"),
            Some(("api.example.com".into(), Some(8443)))
        );
        assert_eq!(
            split_host_port("[::1]:443"),
            Some(("::1".into(), Some(443)))
        );
        assert_eq!(
            split_host_port("example.com"),
            Some(("example.com".into(), None))
        );
        assert_eq!(split_host_port("example.com:99999"), None);
        let err = Policy::from_document(
            doc(serde_json::json!({
                "mode": "restricted", "policyHash": "h", "revocationWatermark": 0,
                "allowHosts": [{ "host": "*.example.com" }]
            })),
            None,
        )
        .unwrap_err();
        assert!(err.to_string().contains("wildcard"), "{err}");
    }

    #[test]
    fn defaults_lease_to_120_seconds_and_ports_to_443() {
        let policy = Policy::from_document(
            doc(serde_json::json!({
                "mode": "restricted", "policyHash": "h", "revocationWatermark": 3,
                "allowHosts": [{ "host": "Registry.NPMjs.org" }]
            })),
            None,
        )
        .unwrap();
        assert_eq!(policy.lease_ttl, Duration::from_secs(120));
        assert!(policy.restricted_allows("registry.npmjs.org", 443));
        assert!(!policy.restricted_allows("registry.npmjs.org", 80));
        assert!(!policy.restricted_allows("example.com", 443));
    }

    #[test]
    fn brokered_secrets_need_a_ca_and_a_single_line_value() {
        let base = |secret: serde_json::Value| {
            doc(serde_json::json!({
                "mode": "standard", "policyHash": "h", "revocationWatermark": 0,
                "brokeredSecrets": [secret]
            }))
        };
        let secret = serde_json::json!({
            "secretId": "s1", "placeholder": "mend_sec_abcdefgh", "value": "real",
            "headerName": "Authorization", "bindHosts": ["api.example.com"]
        });
        let err = Policy::from_document(base(secret.clone()), None).unwrap_err();
        assert!(err.to_string().contains("executorCaCertPem"), "{err}");

        let mut bad = secret.clone();
        bad["value"] = "a\r\nX-Injected: 1".into();
        let err = Policy::from_document(base(bad), None).unwrap_err();
        assert!(err.to_string().contains("single-line"), "{err}");

        let mut bad = secret;
        bad["headerName"] = "Authorization: x".into();
        let err = Policy::from_document(base(bad), None).unwrap_err();
        assert!(err.to_string().contains("headerName"), "{err}");
    }

    #[test]
    fn the_lease_never_outlasts_120_seconds() {
        for ttl in [0, 121, 3600] {
            let err = Policy::from_document(
                doc(serde_json::json!({
                    "mode": "standard", "policyHash": "h", "revocationWatermark": 0,
                    "leaseTtlSecs": ttl
                })),
                None,
            )
            .unwrap_err();
            assert!(err.to_string().contains("leaseTtlSecs"), "{ttl}: {err}");
        }
    }

    #[test]
    fn framing_and_routing_headers_cannot_carry_a_secret() {
        for header in [
            "Host",
            "content-length",
            "Transfer-Encoding",
            "Connection",
            "Upgrade",
            "TE",
            "Proxy-Authorization",
            "Proxy-Connection",
        ] {
            let err = Policy::from_document(
                doc(serde_json::json!({
                    "mode": "standard", "policyHash": "h", "revocationWatermark": 0,
                    "brokeredSecrets": [{
                        "secretId": "s1", "placeholder": "mend_sec_abcdefgh", "value": "real",
                        "headerName": header, "bindHosts": ["api.example.com"]
                    }]
                })),
                None,
            )
            .unwrap_err();
            assert!(
                err.to_string().contains("cannot carry a secret"),
                "{header}: {err}"
            );
        }
    }

    #[test]
    fn durable_tombstones_in_the_policy_win_over_its_grants() {
        let policy = Policy::from_document(
            doc(serde_json::json!({
                "mode": "restricted", "policyHash": "h", "revocationWatermark": 4,
                "allowHosts": [{ "host": "a.example.com" }, { "host": "b.example.com" }],
                "revokedHosts": ["A.example.com"],
                "revokedSecretIds": ["gone"]
            })),
            None,
        )
        .unwrap();
        assert!(!policy.restricted_allows("a.example.com", 443));
        assert!(policy.host_denied("a.example.com"));
        assert!(policy.restricted_allows("b.example.com", 443));
    }

    #[test]
    fn brokered_hosts_are_inspected_only_on_their_ports() {
        let mut policy = Policy::from_document(
            doc(serde_json::json!({
                "mode": "standard", "policyHash": "h", "revocationWatermark": 0,
                "allowHosts": [{ "host": "custom.example.com", "ports": [8443] }]
            })),
            None,
        )
        .unwrap();
        policy.allow_hosts[0].inspect_tls = true;
        assert!(policy.inspects_on("custom.example.com", 8443));
        assert!(!policy.inspects_on("custom.example.com", 443));
        assert!(policy.inspects_any_on(8443));
        assert!(!policy.inspects_any_on(443));
        // A bindHost with no allowHosts entry: 443 only.
        policy.secrets.push(BrokeredSecret {
            secret_id: "s".into(),
            placeholder: "mend_sec_abcdefgh".into(),
            value: serde_json::from_str("\"v\"").unwrap(),
            header_name: "authorization".into(),
            bind_hosts: vec!["api.example.com".into()],
            methods: None,
            path_prefixes: None,
        });
        assert!(policy.inspects_on("api.example.com", 443));
        assert!(!policy.inspects_on("api.example.com", 8443));
    }

    #[test]
    fn secret_debug_output_never_shows_the_value() {
        let value: SecretValue = serde_json::from_str("\"hunter2-real\"").unwrap();
        assert_eq!(format!("{value:?}"), "<redacted>");
    }

    #[test]
    fn resources_must_use_the_synthetic_range() {
        let err = Policy::from_document(
            doc(serde_json::json!({
                "mode": "standard", "policyHash": "h", "revocationWatermark": 0,
                "allowResources": [{ "name": "db", "host": "db", "port": 5432, "guestIp": "10.200.0.5" }]
            })),
            None,
        )
        .unwrap_err();
        assert!(err.to_string().contains("10.201.0.0/16"), "{err}");
    }
}
