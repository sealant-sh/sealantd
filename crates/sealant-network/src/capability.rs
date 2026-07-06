//! Network-mode capability detection: never crash on missing privilege (plan §14.4).

use sealant_protocol::NetworkMode;

/// Resolve a requested mode to the best mode actually available without elevated privilege.
///
/// Privileged/metadata raw-socket backends need capabilities (`CAP_NET_ADMIN` / `CAP_BPF`) that the
/// workspace does not convey; absent them, we degrade to the userspace proxy rather than failing.
#[must_use]
pub fn detect_mode(requested: NetworkMode) -> NetworkMode {
    match requested {
        NetworkMode::Off => NetworkMode::Off,
        NetworkMode::Proxy => NetworkMode::Proxy,
        NetworkMode::Metadata | NetworkMode::Privileged | NetworkMode::Payload => {
            if has_net_admin() {
                requested
            } else {
                NetworkMode::Proxy
            }
        }
    }
}

/// Best-effort check for `CAP_NET_ADMIN` in the effective capability set (Linux only; else `false`).
#[must_use]
pub fn has_net_admin() -> bool {
    #[cfg(target_os = "linux")]
    {
        const CAP_NET_ADMIN: u32 = 12;
        let Ok(status) = std::fs::read_to_string("/proc/self/status") else {
            return false;
        };
        for line in status.lines() {
            if let Some(hex) = line.strip_prefix("CapEff:")
                && let Ok(bits) = u64::from_str_radix(hex.trim(), 16)
            {
                return bits & (1 << CAP_NET_ADMIN) != 0;
            }
        }
        false
    }
    #[cfg(not(target_os = "linux"))]
    {
        false
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn off_stays_off_and_proxy_stays_proxy() {
        assert_eq!(detect_mode(NetworkMode::Off), NetworkMode::Off);
        assert_eq!(detect_mode(NetworkMode::Proxy), NetworkMode::Proxy);
    }

    #[test]
    fn privileged_degrades_to_proxy_without_caps() {
        // The test process is unprivileged, so privileged/metadata degrade to proxy.
        if !has_net_admin() {
            assert_eq!(detect_mode(NetworkMode::Privileged), NetworkMode::Proxy);
            assert_eq!(detect_mode(NetworkMode::Metadata), NetworkMode::Proxy);
        }
    }
}
