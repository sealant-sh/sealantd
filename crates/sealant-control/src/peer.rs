//! Peer-credential validation for the control socket (plan §18): only authorized local peers may
//! drive the daemon. The socket is already `0600`; this adds a uid check via `SO_PEERCRED` on Linux.

use tokio::net::UnixStream;

/// Whether a connecting peer uid is permitted: the daemon's own uid, root, or an explicit allowlist.
#[must_use]
pub fn peer_allowed(peer_uid: u32, self_uid: u32, allowed: &[u32]) -> bool {
    peer_uid == self_uid || peer_uid == 0 || allowed.contains(&peer_uid)
}

/// The effective uid of the current process (Linux); `0` off Linux (where the check is skipped).
#[must_use]
pub fn self_uid() -> u32 {
    #[cfg(target_os = "linux")]
    {
        nix::unistd::geteuid().as_raw()
    }
    #[cfg(not(target_os = "linux"))]
    {
        0
    }
}

/// Validate a connected peer against the policy.
///
/// On Linux, reads the peer uid via `SO_PEERCRED` and **fails closed** if it cannot be determined.
/// Off Linux (dev hosts, no `SO_PEERCRED`) the check is skipped and the peer is allowed.
#[must_use]
pub fn validate_peer(stream: &UnixStream, self_uid: u32, allowed: &[u32]) -> bool {
    #[cfg(target_os = "linux")]
    {
        use nix::sys::socket::{getsockopt, sockopt::PeerCredentials};
        match getsockopt(stream, PeerCredentials) {
            Ok(cred) => peer_allowed(cred.uid(), self_uid, allowed),
            Err(_) => false,
        }
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = (stream, self_uid, allowed);
        true
    }
}

#[cfg(test)]
mod tests {
    use super::peer_allowed;

    #[test]
    fn same_uid_root_and_allowlist_pass_others_rejected() {
        // Same uid as the daemon.
        assert!(peer_allowed(1000, 1000, &[]));
        // Root is always allowed.
        assert!(peer_allowed(0, 1000, &[]));
        // Explicit allowlist.
        assert!(peer_allowed(1001, 1000, &[1001, 1002]));
        // A different, non-allowlisted uid is rejected.
        assert!(!peer_allowed(1001, 1000, &[]));
        assert!(!peer_allowed(31337, 1000, &[1001]));
    }
}
