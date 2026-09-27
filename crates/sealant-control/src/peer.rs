//! Peer-credential validation for the control socket (plan §18): only authorized local peers may
//! drive the daemon. The socket is already `0600`; this adds a uid check via `SO_PEERCRED` on Linux.

use std::collections::HashMap;
use std::sync::{Arc, Mutex, PoisonError};

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

/// The pid of the process that connected `stream` (`SO_PEERCRED`), when the kernel says.
#[must_use]
pub fn peer_pid(stream: &UnixStream) -> Option<i32> {
    #[cfg(target_os = "linux")]
    {
        use nix::sys::socket::{getsockopt, sockopt::PeerCredentials};
        getsockopt(stream, PeerCredentials)
            .ok()
            .map(|cred| cred.pid())
            .filter(|pid| *pid > 0)
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = stream;
        None
    }
}

/// The processes at the far end of the live Unix-socket control connections, by pid
/// ([`peer_pid`]): what relays a client's requests and their replies — `socat` under
/// `docker exec`, `sealantctl`. The daemon's final capture sweep spares them while their
/// connection is open, so the reply to the request that ended the executor reaches its caller.
#[derive(Debug, Clone, Default)]
pub struct ControlPeers(Arc<Mutex<HashMap<i32, usize>>>);

impl ControlPeers {
    /// Record a connection from `pid` until the returned guard drops.
    #[must_use]
    pub fn enter(&self, pid: i32) -> PeerGuard {
        *self
            .0
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .entry(pid)
            .or_default() += 1;
        PeerGuard {
            peers: self.clone(),
            pid,
        }
    }

    /// The pids with a live connection.
    #[must_use]
    pub fn pids(&self) -> Vec<i32> {
        self.0
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .keys()
            .copied()
            .collect()
    }
}

/// One live connection in [`ControlPeers`]; dropping it forgets the connection.
#[derive(Debug)]
pub struct PeerGuard {
    peers: ControlPeers,
    pid: i32,
}

impl Drop for PeerGuard {
    fn drop(&mut self) {
        let mut peers = self.peers.0.lock().unwrap_or_else(PoisonError::into_inner);
        if let Some(count) = peers.get_mut(&self.pid) {
            *count -= 1;
            if *count == 0 {
                peers.remove(&self.pid);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{ControlPeers, peer_allowed};

    #[test]
    fn a_peer_is_listed_while_one_of_its_connections_is_open() {
        let peers = ControlPeers::default();
        let one = peers.enter(42);
        let two = peers.enter(42);
        let other = peers.enter(7);
        let mut pids = peers.pids();
        pids.sort_unstable();
        assert_eq!(pids, [7, 42]);
        drop(one);
        drop(other);
        assert_eq!(peers.pids(), [42]);
        drop(two);
        assert!(peers.pids().is_empty());
    }

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
