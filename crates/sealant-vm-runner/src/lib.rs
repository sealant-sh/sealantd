//! `sealant-vm-runner`: the entrypoint of a `host-vm` workspace container
//! (`agent-home/docs/workspace-isolation-architecture.md` §4.2).
//!
//! The container starts as UID 0 holding only `NET_ADMIN`, `SETUID`, `SETGID` and `SETPCAP`. The
//! runner spends those once, in a fixed order, before any thread exists:
//!
//! 1. [`tap`]: create `tap0` (`10.200.0.1/30`) for the guest's `eth0`.
//! 2. [`nft`]: install the container-netns ruleset that forces every guest packet into the local
//!    forwarders (or rejects it), with `forward` policy `drop`.
//! 3. [`jail`]: drop every capability from the bounding set, keep only `/dev/kvm`'s group, become
//!    `65532:65532`, set no-new-privileges, and abort unless `/proc/self/status` proves it.
//!
//! Then, unprivileged, it starts the egress [`forward`]ers, the four [`vsock`] bridges, and
//! supervises Cloud Hypervisor ([`vmm`]). The runner's own exit code follows [`exit`]: `76`
//! (nothing to save) only on a synced guest frame saying so and a clean VMM exit.
#![cfg_attr(not(test), deny(clippy::unwrap_used, clippy::expect_used))]
#![deny(unsafe_code)]

pub mod exit;
pub mod forward;
pub mod jail;
pub mod net;
pub mod nft;
pub mod protocol;
pub mod proxy_v2;
pub mod selftest;
pub mod tap;
pub mod vmm;
pub mod vsock;

mod sys;
