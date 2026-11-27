//! `sealant-vmd`: stateless per-installation macOS launcher for Apple `Virtualization.framework`
//! microVMs (`macos-workspace-isolation-architecture.md` §§3–6).
//!
//! `sealant-vmd` binds strictly to `127.0.0.1:<port>`, authenticates `sealant-vm-runner`, validates
//! disk paths under the installation's `vm/<installId>/` root, checks exclusive `flock` on
//! `data.img`, spawns one `sealant-vz-worker` per VM in its own session (`setsid`), hands off the
//! upgraded TCP socket FD directly as FD `3`, and immediately closes its own copy so `sealant-vmd`
//! stays 100% out of the live data path.
#![cfg_attr(not(test), deny(clippy::unwrap_used, clippy::expect_used))]

pub mod disk;
pub mod selftest;
pub mod server;
pub mod sys;
