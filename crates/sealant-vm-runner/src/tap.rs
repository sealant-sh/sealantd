//! `tap0`, the guest's network cable (§4.2 step 1). Needs `CAP_NET_ADMIN` in the container netns,
//! so it runs before the privilege drop; the open descriptor outlives the capability.

use std::fs::OpenOptions;
use std::net::Ipv4Addr;
use std::os::fd::{AsFd, AsRawFd, OwnedFd, RawFd};
use std::os::unix::fs::OpenOptionsExt;
use std::path::Path;

use crate::sys;

/// An open TAP queue. `FD_CLOEXEC` stays set: only the Cloud Hypervisor child inherits it, by the
/// hook [`crate::vmm`] installs between its `fork` and `exec`.
#[derive(Debug)]
pub struct Tap {
    fd: OwnedFd,
    name: String,
}

impl Tap {
    pub fn name(&self) -> &str {
        &self.name
    }

    pub fn raw_fd(&self) -> RawFd {
        self.fd.as_raw_fd()
    }

    pub fn into_owned_fd(self) -> OwnedFd {
        self.fd
    }
}

/// Creates `name` on `tun_path` (`IFF_TAP | IFF_NO_PI | IFF_VNET_HDR`), gives it `addr/prefix_len`
/// and `mtu`, and brings it up.
///
/// `IFF_VNET_HDR`: Cloud Hypervisor's virtio-net reads and writes a `virtio_net_hdr` in front of
/// every frame on the TAP and sets its size and offloads on a descriptor passed by `--net fd=`, so
/// a queue opened without it would corrupt every frame.
pub fn create(
    tun_path: &Path,
    name: &str,
    addr: Ipv4Addr,
    prefix_len: u8,
    mtu: u32,
) -> std::io::Result<Tap> {
    create_with_flags(
        tun_path,
        name,
        addr,
        prefix_len,
        mtu,
        sys::IFF_TAP | sys::IFF_NO_PI | sys::IFF_VNET_HDR,
    )
}

/// Creates `name` on `tun_path` with raw Ethernet frames (`IFF_TAP | IFF_NO_PI`, no
/// `IFF_VNET_HDR`), as required by Apple `Virtualization.framework`'s
/// `VZFileHandleNetworkDeviceAttachment`.
pub fn create_raw(
    tun_path: &Path,
    name: &str,
    addr: Ipv4Addr,
    prefix_len: u8,
    mtu: u32,
) -> std::io::Result<Tap> {
    create_with_flags(
        tun_path,
        name,
        addr,
        prefix_len,
        mtu,
        sys::IFF_TAP | sys::IFF_NO_PI,
    )
}

fn create_with_flags(
    tun_path: &Path,
    name: &str,
    addr: Ipv4Addr,
    prefix_len: u8,
    mtu: u32,
    flags: libc::c_short,
) -> std::io::Result<Tap> {
    let file = OpenOptions::new()
        .read(true)
        .write(true)
        .custom_flags(libc::O_CLOEXEC | libc::O_NONBLOCK)
        .open(tun_path)?;
    let fd = OwnedFd::from(file);
    sys::tun_set_iff(fd.as_fd(), name, flags)?;
    sys::configure_interface(name, addr, prefix_len, mtu)?;
    Ok(Tap {
        fd,
        name: name.to_owned(),
    })
}
