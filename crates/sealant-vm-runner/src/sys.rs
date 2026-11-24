//! The raw syscalls the runner needs that `nix` does not wrap: TUN/interface ioctls, the bounding
//! and inheritable capability sets, Landlock's ABI probe and KVM's API version. Every `unsafe` in
//! the crate is here.
#![allow(unsafe_code)]

use std::io;
use std::net::Ipv4Addr;
use std::os::fd::{AsRawFd, BorrowedFd, RawFd};

const IFNAMSIZ: usize = 16;

/// `TUNSETIFF` = `_IOW('T', 202, int)`.
const TUNSETIFF: libc::c_ulong = 0x4004_54ca;
pub(crate) const IFF_TAP: libc::c_short = 0x0002;
pub(crate) const IFF_NO_PI: libc::c_short = 0x1000;
pub(crate) const IFF_VNET_HDR: libc::c_short = 0x4000;

/// `KVM_GET_API_VERSION` = `_IO(KVMIO, 0x00)`.
const KVM_GET_API_VERSION: libc::c_ulong = 0xae00;

/// `struct ifreq` is a 16-byte name and a 24-byte union on every 64-bit Linux ABI.
#[repr(C)]
struct IfReq {
    name: [u8; IFNAMSIZ],
    data: [u8; 24],
}

impl IfReq {
    fn new(name: &str) -> io::Result<Self> {
        let bytes = name.as_bytes();
        if bytes.is_empty() || bytes.len() >= IFNAMSIZ || bytes.contains(&0) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("bad interface name {name:?}"),
            ));
        }
        let mut req = Self {
            name: [0; IFNAMSIZ],
            data: [0; 24],
        };
        req.name[..bytes.len()].copy_from_slice(bytes);
        Ok(req)
    }

    fn set_short(&mut self, v: libc::c_short) {
        self.data[..2].copy_from_slice(&v.to_ne_bytes());
    }

    fn short(&self) -> libc::c_short {
        libc::c_short::from_ne_bytes([self.data[0], self.data[1]])
    }

    fn set_int(&mut self, v: libc::c_int) {
        self.data[..4].copy_from_slice(&v.to_ne_bytes());
    }

    fn set_inet(&mut self, addr: Ipv4Addr) {
        // struct sockaddr_in: family (native u16), port (be16), addr (be32), 8 bytes zero.
        self.data = [0; 24];
        self.data[..2].copy_from_slice(&(libc::AF_INET as u16).to_ne_bytes());
        self.data[4..8].copy_from_slice(&addr.octets());
    }
}

fn ioctl(fd: RawFd, request: libc::c_ulong, req: &mut IfReq) -> io::Result<()> {
    // SAFETY: `req` is a live, correctly sized `struct ifreq` for every request used here; the
    // kernel reads and writes at most `size_of::<IfReq>()` bytes through it.
    let rc = unsafe { libc::ioctl(fd, request as _, req as *mut IfReq) };
    if rc < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

/// Attaches the open `/dev/net/tun` `fd` to a new interface `name` with `flags`.
pub(crate) fn tun_set_iff(fd: BorrowedFd<'_>, name: &str, flags: libc::c_short) -> io::Result<()> {
    let mut req = IfReq::new(name)?;
    req.set_short(flags);
    ioctl(fd.as_raw_fd(), TUNSETIFF, &mut req)
}

/// Sets `name`'s IPv4 address, netmask, MTU and brings it up, through an `AF_INET` socket.
pub(crate) fn configure_interface(
    name: &str,
    addr: Ipv4Addr,
    prefix_len: u8,
    mtu: u32,
) -> io::Result<()> {
    let sock = nix::sys::socket::socket(
        nix::sys::socket::AddressFamily::Inet,
        nix::sys::socket::SockType::Datagram,
        nix::sys::socket::SockFlag::SOCK_CLOEXEC,
        None,
    )
    .map_err(io::Error::from)?;
    let fd = sock.as_raw_fd();

    let mut req = IfReq::new(name)?;
    req.set_inet(addr);
    ioctl(fd, libc::SIOCSIFADDR as libc::c_ulong, &mut req)?;

    let mask = if prefix_len == 0 {
        0
    } else {
        u32::MAX << (32 - u32::from(prefix_len.min(32)))
    };
    let mut req = IfReq::new(name)?;
    req.set_inet(Ipv4Addr::from(mask));
    ioctl(fd, libc::SIOCSIFNETMASK as libc::c_ulong, &mut req)?;

    let mut req = IfReq::new(name)?;
    req.set_int(i32::try_from(mtu).map_err(io::Error::other)?);
    ioctl(fd, libc::SIOCSIFMTU as libc::c_ulong, &mut req)?;

    let mut req = IfReq::new(name)?;
    ioctl(fd, libc::SIOCGIFFLAGS as libc::c_ulong, &mut req)?;
    let flags = req.short() | libc::IFF_UP as libc::c_short;
    req.set_short(flags);
    ioctl(fd, libc::SIOCSIFFLAGS as libc::c_ulong, &mut req)
}

/// `prctl(PR_CAPBSET_DROP, cap)`.
pub(crate) fn capbset_drop(cap: u32) -> io::Result<()> {
    // SAFETY: plain integer arguments.
    let rc = unsafe { libc::prctl(libc::PR_CAPBSET_DROP, libc::c_ulong::from(cap), 0, 0, 0) };
    if rc < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

/// `prctl(PR_CAP_AMBIENT, PR_CAP_AMBIENT_CLEAR_ALL)`.
pub(crate) fn ambient_clear_all() -> io::Result<()> {
    // SAFETY: plain integer arguments.
    let rc = unsafe {
        libc::prctl(
            libc::PR_CAP_AMBIENT,
            libc::PR_CAP_AMBIENT_CLEAR_ALL as libc::c_ulong,
            0,
            0,
            0,
        )
    };
    if rc < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

#[repr(C)]
struct CapHeader {
    version: u32,
    pid: libc::c_int,
}

#[repr(C)]
#[derive(Clone, Copy, Default)]
struct CapData {
    effective: u32,
    permitted: u32,
    inheritable: u32,
}

const LINUX_CAPABILITY_VERSION_3: u32 = 0x2008_0522;

/// Empties the calling thread's inheritable set, leaving effective and permitted as they are.
/// `setresuid` clears permitted, effective and ambient, but not inheritable.
pub(crate) fn clear_inheritable() -> io::Result<()> {
    let mut header = CapHeader {
        version: LINUX_CAPABILITY_VERSION_3,
        pid: 0,
    };
    let mut data = [CapData::default(); 2];
    // SAFETY: v3 header with two data words, as capget(2) requires.
    let rc = unsafe {
        libc::syscall(
            libc::SYS_capget,
            &mut header as *mut CapHeader,
            data.as_mut_ptr(),
        )
    };
    if rc < 0 {
        return Err(io::Error::last_os_error());
    }
    for word in &mut data {
        word.inheritable = 0;
    }
    // SAFETY: as above; the kernel only reads `data`.
    let rc = unsafe {
        libc::syscall(
            libc::SYS_capset,
            &mut header as *mut CapHeader,
            data.as_ptr(),
        )
    };
    if rc < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

/// `landlock_create_ruleset(NULL, 0, LANDLOCK_CREATE_RULESET_VERSION)`: the kernel's Landlock ABI
/// version, or the error that says it has none.
pub(crate) fn landlock_abi_version() -> io::Result<i64> {
    // The same number on x86_64 and aarch64 (syscalls added after 5.x share one table).
    const SYS_LANDLOCK_CREATE_RULESET: libc::c_long = 444;
    const LANDLOCK_CREATE_RULESET_VERSION: libc::c_uint = 1;
    // SAFETY: a NULL attr with size 0 is the documented version query.
    let rc = unsafe {
        libc::syscall(
            SYS_LANDLOCK_CREATE_RULESET,
            std::ptr::null::<libc::c_void>(),
            0usize,
            LANDLOCK_CREATE_RULESET_VERSION,
        )
    };
    if rc < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(rc)
}

/// `ioctl(kvm_fd, KVM_GET_API_VERSION)`: 12 on every kernel since 2.6.22.
pub(crate) fn kvm_api_version(fd: BorrowedFd<'_>) -> io::Result<i32> {
    // SAFETY: KVM_GET_API_VERSION takes no argument.
    let rc = unsafe { libc::ioctl(fd.as_raw_fd(), KVM_GET_API_VERSION as _, 0) };
    if rc < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(rc)
}

/// Clears `FD_CLOEXEC` on `fd`. Async-signal-safe: called between `fork` and `exec`.
pub(crate) fn clear_cloexec(fd: RawFd) -> io::Result<()> {
    // SAFETY: fcntl with integer arguments on a descriptor the caller owns.
    let rc = unsafe { libc::fcntl(fd, libc::F_SETFD, 0) };
    if rc < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

/// Adds a hook that runs in the forked child just before `exec`, clearing `FD_CLOEXEC` on `fd` so
/// that one descriptor, and no other, survives into the child.
pub(crate) fn inherit_fd_in_child(cmd: &mut tokio::process::Command, fd: RawFd) {
    // SAFETY: the hook only calls fcntl(2), which is async-signal-safe, and allocates nothing.
    unsafe {
        cmd.pre_exec(move || clear_cloexec(fd));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ifreq_matches_the_kernel_layout() {
        assert_eq!(std::mem::size_of::<IfReq>(), 40);
        assert!(IfReq::new("tap0").is_ok());
        assert!(IfReq::new("a-name-much-too-long").is_err());
        assert!(IfReq::new("").is_err());
    }
}
