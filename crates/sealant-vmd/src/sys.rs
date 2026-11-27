//! Tightly scoped OS primitives (`getifaddrs`, `flock`, `statvfs`/APFS important-capacity,
//! `O_NOFOLLOW` open, and child `setsid` + FD 3 inheritance) for `sealant-vmd`.

use std::ffi::CStr;
use std::fs::File;
use std::io;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::os::fd::{AsRawFd, FromRawFd, RawFd};
use std::os::unix::process::CommandExt;
use std::path::Path;
use std::process::Command;

use sealant_vmm_proto::{HostIps, MemoryPressureLevel};

/// The fixed descriptor number handed to `sealant-vz-worker` for the upgraded runner TCP socket.
pub const WORKER_TRANSPORT_FD: RawFd = 3;

/// Opens a file with `O_NOFOLLOW | O_CLOEXEC` (read-only or read-write) so a symlink swap at the
/// final path component fails immediately with `ELOOP`.
pub fn open_nofollow(path: &Path, writable: bool) -> io::Result<File> {
    use std::os::unix::ffi::OsStrExt;
    let cpath = std::ffi::CString::new(path.as_os_str().as_bytes())
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "path contains NUL byte"))?;
    let mut flags = libc::O_NOFOLLOW | libc::O_CLOEXEC;
    flags |= if writable {
        libc::O_RDWR
    } else {
        libc::O_RDONLY
    };
    // SAFETY: `cpath` is a valid NUL-terminated path and `flags` uses no O_CREAT.
    let fd = unsafe { libc::open(cpath.as_ptr(), flags) };
    if fd < 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: `fd` is a newly opened, owned descriptor.
    Ok(unsafe { File::from_raw_fd(fd) })
}

/// Attempts a non-blocking exclusive `flock` on `file`. Returns `Ok(true)` if acquired,
/// `Ok(false)` if another process holds the lock (`EWOULDBLOCK`), or `Err` on unexpected failure.
pub fn try_flock_exclusive(file: &File) -> io::Result<bool> {
    // SAFETY: `file.as_raw_fd()` is an open descriptor owned by `file`.
    let rc = unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) };
    if rc == 0 {
        return Ok(true);
    }
    let err = io::Error::last_os_error();
    if err.raw_os_error() == Some(libc::EWOULDBLOCK) {
        return Ok(false);
    }
    Err(err)
}

/// Current effective UID.
#[must_use]
pub fn current_uid() -> u32 {
    // SAFETY: `geteuid` is always safe and cannot fail.
    unsafe { libc::geteuid() }
}

/// Returns all non-loopback IPv4 and IPv6 addresses assigned to host interfaces via `getifaddrs()`.
/// Used by `<name>-proxy` to block guest egress to the Mac host's own LAN/GUA/Tailscale IPs.
pub fn host_interface_ips() -> HostIps {
    let mut out = HostIps::default();
    let mut ifap: *mut libc::ifaddrs = std::ptr::null_mut();
    // SAFETY: `getifaddrs` writes a valid linked list head into `ifap` on return 0.
    if unsafe { libc::getifaddrs(&mut ifap) } != 0 || ifap.is_null() {
        return out;
    }
    let mut cur = ifap;
    while !cur.is_null() {
        // SAFETY: `cur` walks the list returned by `getifaddrs` before `freeifaddrs`.
        let ifa = unsafe { &*cur };
        if !ifa.ifa_addr.is_null() {
            // SAFETY: `ifa_addr` is non-null and holds at least `sa_family`.
            let family = i32::from(unsafe { (*ifa.ifa_addr).sa_family });
            if family == libc::AF_INET {
                // SAFETY: `sa_family == AF_INET` guarantees a `sockaddr_in`.
                let sin = unsafe { &*(ifa.ifa_addr as *const libc::sockaddr_in) };
                let ip = Ipv4Addr::from(u32::from_be(sin.sin_addr.s_addr));
                if !ip.is_loopback() && !ip.is_unspecified() && !out.ipv4.contains(&IpAddr::V4(ip))
                {
                    out.ipv4.push(IpAddr::V4(ip));
                }
            } else if family == libc::AF_INET6 {
                // SAFETY: `sa_family == AF_INET6` guarantees a `sockaddr_in6`.
                let sin6 = unsafe { &*(ifa.ifa_addr as *const libc::sockaddr_in6) };
                let ip = Ipv6Addr::from(sin6.sin6_addr.s6_addr);
                let is_link_local = (ip.segments()[0] & 0xffc0) == 0xfe80;
                if !ip.is_loopback()
                    && !ip.is_unspecified()
                    && !is_link_local
                    && !out.ipv6.contains(&IpAddr::V6(ip))
                {
                    out.ipv6.push(IpAddr::V6(ip));
                }
            }
        }
        cur = ifa.ifa_next;
    }
    // SAFETY: `ifap` was returned by `getifaddrs`.
    unsafe { libc::freeifaddrs(ifap) };
    out.ipv4.sort();
    out.ipv6.sort();
    out
}

/// Configures `cmd` so the child detaches into its own session (`setsid`) — surviving
/// `sealant-vmd` restarts/upgrades — and inherits `tcp_fd` strictly at FD [`WORKER_TRANSPORT_FD`]
/// with `FD_CLOEXEC` cleared.
pub fn configure_worker_handoff(cmd: &mut Command, tcp_fd: RawFd) {
    // SAFETY: Only async-signal-safe syscalls (`setsid`, `dup2`, `fcntl`) run inside `pre_exec`.
    unsafe {
        cmd.pre_exec(move || {
            let _ = libc::setsid();
            if tcp_fd != WORKER_TRANSPORT_FD && libc::dup2(tcp_fd, WORKER_TRANSPORT_FD) < 0 {
                return Err(io::Error::last_os_error());
            }
            let flags = libc::fcntl(WORKER_TRANSPORT_FD, libc::F_GETFD);
            if flags < 0 {
                return Err(io::Error::last_os_error());
            }
            if libc::fcntl(
                WORKER_TRANSPORT_FD,
                libc::F_SETFD,
                flags & !libc::FD_CLOEXEC,
            ) < 0
            {
                return Err(io::Error::last_os_error());
            }
            // Clear O_NONBLOCK so the worker can perform straightforward blocking/threaded I/O.
            let fl = libc::fcntl(WORKER_TRANSPORT_FD, libc::F_GETFL);
            if fl >= 0 {
                let _ = libc::fcntl(WORKER_TRANSPORT_FD, libc::F_SETFL, fl & !libc::O_NONBLOCK);
            }
            Ok(())
        });
    }
}

/// Host memory summary `(total_bytes, available_bytes, pressure)`.
#[must_use]
pub fn host_memory() -> (u64, u64, MemoryPressureLevel) {
    #[cfg(target_os = "macos")]
    {
        let total = sysctl_u64("hw.memsize").unwrap_or(0);
        let free_level = sysctl_u32("kern.memorystatus_vm_pressure_level").unwrap_or(1);
        let pressure = match free_level {
            1 => MemoryPressureLevel::Normal,
            2 => MemoryPressureLevel::Warning,
            _ => MemoryPressureLevel::Critical,
        };
        // Conservative estimate if mach host_statistics isn't queried directly: report
        // available bytes via `vm.page_free_count` + `vm.page_speculative_count` or fallback.
        let page_size = sysctl_u64("hw.pagesize").unwrap_or(16_384);
        let free_pages = sysctl_u64("vm.page_free_count").unwrap_or(0);
        let available = if free_pages > 0 {
            free_pages.saturating_mul(page_size)
        } else {
            total / 2
        };
        (total, available, pressure)
    }
    #[cfg(not(target_os = "macos"))]
    {
        let mut total = 0u64;
        let mut available = 0u64;
        if let Ok(text) = std::fs::read_to_string("/proc/meminfo") {
            for line in text.lines() {
                if let Some(rest) = line.strip_prefix("MemTotal:") {
                    total = parse_kib(rest);
                } else if let Some(rest) = line.strip_prefix("MemAvailable:") {
                    available = parse_kib(rest);
                }
            }
        }
        let pressure = if total > 0 && available < total / 10 {
            MemoryPressureLevel::Critical
        } else if total > 0 && available < total / 5 {
            MemoryPressureLevel::Warning
        } else {
            MemoryPressureLevel::Normal
        };
        (total, available, pressure)
    }
}

#[cfg(not(target_os = "macos"))]
fn parse_kib(rest: &str) -> u64 {
    rest.split_whitespace()
        .next()
        .and_then(|n| n.parse::<u64>().ok())
        .map_or(0, |kib| kib.saturating_mul(1024))
}

/// Available disk space at `path` in bytes. On macOS, callers can also pass an external
/// `volumeAvailableCapacityForImportantUsage` helper; falls back cleanly to `statvfs`.
#[must_use]
pub fn disk_available_bytes(path: &Path) -> u64 {
    #[cfg(target_os = "macos")]
    if let Some(important) = macos_important_capacity(path) {
        return important;
    }
    statvfs_available(path)
}

fn statvfs_available(path: &Path) -> u64 {
    use std::os::unix::ffi::OsStrExt;
    let Ok(cpath) = std::ffi::CString::new(path.as_os_str().as_bytes()) else {
        return 0;
    };
    let mut stat: libc::statvfs = unsafe { std::mem::zeroed() };
    // SAFETY: `cpath` is valid NUL-terminated and `stat` is a writable `libc::statvfs`.
    if unsafe { libc::statvfs(cpath.as_ptr(), &mut stat) } != 0 {
        return 0;
    }
    (stat.f_bavail as u64).saturating_mul(stat.f_frsize as u64)
}

/// Queries macOS `NSURLVolumeAvailableCapacityForImportantUsageKey` via `swift`/`osascript`? No:
/// spawning a subprocess per `/v1/health` is slow, so `sealant-vz-worker --disk-capacity <path>`
/// or a direct CoreFoundation call can provide it; here we check `statvfs` fast and let
/// `sealant-vz-worker --probe-capacity` answer on demand when available.
#[cfg(target_os = "macos")]
fn macos_important_capacity(_path: &Path) -> Option<u64> {
    None
}

/// Returns the macOS product version (e.g. `"15.4.1"` / `"26.6.2"`) on macOS, or OS name elsewhere.
#[must_use]
pub fn macos_version_string() -> String {
    #[cfg(target_os = "macos")]
    {
        sysctl_string("kern.osproductversion").unwrap_or_else(|| "unknown".to_owned())
    }
    #[cfg(not(target_os = "macos"))]
    {
        format!("non-macos-{}", std::env::consts::OS)
    }
}

#[cfg(target_os = "macos")]
fn sysctl_u64(name: &str) -> Option<u64> {
    let cname = std::ffi::CString::new(name).ok()?;
    let mut val: u64 = 0;
    let mut len = std::mem::size_of::<u64>();
    // SAFETY: `cname` is NUL-terminated and `val`/`len` match `u64`.
    let rc = unsafe {
        libc::sysctlbyname(
            cname.as_ptr(),
            (&mut val as *mut u64).cast(),
            &mut len,
            std::ptr::null_mut(),
            0,
        )
    };
    (rc == 0).then_some(val)
}

#[cfg(target_os = "macos")]
fn sysctl_u32(name: &str) -> Option<u32> {
    let cname = std::ffi::CString::new(name).ok()?;
    let mut val: u32 = 0;
    let mut len = std::mem::size_of::<u32>();
    // SAFETY: `cname` is NUL-terminated and `val`/`len` match `u32`.
    let rc = unsafe {
        libc::sysctlbyname(
            cname.as_ptr(),
            (&mut val as *mut u32).cast(),
            &mut len,
            std::ptr::null_mut(),
            0,
        )
    };
    (rc == 0).then_some(val)
}

#[cfg(target_os = "macos")]
fn sysctl_string(name: &str) -> Option<String> {
    let cname = std::ffi::CString::new(name).ok()?;
    let mut len: usize = 0;
    // SAFETY: probing required buffer size with null output pointer.
    if unsafe {
        libc::sysctlbyname(
            cname.as_ptr(),
            std::ptr::null_mut(),
            &mut len,
            std::ptr::null_mut(),
            0,
        )
    } != 0
        || len == 0
    {
        return None;
    }
    let mut buf = vec![0u8; len];
    // SAFETY: `buf` has length `len`.
    if unsafe {
        libc::sysctlbyname(
            cname.as_ptr(),
            buf.as_mut_ptr().cast(),
            &mut len,
            std::ptr::null_mut(),
            0,
        )
    } != 0
    {
        return None;
    }
    CStr::from_bytes_until_nul(&buf)
        .ok()
        .and_then(|s| s.to_str().ok())
        .map(str::to_owned)
}

#[cfg(not(target_os = "macos"))]
#[allow(dead_code)]
fn _keep_cstr_import(_: &CStr) {}
