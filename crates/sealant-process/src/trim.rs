//! `FITRIM` (what `fstrim` does) on a mounted filesystem: the filesystem tells the block device
//! which of its blocks are free, and a sparse disk image behind a `virtio-blk` device with
//! discard punches holes for them, so deleted build output stops occupying the host's disk.
//! Here rather than in the daemon because the ioctl needs one `unsafe` call, and this crate is
//! where the daemon's few system-call wrappers live.
#![allow(unsafe_code)]

use std::path::Path;

/// `struct fstrim_range` (`linux/fs.h`).
#[repr(C)]
#[derive(Debug, Default)]
struct FstrimRange {
    start: u64,
    len: u64,
    minlen: u64,
}

#[cfg(target_os = "linux")]
nix::ioctl_readwrite!(fitrim_ioctl, b'X', 121, FstrimRange);

/// Trim every free block of the filesystem mounted at `mount_point`; returns how many bytes the
/// filesystem reported trimmed.
///
/// # Errors
/// The mount point could not be opened, or the filesystem or device does not support discard
/// (`EOPNOTSUPP`), or the caller lacks `CAP_SYS_ADMIN` (`EPERM`).
#[cfg(target_os = "linux")]
pub fn fitrim(mount_point: &Path) -> std::io::Result<u64> {
    use std::os::fd::AsRawFd;
    let dir = std::fs::File::open(mount_point)?;
    let mut range = FstrimRange {
        start: 0,
        len: u64::MAX,
        minlen: 0,
    };
    // SAFETY: `dir` is an open descriptor for the whole call, and `range` is a live, properly
    // laid-out `fstrim_range` the kernel reads and writes back (`_IOWR('X', 121, ...)`).
    unsafe { fitrim_ioctl(dir.as_raw_fd(), &raw mut range) }.map_err(std::io::Error::from)?;
    Ok(range.len)
}

/// Off Linux there is no `FITRIM`.
///
/// # Errors
/// Always `Unsupported`.
#[cfg(not(target_os = "linux"))]
pub fn fitrim(_mount_point: &Path) -> std::io::Result<u64> {
    Err(std::io::Error::new(
        std::io::ErrorKind::Unsupported,
        "FITRIM is Linux only",
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_mount_point_that_is_not_there_is_an_error() {
        assert!(fitrim(Path::new("/definitely/not/a/mount/point")).is_err());
    }
}
