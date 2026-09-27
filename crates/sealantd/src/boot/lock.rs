//! One daemon per disk. A capture-store boot takes an exclusive lock on its worktree for as long
//! as the process lives, before it reads or writes anything there, and a second boot on the same
//! disk is refused, touching nothing. What makes a recovery reboot on a still-running MicroVM
//! (`sealantd boot --recovery` after the first daemon exited) safe to ask for at any time: if
//! the first daemon is in fact still running, two engines would snap and ship one disk under one
//! lease, and a recovery must never materialize or capture beside a live writer.
//!
//! `flock(2)` on `<worktree>/.sealantd/boot.lock` (the daemon's own directory, never captured):
//! the kernel drops it when the process ends however it ends, so a daemon that crashed or was
//! killed never leaves a stale lock, and the descriptor is close-on-exec, so no child the daemon
//! started keeps it past the daemon.

use std::fs::{File, OpenOptions};
use std::path::{Path, PathBuf};

use nix::errno::Errno;
use nix::fcntl::{Flock, FlockArg};

use crate::boot::error::BootError;

/// The lock file, under the worktree's daemon directory.
#[must_use]
pub fn lock_path(working_directory: &Path) -> PathBuf {
    working_directory.join(".sealantd").join("boot.lock")
}

/// The held lock; released when dropped or when the process ends.
#[derive(Debug)]
pub struct DiskLock {
    _lock: Flock<File>,
}

impl DiskLock {
    /// Take the lock for the disk at `working_directory`, or refuse when another process holds
    /// it (a daemon still running there).
    ///
    /// # Errors
    /// [`BootError::DiskInUse`] naming the refusal when the lock is held; an I/O error when the lock
    /// file cannot be created or locked.
    pub fn acquire(working_directory: &Path) -> Result<Self, BootError> {
        let path = lock_path(working_directory);
        if let Some(dir) = path.parent() {
            std::fs::create_dir_all(dir).map_err(|e| BootError::io_path("mkdir -p", dir, e))?;
        }
        let file = OpenOptions::new()
            .create(true)
            .truncate(false)
            .read(true)
            .write(true)
            .open(&path)
            .map_err(|e| BootError::io_path("open", &path, e))?;
        match Flock::lock(file, FlockArg::LockExclusiveNonblock) {
            Ok(lock) => Ok(Self { _lock: lock }),
            Err((_, Errno::EWOULDBLOCK)) => Err(BootError::DiskInUse(format!(
                "another sealantd is running on {} (it holds {}); refusing to boot beside it — \
                 the disk is left as it is",
                working_directory.display(),
                path.display()
            ))),
            Err((_, errno)) => Err(BootError::io_path(
                "flock",
                &path,
                std::io::Error::from_raw_os_error(errno as i32),
            )),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A second lock on the same disk is refused while the first is held, from this process or
    /// another; once the first is released it is taken again.
    #[test]
    fn one_daemon_per_disk() {
        let tmp = tempfile::tempdir().unwrap();
        let first = DiskLock::acquire(tmp.path()).expect("free");
        let refused = DiskLock::acquire(tmp.path()).expect_err("held");
        assert!(
            refused.to_string().contains("another sealantd"),
            "{refused}"
        );
        drop(first);
        DiskLock::acquire(tmp.path()).expect("released");
    }
}
