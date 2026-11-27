//! Symlink-safe disk resolution and exclusive `flock` checks under `vm/<installId>/`.

use std::fs::File;
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};

use sealant_vmm_proto::{validate_base_image_key, validate_vm_name};

use crate::sys;

#[derive(Debug, thiserror::Error)]
pub enum DiskError {
    #[error("invalid identifier: {0}")]
    InvalidInput(&'static str),
    #[error("disk path escapes vm root: {0}")]
    PathEscape(String),
    #[error("disk not found: {0}")]
    NotFound(String),
    #[error("disk failed safety check ({path}): {reason}")]
    UnsafeFile { path: String, reason: &'static str },
    #[error("data disk is already locked by an active worker: {0}")]
    AlreadyLocked(String),
    #[error("disk I/O error ({path}): {source}")]
    Io {
        path: String,
        source: std::io::Error,
    },
}

/// Validated canonical disk paths for one VM launch.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ValidatedDisks {
    pub vm_root: PathBuf,
    pub base_image: PathBuf,
    pub data_image: PathBuf,
}

/// Validates and resolves `vda` (`<vm_root>/images/<base_image_key>.img`) and `vdb`
/// (`<vm_root>/data/<vm_name>/data.img`), ensuring:
/// 1. Neither identifier can traverse outside `vm_root`.
/// 2. Parent directories canonicalize strictly under `vm_root`.
/// 3. Both files open with `O_NOFOLLOW`, are regular files with `nlink == 1`, owned by the
///    current UID.
/// 4. `data.img` is not currently locked by another active `sealant-vz-worker` (`flock`).
pub fn resolve_and_validate(
    vm_root: &Path,
    base_image_key: &str,
    vm_name: &str,
) -> Result<ValidatedDisks, DiskError> {
    validate_base_image_key(base_image_key).map_err(DiskError::InvalidInput)?;
    validate_vm_name(vm_name).map_err(DiskError::InvalidInput)?;

    let canon_root = std::fs::canonicalize(vm_root).map_err(|source| DiskError::Io {
        path: vm_root.display().to_string(),
        source,
    })?;

    let base_dir = canonical_child(&canon_root, &canon_root.join("images"))?;
    let base_image = base_dir.join(format!("{base_image_key}.img"));
    let _base_file = open_and_verify(&base_image, false)?;

    let data_parent = canonical_child(&canon_root, &canon_root.join("data").join(vm_name))?;
    let data_image = data_parent.join("data.img");
    let data_file = open_and_verify(&data_image, true)?;

    let acquired = sys::try_flock_exclusive(&data_file).map_err(|source| DiskError::Io {
        path: data_image.display().to_string(),
        source,
    })?;
    if !acquired {
        return Err(DiskError::AlreadyLocked(data_image.display().to_string()));
    }
    // Probe lock releases cleanly when `data_file` drops; `sealant-vz-worker` re-acquires and
    // holds `LOCK_EX | LOCK_NB` for the VM's entire lifetime before starting `VZVirtualMachine`.
    drop(data_file);

    Ok(ValidatedDisks {
        vm_root: canon_root,
        base_image,
        data_image,
    })
}

fn canonical_child(canon_root: &Path, dir: &Path) -> Result<PathBuf, DiskError> {
    let canon = std::fs::canonicalize(dir).map_err(|source| {
        if source.kind() == std::io::ErrorKind::NotFound {
            DiskError::NotFound(dir.display().to_string())
        } else {
            DiskError::Io {
                path: dir.display().to_string(),
                source,
            }
        }
    })?;
    if !canon.starts_with(canon_root) {
        return Err(DiskError::PathEscape(canon.display().to_string()));
    }
    Ok(canon)
}

fn open_and_verify(path: &Path, writable: bool) -> Result<File, DiskError> {
    let file = sys::open_nofollow(path, writable).map_err(|source| {
        if source.kind() == std::io::ErrorKind::NotFound {
            DiskError::NotFound(path.display().to_string())
        } else if source.raw_os_error() == Some(libc::ELOOP) {
            DiskError::UnsafeFile {
                path: path.display().to_string(),
                reason: "symlinks are forbidden",
            }
        } else {
            DiskError::Io {
                path: path.display().to_string(),
                source,
            }
        }
    })?;
    let meta = file.metadata().map_err(|source| DiskError::Io {
        path: path.display().to_string(),
        source,
    })?;
    if !meta.file_type().is_file() {
        return Err(DiskError::UnsafeFile {
            path: path.display().to_string(),
            reason: "not a regular file",
        });
    }
    if meta.nlink() != 1 {
        return Err(DiskError::UnsafeFile {
            path: path.display().to_string(),
            reason: "hardlinks (nlink != 1) are forbidden",
        });
    }
    if meta.uid() != sys::current_uid() {
        return Err(DiskError::UnsafeFile {
            path: path.display().to_string(),
            reason: "file is not owned by the current user",
        });
    }
    Ok(file)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::symlink;

    fn setup_tree() -> (tempfile::TempDir, PathBuf) {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path().join("vm");
        std::fs::create_dir_all(root.join("images")).unwrap();
        std::fs::create_dir_all(root.join("data/ws-1")).unwrap();
        std::fs::write(root.join("images/sha256-abc.img"), b"base").unwrap();
        std::fs::write(root.join("data/ws-1/data.img"), b"data").unwrap();
        (dir, root)
    }

    #[test]
    fn valid_disks_pass_and_flock_blocks_concurrent_mount() {
        let (_tmp, root) = setup_tree();
        let disks = resolve_and_validate(&root, "sha256-abc", "ws-1").unwrap();
        assert!(disks.base_image.ends_with("images/sha256-abc.img"));
        assert!(disks.data_image.ends_with("data/ws-1/data.img"));

        // Hold an exclusive flock on data.img to simulate an active worker.
        let held = sys::open_nofollow(&disks.data_image, true).unwrap();
        assert!(sys::try_flock_exclusive(&held).unwrap());
        let err = resolve_and_validate(&root, "sha256-abc", "ws-1").unwrap_err();
        assert!(matches!(err, DiskError::AlreadyLocked(_)), "{err}");
    }

    #[test]
    fn symlinks_and_hardlinks_are_refused() {
        let (tmp, root) = setup_tree();
        let outside = tmp.path().join("secret.img");
        std::fs::write(&outside, b"secret").unwrap();

        // Symlink as base image
        symlink(&outside, root.join("images/sha256-link.img")).unwrap();
        let err = resolve_and_validate(&root, "sha256-link", "ws-1").unwrap_err();
        assert!(matches!(err, DiskError::UnsafeFile { .. }), "{err}");

        // Hardlink as data image
        std::fs::create_dir_all(root.join("data/ws-hard")).unwrap();
        std::fs::hard_link(&outside, root.join("data/ws-hard/data.img")).unwrap();
        let err = resolve_and_validate(&root, "sha256-abc", "ws-hard").unwrap_err();
        assert!(matches!(err, DiskError::UnsafeFile { .. }), "{err}");

        // Symlink directory escaping vm_root
        let outside_dir = tmp.path().join("outside-dir");
        std::fs::create_dir_all(&outside_dir).unwrap();
        std::fs::write(outside_dir.join("data.img"), b"x").unwrap();
        symlink(&outside_dir, root.join("data/ws-escape")).unwrap();
        let err = resolve_and_validate(&root, "sha256-abc", "ws-escape").unwrap_err();
        assert!(matches!(err, DiskError::PathEscape(_)), "{err}");
    }
}
