//! Mounted workspace sources: a caller-owned host directory bind-mounted over the working
//! directory instead of a boot-time clone.
//!
//! The mounted directory is caller property. Boot never creates, cleans, reprovisions, or deletes
//! its contents — it only *verifies* that the orchestrator actually established the mount (a
//! mount-mode boot on a plain container-local directory would silently strand every write in the
//! container's writable layer) and that the mount is writable. Teardown of a mounted workspace is
//! the container's problem; the daemon holds no destructive path for it.

use std::os::unix::fs::MetadataExt as _;
use std::path::{Component, Path, PathBuf};

use crate::boot::config::MountConfig;
use crate::boot::error::BootError;

/// Verify a mount-mode working directory: it must exist, be a directory, be an actual mountpoint,
/// and be writable. Called after `prepare_workspace` (whose `mkdir -p` is a no-op on the existing
/// mount target) and instead of the clone step.
///
/// # Errors
/// Returns [`BootError::Config`] if any invariant fails; every failure is fatal to boot.
pub(crate) fn verify_mounted_source(
    working_directory: &Path,
    mount: &MountConfig,
) -> Result<(), BootError> {
    let metadata = std::fs::metadata(working_directory)
        .map_err(|e| BootError::io_path("stat", working_directory, e))?;
    if !metadata.is_dir() {
        return Err(BootError::config(format!(
            "mounted workspace source {} is not a directory",
            working_directory.display()
        )));
    }
    if !is_mount_point(working_directory) {
        return Err(BootError::config(format!(
            "SEALANT_WORKSPACE_SOURCE=mount but {} is not a mountpoint; the orchestrator must \
             bind-mount the caller-owned host path {} onto it before the daemon starts",
            working_directory.display(),
            mount.host_path.display(),
        )));
    }
    if let Err(errno) = nix::unistd::access(working_directory, nix::unistd::AccessFlags::W_OK) {
        return Err(BootError::config(format!(
            "mounted workspace source {} is not writable ({errno}); writes must land on the \
             caller-owned host path",
            working_directory.display()
        )));
    }
    tracing::info!(
        workdir = %working_directory.display(),
        host_path = %mount.host_path.display(),
        "workspace source is a caller-owned mount; clone skipped, contents are never touched"
    );
    Ok(())
}

/// Verify a bindable root (ADR-0014): it must exist, be a directory, be an actual mountpoint, and
/// be writable — the same invariants as a mounted source, for the same reason. `host_path` is
/// only for the message.
///
/// # Errors
/// Returns [`BootError::Config`] if any invariant fails; every failure is fatal to boot.
pub(crate) fn verify_mount_root(root: &Path, host_path: &str) -> Result<(), BootError> {
    let metadata = std::fs::metadata(root).map_err(|e| BootError::io_path("stat", root, e))?;
    if !metadata.is_dir() {
        return Err(BootError::config(format!(
            "bindable mount root {} is not a directory",
            root.display()
        )));
    }
    if !is_mount_point(root) {
        return Err(BootError::config(format!(
            "bindable mount root {} is not a mountpoint; the orchestrator must bind-mount the \
             caller-owned host path {host_path} onto it before the daemon starts",
            root.display(),
        )));
    }
    if let Err(errno) = nix::unistd::access(root, nix::unistd::AccessFlags::W_OK) {
        return Err(BootError::config(format!(
            "bindable mount root {} is not writable ({errno})",
            root.display()
        )));
    }
    Ok(())
}

/// Whether `path` is a mountpoint. Primary check: an exact entry in `/proc/self/mountinfo`
/// (catches same-filesystem bind mounts, which keep their `st_dev`). Fallback when mountinfo is
/// unavailable: `st_dev` differing from the parent directory's.
pub(crate) fn is_mount_point(path: &Path) -> bool {
    let Ok(canonical) = std::fs::canonicalize(path) else {
        return false;
    };
    if let Ok(mountinfo) = std::fs::read_to_string("/proc/self/mountinfo") {
        return mountinfo_contains(&mountinfo, &canonical);
    }
    let (Ok(own), Some(Ok(parent))) = (
        std::fs::metadata(&canonical),
        canonical.parent().map(std::fs::metadata),
    ) else {
        return false;
    };
    own.dev() != parent.dev()
}

/// Whether a `/proc/self/mountinfo` document lists `path` as a mount point (field 5, with the
/// kernel's octal escaping for space/tab/newline/backslash decoded).
fn mountinfo_contains(mountinfo: &str, path: &Path) -> bool {
    mountinfo
        .lines()
        .filter_map(|line| line.split_whitespace().nth(4))
        .any(|mount_point| PathBuf::from(decode_mountinfo_path(mount_point)) == path)
}

/// Decode the kernel's mountinfo octal escapes (`\040` space, `\011` tab, `\012` newline,
/// `\134` backslash).
fn decode_mountinfo_path(raw: &str) -> String {
    let mut out = String::with_capacity(raw.len());
    let mut chars = raw.chars().peekable();
    while let Some(c) = chars.next() {
        if c != '\\' {
            out.push(c);
            continue;
        }
        let digits: String = chars.clone().take(3).collect();
        if digits.len() == 3
            && let Ok(code) = u8::from_str_radix(&digits, 8)
        {
            out.push(code as char);
            chars.nth(2);
        } else {
            out.push(c);
        }
    }
    out
}

/// Whether `path` is a clean absolute path: rooted, and free of `..` components (`.` components
/// are normalized away by `Path::components` and are harmless to comparisons). Mount
/// host paths and allowlist roots are compared lexically (the daemon cannot resolve host
/// symlinks from inside the container), so anything non-canonical is rejected outright.
pub(crate) fn is_clean_absolute(path: &Path) -> bool {
    let mut components = path.components();
    if components.next() != Some(Component::RootDir) {
        return false;
    }
    components.all(|c| matches!(c, Component::Normal(_)))
}

/// Whether `candidate` is a proper descendant of `root` (component-wise; equality is rejected —
/// mounting an entire store root as a single workspace is always a configuration error).
pub(crate) fn is_proper_descendant(root: &Path, candidate: &Path) -> bool {
    candidate.starts_with(root) && candidate != root
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn root_is_a_mount_point() {
        assert!(is_mount_point(Path::new("/")));
    }

    #[test]
    fn fresh_tempdir_is_not_a_mount_point() {
        let dir = tempfile::tempdir().expect("tmp");
        assert!(!is_mount_point(dir.path()));
    }

    #[test]
    fn missing_path_is_not_a_mount_point() {
        assert!(!is_mount_point(Path::new("/definitely/not/a/real/path")));
    }

    #[test]
    fn mountinfo_field_five_is_matched_with_escapes() {
        let doc = "22 1 0:21 / / rw shared:1 - ext4 /dev/sda1 rw\n\
                   99 22 0:40 / /mnt/store\\040a rw shared:2 - ext4 /dev/sdb1 rw\n";
        assert!(mountinfo_contains(doc, Path::new("/")));
        assert!(mountinfo_contains(doc, Path::new("/mnt/store a")));
        assert!(!mountinfo_contains(doc, Path::new("/mnt/store")));
    }

    #[test]
    fn clean_absolute_rejects_relative_and_dotted() {
        assert!(is_clean_absolute(Path::new("/store/wt1")));
        assert!(!is_clean_absolute(Path::new("store/wt1")));
        assert!(!is_clean_absolute(Path::new("/store/../etc")));
        // `.` components are normalized away by Path::components and compare equal, so they
        // are accepted.
        assert!(is_clean_absolute(Path::new("/store/./wt1")));
    }

    #[test]
    fn proper_descendant_requires_component_boundary_and_inequality() {
        assert!(is_proper_descendant(
            Path::new("/store"),
            Path::new("/store/wt1")
        ));
        assert!(!is_proper_descendant(
            Path::new("/store"),
            Path::new("/storefoo/wt1")
        ));
        assert!(!is_proper_descendant(
            Path::new("/store"),
            Path::new("/store")
        ));
        assert!(!is_proper_descendant(Path::new("/store"), Path::new("/")));
    }
}
