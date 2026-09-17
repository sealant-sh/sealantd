//! Content the plan names beside the worktree (ADR-0015; Mend's ADR-0003 folders and reference
//! repositories). A capture-source workspace mounts nothing from the host, so a control plane
//! that wants a directory beside the repository has to send its bytes: `plan.get` answers
//! `sources`, each a gzipped tar at an object key, and this module lays each one down at its
//! absolute path.
//!
//! Three rules hold the design together:
//!
//! - **Outside the worktree.** A path inside the working directory would be listed by the next
//!   capture and shipped into the store as if the session had written it. An unsafe path is a
//!   control-plane bug, so it fails the boot rather than polluting the chain.
//! - **A copy, never a mount.** Nothing extracted here travels back: it sits outside every
//!   capture root. `read_only` takes the writable bit off as well, which is what a host bind
//!   mount would have done; either way the store never learns about a write.
//! - **Stamped by content.** The archive's sha256 is both the integrity check and the stamp on
//!   disk, so a re-materialize (a pickup, a `capture.replan`) re-extracts only what changed.
//!
//! One source failing is not worth a session: a download, digest or extraction failure is logged
//! and skipped, and the harness runs without that directory. Extraction goes to a scratch
//! directory and is renamed into place, so a failure never leaves half a tree behind.

use std::collections::BTreeMap;
use std::io;
use std::os::unix::fs::PermissionsExt;
use std::path::{Component, Path, PathBuf};
use std::process::Command;

use sealant_capture::registrar::PlanSource;
use sealant_capture::sink::BlobSink;
use sealant_process::CommandGateExt;
use sha2::{Digest, Sha256};

use crate::boot::capture::SourceLayout;
use crate::boot::error::BootError;

/// Where the stamps live, under the capture staging directory (never captured, never swept).
const STAMP_FILE: &str = "sources.json";

/// The largest archive this lays down. A source past it is skipped with a warning: the control
/// plane, which knows what it published, is where a byte budget belongs.
const MAX_SOURCE_BYTES: u64 = 64 * 1024 * 1024;

/// Lay `sources` down at the paths they name, inside the workspace and outside the worktree.
///
/// # Errors
/// Returns [`BootError::Config`] when a source names a path this must not write: outside the
/// workspace root, inside the worktree, or not absolute. Per-source I/O failures are logged and
/// skipped, not returned.
pub(crate) fn apply(
    sink: &dyn BlobSink,
    sources: &[PlanSource],
    layout: &SourceLayout,
) -> Result<(), BootError> {
    if sources.is_empty() {
        return Ok(());
    }
    let targets = sources
        .iter()
        .map(|source| target_of(source, layout).map(|path| (source, path)))
        .collect::<Result<Vec<_>, BootError>>()?;

    let staging_dir = layout.staging_dir.as_path();
    if let Err(error) = std::fs::create_dir_all(staging_dir) {
        return Err(io_at("mkdir -p", staging_dir, error));
    }
    let stamp_path = staging_dir.join(STAMP_FILE);
    let mut stamps = read_stamps(&stamp_path);
    for (source, target) in targets {
        if stamps
            .get(&source.path)
            .is_some_and(|sha| *sha == source.sha256)
            && target.is_dir()
        {
            tracing::info!(name = %source.name, path = %source.path, "source is current");
            continue;
        }
        match lay_down(sink, source, &target, staging_dir) {
            Ok(()) => {
                stamps.insert(source.path.clone(), source.sha256.clone());
                tracing::info!(
                    name = %source.name,
                    path = %source.path,
                    bytes = source.bytes,
                    read_only = source.read_only,
                    "source laid down beside the worktree"
                );
            }
            Err(error) => {
                // The session is worth more than one directory: it runs without this one.
                stamps.remove(&source.path);
                tracing::warn!(
                    name = %source.name,
                    path = %source.path,
                    error = %error,
                    "source skipped"
                );
            }
        }
    }
    write_stamps(&stamp_path, &stamps);
    Ok(())
}

/// The absolute path a source may be written to, or the reason it may not.
fn target_of(source: &PlanSource, layout: &SourceLayout) -> Result<PathBuf, BootError> {
    let workspace_root = layout.workspace_root.as_path();
    let working_directory = layout.working_directory.as_path();
    let refuse = |reason: &str| {
        BootError::config(format!(
            "capture plan source {:?} names {:?}: {reason}",
            source.name, source.path
        ))
    };
    if source.name.is_empty() || source.name.contains('/') {
        return Err(refuse("a source name is a label, not a path"));
    }
    let path = PathBuf::from(&source.path);
    if !path.is_absolute() {
        return Err(refuse("a source path is absolute"));
    }
    if path
        .components()
        .any(|component| component == Component::ParentDir)
    {
        return Err(refuse("a source path carries no `..`"));
    }
    if !path.starts_with(workspace_root) || path == workspace_root {
        return Err(refuse("a source lives under the workspace root"));
    }
    // The decisive rule: content under the worktree would be captured back into the store.
    if path.starts_with(working_directory) || working_directory.starts_with(&path) {
        return Err(refuse("a source lives outside the worktree"));
    }
    Ok(path)
}

/// Fetch, verify and extract one source, then move it into place.
fn lay_down(
    sink: &dyn BlobSink,
    source: &PlanSource,
    target: &Path,
    staging_dir: &Path,
) -> Result<(), BootError> {
    if source.bytes > MAX_SOURCE_BYTES {
        return Err(BootError::config(format!(
            "{} bytes is past the {MAX_SOURCE_BYTES}-byte limit for one source",
            source.bytes
        )));
    }
    let bytes = sink
        .get(&source.key)
        .map_err(|error| BootError::config(format!("fetching {}: {error}", source.key)))?;
    let digest = format!("{:x}", Sha256::digest(&bytes));
    if digest != source.sha256 {
        return Err(BootError::config(format!(
            "archive at {} hashes to {digest}, not the {} the plan declared",
            source.key, source.sha256
        )));
    }

    let scratch = staging_dir.join("sources-scratch");
    std::fs::create_dir_all(&scratch).map_err(|e| io_at("mkdir -p", &scratch, e))?;
    let staged = scratch.join(&source.sha256);
    if staged.exists() {
        std::fs::remove_dir_all(&staged).map_err(|e| io_at("rm -rf", &staged, e))?;
    }
    std::fs::create_dir_all(&staged).map_err(|e| io_at("mkdir -p", &staged, e))?;
    let archive = scratch.join(format!("{}.tar.gz", source.sha256));
    std::fs::write(&archive, &bytes).map_err(|e| io_at("write", &archive, e))?;
    let extracted = extract(&archive, &staged);
    let _ = std::fs::remove_file(&archive);
    extracted?;

    if let Some(parent) = target.parent() {
        std::fs::create_dir_all(parent).map_err(|e| io_at("mkdir -p", parent, e))?;
    }
    // Replace whatever is there: the stamp said this copy is not current. A read-only copy is
    // made writable first — removing a tree needs the writable bit on its directories, the same
    // reason the new copy is sealed only once it is in place.
    if target.exists() {
        set_write_bits(target, true).map_err(|e| io_at("chmod -R", target, e))?;
        std::fs::remove_dir_all(target).map_err(|e| io_at("rm -rf", target, e))?;
    }
    std::fs::rename(&staged, target).map_err(|e| io_at("mv", &staged, e))?;
    if source.read_only {
        set_write_bits(target, false).map_err(|e| io_at("chmod -R", target, e))?;
    }
    Ok(())
}

/// `tar -xzf` into `into`, never restoring ownership: the archive is content the control plane
/// published, not a backup of this machine. Absolute and `..` members are left to tar's own
/// default, which strips the leading `/` and refuses the traversal in both GNU tar and bsdtar —
/// the image's tar is whichever the base image ships, so no GNU-only flag is used (the dotfiles
/// archives take the same plain `-xzf`).
fn extract(archive: &Path, into: &Path) -> Result<(), BootError> {
    let output = Command::new("tar")
        .arg("-xzf")
        .arg(archive)
        .arg("-C")
        .arg(into)
        .arg("--no-same-owner")
        .output_gated()
        .map_err(|e| io_at("spawn tar", archive, e))?;
    if output.status.success() {
        return Ok(());
    }
    Err(BootError::config(format!(
        "tar -xzf exited {}: {}",
        output.status,
        String::from_utf8_lossy(&output.stderr).trim()
    )))
}

/// Add or take away the writable bits across a tree. Sealing runs deepest first, so a directory
/// is never sealed before its children are reached; unsealing runs top down, so a directory is
/// writable before its children are visited.
fn set_write_bits(root: &Path, writable: bool) -> io::Result<()> {
    for entry in walkdir::WalkDir::new(root)
        .contents_first(!writable)
        .into_iter()
        .filter_map(Result::ok)
    {
        // A symlink's own mode is not followed; its target is content elsewhere in the tree.
        if entry.file_type().is_symlink() {
            continue;
        }
        let mode = entry.metadata()?.permissions().mode();
        let next = if writable {
            mode | 0o700
        } else {
            mode & !0o222
        };
        std::fs::set_permissions(entry.path(), std::fs::Permissions::from_mode(next))?;
    }
    Ok(())
}

fn read_stamps(path: &Path) -> BTreeMap<String, String> {
    std::fs::read_to_string(path)
        .ok()
        .and_then(|raw| serde_json::from_str(&raw).ok())
        .unwrap_or_default()
}

/// A stamp that cannot be written costs a re-extraction next boot, never the boot itself.
fn write_stamps(path: &Path, stamps: &BTreeMap<String, String>) {
    match serde_json::to_vec(stamps) {
        Ok(bytes) => {
            if let Err(error) = std::fs::write(path, bytes) {
                tracing::warn!(path = %path.display(), %error, "source stamps not written");
            }
        }
        Err(error) => tracing::warn!(%error, "source stamps not encoded"),
    }
}

fn io_at(what: &'static str, path: &Path, error: io::Error) -> BootError {
    BootError::io_path(what, path, error)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn source(name: &str, path: &str) -> PlanSource {
        PlanSource {
            name: name.to_owned(),
            path: path.to_owned(),
            key: "projects/p/sources/abc".to_owned(),
            sha256: "abc".to_owned(),
            bytes: 10,
            read_only: true,
        }
    }

    /// The rules that decide where a source may land. The worktree one is the load-bearing
    /// rule: content under it would be captured back into the store as the session's own work.
    #[test]
    fn a_source_lands_inside_the_workspace_and_outside_the_worktree() {
        let layout = SourceLayout {
            workspace_root: PathBuf::from("/workspace"),
            working_directory: PathBuf::from("/workspace/repo"),
            staging_dir: PathBuf::from("/workspace/repo/.sealantd/capture"),
        };
        let ok =
            |path: &str| target_of(&source("docs", path), &layout).map(|p| p.display().to_string());
        assert_eq!(ok("/workspace/home/docs").unwrap(), "/workspace/home/docs");
        assert_eq!(ok("/workspace/ref/api").unwrap(), "/workspace/ref/api");

        for refused in [
            "/workspace/repo",           // the worktree itself
            "/workspace/repo/vendor",    // inside the worktree
            "/workspace",                // the root itself
            "/etc/ssh",                  // outside the workspace
            "home/docs",                 // not absolute
            "/workspace/home/../../etc", // a traversal
        ] {
            assert!(ok(refused).is_err(), "{refused} must be refused");
        }
        // A path the worktree sits under is refused too: laying it down would swallow the repo.
        assert!(ok("/workspace").is_err());
        // The name is a label for logs, never a path component.
        assert!(target_of(&source("a/b", "/workspace/home/docs"), &layout).is_err());
        assert!(target_of(&source("", "/workspace/home/docs"), &layout).is_err());
    }
}
