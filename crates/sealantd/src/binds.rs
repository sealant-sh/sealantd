//! Bindable mounts (ADR-0014): a mount whose declared path is a symlink the daemon points at a
//! subdirectory of a root the orchestrator mounted at container start.
//!
//! Neither Docker nor Kubernetes can add a mount to a running container, so a standby workspace
//! mounts the *parent* (a project's worktrees directory) at a hidden root and lets the control
//! plane bind `/workspace/repo` to one worktree later — or rebind it, or bind a sibling
//! repository under `/workspace/repos/<name>`. The daemon owns the symlink, records every binding
//! under `/run/sealant`, and re-applies the record when it restarts inside the same container.
//! Recorded and orchestrator-supplied binds are applied at boot before the control socket binds,
//! so a harness never starts against a missing working directory.

use std::path::{Component, Path, PathBuf};
use std::sync::Mutex;

use sealant_protocol::ControlError;
use sealant_runtime_core::config::{Bind, BindableMount};
use serde::{Deserialize, Serialize};

/// Where the daemon records the live bindings inside the container.
pub const BINDS_STATE_FILE: &str = "/run/sealant/binds.json";

/// The persisted shape of the live bindings.
#[derive(Debug, Default, Serialize, Deserialize)]
struct BindsState {
    binds: Vec<Bind>,
}

/// Why a bind could not be applied at boot. Command-time failures surface as [`ControlError`].
#[derive(Debug)]
pub struct BindError(String);

impl std::fmt::Display for BindError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for BindError {}

/// The bindable mounts of one workspace and their live bindings.
#[derive(Debug)]
pub struct BindRuntime {
    mounts: Vec<BindableMount>,
    state_file: PathBuf,
    binds: Mutex<Vec<Bind>>,
}

impl BindRuntime {
    /// A runtime over the configured bindable mounts, recording state at `state_file`.
    #[must_use]
    pub fn new(mounts: Vec<BindableMount>, state_file: PathBuf) -> Self {
        Self {
            mounts,
            state_file,
            binds: Mutex::new(Vec::new()),
        }
    }

    /// Whether any mount is bindable at all (a plain clone or mount workspace has none).
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.mounts.is_empty()
    }

    /// The configured bindable mounts.
    #[must_use]
    pub fn mounts(&self) -> &[BindableMount] {
        &self.mounts
    }

    /// The live bindings, in application order.
    #[must_use]
    pub fn binds(&self) -> Vec<Bind> {
        self.binds.lock().unwrap_or_else(|e| e.into_inner()).clone()
    }

    /// Apply the orchestrator's binds for this launch, then whatever the record holds for mounts
    /// the orchestrator did not name (a daemon restart inside a live container). The orchestrator
    /// wins: its view is the durable one across container recreation.
    ///
    /// # Errors
    /// Returns the first bind that could not be applied; boot treats it as fatal, because a
    /// harness must never start against a working directory the platform said would be there.
    pub fn apply_initial(&self, initial: &[Bind]) -> Result<(), BindError> {
        let recorded = self.read_state();
        let mut seen: Vec<PathBuf> = Vec::new();
        for bind in initial.iter().chain(recorded.iter()) {
            if seen.contains(&bind.mount_path) {
                continue;
            }
            seen.push(bind.mount_path.clone());
            self.bind(&bind.mount_path.to_string_lossy(), &bind.subpath)
                .map_err(|error| BindError(error.message))?;
        }
        Ok(())
    }

    /// Point `mount_path` at `<root>/<subpath>`; an empty `subpath` unbinds. Idempotent: binding
    /// the same target again is a no-op that still records.
    ///
    /// # Errors
    /// `invalid_argument` for an unknown mount path, an unsafe or missing subpath, or a mount path
    /// occupied by a real file or non-empty directory; `internal` when the filesystem refuses.
    pub fn bind(&self, mount_path: &str, subpath: &str) -> Result<(), ControlError> {
        let mount_path = Path::new(mount_path);
        let mount = self
            .mounts
            .iter()
            .find(|m| m.mount_path == mount_path)
            .ok_or_else(|| {
                ControlError::invalid_argument(format!(
                    "{} is not a bindable mount of this workspace",
                    mount_path.display()
                ))
            })?;
        let subpath = subpath.trim();
        if subpath.is_empty() {
            unlink_binding(mount_path)?;
            self.record(mount_path, "");
            tracing::info!(mount_path = %mount_path.display(), "mount unbound");
            return Ok(());
        }
        let relative = safe_relative(subpath).ok_or_else(|| {
            ControlError::invalid_argument(format!(
                "subpath {subpath:?} must be relative with no `.` or `..` components"
            ))
        })?;
        let target = mount.root_mount_path.join(relative);
        match std::fs::metadata(&target) {
            Ok(meta) if meta.is_dir() => {}
            Ok(_) => {
                return Err(ControlError::invalid_argument(format!(
                    "{} is not a directory",
                    target.display()
                )));
            }
            Err(error) => {
                return Err(ControlError::invalid_argument(format!(
                    "{} does not exist under the mount root ({error})",
                    target.display()
                )));
            }
        }
        unlink_binding(mount_path)?;
        if let Some(parent) = mount_path.parent() {
            std::fs::create_dir_all(parent).map_err(|error| {
                ControlError::internal(format!("mkdir -p {}: {error}", parent.display()))
            })?;
        }
        std::os::unix::fs::symlink(&target, mount_path).map_err(|error| {
            ControlError::internal(format!(
                "symlink {} -> {}: {error}",
                mount_path.display(),
                target.display()
            ))
        })?;
        mark_git_safe(&target);
        self.record(mount_path, subpath);
        tracing::info!(
            mount_path = %mount_path.display(),
            target = %target.display(),
            "mount bound"
        );
        Ok(())
    }

    fn record(&self, mount_path: &Path, subpath: &str) {
        let mut binds = self.binds.lock().unwrap_or_else(|e| e.into_inner());
        binds.retain(|b| b.mount_path != mount_path);
        if !subpath.is_empty() {
            binds.push(Bind {
                mount_path: mount_path.to_path_buf(),
                subpath: subpath.to_owned(),
            });
        }
        let state = BindsState {
            binds: binds.clone(),
        };
        drop(binds);
        if let Some(parent) = self.state_file.parent() {
            let _ = std::fs::create_dir_all(parent);
        }
        match serde_json::to_vec_pretty(&state) {
            Ok(bytes) => {
                if let Err(error) = std::fs::write(&self.state_file, bytes) {
                    tracing::warn!(%error, path = %self.state_file.display(), "could not record binds");
                }
            }
            Err(error) => tracing::warn!(%error, "could not encode binds"),
        }
    }

    fn read_state(&self) -> Vec<Bind> {
        let Ok(bytes) = std::fs::read(&self.state_file) else {
            return Vec::new();
        };
        match serde_json::from_slice::<BindsState>(&bytes) {
            Ok(state) => state.binds,
            Err(error) => {
                tracing::warn!(%error, path = %self.state_file.display(), "ignoring unreadable binds record");
                Vec::new()
            }
        }
    }
}

/// A subpath is safe when every component is a plain name: relative, no `.`, no `..`, no root.
fn safe_relative(subpath: &str) -> Option<PathBuf> {
    let path = Path::new(subpath);
    if path.is_absolute()
        || !path
            .components()
            .all(|component| matches!(component, Component::Normal(_)))
    {
        return None;
    }
    Some(path.to_path_buf())
}

/// Remove whatever currently occupies the mount path so a symlink can take its place: a prior
/// symlink, or an empty directory (the image's `WORKDIR` may have created one). A real file or a
/// non-empty directory is caller content and is never removed.
fn unlink_binding(mount_path: &Path) -> Result<(), ControlError> {
    let Ok(meta) = std::fs::symlink_metadata(mount_path) else {
        return Ok(());
    };
    if meta.file_type().is_symlink() {
        return std::fs::remove_file(mount_path).map_err(|error| {
            ControlError::internal(format!("unlink {}: {error}", mount_path.display()))
        });
    }
    if meta.is_dir() {
        return std::fs::remove_dir(mount_path).map_err(|error| {
            ControlError::invalid_argument(format!(
                "{} is a real directory that is not empty; refusing to bind over it ({error})",
                mount_path.display()
            ))
        });
    }
    Err(ControlError::invalid_argument(format!(
        "{} is a real file; refusing to bind over it",
        mount_path.display()
    )))
}

/// git refuses to operate on a repository owned by another uid unless its real path is listed as
/// safe; the image lists the declared mount path, but through a symlink git sees the target.
fn mark_git_safe(target: &Path) {
    if !target.join(".git").exists() {
        return;
    }
    let value = target.to_string_lossy().into_owned();
    let listed = std::process::Command::new("git")
        .args(["config", "--system", "--get-all", "safe.directory"])
        .output()
        .ok()
        .map(|out| {
            String::from_utf8_lossy(&out.stdout)
                .lines()
                .any(|l| l == value)
        })
        .unwrap_or(false);
    if listed {
        return;
    }
    if let Err(error) = std::process::Command::new("git")
        .args(["config", "--system", "--add", "safe.directory", &value])
        .status()
    {
        tracing::warn!(%error, target = %target.display(), "could not mark the bound repository safe for git");
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn scratch(name: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "sealantd-binds-{name}-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_nanos())
                .unwrap_or(0)
        ));
        std::fs::create_dir_all(&dir).expect("scratch dir");
        dir
    }

    fn runtime(dir: &Path) -> BindRuntime {
        let root = dir.join("roots/workspace");
        std::fs::create_dir_all(root.join("wt-a")).expect("wt-a");
        std::fs::create_dir_all(root.join("wt-b")).expect("wt-b");
        BindRuntime::new(
            vec![BindableMount {
                mount_path: dir.join("repo"),
                root_mount_path: root,
                host_root_path: Some("/var/lib/mend/store/acme/worktrees".to_owned()),
            }],
            dir.join("state/binds.json"),
        )
    }

    #[test]
    fn binds_rebinds_and_unbinds_through_a_symlink() {
        let dir = scratch("bind");
        let binds = runtime(&dir);
        let repo = dir.join("repo");
        let repo_str = repo.to_string_lossy().into_owned();

        binds.bind(&repo_str, "wt-a").expect("bind a");
        assert_eq!(
            std::fs::read_link(&repo).expect("symlink"),
            dir.join("roots/workspace/wt-a")
        );
        binds.bind(&repo_str, "wt-b").expect("rebind b");
        assert_eq!(
            std::fs::read_link(&repo).expect("symlink"),
            dir.join("roots/workspace/wt-b")
        );
        assert_eq!(binds.binds()[0].subpath, "wt-b");

        binds.bind(&repo_str, "").expect("unbind");
        assert!(std::fs::symlink_metadata(&repo).is_err());
        assert!(binds.binds().is_empty());
    }

    #[test]
    fn refuses_unknown_mounts_unsafe_subpaths_and_missing_targets() {
        let dir = scratch("refuse");
        let binds = runtime(&dir);
        let repo = dir.join("repo").to_string_lossy().into_owned();
        assert!(binds.bind("/elsewhere", "wt-a").is_err());
        assert!(binds.bind(&repo, "../wt-a").is_err());
        assert!(binds.bind(&repo, "/wt-a").is_err());
        assert!(binds.bind(&repo, "wt-missing").is_err());
        assert!(std::fs::symlink_metadata(dir.join("repo")).is_err());
    }

    #[test]
    fn never_binds_over_caller_content() {
        let dir = scratch("content");
        let binds = runtime(&dir);
        let repo = dir.join("repo");
        std::fs::create_dir_all(repo.join("keep")).expect("non-empty dir");
        assert!(binds.bind(&repo.to_string_lossy(), "wt-a").is_err());
        assert!(repo.join("keep").is_dir());
        // An EMPTY directory (the image's WORKDIR) is replaced.
        std::fs::remove_dir(repo.join("keep")).expect("empty it");
        binds
            .bind(&repo.to_string_lossy(), "wt-a")
            .expect("bind over empty dir");
        assert!(std::fs::read_link(&repo).is_ok());
    }

    #[test]
    fn boot_applies_the_orchestrator_then_the_record_without_double_binding() {
        let dir = scratch("initial");
        let first = runtime(&dir);
        let repo = dir.join("repo");
        first
            .bind(&repo.to_string_lossy(), "wt-a")
            .expect("record wt-a");
        drop(first);
        // A daemon restart in the same container: the orchestrator says wt-b, the record says wt-a.
        let second = runtime(&dir);
        second
            .apply_initial(&[Bind {
                mount_path: repo.clone(),
                subpath: "wt-b".to_owned(),
            }])
            .expect("apply");
        assert_eq!(
            std::fs::read_link(&repo).expect("symlink"),
            dir.join("roots/workspace/wt-b")
        );
        assert_eq!(second.binds().len(), 1);
        // No orchestrator view at all: the record alone is re-applied.
        let third = runtime(&dir);
        third.apply_initial(&[]).expect("apply recorded");
        assert_eq!(third.binds()[0].subpath, "wt-b");
    }
}
