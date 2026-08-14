//! Runtime dotfiles application (E11): clone the dotfiles repo (optionally with an HTTP askpass
//! shim), auto-detect the manager (chezmoi / stow / copy), apply, and optionally run a bootstrap
//! command. Also applies caller-provided dotfiles archives (manifest.json + *.tar.gz staged by
//! the launching adapter) through the same manager dispatch. Runs synchronously before the
//! control socket binds so a failure aborts boot and nothing observes a half-applied home.

use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::Command;

use serde::Deserialize;

use crate::boot::config::{
    DEFAULT_DOTFILES_BOOTSTRAP_COMMAND, DotfilesConfig, DotfilesManager, DotfilesTarget,
};
use crate::boot::error::BootError;

/// Where the dotfiles repo is checked out.
const CHECKOUT_DIR: &str = "/root/.local/share/chezmoi";
/// Where caller-provided dotfiles archives are extracted before application.
const ARCHIVE_STAGING_DIR: &str = "/root/.local/share/sealant-dotfiles";
/// Home target.
const HOME_DIR: &str = "/root";

/// Apply runtime dotfiles. Returns once application completes (or errors).
///
/// # Errors
/// Returns [`BootError::Dotfiles`] (or a wrapped I/O/command error) on failure.
pub(crate) fn apply(config: &DotfilesConfig, runtime_dir: &Path) -> Result<(), BootError> {
    let checkout = PathBuf::from(CHECKOUT_DIR);
    if let Some(parent) = checkout.parent() {
        std::fs::create_dir_all(parent).map_err(|e| BootError::io_path("mkdir -p", parent, e))?;
    }
    if checkout.exists() {
        std::fs::remove_dir_all(&checkout)
            .map_err(|e| BootError::io_path("rm -rf", &checkout, e))?;
    }

    let askpass = materialize_askpass(config, runtime_dir)?;
    let clone_result = clone_dotfiles(config, &checkout, askpass.as_deref());
    if let Some(path) = &askpass {
        let _ = std::fs::remove_file(path);
    }
    clone_result?;

    apply_tree(
        &checkout,
        config.manager,
        config.target,
        config.bootstrap,
        &config.bootstrap_command,
    )
}

/// Apply one checked-out/extracted dotfiles tree: detect the manager, apply, run the bootstrap.
fn apply_tree(
    checkout: &Path,
    manager: DotfilesManager,
    target: DotfilesTarget,
    bootstrap: bool,
    bootstrap_command: &str,
) -> Result<(), BootError> {
    let manager = detect_manager(manager, checkout);
    tracing::info!(?manager, "applying dotfiles");
    match manager {
        ResolvedManager::Chezmoi => apply_chezmoi(checkout)?,
        ResolvedManager::Stow => apply_stow(checkout, target)?,
        ResolvedManager::Copy => apply_copy(checkout, target)?,
    }

    if bootstrap {
        run_bootstrap(checkout, bootstrap_command)?;
    }
    Ok(())
}

/// The manifest describing caller-provided dotfiles archives (`manifest.json` beside them).
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct ArchiveManifest {
    archives: Vec<ArchiveEntry>,
}

/// One caller-provided archive: a gzipped tar applied like a checkout, in manifest order.
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct ArchiveEntry {
    /// Archive file name inside the archive dir — a plain basename, no path segments.
    file: String,
    #[serde(default)]
    manager: Option<DotfilesManager>,
    #[serde(default)]
    target: Option<DotfilesTarget>,
    /// Run the bootstrap command after applying (skipped when absent), mirroring the repo path.
    #[serde(default = "default_true")]
    bootstrap: bool,
    #[serde(default)]
    bootstrap_command: Option<String>,
}

fn default_true() -> bool {
    true
}

/// Apply caller-provided dotfiles archives from `dir`, in manifest order.
///
/// # Errors
/// Returns [`BootError::Dotfiles`] (or a wrapped I/O/command error) on failure; any failure
/// aborts boot like the repo-based path.
pub(crate) fn apply_archives(dir: &Path) -> Result<(), BootError> {
    let manifest_path = dir.join("manifest.json");
    let raw = std::fs::read_to_string(&manifest_path)
        .map_err(|e| BootError::io_path("read", &manifest_path, e))?;
    let manifest: ArchiveManifest = serde_json::from_str(&raw)
        .map_err(|e| BootError::Dotfiles(format!("invalid dotfiles archive manifest: {e}")))?;

    for (index, entry) in manifest.archives.iter().enumerate() {
        if entry.file.contains('/') || entry.file.contains("..") {
            return Err(BootError::Dotfiles(format!(
                "dotfiles archive file name {:?} must be a plain basename",
                entry.file
            )));
        }
        let archive = dir.join(&entry.file);
        let staging = PathBuf::from(ARCHIVE_STAGING_DIR).join(index.to_string());
        if staging.exists() {
            std::fs::remove_dir_all(&staging)
                .map_err(|e| BootError::io_path("rm -rf", &staging, e))?;
        }
        std::fs::create_dir_all(&staging)
            .map_err(|e| BootError::io_path("mkdir -p", &staging, e))?;
        extract_archive(&archive, &staging)?;
        apply_tree(
            &staging,
            entry.manager.unwrap_or(DotfilesManager::Auto),
            entry.target.unwrap_or(DotfilesTarget::Home),
            entry.bootstrap,
            entry
                .bootstrap_command
                .as_deref()
                .unwrap_or(DEFAULT_DOTFILES_BOOTSTRAP_COMMAND),
        )?;
    }
    Ok(())
}

fn extract_archive(archive: &Path, staging: &Path) -> Result<(), BootError> {
    run_checked(
        Command::new("tar")
            .arg("-xzf")
            .arg(archive)
            .arg("-C")
            .arg(staging),
        "tar -xzf",
    )
}

/// Write the dotfiles HTTP askpass shim if a token is configured.
fn materialize_askpass(
    config: &DotfilesConfig,
    runtime_dir: &Path,
) -> Result<Option<PathBuf>, BootError> {
    let Some(token) = &config.http_token else {
        return Ok(None);
    };
    let path = runtime_dir.join("dotfiles-askpass.sh");
    let script = format!(
        "#!/bin/sh\ncase \"$1\" in\n*[Uu]sername*) printf '%s' {} ;;\n*) printf '%s' {} ;;\nesac\n",
        single_quote(&config.http_username),
        single_quote(token),
    );
    std::fs::write(&path, script).map_err(|e| BootError::io_path("write", &path, e))?;
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o700))
        .map_err(|e| BootError::io_path("chmod", &path, e))?;
    Ok(Some(path))
}

fn single_quote(value: &str) -> String {
    format!("'{}'", value.replace('\'', "'\\''"))
}

fn clone_dotfiles(
    config: &DotfilesConfig,
    checkout: &Path,
    askpass: Option<&Path>,
) -> Result<(), BootError> {
    let mut command = Command::new("git");
    command.arg("clone").arg("--depth").arg("1");
    // No ref means the remote's default branch — `--branch` would also reject commit SHAs.
    if let Some(reference) = &config.reference {
        command.arg("--branch").arg(reference);
    }
    command.arg(&config.url).arg(checkout);
    if let Some(path) = askpass {
        command.env("GIT_ASKPASS", path);
        command.env("GIT_TERMINAL_PROMPT", "0");
    }
    let status = command
        .status()
        .map_err(|e| BootError::Dotfiles(format!("could not spawn git: {e}")))?;
    if !status.success() {
        return Err(BootError::Dotfiles(format!(
            "git clone of dotfiles exited with {status}"
        )));
    }
    Ok(())
}

/// The concrete manager chosen after auto-detection.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ResolvedManager {
    Chezmoi,
    Stow,
    Copy,
}

/// Auto-detect the dotfiles manager (E11): chezmoi if a `.chezmoiroot`/`*.tmpl`/`dot_*` layout or
/// chezmoi binary is present, stow if package-style top-level directories exist, else plain copy.
fn detect_manager(requested: DotfilesManager, checkout: &Path) -> ResolvedManager {
    match requested {
        DotfilesManager::Chezmoi => return ResolvedManager::Chezmoi,
        DotfilesManager::Stow => return ResolvedManager::Stow,
        DotfilesManager::Copy => return ResolvedManager::Copy,
        DotfilesManager::Auto => {}
    }

    let has_chezmoi_layout = checkout.join(".chezmoiroot").exists()
        || dir_has_entry(checkout, |name| {
            name.starts_with("dot_") || name.starts_with("private_") || name.ends_with(".tmpl")
        });
    if has_chezmoi_layout && binary_exists("chezmoi") {
        return ResolvedManager::Chezmoi;
    }

    // Stow layout: top-level package directories (no leading dot, all directories).
    if binary_exists("stow") && looks_like_stow(checkout) {
        return ResolvedManager::Stow;
    }

    ResolvedManager::Copy
}

fn dir_has_entry(dir: &Path, predicate: impl Fn(&str) -> bool) -> bool {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return false;
    };
    entries
        .flatten()
        .any(|e| e.file_name().to_str().is_some_and(&predicate))
}

fn looks_like_stow(dir: &Path) -> bool {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return false;
    };
    let mut package_dirs = 0;
    for entry in entries.flatten() {
        let name = entry.file_name();
        let Some(name) = name.to_str() else { continue };
        if name.starts_with('.') {
            continue;
        }
        if entry.path().is_dir() {
            package_dirs += 1;
        }
    }
    package_dirs > 0
}

fn binary_exists(name: &str) -> bool {
    which(name).is_some()
}

/// Minimal `which`: search `$PATH` for an executable named `name`.
fn which(name: &str) -> Option<PathBuf> {
    let path = std::env::var_os("PATH")?;
    std::env::split_paths(&path)
        .map(|dir| dir.join(name))
        .find(|candidate| is_executable(candidate))
}

fn is_executable(path: &Path) -> bool {
    std::fs::metadata(path)
        .map(|m| m.is_file() && m.permissions().mode() & 0o111 != 0)
        .unwrap_or(false)
}

fn apply_chezmoi(checkout: &Path) -> Result<(), BootError> {
    run_checked(
        Command::new("chezmoi")
            .arg("apply")
            .arg("--source")
            .arg(checkout)
            .arg("--force"),
        "chezmoi apply",
    )
}

fn apply_stow(checkout: &Path, target: DotfilesTarget) -> Result<(), BootError> {
    let target_dir = target_dir(target);
    std::fs::create_dir_all(&target_dir)
        .map_err(|e| BootError::io_path("mkdir -p", &target_dir, e))?;
    // Stow each top-level package directory into the target.
    let entries =
        std::fs::read_dir(checkout).map_err(|e| BootError::io_path("read_dir", checkout, e))?;
    for entry in entries.flatten() {
        let name = entry.file_name();
        let Some(name) = name.to_str() else { continue };
        if name.starts_with('.') || !entry.path().is_dir() {
            continue;
        }
        run_checked(
            Command::new("stow")
                .arg("-d")
                .arg(checkout)
                .arg("-t")
                .arg(&target_dir)
                .arg(name),
            "stow",
        )?;
    }
    Ok(())
}

fn apply_copy(checkout: &Path, target: DotfilesTarget) -> Result<(), BootError> {
    let target_dir = target_dir(target);
    std::fs::create_dir_all(&target_dir)
        .map_err(|e| BootError::io_path("mkdir -p", &target_dir, e))?;
    copy_tree(checkout, &target_dir)
}

fn target_dir(target: DotfilesTarget) -> PathBuf {
    match target {
        DotfilesTarget::Home => PathBuf::from(HOME_DIR),
        DotfilesTarget::Config => PathBuf::from(HOME_DIR).join(".config"),
    }
}

/// Recursively copy the dotfiles tree into the target, skipping the `.git` directory.
fn copy_tree(src: &Path, dst: &Path) -> Result<(), BootError> {
    let entries = std::fs::read_dir(src).map_err(|e| BootError::io_path("read_dir", src, e))?;
    for entry in entries.flatten() {
        let name = entry.file_name();
        if name == ".git" {
            continue;
        }
        let from = entry.path();
        let to = dst.join(&name);
        if from.is_dir() {
            std::fs::create_dir_all(&to).map_err(|e| BootError::io_path("mkdir -p", &to, e))?;
            copy_tree(&from, &to)?;
        } else {
            std::fs::copy(&from, &to).map_err(|e| BootError::io_path("copy", &to, e))?;
        }
    }
    Ok(())
}

fn run_bootstrap(checkout: &Path, command: &str) -> Result<(), BootError> {
    let bootstrap_path = checkout.join(command.trim_start_matches("./"));
    if !bootstrap_path.exists() {
        tracing::info!(command, "dotfiles bootstrap command absent; skipping");
        return Ok(());
    }
    run_checked(
        Command::new("/bin/sh")
            .arg("-c")
            .arg(command)
            .current_dir(checkout),
        "dotfiles bootstrap",
    )
}

fn run_checked(command: &mut Command, label: &str) -> Result<(), BootError> {
    let status = command
        .status()
        .map_err(|e| BootError::Dotfiles(format!("{label}: could not spawn: {e}")))?;
    if !status.success() {
        return Err(BootError::Dotfiles(format!("{label} exited with {status}")));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn copy_manager_when_no_tooling_layout() {
        let dir = tempfile::tempdir().expect("tmp");
        std::fs::write(dir.path().join(".bashrc"), b"export X=1\n").expect("write");
        // Plain files, no chezmoi/stow layout -> copy.
        assert_eq!(
            detect_manager(DotfilesManager::Auto, dir.path()),
            ResolvedManager::Copy
        );
    }

    #[test]
    fn explicit_manager_is_respected() {
        let dir = tempfile::tempdir().expect("tmp");
        assert_eq!(
            detect_manager(DotfilesManager::Stow, dir.path()),
            ResolvedManager::Stow
        );
        assert_eq!(
            detect_manager(DotfilesManager::Chezmoi, dir.path()),
            ResolvedManager::Chezmoi
        );
    }

    #[test]
    fn copy_tree_skips_git_and_copies_files() {
        let src = tempfile::tempdir().expect("src");
        let dst = tempfile::tempdir().expect("dst");
        std::fs::create_dir_all(src.path().join(".git")).expect("git");
        std::fs::write(src.path().join(".git/config"), b"x").expect("write");
        std::fs::write(src.path().join(".vimrc"), b"set nocompatible\n").expect("write");
        std::fs::create_dir_all(src.path().join("nested")).expect("nested");
        std::fs::write(src.path().join("nested/file"), b"hi").expect("write");

        copy_tree(src.path(), dst.path()).expect("copy");
        assert!(dst.path().join(".vimrc").exists());
        assert!(dst.path().join("nested/file").exists());
        assert!(!dst.path().join(".git").exists());
    }

    #[test]
    fn single_quote_escapes() {
        assert_eq!(single_quote("a'b"), "'a'\\''b'");
    }

    #[test]
    fn archive_manifest_parses_with_defaults() {
        let manifest: ArchiveManifest = serde_json::from_str(
            r#"{"archives":[
                {"file":"0.tar.gz"},
                {"file":"1.tar.gz","manager":"copy","target":"config","bootstrap":false,"bootstrapCommand":"./setup.sh"}
            ]}"#,
        )
        .expect("valid manifest");
        assert_eq!(manifest.archives.len(), 2);
        let first = &manifest.archives[0];
        assert_eq!(first.manager, None);
        assert_eq!(first.target, None);
        assert!(first.bootstrap);
        assert_eq!(first.bootstrap_command, None);
        let second = &manifest.archives[1];
        assert_eq!(second.manager, Some(DotfilesManager::Copy));
        assert_eq!(second.target, Some(DotfilesTarget::Config));
        assert!(!second.bootstrap);
        assert_eq!(second.bootstrap_command.as_deref(), Some("./setup.sh"));
    }

    #[test]
    fn archive_file_name_with_path_segments_is_rejected() {
        let dir = tempfile::tempdir().expect("tmp");
        std::fs::write(
            dir.path().join("manifest.json"),
            r#"{"archives":[{"file":"../evil.tar.gz"}]}"#,
        )
        .expect("write");
        let err = apply_archives(dir.path()).expect_err("traversal must be rejected");
        assert!(format!("{err}").contains("plain basename"));
    }

    #[test]
    fn extract_archive_unpacks_into_staging() {
        let source = tempfile::tempdir().expect("src");
        std::fs::write(source.path().join(".zshrc"), b"export MARKER=1\n").expect("write");
        let packed = tempfile::tempdir().expect("packed");
        let archive = packed.path().join("dots.tar.gz");
        let status = Command::new("tar")
            .arg("-czf")
            .arg(&archive)
            .arg("-C")
            .arg(source.path())
            .arg(".")
            .status()
            .expect("tar available");
        assert!(status.success());

        let staging = tempfile::tempdir().expect("staging");
        extract_archive(&archive, staging.path()).expect("extract");
        let content = std::fs::read_to_string(staging.path().join(".zshrc")).expect("read");
        assert_eq!(content, "export MARKER=1\n");
    }
}
