//! Runtime dotfiles application (E11): clone the dotfiles repo (optionally with an HTTP askpass
//! shim), auto-detect the manager (chezmoi / stow / copy), apply, and optionally run a bootstrap
//! command. Also applies caller-provided dotfiles archives (manifest.json + *.tar.gz staged by
//! the launching adapter) through the same manager dispatch. Runs synchronously before the
//! control socket binds so a failure aborts boot and nothing observes a half-applied home.

use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::Command;

use sealant_process::CommandGateExt;
use serde::Deserialize;

use crate::boot::config::{
    DEFAULT_DOTFILES_BOOTSTRAP_COMMAND, DotfilesConfig, DotfilesManager, DotfilesTarget,
};
use crate::boot::error::BootError;

/// Home target.
const HOME_DIR: &str = "/root";
/// The account boot applies dotfiles as. PID 1 runs as root, and the harness child is given the
/// same identity (see `harness_child_env`), so the tools see the home the harness will use.
const HOME_USER: &str = "root";

/// XDG base-directory overrides dropped from every command that applies dotfiles, so chezmoi and
/// a bootstrap script derive their config/data/state/cache paths from the `HOME` set here and
/// never from whatever the boot process happened to inherit.
const XDG_BASE_DIRS: &[&str] = &[
    "XDG_CONFIG_HOME",
    "XDG_DATA_HOME",
    "XDG_STATE_HOME",
    "XDG_CACHE_HOME",
];

/// Top-level dot entries that are repository or stow metadata rather than dotfiles, so they do
/// not make a tree "mixed" and are never copied into the home by the stow manager.
///
/// - `.git`, `.gitignore`, `.gitmodules`, `.cvsignore`, `.svn`, `.hg`: the version-control
///   entries on GNU stow's built-in default ignore list (stow manual, "Types And Syntax Of Ignore
///   Lists"); stow itself never links them.
/// - `.gitattributes`, `.github`: repository metadata no home directory wants; not on stow's
///   list only because stow never looks at top-level dot entries at all.
/// - `.stowrc`, `.stow-local-ignore`, `.stow-global-ignore`: stow's own resource and ignore-list
///   files. `.stow` and `.nonstow`: the marker files stow reads to recognise (or refuse to
///   treat) a directory as a stow directory.
///
/// Anything else with a leading dot at the top level (`.zshenv`, `.config`, `.editorconfig`) is
/// treated as a dotfile the user expects in their home.
const STOW_METADATA: &[&str] = &[
    ".git",
    ".gitignore",
    ".gitmodules",
    ".gitattributes",
    ".github",
    ".cvsignore",
    ".svn",
    ".hg",
    ".stowrc",
    ".stow-local-ignore",
    ".stow-global-ignore",
    ".stow",
    ".nonstow",
];

/// Where dotfiles are applied, and the identity every command that applies them runs under.
#[derive(Debug, Clone)]
struct Home {
    dir: PathBuf,
    user: &'static str,
}

impl Home {
    /// The workspace home: `/root`, as root.
    fn root() -> Self {
        Self {
            dir: PathBuf::from(HOME_DIR),
            user: HOME_USER,
        }
    }

    /// Where the dotfiles repo is checked out.
    fn checkout_dir(&self) -> PathBuf {
        self.dir.join(".local/share/chezmoi")
    }

    /// Where caller-provided dotfiles archives are extracted before application.
    fn archive_staging_dir(&self) -> PathBuf {
        self.dir.join(".local/share/sealant-dotfiles")
    }

    fn target_dir(&self, target: DotfilesTarget) -> PathBuf {
        match target {
            DotfilesTarget::Home => self.dir.clone(),
            DotfilesTarget::Config => self.dir.join(".config"),
        }
    }

    /// Give `command` this home's identity: `HOME`, `USER` and `LOGNAME` set explicitly and the
    /// XDG base-directory overrides removed. Boot never sets these on its own process (see
    /// `prepare_workspace`), and a runtime that starts PID 1 without `HOME` (a MicroVM's init)
    /// would otherwise leave `chezmoi apply` and `./install.sh` resolving `~` to nothing.
    fn identify<'c>(&self, command: &'c mut Command) -> &'c mut Command {
        command
            .env("HOME", &self.dir)
            .env("USER", self.user)
            .env("LOGNAME", self.user);
        for key in XDG_BASE_DIRS {
            command.env_remove(key);
        }
        command
    }
}

/// Apply runtime dotfiles. Returns once application completes (or errors).
///
/// # Errors
/// Returns [`BootError::Dotfiles`] (or a wrapped I/O/command error) on failure.
pub(crate) fn apply(config: &DotfilesConfig, runtime_dir: &Path) -> Result<(), BootError> {
    let home = Home::root();
    let checkout = home.checkout_dir();
    if let Some(parent) = checkout.parent() {
        std::fs::create_dir_all(parent).map_err(|e| BootError::io_path("mkdir -p", parent, e))?;
    }
    if checkout.exists() {
        std::fs::remove_dir_all(&checkout)
            .map_err(|e| BootError::io_path("rm -rf", &checkout, e))?;
    }

    let askpass = materialize_askpass(config, runtime_dir)?;
    let clone_result = clone_dotfiles(config, &checkout, askpass.as_deref(), &home);
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
        &home,
    )
}

/// Apply one checked-out/extracted dotfiles tree: detect the manager, apply, run the bootstrap.
fn apply_tree(
    checkout: &Path,
    manager: DotfilesManager,
    target: DotfilesTarget,
    bootstrap: bool,
    bootstrap_command: &str,
    home: &Home,
) -> Result<(), BootError> {
    let resolution = detect_manager(manager, checkout);
    tracing::info!(
        requested = requested_name(manager),
        manager = resolution.manager.name(),
        reason = %resolution.reason,
        "applying dotfiles"
    );
    let target_dir = home.target_dir(target);
    match resolution.manager {
        ResolvedManager::Chezmoi => apply_chezmoi(checkout, home)?,
        ResolvedManager::Stow => apply_stow(checkout, &target_dir, home)?,
        ResolvedManager::Copy => apply_copy(checkout, &target_dir)?,
    }

    if bootstrap {
        run_bootstrap(checkout, bootstrap_command, home)?;
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
    apply_archives_into(dir, &Home::root())
}

fn apply_archives_into(dir: &Path, home: &Home) -> Result<(), BootError> {
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
        let staging = home.archive_staging_dir().join(index.to_string());
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
            home,
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
    home: &Home,
) -> Result<(), BootError> {
    let mut command = Command::new("git");
    home.identify(&mut command);
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
        .status_gated()
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

impl ResolvedManager {
    fn name(self) -> &'static str {
        match self {
            Self::Chezmoi => "chezmoi",
            Self::Stow => "stow",
            Self::Copy => "copy",
        }
    }
}

fn requested_name(manager: DotfilesManager) -> &'static str {
    match manager {
        DotfilesManager::Auto => "auto",
        DotfilesManager::Chezmoi => "chezmoi",
        DotfilesManager::Stow => "stow",
        DotfilesManager::Copy => "copy",
    }
}

/// The manager a tree is applied with, and what in the tree decided it (logged at apply).
#[derive(Debug, Clone, PartialEq, Eq)]
struct Resolution {
    manager: ResolvedManager,
    reason: String,
}

impl Resolution {
    fn new(manager: ResolvedManager, reason: impl Into<String>) -> Self {
        Self {
            manager,
            reason: reason.into(),
        }
    }
}

/// Resolve the manager for `checkout`, consulting `$PATH` for the chezmoi and stow binaries.
fn detect_manager(requested: DotfilesManager, checkout: &Path) -> Resolution {
    resolve_manager(requested, checkout, binary_exists)
}

/// Auto-detection (E11), top level of the tree only:
///
/// 1. chezmoi, when the tree is a chezmoi source (`.chezmoi*`, `dot_*`, `private_*` or `*.tmpl`
///    at the top) and the chezmoi binary is on `PATH`. A chezmoi source without the binary is
///    copied as-is: its `dot_*` names would be wrong under stow too.
/// 2. stow, only for a real stow layout: at least one non-dot top-level package directory and no
///    top-level dot entries beyond [`STOW_METADATA`]. Plain top-level files (`README.md`,
///    `Brewfile`, `LICENSE`) are not packages and do not prevent it. A mixed tree, dot entries
///    beside package directories, is a home mirror: stow would link the directories as packages
///    and skip every dot entry, so it is copied instead.
/// 3. copy, otherwise.
fn resolve_manager(
    requested: DotfilesManager,
    checkout: &Path,
    has_binary: impl Fn(&str) -> bool,
) -> Resolution {
    match requested {
        DotfilesManager::Chezmoi => {
            return Resolution::new(ResolvedManager::Chezmoi, "requested explicitly");
        }
        DotfilesManager::Stow => {
            return Resolution::new(ResolvedManager::Stow, "requested explicitly");
        }
        DotfilesManager::Copy => {
            return Resolution::new(ResolvedManager::Copy, "requested explicitly");
        }
        DotfilesManager::Auto => {}
    }

    let top = TopLevel::scan(checkout).unwrap_or_default();
    if !top.chezmoi_markers.is_empty() {
        let markers = name_list(&top.chezmoi_markers);
        return if has_binary("chezmoi") {
            Resolution::new(
                ResolvedManager::Chezmoi,
                format!("chezmoi source layout ({markers})"),
            )
        } else {
            Resolution::new(
                ResolvedManager::Copy,
                format!("chezmoi source layout ({markers}) and no chezmoi on PATH"),
            )
        };
    }
    if top.packages.is_empty() {
        return Resolution::new(ResolvedManager::Copy, "no top-level package directories");
    }
    let packages = name_list(&top.packages);
    if !top.home_entries.is_empty() {
        return Resolution::new(
            ResolvedManager::Copy,
            format!(
                "top-level dot entries ({}) beside package directories ({packages}); stow would \
                 skip the dot entries",
                name_list(&top.home_entries)
            ),
        );
    }
    if !has_binary("stow") {
        return Resolution::new(
            ResolvedManager::Copy,
            format!("stow package layout ({packages}) and no stow on PATH"),
        );
    }
    Resolution::new(
        ResolvedManager::Stow,
        format!("stow package layout ({packages})"),
    )
}

/// The top level of a dotfiles tree, classified for manager detection and the stow apply. Each
/// list is sorted so logs and decisions do not depend on directory order.
#[derive(Debug, Default)]
struct TopLevel {
    /// Entries that mark a chezmoi source.
    chezmoi_markers: Vec<String>,
    /// Dot entries that are not [`STOW_METADATA`]: dotfiles meant for the home itself.
    home_entries: Vec<String>,
    /// Non-dot directories (not symlinks to one): stow packages.
    packages: Vec<String>,
    /// Non-dot entries that are not directories: not packages, never stowed.
    loose_files: Vec<String>,
}

impl TopLevel {
    fn scan(dir: &Path) -> std::io::Result<Self> {
        let mut top = Self::default();
        for entry in std::fs::read_dir(dir)? {
            let entry = entry?;
            let Some(name) = entry.file_name().to_str().map(str::to_owned) else {
                continue;
            };
            if is_chezmoi_marker(&name) {
                top.chezmoi_markers.push(name.clone());
            }
            if name.starts_with('.') {
                if !STOW_METADATA.contains(&name.as_str()) {
                    top.home_entries.push(name);
                }
            } else if entry.file_type()?.is_dir() {
                top.packages.push(name);
            } else {
                top.loose_files.push(name);
            }
        }
        top.chezmoi_markers.sort();
        top.home_entries.sort();
        top.packages.sort();
        top.loose_files.sort();
        Ok(top)
    }
}

fn is_chezmoi_marker(name: &str) -> bool {
    name.starts_with(".chezmoi")
        || name.starts_with("dot_")
        || name.starts_with("private_")
        || name.ends_with(".tmpl")
}

/// Up to five names, comma-separated, with a count of the rest.
fn name_list(names: &[String]) -> String {
    const SHOWN: usize = 5;
    let mut list = names
        .iter()
        .take(SHOWN)
        .map(String::as_str)
        .collect::<Vec<_>>()
        .join(", ");
    if names.len() > SHOWN {
        list.push_str(&format!(" +{} more", names.len() - SHOWN));
    }
    list
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

fn apply_chezmoi(checkout: &Path, home: &Home) -> Result<(), BootError> {
    let mut command = Command::new("chezmoi");
    home.identify(&mut command)
        .arg("apply")
        .arg("--source")
        .arg(checkout)
        .arg("--destination")
        .arg(&home.dir)
        .arg("--force")
        .arg("--no-tty");
    run_checked(&mut command, "chezmoi apply")
}

/// Stow every top-level package directory into `target_dir`.
///
/// GNU stow only links packages, so a top-level dot entry (`.zshenv` beside `zsh/`) would never
/// reach the home. Rather than drop it silently, the stow manager copies each one that is not
/// [`STOW_METADATA`] into the target first, and logs their names. They go in before the packages
/// so a package sharing a directory with one (`.config`) is linked inside a real directory, and a
/// path both provide fails the apply with stow's own conflict error instead of one side winning
/// quietly. Loose top-level files (`README.md`) are not packages and are left out, as stow does.
fn apply_stow(checkout: &Path, target_dir: &Path, home: &Home) -> Result<(), BootError> {
    std::fs::create_dir_all(target_dir)
        .map_err(|e| BootError::io_path("mkdir -p", target_dir, e))?;
    let top = TopLevel::scan(checkout).map_err(|e| BootError::io_path("read_dir", checkout, e))?;
    if !top.home_entries.is_empty() {
        tracing::info!(
            entries = %name_list(&top.home_entries),
            "stow: top-level dot entries are not packages; copying them into the target"
        );
        for name in &top.home_entries {
            copy_entry(&checkout.join(name), &target_dir.join(name))?;
        }
    }
    if !top.loose_files.is_empty() {
        tracing::info!(
            files = %name_list(&top.loose_files),
            "stow: top-level files are not packages; not applied"
        );
    }
    for package in &top.packages {
        let mut command = Command::new("stow");
        home.identify(&mut command)
            .arg("-d")
            .arg(checkout)
            .arg("-t")
            .arg(target_dir)
            .arg(package);
        run_checked(&mut command, "stow")?;
    }
    Ok(())
}

fn apply_copy(checkout: &Path, target_dir: &Path) -> Result<(), BootError> {
    std::fs::create_dir_all(target_dir)
        .map_err(|e| BootError::io_path("mkdir -p", target_dir, e))?;
    copy_tree(checkout, target_dir)
}

/// Recursively copy the dotfiles tree into the target, skipping the `.git` directory.
fn copy_tree(src: &Path, dst: &Path) -> Result<(), BootError> {
    let entries = std::fs::read_dir(src).map_err(|e| BootError::io_path("read_dir", src, e))?;
    for entry in entries.flatten() {
        let name = entry.file_name();
        if name == ".git" {
            continue;
        }
        copy_entry(&entry.path(), &dst.join(&name))?;
    }
    Ok(())
}

/// Copy one entry the way `cp -a` would: a directory recursively, a symlink as the same symlink
/// (so a dangling or absolute link from the repository neither fails the apply nor is followed
/// out of the tree), a file as its bytes and mode. A file or symlink already at the destination
/// of a file or symlink is replaced rather than written through, so a later archive never edits
/// the file an earlier one's link points at. A directory is merged into whatever directory is at
/// its destination, including one reached through a symlink: a directory stow folded into an
/// earlier archive's staging tree receives the later archive's files there.
fn copy_entry(from: &Path, to: &Path) -> Result<(), BootError> {
    let file_type = std::fs::symlink_metadata(from)
        .map_err(|e| BootError::io_path("stat", from, e))?
        .file_type();
    if file_type.is_dir() {
        std::fs::create_dir_all(to).map_err(|e| BootError::io_path("mkdir -p", to, e))?;
        return copy_tree(from, to);
    }
    remove_non_directory(to)?;
    if file_type.is_symlink() {
        let link = std::fs::read_link(from).map_err(|e| BootError::io_path("readlink", from, e))?;
        std::os::unix::fs::symlink(&link, to).map_err(|e| BootError::io_path("symlink", to, e))?;
    } else {
        std::fs::copy(from, to).map_err(|e| BootError::io_path("copy", to, e))?;
    }
    Ok(())
}

/// Remove whatever non-directory sits at `path`. A directory is left for the caller's own
/// operation to refuse, loudly.
fn remove_non_directory(path: &Path) -> Result<(), BootError> {
    match std::fs::symlink_metadata(path) {
        Ok(meta) if !meta.is_dir() => {
            std::fs::remove_file(path).map_err(|e| BootError::io_path("rm", path, e))
        }
        Ok(_) => Ok(()),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(e) => Err(BootError::io_path("stat", path, e)),
    }
}

fn run_bootstrap(checkout: &Path, command: &str, home: &Home) -> Result<(), BootError> {
    let bootstrap_path = checkout.join(command.trim_start_matches("./"));
    if !bootstrap_path.exists() {
        tracing::info!(command, "dotfiles bootstrap command absent; skipping");
        return Ok(());
    }
    let mut shell = Command::new("/bin/sh");
    home.identify(&mut shell)
        .arg("-c")
        .arg(command)
        .current_dir(checkout);
    run_checked(&mut shell, "dotfiles bootstrap")
}

fn run_checked(command: &mut Command, label: &str) -> Result<(), BootError> {
    // Gated: the orphan reaper is already sweeping by the time dotfiles are applied, and an
    // ungated child it reaps first fails this `status()` with ECHILD (see `sealant_process::spawn`).
    let status = command
        .status_gated()
        .map_err(|e| BootError::Dotfiles(format!("{label}: could not spawn: {e}")))?;
    if !status.success() {
        return Err(BootError::Dotfiles(format!("{label} exited with {status}")));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::io::Write as _;

    use super::*;

    /// Set in CI, where stow and chezmoi are installed: a real-apply test that finds its tool
    /// missing fails instead of skipping.
    const REQUIRE_TOOLS_ENV: &str = "SEALANTD_REQUIRE_DOTFILES_TOOLS";

    /// Whether the real-apply test for `tool` can run. Without the tool it prints a visible skip
    /// line, unless [`REQUIRE_TOOLS_ENV`] is set, where it fails the test.
    fn tool_available(tool: &str) -> bool {
        if binary_exists(tool) {
            return true;
        }
        assert!(
            std::env::var_os(REQUIRE_TOOLS_ENV).is_none(),
            "{tool} is not on PATH and {REQUIRE_TOOLS_ENV} is set"
        );
        // Straight to stderr: libtest captures `eprintln!`, which would hide the skip.
        let _ = writeln!(
            std::io::stderr(),
            "SKIPPED: {tool} is not on PATH; the real {tool} apply was not exercised"
        );
        false
    }

    /// Write `files` (relative path, contents) under `root`, creating parents.
    fn write_tree(root: &Path, files: &[(&str, &str)]) {
        for (path, contents) in files {
            let path = root.join(path);
            std::fs::create_dir_all(path.parent().expect("parent")).expect("mkdir");
            std::fs::write(&path, contents).expect("write");
        }
    }

    fn make_executable(path: &Path) {
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o755)).expect("chmod");
    }

    /// A throwaway home plus an archive directory that tests fill with archives and a manifest.
    struct Fixture {
        _root: tempfile::TempDir,
        home: Home,
        archives: PathBuf,
        work: PathBuf,
    }

    impl Fixture {
        fn new() -> Self {
            let root = tempfile::tempdir().expect("tmp");
            let home_dir = root.path().join("home");
            let archives = root.path().join("archives");
            let work = root.path().join("work");
            for dir in [&home_dir, &archives, &work] {
                std::fs::create_dir_all(dir).expect("mkdir");
            }
            Self {
                home: Home {
                    dir: home_dir,
                    user: HOME_USER,
                },
                archives,
                work,
                _root: root,
            }
        }

        /// A fresh source directory to build one archive's tree in.
        fn source(&self, name: &str) -> PathBuf {
            let dir = self.work.join(name);
            std::fs::create_dir_all(&dir).expect("mkdir");
            dir
        }

        /// Pack `source` into `<archives>/<file>` as the launching adapter does.
        fn pack(&self, source: &Path, file: &str) {
            let status = Command::new("tar")
                .arg("-czf")
                .arg(self.archives.join(file))
                .arg("-C")
                .arg(source)
                .arg(".")
                .status()
                .expect("tar available");
            assert!(status.success());
        }

        fn manifest(&self, json: &str) {
            std::fs::write(self.archives.join("manifest.json"), json).expect("manifest");
        }

        fn apply(&self) -> Result<(), BootError> {
            apply_archives_into(&self.archives, &self.home)
        }

        fn home_path(&self, path: &str) -> PathBuf {
            self.home.dir.join(path)
        }

        fn read_home(&self, path: &str) -> String {
            std::fs::read_to_string(self.home_path(path))
                .unwrap_or_else(|e| panic!("read {path} from the home: {e}"))
        }
    }

    /// The owner's dotfiles tree on alpha (2026-09-24), in miniature: a home mirror whose top
    /// level holds dot entries beside plain directories and files.
    const ALPHA_TREE: &[(&str, &str)] = &[
        (".config/nvim/init.lua", "vim.o.number = true\n"),
        (".gitconfig", "[user]\n\tname = owner\n"),
        (".tmux.conf", "set -g mouse on\n"),
        (".zshenv", "export ZDOTDIR=$HOME/.config/zsh\n"),
        ("bin/hello", "#!/bin/sh\necho hello\n"),
        ("Brewfile", "brew \"git\"\n"),
        ("legacy/old.sh", "echo old\n"),
        ("Library/Application Support/app.json", "{}\n"),
    ];

    fn resolve_with_every_tool(dir: &Path) -> Resolution {
        resolve_manager(DotfilesManager::Auto, dir, |_| true)
    }

    #[test]
    fn copy_manager_when_no_tooling_layout() {
        let dir = tempfile::tempdir().expect("tmp");
        std::fs::write(dir.path().join(".bashrc"), b"export X=1\n").expect("write");
        // Plain files, no chezmoi/stow layout -> copy.
        assert_eq!(
            detect_manager(DotfilesManager::Auto, dir.path()).manager,
            ResolvedManager::Copy
        );
    }

    #[test]
    fn explicit_manager_is_respected() {
        let dir = tempfile::tempdir().expect("tmp");
        assert_eq!(
            detect_manager(DotfilesManager::Stow, dir.path()).manager,
            ResolvedManager::Stow
        );
        assert_eq!(
            detect_manager(DotfilesManager::Chezmoi, dir.path()).manager,
            ResolvedManager::Chezmoi
        );
    }

    #[test]
    fn a_mixed_tree_resolves_to_copy_and_names_the_dot_entries() {
        let dir = tempfile::tempdir().expect("tmp");
        write_tree(dir.path(), ALPHA_TREE);
        let resolution = resolve_with_every_tool(dir.path());
        assert_eq!(resolution.manager, ResolvedManager::Copy, "{resolution:?}");
        assert!(
            resolution
                .reason
                .contains(".config, .gitconfig, .tmux.conf, .zshenv"),
            "{resolution:?}"
        );
        assert!(
            resolution.reason.contains("Library, bin, legacy"),
            "{resolution:?}"
        );
    }

    #[test]
    fn a_stow_layout_with_metadata_and_loose_files_resolves_to_stow() {
        let dir = tempfile::tempdir().expect("tmp");
        write_tree(
            dir.path(),
            &[
                ("zsh/.zshrc", "export A=1\n"),
                ("git/.gitconfig", "[core]\n"),
                ("README.md", "# dots\n"),
                ("Brewfile", "brew \"stow\"\n"),
                ("LICENSE", "MIT\n"),
                (".gitignore", "*.swp\n"),
                (".gitattributes", "* text=auto\n"),
                (".github/workflows/ci.yml", "on: push\n"),
                (".stowrc", "--target=~\n"),
            ],
        );
        std::fs::create_dir_all(dir.path().join(".git")).expect("git");
        let resolution = resolve_with_every_tool(dir.path());
        assert_eq!(resolution.manager, ResolvedManager::Stow, "{resolution:?}");
        assert_eq!(resolution.reason, "stow package layout (git, zsh)");
    }

    #[test]
    fn a_stow_layout_without_stow_on_path_resolves_to_copy() {
        let dir = tempfile::tempdir().expect("tmp");
        write_tree(dir.path(), &[("zsh/.zshrc", "export A=1\n")]);
        let resolution = resolve_manager(DotfilesManager::Auto, dir.path(), |_| false);
        assert_eq!(resolution.manager, ResolvedManager::Copy);
        assert!(
            resolution.reason.contains("no stow on PATH"),
            "{resolution:?}"
        );
    }

    #[test]
    fn a_template_deep_inside_a_home_mirror_does_not_select_chezmoi() {
        let dir = tempfile::tempdir().expect("tmp");
        write_tree(
            dir.path(),
            &[
                (".config/app/settings.json.tmpl", "{}\n"),
                (".zshrc", "export A=1\n"),
            ],
        );
        let resolution = resolve_with_every_tool(dir.path());
        assert_eq!(resolution.manager, ResolvedManager::Copy, "{resolution:?}");
    }

    #[test]
    fn a_chezmoi_source_selects_chezmoi_only_with_the_binary() {
        let dir = tempfile::tempdir().expect("tmp");
        write_tree(
            dir.path(),
            &[
                ("dot_zshrc", "export A=1\n"),
                ("dot_config/nvim/init.lua", ""),
            ],
        );
        let with = resolve_with_every_tool(dir.path());
        assert_eq!(with.manager, ResolvedManager::Chezmoi);
        assert_eq!(with.reason, "chezmoi source layout (dot_config, dot_zshrc)");
        // `dot_config/` is a non-dot directory, which used to make this a stow tree.
        let without = resolve_manager(DotfilesManager::Auto, dir.path(), |b| b != "chezmoi");
        assert_eq!(without.manager, ResolvedManager::Copy, "{without:?}");
        assert!(without.reason.contains("no chezmoi on PATH"), "{without:?}");
    }

    #[test]
    fn name_list_counts_what_it_does_not_show() {
        let names: Vec<String> = (1..=7).map(|n| format!("p{n}")).collect();
        assert_eq!(name_list(&names), "p1, p2, p3, p4, p5 +2 more");
        assert_eq!(name_list(&names[..2]), "p1, p2");
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
    fn copy_keeps_symlinks_as_symlinks_even_when_dangling() {
        let src = tempfile::tempdir().expect("src");
        let dst = tempfile::tempdir().expect("dst");
        std::os::unix::fs::symlink("/nonexistent/sealant/target", src.path().join(".dangling"))
            .expect("symlink");
        std::fs::write(src.path().join("real"), b"x").expect("write");
        std::os::unix::fs::symlink("real", src.path().join(".relative")).expect("symlink");

        copy_tree(src.path(), dst.path()).expect("a dangling link does not fail the copy");
        assert_eq!(
            std::fs::read_link(dst.path().join(".dangling")).expect("link"),
            Path::new("/nonexistent/sealant/target")
        );
        assert_eq!(
            std::fs::read_link(dst.path().join(".relative")).expect("link"),
            Path::new("real")
        );
    }

    #[test]
    fn copy_replaces_a_symlink_instead_of_writing_through_it() {
        let src = tempfile::tempdir().expect("src");
        let dst = tempfile::tempdir().expect("dst");
        let elsewhere = tempfile::tempdir().expect("elsewhere");
        let outside = elsewhere.path().join("zshrc");
        std::fs::write(&outside, b"earlier\n").expect("write");
        std::os::unix::fs::symlink(&outside, dst.path().join(".zshrc")).expect("symlink");
        std::fs::write(src.path().join(".zshrc"), b"later\n").expect("write");

        copy_tree(src.path(), dst.path()).expect("copy");
        let written = dst.path().join(".zshrc");
        assert!(!written.symlink_metadata().expect("meta").is_symlink());
        assert_eq!(std::fs::read_to_string(written).expect("read"), "later\n");
        assert_eq!(std::fs::read_to_string(outside).expect("read"), "earlier\n");
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

    // Real applies: archives packed with tar, applied through the manifest into a throwaway home,
    // with the real stow and chezmoi binaries where the test names them.

    #[test]
    fn copy_applies_an_archive_into_the_home_and_the_config_target() {
        let fx = Fixture::new();
        let home_tree = fx.source("home");
        write_tree(
            &home_tree,
            &[
                (".zshrc", "export A=1\n"),
                (".config/git/ignore", "*.swp\n"),
            ],
        );
        std::fs::create_dir_all(home_tree.join(".git")).expect("git");
        std::fs::write(home_tree.join(".git/HEAD"), "ref: refs/heads/main\n").expect("write");
        fx.pack(&home_tree, "0.tar.gz");
        let config_tree = fx.source("config");
        write_tree(&config_tree, &[("nvim/init.lua", "-- lua\n")]);
        fx.pack(&config_tree, "1.tar.gz");
        fx.manifest(
            r#"{"archives":[
                {"file":"0.tar.gz","manager":"copy"},
                {"file":"1.tar.gz","manager":"copy","target":"config"}
            ]}"#,
        );

        fx.apply().expect("apply");
        assert_eq!(fx.read_home(".zshrc"), "export A=1\n");
        assert_eq!(fx.read_home(".config/git/ignore"), "*.swp\n");
        assert_eq!(fx.read_home(".config/nvim/init.lua"), "-- lua\n");
        assert!(!fx.home_path(".git").exists());
    }

    #[test]
    fn a_later_archive_overwrites_an_earlier_one_at_the_same_path() {
        let fx = Fixture::new();
        let first = fx.source("first");
        write_tree(
            &first,
            &[(".zshrc", "from the repository\n"), (".vimrc", "set nu\n")],
        );
        fx.pack(&first, "0.tar.gz");
        let second = fx.source("second");
        write_tree(&second, &[(".zshrc", "from the synced home files\n")]);
        fx.pack(&second, "1.tar.gz");
        fx.manifest(r#"{"archives":[{"file":"0.tar.gz"},{"file":"1.tar.gz"}]}"#);

        fx.apply().expect("apply");
        assert_eq!(fx.read_home(".zshrc"), "from the synced home files\n");
        assert_eq!(fx.read_home(".vimrc"), "set nu\n");
    }

    #[test]
    fn the_alpha_tree_under_auto_lands_every_top_level_dot_entry() {
        let fx = Fixture::new();
        let tree = fx.source("alpha");
        write_tree(&tree, ALPHA_TREE);
        fx.pack(&tree, "0.tar.gz");
        fx.manifest(r#"{"archives":[{"file":"0.tar.gz","manager":"auto"}]}"#);

        fx.apply().expect("apply");
        assert_eq!(
            fx.read_home(".config/nvim/init.lua"),
            "vim.o.number = true\n"
        );
        assert_eq!(fx.read_home(".gitconfig"), "[user]\n\tname = owner\n");
        assert_eq!(fx.read_home(".tmux.conf"), "set -g mouse on\n");
        assert_eq!(
            fx.read_home(".zshenv"),
            "export ZDOTDIR=$HOME/.config/zsh\n"
        );
        // Copied as a mirror: the directories keep their names instead of being stowed flat.
        assert!(fx.home_path("bin/hello").is_file());
        assert!(!fx.home_path("hello").exists());
        assert!(
            fx.home_path("Library/Application Support/app.json")
                .is_file()
        );
    }

    #[test]
    fn explicit_stow_copies_top_level_dot_entries_instead_of_dropping_them() {
        // No package directories, so no stow binary is needed: only the dot-entry handling runs.
        let fx = Fixture::new();
        let tree = fx.source("dots");
        write_tree(
            &tree,
            &[
                (".zshenv", "export A=1\n"),
                (".config/tmux/tmux.conf", "set -g mouse on\n"),
                (".gitignore", "*.swp\n"),
                ("README.md", "# dots\n"),
            ],
        );
        std::fs::create_dir_all(tree.join(".git")).expect("git");
        fx.pack(&tree, "0.tar.gz");
        fx.manifest(r#"{"archives":[{"file":"0.tar.gz","manager":"stow"}]}"#);

        fx.apply().expect("apply");
        assert_eq!(fx.read_home(".zshenv"), "export A=1\n");
        assert_eq!(fx.read_home(".config/tmux/tmux.conf"), "set -g mouse on\n");
        assert!(!fx.home_path(".gitignore").exists());
        assert!(!fx.home_path(".git").exists());
        assert!(!fx.home_path("README.md").exists());
    }

    #[test]
    fn stow_links_packages_and_copies_dot_entries_for_real() {
        if !tool_available("stow") {
            return;
        }
        let fx = Fixture::new();
        let tree = fx.source("stow");
        write_tree(
            &tree,
            &[
                ("zsh/.zshrc", "export FROM_STOW=1\n"),
                ("nvim/.config/nvim/init.lua", "-- stowed\n"),
                ("README.md", "# dots\n"),
                (".gitignore", "*.swp\n"),
            ],
        );
        fx.pack(&tree, "0.tar.gz");
        let mixed = fx.source("mixed");
        write_tree(
            &mixed,
            &[
                (".tmux.conf", "set -g mouse on\n"),
                ("scripts/bin/hello", "echo hi\n"),
            ],
        );
        fx.pack(&mixed, "1.tar.gz");
        fx.manifest(
            r#"{"archives":[
                {"file":"0.tar.gz","manager":"auto"},
                {"file":"1.tar.gz","manager":"stow"}
            ]}"#,
        );

        fx.apply().expect("apply");
        let zshrc = fx.home_path(".zshrc");
        assert!(zshrc.symlink_metadata().expect("meta").is_symlink());
        assert_eq!(fx.read_home(".zshrc"), "export FROM_STOW=1\n");
        assert_eq!(fx.read_home(".config/nvim/init.lua"), "-- stowed\n");
        assert!(!fx.home_path("README.md").exists());
        assert!(!fx.home_path(".gitignore").exists());
        assert_eq!(fx.read_home(".tmux.conf"), "set -g mouse on\n");
        assert_eq!(fx.read_home("bin/hello"), "echo hi\n");
    }

    #[test]
    fn stow_links_a_relative_dangling_symlink_and_refuses_an_absolute_one() {
        if !tool_available("stow") {
            return;
        }
        let fx = Fixture::new();
        let relative = fx.source("relative");
        write_tree(&relative, &[("zsh/.zshrc", "export A=1\n")]);
        std::os::unix::fs::symlink("missing-file", relative.join("zsh/.dangling"))
            .expect("symlink");
        fx.pack(&relative, "0.tar.gz");
        fx.manifest(r#"{"archives":[{"file":"0.tar.gz","manager":"stow"}]}"#);

        fx.apply()
            .expect("a relative dangling link is linked like any other file");
        assert_eq!(fx.read_home(".zshrc"), "export A=1\n");
        let linked = fx.home_path(".dangling");
        assert!(linked.symlink_metadata().expect("linked").is_symlink());
        assert!(!linked.exists(), "the link still dangles");

        // GNU stow (2.3.1 on Ubuntu 24.04, 2.4 on nixpkgs) refuses a package holding an absolute
        // symlink ("source is an absolute symlink"), so the apply, and with it boot, fails
        // instead of linking part of the package.
        let absolute = fx.source("absolute");
        write_tree(&absolute, &[("tmux/.tmux.conf", "set -g mouse on\n")]);
        std::os::unix::fs::symlink("/nonexistent/sealant/target", absolute.join("tmux/.abs"))
            .expect("symlink");
        fx.pack(&absolute, "1.tar.gz");
        fx.manifest(r#"{"archives":[{"file":"1.tar.gz","manager":"stow"}]}"#);
        let err = fx.apply().expect_err("stow refuses the absolute link");
        assert!(format!("{err}").contains("stow exited"), "{err}");
        assert!(!fx.home_path(".tmux.conf").exists());
    }

    #[test]
    fn chezmoi_applies_a_source_tree_for_real_with_home_set() {
        if !tool_available("chezmoi") {
            return;
        }
        let fx = Fixture::new();
        let tree = fx.source("chezmoi");
        write_tree(
            &tree,
            &[
                ("dot_zshrc", "export FROM_CHEZMOI=1\n"),
                ("dot_config/git/ignore", "*.swp\n"),
                (
                    "dot_gitconfig.tmpl",
                    "[core]\n\thome = {{ .chezmoi.homeDir }}\n",
                ),
            ],
        );
        fx.pack(&tree, "0.tar.gz");
        fx.manifest(r#"{"archives":[{"file":"0.tar.gz","manager":"auto"}]}"#);

        fx.apply().expect("apply");
        assert_eq!(fx.read_home(".zshrc"), "export FROM_CHEZMOI=1\n");
        assert_eq!(fx.read_home(".config/git/ignore"), "*.swp\n");
        assert_eq!(
            fx.read_home(".gitconfig"),
            format!("[core]\n\thome = {}\n", fx.home.dir.display())
        );
    }

    #[test]
    fn bootstrap_runs_with_home_and_identity_set_explicitly() {
        let fx = Fixture::new();
        let evidence = fx.work.join("bootstrap-env");
        let tree = fx.source("dots");
        write_tree(
            &tree,
            &[
                (".zshrc", "export A=1\n"),
                (
                    "install.sh",
                    &format!(
                        "#!/bin/sh\nprintf '%s|%s|%s|%s|%s' \"$HOME\" \"$USER\" \"$LOGNAME\" \
                         \"${{XDG_CONFIG_HOME-unset}}\" \"$(pwd)\" > '{}'\n",
                        evidence.display()
                    ),
                ),
            ],
        );
        make_executable(&tree.join("install.sh"));
        fx.pack(&tree, "0.tar.gz");
        fx.manifest(r#"{"archives":[{"file":"0.tar.gz"}]}"#);

        fx.apply().expect("apply");
        let seen = std::fs::read_to_string(&evidence).expect("the bootstrap ran");
        let staging = fx.home.archive_staging_dir().join("0");
        assert_eq!(
            seen,
            format!(
                "{}|root|root|unset|{}",
                fx.home.dir.display(),
                staging.display()
            )
        );
    }

    #[test]
    fn a_failing_bootstrap_aborts_before_later_archives() {
        let fx = Fixture::new();
        let failing = fx.source("failing");
        write_tree(&failing, &[("install.sh", "#!/bin/sh\nexit 3\n")]);
        make_executable(&failing.join("install.sh"));
        fx.pack(&failing, "0.tar.gz");
        let later = fx.source("later");
        write_tree(&later, &[(".later", "x\n")]);
        fx.pack(&later, "1.tar.gz");
        fx.manifest(r#"{"archives":[{"file":"0.tar.gz"},{"file":"1.tar.gz"}]}"#);

        let err = fx.apply().expect_err("a failing bootstrap fails the apply");
        assert!(
            format!("{err}").contains("dotfiles bootstrap exited"),
            "{err}"
        );
        assert!(!fx.home_path(".later").exists());
    }

    #[test]
    fn an_absent_bootstrap_or_a_disabled_one_is_skipped() {
        let fx = Fixture::new();
        let evidence = fx.work.join("ran");
        let plain = fx.source("plain");
        write_tree(&plain, &[(".zshrc", "export A=1\n")]);
        fx.pack(&plain, "0.tar.gz");
        let disabled = fx.source("disabled");
        write_tree(
            &disabled,
            &[(
                "install.sh",
                &format!("#!/bin/sh\ntouch '{}'\n", evidence.display()),
            )],
        );
        make_executable(&disabled.join("install.sh"));
        fx.pack(&disabled, "1.tar.gz");
        fx.manifest(r#"{"archives":[{"file":"0.tar.gz"},{"file":"1.tar.gz","bootstrap":false}]}"#);

        fx.apply().expect("apply");
        assert_eq!(fx.read_home(".zshrc"), "export A=1\n");
        assert!(!evidence.exists());
    }
}
