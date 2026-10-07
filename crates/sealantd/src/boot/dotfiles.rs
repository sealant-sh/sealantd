//! Runtime dotfiles application (E11): clone the dotfiles repo (optionally with an HTTP askpass
//! shim), auto-detect the manager (chezmoi / stow / copy), apply, and optionally run a bootstrap
//! command. Also applies caller-provided dotfiles archives (manifest.json + *.tar.gz staged by
//! the launching adapter) through the same manager dispatch. Runs synchronously before the
//! control socket binds so a failure aborts boot and nothing observes a half-applied home.
//!
//! A person's apply (`dotfiles.apply`, Mend's per-person layout) writes nothing into their home as
//! root: root only unpacks their archives into a directory of its own outside every home, and
//! every read and write inside the home runs as the person ([`Home::as_owner`]).

use std::os::unix::fs::{DirBuilderExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::process::Command;

use sealant_process::CommandGateExt;
use sealant_process::identity::RunAs;
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

/// The only variables of the daemon's environment a person's dotfiles commands get: where to find
/// programs, and the locale and terminal. Everything else comes from their identity.
const PERSON_ENV_KEYS: &[&str] = &["PATH", "LANG", "LC_ALL", "LC_CTYPE", "TZ", "TERM"];

/// `PATH` for a person's dotfiles commands when the daemon has none.
const DEFAULT_PATH: &str = sealant_process::identity::DEFAULT_PATH;

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
pub(crate) struct Home {
    dir: PathBuf,
    user: String,
    /// A person's user (Mend's per-person layout): every command runs as them, and every file
    /// the applier writes itself is theirs. `None`: root, into `/root`.
    run_as: Option<RunAs>,
}

/// What [`apply_tree`] does with a tree's bootstrap command.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum BootstrapMode {
    /// Run it before the next tree is applied, and fail the apply when it fails (boot).
    Inline,
    /// Leave it to the caller, who runs it once every file is applied (`dotfiles.apply`).
    Defer,
}

/// A bootstrap command left to the caller ([`BootstrapMode::Defer`]): run `command` in `dir`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct PendingBootstrap {
    pub(crate) dir: PathBuf,
    pub(crate) command: String,
}

impl Home {
    /// The workspace home: `/root`, as root.
    pub(crate) fn root() -> Self {
        Self {
            dir: PathBuf::from(HOME_DIR),
            user: HOME_USER.to_owned(),
            run_as: None,
        }
    }

    /// A person's home: their passwd home, as their user.
    pub(crate) fn of(run_as: RunAs) -> Self {
        Self {
            dir: run_as.home.clone(),
            user: run_as.name.clone(),
            run_as: Some(run_as),
        }
    }

    /// The home directory.
    pub(crate) fn dir(&self) -> &Path {
        &self.dir
    }

    /// Run `work`, which reads or writes inside this home, as the home's user. For a person it
    /// runs on a thread whose every filesystem access is theirs and nothing of root's
    /// ([`RunAs::as_fs_user`]): a link they planted (`~/.config -> /home/other/.config`) leads
    /// only where they could write themselves, and what it makes is theirs. For root, here.
    fn as_owner<T: Send>(
        &self,
        work: impl FnOnce() -> Result<T, BootError> + Send,
    ) -> Result<T, BootError> {
        match &self.run_as {
            None => work(),
            Some(user) => user.as_fs_user(work).map_err(|e| {
                BootError::Dotfiles(format!("could not act as {} in their home: {e}", user.name))
            })?,
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
        if let Some(user) = &self.run_as {
            // A clean, explicit environment: nothing of the daemon's own (its `SEALANT_*`
            // secrets, the launcher's tokens) reaches a person's clone, chezmoi, stow or script;
            // then the person's whole identity: groups, umask, the private TMPDIR and
            // XDG_RUNTIME_DIR, their SHELL ([`sealant_process::identity`]).
            command.env_clear();
            for key in PERSON_ENV_KEYS {
                if let Ok(value) = std::env::var(key) {
                    command.env(key, value);
                }
            }
            let base_path = std::env::var("PATH").unwrap_or_else(|_| DEFAULT_PATH.to_owned());
            command.env("PATH", &base_path);
            // The image's person environment, then the identity.
            command.envs(sealant_process::identity::person_env(Some(&base_path)));
            command.envs(user.env());
            user.apply(command);
            // Started in their home, not in the daemon's directory, which they may not be able
            // to enter (stow then stops: "Your current directory ... seems to have vanished").
            // A command that needs another directory sets it after this.
            command.current_dir(&self.dir);
        }
        command
            .env("HOME", &self.dir)
            .env("USER", &self.user)
            .env("LOGNAME", &self.user);
        for key in XDG_BASE_DIRS {
            command.env_remove(key);
        }
        command
    }
}

/// Clone the dotfiles repository and apply it into `home`, as its user. With
/// [`BootstrapMode::Defer`] the bootstrap is answered instead of run. `runtime_dir` holds the
/// askpass shim for a root home; a person's goes in their private `TMPDIR`, the only place their
/// user can run it from.
pub(crate) fn apply_repository(
    config: &DotfilesConfig,
    runtime_dir: &Path,
    home: &Home,
    mode: BootstrapMode,
) -> Result<Option<PendingBootstrap>, BootError> {
    let checkout = home.checkout_dir();
    home.as_owner(|| {
        if let Some(parent) = checkout.parent() {
            mkdir_all(parent)?;
        }
        remove_tree(&checkout)
    })?;

    let askpass_dir = match &home.run_as {
        Some(user) => {
            user.prepare_dirs()
                .map_err(|e| BootError::io_path("mkdir", &user.tmpdir(), e))?;
            user.tmpdir()
        }
        None => runtime_dir.to_path_buf(),
    };
    let askpass = home.as_owner(|| materialize_askpass(config, &askpass_dir))?;
    let clone_result = clone_dotfiles(config, &checkout, askpass.as_deref(), home);
    if let Some(path) = &askpass {
        let _ = home.as_owner(|| {
            let _ = std::fs::remove_file(path);
            Ok(())
        });
    }
    clone_result?;

    apply_tree(
        &checkout,
        config.manager,
        config.target,
        config.bootstrap,
        &config.bootstrap_command,
        home,
        mode,
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
    mode: BootstrapMode,
) -> Result<Option<PendingBootstrap>, BootError> {
    let resolution = home.as_owner(|| Ok(detect_manager(manager, checkout)))?;
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
        ResolvedManager::Copy => home.as_owner(|| {
            mkdir_all(&target_dir)?;
            copy_tree(checkout, &target_dir)
        })?,
    }

    if !bootstrap {
        return Ok(None);
    }
    match mode {
        BootstrapMode::Inline => {
            run_bootstrap(checkout, bootstrap_command, home)?;
            Ok(None)
        }
        BootstrapMode::Defer => {
            home.as_owner(|| Ok(pending_bootstrap(checkout, bootstrap_command)))
        }
    }
}

/// `mkdir -p path`.
fn mkdir_all(path: &Path) -> Result<(), BootError> {
    std::fs::create_dir_all(path).map_err(|e| BootError::io_path("mkdir -p", path, e))
}

/// `rm -rf path`: a directory and what is in it, or the link or file standing there (std's
/// `remove_dir_all` never follows a link out of the tree).
fn remove_tree(path: &Path) -> Result<(), BootError> {
    let removed = match std::fs::symlink_metadata(path) {
        Ok(meta) if meta.is_dir() => std::fs::remove_dir_all(path),
        Ok(_) => std::fs::remove_file(path),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(e) => Err(e),
    };
    removed.map_err(|e| BootError::io_path("rm -rf", path, e))
}

/// The bootstrap `command` of the tree at `checkout`, when the script it names is there.
fn pending_bootstrap(checkout: &Path, command: &str) -> Option<PendingBootstrap> {
    if checkout.join(command.trim_start_matches("./")).exists() {
        Some(PendingBootstrap {
            dir: checkout.to_path_buf(),
            command: command.to_owned(),
        })
    } else {
        tracing::info!(command, "dotfiles bootstrap command absent; skipping");
        None
    }
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

/// Where a person's archives are unpacked, as root, before they reach the person's home: under
/// the daemon's own runtime directory, outside every home and every capture root, root's only
/// (0700). Each apply takes a directory of its own inside it and removes it when done.
pub(crate) const ARCHIVE_STAGING_ROOT: &str = "/run/sealant/dotfiles-staging";

/// Apply the archives in `dir` into `home`, in manifest order; with [`BootstrapMode::Defer`]
/// every bootstrap is answered, in that order, instead of run.
pub(crate) fn apply_archives_into(
    dir: &Path,
    home: &Home,
    mode: BootstrapMode,
) -> Result<Vec<PendingBootstrap>, BootError> {
    apply_archives_staged_in(dir, home, mode, Path::new(ARCHIVE_STAGING_ROOT))
}

/// [`apply_archives_into`], a person's archives unpacked under `staging_root`.
///
/// Root's home (boot): each archive is extracted straight into its tree in the home, as root.
/// A person's: each is unpacked as root into a directory of root's own outside the home
/// ([`unpack_checked`], which refuses an entry that could reach outside it), and the person
/// writes the tree into their home from there ([`mirror_into_home`]); everything after that
/// (the manager, the copies, the bootstrap) reads and writes as the person.
fn apply_archives_staged_in(
    dir: &Path,
    home: &Home,
    mode: BootstrapMode,
    staging_root: &Path,
) -> Result<Vec<PendingBootstrap>, BootError> {
    let mut pending = Vec::new();
    let manifest_path = dir.join("manifest.json");
    let raw = std::fs::read_to_string(&manifest_path)
        .map_err(|e| BootError::io_path("read", &manifest_path, e))?;
    let manifest: ArchiveManifest = serde_json::from_str(&raw)
        .map_err(|e| BootError::Dotfiles(format!("invalid dotfiles archive manifest: {e}")))?;
    let staging = match &home.run_as {
        Some(_) if !manifest.archives.is_empty() => Some(RootStaging::create(staging_root)?),
        _ => None,
    };

    for (index, entry) in manifest.archives.iter().enumerate() {
        if entry.file.contains('/') || entry.file.contains("..") {
            return Err(BootError::Dotfiles(format!(
                "dotfiles archive file name {:?} must be a plain basename",
                entry.file
            )));
        }
        let archive = dir.join(&entry.file);
        let tree = home.archive_staging_dir().join(index.to_string());
        match &staging {
            None => {
                if tree.exists() {
                    std::fs::remove_dir_all(&tree)
                        .map_err(|e| BootError::io_path("rm -rf", &tree, e))?;
                }
                if let Some(parent) = tree.parent() {
                    mkdir_all(parent)?;
                }
                mkdir_all(&tree)?;
                extract_archive(&archive, &tree)?;
            }
            Some(staging) => {
                let unpacked = staging.dir.join(index.to_string());
                unpack_checked(&archive, &unpacked)?;
                mirror_into_home(&unpacked, &tree, home)?;
                // Root's own directory: nothing of the person's is in it.
                std::fs::remove_dir_all(&unpacked)
                    .map_err(|e| BootError::io_path("rm -rf", &unpacked, e))?;
            }
        }
        pending.extend(apply_tree(
            &tree,
            entry.manager.unwrap_or(DotfilesManager::Auto),
            entry.target.unwrap_or(DotfilesTarget::Home),
            entry.bootstrap,
            entry
                .bootstrap_command
                .as_deref()
                .unwrap_or(DEFAULT_DOTFILES_BOOTSTRAP_COMMAND),
            home,
            mode,
        )?);
    }
    Ok(pending)
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

/// One apply's directory under [`ARCHIVE_STAGING_ROOT`]: root's, 0700, and removed when dropped,
/// the apply failed or not.
#[derive(Debug)]
struct RootStaging {
    dir: PathBuf,
}

impl RootStaging {
    /// Make `root` the daemon's own private directory (a link or file planted there is replaced,
    /// a directory someone else made is removed), remove what a previous daemon left in it, and
    /// make this apply's directory inside.
    fn create(root: &Path) -> Result<Self, BootError> {
        static NEXT: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
        if let Some(parent) = root.parent() {
            mkdir_all(parent)?;
        }
        sealant_process::identity::private_dir(
            root,
            nix::unistd::geteuid().as_raw(),
            nix::unistd::getegid().as_raw(),
        )
        .map_err(|e| BootError::io_path("make private directory", root, e))?;
        let pid = std::process::id();
        let ours = format!("{pid}-");
        let entries =
            std::fs::read_dir(root).map_err(|e| BootError::io_path("read_dir", root, e))?;
        for entry in entries.flatten() {
            if !entry.file_name().to_string_lossy().starts_with(&ours) {
                let _ = remove_tree(&entry.path());
            }
        }
        let n = NEXT.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let dir = root.join(format!("{ours}{n}"));
        // A daemon that is PID 1 again after a restart may meet its own leftover of this name.
        remove_tree(&dir)?;
        std::fs::DirBuilder::new()
            .mode(0o700)
            .create(&dir)
            .map_err(|e| BootError::io_path("mkdir", &dir, e))?;
        Ok(Self { dir })
    }
}

impl Drop for RootStaging {
    fn drop(&mut self) {
        if let Err(e) = std::fs::remove_dir_all(&self.dir) {
            tracing::warn!(dir = %self.dir.display(), error = %e, "dotfiles staging not removed");
        }
    }
}

/// Unpack `archive` as root into `into` (made here, 0700, inside root's own staging
/// directory), refusing an archive that could reach outside it.
///
/// Before anything is written, every entry must be a file, a directory or a link, with a
/// relative path free of `..`, that does not lie under a link the archive makes (where `tar`
/// would write through it). `tar` then extracts without owners (`--no-same-owner`), and what it
/// made is checked again: nothing but files, directories and links, and no file with a link
/// outside the tree.
fn unpack_checked(archive: &Path, into: &Path) -> Result<(), BootError> {
    let refuse =
        |why: String| BootError::Dotfiles(format!("dotfiles archive {}: {why}", archive.display()));
    let meta =
        std::fs::symlink_metadata(archive).map_err(|e| BootError::io_path("stat", archive, e))?;
    if !meta.is_file() {
        return Err(refuse("not a regular file".to_owned()));
    }
    // The two listings at once: each is a `tar` and a gunzip of the whole archive.
    let (names, kinds) = std::thread::scope(|scope| {
        let kinds = scope.spawn(|| list_archive(archive, true));
        let names = list_archive(archive, false);
        let kinds = kinds
            .join()
            .unwrap_or_else(|panic| std::panic::resume_unwind(panic));
        (names, kinds)
    });
    check_members(&names?, &kinds?).map_err(refuse)?;
    std::fs::DirBuilder::new()
        .mode(0o700)
        .create(into)
        .map_err(|e| BootError::io_path("mkdir", into, e))?;
    run_checked(
        Command::new("tar")
            .arg("--no-same-owner")
            .arg("-xzf")
            .arg(archive)
            .arg("-C")
            .arg(into),
        "tar -xzf",
    )?;
    check_unpacked(into).map_err(refuse)
}

/// `tar -tzf archive`, one member per line (`tar` escapes a newline in a name); with `verbose`,
/// `tar -tvzf`, whose lines start with the member's type.
fn list_archive(archive: &Path, verbose: bool) -> Result<String, BootError> {
    let output = Command::new("tar")
        .arg(if verbose { "-tvzf" } else { "-tzf" })
        .arg(archive)
        .env("LC_ALL", "C")
        .stdin(std::process::Stdio::null())
        .output_gated()
        .map_err(|e| BootError::Dotfiles(format!("tar -tzf: could not spawn: {e}")))?;
    if !output.status.success() {
        return Err(BootError::Dotfiles(format!(
            "tar -tzf {} exited with {}: {}",
            archive.display(),
            output.status,
            String::from_utf8_lossy(&output.stderr).trim()
        )));
    }
    Ok(String::from_utf8_lossy(&output.stdout).into_owned())
}

/// A member's path as a key: its components, without `.` and empty ones.
fn member_key(name: &str) -> String {
    name.split('/')
        .filter(|c| !c.is_empty() && *c != ".")
        .collect::<Vec<_>>()
        .join("/")
}

/// The member listing's verdict: `Err` names the first entry refused, and why. `names` is
/// `tar -t`'s listing and `kinds` `tar -tv`'s, line for line.
fn check_members(names: &str, kinds: &str) -> Result<(), String> {
    let names: Vec<&str> = names.lines().collect();
    let kinds: Vec<char> = kinds
        .lines()
        .map(|l| l.chars().next().unwrap_or('?'))
        .collect();
    if names.len() != kinds.len() {
        return Err(format!(
            "its listings disagree ({} names, {} entries)",
            names.len(),
            kinds.len()
        ));
    }
    let mut links = std::collections::HashSet::new();
    let mut seen: std::collections::HashMap<String, usize> = std::collections::HashMap::new();
    for (name, kind) in names.iter().zip(&kinds) {
        *seen.entry(member_key(name)).or_default() += 1;
        if name.starts_with('/') {
            return Err(format!("entry {name:?} has an absolute path"));
        }
        if name.split('/').any(|c| c == "..") {
            return Err(format!("entry {name:?} has a `..` in its path"));
        }
        match kind {
            '-' | 'd' => {}
            'l' | 'h' => {
                links.insert(member_key(name));
            }
            other => {
                return Err(format!(
                    "entry {name:?} is of type {other:?}: only files, directories and links are \
                     applied"
                ));
            }
        }
    }
    for name in &names {
        let key = member_key(name);
        // A second entry of a link's name (a directory over it) would have `tar` reach through it.
        if links.contains(&key) && seen.get(&key).is_some_and(|count| *count > 1) {
            return Err(format!(
                "entry {name:?} is a link's name and appears more than once"
            ));
        }
        let mut prefix = String::new();
        for component in key.split('/') {
            if !prefix.is_empty() && links.contains(&prefix) {
                return Err(format!("entry {name:?} lies under the link {prefix:?}"));
            }
            if !prefix.is_empty() {
                prefix.push('/');
            }
            prefix.push_str(component);
        }
    }
    Ok(())
}

/// What `tar` made under `dir`: nothing but files, directories and symlinks, and no file with a
/// hard link outside `dir`.
fn check_unpacked(dir: &Path) -> Result<(), String> {
    use std::os::unix::fs::MetadataExt;
    let mut linked: std::collections::HashMap<(u64, u64), (u64, u64, PathBuf)> =
        std::collections::HashMap::new();
    for entry in walkdir::WalkDir::new(dir) {
        let entry = entry.map_err(|e| format!("walking what it unpacked: {e}"))?;
        let kind = entry.file_type();
        if kind.is_dir() || kind.is_symlink() {
            continue;
        }
        let path = entry.path();
        if !kind.is_file() {
            return Err(format!(
                "{} is not a file, a directory or a link",
                path.display()
            ));
        }
        let meta = entry
            .metadata()
            .map_err(|e| format!("stat {}: {e}", path.display()))?;
        if meta.nlink() > 1 {
            let seen = linked.entry((meta.dev(), meta.ino())).or_insert((
                meta.nlink(),
                0,
                path.to_path_buf(),
            ));
            seen.1 += 1;
        }
    }
    match linked.values().find(|(nlink, seen, _)| seen < nlink) {
        Some((_, _, path)) => Err(format!(
            "{} has a hard link outside the archive",
            path.display()
        )),
        None => Ok(()),
    }
}

/// One entry of an unpacked tree, as root reads it for the person to write.
#[derive(Debug)]
enum Staged {
    /// A directory (the tree itself when `rel` is empty) and its mode.
    Dir { rel: PathBuf, mode: u32 },
    /// A file, opened by root, its mode and its modification time.
    File {
        rel: PathBuf,
        file: std::fs::File,
        mode: u32,
        modified: Option<std::time::SystemTime>,
    },
    /// A symlink and its target, never followed.
    Link { rel: PathBuf, target: PathBuf },
}

/// Write the tree unpacked at `unpacked` (root's) to `tree` in `home`, as the home's user: root
/// reads, on a thread of its own, and hands each entry over (a file as the file it opened); the
/// user removes what was at `tree` and writes every entry there. The tree is the same as `tar`
/// made, with the user as owner: its files keep their bytes, mode (without set-id bits) and
/// modification time, its directories their mode, its links their target.
fn mirror_into_home(unpacked: &Path, tree: &Path, home: &Home) -> Result<(), BootError> {
    let (send, receive) = std::sync::mpsc::sync_channel::<Result<Staged, BootError>>(64);
    std::thread::scope(|scope| {
        scope.spawn(move || read_staged(unpacked, &send));
        home.as_owner(move || write_staged(tree, &receive))
    })
}

/// Send every entry under `unpacked`, the directory itself first, a directory before what is in
/// it; stop at the first error (sent) or once the writer has stopped listening.
fn read_staged(unpacked: &Path, send: &std::sync::mpsc::SyncSender<Result<Staged, BootError>>) {
    use std::os::unix::fs::OpenOptionsExt;
    let walk = walkdir::WalkDir::new(unpacked).sort_by_file_name();
    for entry in walk {
        let staged = entry
            .map_err(|e| BootError::Dotfiles(format!("walking {}: {e}", unpacked.display())))
            .and_then(|entry| {
                let path = entry.path();
                let rel = path.strip_prefix(unpacked).unwrap_or(path).to_path_buf();
                let kind = entry.file_type();
                if kind.is_symlink() {
                    let target = std::fs::read_link(path)
                        .map_err(|e| BootError::io_path("readlink", path, e))?;
                    return Ok(Staged::Link { rel, target });
                }
                let meta = entry
                    .metadata()
                    .map_err(|e| BootError::Dotfiles(format!("stat {}: {e}", path.display())))?;
                if kind.is_dir() {
                    return Ok(Staged::Dir {
                        rel,
                        mode: meta.permissions().mode() & 0o7777,
                    });
                }
                let file = std::fs::OpenOptions::new()
                    .read(true)
                    .custom_flags(nix::libc::O_NOFOLLOW)
                    .open(path)
                    .map_err(|e| BootError::io_path("open", path, e))?;
                Ok(Staged::File {
                    rel,
                    file,
                    mode: meta.permissions().mode() & 0o777,
                    modified: meta.modified().ok(),
                })
            });
        let failed = staged.is_err();
        if send.send(staged).is_err() || failed {
            return;
        }
    }
}

/// As the home's user: replace whatever is at `tree` with the entries received.
fn write_staged(
    tree: &Path,
    receive: &std::sync::mpsc::Receiver<Result<Staged, BootError>>,
) -> Result<(), BootError> {
    use std::os::unix::fs::OpenOptionsExt;
    remove_tree(tree)?;
    if let Some(parent) = tree.parent() {
        mkdir_all(parent)?;
    }
    // Modes go on the directories last, deepest first: one without write permission would
    // refuse what goes in it.
    let mut dirs = Vec::new();
    for staged in receive {
        match staged? {
            Staged::Dir { rel, mode } => {
                let path = tree.join(rel);
                std::fs::create_dir(&path).map_err(|e| BootError::io_path("mkdir", &path, e))?;
                dirs.push((path, mode));
            }
            Staged::Link { rel, target } => {
                let path = tree.join(rel);
                std::os::unix::fs::symlink(&target, &path)
                    .map_err(|e| BootError::io_path("symlink", &path, e))?;
            }
            Staged::File {
                rel,
                mut file,
                mode,
                modified,
            } => {
                let path = tree.join(rel);
                let mut out = std::fs::OpenOptions::new()
                    .write(true)
                    .create_new(true)
                    .mode(0o600)
                    .open(&path)
                    .map_err(|e| BootError::io_path("create", &path, e))?;
                std::io::copy(&mut file, &mut out)
                    .map_err(|e| BootError::io_path("write", &path, e))?;
                out.set_permissions(std::fs::Permissions::from_mode(mode))
                    .map_err(|e| BootError::io_path("chmod", &path, e))?;
                if let Some(modified) = modified {
                    let _ = out.set_modified(modified);
                }
            }
        }
    }
    for (path, mode) in dirs.iter().rev() {
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(*mode))
            .map_err(|e| BootError::io_path("chmod", path, e))?;
    }
    Ok(())
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
    let top = home.as_owner(|| {
        mkdir_all(target_dir)?;
        let top =
            TopLevel::scan(checkout).map_err(|e| BootError::io_path("read_dir", checkout, e))?;
        if !top.home_entries.is_empty() {
            tracing::info!(
                entries = %name_list(&top.home_entries),
                "stow: top-level dot entries are not packages; copying them into the target"
            );
            for name in &top.home_entries {
                copy_entry(&checkout.join(name), &target_dir.join(name))?;
            }
        }
        Ok(top)
    })?;
    if !top.loose_files.is_empty() {
        tracing::info!(
            files = %name_list(&top.loose_files),
            "stow: top-level files are not packages; not applied"
        );
    }
    // `--no-folding`: without it stow links a whole directory the home does not have yet
    // (`~/.config` → the per-boot staging tree), so anything written there later lands in
    // staging, and a later archive or the next boot's apply can remove it.
    for package in &top.packages {
        let mut command = Command::new("stow");
        home.identify(&mut command)
            .arg("--no-folding")
            .arg("-d")
            .arg(checkout)
            .arg("-t")
            .arg(target_dir)
            .arg(package);
        run_checked(&mut command, "stow")?;
    }
    Ok(())
}

/// Recursively copy the dotfiles tree into the target, skipping the `.git` directory. A
/// person's copy runs as them ([`Home::as_owner`]), so everything it writes is theirs.
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
/// earlier archive's staging tree receives the later archive's files there. For a person that
/// is only a directory they can write themselves: a link of theirs into another person's home
/// fails here, naming it.
fn copy_entry(from: &Path, to: &Path) -> Result<(), BootError> {
    let file_type = std::fs::symlink_metadata(from)
        .map_err(|e| BootError::io_path("stat", from, e))?
        .file_type();
    if file_type.is_dir() {
        match std::fs::metadata(to) {
            Ok(meta) if meta.is_dir() => {}
            Err(e) if e.kind() != std::io::ErrorKind::NotFound => {
                return Err(BootError::io_path("reach directory", to, e));
            }
            _ => std::fs::create_dir_all(to).map_err(|e| BootError::io_path("mkdir -p", to, e))?,
        }
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
    if !home.as_owner(|| Ok(bootstrap_path.exists()))? {
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
                    user: HOME_USER.to_owned(),
                    run_as: None,
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
            apply_archives_into(&self.archives, &self.home, BootstrapMode::Inline).map(|_| ())
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
        let err = apply_archives_into(dir.path(), &Home::root(), BootstrapMode::Inline)
            .expect_err("traversal must be rejected");
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

    /// `tar` run in `dir` with `args`, which must succeed.
    fn tar_in(dir: &Path, args: &[&str]) {
        let status = Command::new("tar")
            .args(args)
            .current_dir(dir)
            .status()
            .expect("tar available");
        assert!(status.success(), "tar {args:?}");
    }

    #[test]
    fn the_member_listing_refuses_what_could_reach_outside_the_tree() {
        let ok = "./\n./.zshrc\n./.config/\n./.config/nvim/init.lua\n./.vim\n./b\n";
        let kinds = "d\n-\nd\n-\nl\nh\n";
        assert_eq!(check_members(ok, kinds), Ok(()));
        for (names, kinds, why) in [
            ("/etc/profile\n", "-\n", "absolute path"),
            ("./../.zshrc\n", "-\n", "`..`"),
            ("a/../../x\n", "-\n", "`..`"),
            (
                "./.config\n./.config/fish/config.fish\n",
                "l\n-\n",
                "under the link \".config\"",
            ),
            ("x\nx/y\n", "h\n-\n", "under the link \"x\""),
            ("./x\nx\n", "l\nl\n", "more than once"),
            ("./x\n./x/\n", "l\nd\n", "more than once"),
            ("./x/\n./x\n", "d\nl\n", "more than once"),
            ("./dev\n", "c\n", "type 'c'"),
            ("./fifo\n", "p\n", "type 'p'"),
            ("./a\n./b\n", "-\n", "listings disagree"),
        ] {
            let err = check_members(names, kinds).expect_err(names);
            assert!(err.contains(why), "{names:?}: {err}");
        }
    }

    /// A tree of the usual kinds, packed as the launching adapter packs one.
    fn pack_ordinary(work: &Path) -> PathBuf {
        let src = work.join("src");
        write_tree(
            &src,
            &[
                (".zshrc", "export A=1\n"),
                (".config/nvim/init.lua", "-- lua\n"),
                ("bin/hello", "#!/bin/sh\necho hi\n"),
            ],
        );
        make_executable(&src.join("bin/hello"));
        std::fs::set_permissions(src.join(".zshrc"), std::fs::Permissions::from_mode(0o600))
            .expect("chmod");
        std::fs::set_permissions(src.join("bin"), std::fs::Permissions::from_mode(0o750))
            .expect("chmod");
        std::os::unix::fs::symlink("/nonexistent/abs", src.join(".abs")).expect("symlink");
        std::os::unix::fs::symlink(".zshrc", src.join(".rel")).expect("symlink");
        let archive = work.join("0.tar.gz");
        tar_in(
            work,
            &[
                "-czf",
                &archive.to_string_lossy(),
                "-C",
                &src.to_string_lossy(),
                ".",
            ],
        );
        archive
    }

    #[test]
    fn an_ordinary_archive_unpacks_and_mirrors_with_its_modes_and_links() {
        let work = tempfile::tempdir().expect("tmp");
        let archive = pack_ordinary(work.path());
        let unpacked = work.path().join("unpacked");
        unpack_checked(&archive, &unpacked).expect("unpack");

        let fx = Fixture::new();
        let tree = fx.home.archive_staging_dir().join("0");
        // Whatever stood at the tree is replaced, a link there removed rather than followed.
        let elsewhere = work.path().join("elsewhere");
        std::fs::create_dir_all(&elsewhere).expect("mkdir");
        std::fs::create_dir_all(tree.parent().expect("parent")).expect("mkdir");
        std::os::unix::fs::symlink(&elsewhere, &tree).expect("symlink");
        mirror_into_home(&unpacked, &tree, &fx.home).expect("mirror");

        assert!(
            std::fs::read_dir(&elsewhere)
                .expect("read")
                .next()
                .is_none()
        );
        let mode = |p: &str| {
            std::fs::symlink_metadata(tree.join(p))
                .expect("stat")
                .permissions()
                .mode()
                & 0o7777
        };
        assert_eq!(mode(".zshrc"), 0o600);
        assert_eq!(mode("bin/hello"), 0o755);
        assert_eq!(mode("bin"), 0o750);
        assert_eq!(
            std::fs::read_to_string(tree.join(".config/nvim/init.lua")).expect("read"),
            "-- lua\n"
        );
        assert_eq!(
            std::fs::read_link(tree.join(".abs")).expect("link"),
            Path::new("/nonexistent/abs")
        );
        assert_eq!(
            std::fs::read_link(tree.join(".rel")).expect("link"),
            Path::new(".zshrc")
        );
        let modified = |root: &Path| {
            std::fs::metadata(root.join(".config/nvim/init.lua"))
                .expect("stat")
                .modified()
                .expect("mtime")
        };
        assert_eq!(modified(&tree), modified(&unpacked));
    }

    #[test]
    fn absolute_and_dotdot_entries_are_refused_before_anything_is_written() {
        let work = tempfile::tempdir().expect("tmp");
        let outside = work.path().join("outside");
        std::fs::write(&outside, "planted\n").expect("write");
        let inner = work.path().join("a/b");
        std::fs::create_dir_all(&inner).expect("mkdir");
        // `-P` keeps the leading `/` and the `..` that tar would otherwise strip.
        let absolute = work.path().join("absolute.tar.gz");
        tar_in(
            work.path(),
            &[
                "-czPf",
                &absolute.to_string_lossy(),
                &outside.to_string_lossy(),
            ],
        );
        let dotdot = work.path().join("dotdot.tar.gz");
        tar_in(
            &inner,
            &["-czPf", &dotdot.to_string_lossy(), "../../outside"],
        );
        for (archive, why) in [(absolute, "absolute path"), (dotdot, "`..`")] {
            let into = work.path().join("into");
            let err = unpack_checked(&archive, &into).expect_err("refused");
            assert!(format!("{err}").contains(why), "{err}");
            assert!(!into.exists(), "nothing was unpacked");
        }
        assert_eq!(
            std::fs::read_to_string(&outside).expect("read"),
            "planted\n"
        );
    }

    #[test]
    fn an_entry_under_a_link_and_a_special_file_are_refused() {
        let work = tempfile::tempdir().expect("tmp");
        let victim = work.path().join("victim");
        std::fs::create_dir_all(&victim).expect("mkdir");
        // A link to the victim directory, then a file appended under the link's name.
        let first = work.path().join("first");
        std::fs::create_dir_all(&first).expect("mkdir");
        std::os::unix::fs::symlink(&victim, first.join("dir")).expect("symlink");
        let second = work.path().join("second");
        write_tree(&second, &[("dir/planted", "x\n")]);
        let plain = work.path().join("through.tar");
        tar_in(&first, &["-cf", &plain.to_string_lossy(), "dir"]);
        tar_in(&second, &["-rf", &plain.to_string_lossy(), "dir/planted"]);
        let through = work.path().join("through.tar.gz");
        let gz = std::fs::File::create(&through).expect("create");
        let status = Command::new("gzip")
            .arg("-c")
            .arg(&plain)
            .stdout(gz)
            .status()
            .expect("gzip");
        assert!(status.success());
        let err = unpack_checked(&through, &work.path().join("into1")).expect_err("refused");
        assert!(format!("{err}").contains("under the link \"dir\""), "{err}");
        assert!(!victim.join("planted").exists());

        let fifo_src = work.path().join("fifo");
        std::fs::create_dir_all(&fifo_src).expect("mkdir");
        let status = Command::new("mkfifo")
            .arg(fifo_src.join("pipe"))
            .status()
            .expect("mkfifo");
        assert!(status.success());
        let fifo = work.path().join("fifo.tar.gz");
        tar_in(
            work.path(),
            &[
                "-czf",
                &fifo.to_string_lossy(),
                "-C",
                &fifo_src.to_string_lossy(),
                ".",
            ],
        );
        let err = unpack_checked(&fifo, &work.path().join("into2")).expect_err("refused");
        assert!(format!("{err}").contains("type 'p'"), "{err}");
    }

    #[test]
    fn an_unpacked_file_with_a_hard_link_outside_the_tree_is_refused() {
        let work = tempfile::tempdir().expect("tmp");
        let tree = work.path().join("tree");
        std::fs::create_dir_all(&tree).expect("mkdir");
        std::fs::write(work.path().join("secret"), "s\n").expect("write");
        std::fs::hard_link(work.path().join("secret"), tree.join("copy")).expect("link");
        let err = check_unpacked(&tree).expect_err("refused");
        assert!(err.contains("hard link outside"), "{err}");
        std::fs::hard_link(tree.join("copy"), tree.join("again")).expect("link");
        std::fs::remove_file(work.path().join("secret")).expect("rm");
        assert_eq!(check_unpacked(&tree), Ok(()), "two links, both inside");
    }

    #[test]
    fn a_person_s_staging_directory_is_root_s_own_and_removed_when_done() {
        let work = tempfile::tempdir().expect("tmp");
        let root = work.path().join("run/dotfiles-staging");
        // A previous daemon's leftover goes; a link planted at the root is replaced.
        std::fs::create_dir_all(root.parent().expect("parent")).expect("mkdir");
        std::os::unix::fs::symlink(work.path(), &root).expect("symlink");
        let staging = RootStaging::create(&root).expect("staging");
        let meta = std::fs::symlink_metadata(&root).expect("stat");
        assert!(meta.is_dir() && meta.permissions().mode() & 0o7777 == 0o700);
        let dir = staging.dir.clone();
        assert_eq!(
            std::fs::metadata(&dir).expect("stat").permissions().mode() & 0o7777,
            0o700
        );
        std::fs::create_dir_all(root.join("1-0/x")).expect("leftover");
        drop(staging);
        assert!(!dir.exists());
        let again = RootStaging::create(&root).expect("staging");
        assert!(!root.join("1-0").exists() || std::process::id() == 1);
        drop(again);
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
        // Linked file by file, never by folding a directory into the staging tree.
        for dir in [".config", ".config/nvim"] {
            let meta = fx.home_path(dir).symlink_metadata().expect("meta");
            assert!(
                meta.is_dir() && !meta.is_symlink(),
                "{dir} was folded into a link"
            );
        }
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
