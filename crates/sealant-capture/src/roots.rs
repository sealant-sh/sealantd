//! The capture roots: which on-disk paths each chunked class carries, as one policy the engine's
//! listings and the materializer's sweep share. Whatever a snap would list is exactly what a
//! materialize may remove when the plan no longer has it; everything else on disk is left alone.

use std::ffi::OsStr;
use std::io;
use std::os::unix::ffi::OsStrExt;
use std::path::{Path, PathBuf};

use crate::gitpack::{GitError, GitRepo};
use crate::index::{self, DAEMON_DIR, Listing, has_component_in, rel_key};
use crate::longpath;
use crate::tree::os_of_key;

/// Where the classes live on disk.
#[derive(Debug, Clone)]
pub struct ClassRoots {
    /// Worktree root.
    pub root: PathBuf,
    /// Harness home (the `harness/` subtree of the workspace class); none when not captured.
    pub harness_home: Option<PathBuf>,
    /// Directory names treated as bulk wherever they appear.
    pub bulk_dirs: Vec<String>,
    /// The staging directory (never listed, never swept).
    pub staging_dir: PathBuf,
}

impl ClassRoots {
    /// The daemon's own paths: staging, `<root>/.sealantd`, the harness home as a whole.
    #[must_use]
    pub fn is_daemon_path(&self, abs: &Path) -> bool {
        abs == self.staging_dir
            || abs == self.root.join(DAEMON_DIR)
            || self.harness_home.as_deref() == Some(abs)
    }

    /// The workspace class listing: `.git/` bookkeeping (minus objects, refs, `HEAD`,
    /// `packed-refs`, other worktrees' admin directories, and git's transient files — but a
    /// symbolic ref or `HEAD` git stores as a symlink is carried as that symlink, beside its
    /// entry in the git section, so a restore stores it as it was), local
    /// git-lfs objects (`.git/lfs/`, which may exist nowhere else), `tree/` (git-ignored files
    /// and the nested repositories in `gitlinks`, [`crate::tree::key_of`] keys of their paths),
    /// `harness/` (the harness home minus credential files).
    pub fn workspace_listing(
        &self,
        repo: &GitRepo,
        gitlinks: &[String],
    ) -> Result<Listing, GitError> {
        let mut listing = Listing::default();
        // Objects and refs travel in the git section; `worktrees/` holds other worktrees'
        // bookkeeping, which is theirs to capture.
        let git_prune = |_: &Path, v: &str, _: &str| v == ".git/objects" || v == ".git/worktrees";
        // A symbolic ref stored as a symlink (`core.preferSymlinkRefs`) is a ref, and the git
        // section holds it (`symrefs`, `head`) — as the same ref to git, written back as text.
        // How the repository stored it is this class's: the symlink itself, its link text
        // and mtime (review 2026-09-28, seventh pass, #1).
        let git_include = |abs: &Path, v: &str, _: &str| {
            if v == ".git/HEAD" || v.starts_with(".git/refs/") {
                return crate::gitpack::symlinked_symref(abs).is_some();
            }
            !(v == ".git/packed-refs" || v == ".git/commondir" || v == ".git/gitdir")
        };
        listing.mount(".git", &repo.git_dir, "", git_prune, git_include);
        if repo.common_dir != repo.git_dir {
            // The common directory's `HEAD` is the main worktree's, not this one's.
            let common_include =
                |abs: &Path, v: &str, name: &str| v != ".git/HEAD" && git_include(abs, v, name);
            listing.mount(".git", &repo.common_dir, "", git_prune, common_include);
        }

        let bulk = &self.bulk_dirs;
        let root = &self.root;
        // Paths as bytes, exactly: a name that is not UTF-8 is still a file to capture.
        let mut tree_roots: Vec<(PathBuf, bool)> = Vec::new();
        let out = repo.run(&[
            "ls-files",
            "-o",
            "-i",
            "--exclude-standard",
            "--directory",
            "-z",
        ])?;
        for rel in out.stdout.split(|b| *b == 0) {
            if !rel.is_empty() {
                let is_dir = rel.ends_with(b"/");
                let rel = rel.strip_suffix(b"/").unwrap_or(rel);
                tree_roots.push((PathBuf::from(OsStr::from_bytes(rel)), is_dir));
            }
        }
        // A directory git could not open may hold ignored files it never saw: what is under it
        // is unknown, not absent.
        for dir in unopened_dirs(&out.stderr, root) {
            let abs = root.join(&dir);
            if has_component_in(&dir, bulk) || self.is_daemon_path(&abs) {
                continue;
            }
            let error = longpath::read_dir(&abs)
                .err()
                .unwrap_or_else(|| io::Error::other("git could not open it"));
            listing.note_unreadable(format!("tree/{}", rel_key(&dir)), abs, &error);
        }
        // Nested repositories, and the paths git cannot reach: a directory, or a file (mounted
        // as one; a directory mount of a file would take nothing).
        // Each is a key of the path's bytes: a name that is not UTF-8 is found under its own
        // name (decoded lossily, it was looked for where nothing is, and carried as nothing).
        tree_roots.extend(gitlinks.iter().map(|g| {
            let rel = PathBuf::from(os_of_key(g));
            let is_dir = longpath::symlink_metadata(&root.join(&rel)).is_ok_and(|m| m.is_dir());
            (rel, is_dir)
        }));
        for (rel, is_dir) in tree_roots {
            let abs = root.join(&rel);
            if has_component_in(&rel, bulk)
                || rel.as_os_str() == DAEMON_DIR
                || self.is_daemon_path(&abs)
            {
                continue;
            }
            if is_dir {
                listing.mount(
                    "tree",
                    root,
                    &rel,
                    |abs, _, name| bulk.iter().any(|b| b == name) || self.is_daemon_path(abs),
                    |_, _, _| true,
                );
            } else {
                listing.mount_file(&format!("tree/{}", rel_key(&rel)), "tree", root, &abs);
            }
        }
        if let Some(home) = &self.harness_home
            && home.is_dir()
        {
            let creds: Vec<PathBuf> = index::CREDENTIAL_FILES
                .iter()
                .map(|c| home.join(c))
                .collect();
            listing.mount(
                "harness",
                home,
                "",
                |_, _, _| false,
                |abs, _, _| !creds.iter().any(|c| c == abs),
            );
        }
        Ok(listing)
    }

    /// The bulk class listing: every bulk directory under the root.
    #[must_use]
    pub fn bulk_listing(&self) -> Listing {
        let mut listing = Listing::default();
        let bulk = &self.bulk_dirs;
        let root = &self.root;
        listing.mount(
            "",
            root,
            "",
            |abs, v, name| v == ".git" || name == DAEMON_DIR || self.is_daemon_path(abs),
            |abs, _, _| {
                abs.strip_prefix(root)
                    .is_ok_and(|rel| has_component_in(rel, bulk))
            },
        );
        listing
    }

    /// Where a workspace-class virtual path lands on disk: `.git/…` in the git dir, `tree/…`
    /// under the root, `harness/…` in the harness home. `None` for an unknown root name or a
    /// harness path without a harness home.
    #[must_use]
    pub fn workspace_path(&self, repo_git_dir: &Path, virtual_path: &str) -> Option<PathBuf> {
        let (head, rest) = virtual_path.split_once('/').unwrap_or((virtual_path, ""));
        let base = match head {
            ".git" => repo_git_dir.to_path_buf(),
            "tree" => self.root.clone(),
            "harness" => self.harness_home.clone()?,
            _ => return None,
        };
        Some(if rest.is_empty() {
            base
        } else {
            base.join(os_of_key(rest))
        })
    }
}

/// The directories `git ls-files` warned it could not open (`warning: could not open directory
/// '<path>/': <reason>`), relative to the worktree. The message may be translated, so every
/// single-quoted path on a stderr line is a candidate, and the filesystem decides: a candidate
/// is kept when it is a directory under `root` that cannot be listed.
fn unopened_dirs(stderr: &[u8], root: &Path) -> Vec<PathBuf> {
    let mut dirs = Vec::new();
    for line in stderr.split(|b| *b == b'\n') {
        for (i, quoted) in line.split(|b| *b == b'\'').enumerate() {
            if i % 2 == 0 {
                continue;
            }
            let path = quoted.strip_suffix(b"/").unwrap_or(quoted);
            if path.is_empty() {
                continue;
            }
            let rel = PathBuf::from(OsStr::from_bytes(path));
            if rel.is_absolute() || dirs.contains(&rel) {
                continue;
            }
            if let Err(error) = longpath::read_dir(&root.join(&rel))
                && !index::is_vanished(&error)
                && longpath::symlink_metadata(&root.join(&rel)).is_ok_and(|m| m.is_dir())
            {
                dirs.push(rel);
            }
        }
    }
    dirs
}
