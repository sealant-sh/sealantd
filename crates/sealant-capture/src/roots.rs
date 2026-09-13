//! The capture roots: which on-disk paths each chunked class carries, as one policy the engine's
//! listings and the materializer's sweep share. Whatever a snap would list is exactly what a
//! materialize may remove when the plan no longer has it; everything else on disk is left alone.

use std::path::{Path, PathBuf};

use crate::gitpack::{GitError, GitRepo};
use crate::index::{self, DAEMON_DIR, Listing, has_component_in};

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
    /// `packed-refs`), `tree/` (git-ignored files and the nested repositories in `gitlinks`),
    /// `harness/` (the harness home minus credential files).
    pub fn workspace_listing(
        &self,
        repo: &GitRepo,
        gitlinks: &[String],
    ) -> Result<Listing, GitError> {
        let mut listing = Listing::default();
        let git_prune = |_: &Path, v: &str, _: &str| {
            v == ".git/objects" || v == ".git/worktrees" || v == ".git/lfs"
        };
        let git_include = |_: &Path, v: &str, _: &str| {
            !(v == ".git/HEAD"
                || v == ".git/packed-refs"
                || v == ".git/commondir"
                || v == ".git/gitdir"
                || v.starts_with(".git/refs/"))
        };
        listing.mount(".git", &repo.git_dir, "", git_prune, git_include);
        if repo.common_dir != repo.git_dir {
            listing.mount(".git", &repo.common_dir, "", git_prune, git_include);
        }

        let bulk = &self.bulk_dirs;
        let root = &self.root;
        let mut tree_roots: Vec<String> = Vec::new();
        let out = repo.run(&[
            "ls-files",
            "-o",
            "-i",
            "--exclude-standard",
            "--directory",
            "-z",
        ])?;
        for rel in String::from_utf8_lossy(&out.stdout).split('\0') {
            if !rel.is_empty() {
                tree_roots.push(rel.to_owned());
            }
        }
        tree_roots.extend(gitlinks.iter().map(|g| format!("{g}/")));
        for rel in tree_roots {
            let is_dir = rel.ends_with('/');
            let rel = rel.trim_end_matches('/');
            let abs = root.join(rel);
            if has_component_in(Path::new(rel), bulk)
                || rel == DAEMON_DIR
                || self.is_daemon_path(&abs)
            {
                continue;
            }
            if is_dir {
                listing.mount(
                    "tree",
                    root,
                    rel,
                    |abs, _, name| bulk.iter().any(|b| b == name) || self.is_daemon_path(abs),
                    |_, _, _| true,
                );
            } else {
                listing.mount_file(&format!("tree/{rel}"), "tree", root, &abs);
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
            base.join(rest)
        })
    }
}
