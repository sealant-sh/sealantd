//! Git class: the closure of refs, `HEAD`, index, stash and reflog tips read first, packed with
//! `git pack-objects --revs` against the previous capture's tips as negatives (never `--thin`),
//! indexed with `git index-pack`, checked with `git fsck --connectivity-only`; bounded retries
//! when refs move or an object goes missing mid-pack (ADR-0015 *Snap rules*). Also the
//! materialize-side helpers: install a pack, write `packed-refs` and `HEAD`, check out a tree.

use std::collections::BTreeMap;
use std::fs::{self, File};
use std::io::{self, Write};
use std::os::unix::ffi::OsStrExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};

use sealant_process::CommandGateExt;

use crate::chunk::sha256_hex;
use crate::longpath;
use crate::manifest::{FsckStatus, INDEX_TREE_REF, PSEUDO_REF_PREFIX, WORKTREE_TREE_REF};
use crate::tree::{bytes_of, key_of};

/// Bounded attempts when refs move or objects vanish between the read and the pack.
pub const PACK_ATTEMPTS: u32 = 3;

/// Bounded re-runs of `git add` that each set aside one more path git died on.
const FATAL_PATH_RETRIES: usize = 16;

/// The `git add` a worktree tree is written with ([`GitRepo::worktree_add_args`]).
#[derive(Debug, Clone)]
struct AddArgs {
    /// Flags (`add -A --ignore-errors`).
    args: Vec<String>,
    /// Pathspecs: `.` and the `:(exclude)` items.
    pathspecs: Vec<String>,
    /// Nested repositories left out (the chunked class carries them).
    nested: Vec<String>,
    /// Paths git cannot reach, left out (the chunked class carries them).
    beyond: Vec<String>,
}

/// Git errors.
#[derive(Debug, thiserror::Error)]
pub enum GitError {
    /// A git command failed.
    #[error("git {args}: {stderr}")]
    Command {
        /// The arguments.
        args: String,
        /// Trimmed stderr.
        stderr: String,
    },
    /// Not a git repository.
    #[error("{0} is not a git repository")]
    NotARepo(PathBuf),
    /// I/O on a path: what was done, and where.
    #[error("{op} {}: {source}", path.display())]
    IoAt {
        /// What was done (`mkdir -p`, `write`, `rename`, …).
        op: &'static str,
        /// Where.
        path: PathBuf,
        /// What the filesystem said.
        source: io::Error,
    },
    /// I/O.
    #[error(transparent)]
    Io(#[from] io::Error),
}

/// An I/O error on `path`, named (a bare `Permission denied` names no path).
fn at<'a>(op: &'static str, path: &'a Path) -> impl FnOnce(io::Error) -> GitError + 'a {
    move |source| GitError::IoAt {
        op,
        path: path.to_path_buf(),
        source,
    }
}

/// What [`GitRepo::set_remote`] did.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RemoteChange {
    /// The remote did not exist.
    Added,
    /// The remote pointed somewhere else.
    Updated,
    /// The remote already had this URL.
    Unchanged,
}

/// A repository and its directories.
#[derive(Debug, Clone)]
pub struct GitRepo {
    /// Working tree root.
    pub root: PathBuf,
    /// `git rev-parse --git-dir`, absolute.
    pub git_dir: PathBuf,
    /// `git rev-parse --git-common-dir`, absolute (differs from `git_dir` in a linked worktree).
    pub common_dir: PathBuf,
}

/// Run git with a clean environment (no inherited `GIT_DIR`/`GIT_INDEX_FILE`/`GIT_WORK_TREE`).
///
/// Every child started from this command must be spawned through the process-wide spawn gate
/// (`sealant_process::CommandGateExt`: `output_gated`/`spawn_gated`, never `output`/`spawn`).
/// sealantd is PID 1 in the workspace and its orphan reaper reaps any waitable child it did not
/// spawn — an ungated `git` that exits mid-sweep is reaped out from under us and the `wait()`
/// here fails with `ECHILD` ("No child process"), which is how a `capture.flush` died under load.
fn git_command(cwd: &Path) -> Command {
    let mut c = Command::new("git");
    c.current_dir(cwd)
        .env_remove("GIT_DIR")
        .env_remove("GIT_WORK_TREE")
        .env_remove("GIT_INDEX_FILE")
        .env("GIT_OPTIONAL_LOCKS", "0")
        .env("GIT_TERMINAL_PROMPT", "0")
        .stdin(Stdio::null());
    c
}

fn check(args: &[&str], out: Output) -> Result<Output, GitError> {
    if out.status.success() {
        Ok(out)
    } else {
        Err(GitError::Command {
            args: args.join(" "),
            stderr: String::from_utf8_lossy(&out.stderr).trim().to_owned(),
        })
    }
}

fn stdout_string(out: &Output) -> String {
    String::from_utf8_lossy(&out.stdout).trim().to_owned()
}

/// `bytes` without its trailing line end (`\n`, `\r\n`): a ref name or target as git wrote it.
fn trim_newline(bytes: &[u8]) -> &[u8] {
    let bytes = bytes.strip_suffix(b"\n").unwrap_or(bytes);
    bytes.strip_suffix(b"\r").unwrap_or(bytes)
}

/// Walk `dir` (a `refs/` directory; `name` is its ref name, `refs`) and add every loose
/// symbolic ref under it (a file reading `ref: <target>`) to `found`, name → target, both keys.
/// Lock files are git's transient state, not refs.
fn collect_loose_symrefs(
    dir: &Path,
    name: &[u8],
    found: &mut BTreeMap<String, String>,
) -> Result<(), GitError> {
    let entries = match fs::read_dir(dir) {
        Ok(entries) => entries,
        Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(()),
        Err(e) => return Err(at("list", dir)(e)),
    };
    for entry in entries {
        let entry = entry.map_err(at("list", dir))?;
        let path = entry.path();
        let file_name = entry.file_name();
        let mut child = name.to_vec();
        child.push(b'/');
        child.extend_from_slice(file_name.as_bytes());
        let kind = entry.file_type().map_err(at("stat", &path))?;
        if kind.is_dir() {
            collect_loose_symrefs(&path, &child, found)?;
        } else if kind.is_file() && !file_name.as_bytes().ends_with(b".lock") {
            let bytes = match fs::read(&path) {
                Ok(bytes) => bytes,
                // Removed between the listing and the read: a ref that is gone.
                Err(e) if e.kind() == io::ErrorKind::NotFound => continue,
                Err(e) => return Err(at("read", &path)(e)),
            };
            if let Some(target) = bytes.strip_prefix(b"ref: ") {
                let target = trim_newline(target);
                // A name git itself would ignore as broken is not a ref it holds, and one a
                // restore could not write back must not fail the restore of everything else.
                if is_safe_ref_name(&child) && is_safe_symref_target(target) {
                    found.insert(key_of(&child).into_owned(), key_of(target).into_owned());
                } else {
                    tracing::warn!(
                        name = %key_of(&child),
                        "capture: a loose symbolic ref git would not read is left out"
                    );
                }
            }
        }
    }
    Ok(())
}

impl GitRepo {
    /// Open the repository whose working tree is `root`.
    pub fn open(root: &Path) -> Result<Self, GitError> {
        let out = git_command(root)
            .args(["rev-parse", "--git-dir", "--git-common-dir"])
            .output_gated()?;
        if !out.status.success() {
            return Err(GitError::NotARepo(root.to_path_buf()));
        }
        let text = String::from_utf8_lossy(&out.stdout);
        let mut lines = text.lines();
        let git_dir = abs(root, lines.next().unwrap_or(".git"));
        let common_dir = abs(root, lines.next().unwrap_or(".git"));
        Ok(Self {
            root: root.to_path_buf(),
            git_dir,
            common_dir,
        })
    }

    /// `git init` a repository at `root` if none exists there, then open it.
    pub fn init(root: &Path) -> Result<Self, GitError> {
        fs::create_dir_all(root).map_err(at("mkdir -p", root))?;
        if !root.join(".git").exists() {
            let args = ["init", "-q"];
            check(&args, git_command(root).args(args).output_gated()?)?;
        }
        Self::open(root)
    }

    /// Add `pattern` to the repository's local excludes (`info/exclude` in the common dir) unless
    /// it is there already. The user's `.gitignore` is never touched.
    pub fn exclude_locally(&self, pattern: &str) -> Result<(), GitError> {
        let info = self.common_dir.join("info");
        fs::create_dir_all(&info).map_err(at("mkdir -p", &info))?;
        let path = info.join("exclude");
        let mut text = fs::read_to_string(&path).unwrap_or_default();
        if text.lines().any(|l| l.trim() == pattern) {
            return Ok(());
        }
        if !text.is_empty() && !text.ends_with('\n') {
            text.push('\n');
        }
        text.push_str(pattern);
        text.push('\n');
        let tmp = info.join("exclude.capture-tmp");
        fs::write(&tmp, text).map_err(at("write", &tmp))?;
        fs::rename(&tmp, &path).map_err(at("rename into", &path))?;
        Ok(())
    }

    /// Whether `path` (worktree-relative) is ignored by the repository's ignore rules.
    pub fn is_ignored(&self, path: &str) -> Result<bool, GitError> {
        let args = ["check-ignore", "-q", "--", path];
        let out = git_command(&self.root).args(args).output_gated()?;
        match out.status.code() {
            Some(0) => Ok(true),
            Some(1) => Ok(false),
            _ => Err(GitError::Command {
                args: args.join(" "),
                stderr: String::from_utf8_lossy(&out.stderr).trim().to_owned(),
            }),
        }
    }

    /// Run a git command in the working tree and return its output on success.
    pub fn run(&self, args: &[&str]) -> Result<Output, GitError> {
        check(args, git_command(&self.root).args(args).output_gated()?)
    }

    /// Run a git command with stdin.
    fn run_with_stdin(&self, args: &[&str], stdin: &[u8]) -> Result<Output, GitError> {
        let mut child = git_command(&self.root)
            .args(args)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn_gated()?;
        if let Some(mut pipe) = child.take_stdin() {
            // A closed pipe (git exited early) surfaces as the command's status.
            let _ = pipe.write_all(stdin);
        }
        check(args, child.wait_with_output()?)
    }

    /// Make `name` a remote with `url`, and say what that took. The caller validates both: they
    /// reach git as plain arguments.
    pub fn set_remote(&self, name: &str, url: &str) -> Result<RemoteChange, GitError> {
        let key = format!("remote.{name}.url");
        let current = git_command(&self.root)
            .args(["config", "--local", "--get", &key])
            .output_gated()?;
        if !current.status.success() {
            self.run(&["remote", "add", name, url])?;
            return Ok(RemoteChange::Added);
        }
        if stdout_string(&current).trim_end_matches('\n') == url {
            return Ok(RemoteChange::Unchanged);
        }
        self.run(&["remote", "set-url", name, url])?;
        Ok(RemoteChange::Updated)
    }

    /// Ref name → sha for every ref (including `refs/stash`). A name is a [`key_of`] key of the
    /// ref's bytes, so two names that differ only in bytes that are not UTF-8 stay two refs.
    pub fn refs(&self) -> Result<BTreeMap<String, String>, GitError> {
        let out = self.run(&["for-each-ref", "--format=%(objectname) %(refname)"])?;
        // A ref name holds no control byte and no space (`git check-ref-format`): one line per
        // ref, the sha up to the first space, the name the bytes after it.
        Ok(out
            .stdout
            .split(|b| *b == b'\n')
            .filter_map(|line| {
                let space = line.iter().position(|b| *b == b' ')?;
                let (sha, name) = (&line[..space], &line[space + 1..]);
                (!name.is_empty() && !sha.is_empty()).then(|| {
                    (
                        key_of(name).into_owned(),
                        String::from_utf8_lossy(sha).into_owned(),
                    )
                })
            })
            .collect())
    }

    /// Symbolic refs other than `HEAD` (`refs/remotes/origin/HEAD` → `refs/remotes/origin/main`):
    /// ref name → the ref it points at, both [`key_of`] keys of their bytes. [`Self::refs`] lists
    /// the ones whose target resolves too, by the sha they resolve to.
    ///
    /// Read off the loose refs themselves, not `git for-each-ref`: that resolves each one and
    /// leaves out a symbolic ref whose target does not exist (a dangling
    /// `refs/remotes/origin/HEAD`), which is still a ref the repository holds. `packed-refs`
    /// cannot hold a symbolic ref, so the loose files under `refs/` (the common directory's,
    /// and a linked worktree's own) are all of them.
    pub fn symrefs(&self) -> Result<BTreeMap<String, String>, GitError> {
        let mut found = BTreeMap::new();
        let mut dirs = vec![&self.common_dir];
        if self.git_dir != self.common_dir {
            dirs.push(&self.git_dir);
        }
        for dir in dirs {
            collect_loose_symrefs(&dir.join("refs"), b"refs", &mut found)?;
        }
        Ok(found)
    }

    /// `HEAD` as a ref name (symbolic; a [`key_of`] key of its bytes) or a sha (detached).
    pub fn head(&self) -> Result<String, GitError> {
        let out = git_command(&self.root)
            .args(["symbolic-ref", "-q", "HEAD"])
            .output_gated()?;
        if out.status.success() {
            return Ok(key_of(trim_newline(&out.stdout)).into_owned());
        }
        let out = self.run(&["rev-parse", "--verify", "-q", "HEAD"]);
        match out {
            Ok(o) => Ok(stdout_string(&o)),
            Err(_) => Ok(fs::read(self.git_dir.join("HEAD"))
                .map(|bytes| {
                    let text = trim_newline(&bytes);
                    let text = text.strip_prefix(b"ref: ").unwrap_or(text);
                    key_of(text).into_owned()
                })
                .unwrap_or_else(|_| "refs/heads/main".to_owned())),
        }
    }

    /// The tree `HEAD` points at, or `None` when `HEAD` names no commit (an unborn branch).
    pub fn head_tree(&self) -> Result<Option<String>, GitError> {
        let out = git_command(&self.root)
            .args(["rev-parse", "--verify", "-q", "HEAD^{tree}"])
            .output_gated()?;
        Ok(out.status.success().then(|| stdout_string(&out)))
    }

    /// Every sha a reflog entry points at; empty when the repository has no reflog at all (a
    /// freshly materialized one), where `git rev-list --reflog` exits with its usage text.
    pub fn reflog_tips(&self) -> Result<Vec<String>, GitError> {
        if !self.git_dir.join("logs").exists() {
            return Ok(Vec::new());
        }
        let out = self.run(&["rev-list", "--no-walk=unsorted", "--reflog"])?;
        Ok(stdout_string(&out).lines().map(str::to_owned).collect())
    }

    /// Tree of the index, written from a scratch copy so a held `index.lock` never matters;
    /// `None` when there is no index or it has unmerged entries.
    pub fn index_tree(&self, scratch_dir: &Path) -> Result<Option<String>, GitError> {
        let real_index = self.git_dir.join("index");
        if !real_index.exists() {
            return Ok(None);
        }
        fs::create_dir_all(scratch_dir).map_err(at("mkdir -p", scratch_dir))?;
        let tmp_index = scratch_dir.join("index-tree");
        fs::copy(&real_index, &tmp_index).map_err(at("copy into", &tmp_index))?;
        let out = git_command(&self.root)
            .env("GIT_INDEX_FILE", &tmp_index)
            .args(["write-tree"])
            .output_gated()?;
        fs::remove_file(&tmp_index).ok();
        Ok(out.status.success().then(|| stdout_string(&out)))
    }

    /// Blobs the index references (the fallback tips when `write-tree` refuses an unmerged index).
    pub fn index_blobs(&self) -> Result<Vec<String>, GitError> {
        let out = self.run(&["ls-files", "-s"])?;
        Ok(stdout_string(&out)
            .lines()
            .filter_map(|l| l.split_whitespace().nth(1))
            .map(str::to_owned)
            .collect())
    }

    /// `git ls-files -o --exclude-standard -z` (untranslated) against `index` when given, else
    /// the real index: the untracked paths git would add, and on stderr the directories it
    /// could not open.
    fn untracked(&self, index: Option<&Path>) -> Result<Output, GitError> {
        let mut cmd = git_command(&self.root);
        if let Some(index) = index {
            cmd.env("GIT_INDEX_FILE", index);
        }
        let others = ["ls-files", "-o", "--exclude-standard", "-z"];
        check(&others, cmd.env("LC_ALL", "C").args(others).output_gated()?)
    }

    /// Nested repositories under the worktree (directories holding a `.git`, the root's own
    /// excluded), relative to the root: the untracked ones git lists as a lone `dir/` entry
    /// (it never descends into an embedded repository) plus the tracked gitlinks whose
    /// directory holds a `.git` on disk. Ignored ones are not listed; they are carried by the
    /// ignored-files walk already. Read against `index` when given, else the real index.
    pub fn nested_repositories(&self, index: Option<&Path>) -> Result<Vec<String>, GitError> {
        let out = self.untracked(index)?;
        self.nested_in(&out, index)
    }

    fn nested_in(&self, untracked: &Output, index: Option<&Path>) -> Result<Vec<String>, GitError> {
        let mut nested: Vec<String> = String::from_utf8_lossy(&untracked.stdout)
            .split('\0')
            .filter_map(|l| l.strip_suffix('/'))
            .filter(|d| !d.is_empty() && longpath::exists(&self.root.join(d).join(".git")))
            .map(str::to_owned)
            .collect();
        let mut cmd = git_command(&self.root);
        if let Some(index) = index {
            cmd.env("GIT_INDEX_FILE", index);
        }
        let staged = ["ls-files", "-s", "-z"];
        let out = check(&staged, cmd.args(staged).output_gated()?)?;
        nested.extend(
            String::from_utf8_lossy(&out.stdout)
                .split('\0')
                .filter(|l| l.starts_with("160000 "))
                .filter_map(|l| l.split_once('\t').map(|(_, p)| p))
                .filter(|p| longpath::exists(&self.root.join(p).join(".git")))
                .map(str::to_owned),
        );
        nested.sort();
        nested.dedup();
        Ok(nested)
    }

    /// The paths of the working tree the chunked class carries for the git class: the nested
    /// repositories ([`Self::nested_repositories`]) and the paths git cannot reach
    /// ([`Self::beyond_reach`]), sorted. What a materialize sweeps and the worktree metadata
    /// overlay leaves out, as a snap decided.
    pub fn chunked_paths(&self, index: Option<&Path>) -> Result<Vec<String>, GitError> {
        let out = self.untracked(index)?;
        let mut paths = self.nested_in(&out, index)?;
        paths.extend(self.beyond_in(&out, index)?);
        paths.sort();
        paths.dedup();
        Ok(paths)
    }

    /// Untracked paths git cannot reach, relative to the root: it runs in the worktree and
    /// passes each path whole to one system call, which refuses `PATH_MAX` bytes or more (a
    /// file's path as it is; a directory's with the `/` git appends to open it,
    /// [`crate::worktree_meta::beyond_git`]). Git lists such a file, then fails the add on it
    /// (`fatal: unable to stat`); it warns that it could not open such a directory and drops
    /// it. The chunked class carries both, whatever their length. Outermost only. A path that
    /// is not UTF-8 is left to the walks that report what no class carries.
    pub fn beyond_reach(&self, index: Option<&Path>) -> Result<Vec<String>, GitError> {
        let out = self.untracked(index)?;
        self.beyond_in(&out, index)
    }

    /// [`Self::beyond_reach`] from an [`Self::untracked`] listing. Git's warning about a
    /// directory it could not open is cut at its message buffer (4 KB) exactly when the
    /// directory is too long to open, so the path is not read off it: the directory the cut
    /// text still names whole is walked (a path of any length), and every untracked,
    /// unignored directory under it that git cannot open is taken — too long, or one this
    /// walk cannot list either (the chunked class then reports it unreadable).
    fn beyond_in(&self, untracked: &Output, index: Option<&Path>) -> Result<Vec<String>, GitError> {
        let mut found: Vec<Vec<u8>> = Vec::new();
        let mut nested: Vec<&[u8]> = Vec::new();
        for p in untracked.stdout.split(|b| *b == 0) {
            if let Some(dir) = p.strip_suffix(b"/") {
                nested.push(dir);
            } else if crate::worktree_meta::beyond_git(p, false) {
                found.push(p.to_vec());
            }
        }
        const WARNING: &[u8] = b"warning: could not open directory '";
        let mut cut: Vec<Vec<u8>> = Vec::new();
        for line in untracked.stderr.split(|b| *b == b'\n') {
            let Some(rest) = line.strip_prefix(WARNING) else {
                continue;
            };
            if rest.windows(3).any(|w| w == b"': ") {
                // Whole: a directory git could not open for another reason, which the add
                // reports as unreadable on its own.
                continue;
            }
            let whole = rest
                .iter()
                .rposition(|b| *b == b'/')
                .map_or(&b""[..], |i| &rest[..i]);
            cut.push(whole.to_vec());
        }
        if !cut.is_empty() {
            cut.sort();
            cut.dedup();
            let mut cmd = git_command(&self.root);
            if let Some(index) = index {
                cmd.env("GIT_INDEX_FILE", index);
            }
            let args = [
                "ls-files",
                "-o",
                "-i",
                "--exclude-standard",
                "--directory",
                "-z",
            ];
            let ignored_out = check(&args, cmd.env("LC_ALL", "C").args(args).output_gated()?)?;
            let ignored: std::collections::BTreeSet<&[u8]> = ignored_out
                .stdout
                .split(|b| *b == 0)
                .filter(|p| !p.is_empty())
                .map(|p| p.strip_suffix(b"/").unwrap_or(p))
                .collect();
            let under_any = |rel: &[u8], set: &[&[u8]]| {
                set.iter().any(|d| {
                    rel == *d
                        || rel
                            .strip_prefix(*d)
                            .is_some_and(|r| r.first() == Some(&b'/'))
                })
            };
            let ignored_list: Vec<&[u8]> = ignored.iter().copied().collect();
            for whole in &cut {
                if cut
                    .iter()
                    .any(|o| o != whole && under_any(whole, &[o.as_slice()]))
                {
                    continue;
                }
                let base = if whole.is_empty() {
                    self.root.clone()
                } else {
                    self.root.join(std::ffi::OsStr::from_bytes(whole))
                };
                let rel_of = |path: &Path| -> Vec<u8> {
                    path.strip_prefix(&self.root)
                        .unwrap_or(path)
                        .as_os_str()
                        .as_bytes()
                        .to_vec()
                };
                longpath::walk(&base, &mut |visit| {
                    let (path, kind) = match visit {
                        longpath::Visit::Entry { path, kind, .. } => (path, kind),
                        longpath::Visit::Error { path, error, .. } => {
                            if !crate::index::is_vanished(&error) {
                                found.push(rel_of(path));
                            }
                            return false;
                        }
                    };
                    let rel = rel_of(path);
                    if under_any(&rel, &ignored_list) || under_any(&rel, &nested) {
                        return false;
                    }
                    if kind != longpath::Kind::Dir {
                        if crate::worktree_meta::beyond_git(&rel, false) {
                            found.push(rel);
                        }
                        return false;
                    }
                    if path.file_name() == Some(std::ffi::OsStr::new(".git")) {
                        return false;
                    }
                    if crate::worktree_meta::beyond_git(&rel, true) {
                        found.push(rel);
                        return false;
                    }
                    true
                });
            }
        }
        let mut found: Vec<String> = found
            .into_iter()
            .filter_map(|p| String::from_utf8(p).ok())
            .collect();
        found.sort();
        found.dedup();
        let outer: Vec<String> = found
            .iter()
            .filter(|p| {
                !found.iter().any(|o| {
                    o != *p
                        && p.strip_prefix(o.as_str())
                            .is_some_and(|r| r.starts_with('/'))
                })
            })
            .cloned()
            .collect();
        Ok(outer)
    }

    /// The `git add` flags and pathspecs for [`Self::worktree_tree`], the nested repositories
    /// it leaves out and the paths git cannot reach ([`Self::beyond_reach`]). `excludes`,
    /// every nested repository under the root and every path beyond git's reach become
    /// `:(exclude)` pathspec items, so `add -A` never reaches a path git cannot index: a nested
    /// repository with no commit checked out is a fatal error on git 2.52 (`--ignore-errors`
    /// does not cover "does not have a commit checked out" there) and a skipped "unable to
    /// index" error on 2.55; one with a commit would become an embedded gitlink that carries
    /// none of its bytes; a file too long for one system call is fatal ("unable to stat"). The
    /// chunked class carries the bytes in every case, so all are excluded alike and returned.
    /// An exclude git already ignores (the local exclude the engine adds at boot) is skipped by
    /// `.` on its own; naming it in a pathspec makes `git add` report it as an ignored path and
    /// exit 1, so only the paths git would otherwise index get a pathspec item. Nested
    /// repositories below an exclude are left out of the returned list: they are not part of
    /// the tree the worktree tree describes. The pathspecs travel in a file
    /// (`--pathspec-from-file`): a thousand paths of 4 KB would not fit an argument list.
    fn worktree_add_args(
        &self,
        tmp_index: &Path,
        excludes: &[String],
    ) -> Result<AddArgs, GitError> {
        // `--ignore-errors` stays as belt and braces for anything the enumeration missed.
        let args: Vec<String> = ["add", "-A", "--ignore-errors"]
            .iter()
            .map(|s| (*s).to_owned())
            .collect();
        let mut pathspecs: Vec<String> = vec![".".to_owned()];
        let excludes: Vec<&str> = excludes
            .iter()
            .map(|e| e.trim_matches('/'))
            .filter(|e| !e.is_empty())
            .collect();
        for e in &excludes {
            if !self.is_ignored(e)? {
                pathspecs.push(format!(":(exclude){e}"));
            }
        }
        let under_exclude = |p: &str| {
            excludes
                .iter()
                .any(|e| p == *e || p.strip_prefix(e).is_some_and(|r| r.starts_with('/')))
        };
        let untracked = self.untracked(Some(tmp_index))?;
        let mut nested = Vec::new();
        for n in self.nested_in(&untracked, Some(tmp_index))? {
            if under_exclude(&n) {
                continue;
            }
            if !self.is_ignored(&n)? {
                pathspecs.push(format!(":(exclude){n}"));
            }
            nested.push(n);
        }
        let mut beyond = Vec::new();
        for b in self.beyond_in(&untracked, Some(tmp_index))? {
            if under_exclude(&b)
                || nested
                    .iter()
                    .any(|n| b == *n || b.starts_with(&format!("{n}/")))
            {
                continue;
            }
            pathspecs.push(format!(":(exclude){b}"));
            beyond.push(b);
        }
        Ok(AddArgs {
            args,
            pathspecs,
            nested,
            beyond,
        })
    }

    /// Run `git add` as [`AddArgs`] says against `tmp_index`, its pathspecs from a file beside
    /// it, untranslated (what could not be read is read off the messages).
    fn run_add(&self, tmp_index: &Path, add: &AddArgs) -> Result<Output, GitError> {
        let spec_file = tmp_index.with_extension("pathspecs");
        let mut specs: Vec<u8> = Vec::new();
        for p in &add.pathspecs {
            specs.extend_from_slice(p.as_bytes());
            specs.push(0);
        }
        fs::write(&spec_file, &specs).map_err(at("write", &spec_file))?;
        let out = git_command(&self.root)
            .env("GIT_INDEX_FILE", tmp_index)
            .env("LC_ALL", "C")
            .args(&add.args)
            .arg(format!("--pathspec-from-file={}", spec_file.display()))
            .arg("--pathspec-file-nul")
            .output_gated();
        fs::remove_file(&spec_file).ok();
        Ok(out?)
    }

    /// Tree of the working tree: a throwaway copy of the index with `git add -A` applied, then
    /// `write-tree`. Nested repositories are left out of the add (see
    /// [`Self::worktree_add_args`]) and their paths are returned beside the sha so the chunked
    /// class can carry them; a tracked gitlink keeps the entry the index already had.
    ///
    /// Tracked always wins: a path the index holds is part of the tree whatever the ignore rules
    /// say (`git add -A` only consults them for untracked paths). Without an index on disk the
    /// throwaway one is seeded from `HEAD`'s tree, so the tracked files of the checked-out
    /// commit keep that standing — from an empty index, a tracked file that happens to match
    /// `.gitignore` (`core.*` against a tracked `core.json`) would be taken for an ignored one
    /// and dropped from the tree.
    pub fn worktree_tree(
        &self,
        scratch_dir: &Path,
        excludes: &[String],
    ) -> Result<(String, Vec<String>), GitError> {
        let wt = self.worktree_tree_carrying(scratch_dir, excludes, None)?;
        Ok((wt.tree, wt.gitlinks))
    }

    /// [`Self::worktree_tree`], and what `git add` could not read: a directory it could not
    /// open (it skips one with a warning, so an untracked one would silently drop out of the
    /// tree and a tracked one fall back to the index's stale blobs) or a path it could not
    /// stat or open. With `carry_from` (the previous capture's worktree tree), each such path
    /// takes that tree's entry, never a deletion; see [`WorktreeTree`].
    pub fn worktree_tree_carrying(
        &self,
        scratch_dir: &Path,
        excludes: &[String],
        carry_from: Option<&str>,
    ) -> Result<WorktreeTree, GitError> {
        fs::create_dir_all(scratch_dir).map_err(at("mkdir -p", scratch_dir))?;
        let tmp_index = scratch_dir.join("snap-index");
        let real_index = self.git_dir.join("index");
        fs::remove_file(&tmp_index).ok();
        if real_index.exists() {
            fs::copy(&real_index, &tmp_index).map_err(at("copy into", &tmp_index))?;
        } else if let Some(head_tree) = self.head_tree()? {
            let rt = ["read-tree", &head_tree];
            check(
                &rt,
                git_command(&self.root)
                    .env("GIT_INDEX_FILE", &tmp_index)
                    .args(rt)
                    .output_gated()?,
            )?;
        }
        let mut add = self.worktree_add_args(&tmp_index, excludes)?;
        // A path git dies on (`fatal: unable to stat '<p>'`: a file it listed and cannot stat)
        // fails that path only: it joins the chunked class, which reads it or reports it
        // unreadable, and the add runs again without it. Bounded; each round names a new path.
        let mut out = self.run_add(&tmp_index, &add)?;
        for _ in 0..FATAL_PATH_RETRIES {
            if out.status.success() {
                break;
            }
            let stderr = String::from_utf8_lossy(&out.stderr).to_string();
            let fatal: Vec<String> = stderr
                .lines()
                .filter_map(|l| l.strip_prefix("fatal: unable to stat '"))
                .filter_map(|l| l.rsplit_once("': ").map(|(p, _)| p.to_owned()))
                .filter(|p| !p.is_empty() && !add.beyond.contains(p))
                .collect();
            if fatal.is_empty() {
                break;
            }
            for p in fatal {
                tracing::warn!(path = %p, "git cannot stat this path; the chunked class carries it");
                add.pathspecs.push(format!(":(exclude){p}"));
                add.beyond.push(p);
            }
            // The add died part way: start again from the index it was given.
            fs::remove_file(&tmp_index).ok();
            if real_index.exists() {
                fs::copy(&real_index, &tmp_index).map_err(at("copy into", &tmp_index))?;
            } else if let Some(head_tree) = self.head_tree()? {
                let rt = ["read-tree", &head_tree];
                check(
                    &rt,
                    git_command(&self.root)
                        .env("GIT_INDEX_FILE", &tmp_index)
                        .args(rt)
                        .output_gated()?,
                )?;
            }
            out = self.run_add(&tmp_index, &add)?;
        }
        let AddArgs {
            args,
            pathspecs,
            mut nested,
            mut beyond,
        } = add;
        // Belt and braces: anything `--ignore-errors` skipped past that the enumeration did not
        // name joins the chunked class the same way.
        let stderr = String::from_utf8_lossy(&out.stderr).to_string();
        let mut unindexed: Vec<String> = stderr
            .lines()
            .filter_map(|l| l.strip_prefix("error: unable to index file '"))
            .filter_map(|l| l.strip_suffix('\''))
            .map(|p| p.trim_end_matches('/').to_owned())
            .collect();
        if !out.status.success() && unindexed.is_empty() {
            return Err(GitError::Command {
                args: format!("{} -- {}", args.join(" "), pathspecs.join(" ")),
                stderr: stderr.trim().to_owned(),
            });
        }
        let unreadable = unreadable_in_add(&self.root, &stderr);
        let carried = match carry_from {
            Some(from) => self.carry_into_index(&tmp_index, from, &unreadable),
            None => Vec::new(),
        };
        let wt = ["write-tree"];
        let out = check(
            &wt,
            git_command(&self.root)
                .env("GIT_INDEX_FILE", &tmp_index)
                .args(wt)
                .output_gated()?,
        )?;
        let tree = stdout_string(&out);
        let ls = ["ls-files", "-s", "-z"];
        let out = check(
            &ls,
            git_command(&self.root)
                .env("GIT_INDEX_FILE", &tmp_index)
                .args(ls)
                .output_gated()?,
        )?;
        let mut gitlinks: Vec<String> = String::from_utf8_lossy(&out.stdout)
            .split('\0')
            .filter(|l| l.starts_with("160000 "))
            .filter_map(|l| l.split_once('\t').map(|(_, p)| p.to_owned()))
            .collect();
        gitlinks.append(&mut unindexed);
        gitlinks.append(&mut nested);
        gitlinks.append(&mut beyond);
        gitlinks.sort();
        gitlinks.dedup();
        fs::remove_file(&tmp_index).ok();
        Ok(WorktreeTree {
            tree,
            gitlinks,
            unreadable,
            carried,
        })
    }

    /// Give each unreadable path in `tmp_index` the entry `from` (a tree) holds for it: the
    /// index's entries at and under the path are removed, then a subtree is read in under the
    /// path's prefix, or a blob (or gitlink) entry is added. A path `from` does not hold is left
    /// as `git add` left it (an untracked one absent, a tracked one at the index's blob).
    /// Returns the paths carried; a git failure skips that path, logged.
    fn carry_into_index(
        &self,
        tmp_index: &Path,
        from: &str,
        unreadable: &[(String, String)],
    ) -> Vec<String> {
        let git = |args: &[&str]| -> Result<Output, GitError> {
            check(
                args,
                git_command(&self.root)
                    .env("GIT_INDEX_FILE", tmp_index)
                    .env("GIT_LITERAL_PATHSPECS", "1")
                    .args(args)
                    .output_gated()?,
            )
        };
        let mut carried = Vec::new();
        for (path, _) in unreadable {
            let carry = || -> Result<bool, GitError> {
                let listed = git(&["ls-tree", "-z", from, "--", path])?;
                let Some((meta, _)) = listed.stdout.split(|b| *b == 0).next().and_then(|e| {
                    let e = std::str::from_utf8(e).ok()?;
                    e.split_once('\t')
                }) else {
                    return Ok(false);
                };
                let mut fields = meta.split(' ');
                let (Some(mode), Some(kind), Some(sha)) =
                    (fields.next(), fields.next(), fields.next())
                else {
                    return Ok(false);
                };
                git(&[
                    "rm",
                    "-r",
                    "--cached",
                    "-f",
                    "-q",
                    "--ignore-unmatch",
                    "--",
                    path,
                ])?;
                if kind == "tree" {
                    git(&["read-tree", &format!("--prefix={path}/"), sha])?;
                } else {
                    git(&[
                        "update-index",
                        "--add",
                        "--cacheinfo",
                        &format!("{mode},{sha},{path}"),
                    ])?;
                }
                Ok(true)
            };
            match carry() {
                Ok(true) => carried.push(path.clone()),
                Ok(false) => {}
                Err(error) => {
                    tracing::warn!(%path, %error, "could not carry an unreadable path from the previous capture");
                }
            }
        }
        carried
    }

    /// Filter `shas` to the ones the object store holds.
    pub fn existing(&self, shas: &[String]) -> Result<Vec<String>, GitError> {
        if shas.is_empty() {
            return Ok(Vec::new());
        }
        let input = shas.iter().map(|s| format!("{s}\n")).collect::<String>();
        let out = self.run_with_stdin(&["cat-file", "--batch-check"], input.as_bytes())?;
        Ok(stdout_string(&out)
            .lines()
            .filter(|l| !l.ends_with(" missing"))
            .filter_map(|l| l.split_whitespace().next())
            .map(str::to_owned)
            .collect())
    }

    /// `git fsck --connectivity-only --no-dangling`.
    pub fn fsck(&self) -> Result<FsckStatus, GitError> {
        let out = git_command(&self.root)
            .args(["fsck", "--connectivity-only", "--no-dangling"])
            .output_gated()?;
        Ok(if out.status.success() {
            FsckStatus::Verified
        } else {
            FsckStatus::Failed
        })
    }

    /// `git status --porcelain`.
    pub fn status_porcelain(&self) -> Result<String, GitError> {
        Ok(stdout_string(&self.run(&["status", "--porcelain"])?))
    }
}

fn abs(root: &Path, p: &str) -> PathBuf {
    let path = Path::new(p);
    if path.is_absolute() {
        path.to_path_buf()
    } else {
        root.join(path)
    }
}

/// A worktree tree and what went into it ([`GitRepo::worktree_tree_carrying`]).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WorktreeTree {
    /// The tree.
    pub tree: String,
    /// Nested repositories and paths git could not index (the chunked class carries them).
    pub gitlinks: Vec<String>,
    /// Paths `git add` could not read, root-relative, with what the filesystem said: each one
    /// verified on disk (it exists and cannot be listed, stat'ed or opened), outermost only.
    pub unreadable: Vec<(String, String)>,
    /// Of `unreadable`, the paths that took the previous capture's entry.
    pub carried: Vec<String>,
}

/// The paths `git add` (run with `LC_ALL=C`) said it could not read: `warning: could not open
/// directory '<p>/': …`, `error: open("<p>"): …`, and a bare `<p>: …` (a tracked path it could
/// not stat). A candidate counts only when the filesystem agrees it exists and cannot be read;
/// a path under another kept one is dropped.
fn unreadable_in_add(root: &Path, stderr: &str) -> Vec<(String, String)> {
    let mut found: Vec<(String, String)> = Vec::new();
    for line in stderr.lines() {
        let candidate = if let Some(rest) = line.strip_prefix("warning: could not open directory '")
        {
            rest.rsplit_once("': ").map(|(p, _)| p)
        } else if let Some(rest) = line.strip_prefix("error: open(\"") {
            rest.rsplit_once("\"): ").map(|(p, _)| p)
        } else if line.starts_with("error: ")
            || line.starts_with("warning: ")
            || line.starts_with("fatal: ")
        {
            None
        } else {
            line.rsplit_once(": ").map(|(p, _)| p)
        };
        let Some(p) = candidate.map(|p| p.trim_end_matches('/')) else {
            continue;
        };
        if p.is_empty() || Path::new(p).is_absolute() || found.iter().any(|(f, _)| f == p) {
            continue;
        }
        let abs = root.join(p);
        let error = match longpath::symlink_metadata(&abs) {
            Err(e) => Some(e),
            Ok(m) if m.is_dir() => longpath::read_dir(&abs).err(),
            Ok(m) if m.is_file() => longpath::open(&abs).err(),
            Ok(_) => None,
        };
        if let Some(e) = error
            && !crate::index::is_vanished(&e)
        {
            found.push((p.to_owned(), e.to_string()));
        }
    }
    found.sort();
    let outer: Vec<(String, String)> = found
        .iter()
        .filter(|(p, _)| {
            !found.iter().any(|(o, _)| {
                o != p
                    && p.strip_prefix(o.as_str())
                        .is_some_and(|r| r.starts_with('/'))
            })
        })
        .cloned()
        .collect();
    outer
}

/// The closure read before packing.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Closure {
    /// Refs plus the two pseudo-refs.
    pub refs: BTreeMap<String, String>,
    /// Symbolic refs other than `HEAD`: name → the ref it points at.
    pub symrefs: BTreeMap<String, String>,
    /// `HEAD`.
    pub head: String,
    /// Every positive tip: ref values, `HEAD`, reflog entries, index and worktree trees (or the
    /// index blobs when the index is unmerged).
    pub tips: Vec<String>,
    /// Paths of nested repositories under the worktree (left out of the worktree tree; the
    /// chunked class carries their bytes).
    pub gitlinks: Vec<String>,
    /// Paths the worktree tree could not read ([`WorktreeTree::unreadable`]).
    pub unreadable: Vec<(String, String)>,
    /// Of those, the ones carried from the previous capture's worktree tree.
    pub carried: Vec<String>,
}

/// Read the closure (refs, `HEAD`, index, stash, reflog, worktree) in that order. `excludes` are
/// pathspecs (relative to the root) left out of the worktree tree: the daemon directory.
pub fn read_closure(
    repo: &GitRepo,
    scratch_dir: &Path,
    excludes: &[String],
) -> Result<Closure, GitError> {
    read_closure_carrying(repo, scratch_dir, excludes, None)
}

/// [`read_closure`], carrying what the worktree could not read from `carry_from` (the previous
/// capture's worktree tree; see [`GitRepo::worktree_tree_carrying`]).
pub fn read_closure_carrying(
    repo: &GitRepo,
    scratch_dir: &Path,
    excludes: &[String],
    carry_from: Option<&str>,
) -> Result<Closure, GitError> {
    let mut refs = repo.refs()?;
    let symrefs = repo.symrefs()?;
    let head = repo.head()?;
    let mut tips: Vec<String> = refs.values().cloned().collect();
    if !head.starts_with("refs/") {
        tips.push(head.clone());
    }
    match repo.index_tree(scratch_dir)? {
        Some(tree) => {
            refs.insert(INDEX_TREE_REF.to_owned(), tree.clone());
            tips.push(tree);
        }
        None => tips.extend(repo.index_blobs()?),
    }
    tips.extend(repo.reflog_tips()?);
    let WorktreeTree {
        tree: wt,
        gitlinks,
        unreadable,
        carried,
    } = repo.worktree_tree_carrying(scratch_dir, excludes, carry_from)?;
    refs.insert(WORKTREE_TREE_REF.to_owned(), wt.clone());
    tips.push(wt);
    tips.sort();
    tips.dedup();
    Ok(Closure {
        refs,
        symrefs,
        head,
        tips,
        gitlinks,
        unreadable,
        carried,
    })
}

/// The tips whose objects a materialized repository got from the chain: ref values, a detached
/// `HEAD`, reflog entries. These are what a snap after a materialize may hold as negatives.
///
/// Deliberately not [`read_closure`]: that writes the index and worktree trees afresh, and
/// those objects exist only locally unless they happen to equal the chain head's pseudo-refs
/// (the head's own tips are negatives already). Seeding them as "stored" hid every tree the
/// materialized disk differed by from the next pack — observed as a capture whose root tree
/// named subtrees no pack of the chain held (`fatal: unable to read tree`).
pub fn stored_tips(repo: &GitRepo) -> Result<Vec<String>, GitError> {
    let refs = repo.refs()?;
    let head = repo.head()?;
    let mut tips: Vec<String> = refs.into_values().collect();
    if !head.starts_with("refs/") {
        tips.push(head);
    }
    tips.extend(repo.reflog_tips()?);
    tips.sort();
    tips.dedup();
    Ok(tips)
}

/// A finished, self-contained git pack with its index.
#[derive(Debug, Clone)]
pub struct FinishedGitPack {
    /// `<dir>/<sha256>`.
    pub path: PathBuf,
    /// `<dir>/<sha256>.idx`.
    pub idx_path: PathBuf,
    /// sha256 of the pack bytes.
    pub sha256: String,
    /// Pack size.
    pub bytes: u64,
    /// Object count.
    pub objects: u32,
}

/// Result of building the git class.
#[derive(Debug, Clone)]
pub struct GitPackResult {
    /// The pack, or `None` when nothing is new since the previous tips.
    pub pack: Option<FinishedGitPack>,
    /// The closure the pack corresponds to.
    pub closure: Closure,
    /// fsck outcome.
    pub fsck: FsckStatus,
    /// Attempts used.
    pub attempts: u32,
}

/// Object count from a pack header (`PACK`, version, count; big-endian).
fn pack_object_count(path: &Path) -> io::Result<u32> {
    let mut header = [0u8; 12];
    use std::os::unix::fs::FileExt;
    File::open(path)?.read_exact_at(&mut header, 0)?;
    if &header[0..4] != b"PACK" {
        return Err(io::Error::other("not a git pack"));
    }
    Ok(u32::from_be_bytes([
        header[8], header[9], header[10], header[11],
    ]))
}

fn pack_once(
    repo: &GitRepo,
    out_dir: &Path,
    tips: &[String],
    negatives: &[String],
    attempt: u32,
) -> Result<Option<FinishedGitPack>, GitError> {
    let mut input = String::new();
    for t in tips {
        input.push_str(t);
        input.push('\n');
    }
    for n in negatives {
        input.push('^');
        input.push_str(n);
        input.push('\n');
    }
    let tmp = out_dir.join(format!(".git-pack-{attempt}.pack"));
    let file = File::create(&tmp).map_err(at("create", &tmp))?;
    let args = ["pack-objects", "--revs", "--stdout", "-q"];
    let mut child = git_command(&repo.root)
        .args(args)
        .stdin(Stdio::piped())
        .stdout(Stdio::from(file))
        .stderr(Stdio::piped())
        .spawn_gated()?;
    if let Some(mut pipe) = child.take_stdin() {
        let _ = pipe.write_all(input.as_bytes());
    }
    let out = child.wait_with_output()?;
    if let Err(e) = check(&args, out) {
        fs::remove_file(&tmp).ok();
        return Err(e);
    }
    let objects = pack_object_count(&tmp)?;
    if objects == 0 {
        fs::remove_file(&tmp).ok();
        return Ok(None);
    }
    // `git index-pack <file.pack>` writes `<file>.idx` beside it and verifies the pack; git
    // 2.41+ also writes `<file>.rev`, which nothing here uses.
    let tmp_str = tmp.to_string_lossy().to_string();
    let args = ["index-pack", &tmp_str];
    check(&args, git_command(&repo.root).args(args).output_gated()?)?;
    fs::remove_file(tmp.with_extension("rev")).ok();
    let bytes = fs::read(&tmp)?;
    let sha256 = sha256_hex(&bytes);
    let path = out_dir.join(&sha256);
    let idx_path = out_dir.join(format!("{sha256}.idx"));
    fs::rename(&tmp, &path).map_err(at("rename into", &path))?;
    fs::rename(tmp.with_extension("idx"), &idx_path).map_err(at("rename into", &idx_path))?;
    Ok(Some(FinishedGitPack {
        path,
        idx_path,
        sha256,
        bytes: bytes.len() as u64,
        objects,
    }))
}

/// Build the git class: read the closure, pack it against `previous_tips`, re-read refs and
/// retry if anything moved or an object went missing, bounded to [`PACK_ATTEMPTS`]; after that,
/// ship the last pack with `fsck = unverified`. `excludes` are root-relative paths left out of
/// the worktree tree.
pub fn build_git_pack(
    repo: &GitRepo,
    out_dir: &Path,
    previous_tips: &[String],
    excludes: &[String],
) -> Result<GitPackResult, GitError> {
    build_git_pack_carrying(repo, out_dir, previous_tips, excludes, None)
}

/// [`build_git_pack`], carrying what the worktree could not read from `carry_from` (the
/// previous capture's worktree tree; see [`GitRepo::worktree_tree_carrying`]).
pub fn build_git_pack_carrying(
    repo: &GitRepo,
    out_dir: &Path,
    previous_tips: &[String],
    excludes: &[String],
    carry_from: Option<&str>,
) -> Result<GitPackResult, GitError> {
    fs::create_dir_all(out_dir).map_err(at("mkdir -p", out_dir))?;
    let negatives = repo.existing(previous_tips)?;
    let mut last: Option<(Option<FinishedGitPack>, Closure)> = None;
    for attempt in 1..=PACK_ATTEMPTS {
        let closure = read_closure_carrying(repo, out_dir, excludes, carry_from)?;
        let packed = match pack_once(repo, out_dir, &closure.tips, &negatives, attempt) {
            Ok(p) => p,
            Err(e) => {
                tracing::warn!(attempt, error = %e, "pack-objects failed; re-reading refs");
                continue;
            }
        };
        let refs_after = repo.refs()?;
        let head_after = repo.head()?;
        let symrefs_after = repo.symrefs()?;
        let moved = symrefs_after != closure.symrefs
            || closure
                .refs
                .iter()
                .filter(|(k, _)| !k.starts_with(PSEUDO_REF_PREFIX))
                .any(|(k, v)| refs_after.get(k) != Some(v))
            || refs_after.keys().any(|k| !closure.refs.contains_key(k))
            || head_after != closure.head;
        if !moved {
            let fsck = repo.fsck()?;
            return Ok(GitPackResult {
                pack: packed,
                closure,
                fsck,
                attempts: attempt,
            });
        }
        tracing::debug!(attempt, "refs moved during pack; retrying");
        if let Some(p) = &packed {
            fs::remove_file(&p.path).ok();
            fs::remove_file(&p.idx_path).ok();
        }
        last = Some((packed, closure));
    }
    // Retries exhausted: the last closure is packed once more, shipped unverified.
    let closure = match last {
        Some((_, c)) => c,
        None => read_closure_carrying(repo, out_dir, excludes, carry_from)?,
    };
    let packed = pack_once(repo, out_dir, &closure.tips, &negatives, PACK_ATTEMPTS + 1)?;
    Ok(GitPackResult {
        pack: packed,
        closure,
        fsck: FsckStatus::Unverified,
        attempts: PACK_ATTEMPTS + 1,
    })
}

// ---------------------------------------------------------------------------------------------
// Materialize side.
// ---------------------------------------------------------------------------------------------

/// Whether the pack named by `sha256` is installed already (pack and index both present).
#[must_use]
pub fn pack_installed(repo: &GitRepo, sha256: &str) -> bool {
    let dir = repo.common_dir.join("objects").join("pack");
    dir.join(format!("pack-{sha256}.pack")).exists()
        && dir.join(format!("pack-{sha256}.idx")).exists()
}

/// Install a pack (and its index; regenerated with `git index-pack` when absent) into
/// `objects/pack`. `Ok(false)` when it was there already.
pub fn install_pack(
    repo: &GitRepo,
    sha256: &str,
    pack: &[u8],
    idx: Option<&[u8]>,
) -> Result<bool, GitError> {
    let dir = repo.common_dir.join("objects").join("pack");
    fs::create_dir_all(&dir).map_err(at("mkdir -p", &dir))?;
    let pack_path = dir.join(format!("pack-{sha256}.pack"));
    let idx_path = dir.join(format!("pack-{sha256}.idx"));
    if pack_path.exists() && idx_path.exists() {
        return Ok(false);
    }
    let tmp = dir.join(format!("tmp-capture-{sha256}.pack"));
    fs::write(&tmp, pack).map_err(at("write", &tmp))?;
    let tmp_idx = tmp.with_extension("idx");
    match idx {
        Some(bytes) => fs::write(&tmp_idx, bytes).map_err(at("write", &tmp_idx))?,
        None => {
            let tmp_str = tmp.to_string_lossy().to_string();
            let args = ["index-pack", &tmp_str];
            check(&args, git_command(&repo.root).args(args).output_gated()?)?;
            fs::remove_file(tmp.with_extension("rev")).ok();
        }
    }
    fs::rename(&tmp_idx, &idx_path).map_err(at("rename into", &idx_path))?;
    fs::rename(&tmp, &pack_path).map_err(at("rename into", &pack_path))?;
    Ok(true)
}

/// Make the repository's refs exactly `refs` (the pseudo-refs skipped) with `symrefs`
/// symbolic: `packed-refs` is written from the direct ones and every loose ref is removed,
/// whether the manifest names it or not, so a branch, tag, remote-tracking ref or stash the
/// disk held beyond the manifest does not survive a materialize; then each symbolic ref is
/// written loose (`packed-refs` cannot hold one) as `ref: <target>`, whether its target exists
/// or not. Directories under `refs/` a loose ref leaves empty go too, except `refs/heads` and
/// `refs/tags`, which git expects. Names and targets are [`key_of`] keys: each is written as
/// the bytes it stands for ([`bytes_of`]), so a name that is not UTF-8 comes back exactly.
pub fn write_packed_refs(
    repo: &GitRepo,
    refs: &BTreeMap<String, String>,
    symrefs: &BTreeMap<String, String>,
) -> Result<(), GitError> {
    for (name, target) in symrefs {
        if !is_safe_ref_name(&bytes_of(name)) || !is_safe_symref_target(&bytes_of(target)) {
            return Err(GitError::Command {
                args: "symbolic-ref".to_owned(),
                stderr: format!("refusing symbolic ref {name:?} -> {target:?}"),
            });
        }
    }
    // No `peeled` trait: this file carries no `^<peeled>` lines, and a file that claimed the
    // trait without them tells git that no ref here is an annotated tag. Git 2.43 and 2.52
    // believe it: `describe` finds no annotated tag, `show-ref -d` and the refs a fetch is
    // offered lose `v1^{}`, and 2.52's `for-each-ref %(*objectname)` fails on "bad tag".
    // Without the trait git peels each tag from its object, on every version.
    let mut text: Vec<u8> = b"# pack-refs with: sorted \n".to_vec();
    // Sorted by bytes, as git reads a `sorted` file (the keys' order is not the bytes' order
    // once one is escaped).
    let mut direct: Vec<(Vec<u8>, &String)> = refs
        .iter()
        .filter(|(name, _)| !name.starts_with(PSEUDO_REF_PREFIX) && !symrefs.contains_key(*name))
        .map(|(name, sha)| (bytes_of(name).into_owned(), sha))
        .collect();
    direct.sort();
    for (name, sha) in direct {
        if !is_safe_ref_name(&name) {
            return Err(GitError::Command {
                args: "pack-refs".to_owned(),
                stderr: format!("refusing ref {:?}", key_of(&name)),
            });
        }
        text.extend_from_slice(sha.as_bytes());
        text.push(b' ');
        text.extend_from_slice(&name);
        text.push(b'\n');
    }
    let path = repo.common_dir.join("packed-refs");
    let tmp = repo.common_dir.join("packed-refs.capture-tmp");
    fs::write(&tmp, text).map_err(at("write", &tmp))?;
    fs::rename(&tmp, &path).map_err(at("rename into", &path))?;
    // After `packed-refs` holds the manifest's refs: a loose ref shadows a packed one, so none
    // may remain.
    for dir in [&repo.common_dir, &repo.git_dir] {
        remove_loose_refs(&dir.join("refs"), 0)?;
    }
    for (name, target) in symrefs {
        let name = bytes_of(name);
        // A worktree's own refs live in its git directory, the rest in the common one.
        let per_worktree = [&b"refs/bisect/"[..], b"refs/worktree/", b"refs/rewritten/"]
            .iter()
            .any(|p| name.starts_with(p));
        let base = if per_worktree {
            &repo.git_dir
        } else {
            &repo.common_dir
        };
        let path = base.join(std::ffi::OsStr::from_bytes(&name));
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent).map_err(at("mkdir -p", parent))?;
        }
        let mut line = b"ref: ".to_vec();
        line.extend_from_slice(&bytes_of(target));
        line.push(b'\n');
        fs::write(&path, line).map_err(at("write", &path))?;
    }
    Ok(())
}

/// A symbolic ref's target that can be written back as the file's one line: not empty, no
/// control byte. Not required to exist, nor to be under `refs/` (git reads what it reads).
fn is_safe_symref_target(target: &[u8]) -> bool {
    !target.is_empty() && !target.iter().any(|b| *b < 0x20 || *b == 0x7f)
}

/// A ref name that is safe to write as a path under the git dir: `refs/…`, components that
/// are not empty, `.`/`..`-led, or `.lock`, and no control or special bytes. Bytes of `0x80`
/// and above (a name that is not UTF-8) are allowed: git allows them.
fn is_safe_ref_name(name: &[u8]) -> bool {
    name.starts_with(b"refs/")
        && name
            .split(|b| *b == b'/')
            .all(|c| !c.is_empty() && !c.starts_with(b".") && !c.ends_with(b".lock"))
        && !name.windows(2).any(|w| w == b"..")
        && !name.iter().any(|b| {
            *b < 0x20
                || *b == 0x7f
                || matches!(b, b' ' | b'~' | b'^' | b':' | b'?' | b'*' | b'[' | b'\\')
        })
}

/// Remove every file under `dir` (a `refs/` directory) and the directories that empties, but
/// `refs/` itself, `refs/heads` and `refs/tags`.
fn remove_loose_refs(dir: &Path, depth: usize) -> Result<(), GitError> {
    let entries = match fs::read_dir(dir) {
        Ok(entries) => entries,
        Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(()),
        Err(e) => return Err(at("list", dir)(e)),
    };
    for entry in entries {
        let entry = entry?;
        let path = entry.path();
        if entry.file_type()?.is_dir() {
            remove_loose_refs(&path, depth + 1)?;
            let keep = depth == 0 && (entry.file_name() == "heads" || entry.file_name() == "tags");
            if !keep {
                match fs::remove_dir(&path) {
                    Ok(()) => {}
                    Err(e) if e.kind() == io::ErrorKind::DirectoryNotEmpty => {}
                    Err(e) => return Err(at("rmdir", &path)(e)),
                }
            }
        } else {
            fs::remove_file(&path).map_err(at("rm", &path))?;
        }
    }
    Ok(())
}

/// Write `HEAD` (a symbolic ref, a [`key_of`] key written as its bytes, or a detached sha).
pub fn write_head(repo: &GitRepo, head: &str) -> Result<(), GitError> {
    let mut text = Vec::new();
    if head.starts_with("refs/") {
        text.extend_from_slice(b"ref: ");
    }
    text.extend_from_slice(&bytes_of(head));
    text.push(b'\n');
    let path = repo.git_dir.join("HEAD");
    fs::write(&path, text).map_err(at("write", &path))?;
    Ok(())
}

/// Check `tree` out into the working tree through a throwaway index: every file of the tree
/// is written (nothing is removed). See [`checkout_tree_from`] for the delta form.
pub fn checkout_tree(repo: &GitRepo, tree: &str, scratch_dir: &Path) -> Result<(), GitError> {
    let tmp_index = scratch_index(scratch_dir)?;
    let rt = ["read-tree", tree];
    check(
        &rt,
        git_command(&repo.root)
            .env("GIT_INDEX_FILE", &tmp_index)
            .args(rt)
            .output_gated()?,
    )?;
    let co = ["checkout-index", "-a", "-f", "-q"];
    check(
        &co,
        git_command(&repo.root)
            .env("GIT_INDEX_FILE", &tmp_index)
            .args(co)
            .output_gated()?,
    )?;
    fs::remove_file(&tmp_index).ok();
    Ok(())
}

/// Move a working tree that holds `from` to `to` through a throwaway index: a two-tree
/// `read-tree --reset -u`, which writes the paths that differ between the trees, deletes the
/// ones `to` dropped and leaves the rest untouched (the index is trusted for them, so the
/// caller vouches that the working tree still holds `from`). Returns the number of paths the
/// tree diff names.
pub fn checkout_tree_from(
    repo: &GitRepo,
    from: &str,
    to: &str,
    scratch_dir: &Path,
) -> Result<u64, GitError> {
    if from == to {
        return Ok(0);
    }
    let tmp_index = scratch_index(scratch_dir)?;
    let seed = ["read-tree", from];
    check(
        &seed,
        git_command(&repo.root)
            .env("GIT_INDEX_FILE", &tmp_index)
            .args(seed)
            .output_gated()?,
    )?;
    let merge = ["read-tree", "--reset", "-u", from, to];
    check(
        &merge,
        git_command(&repo.root)
            .env("GIT_INDEX_FILE", &tmp_index)
            .args(merge)
            .output_gated()?,
    )?;
    fs::remove_file(&tmp_index).ok();
    let diff = [
        "diff-tree",
        "-r",
        "--name-only",
        "--no-renames",
        "-z",
        from,
        to,
    ];
    let out = check(&diff, git_command(&repo.root).args(diff).output_gated()?)?;
    Ok(out
        .stdout
        .split(|b| *b == 0)
        .filter(|p| !p.is_empty())
        .count() as u64)
}

/// Files under the working tree that `tree` does not have and git would not ignore, relative
/// to the root: the leftovers of an earlier checkout. Nested repositories (a lone `dir/` entry)
/// and anything under `excludes` are not listed.
pub fn untracked_against(
    repo: &GitRepo,
    tree: &str,
    scratch_dir: &Path,
    excludes: &[String],
) -> Result<Vec<String>, GitError> {
    let tmp_index = scratch_index(scratch_dir)?;
    let rt = ["read-tree", tree];
    check(
        &rt,
        git_command(&repo.root)
            .env("GIT_INDEX_FILE", &tmp_index)
            .args(rt)
            .output_gated()?,
    )?;
    let mut args: Vec<String> = ["ls-files", "-o", "--exclude-standard", "-z"]
        .iter()
        .map(|s| (*s).to_owned())
        .collect();
    for e in excludes {
        let e = e.trim_matches('/');
        if !e.is_empty() {
            args.push(format!("--exclude=/{e}/"));
        }
    }
    let argv: Vec<&str> = args.iter().map(String::as_str).collect();
    let out = check(
        &argv,
        git_command(&repo.root)
            .env("GIT_INDEX_FILE", &tmp_index)
            .args(&argv)
            .output_gated()?,
    )?;
    fs::remove_file(&tmp_index).ok();
    Ok(String::from_utf8_lossy(&out.stdout)
        .split('\0')
        .filter(|p| !p.is_empty() && !p.ends_with('/'))
        .map(str::to_owned)
        .collect())
}

fn scratch_index(scratch_dir: &Path) -> Result<PathBuf, GitError> {
    fs::create_dir_all(scratch_dir).map_err(at("mkdir -p", scratch_dir))?;
    let tmp_index = scratch_dir.join("materialize-index");
    fs::remove_file(&tmp_index).ok();
    Ok(tmp_index)
}

/// Every path `tree` names — blobs, symlinks, subtrees and gitlinks — relative to the root.
/// A name that is not UTF-8 is converted lossily.
pub fn tree_names(
    repo: &GitRepo,
    tree: &str,
) -> Result<std::collections::BTreeSet<String>, GitError> {
    let out = repo.run(&[
        "ls-tree",
        "-r",
        "-t",
        "-z",
        "--name-only",
        "--full-tree",
        tree,
    ])?;
    Ok(out
        .stdout
        .split(|b| *b == 0)
        .filter(|p| !p.is_empty())
        .map(|p| String::from_utf8_lossy(p).into_owned())
        .collect())
}

/// Rebuild the real index from `tree` (used when the workspace class carried no index).
pub fn read_tree_into_index(repo: &GitRepo, tree: &str) -> Result<(), GitError> {
    repo.run(&["read-tree", tree]).map(|_| ())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fixture() -> (tempfile::TempDir, GitRepo) {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path().join("r");
        let repo = GitRepo::init(&root).unwrap();
        repo.run(&["config", "user.email", "t@t"]).unwrap();
        repo.run(&["config", "user.name", "t"]).unwrap();
        fs::write(root.join("a"), "a\n").unwrap();
        repo.run(&["add", "a"]).unwrap();
        repo.run(&["commit", "-q", "-m", "one"]).unwrap();
        (dir, repo)
    }

    /// A repository with no reflog (nothing ever updated a ref through git) has no tips, and
    /// asking is not an error.
    #[test]
    fn reflog_tips_of_a_repo_without_a_reflog_is_empty() {
        let dir = tempfile::tempdir().unwrap();
        let repo = GitRepo::init(&dir.path().join("r")).unwrap();
        assert!(!repo.git_dir.join("logs").exists());
        assert!(repo.reflog_tips().unwrap().is_empty());
        let (_dir, committed) = fixture();
        assert_eq!(committed.reflog_tips().unwrap().len(), 1);
    }

    #[test]
    fn closure_has_pseudo_refs_and_pack_round_trips() {
        let (dir, repo) = fixture();
        fs::write(repo.root.join("b"), "uncommitted\n").unwrap();
        let scratch = dir.path().join("scratch");
        let r = build_git_pack(&repo, &scratch, &[], &[]).unwrap();
        assert_eq!(r.fsck, FsckStatus::Verified);
        assert!(r.closure.refs.contains_key(WORKTREE_TREE_REF));
        assert!(r.closure.refs.contains_key(INDEX_TREE_REF));
        assert!(
            r.closure.refs.contains_key("refs/heads/main")
                || r.closure.refs.contains_key("refs/heads/master")
        );
        let pack = r.pack.as_ref().unwrap();
        assert!(pack.objects >= 4);
        assert!(pack.idx_path.exists());

        // Nothing new: no pack.
        let tips = r.closure.tips.clone();
        let r2 = build_git_pack(&repo, &scratch, &tips, &[]).unwrap();
        assert!(r2.pack.is_none());

        // Materialize into a fresh repo and check the worktree tree out.
        let fresh = GitRepo::init(&dir.path().join("fresh")).unwrap();
        let bytes = fs::read(&pack.path).unwrap();
        install_pack(&fresh, &pack.sha256, &bytes, None).unwrap();
        write_packed_refs(&fresh, &r.closure.refs, &r.closure.symrefs).unwrap();
        write_head(&fresh, &r.closure.head).unwrap();
        checkout_tree(&fresh, &r.closure.refs[WORKTREE_TREE_REF], &scratch).unwrap();
        read_tree_into_index(&fresh, &r.closure.refs[INDEX_TREE_REF]).unwrap();
        assert_eq!(
            fs::read_to_string(fresh.root.join("b")).unwrap(),
            "uncommitted\n"
        );
        assert_eq!(fresh.fsck().unwrap(), FsckStatus::Verified);
        assert_eq!(
            fresh.status_porcelain().unwrap(),
            repo.status_porcelain().unwrap()
        );
        assert!(
            !fresh
                .refs()
                .unwrap()
                .keys()
                .any(|k| k.starts_with(PSEUDO_REF_PREFIX))
        );
    }

    /// A tracked file that matches `.gitignore` stays in the worktree tree, with or without an
    /// index on disk: tracked always wins, ignore rules only sort untracked paths.
    #[test]
    fn tracked_files_matching_gitignore_stay_in_the_worktree_tree() {
        let (dir, repo) = fixture();
        let root = repo.root.clone();
        fs::write(root.join(".gitignore"), "core.*\n").unwrap();
        fs::create_dir_all(root.join("tooling")).unwrap();
        fs::write(root.join("tooling/core.json"), "{}\n").unwrap();
        fs::write(root.join("core.1234"), "dump\n").unwrap();
        repo.run(&["add", "-f", ".gitignore", "tooling/core.json"])
            .unwrap();
        repo.run(&["commit", "-q", "-m", "core"]).unwrap();
        fs::write(root.join("tooling/core.json"), "{\"edited\":true}\n").unwrap();
        let scratch = dir.path().join("scratch");
        let names =
            |tree: &str| stdout_string(&repo.run(&["ls-tree", "-r", "--name-only", tree]).unwrap());

        let (tree, _) = repo.worktree_tree(&scratch, &[]).unwrap();
        let listed = names(&tree);
        assert!(listed.contains("tooling/core.json"), "{listed}");
        assert!(!listed.contains("core.1234"), "{listed}");
        let out = repo
            .run(&["show", &format!("{tree}:tooling/core.json")])
            .unwrap();
        assert_eq!(
            stdout_string(&out),
            "{\"edited\":true}",
            "the edit is in the tree"
        );

        // No index at all (a materialized base whose workspace class carried none): the tree
        // is seeded from HEAD, so the tracked file keeps its standing.
        fs::remove_file(repo.git_dir.join("index")).unwrap();
        let (tree_without_index, _) = repo.worktree_tree(&scratch, &[]).unwrap();
        assert_eq!(tree_without_index, tree);
        assert!(
            !repo.git_dir.join("index").exists(),
            "the real index is never written"
        );
        assert!(stored_tips(&repo).unwrap().iter().all(|t| t != &tree));
    }

    /// Every nested repository is named in an `:(exclude)` pathspec ahead of `git add -A`, so
    /// the add succeeds without `--ignore-errors` (git 2.52 makes a commit-less nested
    /// repository fatal even with it) alongside an ignored exclude, which is never named. The
    /// tree carries neither nested repository; both come back for the chunked class.
    #[test]
    fn nested_repositories_are_excluded_from_the_add_without_ignore_errors() {
        let (dir, repo) = fixture();
        let root = repo.root.clone();
        fs::write(root.join(".gitignore"), "ign/\n").unwrap();
        // Commit-less nested repository, one with a commit, one under an ignored directory.
        let nested_a = GitRepo::init(&root.join("vendor/x")).unwrap();
        fs::write(nested_a.root.join("v.txt"), "vendored\n").unwrap();
        let nested_b = GitRepo::init(&root.join("vendor/y")).unwrap();
        nested_b.run(&["config", "user.email", "t@t"]).unwrap();
        nested_b.run(&["config", "user.name", "t"]).unwrap();
        fs::write(nested_b.root.join("w.txt"), "committed\n").unwrap();
        nested_b.run(&["add", "w.txt"]).unwrap();
        nested_b.run(&["commit", "-q", "-m", "w"]).unwrap();
        GitRepo::init(&root.join("ign/z")).unwrap();
        fs::write(root.join("plain.txt"), "plain\n").unwrap();
        fs::create_dir_all(root.join("keep-out")).unwrap();
        fs::write(root.join("keep-out/k.txt"), "k\n").unwrap();

        assert_eq!(
            repo.nested_repositories(None).unwrap(),
            vec!["vendor/x".to_owned(), "vendor/y".to_owned()],
            "ignored nested repositories are not enumerated"
        );

        let scratch = dir.path().join("scratch");
        fs::create_dir_all(&scratch).unwrap();
        let tmp_index = scratch.join("idx");
        fs::copy(repo.git_dir.join("index"), &tmp_index).unwrap();
        let excludes = vec!["ign".to_owned(), "keep-out/".to_owned()];
        let add = repo.worktree_add_args(&tmp_index, &excludes).unwrap();
        let args = &add.pathspecs;
        assert_eq!(
            add.nested,
            vec!["vendor/x".to_owned(), "vendor/y".to_owned()]
        );
        assert!(args.contains(&":(exclude)vendor/x".to_owned()), "{args:?}");
        assert!(args.contains(&":(exclude)vendor/y".to_owned()), "{args:?}");
        assert!(args.contains(&":(exclude)keep-out".to_owned()), "{args:?}");
        assert!(
            !args.iter().any(|a| a.starts_with(":(exclude)ign")),
            "an ignored exclude is never named: {args:?}"
        );

        // The argv works on its own: drop the flag and run it.
        let dashes = "--".to_owned();
        let without_flag: Vec<&String> = add
            .args
            .iter()
            .filter(|a| *a != "--ignore-errors")
            .chain(std::iter::once(&dashes))
            .chain(args.iter())
            .collect();
        let out = git_command(&root)
            .env("GIT_INDEX_FILE", &tmp_index)
            .args(&without_flag)
            .output()
            .unwrap();
        assert!(
            out.status.success(),
            "git {without_flag:?}: {}",
            String::from_utf8_lossy(&out.stderr)
        );
        let out = git_command(&root)
            .env("GIT_INDEX_FILE", &tmp_index)
            .args(["ls-files", "-s"])
            .output()
            .unwrap();
        let listing = String::from_utf8_lossy(&out.stdout).to_string();
        assert!(listing.contains("plain.txt"), "{listing}");
        assert!(!listing.contains("vendor/"), "{listing}");
        assert!(!listing.contains("keep-out"), "{listing}");
        assert!(!listing.contains("ign/"), "{listing}");

        // The helper itself: same tree, both nested repositories reported.
        let (tree, gitlinks) = repo.worktree_tree(&scratch, &excludes).unwrap();
        assert_eq!(gitlinks, vec!["vendor/x".to_owned(), "vendor/y".to_owned()]);
        let out = repo.run(&["ls-tree", "-r", "--name-only", &tree]).unwrap();
        let names = stdout_string(&out);
        assert!(names.contains("plain.txt"), "{names}");
        assert!(!names.contains("vendor"), "{names}");

        // A tracked gitlink (an embedded repository someone already added) is treated alike:
        // excluded from the add, its index entry kept, reported for the chunked class.
        repo.run(&["-c", "advice.addEmbeddedRepo=false", "add", "vendor/y"])
            .unwrap();
        assert_eq!(
            repo.nested_repositories(None).unwrap(),
            vec!["vendor/x".to_owned(), "vendor/y".to_owned()]
        );
        let (tree, gitlinks) = repo.worktree_tree(&scratch, &excludes).unwrap();
        assert_eq!(gitlinks, vec!["vendor/x".to_owned(), "vendor/y".to_owned()]);
        let out = repo.run(&["ls-tree", "-r", &tree]).unwrap();
        let entries = stdout_string(&out);
        assert!(entries.contains("160000 commit"), "{entries}");
        assert!(!entries.contains("vendor/x"), "{entries}");
    }

    /// An annotated tag restored through `packed-refs` still peels to its commit: the file
    /// never claims a peel trait it does not carry the `^` lines for (checked on the file
    /// itself, so it holds whichever git runs it), and git sees the tag as annotated.
    #[test]
    fn an_annotated_tag_in_packed_refs_still_peels() {
        let (dir, repo) = fixture();
        repo.run(&["tag", "-a", "v1", "-m", "v1"]).unwrap();
        repo.run(&["tag", "light"]).unwrap();
        let scratch = dir.path().join("scratch");
        let r = build_git_pack(&repo, &scratch, &[], &[]).unwrap();
        let fresh = GitRepo::init(&dir.path().join("fresh")).unwrap();
        let pack = r.pack.as_ref().unwrap();
        install_pack(&fresh, &pack.sha256, &fs::read(&pack.path).unwrap(), None).unwrap();
        write_packed_refs(&fresh, &r.closure.refs, &r.closure.symrefs).unwrap();
        write_head(&fresh, &r.closure.head).unwrap();

        let text = fs::read_to_string(fresh.common_dir.join("packed-refs")).unwrap();
        let header = text.lines().next().unwrap_or_default();
        let claims_peeled = header.starts_with("# pack-refs with:")
            && header
                .split_whitespace()
                .any(|t| t == "peeled" || t == "fully-peeled");
        let lines: Vec<&str> = text.lines().collect();
        for (i, line) in lines.iter().enumerate() {
            let Some((sha, name)) = line.split_once(' ') else {
                continue;
            };
            if line.starts_with('#') || line.starts_with('^') {
                continue;
            }
            let kind = stdout_string(&fresh.run(&["cat-file", "-t", sha]).unwrap());
            if claims_peeled && kind.trim() == "tag" {
                let peeled =
                    stdout_string(&fresh.run(&["rev-parse", &format!("{sha}^{{}}")]).unwrap());
                assert_eq!(
                    lines.get(i + 1).copied(),
                    Some(format!("^{}", peeled.trim()).as_str()),
                    "{name} is an annotated tag the peel trait leaves unpeeled:\n{text}"
                );
            }
        }

        let peel = |dir: &GitRepo| {
            stdout_string(
                &dir.run(&[
                    "for-each-ref",
                    "--format=%(refname) %(objectname) %(*objectname)",
                ])
                .unwrap(),
            )
        };
        assert_eq!(peel(&fresh), peel(&repo));
        let describe = |dir: &GitRepo| stdout_string(&dir.run(&["describe", "HEAD"]).unwrap());
        assert_eq!(describe(&fresh).trim(), "v1");
    }
}
