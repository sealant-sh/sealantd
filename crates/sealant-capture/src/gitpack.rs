//! Git class: the closure of refs, `HEAD`, index, stash and reflog tips read first, packed with
//! `git pack-objects --revs` against the previous capture's tips as negatives (never `--thin`),
//! indexed with `git index-pack`, checked with `git fsck --connectivity-only`; bounded retries
//! when refs move or an object goes missing mid-pack (ADR-0015 *Snap rules*). Also the
//! materialize-side helpers: install a pack, write `packed-refs` and `HEAD`, check out a tree.

use std::collections::BTreeMap;
use std::fs::{self, File};
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};

use crate::chunk::sha256_hex;
use crate::manifest::{FsckStatus, INDEX_TREE_REF, PSEUDO_REF_PREFIX, WORKTREE_TREE_REF};

/// Bounded attempts when refs move or objects vanish between the read and the pack.
pub const PACK_ATTEMPTS: u32 = 3;

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
    /// I/O.
    #[error(transparent)]
    Io(#[from] io::Error),
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

impl GitRepo {
    /// Open the repository whose working tree is `root`.
    pub fn open(root: &Path) -> Result<Self, GitError> {
        let out = git_command(root)
            .args(["rev-parse", "--git-dir", "--git-common-dir"])
            .output()?;
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
        fs::create_dir_all(root)?;
        if !root.join(".git").exists() {
            let args = ["init", "-q"];
            check(&args, git_command(root).args(args).output()?)?;
        }
        Self::open(root)
    }

    /// Run a git command in the working tree and return its output on success.
    pub fn run(&self, args: &[&str]) -> Result<Output, GitError> {
        check(args, git_command(&self.root).args(args).output()?)
    }

    /// Run a git command with stdin.
    fn run_with_stdin(&self, args: &[&str], stdin: &[u8]) -> Result<Output, GitError> {
        let mut child = git_command(&self.root)
            .args(args)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()?;
        if let Some(mut pipe) = child.stdin.take() {
            // A closed pipe (git exited early) surfaces as the command's status.
            let _ = pipe.write_all(stdin);
        }
        check(args, child.wait_with_output()?)
    }

    /// Ref name → sha for every ref (including `refs/stash`).
    pub fn refs(&self) -> Result<BTreeMap<String, String>, GitError> {
        let out = self.run(&["for-each-ref", "--format=%(refname) %(objectname)"])?;
        Ok(stdout_string(&out)
            .lines()
            .filter_map(|l| l.split_once(' '))
            .map(|(r, s)| (r.to_owned(), s.to_owned()))
            .collect())
    }

    /// `HEAD` as a ref name (symbolic) or a sha (detached).
    pub fn head(&self) -> Result<String, GitError> {
        let out = git_command(&self.root)
            .args(["symbolic-ref", "-q", "HEAD"])
            .output()?;
        if out.status.success() {
            return Ok(stdout_string(&out));
        }
        let out = self.run(&["rev-parse", "--verify", "-q", "HEAD"]);
        match out {
            Ok(o) => Ok(stdout_string(&o)),
            Err(_) => Ok(fs::read_to_string(self.git_dir.join("HEAD"))
                .map(|s| s.trim().trim_start_matches("ref: ").to_owned())
                .unwrap_or_else(|_| "refs/heads/main".to_owned())),
        }
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
        fs::create_dir_all(scratch_dir)?;
        let tmp_index = scratch_dir.join("index-tree");
        fs::copy(&real_index, &tmp_index)?;
        let out = git_command(&self.root)
            .env("GIT_INDEX_FILE", &tmp_index)
            .args(["write-tree"])
            .output()?;
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

    /// Tree of the working tree: a throwaway copy of the index with `git add -A` applied, then
    /// `write-tree`. Nested repositories become gitlinks (or fail to index when they have no
    /// commit); their paths are returned beside the sha so the chunked class can carry them.
    pub fn worktree_tree(
        &self,
        scratch_dir: &Path,
        excludes: &[String],
    ) -> Result<(String, Vec<String>), GitError> {
        fs::create_dir_all(scratch_dir)?;
        let tmp_index = scratch_dir.join("snap-index");
        let real_index = self.git_dir.join("index");
        if real_index.exists() {
            fs::copy(&real_index, &tmp_index)?;
        } else {
            fs::remove_file(&tmp_index).ok();
        }
        // `--ignore-errors` keeps going past paths git cannot index (a nested repository with
        // no commit checked out); those paths are reported so the chunked class can carry them.
        let mut add: Vec<String> = ["add", "-A", "--ignore-errors", "--", "."]
            .iter()
            .map(|s| (*s).to_owned())
            .collect();
        add.extend(
            excludes
                .iter()
                .map(|e| format!(":(exclude){}", e.trim_matches('/'))),
        );
        let out = git_command(&self.root)
            .env("GIT_INDEX_FILE", &tmp_index)
            .args(&add)
            .output()?;
        let stderr = String::from_utf8_lossy(&out.stderr).to_string();
        let mut unindexed: Vec<String> = stderr
            .lines()
            .filter_map(|l| l.strip_prefix("error: unable to index file '"))
            .filter_map(|l| l.strip_suffix('\''))
            .map(|p| p.trim_end_matches('/').to_owned())
            .collect();
        if !out.status.success() && unindexed.is_empty() {
            return Err(GitError::Command {
                args: add.join(" "),
                stderr: stderr.trim().to_owned(),
            });
        }
        let wt = ["write-tree"];
        let out = check(
            &wt,
            git_command(&self.root)
                .env("GIT_INDEX_FILE", &tmp_index)
                .args(wt)
                .output()?,
        )?;
        let tree = stdout_string(&out);
        let ls = ["ls-files", "-s", "-z"];
        let out = check(
            &ls,
            git_command(&self.root)
                .env("GIT_INDEX_FILE", &tmp_index)
                .args(ls)
                .output()?,
        )?;
        let mut gitlinks: Vec<String> = String::from_utf8_lossy(&out.stdout)
            .split('\0')
            .filter(|l| l.starts_with("160000 "))
            .filter_map(|l| l.split_once('\t').map(|(_, p)| p.to_owned()))
            .collect();
        gitlinks.append(&mut unindexed);
        gitlinks.sort();
        gitlinks.dedup();
        fs::remove_file(&tmp_index).ok();
        Ok((tree, gitlinks))
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
            .output()?;
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

/// The closure read before packing.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Closure {
    /// Refs plus the two pseudo-refs.
    pub refs: BTreeMap<String, String>,
    /// `HEAD`.
    pub head: String,
    /// Every positive tip: ref values, `HEAD`, reflog entries, index and worktree trees (or the
    /// index blobs when the index is unmerged).
    pub tips: Vec<String>,
    /// Paths of nested repositories (gitlinks in the worktree tree).
    pub gitlinks: Vec<String>,
}

/// Read the closure (refs, `HEAD`, index, stash, reflog, worktree) in that order. `excludes` are
/// pathspecs (relative to the root) left out of the worktree tree: the daemon directory.
pub fn read_closure(
    repo: &GitRepo,
    scratch_dir: &Path,
    excludes: &[String],
) -> Result<Closure, GitError> {
    let mut refs = repo.refs()?;
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
    let (wt, gitlinks) = repo.worktree_tree(scratch_dir, excludes)?;
    refs.insert(WORKTREE_TREE_REF.to_owned(), wt.clone());
    tips.push(wt);
    tips.sort();
    tips.dedup();
    Ok(Closure {
        refs,
        head,
        tips,
        gitlinks,
    })
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
    let file = File::create(&tmp)?;
    let args = ["pack-objects", "--revs", "--stdout", "-q"];
    let mut child = git_command(&repo.root)
        .args(args)
        .stdin(Stdio::piped())
        .stdout(Stdio::from(file))
        .stderr(Stdio::piped())
        .spawn()?;
    if let Some(mut pipe) = child.stdin.take() {
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
    // `git index-pack <file.pack>` writes `<file>.idx` beside it and verifies the pack.
    let tmp_str = tmp.to_string_lossy().to_string();
    let args = ["index-pack", &tmp_str];
    check(&args, git_command(&repo.root).args(args).output()?)?;
    let bytes = fs::read(&tmp)?;
    let sha256 = sha256_hex(&bytes);
    let path = out_dir.join(&sha256);
    let idx_path = out_dir.join(format!("{sha256}.idx"));
    fs::rename(&tmp, &path)?;
    fs::rename(tmp.with_extension("idx"), &idx_path)?;
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
    fs::create_dir_all(out_dir)?;
    let negatives = repo.existing(previous_tips)?;
    let mut last: Option<(Option<FinishedGitPack>, Closure)> = None;
    for attempt in 1..=PACK_ATTEMPTS {
        let closure = read_closure(repo, out_dir, excludes)?;
        let packed = match pack_once(repo, out_dir, &closure.tips, &negatives, attempt) {
            Ok(p) => p,
            Err(e) => {
                tracing::warn!(attempt, error = %e, "pack-objects failed; re-reading refs");
                continue;
            }
        };
        let refs_after = repo.refs()?;
        let head_after = repo.head()?;
        let moved = closure
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
        None => read_closure(repo, out_dir, excludes)?,
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

/// Install a pack (and its index; regenerated with `git index-pack` when absent) into
/// `objects/pack`.
pub fn install_pack(
    repo: &GitRepo,
    sha256: &str,
    pack: &[u8],
    idx: Option<&[u8]>,
) -> Result<(), GitError> {
    let dir = repo.common_dir.join("objects").join("pack");
    fs::create_dir_all(&dir)?;
    let pack_path = dir.join(format!("pack-{sha256}.pack"));
    let idx_path = dir.join(format!("pack-{sha256}.idx"));
    if pack_path.exists() && idx_path.exists() {
        return Ok(());
    }
    let tmp = dir.join(format!("tmp-capture-{sha256}.pack"));
    fs::write(&tmp, pack)?;
    match idx {
        Some(bytes) => fs::write(tmp.with_extension("idx"), bytes)?,
        None => {
            let tmp_str = tmp.to_string_lossy().to_string();
            let args = ["index-pack", &tmp_str];
            check(&args, git_command(&repo.root).args(args).output()?)?;
        }
    }
    fs::rename(tmp.with_extension("idx"), &idx_path)?;
    fs::rename(&tmp, &pack_path)?;
    Ok(())
}

/// Write `packed-refs` from `refs`, skipping the pseudo-refs, and remove loose refs that would
/// shadow it.
pub fn write_packed_refs(repo: &GitRepo, refs: &BTreeMap<String, String>) -> Result<(), GitError> {
    let mut text = String::from("# pack-refs with: peeled fully-peeled sorted \n");
    for (name, sha) in refs {
        if name.starts_with(PSEUDO_REF_PREFIX) {
            continue;
        }
        text.push_str(sha);
        text.push(' ');
        text.push_str(name);
        text.push('\n');
        let loose = repo.common_dir.join(name);
        if loose.is_file() {
            fs::remove_file(loose)?;
        }
    }
    let path = repo.common_dir.join("packed-refs");
    let tmp = repo.common_dir.join("packed-refs.capture-tmp");
    fs::write(&tmp, text)?;
    fs::rename(tmp, path)?;
    Ok(())
}

/// Write `HEAD` (a symbolic ref or a detached sha).
pub fn write_head(repo: &GitRepo, head: &str) -> Result<(), GitError> {
    let text = if head.starts_with("refs/") {
        format!("ref: {head}\n")
    } else {
        format!("{head}\n")
    };
    fs::write(repo.git_dir.join("HEAD"), text)?;
    Ok(())
}

/// Check `tree` out into the working tree through a throwaway index (files only; nothing is
/// removed), then either restore the real index from `index_bytes` or read it from `index_tree`.
pub fn checkout_tree(repo: &GitRepo, tree: &str, scratch_dir: &Path) -> Result<(), GitError> {
    fs::create_dir_all(scratch_dir)?;
    let tmp_index = scratch_dir.join("materialize-index");
    fs::remove_file(&tmp_index).ok();
    let rt = ["read-tree", tree];
    check(
        &rt,
        git_command(&repo.root)
            .env("GIT_INDEX_FILE", &tmp_index)
            .args(rt)
            .output()?,
    )?;
    let co = ["checkout-index", "-a", "-f", "-q"];
    check(
        &co,
        git_command(&repo.root)
            .env("GIT_INDEX_FILE", &tmp_index)
            .args(co)
            .output()?,
    )?;
    fs::remove_file(&tmp_index).ok();
    Ok(())
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
        write_packed_refs(&fresh, &r.closure.refs).unwrap();
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
}
