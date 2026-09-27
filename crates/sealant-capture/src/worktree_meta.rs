//! The worktree metadata overlay ([`crate::manifest::WorktreeMeta`]): what a git tree drops
//! about the working tree it describes. A tree carries a file's bytes and whether it is
//! executable; a checkout writes every file `0644`/`0755` under the umask with the time of the
//! checkout, creates no directory git does not track (an empty one is lost) and writes every
//! name of a hardlinked file as a file of its own. The overlay records, for the paths the
//! worktree tree names and every directory of the working tree that no other class carries:
//!
//! - exact mode bits (`st_mode & 0o7777`) of files and directories, the root included;
//! - mtimes in nanoseconds of files, symlinks and directories;
//! - directories git does not track (empty ones, and ones holding only empty ones);
//! - hardlink groups among the worktree tree's files.
//!
//! [`capture`] reads it from disk after the worktree tree is written; [`apply`] brings a disk
//! the git class checked out to it — after every other class, since restoring an ignored file
//! or a bulk directory moves the mtime of the directory it lands in. `apply` fails on the
//! first path it cannot bring to the document (missing, the wrong kind, a failed `chmod`,
//! `utimensat` or link) rather than leaving a partly restored tree reported as restored.
//!
//! Out of scope, by class: `.git`, the daemon directory and staging, the harness home, nested
//! repositories and bulk directories (the chunked classes carry their own metadata), and every
//! directory git ignores (the workspace class carries it). A path that is not UTF-8 is skipped
//! with a warning (the document is JSON, as dir objects are).

use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::fs::{self, Metadata};
use std::io;
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::path::{Component, Path, PathBuf};

use nix::sys::stat::{UtimensatFlags, utimensat};
use nix::sys::time::TimeSpec;
use serde::{Deserialize, Serialize};

use crate::gitpack::{GitError, GitRepo};
use crate::index::{has_component_in, mtime_ns};
use crate::manifest::WORKTREE_META_FORMAT;

/// Overlay errors.
#[derive(Debug, thiserror::Error)]
pub enum MetaError {
    /// A git command failed.
    #[error(transparent)]
    Git(#[from] GitError),
    /// Reading or setting a path's metadata failed.
    #[error("worktree metadata {path}: {source}")]
    Io {
        /// The path (worktree-relative; `""` is the root).
        path: String,
        /// The error.
        source: io::Error,
    },
    /// The disk does not hold what the document names (after a checkout of its tree).
    #[error("worktree metadata {path}: {reason}")]
    Mismatch {
        /// The path.
        path: String,
        /// What was found.
        reason: String,
    },
    /// The document is malformed.
    #[error("worktree metadata document: {0}")]
    BadDocument(String),
}

fn io_err(path: &str) -> impl FnOnce(io::Error) -> MetaError + '_ {
    move |source| MetaError::Io {
        path: path.to_owned(),
        source,
    }
}

/// What a path is.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum MetaKind {
    /// A regular file of the worktree tree.
    File,
    /// A symlink of the worktree tree.
    Symlink,
    /// A directory (tracked or not).
    Dir,
}

/// One path of the working tree.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MetaEntry {
    /// Worktree-relative, `/`-separated; `""` is the root.
    pub path: String,
    /// Kind.
    pub kind: MetaKind,
    /// `st_mode & 0o7777`; absent for a symlink (its mode is not settable).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mode: Option<u32>,
    /// Modification time, nanoseconds since the Unix epoch.
    pub mtime: i64,
}

/// The overlay document: entries sorted by path, hardlink groups sorted (each group's members
/// sorted, the first being the one the others link to). Encodes deterministically, so an
/// unchanged working tree encodes to the same bytes.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct MetaDocument {
    /// [`WORKTREE_META_FORMAT`].
    pub format: u32,
    /// Every path, sorted.
    pub entries: Vec<MetaEntry>,
    /// Paths sharing one inode, each group of two or more files of `entries`.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub hardlinks: Vec<Vec<String>>,
}

impl MetaDocument {
    /// Canonical bytes (compact JSON; the order is fixed by construction).
    #[must_use]
    pub fn encode(&self) -> Vec<u8> {
        // Serializing a struct cannot fail.
        serde_json::to_vec(self).unwrap_or_default()
    }

    /// Decode, refusing a format this build does not read and any path that is not a plain
    /// relative path.
    pub fn decode(bytes: &[u8]) -> Result<Self, MetaError> {
        let doc: Self =
            serde_json::from_slice(bytes).map_err(|e| MetaError::BadDocument(e.to_string()))?;
        if doc.format == 0 || doc.format > WORKTREE_META_FORMAT {
            return Err(MetaError::BadDocument(format!(
                "format {}; this build reads up to {WORKTREE_META_FORMAT}",
                doc.format
            )));
        }
        let mut kinds: HashMap<&str, MetaKind> = HashMap::new();
        for e in &doc.entries {
            if !is_plain_relative(&e.path) {
                return Err(MetaError::BadDocument(format!("path {:?}", e.path)));
            }
            if e.kind != MetaKind::Symlink && e.mode.is_none() {
                return Err(MetaError::BadDocument(format!("{:?} has no mode", e.path)));
            }
            kinds.insert(&e.path, e.kind);
        }
        for group in &doc.hardlinks {
            if group.len() < 2
                || group
                    .iter()
                    .any(|p| kinds.get(p.as_str()) != Some(&MetaKind::File))
            {
                return Err(MetaError::BadDocument(format!(
                    "hardlink group {group:?} does not name files of the document"
                )));
            }
        }
        Ok(doc)
    }
}

/// `""` or a relative path of normal components.
fn is_plain_relative(p: &str) -> bool {
    p.is_empty()
        || (!p.starts_with('/')
            && !p.ends_with('/')
            && p.split('/')
                .all(|c| !c.is_empty() && c != "." && c != ".." && !c.contains('\0')))
}

/// Which directories of the working tree the overlay covers: everything under `root` but the
/// paths other classes carry.
#[derive(Debug, Clone)]
pub struct MetaScope {
    /// Worktree root.
    pub root: PathBuf,
    /// Root-relative paths left out (the daemon directory, a staging directory under the root).
    pub excludes: Vec<String>,
    /// Directory names the bulk class carries wherever they appear.
    pub bulk_dirs: Vec<String>,
    /// Root-relative nested repositories (the workspace class carries them).
    pub nested: Vec<String>,
    /// Absolute paths left out (the staging directory, the harness home).
    pub skip_abs: Vec<PathBuf>,
}

impl MetaScope {
    /// Directories under the root the overlay covers, relative (`""` is the root), with their
    /// metadata: the walk prunes `.git`, the excludes, bulk directories, nested repositories
    /// and every directory git reports ignored. A directory that cannot be listed is kept and
    /// not descended into (git cannot see into it either); one that vanished mid-walk is
    /// skipped.
    fn directories(&self, repo: &GitRepo) -> Result<BTreeMap<String, Metadata>, MetaError> {
        let out = repo.run(&[
            "ls-files",
            "-o",
            "-i",
            "--exclude-standard",
            "--directory",
            "-z",
        ])?;
        let ignored: BTreeSet<String> = out
            .stdout
            .split(|b| *b == 0)
            .filter_map(|p| std::str::from_utf8(p).ok())
            .filter_map(|p| p.strip_suffix('/'))
            .map(str::to_owned)
            .collect();
        let under = |rel: &str, set: &[String]| {
            set.iter().any(|e| {
                let e = e.trim_matches('/');
                !e.is_empty()
                    && (rel == e || rel.strip_prefix(e).is_some_and(|r| r.starts_with('/')))
            })
        };
        let mut dirs = BTreeMap::new();
        let walker = walkdir::WalkDir::new(&self.root)
            .follow_links(false)
            .sort_by_file_name()
            .into_iter()
            .filter_entry(|e| {
                if !e.file_type().is_dir() {
                    return false;
                }
                if e.depth() == 0 {
                    return true;
                }
                let Ok(rel) = e.path().strip_prefix(&self.root) else {
                    return false;
                };
                let Some(rel_str) = rel.to_str() else {
                    tracing::warn!(path = %rel.display(), "worktree metadata: not UTF-8; skipped");
                    return false;
                };
                !(e.file_name() == ".git"
                    || under(rel_str, &self.excludes)
                    || under(rel_str, &self.nested)
                    || ignored.contains(rel_str)
                    || has_component_in(rel, &self.bulk_dirs)
                    || self.skip_abs.iter().any(|s| s == e.path()))
            });
        for entry in walker {
            let entry = match entry {
                Ok(entry) => entry,
                Err(error) => {
                    let path = error
                        .path()
                        .map(|p| p.display().to_string())
                        .unwrap_or_default();
                    match error.io_error().map(io::Error::kind) {
                        Some(io::ErrorKind::NotFound) => continue,
                        Some(io::ErrorKind::PermissionDenied) => {
                            tracing::warn!(%path, "worktree metadata: cannot list; not descended");
                            continue;
                        }
                        _ => {
                            return Err(MetaError::Io {
                                path,
                                source: error.into(),
                            });
                        }
                    }
                }
            };
            let rel = entry
                .path()
                .strip_prefix(&self.root)
                .unwrap_or(entry.path());
            let Some(rel) = rel.to_str() else { continue };
            let meta = match fs::symlink_metadata(entry.path()) {
                Ok(meta) if meta.is_dir() => meta,
                Ok(_) => continue,
                Err(e) if e.kind() == io::ErrorKind::NotFound => continue,
                Err(e) => return Err(io_err(rel)(e)),
            };
            dirs.insert(rel.to_owned(), meta);
        }
        Ok(dirs)
    }
}

/// One `git ls-tree -r -t` record of the worktree tree.
struct TreePath {
    path: String,
    kind: MetaKind,
    blob: String,
}

fn tree_paths(repo: &GitRepo, tree: &str) -> Result<Vec<TreePath>, MetaError> {
    let out = repo.run(&["ls-tree", "-r", "-t", "-z", "--full-tree", tree])?;
    let mut paths = Vec::new();
    for record in out.stdout.split(|b| *b == 0).filter(|r| !r.is_empty()) {
        let Some(tab) = record.iter().position(|b| *b == b'\t') else {
            continue;
        };
        let (head, path) = (&record[..tab], &record[tab + 1..]);
        let Ok(path) = std::str::from_utf8(path) else {
            tracing::warn!(path = %String::from_utf8_lossy(path), "worktree metadata: not UTF-8; skipped");
            continue;
        };
        let head = String::from_utf8_lossy(head);
        let mut fields = head.split(' ');
        let (mode, _, blob) = (
            fields.next().unwrap_or(""),
            fields.next(),
            fields.next().unwrap_or(""),
        );
        let kind = match mode {
            "100644" | "100755" => MetaKind::File,
            "120000" => MetaKind::Symlink,
            "040000" => MetaKind::Dir,
            // Gitlinks: the workspace class carries nested repositories.
            _ => continue,
        };
        paths.push(TreePath {
            path: path.to_owned(),
            kind,
            blob: blob.to_owned(),
        });
    }
    Ok(paths)
}

fn kind_of(meta: &Metadata) -> Option<MetaKind> {
    let ft = meta.file_type();
    if ft.is_symlink() {
        Some(MetaKind::Symlink)
    } else if ft.is_dir() {
        Some(MetaKind::Dir)
    } else if ft.is_file() {
        Some(MetaKind::File)
    } else {
        None
    }
}

fn entry_of(path: &str, kind: MetaKind, meta: &Metadata) -> MetaEntry {
    MetaEntry {
        path: path.to_owned(),
        kind,
        mode: (kind != MetaKind::Symlink).then(|| meta.mode() & 0o7777),
        mtime: mtime_ns(meta),
    }
}

fn abs_of(root: &Path, rel: &str) -> PathBuf {
    if rel.is_empty() {
        root.to_path_buf()
    } else {
        root.join(rel)
    }
}

/// Read the overlay of the working tree `worktree_tree` (the tree just written from it) plus
/// every directory in `scope`. A path that changed kind or vanished since the tree was written
/// is left out: the next capture sees the change. Any other failure to read a path fails.
pub fn capture(
    repo: &GitRepo,
    worktree_tree: &str,
    scope: &MetaScope,
) -> Result<MetaDocument, MetaError> {
    let mut entries: BTreeMap<String, MetaEntry> = BTreeMap::new();
    // (dev, ino) → (path, blob) of every file with more than one name.
    let mut inodes: BTreeMap<(u64, u64), Vec<(String, String)>> = BTreeMap::new();
    for tp in tree_paths(repo, worktree_tree)? {
        let meta = match fs::symlink_metadata(scope.root.join(&tp.path)) {
            Ok(meta) => meta,
            Err(e) if e.kind() == io::ErrorKind::NotFound => continue,
            Err(e) => return Err(io_err(&tp.path)(e)),
        };
        if kind_of(&meta) != Some(tp.kind) {
            continue;
        }
        if tp.kind == MetaKind::File && meta.nlink() > 1 {
            inodes
                .entry((meta.dev(), meta.ino()))
                .or_default()
                .push((tp.path.clone(), tp.blob.clone()));
        }
        entries.insert(tp.path.clone(), entry_of(&tp.path, tp.kind, &meta));
    }
    for (rel, meta) in scope.directories(repo)? {
        entries
            .entry(rel.clone())
            .or_insert_with(|| entry_of(&rel, MetaKind::Dir, &meta));
    }
    let mut hardlinks: Vec<Vec<String>> = inodes
        .into_values()
        .filter(|members| {
            members.len() > 1 && members.iter().all(|(_, blob)| *blob == members[0].1)
        })
        .map(|members| {
            let mut paths: Vec<String> = members.into_iter().map(|(p, _)| p).collect();
            paths.sort();
            paths
        })
        .collect();
    hardlinks.sort();
    Ok(MetaDocument {
        format: WORKTREE_META_FORMAT,
        entries: entries.into_values().collect(),
        hardlinks,
    })
}

/// Bring the disk under `scope.root` to `doc`, after the git class checked out its tree and
/// every other class was restored: create the directories it names that are missing, remove
/// the (empty) directories in scope it does not name, link hardlink groups, then set modes and
/// mtimes — files and symlinks first, then directories deepest first, so nothing written later
/// moves a directory's mtime. Only what differs is touched; returns how many paths changed.
/// Fails on the first path it cannot bring to the document.
pub fn apply(repo: &GitRepo, doc: &MetaDocument, scope: &MetaScope) -> Result<u64, MetaError> {
    let root = &scope.root;
    let mut changed = 0u64;
    // Directories: parents sort before children.
    for e in doc.entries.iter().filter(|e| e.kind == MetaKind::Dir) {
        let abs = abs_of(root, &e.path);
        match fs::symlink_metadata(&abs) {
            Ok(meta) if meta.is_dir() => {}
            Ok(meta) => {
                return Err(MetaError::Mismatch {
                    path: e.path.clone(),
                    reason: format!("a directory on the plan, a {:?} on disk", kind_of(&meta)),
                });
            }
            Err(err) if err.kind() == io::ErrorKind::NotFound => {
                fs::create_dir_all(&abs).map_err(io_err(&e.path))?;
                changed += 1;
            }
            Err(err) => return Err(io_err(&e.path)(err)),
        }
    }
    // Every other path is on disk as the checkout wrote it.
    for e in doc.entries.iter().filter(|e| e.kind != MetaKind::Dir) {
        let meta = fs::symlink_metadata(abs_of(root, &e.path)).map_err(io_err(&e.path))?;
        if kind_of(&meta) != Some(e.kind) {
            return Err(MetaError::Mismatch {
                path: e.path.clone(),
                reason: format!("a {:?} on the plan, a {:?} on disk", e.kind, kind_of(&meta)),
            });
        }
    }
    // Directories in scope the document does not name: an empty directory the plan dropped.
    // One that still holds something (a file another class owns) stays.
    let planned: BTreeSet<&str> = doc.entries.iter().map(|e| e.path.as_str()).collect();
    let mut stale: Vec<String> = scope
        .directories(repo)?
        .into_keys()
        .filter(|rel| !rel.is_empty() && !planned.contains(rel.as_str()))
        .collect();
    stale.sort_by(|a, b| b.len().cmp(&a.len()).then_with(|| a.cmp(b)));
    for rel in stale {
        match fs::remove_dir(root.join(&rel)) {
            Ok(()) => changed += 1,
            Err(e)
                if matches!(
                    e.kind(),
                    io::ErrorKind::DirectoryNotEmpty | io::ErrorKind::NotFound
                ) => {}
            Err(e) => return Err(io_err(&rel)(e)),
        }
    }
    // Hardlink groups: every member on the first member's inode.
    for group in &doc.hardlinks {
        let Some((first, rest)) = group.split_first() else {
            continue;
        };
        let canonical = root.join(first);
        let target = fs::symlink_metadata(&canonical).map_err(io_err(first))?;
        for member in rest {
            let abs = root.join(member);
            let meta = fs::symlink_metadata(&abs).map_err(io_err(member))?;
            if (meta.dev(), meta.ino()) == (target.dev(), target.ino()) {
                continue;
            }
            fs::remove_file(&abs).map_err(io_err(member))?;
            fs::hard_link(&canonical, &abs).map_err(io_err(member))?;
            changed += 1;
        }
    }
    // Files and symlinks, then directories deepest first.
    let mut dirs: Vec<&MetaEntry> = Vec::new();
    for e in &doc.entries {
        if e.kind == MetaKind::Dir {
            dirs.push(e);
            continue;
        }
        changed += u64::from(settle(root, e)?);
    }
    dirs.sort_by(|a, b| {
        depth(&b.path)
            .cmp(&depth(&a.path))
            .then_with(|| a.path.cmp(&b.path))
    });
    for e in dirs {
        changed += u64::from(settle(root, e)?);
    }
    Ok(changed)
}

fn depth(rel: &str) -> usize {
    if rel.is_empty() {
        0
    } else {
        Path::new(rel)
            .components()
            .filter(|c| matches!(c, Component::Normal(_)))
            .count()
    }
}

/// Set one path's mode and mtime where they differ; whether anything changed.
fn settle(root: &Path, e: &MetaEntry) -> Result<bool, MetaError> {
    let abs = abs_of(root, &e.path);
    let meta = fs::symlink_metadata(&abs).map_err(io_err(&e.path))?;
    let mut changed = false;
    if let Some(mode) = e.mode
        && e.kind != MetaKind::Symlink
        && meta.mode() & 0o7777 != mode
    {
        fs::set_permissions(&abs, fs::Permissions::from_mode(mode)).map_err(io_err(&e.path))?;
        changed = true;
    }
    if mtime_ns(&meta) != e.mtime {
        set_mtime_nofollow(&abs, e.mtime).map_err(io_err(&e.path))?;
        changed = true;
    }
    Ok(changed)
}

/// Set `abs`'s mtime (nanoseconds since the epoch) without following a symlink, so a
/// symlink gets its own mtime and a file is not opened (its mode may forbid that).
pub fn set_mtime_nofollow(abs: &Path, mtime_ns: i64) -> io::Result<()> {
    let mtime = TimeSpec::new(
        mtime_ns.div_euclid(1_000_000_000),
        mtime_ns.rem_euclid(1_000_000_000),
    );
    utimensat(
        nix::fcntl::AT_FDCWD,
        abs,
        &TimeSpec::UTIME_OMIT,
        &mtime,
        UtimensatFlags::NoFollowSymlink,
    )
    .map_err(io::Error::from)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn decode_refuses_unknown_formats_and_unsafe_paths() {
        let doc = |format: u32, path: &str| {
            MetaDocument {
                format,
                entries: vec![MetaEntry {
                    path: path.to_owned(),
                    kind: MetaKind::File,
                    mode: Some(0o644),
                    mtime: 1,
                }],
                hardlinks: vec![],
            }
            .encode()
        };
        assert!(MetaDocument::decode(&doc(1, "a/b")).is_ok());
        assert!(MetaDocument::decode(&doc(1, "")).is_ok());
        assert!(MetaDocument::decode(&doc(2, "a")).is_err());
        assert!(MetaDocument::decode(&doc(0, "a")).is_err());
        for bad in ["/etc/passwd", "../x", "a/../../x", "a//b", "a/", "./a"] {
            assert!(MetaDocument::decode(&doc(1, bad)).is_err(), "{bad}");
        }
        let mut grouped = MetaDocument::decode(&doc(1, "a")).unwrap();
        grouped.hardlinks = vec![vec!["a".into(), "missing".into()]];
        assert!(MetaDocument::decode(&grouped.encode()).is_err());
        let text = String::from_utf8(doc(1, "a")).unwrap();
        assert_eq!(
            text,
            r#"{"format":1,"entries":[{"path":"a","kind":"file","mode":420,"mtime":1}]}"#
        );
    }
}
