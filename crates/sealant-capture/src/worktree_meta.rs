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
//! - hardlink groups among the worktree tree's files, and the names another class carries of a
//!   tracked file's inode (`shared`: an ignored file or a bulk file hardlinked to a tracked one);
//! - inodes the workspace and bulk classes share with no tracked name (`cross_links`: an
//!   ignored file hardlinked into `node_modules`). Each class carries its own names of such an
//!   inode (and links them among themselves); only this overlay says they are one file.
//!
//! [`capture`] reads it from disk after the worktree tree is written; [`apply`] brings a disk
//! the git class checked out to it — after every other class, since restoring an ignored file
//! or a bulk directory moves the mtime of the directory it lands in. `apply` fails on the
//! first path it cannot bring to the document (missing, the wrong kind, a failed `chmod`,
//! `utimensat` or link) rather than leaving a partly restored tree reported as restored.
//!
//! Out of scope, by class: `.git`, the daemon directory and staging, the harness home, nested
//! repositories and bulk directories (the chunked classes carry their own metadata), and every
//! directory git ignores (the workspace class carries it).
//!
//! # Paths that are not UTF-8
//!
//! A path is bytes; the document is JSON. Every path is written as a *key*, the encoding dir
//! objects use for names, with the same functions ([`crate::tree::key_of`]): the bytes as UTF-8 when they
//! are UTF-8 and hold no character of `U+10FF80..=U+10FFFF`; otherwise each byte of an invalid
//! sequence, and each byte of such a character, becomes `U+10FF00 + byte`. The mapping is a
//! bijection ([`key_of`], [`bytes_of`]), and `/` is never escaped, so a path keys component by
//! component. An entry whose key was escaped also carries its bytes, hex, in `raw_path`
//! (`raw_member` for a shared link's other name); a reader takes those when present. A path that
//! is UTF-8 (every path, in practice) encodes as plain text with no extra field.

use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::ffi::OsStr;
use std::fs::Metadata;
use std::io::{self, Read};
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use crate::gitpack::{GitError, GitRepo};
use crate::index::{has_component_in, mtime_ns};
use crate::longpath;
use crate::manifest::WORKTREE_META_FORMAT;
pub use crate::tree::{bytes_of, key_of, raw_of};

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
    /// A strict apply ([`apply_strict`]) found a hardlink the document names across classes
    /// that the restored names cannot make: a member missing, not a file, or holding other
    /// bytes than the rest. The capture promised an inode the restore cannot give back.
    #[error("worktree metadata: the hardlink of {member} is not restorable: {reason}")]
    LinkUnfulfilled {
        /// The member (its class's key).
        member: String,
        /// What was found.
        reason: String,
    },
}

fn io_err(path: &[u8]) -> impl FnOnce(io::Error) -> MetaError + '_ {
    move |source| MetaError::Io {
        path: String::from_utf8_lossy(path).into_owned(),
        source,
    }
}

/// The bytes of a `key` + `raw` pair: `raw` wins when present, and must agree with the key.
fn bytes_of_pair(key: &str, raw: Option<&str>) -> Result<Vec<u8>, MetaError> {
    let Some(raw) = raw else {
        return Ok(bytes_of(key).into_owned());
    };
    let bytes =
        hex::decode(raw).map_err(|e| MetaError::BadDocument(format!("{key:?}: raw bytes: {e}")))?;
    if key_of(&bytes) != key {
        return Err(MetaError::BadDocument(format!(
            "{key:?}: raw bytes {raw} do not match the key"
        )));
    }
    Ok(bytes)
}

// ---------------------------------------------------------------------------------------------
// The document.
// ---------------------------------------------------------------------------------------------

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
    /// Worktree-relative, `/`-separated; `""` is the root. A key (see the module docs).
    pub path: String,
    /// The path's bytes, hex, when `path` is an escaped key.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub raw_path: Option<String>,
    /// Kind.
    pub kind: MetaKind,
    /// `st_mode & 0o7777`; absent for a symlink (its mode is not settable).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mode: Option<u32>,
    /// Modification time, nanoseconds since the Unix epoch.
    pub mtime: i64,
}

/// The class that carries a shared link's other name.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum LinkClass {
    /// The workspace class: `member` is its virtual path (`tree/…`, `.git/…`, `harness/…`).
    Workspace,
    /// The bulk class: `member` is root-relative.
    Bulk,
}

/// A name another class carries of a tracked file's inode.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct SharedLink {
    /// The tracked file (a key of a `file` entry).
    pub path: String,
    /// The class carrying the other name.
    pub class: LinkClass,
    /// The other name, as that class names it (a key).
    pub member: String,
    /// The member's bytes, hex, when `member` is an escaped key.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub raw_member: Option<String>,
}

/// One name of an untracked inode, as the class that carries it names it.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct LinkMember {
    /// The class carrying the name.
    pub class: LinkClass,
    /// The name, as that class names it (a key): the workspace class's virtual path
    /// (`tree/…`, `.git/…`, `harness/…`), the bulk class's root-relative path.
    pub member: String,
    /// The member's bytes, hex, when `member` is an escaped key.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub raw_member: Option<String>,
}

impl LinkMember {
    /// The member's bytes.
    fn bytes(&self) -> Result<Vec<u8>, MetaError> {
        bytes_of_pair(&self.member, self.raw_member.as_deref())
    }
}

/// The overlay document: entries sorted by path, hardlink groups sorted (each group's members
/// sorted, the first being the one the others link to), shared links sorted, cross-class
/// groups sorted (each group's members sorted, the first being the one the others link to).
/// Encodes
/// deterministically, so an unchanged working tree encodes to the same bytes.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct MetaDocument {
    /// [`WORKTREE_META_FORMAT`].
    pub format: u32,
    /// Every path, sorted by key.
    pub entries: Vec<MetaEntry>,
    /// Keys of paths sharing one inode, each group of two or more files of `entries`.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub hardlinks: Vec<Vec<String>>,
    /// Names other classes carry of a tracked file's inode.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub shared: Vec<SharedLink>,
    /// Inodes named in both the workspace and the bulk class and by no tracked file: each group
    /// every name those classes carry of one inode, two or more. Absent when empty, so a
    /// document without one encodes exactly as before (a reader that predates the field
    /// restores each name as its own class captured it, as it always did).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub cross_links: Vec<Vec<LinkMember>>,
}

impl MetaDocument {
    /// Canonical bytes (compact JSON; the order is fixed by construction).
    #[must_use]
    pub fn encode(&self) -> Vec<u8> {
        // Serializing a struct cannot fail.
        serde_json::to_vec(self).unwrap_or_default()
    }

    /// Decode, refusing a format this build does not read, any path that is not a plain
    /// relative path, raw bytes that disagree with their key, and links that name no file.
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
            let bytes = bytes_of_pair(&e.path, e.raw_path.as_deref())?;
            if !is_plain_relative(&bytes) {
                return Err(MetaError::BadDocument(format!("path {:?}", e.path)));
            }
            if e.kind != MetaKind::Symlink && e.mode.is_none() {
                return Err(MetaError::BadDocument(format!("{:?} has no mode", e.path)));
            }
            kinds.insert(&e.path, e.kind);
        }
        let is_file = |p: &String| kinds.get(p.as_str()) == Some(&MetaKind::File);
        for group in &doc.hardlinks {
            if group.len() < 2 || !group.iter().all(is_file) {
                return Err(MetaError::BadDocument(format!(
                    "hardlink group {group:?} does not name files of the document"
                )));
            }
        }
        for link in &doc.shared {
            let member = bytes_of_pair(&link.member, link.raw_member.as_deref())?;
            if !is_file(&link.path) || member.is_empty() || !is_plain_relative(&member) {
                return Err(MetaError::BadDocument(format!("shared link {link:?}")));
            }
        }
        for group in &doc.cross_links {
            let mut seen = BTreeSet::new();
            for m in group {
                let member = m.bytes()?;
                if member.is_empty()
                    || !is_plain_relative(&member)
                    || !seen.insert((m.class, member))
                {
                    return Err(MetaError::BadDocument(format!("cross-class link {m:?}")));
                }
            }
            if seen.len() < 2 {
                return Err(MetaError::BadDocument(format!(
                    "cross-class link group {group:?} names fewer than two members"
                )));
            }
        }
        Ok(doc)
    }

    /// The bytes of an entry's path.
    fn path_bytes(e: &MetaEntry) -> Result<Vec<u8>, MetaError> {
        bytes_of_pair(&e.path, e.raw_path.as_deref())
    }
}

/// `""` or a relative path of normal components.
fn is_plain_relative(p: &[u8]) -> bool {
    p.is_empty()
        || p.split(|b| *b == b'/')
            .all(|c| !c.is_empty() && c != b"." && c != b".." && !c.contains(&0))
}

fn os(bytes: &[u8]) -> &Path {
    Path::new(OsStr::from_bytes(bytes))
}

// ---------------------------------------------------------------------------------------------
// Scope.
// ---------------------------------------------------------------------------------------------

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
    /// Root-relative nested repositories (the workspace class carries them), as
    /// [`crate::tree::key_of`] keys.
    pub nested: Vec<String>,
    /// Absolute paths left out (the staging directory, the harness home).
    pub skip_abs: Vec<PathBuf>,
}

fn under(rel: &[u8], set: &[String]) -> bool {
    set.iter().any(|e| {
        // Keys of the paths' bytes: a nested repository whose name is not UTF-8 is its bytes.
        let e = crate::tree::bytes_of(e.trim_matches('/'));
        let e = e.as_ref();
        !e.is_empty()
            && (rel == e
                || rel
                    .strip_prefix(e)
                    .is_some_and(|r| r.first() == Some(&b'/')))
    })
}

/// What [`MetaScope::directories`] found.
#[derive(Debug, Default)]
struct Directories {
    /// Directories in scope, root-relative bytes (empty is the root), with their metadata.
    dirs: BTreeMap<Vec<u8>, Metadata>,
    /// Paths in scope that could not be listed or stat'ed, or that no class carries, with what
    /// was wrong: never taken as gone.
    unreadable: Vec<(Vec<u8>, String)>,
}

/// A worktree-relative path git cannot reach: it runs in the worktree and passes each path
/// whole to one system call, which refuses `PATH_MAX` bytes or more — a file's path as it is,
/// a directory's with the `/` git appends to open it ([`crate::gitpack::GitRepo::beyond_reach`]
/// lists them for the chunked class).
#[must_use]
pub fn beyond_git(rel: &[u8], is_dir: bool) -> bool {
    rel.len() + usize::from(is_dir) >= longpath::PATH_MAX
}

impl MetaScope {
    /// Directories under the root the overlay covers, as root-relative bytes (empty is the
    /// root), with their metadata: the walk prunes `.git`, the excludes, bulk directories,
    /// nested repositories (and the paths git cannot reach, which the chunked class carries)
    /// and every directory git reports ignored. A path of any length is walked. A directory
    /// that cannot be listed is kept and not descended into; one that cannot be stat'ed is left
    /// out; both are reported unreadable, as is a path git cannot reach that no class carries.
    /// One that vanished mid-walk is skipped. No single path fails the walk.
    fn directories(&self, repo: &GitRepo) -> Result<Directories, MetaError> {
        let out = repo.run(&[
            "ls-files",
            "-o",
            "-i",
            "--exclude-standard",
            "--directory",
            "-z",
        ])?;
        let listed: Vec<&[u8]> = out
            .stdout
            .split(|b| *b == 0)
            .filter(|p| !p.is_empty())
            .collect();
        let ignored: BTreeSet<&[u8]> = listed.iter().filter_map(|p| p.strip_suffix(b"/")).collect();
        let ignored_files: BTreeSet<&[u8]> = listed
            .iter()
            .copied()
            .filter(|p| !p.ends_with(b"/"))
            .collect();
        let mut found = Directories::default();
        match longpath::symlink_metadata(&self.root) {
            Ok(meta) if meta.is_dir() => {
                found.dirs.insert(Vec::new(), meta);
            }
            Ok(_) => return Ok(found),
            Err(e) if crate::index::is_vanished(&e) => return Ok(found),
            Err(e) => {
                found.unreadable.push((Vec::new(), e.to_string()));
                return Ok(found);
            }
        }
        let rel_of = |path: &Path| -> Vec<u8> {
            path.strip_prefix(&self.root)
                .unwrap_or(path)
                .as_os_str()
                .as_bytes()
                .to_vec()
        };
        longpath::walk(&self.root, &mut |visit| {
            let (path, kind) = match visit {
                longpath::Visit::Entry { path, kind, .. } => (path, kind),
                longpath::Visit::Error { path, error, .. } => {
                    if !crate::index::is_vanished(&error) {
                        tracing::warn!(path = %path.display(), %error, "worktree metadata: cannot list; not descended");
                        found.unreadable.push((rel_of(path), error.to_string()));
                    }
                    return false;
                }
            };
            let rel = rel_of(path);
            let is_dir = kind == longpath::Kind::Dir;
            let carried_elsewhere = under(&rel, &self.nested) || under(&rel, &self.excludes);
            if !is_dir {
                // Git lists such a file for the chunked class; one it did not list (a
                // filesystem that gives no entry types) is carried by nobody: say so.
                if beyond_git(&rel, false)
                    && !carried_elsewhere
                    && !ignored_files.contains(rel.as_slice())
                {
                    found
                        .unreadable
                        .push((rel, "too long for git, and in no other class".to_owned()));
                }
                return false;
            }
            if path.file_name() == Some(OsStr::new(".git"))
                || carried_elsewhere
                || ignored.contains(rel.as_slice())
                || has_component_in(Path::new(OsStr::from_bytes(&rel)), &self.bulk_dirs)
                || self.skip_abs.iter().any(|s| s == path)
            {
                return false;
            }
            if beyond_git(&rel, true) {
                found
                    .unreadable
                    .push((rel, "too long for git, and in no other class".to_owned()));
                return false;
            }
            match longpath::symlink_metadata(path) {
                Ok(meta) if meta.is_dir() => {
                    found.dirs.insert(rel, meta);
                    true
                }
                Ok(_) => false,
                Err(e) if crate::index::is_vanished(&e) => false,
                Err(e) => {
                    found.unreadable.push((rel, e.to_string()));
                    false
                }
            }
        });
        Ok(found)
    }
}

// ---------------------------------------------------------------------------------------------
// Capture.
// ---------------------------------------------------------------------------------------------

/// One `git ls-tree -r -t` record of the worktree tree.
struct TreePath {
    path: Vec<u8>,
    kind: MetaKind,
    blob: Vec<u8>,
}

fn tree_paths(repo: &GitRepo, tree: &str) -> Result<Vec<TreePath>, MetaError> {
    let out = repo.run(&["ls-tree", "-r", "-t", "-z", "--full-tree", tree])?;
    let mut paths = Vec::new();
    for record in out.stdout.split(|b| *b == 0).filter(|r| !r.is_empty()) {
        let Some(tab) = record.iter().position(|b| *b == b'\t') else {
            continue;
        };
        let (head, path) = (&record[..tab], &record[tab + 1..]);
        let mut fields = head.split(|b| *b == b' ');
        let (mode, _, blob) = (
            fields.next().unwrap_or(b""),
            fields.next(),
            fields.next().unwrap_or(b""),
        );
        let kind = match mode {
            b"100644" | b"100755" => MetaKind::File,
            b"120000" => MetaKind::Symlink,
            b"040000" => MetaKind::Dir,
            // Gitlinks: the workspace class carries nested repositories.
            _ => continue,
        };
        paths.push(TreePath {
            path: path.to_vec(),
            kind,
            blob: blob.to_vec(),
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

fn entry_of(path: &[u8], kind: MetaKind, meta: &Metadata) -> MetaEntry {
    let key = key_of(path).into_owned();
    MetaEntry {
        raw_path: raw_of(&key),
        path: key,
        kind,
        mode: (kind != MetaKind::Symlink).then(|| meta.mode() & 0o7777),
        mtime: mtime_ns(meta),
    }
}

fn abs_of(root: &Path, rel: &[u8]) -> PathBuf {
    if rel.is_empty() {
        root.to_path_buf()
    } else {
        root.join(os(rel))
    }
}

/// A tracked file with names outside the overlay: its inode has more links than the overlay
/// names. [`capture`] reports these; the engine finds the other names in the classes that carry
/// them and records them as [`SharedLink`]s.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OutsideLinks {
    /// The tracked file's key.
    pub path: String,
    /// Its device and inode.
    pub dev: u64,
    /// Its inode.
    pub ino: u64,
}

/// What [`capture`] read.
#[derive(Debug, Clone)]
pub struct Captured {
    /// The document (without `shared` and `cross_links`, which the caller fills from the other
    /// classes).
    pub doc: MetaDocument,
    /// Tracked files whose inode has names the overlay does not hold.
    pub outside: Vec<OutsideLinks>,
    /// Paths of the worktree tree whose metadata could not be read (a directory above them
    /// that cannot be searched): never taken as gone.
    pub unreadable: Vec<UnreadableMeta>,
    /// Paths of the worktree tree that are of another kind on disk (a file the tree holds as a
    /// symlink, a directory it holds as a file), as keys. Left out of the document: the tree
    /// does not hold what the disk does, so a capture that must be the disk (a final one) fails
    /// on them; an automatic one leaves them to the next snap.
    pub changed_kind: Vec<String>,
    /// Every regular file of the worktree tree with more than one name, as read here
    /// ([`crate::aliases`]).
    pub linked: Vec<crate::aliases::LinkedName>,
}

/// A path of the worktree tree whose metadata could not be read.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UnreadableMeta {
    /// Its key.
    pub path: String,
    /// What the filesystem said.
    pub error: String,
    /// Its entry was carried from the previous document.
    pub carried: bool,
}

/// Read the overlay of the working tree `worktree_tree` (the tree just written from it) plus
/// every directory in `scope`. A path that vanished since the tree was written is left out: the
/// next capture sees the change. One whose kind on disk is not the tree's is left out too, and
/// named in [`Captured::changed_kind`]: never silently. A tracked path whose metadata cannot be
/// read (git carried its content from the previous capture, `gitpack.rs`) is reported in
/// `unreadable` and keeps its entry of `carry`, the previous document, when it had one — an
/// automatic snap passes it, a final one passes `None` and fails on the report. Any other
/// failure to read a path fails.
pub fn capture(
    repo: &GitRepo,
    worktree_tree: &str,
    scope: &MetaScope,
    carry: Option<&MetaDocument>,
) -> Result<Captured, MetaError> {
    let mut entries: BTreeMap<String, MetaEntry> = BTreeMap::new();
    let mut unreadable = Vec::new();
    let mut changed_kind = Vec::new();
    let carried: HashMap<&str, &MetaEntry> = carry
        .map(|doc| doc.entries.iter().map(|e| (e.path.as_str(), e)).collect())
        .unwrap_or_default();
    // (dev, ino) → (key, blob, nlink) of every file with more than one name.
    type Named = (String, Vec<u8>, u64);
    let mut inodes: BTreeMap<(u64, u64), Vec<Named>> = BTreeMap::new();
    let mut linked = Vec::new();
    for tp in tree_paths(repo, worktree_tree)? {
        let meta = match longpath::symlink_metadata(&abs_of(&scope.root, &tp.path)) {
            Ok(meta) => meta,
            Err(e) if crate::index::is_vanished(&e) => continue,
            // Any other error is this path's alone: unreadable, its last entry carried.
            Err(e) => {
                let key = key_of(&tp.path).into_owned();
                let previous = carried.get(key.as_str()).filter(|p| p.kind == tp.kind);
                if let Some(previous) = previous {
                    entries.insert(key.clone(), (*previous).clone());
                }
                unreadable.push(UnreadableMeta {
                    path: key,
                    error: e.to_string(),
                    carried: previous.is_some(),
                });
                continue;
            }
        };
        if kind_of(&meta) != Some(tp.kind) {
            // A path the chunked class carries (a nested repository, a path git could not
            // index) is on disk as that class holds it, whatever the tree kept for it.
            if !under(&tp.path, &scope.nested) {
                changed_kind.push(key_of(&tp.path).into_owned());
            }
            continue;
        }
        let entry = entry_of(&tp.path, tp.kind, &meta);
        if tp.kind == MetaKind::File
            && let Some(name) =
                crate::aliases::LinkedName::of(&abs_of(&scope.root, &tp.path), &meta)
        {
            linked.push(name);
        }
        if tp.kind == MetaKind::File && meta.nlink() > 1 {
            inodes.entry((meta.dev(), meta.ino())).or_default().push((
                entry.path.clone(),
                tp.blob,
                meta.nlink(),
            ));
        }
        entries.insert(entry.path.clone(), entry);
    }
    let found = scope.directories(repo)?;
    for (rel, meta) in found.dirs {
        let entry = entry_of(&rel, MetaKind::Dir, &meta);
        entries.entry(entry.path.clone()).or_insert(entry);
    }
    // A directory that could not be listed or stat'ed: what the previous document held at and
    // under it (directories; tracked paths came from the tree) is carried, never dropped.
    for (rel, error) in found.unreadable {
        let key = key_of(&rel).into_owned();
        let prefix = format!("{key}/");
        let mut carried_any = false;
        for (path, previous) in &carried {
            let at_or_under = rel.is_empty() || *path == key || path.starts_with(&prefix);
            if previous.kind == MetaKind::Dir && at_or_under && !entries.contains_key(*path) {
                entries.insert((*path).to_owned(), (*previous).clone());
                carried_any = true;
            }
        }
        match unreadable.iter_mut().find(|u| u.path == key) {
            Some(u) => u.carried |= carried_any,
            None => unreadable.push(UnreadableMeta {
                path: key,
                error,
                carried: carried_any,
            }),
        }
    }
    let mut hardlinks: Vec<Vec<String>> = Vec::new();
    let mut outside = Vec::new();
    for ((dev, ino), members) in inodes {
        let same_blob = members.iter().all(|(_, blob, _)| *blob == members[0].1);
        if members.len() > 1 && same_blob {
            let mut paths: Vec<String> = members.iter().map(|(p, _, _)| p.clone()).collect();
            paths.sort();
            hardlinks.push(paths);
        }
        let nlink = members.iter().map(|(_, _, n)| *n).max().unwrap_or(0);
        if same_blob && nlink > members.len() as u64 {
            let first = members.iter().map(|(p, _, _)| p).min().cloned();
            if let Some(path) = first {
                outside.push(OutsideLinks { path, dev, ino });
            }
        }
    }
    hardlinks.sort();
    Ok(Captured {
        doc: MetaDocument {
            format: WORKTREE_META_FORMAT,
            entries: entries.into_values().collect(),
            hardlinks,
            shared: Vec::new(),
            cross_links: Vec::new(),
        },
        outside,
        unreadable,
        changed_kind,
        linked,
    })
}

// ---------------------------------------------------------------------------------------------
// Apply.
// ---------------------------------------------------------------------------------------------

/// What [`apply`] did.
#[derive(Debug, Default)]
pub struct Applied {
    /// Paths it changed: directories created or removed, links made, modes and mtimes set.
    pub changed: u64,
    /// Other classes' names whose inode it linked (the class's index must learn their new
    /// inode, or its new ctime: a link moves the ctime of every name of the inode): class,
    /// member key, metadata after every link.
    pub relinked: Vec<(LinkClass, String, Metadata)>,
}

fn same_bytes(a: &Path, b: &Path) -> io::Result<bool> {
    let (ma, mb) = (longpath::metadata(a)?, longpath::metadata(b)?);
    if ma.len() != mb.len() {
        return Ok(false);
    }
    let (mut fa, mut fb) = (longpath::open(a)?, longpath::open(b)?);
    let (mut ba, mut bb) = (vec![0u8; 1 << 16], vec![0u8; 1 << 16]);
    loop {
        let n = fa.read(&mut ba)?;
        if n == 0 {
            return Ok(true);
        }
        fb.read_exact(&mut bb[..n])?;
        if ba[..n] != bb[..n] {
            return Ok(false);
        }
    }
}

/// Bring the disk under `scope.root` to `doc`, after the git class checked out its tree and
/// every other class was restored: create the directories it names that are missing, remove
/// the (empty) directories in scope it does not name, link hardlink groups, link the other
/// classes' names of a tracked file's inode ([`SharedLink`]; `resolve` says where a class's
/// member is on disk), then set modes and mtimes — files and symlinks first, then directories
/// deepest first, so nothing written later moves a directory's mtime. Only what differs is
/// touched. Fails on the first path it cannot bring to the document.
///
/// A shared link is made only when the other name is on disk and holds exactly the tracked
/// file's bytes: that class restored it from its own capture, which can be older than the
/// worktree tree (a bulk section still `"pending"`, or one captured before the file changed),
/// and linking would then replace one of the two contents with the other. Left unlinked, each
/// name holds what its own class captured.
pub fn apply(
    repo: &GitRepo,
    doc: &MetaDocument,
    scope: &MetaScope,
    resolve: &dyn Fn(LinkClass, &[u8]) -> Option<PathBuf>,
) -> Result<Applied, MetaError> {
    apply_with(repo, doc, scope, resolve, false)
}

/// [`apply`] over a capture that promised its links: the classes were captured together (a
/// sealed final capture, every class restored), so every link it names across classes — a
/// shared link, a cross-class group — must be made. A member the restore placed nowhere
/// (`resolve` says `None`: its class is not restored here) is passed over; one missing, not a
/// file, or holding other bytes than the rest fails with [`MetaError::LinkUnfulfilled`]
/// instead of being left unlinked in silence (review 2026-09-28, fifth pass, #11). Neither file
/// is written over either way.
pub fn apply_strict(
    repo: &GitRepo,
    doc: &MetaDocument,
    scope: &MetaScope,
    resolve: &dyn Fn(LinkClass, &[u8]) -> Option<PathBuf>,
) -> Result<Applied, MetaError> {
    apply_with(repo, doc, scope, resolve, true)
}

fn apply_with(
    repo: &GitRepo,
    doc: &MetaDocument,
    scope: &MetaScope,
    resolve: &dyn Fn(LinkClass, &[u8]) -> Option<PathBuf>,
    strict: bool,
) -> Result<Applied, MetaError> {
    let unfulfilled = |member: &str, reason: &str| -> Result<(), MetaError> {
        if strict {
            Err(MetaError::LinkUnfulfilled {
                member: member.to_owned(),
                reason: reason.to_owned(),
            })
        } else {
            Ok(())
        }
    };
    let root = &scope.root;
    let mut applied = Applied::default();
    let entries: Vec<(Vec<u8>, &MetaEntry)> = doc
        .entries
        .iter()
        .map(|e| MetaDocument::path_bytes(e).map(|b| (b, e)))
        .collect::<Result<_, _>>()?;
    // Directories: parents sort before children.
    for (rel, e) in entries.iter().filter(|(_, e)| e.kind == MetaKind::Dir) {
        let abs = abs_of(root, rel);
        match longpath::symlink_metadata(&abs) {
            Ok(meta) if meta.is_dir() => {}
            Ok(meta) => {
                return Err(MetaError::Mismatch {
                    path: e.path.clone(),
                    reason: format!("a directory on the plan, a {:?} on disk", kind_of(&meta)),
                });
            }
            Err(err) if err.kind() == io::ErrorKind::NotFound => {
                longpath::create_dir_all(&abs).map_err(io_err(rel))?;
                applied.changed += 1;
            }
            Err(err) => return Err(io_err(rel)(err)),
        }
    }
    // Every other path is on disk as the checkout wrote it.
    for (rel, e) in entries.iter().filter(|(_, e)| e.kind != MetaKind::Dir) {
        let meta = longpath::symlink_metadata(&abs_of(root, rel)).map_err(io_err(rel))?;
        if kind_of(&meta) != Some(e.kind) {
            return Err(MetaError::Mismatch {
                path: e.path.clone(),
                reason: format!("a {:?} on the plan, a {:?} on disk", e.kind, kind_of(&meta)),
            });
        }
    }
    // Directories in scope the document does not name: an empty directory the plan dropped.
    // One that still holds something (a file another class owns) stays.
    let planned: BTreeSet<&[u8]> = entries.iter().map(|(b, _)| b.as_slice()).collect();
    let mut stale: Vec<Vec<u8>> = scope
        .directories(repo)?
        .dirs
        .into_keys()
        .filter(|rel| !rel.is_empty() && !planned.contains(rel.as_slice()))
        .collect();
    stale.sort_by(|a, b| b.len().cmp(&a.len()).then_with(|| a.cmp(b)));
    for rel in stale {
        match longpath::remove_dir(&abs_of(root, &rel)) {
            Ok(()) => applied.changed += 1,
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
        let first = bytes_of(first);
        let canonical = abs_of(root, &first);
        let target = longpath::symlink_metadata(&canonical).map_err(io_err(&first))?;
        for member in rest {
            let member = bytes_of(member);
            let abs = abs_of(root, &member);
            let meta = longpath::symlink_metadata(&abs).map_err(io_err(&member))?;
            if (meta.dev(), meta.ino()) == (target.dev(), target.ino()) {
                continue;
            }
            relink(&canonical, &abs).map_err(io_err(&member))?;
            applied.changed += 1;
        }
    }
    // Other classes' names of a tracked file's inode.
    let mut relinked = Vec::new();
    for link in &doc.shared {
        let tracked = bytes_of(&link.path);
        let canonical = abs_of(root, &tracked);
        let member = bytes_of_pair(&link.member, link.raw_member.as_deref())?;
        let Some(abs) = resolve(link.class, &member) else {
            continue;
        };
        let target = longpath::symlink_metadata(&canonical).map_err(io_err(&tracked))?;
        let meta = match longpath::symlink_metadata(&abs) {
            Ok(meta) if meta.is_file() => meta,
            Ok(_) => {
                unfulfilled(&link.member, "not a file")?;
                continue;
            }
            Err(e) if e.kind() == io::ErrorKind::NotFound => {
                unfulfilled(&link.member, "missing")?;
                continue;
            }
            Err(e) => return Err(io_err(&member)(e)),
        };
        if (meta.dev(), meta.ino()) == (target.dev(), target.ino()) {
            continue;
        }
        if !same_bytes(&canonical, &abs).map_err(io_err(&member))? {
            unfulfilled(
                &link.member,
                &format!("holds other bytes than {}", link.path),
            )?;
            tracing::debug!(tracked = %link.path, member = %link.member, "shared hardlink: contents differ; left unlinked");
            continue;
        }
        relink(&canonical, &abs).map_err(io_err(&member))?;
        relinked.push((link.class, link.member.clone(), abs, member));
        applied.changed += 1;
    }
    // Inodes the workspace and bulk classes share with no tracked name: every member on the
    // first member's inode, under the same rule as a shared link (a name that is missing, not
    // a file, or holds other bytes than the first is left as its own class restored it). When
    // anything was linked, every name of the group is restated: the link moved the inode's
    // ctime, which each class's index holds.
    for group in &doc.cross_links {
        let mut named: Vec<(&LinkMember, PathBuf, Vec<u8>)> = Vec::new();
        for m in group {
            let bytes = m.bytes()?;
            let Some(abs) = resolve(m.class, &bytes) else {
                continue;
            };
            match longpath::symlink_metadata(&abs) {
                Ok(meta) if meta.is_file() => named.push((m, abs, bytes)),
                Ok(_) => unfulfilled(&m.member, "not a file")?,
                Err(e) if e.kind() == io::ErrorKind::NotFound => {
                    unfulfilled(&m.member, "missing")?;
                }
                Err(e) => return Err(io_err(&bytes)(e)),
            }
        }
        let Some(((head, canonical, first), rest)) = named.split_first() else {
            continue;
        };
        let target = longpath::symlink_metadata(canonical).map_err(io_err(first))?;
        let mut linked = false;
        let mut on_inode = vec![0];
        for (i, (m, abs, bytes)) in rest.iter().enumerate() {
            let meta = longpath::symlink_metadata(abs).map_err(io_err(bytes))?;
            if (meta.dev(), meta.ino()) != (target.dev(), target.ino()) {
                if !same_bytes(canonical, abs).map_err(io_err(bytes))? {
                    unfulfilled(
                        &m.member,
                        &format!("holds other bytes than {}", head.member),
                    )?;
                    tracing::debug!(canonical = %head.member, member = %m.member, "cross-class hardlink: contents differ; left unlinked");
                    continue;
                }
                relink(canonical, abs).map_err(io_err(bytes))?;
                applied.changed += 1;
                linked = true;
            }
            on_inode.push(i + 1);
        }
        if linked {
            for i in on_inode {
                let (m, abs, bytes) = &named[i];
                relinked.push((m.class, m.member.clone(), abs.clone(), bytes.clone()));
            }
        }
    }
    // Files and symlinks, then directories deepest first.
    let mut dirs: Vec<&(Vec<u8>, &MetaEntry)> = Vec::new();
    for item in &entries {
        if item.1.kind == MetaKind::Dir {
            dirs.push(item);
            continue;
        }
        applied.changed += u64::from(settle(root, &item.0, item.1)?);
    }
    let depth = |rel: &[u8]| {
        if rel.is_empty() {
            0
        } else {
            rel.split(|b| *b == b'/').count()
        }
    };
    dirs.sort_by(|a, b| depth(&b.0).cmp(&depth(&a.0)).then_with(|| a.0.cmp(&b.0)));
    for (rel, e) in dirs {
        applied.changed += u64::from(settle(root, rel, e)?);
    }
    // Stat relinked names once the shared inode has its final mode and mtime.
    for (class, member, abs, bytes) in relinked {
        let meta = longpath::symlink_metadata(&abs).map_err(io_err(&bytes))?;
        applied.relinked.push((class, member, meta));
    }
    Ok(applied)
}

/// Make `abs` a name of `canonical`'s inode (remove it, link it) and give its directory back
/// the mtime it had: the unlink and the link move it, and a directory another class restored
/// (a bulk package's, `node_modules` itself) has its mtime set already — nothing here sets it
/// again.
fn relink(canonical: &Path, abs: &Path) -> io::Result<()> {
    let parent = abs
        .parent()
        .map(|dir| longpath::symlink_metadata(dir).map(|meta| (dir, mtime_ns(&meta))))
        .transpose()?;
    longpath::remove_file(abs)?;
    longpath::hard_link(canonical, abs)?;
    if let Some((dir, mtime)) = parent {
        set_mtime_nofollow(dir, mtime)?;
    }
    Ok(())
}

/// Set one path's mode and mtime where they differ; whether anything changed.
fn settle(root: &Path, rel: &[u8], e: &MetaEntry) -> Result<bool, MetaError> {
    let abs = abs_of(root, rel);
    let meta = longpath::symlink_metadata(&abs).map_err(io_err(rel))?;
    let mut changed = false;
    if let Some(mode) = e.mode
        && e.kind != MetaKind::Symlink
        && meta.mode() & 0o7777 != mode
    {
        longpath::set_mode(&abs, mode).map_err(io_err(rel))?;
        changed = true;
    }
    if mtime_ns(&meta) != e.mtime {
        set_mtime_nofollow(&abs, e.mtime).map_err(io_err(rel))?;
        changed = true;
    }
    Ok(changed)
}

/// Set `abs`'s mtime (nanoseconds since the epoch) without following a symlink, so a
/// symlink gets its own mtime and a file is not opened (its mode may forbid that). A path of
/// any length ([`longpath::set_mtime_nofollow`]).
pub fn set_mtime_nofollow(abs: &Path, mtime_ns: i64) -> io::Result<()> {
    longpath::set_mtime_nofollow(abs, mtime_ns)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn git(root: &Path, args: &[&str]) {
        let out = std::process::Command::new("git")
            .current_dir(root)
            .env("GIT_OPTIONAL_LOCKS", "0")
            .args(args)
            .output()
            .unwrap();
        assert!(out.status.success(), "git {args:?}");
    }

    /// Finding 1b of the third Docker end to end: one path whose metadata cannot be read (any
    /// error, not only `EACCES`) failed the whole overlay, and with it every snap. Now that
    /// path alone is unreadable — a tracked file's previous entry and an unlistable
    /// directory's previous subdirectories carried — and every other path is read.
    #[test]
    fn one_path_that_cannot_be_read_is_unreadable_and_the_rest_is_captured() {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path().join("ws");
        std::fs::create_dir_all(root.join("u/sub")).unwrap();
        git(&root, &["init", "-q", "-b", "main"]);
        std::fs::write(root.join("a.txt"), "a\n").unwrap();
        std::fs::write(root.join("b.txt"), "b\n").unwrap();
        std::fs::write(root.join("u/sub/f.txt"), "f\n").unwrap();
        std::fs::create_dir_all(root.join("v")).unwrap();
        let repo = GitRepo::open(&root).unwrap();
        let scope = MetaScope {
            root: root.clone(),
            excludes: vec![".sealantd".to_owned()],
            bulk_dirs: Vec::new(),
            nested: Vec::new(),
            skip_abs: Vec::new(),
        };
        let scratch = tmp.path().join("scratch");
        let (tree, _) = repo.worktree_tree(&scratch, &scope.excludes).unwrap();
        let before = capture(&repo, &tree, &scope, None).unwrap();
        assert!(before.unreadable.is_empty());

        longpath::inject_fault(&root.join("b.txt"), nix::libc::EIO);
        longpath::inject_fault(&root.join("u"), nix::libc::EIO);
        longpath::inject_fault(&root.join("v"), nix::libc::ELOOP);
        let after = capture(&repo, &tree, &scope, Some(&before.doc)).unwrap();
        let unreadable: BTreeMap<&str, bool> = after
            .unreadable
            .iter()
            .map(|u| (u.path.as_str(), u.carried))
            .collect();
        assert_eq!(
            unreadable,
            BTreeMap::from([("b.txt", true), ("u", true), ("v", true)]),
            "{:?}",
            after.unreadable
        );
        let paths: BTreeSet<&str> = after.doc.entries.iter().map(|e| e.path.as_str()).collect();
        // Every path is there: read, or (unreadable) carried from the previous document.
        for p in ["", "a.txt", "b.txt", "u", "u/sub", "u/sub/f.txt", "v"] {
            assert!(paths.contains(p), "{p} is in the overlay: {paths:?}");
        }

        // A final snap carries nothing: the same paths are unreadable, none carried.
        let strict = capture(&repo, &tree, &scope, None).unwrap();
        assert!(strict.unreadable.iter().all(|u| !u.carried));
        assert_eq!(strict.unreadable.len(), 3);
    }

    fn file(path: &str) -> MetaEntry {
        MetaEntry {
            path: path.to_owned(),
            raw_path: raw_of(path),
            kind: MetaKind::File,
            mode: Some(0o644),
            mtime: 1,
        }
    }

    fn doc(format: u32, path: &str) -> Vec<u8> {
        MetaDocument {
            format,
            entries: vec![file(path)],
            ..MetaDocument::default()
        }
        .encode()
    }

    #[test]
    fn decode_refuses_unknown_formats_and_unsafe_paths() {
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

    /// The overlay's keys are the dir objects' names (`tree.rs`), byte for byte: a document
    /// written before the two shared one encoder decodes to the same paths.
    #[test]
    fn keys_are_the_dir_objects_encoding() {
        let corpus: [&[u8]; 6] = [
            b"plain/utf8",
            b"caf\xe9/\xff\xfe.txt",
            "x\u{10FFAA}y".as_bytes(),
            b"\x80",
            "\u{10FF7F}".as_bytes(),
            b"",
        ];
        for raw in corpus {
            assert_eq!(bytes_of(&key_of(raw)).as_ref(), raw);
        }
        let entry = file(&key_of(b"caf\xe9"));
        let text = String::from_utf8(
            MetaDocument {
                format: 1,
                entries: vec![entry],
                ..MetaDocument::default()
            }
            .encode(),
        )
        .unwrap();
        assert_eq!(
            text,
            "{\"format\":1,\"entries\":[{\"path\":\"caf\u{10FFE9}\",\"raw_path\":\"636166e9\",\"kind\":\"file\",\"mode\":420,\"mtime\":1}]}"
        );
    }

    /// A path that is not UTF-8 is a key plus its bytes in `raw_path`, and comes back byte
    /// for byte; raw bytes that disagree with the key, or that hold a `..`, are refused.
    #[test]
    fn non_utf8_paths_are_keys_with_raw_bytes() {
        let raw: &[u8] = b"caf\xe9/\xff\xfe.txt";
        let key = key_of(raw).into_owned();
        assert_eq!(bytes_of(&key).as_ref(), raw);
        let entry = file(&key);
        assert_eq!(entry.raw_path.as_deref(), Some(hex::encode(raw).as_str()));
        let bytes = MetaDocument {
            format: 1,
            entries: vec![entry.clone()],
            ..MetaDocument::default()
        }
        .encode();
        let back = MetaDocument::decode(&bytes).unwrap();
        assert_eq!(MetaDocument::path_bytes(&back.entries[0]).unwrap(), raw);
        // A UTF-8 name that holds an escape-range character is escaped too, and round-trips.
        let odd = "x\u{10FFAA}y".as_bytes();
        assert_eq!(bytes_of(&key_of(odd)).as_ref(), odd);
        assert!(raw_of(&key_of(odd)).is_some());
        assert!(raw_of("plain/utf8 ✓").is_none());

        let mut lying = entry.clone();
        lying.raw_path = Some(hex::encode(b"other"));
        let lying = MetaDocument {
            format: 1,
            entries: vec![lying],
            ..MetaDocument::default()
        };
        assert!(MetaDocument::decode(&lying.encode()).is_err());
        let dots = key_of(b"a/\xff/../..").into_owned();
        assert!(MetaDocument::decode(&doc(1, &dots)).is_err());
    }

    /// `cross_links` decode: two or more distinct plain members; a document without the field
    /// encodes as before.
    #[test]
    fn cross_links_decode_under_their_own_rules() {
        let m = |class, member: &str| LinkMember {
            class,
            member: member.to_owned(),
            raw_member: raw_of(member),
        };
        assert!(
            !String::from_utf8(MetaDocument::default().encode())
                .unwrap()
                .contains("cross_links")
        );
        let with = |group: Vec<LinkMember>| MetaDocument {
            format: 1,
            cross_links: vec![group],
            ..MetaDocument::default()
        };
        let good = with(vec![
            m(LinkClass::Workspace, "tree/ignored/x"),
            m(LinkClass::Bulk, &key_of(b"node_modules/caf\xe9")),
        ]);
        assert_eq!(MetaDocument::decode(&good.encode()).unwrap(), good);
        for bad in [
            vec![m(LinkClass::Workspace, "tree/x")],
            vec![m(LinkClass::Bulk, "a"), m(LinkClass::Bulk, "a")],
            vec![
                m(LinkClass::Workspace, "tree/x"),
                m(LinkClass::Bulk, "../x"),
            ],
            vec![m(LinkClass::Workspace, "tree/x"), m(LinkClass::Bulk, "")],
        ] {
            assert!(
                MetaDocument::decode(&with(bad.clone()).encode()).is_err(),
                "{bad:?}"
            );
        }
    }
}
