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
//!   tracked file's inode (`shared`: an ignored file or a bulk file hardlinked to a tracked one).
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
//! objects use for names (`tree.rs` on the read-fidelity change): the bytes as UTF-8 when they
//! are UTF-8 and hold no character of `U+10FF80..=U+10FFFF`; otherwise each byte of an invalid
//! sequence, and each byte of such a character, becomes `U+10FF00 + byte`. The mapping is a
//! bijection ([`key_of`], [`bytes_of`]), and `/` is never escaped, so a path keys component by
//! component. An entry whose key was escaped also carries its bytes, hex, in `raw_path`
//! (`raw_member` for a shared link's other name); a reader takes those when present. A path that
//! is UTF-8 (every path, in practice) encodes as plain text with no extra field.

use std::borrow::Cow;
use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::ffi::OsStr;
use std::fs::{self, Metadata};
use std::io::{self, Read};
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::path::{Path, PathBuf};

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

fn io_err(path: &[u8]) -> impl FnOnce(io::Error) -> MetaError + '_ {
    move |source| MetaError::Io {
        path: String::from_utf8_lossy(path).into_owned(),
        source,
    }
}

// ---------------------------------------------------------------------------------------------
// Keys: byte strings as JSON strings (the dir objects' name encoding).
// ---------------------------------------------------------------------------------------------

/// `U+10FF00`: an escaped byte `b` is the character `ESCAPE_BASE + b`.
const ESCAPE_BASE: u32 = 0x10_FF00;
/// The first character of the escape range (`ESCAPE_BASE + 0x80`).
const ESCAPE_FIRST: u32 = 0x10_FF80;

fn is_escape_char(c: char) -> bool {
    u32::from(c) >= ESCAPE_FIRST
}

fn escaped(b: u8) -> char {
    // `ESCAPE_BASE + b` for `b` in 0..=255 is below `char::MAX` and not a surrogate.
    char::from_u32(ESCAPE_BASE + u32::from(b)).unwrap_or(char::REPLACEMENT_CHARACTER)
}

/// The key of a byte string (see the module docs).
#[must_use]
pub fn key_of(bytes: &[u8]) -> Cow<'_, str> {
    if let Ok(s) = std::str::from_utf8(bytes)
        && !s.chars().any(is_escape_char)
    {
        return Cow::Borrowed(s);
    }
    let mut out = String::with_capacity(bytes.len() + 8);
    for chunk in bytes.utf8_chunks() {
        for c in chunk.valid().chars() {
            if is_escape_char(c) {
                let mut buf = [0u8; 4];
                out.extend(c.encode_utf8(&mut buf).bytes().map(escaped));
            } else {
                out.push(c);
            }
        }
        out.extend(chunk.invalid().iter().copied().map(escaped));
    }
    Cow::Owned(out)
}

/// The bytes a key stands for: the inverse of [`key_of`].
#[must_use]
pub fn bytes_of(key: &str) -> Cow<'_, [u8]> {
    if !key.chars().any(is_escape_char) {
        return Cow::Borrowed(key.as_bytes());
    }
    let mut out = Vec::with_capacity(key.len());
    for c in key.chars() {
        if is_escape_char(c) {
            // In the escape range, so `c - ESCAPE_BASE` is 0x80..=0xFF.
            out.push(u8::try_from(u32::from(c) - ESCAPE_BASE).unwrap_or(b'?'));
        } else {
            let mut buf = [0u8; 4];
            out.extend_from_slice(c.encode_utf8(&mut buf).as_bytes());
        }
    }
    Cow::Owned(out)
}

/// The hex of a key's bytes when the key was escaped (`raw_path`, `raw_member`).
#[must_use]
pub fn raw_of(key: &str) -> Option<String> {
    key.chars()
        .any(is_escape_char)
        .then(|| hex::encode(bytes_of(key)))
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

/// The overlay document: entries sorted by path, hardlink groups sorted (each group's members
/// sorted, the first being the one the others link to), shared links sorted. Encodes
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
    /// Root-relative nested repositories (the workspace class carries them).
    pub nested: Vec<String>,
    /// Absolute paths left out (the staging directory, the harness home).
    pub skip_abs: Vec<PathBuf>,
}

fn under(rel: &[u8], set: &[String]) -> bool {
    set.iter().any(|e| {
        let e = e.trim_matches('/').as_bytes();
        !e.is_empty()
            && (rel == e
                || rel
                    .strip_prefix(e)
                    .is_some_and(|r| r.first() == Some(&b'/')))
    })
}

impl MetaScope {
    /// Directories under the root the overlay covers, as root-relative bytes (empty is the
    /// root), with their metadata: the walk prunes `.git`, the excludes, bulk directories,
    /// nested repositories and every directory git reports ignored. A directory that cannot be
    /// listed is kept and not descended into (git cannot see into it either); one that
    /// vanished mid-walk is skipped.
    fn directories(&self, repo: &GitRepo) -> Result<BTreeMap<Vec<u8>, Metadata>, MetaError> {
        let out = repo.run(&[
            "ls-files",
            "-o",
            "-i",
            "--exclude-standard",
            "--directory",
            "-z",
        ])?;
        let ignored: BTreeSet<&[u8]> = out
            .stdout
            .split(|b| *b == 0)
            .filter_map(|p| p.strip_suffix(b"/"))
            .collect();
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
                let bytes = rel.as_os_str().as_bytes();
                !(e.file_name() == ".git"
                    || under(bytes, &self.excludes)
                    || under(bytes, &self.nested)
                    || ignored.contains(bytes)
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
                .unwrap_or(entry.path())
                .as_os_str()
                .as_bytes();
            let meta = match fs::symlink_metadata(entry.path()) {
                Ok(meta) if meta.is_dir() => meta,
                Ok(_) => continue,
                Err(e) if e.kind() == io::ErrorKind::NotFound => continue,
                Err(e) => return Err(io_err(rel)(e)),
            };
            dirs.insert(rel.to_vec(), meta);
        }
        Ok(dirs)
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
    /// The document (without `shared`, which the caller fills from the other classes).
    pub doc: MetaDocument,
    /// Tracked files whose inode has names the overlay does not hold.
    pub outside: Vec<OutsideLinks>,
    /// Paths of the worktree tree whose metadata could not be read (a directory above them
    /// that cannot be searched): never taken as gone.
    pub unreadable: Vec<UnreadableMeta>,
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
/// every directory in `scope`. A path that changed kind or vanished since the tree was written
/// is left out: the next capture sees the change. A tracked path whose metadata cannot be read
/// (git carried its content from the previous capture, `gitpack.rs`) is reported in
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
    let carried: HashMap<&str, &MetaEntry> = carry
        .map(|doc| doc.entries.iter().map(|e| (e.path.as_str(), e)).collect())
        .unwrap_or_default();
    // (dev, ino) → (key, blob, nlink) of every file with more than one name.
    type Named = (String, Vec<u8>, u64);
    let mut inodes: BTreeMap<(u64, u64), Vec<Named>> = BTreeMap::new();
    for tp in tree_paths(repo, worktree_tree)? {
        let meta = match fs::symlink_metadata(scope.root.join(os(&tp.path))) {
            Ok(meta) => meta,
            Err(e) if e.kind() == io::ErrorKind::NotFound => continue,
            Err(e) if e.kind() == io::ErrorKind::PermissionDenied => {
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
            Err(e) => return Err(io_err(&tp.path)(e)),
        };
        if kind_of(&meta) != Some(tp.kind) {
            continue;
        }
        let entry = entry_of(&tp.path, tp.kind, &meta);
        if tp.kind == MetaKind::File && meta.nlink() > 1 {
            inodes.entry((meta.dev(), meta.ino())).or_default().push((
                entry.path.clone(),
                tp.blob,
                meta.nlink(),
            ));
        }
        entries.insert(entry.path.clone(), entry);
    }
    for (rel, meta) in scope.directories(repo)? {
        let entry = entry_of(&rel, MetaKind::Dir, &meta);
        entries.entry(entry.path.clone()).or_insert(entry);
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
        },
        outside,
        unreadable,
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
    /// Other classes' names it linked to a tracked file (the class's index must learn their new
    /// inode): class, member key, metadata after the link.
    pub relinked: Vec<(LinkClass, String, Metadata)>,
}

fn same_bytes(a: &Path, b: &Path) -> io::Result<bool> {
    let (ma, mb) = (fs::metadata(a)?, fs::metadata(b)?);
    if ma.len() != mb.len() {
        return Ok(false);
    }
    let (mut fa, mut fb) = (fs::File::open(a)?, fs::File::open(b)?);
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
        match fs::symlink_metadata(&abs) {
            Ok(meta) if meta.is_dir() => {}
            Ok(meta) => {
                return Err(MetaError::Mismatch {
                    path: e.path.clone(),
                    reason: format!("a directory on the plan, a {:?} on disk", kind_of(&meta)),
                });
            }
            Err(err) if err.kind() == io::ErrorKind::NotFound => {
                fs::create_dir_all(&abs).map_err(io_err(rel))?;
                applied.changed += 1;
            }
            Err(err) => return Err(io_err(rel)(err)),
        }
    }
    // Every other path is on disk as the checkout wrote it.
    for (rel, e) in entries.iter().filter(|(_, e)| e.kind != MetaKind::Dir) {
        let meta = fs::symlink_metadata(abs_of(root, rel)).map_err(io_err(rel))?;
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
        .into_keys()
        .filter(|rel| !rel.is_empty() && !planned.contains(rel.as_slice()))
        .collect();
    stale.sort_by(|a, b| b.len().cmp(&a.len()).then_with(|| a.cmp(b)));
    for rel in stale {
        match fs::remove_dir(root.join(os(&rel))) {
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
        let canonical = root.join(os(&first));
        let target = fs::symlink_metadata(&canonical).map_err(io_err(&first))?;
        for member in rest {
            let member = bytes_of(member);
            let abs = root.join(os(&member));
            let meta = fs::symlink_metadata(&abs).map_err(io_err(&member))?;
            if (meta.dev(), meta.ino()) == (target.dev(), target.ino()) {
                continue;
            }
            fs::remove_file(&abs).map_err(io_err(&member))?;
            fs::hard_link(&canonical, &abs).map_err(io_err(&member))?;
            applied.changed += 1;
        }
    }
    // Other classes' names of a tracked file's inode.
    let mut relinked = Vec::new();
    for link in &doc.shared {
        let tracked = bytes_of(&link.path);
        let canonical = root.join(os(&tracked));
        let member = bytes_of_pair(&link.member, link.raw_member.as_deref())?;
        let Some(abs) = resolve(link.class, &member) else {
            continue;
        };
        let target = fs::symlink_metadata(&canonical).map_err(io_err(&tracked))?;
        let meta = match fs::symlink_metadata(&abs) {
            Ok(meta) if meta.is_file() => meta,
            Ok(_) => continue,
            Err(e) if e.kind() == io::ErrorKind::NotFound => continue,
            Err(e) => return Err(io_err(&member)(e)),
        };
        if (meta.dev(), meta.ino()) == (target.dev(), target.ino()) {
            continue;
        }
        if !same_bytes(&canonical, &abs).map_err(io_err(&member))? {
            tracing::debug!(tracked = %link.path, member = %link.member, "shared hardlink: contents differ; left unlinked");
            continue;
        }
        fs::remove_file(&abs).map_err(io_err(&member))?;
        fs::hard_link(&canonical, &abs).map_err(io_err(&member))?;
        relinked.push((link.class, link.member.clone(), abs, member));
        applied.changed += 1;
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
        let meta = fs::symlink_metadata(&abs).map_err(io_err(&bytes))?;
        applied.relinked.push((class, member, meta));
    }
    Ok(applied)
}

/// Set one path's mode and mtime where they differ; whether anything changed.
fn settle(root: &Path, rel: &[u8], e: &MetaEntry) -> Result<bool, MetaError> {
    let abs = abs_of(root, rel);
    let meta = fs::symlink_metadata(&abs).map_err(io_err(rel))?;
    let mut changed = false;
    if let Some(mode) = e.mode
        && e.kind != MetaKind::Symlink
        && meta.mode() & 0o7777 != mode
    {
        fs::set_permissions(&abs, fs::Permissions::from_mode(mode)).map_err(io_err(rel))?;
        changed = true;
    }
    if mtime_ns(&meta) != e.mtime {
        set_mtime_nofollow(&abs, e.mtime).map_err(io_err(rel))?;
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
}
