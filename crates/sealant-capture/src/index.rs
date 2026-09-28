//! The tree index and walker for chunked classes: a full stat scan of one or more mounted
//! directories under the capture policy, change detection by `(size, mtime, ctime, inode,
//! device, mode)` with chunk-hash confirmation, and the dir-object builder (file groups, hardlink
//! groups, bounded re-reads of files that change underneath the reader).
//!
//! Grown from `sealant_fs::snapshot`, with its own policy: `DEFAULT_IGNORES` is right for
//! telemetry and wrong for the work product.
//!
//! # What is never captured
//!
//! Outside the daemon's own paths (its staging and `<root>/.sealantd`, [`DAEMON_DIR`]) and the
//! harness credential files ([`CREDENTIAL_FILES`], re-injected at launch), a chunked class
//! carries every regular file, directory and symlink under its roots whatever it is called — a
//! user's `Cargo.lock`, `*.pid`, SQLite `-shm`, a `.pack` without an `.idx`. The only other
//! exclusions are git's own transient bookkeeping *inside a git directory*
//! ([`is_git_transient`]); sockets, fifos and devices are not file content and are skipped.
//!
//! # Reading honestly
//!
//! A path that disappears while it is walked or read (`ENOENT`, `ENOTDIR`, `EISDIR`) was
//! removed, and a snap leaves it out. A path that exists but cannot be listed, stat'ed or read
//! (permission denied, an I/O error) is *unreadable*, never a removal: a `final` snap
//! ([`TreeBuilder::strict`]) fails with [`UnreadableWork`] naming every such path, and any other
//! snap carries the path's last read content forward (from the index), marks the entry
//! `unread`, and says so in the log.
//!
//! # When a file is re-read
//!
//! A file is read again unless its stat key — size, mtime, ctime (nanoseconds), inode, device
//! and mode — matches the index *and* its last read was not racy *and* the watcher has not
//! reported a write to it since ([`Suspects`]). ctime cannot be set from user space, so an
//! overwrite that restores size and mtime still moves it. A read is racy when the file's ctime
//! lies within the racy window of the moment the read began: a same-size write right after the
//! read can land in the same timestamp tick (filesystem timestamps are coarse), so the next
//! build re-reads rather than trusts the stat (git's "racily clean" rule).

use std::collections::{BTreeMap, HashMap, HashSet};
use std::fs::{self, Metadata};
use std::io;
use std::os::unix::ffi::OsStringExt;
use std::os::unix::fs::MetadataExt;
use std::path::{Component, Path, PathBuf};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};

use crate::chunk::{ChunkId, chunk_reader};
use crate::longpath;
use crate::tree::{DirEntry, DirObject, EncodedDir, key_of_os};

/// Bounded attempts for a file (or file group) that changes underneath the reader.
pub const READ_ATTEMPTS: u32 = 3;

/// A read whose file's ctime is this close to the start of the read is racy: the next build
/// re-reads the file instead of trusting its stat. Two seconds covers the coarsest common
/// timestamp granularity (FAT's two seconds; ext4, xfs, btrfs and tmpfs keep nanoseconds on a
/// clock that ticks every few milliseconds).
pub const RACY_WINDOW: Duration = Duration::from_secs(2);

/// Directory names treated as bulk (dependencies and build outputs) wherever they appear.
pub const DEFAULT_BULK_DIRS: &[&str] = &[
    "node_modules",
    "dist",
    "build",
    "target",
    ".turbo",
    ".next",
    ".output",
    ".cache",
    "coverage",
];

/// Harness credential files excluded relative to the harness home (ADR-0015 open question 2).
pub const CREDENTIAL_FILES: &[&str] = &[".claude/.credentials.json", ".codex/auth.json"];

/// The daemon's own directory under the workspace root (staging lives beneath it).
pub const DAEMON_DIR: &str = ".sealantd";

/// Whether a virtual path (`/`-separated) is git's transient bookkeeping inside a git directory
/// (a `.git` component; the workspace class mounts the repository's git dir at `.git`). Only
/// the files git itself names for a transaction in progress are left out, each at the place
/// git writes it; every other file in a git directory is the user's — a hook project's
/// `hooks/Cargo.lock`, a config include called `personal.lock` — and is captured, in every
/// class (review 2026-09-28, eleventh pass, #2; cross-repo decision 33: an allow-list, never a
/// pattern). The transient ones ([`git_dir_transient`]):
///
/// - a lock git takes to write a file of its own (`<file>.lock`, renamed over `<file>` when the
///   write is done; the rename is what makes it real, and the next snap sees `<file>`): the
///   index (`index.lock`, a partial commit's `next-index-<pid>.lock`), `HEAD` and the other
///   root refs (`ORIG_HEAD.lock`, `*_HEAD.lock`, `AUTO_MERGE.lock`, `MERGE_RR.lock`, …),
///   `config.lock`, `config.worktree.lock`, `packed-refs.lock`, `shallow.lock`,
///   `gc.pid.lock`, `gc.log.lock`, any `.lock` under `refs/` or `logs/` (a ref name never ends
///   in `.lock`: `git check-ref-format`), under `reftable/` (`tables.list.lock`), under an
///   operation's directory (`rebase-merge/`, `rebase-apply/`, `sequencer/`), `info/refs.lock`,
///   `info/sparse-checkout.lock`, and in the object store `objects/maintenance.lock`,
///   `objects/schedule.lock`, `objects/info/*.lock` (`alternates`, `packs`, `commit-graph`),
///   `objects/info/commit-graphs/*.lock`, `objects/pack/multi-pack-index.lock` and
///   `objects/pack/multi-pack-index.d/*.lock`;
/// - `gc.pid`, the host and pid of a running `git gc`, meaningless on another executor;
/// - under `objects/`, whatever git is still writing or receiving: a `tmp_*` or `incoming-*`
///   name (a loose object mid-write, a pack mid-`index-pack`, a push's quarantine) and a
///   `.tmp-*` name in `objects/pack/` (a `git repack` in progress). A `.pack` without its `.idx`
///   in `objects/pack/` is left out by the listing ([`Listing::mount`]).
///
/// The same names in a linked worktree's administrative directory (`worktrees/<name>/`: its
/// `index`, `HEAD`, pseudo-refs, `refs/`, `logs/`, operation directories and
/// `config.worktree`) and in a submodule's git directory (`modules/<name>/`, all of them) are
/// transient too.
///
/// A final flush drops them as well. It runs after every writer was stopped, so a lock found
/// then is stale: the git that took it is gone and nothing will rename it. Its content is a
/// write git never made real — the file beside it is what git reads — and git's own recovery
/// is to remove it. Captured, it would come back and make every later git command of that kind
/// fail; refusing the final flush over it would keep an executor a killed git left a lock on
/// from ever completing. So neither: the lock is not work product, and a restore has none.
///
/// A file with any of these names outside a git directory is a user's file and is captured.
#[must_use]
pub fn is_git_transient(v: &str) -> bool {
    let comps: Vec<&str> = v.split('/').filter(|c| !c.is_empty()).collect();
    let Some(git_at) = comps.iter().rposition(|c| *c == ".git") else {
        return false;
    };
    git_dir_transient(&comps[git_at + 1..], GitDirKind::Repository)
}

/// What a directory holding git state is: a repository's git directory, or a linked worktree's
/// administrative directory (per-worktree state only).
#[derive(Clone, Copy, PartialEq, Eq)]
enum GitDirKind {
    Repository,
    Worktree,
}

/// Names under a git directory that are git's own and never a submodule's name component:
/// where a `modules/<name>/` prefix cannot end.
const GIT_DIR_NAMES: &[&str] = &[
    "hooks",
    "info",
    "logs",
    "lfs",
    "modules",
    "objects",
    "refs",
    "reftable",
    "rebase-apply",
    "rebase-merge",
    "rr-cache",
    "sequencer",
    "worktrees",
];

/// Root refs git writes through a lock whose names do not end in `_HEAD`.
const ROOT_REFS: &[&str] = &[
    "HEAD",
    "AUTO_MERGE",
    "BISECT_EXPECTED_REV",
    "MERGE_AUTOSTASH",
    "MERGE_RR",
    "NOTES_MERGE_PARTIAL",
    "NOTES_MERGE_REF",
];

/// [`is_git_transient`] for `rel`, a path's components relative to a git directory of `kind`.
fn git_dir_transient(rel: &[&str], kind: GitDirKind) -> bool {
    let Some((name, dirs)) = rel.split_last() else {
        return false;
    };
    let repository = kind == GitDirKind::Repository;
    let lock = name.strip_suffix(".lock");
    match dirs {
        [] => {
            let Some(file) = lock else {
                return repository && *name == "gc.pid";
            };
            let root_ref = ROOT_REFS.contains(&file)
                || file.strip_suffix("_HEAD").is_some_and(|stem| {
                    !stem.is_empty()
                        && stem
                            .bytes()
                            .all(|b| b.is_ascii_uppercase() || b == b'_' || b == b'-')
                });
            let next_index = file
                .strip_prefix("next-index-")
                .is_some_and(|pid| !pid.is_empty() && pid.bytes().all(|b| b.is_ascii_digit()));
            root_ref
                || next_index
                || matches!(file, "index" | "config.worktree")
                || (repository
                    && matches!(
                        file,
                        "config" | "packed-refs" | "shallow" | "gc.pid" | "gc.log"
                    ))
        }
        ["refs", ..] | ["logs", ..] | ["rebase-merge"] | ["rebase-apply"] | ["sequencer"] => {
            lock.is_some()
        }
        ["reftable"] => repository && lock.is_some(),
        ["info"] => repository && matches!(*name, "refs.lock" | "sparse-checkout.lock"),
        ["objects", within @ ..] => repository && objects_transient(within, name),
        ["worktrees", _, ..] if repository => git_dir_transient(&rel[2..], GitDirKind::Worktree),
        ["modules", ..] if repository => (2..rel.len()).any(|end| {
            rel[1..end].iter().all(|c| !GIT_DIR_NAMES.contains(c))
                && git_dir_transient(&rel[end..], GitDirKind::Repository)
        }),
        _ => false,
    }
}

/// [`git_dir_transient`] under `objects/`: `within` the directories below it, `name` the file.
fn objects_transient(within: &[&str], name: &str) -> bool {
    let writing = |c: &str| c.starts_with("tmp_") || c.starts_with("incoming-");
    if within.iter().any(|c| writing(c)) || writing(name) {
        return true;
    }
    let lock = name.ends_with(".lock");
    match within {
        [] => matches!(name, "maintenance.lock" | "schedule.lock"),
        ["info"] | ["info", "commit-graphs"] | ["pack", "multi-pack-index.d"] => lock,
        ["pack"] => name == "multi-pack-index.lock" || name.starts_with(".tmp-"),
        _ => false,
    }
}

/// Whether a virtual path is a pack in a git directory's `objects/pack/` (whose `.idx` decides
/// whether git has finished writing it).
fn in_git_pack_dir(v: &str) -> bool {
    let comps: Vec<&str> = v.split('/').filter(|c| !c.is_empty()).collect();
    let Some(git_at) = comps.iter().rposition(|c| *c == ".git") else {
        return false;
    };
    let rel = &comps[git_at + 1..];
    let n = rel.len();
    n >= 3 && rel[n - 3] == "objects" && rel[n - 2] == "pack" && (n == 3 || rel[0] == "modules")
}

/// Whether a virtual path lies inside a git directory.
fn in_git_dir(v: &str) -> bool {
    v.split('/').any(|c| c == ".git")
}

/// Whether a file type is captured at all (sockets, fifos and devices are not).
#[must_use]
pub fn is_capturable_type(meta: &Metadata) -> bool {
    let ft = meta.file_type();
    ft.is_file() || ft.is_dir() || ft.is_symlink()
}

/// Whether an I/O error means the path is gone (removed or replaced while it was walked or
/// read), as opposed to present and unreadable.
#[must_use]
pub fn is_vanished(error: &io::Error) -> bool {
    matches!(
        error.kind(),
        io::ErrorKind::NotFound | io::ErrorKind::NotADirectory | io::ErrorKind::IsADirectory
    )
}

/// Modification time as nanoseconds since the Unix epoch, exactly: signed 64-bit seconds and
/// the nanoseconds within them, which no filesystem time overflows. What the stat comparisons
/// that decide whether a file changed use, and what a capture records (review 2026-09-28, ninth
/// pass, #3 and tenth pass: a time past 2262 was recorded as the last nanosecond of 2262, by a
/// final capture and then by an automatic one, and a restore wrote that false time).
#[must_use]
pub fn mtime_ns(meta: &Metadata) -> i128 {
    i128::from(meta.mtime()) * 1_000_000_000 + i128::from(meta.mtime_nsec())
}

/// The first and last nanosecond a signed 64-bit count holds: 1677-09-21 to 2262-04-11. A
/// recorded time outside them is a wide time: written exactly all the same, but read only by
/// a store that reads the `wide_times` manifest feature (`crate::registrar::MANIFEST_FEATURES`),
/// and by a restore of this build (one before it refuses the number rather than write another
/// time).
pub const NARROW_NS: (i128, i128) = (i64::MIN as i128, i64::MAX as i128);

/// Whether `ns` is a wide time ([`NARROW_NS`]).
#[must_use]
pub fn is_wide_ns(ns: i128) -> bool {
    ns < NARROW_NS.0 || ns > NARROW_NS.1
}

/// Why `meta`'s modification time cannot be recorded for a store that does not read
/// `wide_times` (it is a wide time, [`NARROW_NS`]); `Ok` when it can. A final snap for such a
/// store fails naming the path (`unreadable`); an automatic one records the time exactly
/// all the same (a restore of this build writes it back; the store keeps the number).
pub fn narrow_mtime(meta: &Metadata) -> Result<(), String> {
    if is_wide_ns(mtime_ns(meta)) {
        return Err(format!(
            "its modification time ({} s since the epoch) is outside signed 64-bit nanoseconds              (1677 to 2262), and the store does not read the manifest feature wide_times",
            meta.mtime()
        ));
    }
    Ok(())
}

/// Status-change time as nanoseconds since the Unix epoch, exactly ([`mtime_ns`]).
#[must_use]
pub fn ctime_ns(meta: &Metadata) -> i128 {
    i128::from(meta.ctime()) * 1_000_000_000 + i128::from(meta.ctime_nsec())
}

fn now_ns() -> i128 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| i128::try_from(d.as_nanos()).unwrap_or(i128::MAX))
}

/// Stat fields that decide whether a file must be re-read.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct FileStat {
    /// Size.
    pub size: u64,
    /// mtime in nanoseconds ([`mtime_ns`]).
    pub mtime: i128,
    /// Inode.
    pub ino: u64,
    /// Device.
    pub dev: u64,
    /// ctime in nanoseconds (0 in an index written before it was recorded, which then never
    /// matches, so such a file is read once more).
    #[serde(default)]
    pub ctime: i128,
    /// `st_mode` permission bits (what a carried entry is written with).
    #[serde(default)]
    pub mode: u32,
}

impl FileStat {
    /// From metadata.
    #[must_use]
    pub fn of(meta: &Metadata) -> Self {
        Self {
            size: meta.len(),
            mtime: mtime_ns(meta),
            ino: meta.ino(),
            dev: meta.dev(),
            ctime: ctime_ns(meta),
            mode: meta.mode() & 0o7777,
        }
    }
}

/// A file's last known stat and chunk list.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct IndexedFile {
    /// Stat at the last read.
    pub stat: FileStat,
    /// Chunks at the last read.
    pub chunks: Vec<ChunkId>,
}

/// The tree index: virtual path → last known stat and chunks. Persisted between snaps so an
/// unchanged file is never re-read.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct TreeIndex {
    /// Files by virtual path.
    pub files: HashMap<String, IndexedFile>,
    /// Files whose last read was racy (see the module docs): re-read by the next build whatever
    /// their stat says.
    #[serde(default, skip_serializing_if = "HashSet::is_empty")]
    pub racy: HashSet<String>,
}

impl TreeIndex {
    /// Load from a JSON file; a missing or unreadable file is an empty index.
    #[must_use]
    pub fn load(path: &Path) -> Self {
        fs::read(path)
            .ok()
            .and_then(|b| serde_json::from_slice(&b).ok())
            .unwrap_or_default()
    }

    /// Save as JSON (write-then-rename).
    pub fn save(&self, path: &Path) -> io::Result<()> {
        use crate::io_at::IoAt;
        let tmp = path.with_extension("tmp");
        fs::write(&tmp, serde_json::to_vec(self)?).at("write", &tmp)?;
        fs::rename(tmp, path).at("rename into", path)
    }
}

/// Paths the watcher saw written since they were last read: never trusted from the index.
pub type Suspects = HashSet<PathBuf>;

/// One entry of a walk: a virtual path inside the class, its source and its metadata.
#[derive(Debug, Clone)]
pub struct Source {
    /// Absolute source path.
    pub abs: PathBuf,
    /// lstat metadata.
    pub meta: Metadata,
}

/// A path the walk found but could not list or stat.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Unreadable {
    /// Absolute path.
    pub abs: PathBuf,
    /// What the filesystem said.
    pub error: String,
}

/// The set of paths a class captures, keyed by virtual path (`/`-separated keys, relative to
/// the class root; see `tree` for names that are not UTF-8), directories included.
#[derive(Debug, Default)]
pub struct Listing {
    /// Entries.
    pub entries: BTreeMap<String, Source>,
    /// Paths that exist but could not be listed (a directory) or stat'ed, by virtual path.
    /// What is under them is unknown, never absent.
    pub unreadable: BTreeMap<String, Unreadable>,
    /// Mount roots that are symlinks to a directory (a `.git` moved aside and linked back, a
    /// harness home configured as a link), by virtual path: the link text, as bytes. The walk
    /// goes through the link, and the root's entry is the directory it names (review
    /// 2026-09-28, eighth pass, #1).
    pub root_links: BTreeMap<String, Vec<u8>>,
}

fn join_virtual(prefix: &str, rel: &str) -> String {
    match (prefix.is_empty(), rel.is_empty()) {
        (true, _) => rel.to_owned(),
        (_, true) => prefix.to_owned(),
        _ => format!("{prefix}/{rel}"),
    }
}

/// The key of a relative path (`/` is never escaped, so the key of the whole path is the keys
/// of its components joined by `/`).
#[must_use]
pub fn rel_key(rel: &Path) -> String {
    key_of_os(rel.as_os_str()).into_owned()
}

impl Listing {
    /// Add one path, creating (stat'ing) missing ancestor directories from `ancestor_abs`.
    fn add(&mut self, virtual_path: String, abs: PathBuf, meta: Metadata) {
        self.entries.insert(virtual_path, Source { abs, meta });
    }

    /// Record a path that exists but could not be listed or stat'ed.
    pub fn note_unreadable(&mut self, virtual_path: String, abs: PathBuf, error: &io::Error) {
        tracing::debug!(path = %abs.display(), %error, "capture: unreadable");
        self.unreadable.entry(virtual_path).or_insert(Unreadable {
            abs,
            error: error.to_string(),
        });
    }

    /// Make sure every ancestor of `virtual_path` is present, stat'ing them under `abs_base`
    /// (the absolute directory that corresponds to `virtual_base`).
    fn ensure_ancestors(&mut self, virtual_path: &str, virtual_base: &str, abs_base: &Path) {
        let Some(rel) = virtual_path
            .strip_prefix(virtual_base)
            .map(|r| r.trim_start_matches('/'))
        else {
            return;
        };
        let mut acc = String::new();
        let mut abs = abs_base.to_path_buf();
        for comp in rel.split('/') {
            if comp.is_empty() {
                continue;
            }
            acc = join_virtual(&acc, comp);
            abs = abs.join(crate::tree::os_of_key(comp));
            let v = join_virtual(virtual_base, &acc);
            if v == virtual_path {
                break;
            }
            if !self.entries.contains_key(&v)
                && let Ok(meta) = longpath::symlink_metadata(&abs)
            {
                self.entries.insert(
                    v,
                    Source {
                        abs: abs.clone(),
                        meta,
                    },
                );
            }
        }
    }

    /// Mount `<abs_base>/<rel>` at `<virtual_base>/<rel>`, walking it fully; the base itself and
    /// the ancestors between the base and `rel` are added as directories. `prune` decides per
    /// directory (absolute path, virtual path, name) whether to descend; `include` decides per
    /// entry whether to keep it — a directory that is not included is still added lazily as the
    /// ancestor of an included descendant. Git's transient bookkeeping ([`is_git_transient`],
    /// and a `.pack` without its `.idx` inside a git directory) and uncapturable types are left
    /// out here. A path that cannot be listed or stat'ed and that `include` keeps is recorded
    /// in [`Listing::unreadable`]; one that vanished mid-walk is skipped. Entries already
    /// present are not overwritten (the first mount wins, so overlays are expressed by mount
    /// order).
    pub fn mount<P, I>(
        &mut self,
        virtual_base: &str,
        abs_base: &Path,
        rel: impl AsRef<Path>,
        mut prune: P,
        mut include: I,
    ) where
        P: FnMut(&Path, &str, &str) -> bool,
        I: FnMut(&Path, &str, &str) -> bool,
    {
        let rel = rel.as_ref();
        let rel_v = rel_key(rel);
        let rel_v = rel_v.trim_matches('/');
        let abs_dir = if rel_v.is_empty() {
            abs_base.to_path_buf()
        } else {
            abs_base.join(rel)
        };
        let virtual_root = join_virtual(virtual_base, rel_v);
        // The base is a configured root (`.git`, the worktree, the harness home): walked through
        // a link when it is one, and one that cannot be walked as a directory is unreadable —
        // never an empty listing (review 2026-09-28, eighth pass, #1).
        let Some(base_meta) = self.root_dir_meta(virtual_base, abs_base) else {
            return;
        };
        let root_meta = if rel_v.is_empty() {
            base_meta.clone()
        } else {
            match longpath::symlink_metadata(&abs_dir) {
                Ok(meta) => meta,
                Err(error) => {
                    if !is_vanished(&error) {
                        self.note_unreadable(virtual_root, abs_dir, &error);
                    }
                    return;
                }
            }
        };
        if !root_meta.is_dir() {
            return;
        }
        if !virtual_base.is_empty() && !self.entries.contains_key(virtual_base) {
            self.add(virtual_base.to_owned(), abs_base.to_path_buf(), base_meta);
        }
        if !virtual_root.is_empty() && !self.entries.contains_key(&virtual_root) {
            self.ensure_ancestors(&virtual_root, virtual_base, abs_base);
            self.add(virtual_root.clone(), abs_dir.clone(), root_meta);
        }
        let virtual_of = |path: &Path| -> String {
            let rel = path.strip_prefix(&abs_dir).unwrap_or(path);
            join_virtual(&virtual_root, &rel_key(rel))
        };
        let name_of_path = |path: &Path| -> String {
            path.file_name()
                .map(|n| key_of_os(n).into_owned())
                .unwrap_or_default()
        };
        // Per-directory name sets, for the `.pack` without `.idx` rule.
        let mut dir_names: HashMap<PathBuf, HashSet<String>> = HashMap::new();
        // A path of any length: a tree deeper than `PATH_MAX` is walked like any other.
        longpath::walk(&abs_dir, &mut |visit| {
            let (path, kind) = match visit {
                longpath::Visit::Entry { path, kind, .. } => (path, kind),
                longpath::Visit::Error { path, error, .. } => {
                    self.walk_error(path, &error, &virtual_of, &name_of_path, &mut include);
                    return false;
                }
            };
            let v = virtual_of(path);
            let name = name_of_path(path);
            if kind == longpath::Kind::Dir && prune(path, &v, &name) {
                return false;
            }
            let meta = match longpath::symlink_metadata(path) {
                Ok(meta) => meta,
                Err(error) => {
                    self.walk_error(path, &error, &virtual_of, &name_of_path, &mut include);
                    return false;
                }
            };
            if !is_capturable_type(&meta) {
                return false;
            }
            if !meta.is_dir() && in_git_dir(&v) {
                if is_git_transient(&v) {
                    return false;
                }
                if let Some(stem) = name.strip_suffix(".pack")
                    && in_git_pack_dir(&v)
                {
                    let parent = path.parent().map(Path::to_path_buf).unwrap_or_default();
                    let names = dir_names.entry(parent.clone()).or_insert_with(|| {
                        longpath::read_dir(&parent)
                            .map(|names| {
                                names
                                    .into_iter()
                                    .map(|(n, _)| key_of_os(&n).into_owned())
                                    .collect()
                            })
                            .unwrap_or_default()
                    });
                    if !names.contains(&format!("{stem}.idx")) {
                        tracing::debug!(path = %path.display(), "skipping .pack without .idx");
                        return false;
                    }
                }
            }
            if !include(path, &v, &name) || self.entries.contains_key(&v) {
                // A directory is walked all the same: an included descendant brings it in.
                return true;
            }
            self.ensure_ancestors(&v, &virtual_root, &abs_dir);
            self.add(v, path.to_path_buf(), meta);
            true
        });
    }

    /// The metadata a mount's base is walked by: its own when it is a directory; the directory
    /// it names when it is a symlink to one (a `.git` moved beside the worktree and linked
    /// back, a harness home configured as a link) — git and the harness read through the link,
    /// and so does the walk, with the link text kept in [`Self::root_links`]. `None` when there
    /// is nothing to walk: the base (or the target of its link) does not exist, or it cannot be
    /// walked as the directory the class holds (a file, a link to one, a loop, a permission
    /// error), which is recorded unreadable — what is there is not captured, and a final snap
    /// says so instead of listing nothing (review 2026-09-28, eighth pass, #1).
    fn root_dir_meta(&mut self, virtual_base: &str, abs_base: &Path) -> Option<Metadata> {
        let meta = match longpath::symlink_metadata(abs_base) {
            Ok(meta) => meta,
            Err(error) => {
                if !is_vanished(&error) {
                    self.note_unreadable(virtual_base.to_owned(), abs_base.to_path_buf(), &error);
                }
                return None;
            }
        };
        if meta.is_dir() {
            return Some(meta);
        }
        let error = if meta.is_symlink() {
            match longpath::metadata(abs_base) {
                Ok(target) if target.is_dir() => {
                    if let Ok(link) = longpath::read_link(abs_base) {
                        self.root_links
                            .insert(virtual_base.to_owned(), link.into_os_string().into_vec());
                    }
                    return Some(target);
                }
                // A dangling link: nothing is there to capture.
                Err(error) if error.kind() == io::ErrorKind::NotFound => return None,
                Err(error) => error,
                Ok(_) => io::Error::other(
                    "a symlink to something other than a directory, where the class holds a \
                     directory",
                ),
            }
        } else {
            io::Error::other("not a directory, where the class holds a directory")
        };
        self.note_unreadable(virtual_base.to_owned(), abs_base.to_path_buf(), &error);
        None
    }

    /// A walk error: a vanished path is skipped, anything else `include` keeps is unreadable.
    fn walk_error<I>(
        &mut self,
        path: &Path,
        error: &io::Error,
        virtual_of: &dyn Fn(&Path) -> String,
        name_of_path: &dyn Fn(&Path) -> String,
        include: &mut I,
    ) where
        I: FnMut(&Path, &str, &str) -> bool,
    {
        if is_vanished(error) {
            return;
        }
        let v = virtual_of(path);
        if is_git_transient(&v) || !include(path, &v, &name_of_path(path)) {
            return;
        }
        self.note_unreadable(v, path.to_path_buf(), error);
    }

    /// Mount a single file at `virtual_path`.
    pub fn mount_file(
        &mut self,
        virtual_path: &str,
        virtual_base: &str,
        abs_base: &Path,
        abs: &Path,
    ) {
        let meta = match longpath::symlink_metadata(abs) {
            Ok(meta) => meta,
            Err(error) => {
                if !is_vanished(&error) {
                    self.note_unreadable(virtual_path.to_owned(), abs.to_path_buf(), &error);
                }
                return;
            }
        };
        if !is_capturable_type(&meta) || self.entries.contains_key(virtual_path) {
            return;
        }
        if is_git_transient(virtual_path) {
            return;
        }
        if !virtual_base.is_empty()
            && !self.entries.contains_key(virtual_base)
            && let Ok(base_meta) = longpath::symlink_metadata(abs_base)
        {
            self.add(virtual_base.to_owned(), abs_base.to_path_buf(), base_meta);
        }
        self.ensure_ancestors(virtual_path, virtual_base, abs_base);
        self.add(virtual_path.to_owned(), abs.to_path_buf(), meta);
    }

    /// Number of entries.
    #[must_use]
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Whether the listing is empty.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }
}

/// Whether any component of a relative path is in `names`.
#[must_use]
pub fn has_component_in(rel: &Path, names: &[String]) -> bool {
    rel.components().any(|c| match c {
        Component::Normal(n) => names.iter().any(|b| b.as_str() == n.to_string_lossy()),
        _ => false,
    })
}

/// Receives every chunk the builder reads that the store does not already hold.
pub trait ChunkSink {
    /// Whether the chunk is already stored (so its bytes need not be kept).
    fn contains(&self, id: &ChunkId) -> bool;
    /// Store a new chunk.
    fn put(&mut self, id: ChunkId, data: &[u8]) -> io::Result<()>;
    /// Whether the builder should stop at the next chunk boundary and hand back what it has
    /// (a due small-class snap is waiting on a bulk build). Never asked by a small-class build.
    fn should_yield(&self) -> bool {
        false
    }
}

/// The build stopped at a chunk boundary because the sink asked it to; the index holds every
/// file read so far, the sink every chunk, so the next attempt resumes without re-reading them.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Yielded;

/// Whether `error` is the builder's yield marker.
fn is_yield(error: &io::Error) -> bool {
    error.kind() == io::ErrorKind::Interrupted
}

/// A strict (`final`) build found work it could not read: the snap does not hold it, so it
/// fails rather than register a capture that silently lacks it. Travels inside an
/// [`io::Error`]; [`UnreadableWork::of`] finds it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UnreadableWork {
    /// `(virtual path, what the filesystem said)`, in path order.
    pub paths: Vec<(String, String)>,
}

impl UnreadableWork {
    /// The unreadable work an I/O error carries, if it is one.
    #[must_use]
    pub fn of(error: &io::Error) -> Option<&Self> {
        error.get_ref()?.downcast_ref()
    }

    /// Wrapped in an [`io::Error`], as a strict build returns it.
    #[must_use]
    pub fn into_io(self) -> io::Error {
        io::Error::other(self)
    }
}

impl std::fmt::Display for UnreadableWork {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{} path(s) could not be read, so the snap does not hold them:",
            self.paths.len()
        )?;
        for (v, error) in self.paths.iter().take(20) {
            write!(f, " {v} ({error});")?;
        }
        if self.paths.len() > 20 {
            write!(f, " and {} more", self.paths.len() - 20)?;
        }
        Ok(())
    }
}

impl std::error::Error for UnreadableWork {}

/// Counters from one build.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct BuildStats {
    /// Files listed.
    pub files: u64,
    /// Files read (chunked) this build.
    pub files_read: u64,
    /// Bytes read this build.
    pub bytes_read: u64,
    /// Chunks referenced by the tree.
    pub chunks: u64,
    /// Chunks new to the sink this build.
    pub chunks_new: u64,
    /// Files marked torn.
    pub torn: u64,
    /// Files skipped because they vanished during the build.
    pub vanished: u64,
    /// Paths that could not be read (listed, stat'ed or opened) this build.
    pub unreadable: u64,
    /// Files whose last read content was carried, marked `unread`, because they could not be
    /// read this build.
    pub carried: u64,
}

/// A path a build could not read, and whether its last read content was carried.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct UnreadablePath {
    /// Virtual path (`.git/…`, `tree/…`, `harness/…` in the workspace class).
    pub path: String,
    /// What the filesystem said.
    pub error: String,
    /// Something under it was carried from the last read (an automatic build only).
    pub carried: bool,
}

/// A built tree: the root dir object key, every dir object (new or not), the chunk set it
/// references and the updated index.
#[derive(Debug)]
pub struct BuiltTree {
    /// Root dir object.
    pub root: EncodedDir,
    /// Every dir object of the tree, keyed by sha256.
    pub dirs: HashMap<String, EncodedDir>,
    /// Every chunk the tree references.
    pub chunks: HashSet<ChunkId>,
    /// Stats.
    pub stats: BuildStats,
    /// What could not be read (an automatic build; a strict one fails instead), in path order.
    pub unreadable: Vec<UnreadablePath>,
}

/// What reading one file found.
#[derive(Debug)]
enum Read {
    /// Its chunks, the stat they correspond to, whether it is torn, whether the read was racy.
    Data {
        chunks: Vec<ChunkId>,
        stat: FileStat,
        torn: bool,
        racy: bool,
    },
    /// It is gone.
    Vanished,
    /// It is there and could not be read.
    Unreadable(io::Error),
}

impl Read {
    fn from_error(error: io::Error) -> Self {
        if is_vanished(&error) {
            Self::Vanished
        } else {
            Self::Unreadable(error)
        }
    }
}

/// A node of the tree being built: a listed path, a file carried from the index because the
/// path it lives under could not be read, or a directory standing in for one that could not be
/// listed.
enum Node<'l> {
    Listed(&'l Source),
    Carried(IndexedFile),
    CarriedDir,
}

impl Node<'_> {
    fn is_dir(&self) -> bool {
        match self {
            Node::Listed(src) => src.meta.is_dir(),
            Node::Carried(_) => false,
            Node::CarriedDir => true,
        }
    }
}

/// Builds dir objects for a [`Listing`].
pub struct TreeBuilder<'a> {
    index: &'a mut TreeIndex,
    key_for_dir: &'a dyn Fn(&str) -> String,
    strict: bool,
    narrow_times: bool,
    racy_window_ns: i128,
    suspects: Option<&'a mut Suspects>,
    /// Paths read fresh this build whose read was racy.
    racy: HashSet<String>,
}

impl std::fmt::Debug for TreeBuilder<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TreeBuilder")
            .field("index_files", &self.index.files.len())
            .field("strict", &self.strict)
            .finish_non_exhaustive()
    }
}

fn parent_of(v: &str) -> &str {
    v.rsplit_once('/').map_or("", |(p, _)| p)
}

fn name_of(v: &str) -> &str {
    v.rsplit_once('/').map_or(v, |(_, n)| n)
}

/// A file entry for content carried from the index, marked `unread`.
fn carried_entry(name: &str, mode: u32, file: &IndexedFile) -> DirEntry {
    let mut e = DirEntry::file(
        name,
        mode,
        file.stat.size,
        file.stat.mtime,
        file.chunks.clone(),
    );
    e.unread = Some(true);
    e
}

impl<'a> TreeBuilder<'a> {
    /// `key_for_dir` maps a dir object's sha256 to its store key (the epoch prefix).
    pub fn new(index: &'a mut TreeIndex, key_for_dir: &'a dyn Fn(&str) -> String) -> Self {
        Self {
            index,
            key_for_dir,
            strict: false,
            narrow_times: false,
            racy_window_ns: i128::try_from(RACY_WINDOW.as_nanos()).unwrap_or(i128::MAX),
            suspects: None,
            racy: HashSet::new(),
        }
    }

    /// A strict build (a `final` snap) fails with [`UnreadableWork`] when anything it should
    /// hold cannot be read, instead of carrying the last read content forward.
    #[must_use]
    pub fn strict(mut self, strict: bool) -> Self {
        self.strict = strict;
        self
    }

    /// A build for a store that does not read the `wide_times` manifest feature, which must be
    /// what that store keeps (a final snap's): a wide modification time ([`is_wide_ns`]) is
    /// unreadable to it, and the build fails naming the path as [`Self::strict`] does.
    #[must_use]
    pub fn narrow_times(mut self, narrow: bool) -> Self {
        self.narrow_times = narrow;
        self
    }

    /// The racy window (default [`RACY_WINDOW`]); zero trusts every stat.
    #[must_use]
    pub fn racy_window(mut self, window: Duration) -> Self {
        self.racy_window_ns = i128::try_from(window.as_nanos()).unwrap_or(i128::MAX);
        self
    }

    /// Paths the watcher saw written: re-read whatever the index says; each is removed once
    /// read.
    #[must_use]
    pub fn suspects(mut self, suspects: &'a mut Suspects) -> Self {
        self.suspects = Some(suspects);
        self
    }

    fn is_suspect(&self, abs: &Path) -> bool {
        self.suspects.as_ref().is_some_and(|s| s.contains(abs))
    }

    fn read_done(&mut self, abs: &Path) {
        if let Some(s) = self.suspects.as_mut() {
            s.remove(abs);
        }
    }

    /// Whether the index entry for `v` may stand in for a read: its stat matches, its last
    /// read was not racy, the watcher has not reported a write, and the sink has its chunks.
    fn reusable(
        &self,
        v: &str,
        abs: &Path,
        stat: &FileStat,
        sink: &dyn ChunkSink,
    ) -> Option<&IndexedFile> {
        self.index.files.get(v).filter(|prev| {
            prev.stat == *stat
                && !self.index.racy.contains(v)
                && !self.is_suspect(abs)
                && prev.chunks.iter().all(|c| sink.contains(c))
        })
    }

    /// Read a file into `sink`, re-reading up to [`READ_ATTEMPTS`] times if it changes underneath.
    fn read_file(
        &mut self,
        abs: &Path,
        sink: &mut dyn ChunkSink,
        stats: &mut BuildStats,
    ) -> Result<Read, Yielded> {
        let started = now_ns();
        let mut last: Option<(Vec<ChunkId>, FileStat)> = None;
        for attempt in 0..=READ_ATTEMPTS {
            let before = match longpath::symlink_metadata(abs) {
                Ok(m) => FileStat::of(&m),
                Err(e) => return Ok(Read::from_error(e)),
            };
            let (chunks, bytes) = match Self::chunk_or_yield(self.chunk_file(abs, sink, stats))? {
                Ok(read) => read,
                Err(e) => return Ok(Read::from_error(e)),
            };
            let after = match longpath::symlink_metadata(abs) {
                Ok(m) => FileStat::of(&m),
                Err(e) => return Ok(Read::from_error(e)),
            };
            stats.files_read += 1;
            stats.bytes_read += bytes;
            if before == after {
                self.read_done(abs);
                return Ok(Read::Data {
                    chunks,
                    stat: after,
                    torn: false,
                    racy: started.saturating_sub(after.ctime) < self.racy_window_ns,
                });
            }
            last = Some((chunks, after));
            if attempt < READ_ATTEMPTS {
                tracing::debug!(path = %abs.display(), "file changed while reading; retrying");
            }
        }
        // Every attempt changed underneath: ship the last read, marked torn (and racy, so the
        // next build reads it again).
        let Some((chunks, stat)) = last else {
            return Ok(Read::Vanished);
        };
        stats.torn += 1;
        self.read_done(abs);
        Ok(Read::Data {
            chunks,
            stat,
            torn: true,
            racy: true,
        })
    }

    /// A chunking result: `Ok(Ok)` read, `Ok(Err)` the read failed, `Err` yielded.
    fn chunk_or_yield<T>(result: io::Result<T>) -> Result<io::Result<T>, Yielded> {
        match result {
            Err(e) if is_yield(&e) => Err(Yielded),
            other => Ok(other),
        }
    }

    fn chunk_file(
        &mut self,
        abs: &Path,
        sink: &mut dyn ChunkSink,
        stats: &mut BuildStats,
    ) -> io::Result<(Vec<ChunkId>, u64)> {
        let file = longpath::open(abs)?;
        let mut chunks = Vec::new();
        let mut bytes = 0u64;
        for chunk in chunk_reader(io::BufReader::with_capacity(1 << 20, file)) {
            let chunk = chunk?;
            bytes += chunk.data.len() as u64;
            if !sink.contains(&chunk.id) {
                sink.put(chunk.id, &chunk.data)?;
                stats.chunks_new += 1;
                if sink.should_yield() {
                    return Err(io::Error::new(io::ErrorKind::Interrupted, "build yielded"));
                }
            }
            chunks.push(chunk.id);
        }
        Ok((chunks, bytes))
    }

    /// Chunks for a file: reused from the index when [`Self::reusable`], read otherwise.
    fn file_chunks(
        &mut self,
        v: &str,
        src: &Source,
        sink: &mut dyn ChunkSink,
        stats: &mut BuildStats,
    ) -> Result<Read, Yielded> {
        let stat = FileStat::of(&src.meta);
        if let Some(prev) = self.reusable(v, &src.abs, &stat, sink) {
            return Ok(Read::Data {
                chunks: prev.chunks.clone(),
                stat,
                torn: false,
                racy: false,
            });
        }
        if sink.should_yield() {
            return Err(Yielded);
        }
        self.read_file(&src.abs, sink, stats)
    }

    /// Keep what a yielded build read, so the resumed build skips it.
    fn keep_progress(&mut self, new_index: HashMap<String, IndexedFile>) {
        for v in new_index.keys() {
            if !self.racy.contains(v) {
                self.index.racy.remove(v);
            }
        }
        self.index.racy.extend(self.racy.drain());
        self.index.files.extend(new_index);
    }

    /// Build the tree for `listing`. `Ok(None)` when the sink asked the build to yield: the index
    /// keeps every file read so far (stale entries are harmless, the next successful build
    /// replaces the index wholesale), so the resumed build skips them. A strict build fails
    /// with [`UnreadableWork`] (inside the [`io::Error`]) when anything could not be read.
    #[allow(clippy::too_many_lines)]
    pub fn build(
        mut self,
        listing: &Listing,
        sink: &mut dyn ChunkSink,
    ) -> Result<Option<BuiltTree>, io::Error> {
        let mut stats = BuildStats::default();
        let mut unreadable: Vec<(String, String)> = listing
            .unreadable
            .iter()
            .map(|(v, u)| (v.clone(), u.error.clone()))
            .collect();
        // A wide modification time (outside signed 64-bit nanoseconds) for a store that does
        // not read `wide_times`: a strict build does not hold that path as the store can keep
        // it, and says so (review 2026-09-28, ninth pass, #3). Otherwise the dir objects record
        // it exactly, an automatic build's as a final one's.
        if self.narrow_times {
            for (v, src) in &listing.entries {
                if let Err(why) = narrow_mtime(&src.meta) {
                    unreadable.push((v.clone(), why));
                }
            }
        }

        // Every node: the listing, plus (not strict) what the index last held under a path that
        // could not be read (carried, never dropped), plus the directories those need. A strict
        // build carries nothing; it reads on so that its error names everything unreadable.
        let mut nodes: BTreeMap<String, Node<'_>> = listing
            .entries
            .iter()
            .map(|(v, src)| (v.clone(), Node::Listed(src)))
            .collect();
        let mut carried_paths: HashSet<String> = HashSet::new();
        let carry_from = if self.strict {
            None
        } else {
            Some(listing.unreadable.keys())
        };
        for u in carry_from.into_iter().flatten() {
            let under = format!("{u}/");
            let mut carried: Vec<(&String, &IndexedFile)> = self
                .index
                .files
                .iter()
                .filter(|(v, _)| (*v == u || v.starts_with(&under)) && !nodes.contains_key(*v))
                .collect();
            carried.sort_by(|a, b| a.0.cmp(b.0));
            for (v, file) in carried {
                let mut ancestors_ok = true;
                let mut at = parent_of(v);
                while !at.is_empty() {
                    match nodes.get(at) {
                        Some(n) if n.is_dir() => break,
                        Some(_) => {
                            ancestors_ok = false;
                            break;
                        }
                        None => {
                            nodes.insert(at.to_owned(), Node::CarriedDir);
                        }
                    }
                    at = parent_of(at);
                }
                if ancestors_ok {
                    nodes.insert(v.clone(), Node::Carried(file.clone()));
                    carried_paths.insert(u.clone());
                }
            }
        }

        // Hardlink groups: members in path order; the canonical member is the first one that
        // reads (or, unreadable, whose last read the index holds). Resolved up front, because
        // directories are built deepest first and a member can come before its canonical.
        let mut groups: HashMap<(u64, u64), Vec<String>> = HashMap::new();
        for (v, node) in &nodes {
            if let Node::Listed(src) = node
                && src.meta.is_file()
                && src.meta.nlink() > 1
            {
                groups
                    .entry((src.meta.dev(), src.meta.ino()))
                    .or_default()
                    .push(v.clone());
            }
        }
        let mut new_index: HashMap<String, IndexedFile> = HashMap::new();
        // Member → its canonical; a canonical maps to itself.
        let mut link_of: HashMap<String, String> = HashMap::new();
        // The canonical's entry, ready to place.
        let mut canonical_entry: HashMap<String, DirEntry> = HashMap::new();
        // Members left out: vanished, or unreadable with nothing to carry.
        let mut skipped: HashSet<String> = HashSet::new();
        let mut chunks_all: HashSet<ChunkId> = HashSet::new();
        let mut group_list: Vec<Vec<String>> =
            groups.into_values().filter(|g| g.len() > 1).collect();
        group_list.sort();
        for members in group_list {
            let mut canonical: Option<String> = None;
            for m in &members {
                let Some(Node::Listed(src)) = nodes.get(m) else {
                    continue;
                };
                let outcome = match self.file_chunks(m, src, sink, &mut stats) {
                    Ok(o) => o,
                    Err(Yielded) => {
                        self.keep_progress(new_index);
                        return Ok(None);
                    }
                };
                let mode = src.meta.mode() & 0o7777;
                match outcome {
                    Read::Data {
                        chunks,
                        stat,
                        torn,
                        racy,
                    } => {
                        let mut e =
                            DirEntry::file(name_of(m), mode, stat.size, stat.mtime, chunks.clone());
                        e.torn = torn.then_some(true);
                        chunks_all.extend(chunks.iter().copied());
                        if racy {
                            self.racy.insert(m.clone());
                        }
                        new_index.insert(m.clone(), IndexedFile { stat, chunks });
                        canonical_entry.insert(m.clone(), e);
                        canonical = Some(m.clone());
                        break;
                    }
                    Read::Vanished => {
                        stats.vanished += 1;
                        skipped.insert(m.clone());
                    }
                    Read::Unreadable(error) => {
                        unreadable.push((m.clone(), error.to_string()));
                        // Same inode: every member is as unreadable. Carry the last read the
                        // index holds under any of them.
                        let carry = members
                            .iter()
                            .filter(|c| !skipped.contains(*c))
                            .find_map(|c| self.index.files.get(c).cloned().map(|f| (c.clone(), f)));
                        if let Some((c, file)) = carry
                            && !self.strict
                        {
                            let e = carried_entry(name_of(&c), mode, &file);
                            chunks_all.extend(file.chunks.iter().copied());
                            new_index.insert(c.clone(), file);
                            canonical_entry.insert(c.clone(), e);
                            stats.carried += 1;
                            carried_paths.insert(m.clone());
                            canonical = Some(c);
                        }
                        break;
                    }
                }
            }
            for m in &members {
                match &canonical {
                    Some(c) => {
                        if !skipped.contains(m) {
                            link_of.insert(m.clone(), c.clone());
                        }
                    }
                    None => {
                        skipped.insert(m.clone());
                    }
                }
            }
        }

        // Children per directory, deepest directories first.
        let mut children: BTreeMap<String, Vec<String>> = BTreeMap::new();
        children.entry(String::new()).or_default();
        for (v, node) in &nodes {
            children
                .entry(parent_of(v).to_owned())
                .or_default()
                .push(v.clone());
            if node.is_dir() {
                children.entry(v.clone()).or_default();
            }
        }
        let mut dirs_by_depth: Vec<String> = children.keys().cloned().collect();
        dirs_by_depth.sort_by_key(|d| {
            std::cmp::Reverse(d.matches('/').count() + usize::from(!d.is_empty()))
        });

        let mut dir_keys: HashMap<String, String> = HashMap::new();
        let mut dirs: HashMap<String, EncodedDir> = HashMap::new();
        let mut root: Option<EncodedDir> = None;

        for dir in dirs_by_depth {
            let kids = children.get(&dir).cloned().unwrap_or_default();
            let names: HashSet<&str> = kids.iter().map(|k| name_of(k)).collect();
            let mut entries: Vec<DirEntry> = Vec::new();
            // File groups: `X-wal` with sibling `X`. A group that cannot be read whole (one
            // side vanished or is unreadable) falls back to its files one by one below.
            let mut grouped: HashSet<String> = HashSet::new();
            for v in &kids {
                let name = name_of(v);
                let Some(base) = name.strip_suffix("-wal") else {
                    continue;
                };
                if !names.contains(base) {
                    continue;
                }
                let base_v = join_virtual(&dir, base);
                let (Some(Node::Listed(wal)), Some(Node::Listed(db))) =
                    (nodes.get(v), nodes.get(&base_v))
                else {
                    continue;
                };
                if !wal.meta.is_file()
                    || !db.meta.is_file()
                    || link_of.contains_key(v)
                    || link_of.contains_key(&base_v)
                {
                    continue;
                }
                let started = now_ns();
                let group = match self.read_group(&base_v, db, v, wal, sink, &mut stats) {
                    Ok(Some(group)) => group,
                    Ok(None) => continue,
                    Err(Yielded) => {
                        self.keep_progress(new_index);
                        return Ok(None);
                    }
                };
                grouped.insert(v.clone());
                grouped.insert(base_v.clone());
                stats.files += 2;
                for (path, src, chunks, stat, torn) in group {
                    let mut e = DirEntry::file(
                        name_of(&path),
                        src.meta.mode() & 0o7777,
                        stat.size,
                        stat.mtime,
                        chunks.clone(),
                    );
                    e.group = Some(base.to_owned());
                    e.torn = torn.then_some(true);
                    chunks_all.extend(chunks.iter().copied());
                    if torn || started.saturating_sub(stat.ctime) < self.racy_window_ns {
                        self.racy.insert(path.clone());
                    }
                    new_index.insert(path.clone(), IndexedFile { stat, chunks });
                    entries.push(e);
                }
            }
            for v in &kids {
                if grouped.contains(v) || skipped.contains(v) {
                    continue;
                }
                let name = name_of(v);
                let src = match &nodes[v] {
                    Node::Listed(src) => *src,
                    Node::Carried(file) => {
                        stats.files += 1;
                        stats.carried += 1;
                        let mode = if file.stat.mode == 0 {
                            0o644
                        } else {
                            file.stat.mode
                        };
                        chunks_all.extend(file.chunks.iter().copied());
                        new_index.insert(v.clone(), file.clone());
                        entries.push(carried_entry(name, mode, file));
                        continue;
                    }
                    Node::CarriedDir => {
                        let Some(key) = dir_keys.get(v) else { continue };
                        let mut e = DirEntry::dir(name, 0o755, 0, key.clone());
                        e.unread = Some(true);
                        entries.push(e);
                        continue;
                    }
                };
                let mode = src.meta.mode() & 0o7777;
                let mtime = mtime_ns(&src.meta);
                if src.meta.is_dir() {
                    let Some(key) = dir_keys.get(v) else { continue };
                    let mut e = DirEntry::dir(name, mode, mtime, key.clone());
                    if listing.unreadable.contains_key(v) {
                        e.unread = Some(true);
                    }
                    entries.push(e);
                } else if src.meta.is_symlink() {
                    match longpath::read_link(&src.abs) {
                        Ok(target) => {
                            entries.push(DirEntry::symlink(
                                name,
                                mode,
                                mtime,
                                key_of_os(target.as_os_str()),
                            ));
                        }
                        Err(error) if is_vanished(&error) => stats.vanished += 1,
                        Err(error) => {
                            // Unreachable in practice (lstat just saw a symlink); the index
                            // keeps no symlink text to carry.
                            unreadable.push((v.clone(), error.to_string()));
                        }
                    }
                } else if src.meta.is_file() {
                    if let Some(canon) = link_of.get(v) {
                        stats.files += 1;
                        if canon == v {
                            if let Some(e) = canonical_entry.remove(v) {
                                entries.push(e);
                            }
                        } else {
                            entries.push(DirEntry::hardlink(
                                name,
                                mode,
                                src.meta.len(),
                                mtime,
                                canon.clone(),
                            ));
                        }
                        continue;
                    }
                    stats.files += 1;
                    let outcome = match self.file_chunks(v, src, sink, &mut stats) {
                        Ok(o) => o,
                        Err(Yielded) => {
                            self.keep_progress(new_index);
                            return Ok(None);
                        }
                    };
                    match outcome {
                        Read::Data {
                            chunks,
                            stat,
                            torn,
                            racy,
                        } => {
                            let mut e =
                                DirEntry::file(name, mode, stat.size, stat.mtime, chunks.clone());
                            e.torn = torn.then_some(true);
                            chunks_all.extend(chunks.iter().copied());
                            if racy {
                                self.racy.insert(v.clone());
                            }
                            new_index.insert(v.clone(), IndexedFile { stat, chunks });
                            entries.push(e);
                        }
                        Read::Vanished => stats.vanished += 1,
                        Read::Unreadable(error) => {
                            unreadable.push((v.clone(), error.to_string()));
                            if !self.strict
                                && let Some(file) = self.index.files.get(v).cloned()
                            {
                                stats.carried += 1;
                                carried_paths.insert(v.clone());
                                chunks_all.extend(file.chunks.iter().copied());
                                entries.push(carried_entry(name, mode, &file));
                                new_index.insert(v.clone(), file);
                            }
                        }
                    }
                }
            }
            let encoded = DirObject::new(entries).encode();
            dir_keys.insert(dir.clone(), (self.key_for_dir)(&encoded.sha256));
            dirs.insert(encoded.sha256.clone(), encoded.clone());
            if dir.is_empty() {
                root = Some(encoded);
            }
        }
        stats.unreadable = unreadable.len() as u64;
        if !unreadable.is_empty() {
            unreadable.sort();
            if self.strict {
                return Err(UnreadableWork { paths: unreadable }.into_io());
            }
            tracing::warn!(
                unreadable = unreadable.len(),
                carried = stats.carried,
                first = %unreadable[0].0,
                error = %unreadable[0].1,
                "capture: paths could not be read; their last read content is carried, marked unread"
            );
        }
        stats.chunks = chunks_all.len() as u64;
        self.index.files = new_index;
        self.index.racy = std::mem::take(&mut self.racy);
        let root = root.unwrap_or_else(|| DirObject::default().encode());
        let unreadable = unreadable
            .into_iter()
            .map(|(path, error)| UnreadablePath {
                carried: carried_paths.contains(&path),
                path,
                error,
            })
            .collect();
        Ok(Some(BuiltTree {
            root,
            dirs,
            chunks: chunks_all,
            stats,
            unreadable,
        }))
    }

    /// Read a SQLite `db` + `-wal` group: `-wal` first, then `db`; re-read both if either changed,
    /// bounded to [`READ_ATTEMPTS`]; then marked torn. `Ok(None)` when either side vanished or
    /// could not be read: the caller reads the two as single files, so one side's trouble never
    /// drops the other.
    #[allow(clippy::type_complexity)]
    fn read_group<'s>(
        &mut self,
        db_v: &str,
        db: &'s Source,
        wal_v: &str,
        wal: &'s Source,
        sink: &mut dyn ChunkSink,
        stats: &mut BuildStats,
    ) -> Result<Option<Vec<(String, &'s Source, Vec<ChunkId>, FileStat, bool)>>, Yielded> {
        let stat_both = || -> Option<(FileStat, FileStat)> {
            Some((
                FileStat::of(&longpath::symlink_metadata(&wal.abs).ok()?),
                FileStat::of(&longpath::symlink_metadata(&db.abs).ok()?),
            ))
        };
        let mut last = None;
        for attempt in 0..READ_ATTEMPTS {
            let Some(before) = stat_both() else {
                return Ok(None);
            };
            let reuse = self
                .reusable(wal_v, &wal.abs, &before.0, sink)
                .zip(self.reusable(db_v, &db.abs, &before.1, sink))
                .map(|(w, d)| (w.chunks.clone(), d.chunks.clone()));
            let (wal_chunks, db_chunks) = match reuse {
                Some(r) => r,
                None => {
                    if sink.should_yield() {
                        return Err(Yielded);
                    }
                    let Ok((w, wb)) = Self::chunk_or_yield(self.chunk_file(&wal.abs, sink, stats))?
                    else {
                        return Ok(None);
                    };
                    let Ok((d, db_bytes)) =
                        Self::chunk_or_yield(self.chunk_file(&db.abs, sink, stats))?
                    else {
                        return Ok(None);
                    };
                    stats.files_read += 2;
                    stats.bytes_read += wb + db_bytes;
                    (w, d)
                }
            };
            let Some(after) = stat_both() else {
                return Ok(None);
            };
            let torn = before != after;
            last = Some(vec![
                (wal_v.to_owned(), wal, wal_chunks, after.0, torn),
                (db_v.to_owned(), db, db_chunks, after.1, torn),
            ]);
            if !torn {
                break;
            }
            tracing::debug!(db = %db.abs.display(), attempt, "file group changed while reading");
        }
        if last.as_ref().is_some_and(|g| g[0].4) {
            stats.torn += 2;
        }
        self.read_done(&wal.abs);
        self.read_done(&db.abs);
        Ok(last)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[derive(Default)]
    struct MemSink(HashMap<ChunkId, Vec<u8>>);
    impl ChunkSink for MemSink {
        fn contains(&self, id: &ChunkId) -> bool {
            self.0.contains_key(id)
        }
        fn put(&mut self, id: ChunkId, data: &[u8]) -> io::Result<()> {
            self.0.insert(id, data.to_vec());
            Ok(())
        }
    }

    fn key(sha: &str) -> String {
        format!("t/{sha}")
    }

    /// Only git's transient bookkeeping inside a git directory is left out by name; the same
    /// names anywhere else are a user's files.
    #[test]
    fn only_git_transients_are_excluded() {
        let dir = tempfile::tempdir().unwrap();
        let r = dir.path();
        fs::create_dir_all(r.join(".git/objects/pack")).unwrap();
        fs::create_dir_all(r.join(".git/objects/incoming-q")).unwrap();
        fs::create_dir_all(r.join("objects/pack")).unwrap();
        fs::write(r.join(".git/index.lock"), b"").unwrap();
        fs::write(r.join(".git/gc.pid"), b"").unwrap();
        fs::write(r.join(".git/objects/pack/tmp_pack_x"), b"").unwrap();
        fs::write(r.join(".git/objects/incoming-q/o"), b"").unwrap();
        fs::write(r.join(".git/objects/pack/pack-a.pack"), b"a").unwrap();
        fs::write(r.join(".git/objects/pack/pack-b.pack"), b"b").unwrap();
        fs::write(r.join(".git/objects/pack/pack-b.idx"), b"i").unwrap();
        fs::write(r.join(".git/config"), b"c").unwrap();
        for user in [
            "Cargo.lock",
            "server.pid",
            "gc.pid",
            "s.db-shm",
            "objects/tmp_x",
            "objects/incoming-x",
            "objects/pack/p.pack",
        ] {
            fs::write(r.join(user), b"u").unwrap();
        }
        let mut l = Listing::default();
        l.mount("", r, "", |_, _, _| false, |_, _, _| true);
        for gone in [
            ".git/index.lock",
            ".git/gc.pid",
            ".git/objects/pack/tmp_pack_x",
            ".git/objects/incoming-q/o",
            ".git/objects/pack/pack-a.pack",
        ] {
            assert!(!l.entries.contains_key(gone), "{gone} is git's transient");
        }
        for kept in [
            ".git/config",
            ".git/objects/pack/pack-b.pack",
            ".git/objects/pack/pack-b.idx",
            "Cargo.lock",
            "server.pid",
            "gc.pid",
            "s.db-shm",
            "objects/tmp_x",
            "objects/incoming-x",
            "objects/pack/p.pack",
        ] {
            assert!(l.entries.contains_key(kept), "{kept} is work product");
        }
        assert!(is_git_transient(".git/HEAD.lock"));
        assert!(is_git_transient("tree/vendor/x/.git/refs/heads/main.lock"));
        assert!(is_git_transient(".git/objects/ab/tmp_obj_1"));
        assert!(!is_git_transient("tree/Cargo.lock"));
        assert!(!is_git_transient(".git/lfs/objects/ab/cd/abcd"));
    }

    /// Only git's own transaction files, where git writes them, are transient; every other
    /// `.lock` in a git directory is the user's (review 2026-09-28, eleventh pass, #2; decision
    /// 33).
    #[test]
    fn git_transients_are_an_allow_list() {
        for transient in [
            ".git/index.lock",
            ".git/HEAD.lock",
            ".git/ORIG_HEAD.lock",
            ".git/CHERRY_PICK_HEAD.lock",
            ".git/AUTO_MERGE.lock",
            ".git/MERGE_RR.lock",
            ".git/next-index-4242.lock",
            ".git/config.lock",
            ".git/config.worktree.lock",
            ".git/packed-refs.lock",
            ".git/shallow.lock",
            ".git/gc.pid",
            ".git/gc.pid.lock",
            ".git/gc.log.lock",
            ".git/refs/heads/main.lock",
            ".git/refs/remotes/origin/feature/x.lock",
            ".git/logs/HEAD.lock",
            ".git/logs/refs/heads/main.lock",
            ".git/reftable/tables.list.lock",
            ".git/rebase-merge/git-rebase-todo.lock",
            ".git/sequencer/todo.lock",
            ".git/info/sparse-checkout.lock",
            ".git/info/refs.lock",
            ".git/objects/maintenance.lock",
            ".git/objects/info/commit-graph.lock",
            ".git/objects/info/alternates.lock",
            ".git/objects/info/commit-graphs/commit-graph-chain.lock",
            ".git/objects/pack/multi-pack-index.lock",
            ".git/objects/pack/multi-pack-index.d/multi-pack-index-chain.lock",
            ".git/objects/pack/.tmp-77-pack-abc.pack",
            ".git/objects/pack/tmp_pack_x",
            ".git/objects/ab/tmp_obj_1",
            ".git/objects/tmp_objdir-incoming-x/ab/cd",
            ".git/worktrees/wt/index.lock",
            ".git/worktrees/wt/HEAD.lock",
            ".git/worktrees/wt/logs/HEAD.lock",
            ".git/worktrees/wt/refs/bisect/bad.lock",
            ".git/modules/sub/index.lock",
            ".git/modules/lib/sub/refs/heads/main.lock",
            ".git/modules/sub/objects/ab/tmp_obj_2",
            "tree/vendor/x/.git/index.lock",
            "node_modules/pkg/.git/packed-refs.lock",
        ] {
            assert!(
                is_git_transient(transient),
                "{transient} is git's transient"
            );
        }
        for kept in [
            ".git/hooks/Cargo.lock",
            ".git/hooks/project/Cargo.lock",
            ".git/personal.lock",
            ".git/my-index.lock",
            ".git/next-index-.lock",
            ".git/Head.lock",
            ".git/_HEAD.lock",
            ".git/gc.log",
            ".git/info/exclude.lock",
            ".git/info/Cargo.lock",
            ".git/lfs/tmp/x.lock",
            ".git/rr-cache/ab/postimage.lock",
            ".git/objects/Cargo.lock",
            ".git/objects/pack/pack-a.keep",
            ".git/objects/pack/user.lock",
            ".git/worktrees/wt/config.lock",
            ".git/worktrees/wt/objects/tmp_obj_3",
            ".git/worktrees/wt/hooks/Cargo.lock",
            ".git/modules/sub/hooks/Cargo.lock",
            ".git/modules/sub/personal.lock",
            "tree/ignored/nested/.git/hooks/Cargo.lock",
            "node_modules/nested/.git/hooks/Cargo.lock",
            "tree/Cargo.lock",
            "tree/index.lock",
            "harness/.claude/config.lock",
        ] {
            assert!(!is_git_transient(kept), "{kept} is the user's");
        }
        // A pack is judged by its `.idx` only where git keeps packs.
        assert!(in_git_pack_dir(".git/objects/pack/p.pack"));
        assert!(in_git_pack_dir(".git/modules/sub/objects/pack/p.pack"));
        assert!(!in_git_pack_dir(".git/hooks/p.pack"));
        assert!(!in_git_pack_dir(".git/lfs/objects/pack/p.pack"));
    }

    #[test]
    fn nested_mounts_get_their_ancestors() {
        let dir = tempfile::tempdir().unwrap();
        let r = dir.path();
        fs::create_dir_all(r.join("vendor/x/.git")).unwrap();
        fs::write(r.join("vendor/x/v.txt"), b"v").unwrap();
        fs::write(r.join(".env"), b"e").unwrap();
        let mut l = Listing::default();
        l.mount("tree", r, "vendor/x", |_, _, _| false, |_, _, _| true);
        l.mount_file("tree/.env", "tree", r, &r.join(".env"));
        for k in [
            "tree",
            "tree/vendor",
            "tree/vendor/x",
            "tree/vendor/x/.git",
            "tree/vendor/x/v.txt",
            "tree/.env",
        ] {
            assert!(l.entries.contains_key(k), "missing {k}");
        }
        assert!(!l.entries.contains_key("tree/vendor/x/.git/objects"));
        let mut index = TreeIndex::default();
        let mut sink = MemSink::default();
        let built = TreeBuilder::new(&mut index, &key)
            .build(&l, &mut sink)
            .unwrap()
            .unwrap();
        let root = DirObject::decode(&built.root.bytes).unwrap();
        assert_eq!(root.entries.len(), 1);
        assert_eq!(root.entries[0].name, "tree");
        assert_eq!(built.stats.files, 2);
    }

    #[test]
    fn builds_groups_hardlinks_and_reuses_index() {
        let dir = tempfile::tempdir().unwrap();
        let r = dir.path();
        fs::create_dir_all(r.join("sub")).unwrap();
        fs::write(r.join("sub/state.db"), b"db bytes").unwrap();
        fs::write(r.join("sub/state.db-wal"), b"wal bytes").unwrap();
        fs::write(r.join("a.txt"), b"alpha").unwrap();
        fs::hard_link(r.join("a.txt"), r.join("sub/a-link.txt")).unwrap();
        std::os::unix::fs::symlink("a.txt", r.join("l")).unwrap();
        let mut l = Listing::default();
        l.mount("", r, "", |_, _, _| false, |_, _, _| true);

        let mut index = TreeIndex::default();
        let mut sink = MemSink::default();
        let built = TreeBuilder::new(&mut index, &key)
            .racy_window(Duration::ZERO)
            .build(&l, &mut sink)
            .unwrap()
            .unwrap();
        assert_eq!(built.stats.files, 4);
        assert_eq!(built.stats.files_read, 3); // db, wal, a.txt (the link is not read)
        let root = DirObject::decode(&built.root.bytes).unwrap();
        let names: Vec<_> = root.entries.iter().map(|e| e.name.as_str()).collect();
        assert_eq!(names, vec!["a.txt", "l", "sub"]);
        let sub_key = root.entries[2].child.clone().unwrap();
        let sub = built.dirs.get(sub_key.strip_prefix("t/").unwrap()).unwrap();
        let sub = DirObject::decode(&sub.bytes).unwrap();
        let link = sub.entries.iter().find(|e| e.name == "a-link.txt").unwrap();
        assert_eq!(link.kind, crate::tree::EntryKind::HardlinkGroup);
        assert_eq!(link.target.as_deref(), Some("a.txt"));
        let db = sub.entries.iter().find(|e| e.name == "state.db").unwrap();
        assert_eq!(db.group.as_deref(), Some("state.db"));
        let wal = sub
            .entries
            .iter()
            .find(|e| e.name == "state.db-wal")
            .unwrap();
        assert_eq!(wal.group.as_deref(), Some("state.db"));
        assert_eq!(wal.torn, None);

        // Second build: nothing re-read.
        let built2 = TreeBuilder::new(&mut index, &key)
            .racy_window(Duration::ZERO)
            .build(&l, &mut sink)
            .unwrap()
            .unwrap();
        assert_eq!(built2.stats.files_read, 0);
        assert_eq!(built2.root.sha256, built.root.sha256);

        // Touch a file: only it is re-read, and the tree changes.
        fs::write(r.join("a.txt"), b"alpha2").unwrap();
        let mut l = Listing::default();
        l.mount("", r, "", |_, _, _| false, |_, _, _| true);
        let built3 = TreeBuilder::new(&mut index, &key)
            .racy_window(Duration::ZERO)
            .build(&l, &mut sink)
            .unwrap()
            .unwrap();
        assert_eq!(built3.stats.files_read, 1);
        assert_ne!(built3.root.sha256, built.root.sha256);
    }

    /// A sink that asks the build to yield after `after` new chunks.
    struct YieldSink {
        inner: MemSink,
        after: usize,
    }
    impl ChunkSink for YieldSink {
        fn contains(&self, id: &ChunkId) -> bool {
            self.inner.contains(id)
        }
        fn put(&mut self, id: ChunkId, data: &[u8]) -> io::Result<()> {
            self.inner.put(id, data)
        }
        fn should_yield(&self) -> bool {
            self.inner.0.len() >= self.after
        }
    }

    #[test]
    fn a_yielded_build_resumes_without_rereading() {
        let dir = tempfile::tempdir().unwrap();
        let r = dir.path();
        for i in 0..6 {
            fs::write(r.join(format!("f{i}.txt")), format!("content {i}")).unwrap();
        }
        let mut l = Listing::default();
        l.mount("", r, "", |_, _, _| false, |_, _, _| true);
        let mut index = TreeIndex::default();
        let mut sink = YieldSink {
            inner: MemSink::default(),
            after: 3,
        };
        let first = TreeBuilder::new(&mut index, &key)
            .racy_window(Duration::ZERO)
            .build(&l, &mut sink)
            .unwrap();
        assert!(first.is_none(), "the build yields after three chunks");
        assert_eq!(sink.inner.0.len(), 3, "every chunk read stays in the sink");
        assert_eq!(
            index.files.len(),
            2,
            "files read whole are kept; the file cut mid-read is re-read on resume"
        );
        sink.after = usize::MAX;
        let done = TreeBuilder::new(&mut index, &key)
            .racy_window(Duration::ZERO)
            .build(&l, &mut sink)
            .unwrap()
            .unwrap();
        assert_eq!(done.stats.files, 6);
        assert_eq!(
            done.stats.files_read, 4,
            "the resumed build reads only the rest"
        );
        assert_eq!(
            done.stats.chunks_new, 3,
            "chunks already in the sink are not put again"
        );
        assert_eq!(index.files.len(), 6);
    }

    fn listing(r: &Path) -> Listing {
        let mut l = Listing::default();
        l.mount("", r, "", |_, _, _| false, |_, _, _| true);
        l
    }

    fn build(index: &mut TreeIndex, sink: &mut MemSink, l: &Listing) -> BuiltTree {
        TreeBuilder::new(index, &key)
            .racy_window(Duration::ZERO)
            .build(l, sink)
            .unwrap()
            .unwrap()
    }

    fn root_entry(built: &BuiltTree, name: &str) -> Option<DirEntry> {
        DirObject::decode(&built.root.bytes)
            .unwrap()
            .entries
            .into_iter()
            .find(|e| e.name == name)
    }

    fn content(sink: &MemSink, e: &DirEntry) -> Vec<u8> {
        e.chunks
            .iter()
            .flatten()
            .flat_map(|c| sink.0[c].clone())
            .collect()
    }

    /// Whether permission bits bind this process (they do not for root).
    fn permissions_bind(probe: &Path) -> bool {
        use std::os::unix::fs::PermissionsExt;
        fs::write(probe, b"p").unwrap();
        fs::set_permissions(probe, fs::Permissions::from_mode(0o000)).unwrap();
        let binds = fs::File::open(probe).is_err();
        fs::set_permissions(probe, fs::Permissions::from_mode(0o600)).unwrap();
        fs::remove_file(probe).unwrap();
        binds
    }

    fn set_mtime(path: &Path, mtime: std::time::SystemTime) {
        fs::File::options()
            .write(true)
            .open(path)
            .unwrap()
            .set_times(fs::FileTimes::new().set_modified(mtime))
            .unwrap();
    }

    /// Finding 12: a same-size overwrite that restores the mtime moves the ctime, so the file
    /// is read again (the key was size, mtime, inode, device, and the stale chunks were reused).
    #[test]
    fn a_same_size_overwrite_with_the_mtime_restored_is_read_again() {
        let dir = tempfile::tempdir().unwrap();
        let r = dir.path();
        let f = r.join("state");
        fs::write(&f, b"AAAA").unwrap();
        let mtime = fs::metadata(&f).unwrap().modified().unwrap();
        let mut index = TreeIndex::default();
        let mut sink = MemSink::default();
        build(&mut index, &mut sink, &listing(r));
        std::thread::sleep(Duration::from_millis(20));
        fs::write(&f, b"BBBB").unwrap();
        set_mtime(&f, mtime);
        let built = build(&mut index, &mut sink, &listing(r));
        assert_eq!(built.stats.files_read, 1);
        assert_eq!(
            content(&sink, &root_entry(&built, "state").unwrap()),
            b"BBBB"
        );
    }

    /// A read right after a change is racy: the next build reads the file again even with an
    /// identical stat; once the window has passed, the stat is trusted.
    #[test]
    fn a_racy_read_is_not_trusted_by_the_next_build() {
        let dir = tempfile::tempdir().unwrap();
        let r = dir.path();
        fs::write(r.join("f"), b"x").unwrap();
        let l = listing(r);
        let mut index = TreeIndex::default();
        let mut sink = MemSink::default();
        let racy = |index: &mut TreeIndex, sink: &mut MemSink| {
            TreeBuilder::new(index, &key)
                .racy_window(Duration::from_secs(3600))
                .build(&l, sink)
                .unwrap()
                .unwrap()
        };
        assert_eq!(racy(&mut index, &mut sink).stats.files_read, 1);
        assert!(index.racy.contains("f"));
        assert_eq!(
            racy(&mut index, &mut sink).stats.files_read,
            1,
            "racy: read again"
        );
        let calm = build(&mut index, &mut sink, &l);
        assert_eq!(calm.stats.files_read, 1, "still racy from the last read");
        assert!(index.racy.is_empty());
        assert_eq!(build(&mut index, &mut sink, &l).stats.files_read, 0);
    }

    /// A path the watcher reported written is read again whatever the index says (here the
    /// index holds stale chunks under the file's exact stat).
    #[test]
    fn a_suspect_is_read_again_whatever_its_stat() {
        let dir = tempfile::tempdir().unwrap();
        let r = dir.path();
        fs::write(r.join("f"), b"new bytes").unwrap();
        let l = listing(r);
        let mut index = TreeIndex::default();
        let mut sink = MemSink::default();
        build(&mut index, &mut sink, &l);
        let stale = ChunkId::of(b"old bytes");
        sink.0.insert(stale, b"old bytes".to_vec());
        index.files.get_mut("f").unwrap().chunks = vec![stale];
        let reused = build(&mut index, &mut sink, &l);
        assert_eq!(
            reused.stats.files_read, 0,
            "without the watcher the stat is trusted"
        );
        let mut suspects: Suspects = [r.join("f")].into_iter().collect();
        let built = TreeBuilder::new(&mut index, &key)
            .racy_window(Duration::ZERO)
            .suspects(&mut suspects)
            .build(&l, &mut sink)
            .unwrap()
            .unwrap();
        assert_eq!(built.stats.files_read, 1);
        assert_eq!(
            content(&sink, &root_entry(&built, "f").unwrap()),
            b"new bytes"
        );
        assert!(suspects.is_empty(), "a suspect read is cleared");
    }

    /// Finding 10: a file that exists but cannot be read is never a deletion. An automatic build
    /// carries its last read content, marked `unread`; a strict (final) build fails naming it; a
    /// file that is gone is left out.
    #[test]
    fn an_unreadable_file_is_carried_or_fails_a_strict_build() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        let r = dir.path().join("r");
        fs::create_dir_all(&r).unwrap();
        if !permissions_bind(&dir.path().join("probe")) {
            eprintln!("skipped: permission bits do not bind this process");
            return;
        }
        fs::write(r.join("keep"), b"KEEP").unwrap();
        fs::write(r.join("gone"), b"GONE").unwrap();
        let mut index = TreeIndex::default();
        let mut sink = MemSink::default();
        build(&mut index, &mut sink, &listing(&r));
        std::thread::sleep(Duration::from_millis(20));
        fs::set_permissions(r.join("keep"), fs::Permissions::from_mode(0o000)).unwrap();
        fs::remove_file(r.join("gone")).unwrap();
        let l = listing(&r);

        let strict = TreeBuilder::new(&mut index.clone(), &key)
            .racy_window(Duration::ZERO)
            .strict(true)
            .build(&l, &mut sink)
            .unwrap_err();
        let work = UnreadableWork::of(&strict).expect("unreadable work");
        assert_eq!(work.paths.len(), 1);
        assert_eq!(work.paths[0].0, "keep");

        let built = build(&mut index, &mut sink, &l);
        let keep = root_entry(&built, "keep").expect("carried, not deleted");
        assert_eq!(keep.unread, Some(true));
        assert_eq!(content(&sink, &keep), b"KEEP");
        assert_eq!(keep.mode, 0o000);
        assert!(
            root_entry(&built, "gone").is_none(),
            "a removed file is left out"
        );
        assert_eq!((built.stats.unreadable, built.stats.carried), (1, 1));
        assert!(
            index.files.contains_key("keep"),
            "the carried read stays indexed"
        );
        fs::set_permissions(r.join("keep"), fs::Permissions::from_mode(0o600)).unwrap();
    }

    /// Finding 10: a directory that cannot be listed keeps what the last reads under it found
    /// (an automatic build) or fails a strict build; its contents are never taken as removed.
    #[test]
    fn an_unlistable_directory_is_carried_or_fails_a_strict_build() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        let r = dir.path().join("r");
        fs::create_dir_all(r.join("sec/deep")).unwrap();
        if !permissions_bind(&dir.path().join("probe")) {
            eprintln!("skipped: permission bits do not bind this process");
            return;
        }
        fs::write(r.join("sec/a"), b"A").unwrap();
        fs::write(r.join("sec/deep/b"), b"B").unwrap();
        let mut index = TreeIndex::default();
        let mut sink = MemSink::default();
        build(&mut index, &mut sink, &listing(&r));
        fs::set_permissions(r.join("sec"), fs::Permissions::from_mode(0o000)).unwrap();
        let l = listing(&r);
        assert!(l.unreadable.contains_key("sec"), "{:?}", l.unreadable);

        let strict = TreeBuilder::new(&mut index.clone(), &key)
            .strict(true)
            .build(&l, &mut sink)
            .unwrap_err();
        assert_eq!(
            UnreadableWork::of(&strict).unwrap().paths[0].0,
            "sec",
            "{strict}"
        );

        let built = build(&mut index, &mut sink, &l);
        fs::set_permissions(r.join("sec"), fs::Permissions::from_mode(0o755)).unwrap();
        let sec = root_entry(&built, "sec").unwrap();
        assert_eq!(sec.unread, Some(true));
        let sec_obj = built.dirs[sec.child.as_deref().unwrap().strip_prefix("t/").unwrap()].clone();
        let sec_obj = DirObject::decode(&sec_obj.bytes).unwrap();
        let names: Vec<_> = sec_obj.entries.iter().map(|e| e.name.as_str()).collect();
        assert_eq!(names, vec!["a", "deep"]);
        assert_eq!(content(&sink, &sec_obj.entries[0]), b"A");
        assert_eq!(built.stats.carried, 2);
    }

    /// A SQLite `-wal` that vanishes (a checkpoint on close) never takes the database with it.
    #[test]
    fn a_vanished_wal_leaves_its_database_captured() {
        let dir = tempfile::tempdir().unwrap();
        let r = dir.path();
        fs::write(r.join("s.db"), b"db").unwrap();
        fs::write(r.join("s.db-wal"), b"wal").unwrap();
        let l = listing(r);
        fs::remove_file(r.join("s.db-wal")).unwrap();
        let mut index = TreeIndex::default();
        let mut sink = MemSink::default();
        let built = build(&mut index, &mut sink, &l);
        let db = root_entry(&built, "s.db").expect("the database stays");
        assert_eq!(content(&sink, &db), b"db");
        assert!(root_entry(&built, "s.db-wal").is_none());
    }

    /// A hardlink group whose first member vanished before the read is carried by the next
    /// member, not written as links to a path that is gone.
    #[test]
    fn a_hardlink_group_survives_its_first_member_vanishing() {
        let dir = tempfile::tempdir().unwrap();
        let r = dir.path();
        fs::write(r.join("a"), b"shared").unwrap();
        fs::hard_link(r.join("a"), r.join("b")).unwrap();
        fs::hard_link(r.join("a"), r.join("c")).unwrap();
        let l = listing(r);
        fs::remove_file(r.join("a")).unwrap();
        let mut index = TreeIndex::default();
        let mut sink = MemSink::default();
        let built = build(&mut index, &mut sink, &l);
        assert!(root_entry(&built, "a").is_none());
        let b = root_entry(&built, "b").unwrap();
        assert_eq!(b.kind, crate::tree::EntryKind::File);
        assert_eq!(content(&sink, &b), b"shared");
        let c = root_entry(&built, "c").unwrap();
        assert_eq!(c.kind, crate::tree::EntryKind::HardlinkGroup);
        assert_eq!(c.target.as_deref(), Some("b"));
    }

    /// Names and symlink text that are not UTF-8 keep their bytes: two names that a lossy
    /// conversion would merge stay two entries, and each decodes to exactly its bytes.
    #[test]
    fn names_and_targets_that_are_not_utf8_keep_their_bytes() {
        use std::ffi::OsStr;
        use std::os::unix::ffi::OsStrExt;
        let dir = tempfile::tempdir().unwrap();
        let r = dir.path();
        let a = OsStr::from_bytes(b"caf\xe9");
        let b = OsStr::from_bytes(b"caf\xe8");
        fs::write(r.join(a), b"one").unwrap();
        fs::write(r.join(b), b"two").unwrap();
        std::os::unix::fs::symlink(OsStr::from_bytes(b"\xff/t"), r.join("l")).unwrap();
        fs::create_dir_all(r.join(OsStr::from_bytes(b"d\x80"))).unwrap();
        fs::write(r.join(OsStr::from_bytes(b"d\x80/in")), b"in").unwrap();
        let mut index = TreeIndex::default();
        let mut sink = MemSink::default();
        let built = build(&mut index, &mut sink, &listing(r));
        let root = DirObject::decode(&built.root.bytes).unwrap();
        assert_eq!(root.entries.len(), 4, "{:?}", root.entries);
        let by_bytes = |bytes: &[u8]| {
            root.entries
                .iter()
                .find(|e| e.os_name().as_bytes() == bytes)
                .cloned()
                .unwrap()
        };
        let one = by_bytes(b"caf\xe9");
        assert_eq!(content(&sink, &one), b"one");
        assert_eq!(one.raw_name.as_deref(), Some("636166e9"));
        assert_eq!(content(&sink, &by_bytes(b"caf\xe8")), b"two");
        let l = by_bytes(b"l");
        assert_eq!(l.os_target().unwrap().as_bytes(), b"\xff/t");
        assert_eq!(l.raw_target.as_deref(), Some("ff2f74"));
        assert!(l.raw_name.is_none());
        let d = by_bytes(b"d\x80");
        assert!(d.child.is_some());
        assert!(index.files.keys().any(|k| k.ends_with("/in")));
    }
}
