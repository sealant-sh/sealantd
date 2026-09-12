//! The tree index and walker for chunked classes: a full stat scan of one or more mounted
//! directories under the capture ignore policy, change detection by `(size, mtime, inode)` with
//! chunk-hash confirmation, and the dir-object builder (file groups, hardlink groups, bounded
//! re-reads of files that change underneath the reader).
//!
//! Grown from `sealant_fs::snapshot`, with its own policy: `DEFAULT_IGNORES` is right for
//! telemetry and wrong for the work product.

use std::collections::{BTreeMap, HashMap, HashSet};
use std::fs::{self, Metadata};
use std::io;
use std::os::unix::fs::MetadataExt;
use std::path::{Component, Path, PathBuf};

use serde::{Deserialize, Serialize};
use walkdir::WalkDir;

use crate::chunk::{ChunkId, chunk_reader};
use crate::tree::{DirEntry, DirObject, EncodedDir};

/// Bounded attempts for a file (or file group) that changes underneath the reader.
pub const READ_ATTEMPTS: u32 = 3;

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

/// Whether a file name is always excluded (ADR-0015 *Snap rules*): `*.lock`, `gc.pid`, SQLite
/// `-shm`, pid files, and `tmp_*` / `incoming-*` under an `objects` directory.
#[must_use]
pub fn is_excluded_name(name: &str, parent_name: Option<&str>) -> bool {
    if name.ends_with(".lock")
        || name == "gc.pid"
        || name.ends_with("-shm")
        || name.ends_with(".pid")
    {
        return true;
    }
    parent_name == Some("objects") && (name.starts_with("tmp_") || name.starts_with("incoming-"))
}

/// Whether a file type is captured at all (sockets, fifos and devices are not).
#[must_use]
pub fn is_capturable_type(meta: &Metadata) -> bool {
    let ft = meta.file_type();
    ft.is_file() || ft.is_dir() || ft.is_symlink()
}

/// Modification time as nanoseconds since the Unix epoch.
#[must_use]
pub fn mtime_ns(meta: &Metadata) -> i64 {
    meta.mtime()
        .saturating_mul(1_000_000_000)
        .saturating_add(meta.mtime_nsec())
}

/// Stat fields that decide whether a file must be re-read.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct FileStat {
    /// Size.
    pub size: u64,
    /// mtime in nanoseconds.
    pub mtime: i64,
    /// Inode.
    pub ino: u64,
    /// Device.
    pub dev: u64,
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
        let tmp = path.with_extension("tmp");
        fs::write(&tmp, serde_json::to_vec(self)?)?;
        fs::rename(tmp, path)
    }
}

/// One entry of a walk: a virtual path inside the class, its source and its metadata.
#[derive(Debug, Clone)]
pub struct Source {
    /// Absolute source path.
    pub abs: PathBuf,
    /// lstat metadata.
    pub meta: Metadata,
}

/// The set of paths a class captures, keyed by virtual path (`/`-separated, relative to the
/// class root), directories included.
#[derive(Debug, Default)]
pub struct Listing {
    /// Entries.
    pub entries: BTreeMap<String, Source>,
}

fn join_virtual(prefix: &str, rel: &str) -> String {
    match (prefix.is_empty(), rel.is_empty()) {
        (true, _) => rel.to_owned(),
        (_, true) => prefix.to_owned(),
        _ => format!("{prefix}/{rel}"),
    }
}

impl Listing {
    /// Add one path, creating (stat'ing) missing ancestor directories from `ancestor_abs`.
    fn add(&mut self, virtual_path: String, abs: PathBuf, meta: Metadata) {
        self.entries.insert(virtual_path, Source { abs, meta });
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
            abs = abs.join(comp);
            let v = join_virtual(virtual_base, &acc);
            if v == virtual_path {
                break;
            }
            if !self.entries.contains_key(&v)
                && let Ok(meta) = fs::symlink_metadata(&abs)
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

    /// Mount `abs_dir` at `virtual_prefix`, walking it fully. `prune` decides per directory
    /// (virtual path, name) whether to descend; `include` decides per non-directory entry
    /// (virtual path, name) whether to keep it. Exclusions from [`is_excluded_name`], uncapturable
    /// types and `.pack` files without their `.idx` are applied here. Entries already present are
    /// not overwritten (the first mount wins, so overlays are expressed by mount order).
    pub fn mount<P, I>(
        &mut self,
        virtual_prefix: &str,
        abs_dir: &Path,
        mut prune: P,
        mut include: I,
    ) where
        P: FnMut(&str, &str) -> bool,
        I: FnMut(&str, &str) -> bool,
    {
        let Ok(root_meta) = fs::symlink_metadata(abs_dir) else {
            return;
        };
        if !root_meta.is_dir() {
            return;
        }
        if !virtual_prefix.is_empty() && !self.entries.contains_key(virtual_prefix) {
            self.add(virtual_prefix.to_owned(), abs_dir.to_path_buf(), root_meta);
        }
        // Per-directory name sets, for the `.pack` without `.idx` rule.
        let mut dir_names: HashMap<PathBuf, HashSet<String>> = HashMap::new();
        let walker = WalkDir::new(abs_dir)
            .follow_links(false)
            .min_depth(1)
            .sort_by_file_name()
            .into_iter()
            .filter_entry(|e| {
                let name = e.file_name().to_string_lossy();
                let rel = e.path().strip_prefix(abs_dir).unwrap_or(e.path());
                let v = join_virtual(virtual_prefix, &rel.to_string_lossy());
                if e.file_type().is_dir() {
                    !prune(&v, &name)
                } else {
                    true
                }
            });
        for entry in walker.flatten() {
            let path = entry.path();
            let Ok(rel) = path.strip_prefix(abs_dir) else {
                continue;
            };
            let Ok(meta) = entry.metadata() else {
                continue;
            };
            if !is_capturable_type(&meta) {
                continue;
            }
            let name = entry.file_name().to_string_lossy().to_string();
            let parent = path.parent().map(Path::to_path_buf).unwrap_or_default();
            let parent_name = parent.file_name().map(|n| n.to_string_lossy().to_string());
            if !meta.is_dir() {
                if is_excluded_name(&name, parent_name.as_deref()) {
                    continue;
                }
                if let Some(stem) = name.strip_suffix(".pack") {
                    let names = dir_names.entry(parent.clone()).or_insert_with(|| {
                        fs::read_dir(&parent)
                            .map(|rd| {
                                rd.flatten()
                                    .map(|d| d.file_name().to_string_lossy().to_string())
                                    .collect()
                            })
                            .unwrap_or_default()
                    });
                    if !names.contains(&format!("{stem}.idx")) {
                        tracing::debug!(path = %path.display(), "skipping .pack without .idx");
                        continue;
                    }
                }
            }
            let v = join_virtual(virtual_prefix, &rel.to_string_lossy());
            if !meta.is_dir() && !include(&v, &name) {
                continue;
            }
            if self.entries.contains_key(&v) {
                continue;
            }
            self.ensure_ancestors(&v, virtual_prefix, abs_dir);
            self.add(v, path.to_path_buf(), meta);
        }
    }

    /// Mount a single file at `virtual_path`.
    pub fn mount_file(
        &mut self,
        virtual_path: &str,
        virtual_base: &str,
        abs_base: &Path,
        abs: &Path,
    ) {
        let Ok(meta) = fs::symlink_metadata(abs) else {
            return;
        };
        if !is_capturable_type(&meta) || self.entries.contains_key(virtual_path) {
            return;
        }
        let name = abs
            .file_name()
            .map(|n| n.to_string_lossy().to_string())
            .unwrap_or_default();
        let parent_name = abs
            .parent()
            .and_then(Path::file_name)
            .map(|n| n.to_string_lossy().to_string());
        if is_excluded_name(&name, parent_name.as_deref()) {
            return;
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
}

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
}

/// Builds dir objects for a [`Listing`].
pub struct TreeBuilder<'a> {
    index: &'a mut TreeIndex,
    key_for_dir: &'a dyn Fn(&str) -> String,
}

impl std::fmt::Debug for TreeBuilder<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TreeBuilder")
            .field("index_files", &self.index.files.len())
            .finish_non_exhaustive()
    }
}

fn parent_of(v: &str) -> &str {
    v.rsplit_once('/').map_or("", |(p, _)| p)
}

fn name_of(v: &str) -> &str {
    v.rsplit_once('/').map_or(v, |(_, n)| n)
}

impl<'a> TreeBuilder<'a> {
    /// `key_for_dir` maps a dir object's sha256 to its store key (the epoch prefix).
    pub fn new(index: &'a mut TreeIndex, key_for_dir: &'a dyn Fn(&str) -> String) -> Self {
        Self { index, key_for_dir }
    }

    /// Read a file into `sink`, re-reading up to [`READ_ATTEMPTS`] times if it changes underneath.
    /// Returns the chunk list, the stat it corresponds to, whether it is torn, and bytes read; or
    /// `None` when the file vanished.
    fn read_file(
        &mut self,
        abs: &Path,
        sink: &mut dyn ChunkSink,
        stats: &mut BuildStats,
    ) -> Option<(Vec<ChunkId>, FileStat, bool)> {
        for _ in 0..READ_ATTEMPTS {
            let before = FileStat::of(&fs::symlink_metadata(abs).ok()?);
            let (chunks, bytes) = self.chunk_file(abs, sink, stats).ok()?;
            let after = FileStat::of(&fs::symlink_metadata(abs).ok()?);
            stats.files_read += 1;
            stats.bytes_read += bytes;
            if before == after {
                return Some((chunks, after, false));
            }
            tracing::debug!(path = %abs.display(), "file changed while reading; retrying");
        }
        // Last attempt: ship what we read, marked torn.
        let (chunks, bytes) = self.chunk_file(abs, sink, stats).ok()?;
        let after = FileStat::of(&fs::symlink_metadata(abs).ok()?);
        stats.files_read += 1;
        stats.bytes_read += bytes;
        stats.torn += 1;
        Some((chunks, after, true))
    }

    fn chunk_file(
        &mut self,
        abs: &Path,
        sink: &mut dyn ChunkSink,
        stats: &mut BuildStats,
    ) -> io::Result<(Vec<ChunkId>, u64)> {
        let file = fs::File::open(abs)?;
        let mut chunks = Vec::new();
        let mut bytes = 0u64;
        for chunk in chunk_reader(io::BufReader::with_capacity(1 << 20, file)) {
            let chunk = chunk?;
            bytes += chunk.data.len() as u64;
            if !sink.contains(&chunk.id) {
                sink.put(chunk.id, &chunk.data)?;
                stats.chunks_new += 1;
            }
            chunks.push(chunk.id);
        }
        Ok((chunks, bytes))
    }

    /// Chunks for a file: reused from the index when `(size, mtime, inode)` match and every chunk
    /// is still known to the sink, read otherwise.
    fn file_chunks(
        &mut self,
        v: &str,
        src: &Source,
        sink: &mut dyn ChunkSink,
        stats: &mut BuildStats,
    ) -> Option<(Vec<ChunkId>, FileStat, bool)> {
        let stat = FileStat::of(&src.meta);
        if let Some(prev) = self.index.files.get(v)
            && prev.stat == stat
            && prev.chunks.iter().all(|c| sink.contains(c))
        {
            return Some((prev.chunks.clone(), stat, false));
        }
        self.read_file(&src.abs, sink, stats)
    }

    /// Build the tree for `listing`.
    pub fn build(
        mut self,
        listing: &Listing,
        sink: &mut dyn ChunkSink,
    ) -> Result<BuiltTree, io::Error> {
        let mut stats = BuildStats::default();
        // Hardlink groups: canonical member = first in path order.
        let mut canonical: HashMap<(u64, u64), String> = HashMap::new();
        let mut link_of: HashMap<String, String> = HashMap::new();
        for (v, src) in &listing.entries {
            if src.meta.is_file() && src.meta.nlink() > 1 {
                let key = (src.meta.dev(), src.meta.ino());
                match canonical.get(&key) {
                    Some(c) => {
                        link_of.insert(v.clone(), c.clone());
                    }
                    None => {
                        canonical.insert(key, v.clone());
                    }
                }
            }
        }
        // Children per directory, deepest directories first.
        let mut children: BTreeMap<String, Vec<String>> = BTreeMap::new();
        children.entry(String::new()).or_default();
        for v in listing.entries.keys() {
            children
                .entry(parent_of(v).to_owned())
                .or_default()
                .push(v.clone());
            if listing.entries[v].meta.is_dir() {
                children.entry(v.clone()).or_default();
            }
        }
        let mut dirs_by_depth: Vec<String> = children.keys().cloned().collect();
        dirs_by_depth.sort_by_key(|d| {
            std::cmp::Reverse(d.matches('/').count() + usize::from(!d.is_empty()))
        });

        let mut dir_keys: HashMap<String, String> = HashMap::new();
        let mut dirs: HashMap<String, EncodedDir> = HashMap::new();
        let mut chunks_all: HashSet<ChunkId> = HashSet::new();
        let mut new_index: HashMap<String, IndexedFile> = HashMap::new();
        let mut root: Option<EncodedDir> = None;

        for dir in dirs_by_depth {
            let kids = children.get(&dir).cloned().unwrap_or_default();
            let names: HashSet<&str> = kids.iter().map(|k| name_of(k)).collect();
            let mut entries: Vec<DirEntry> = Vec::new();
            // File groups: `X-wal` with sibling `X`.
            let mut grouped: HashSet<String> = HashSet::new();
            for v in &kids {
                let name = name_of(v);
                if let Some(base) = name.strip_suffix("-wal")
                    && names.contains(base)
                {
                    let base_v = join_virtual(&dir, base);
                    if let (Some(wal), Some(db)) =
                        (listing.entries.get(v), listing.entries.get(&base_v))
                        && wal.meta.is_file()
                        && db.meta.is_file()
                    {
                        grouped.insert(v.clone());
                        grouped.insert(base_v.clone());
                        stats.files += 2;
                        let Some(group) = self.read_group(&base_v, db, v, wal, sink, &mut stats)
                        else {
                            stats.vanished += 2;
                            continue;
                        };
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
                            new_index.insert(path.clone(), IndexedFile { stat, chunks });
                            entries.push(e);
                        }
                    }
                }
            }
            for v in &kids {
                if grouped.contains(v) {
                    continue;
                }
                let src = &listing.entries[v];
                let name = name_of(v);
                let mode = src.meta.mode() & 0o7777;
                let mtime = mtime_ns(&src.meta);
                if src.meta.is_dir() {
                    let Some(key) = dir_keys.get(v) else { continue };
                    entries.push(DirEntry::dir(name, mode, mtime, key.clone()));
                } else if src.meta.is_symlink() {
                    let Ok(target) = fs::read_link(&src.abs) else {
                        stats.vanished += 1;
                        continue;
                    };
                    entries.push(DirEntry::symlink(
                        name,
                        mode,
                        mtime,
                        target.to_string_lossy(),
                    ));
                } else if src.meta.is_file() {
                    stats.files += 1;
                    if let Some(canon) = link_of.get(v) {
                        entries.push(DirEntry::hardlink(
                            name,
                            mode,
                            src.meta.len(),
                            mtime,
                            canon.clone(),
                        ));
                        continue;
                    }
                    let Some((chunks, stat, torn)) = self.file_chunks(v, src, sink, &mut stats)
                    else {
                        stats.vanished += 1;
                        continue;
                    };
                    let mut e = DirEntry::file(name, mode, stat.size, stat.mtime, chunks.clone());
                    e.torn = torn.then_some(true);
                    chunks_all.extend(chunks.iter().copied());
                    new_index.insert(v.clone(), IndexedFile { stat, chunks });
                    entries.push(e);
                }
            }
            let encoded = DirObject::new(entries).encode();
            dir_keys.insert(dir.clone(), (self.key_for_dir)(&encoded.sha256));
            dirs.insert(encoded.sha256.clone(), encoded.clone());
            if dir.is_empty() {
                root = Some(encoded);
            }
        }
        stats.chunks = chunks_all.len() as u64;
        self.index.files = new_index;
        let root = root.unwrap_or_else(|| DirObject::default().encode());
        Ok(BuiltTree {
            root,
            dirs,
            chunks: chunks_all,
            stats,
        })
    }

    /// Read a SQLite `db` + `-wal` group: `-wal` first, then `db`; re-read both if either changed,
    /// bounded to [`READ_ATTEMPTS`]; then marked torn.
    #[allow(clippy::type_complexity)]
    fn read_group<'s>(
        &mut self,
        db_v: &str,
        db: &'s Source,
        wal_v: &str,
        wal: &'s Source,
        sink: &mut dyn ChunkSink,
        stats: &mut BuildStats,
    ) -> Option<Vec<(String, &'s Source, Vec<ChunkId>, FileStat, bool)>> {
        let mut last = None;
        for attempt in 0..READ_ATTEMPTS {
            let before = (
                FileStat::of(&fs::symlink_metadata(&wal.abs).ok()?),
                FileStat::of(&fs::symlink_metadata(&db.abs).ok()?),
            );
            let reuse = self
                .index
                .files
                .get(wal_v)
                .zip(self.index.files.get(db_v))
                .filter(|(w, d)| {
                    w.stat == before.0
                        && d.stat == before.1
                        && w.chunks
                            .iter()
                            .chain(d.chunks.iter())
                            .all(|c| sink.contains(c))
                })
                .map(|(w, d)| (w.chunks.clone(), d.chunks.clone()));
            let (wal_chunks, db_chunks) = match reuse {
                Some(r) => r,
                None => {
                    let (w, wb) = self.chunk_file(&wal.abs, sink, stats).ok()?;
                    let (d, db_bytes) = self.chunk_file(&db.abs, sink, stats).ok()?;
                    stats.files_read += 2;
                    stats.bytes_read += wb + db_bytes;
                    (w, d)
                }
            };
            let after = (
                FileStat::of(&fs::symlink_metadata(&wal.abs).ok()?),
                FileStat::of(&fs::symlink_metadata(&db.abs).ok()?),
            );
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
        last
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

    #[test]
    fn exclusions_and_pack_without_idx() {
        let dir = tempfile::tempdir().unwrap();
        let r = dir.path();
        fs::create_dir_all(r.join("objects/pack")).unwrap();
        fs::write(r.join("index.lock"), b"").unwrap();
        fs::write(r.join("gc.pid"), b"").unwrap();
        fs::write(r.join("s.db-shm"), b"").unwrap();
        fs::write(r.join("objects/tmp_pack_x"), b"").unwrap();
        fs::write(r.join("objects/incoming-x"), b"").unwrap();
        fs::write(r.join("objects/pack/pack-a.pack"), b"a").unwrap();
        fs::write(r.join("objects/pack/pack-b.pack"), b"b").unwrap();
        fs::write(r.join("objects/pack/pack-b.idx"), b"i").unwrap();
        fs::write(r.join("keep.txt"), b"k").unwrap();
        let mut l = Listing::default();
        l.mount("", r, |_, _| false, |_, _| true);
        let keys: Vec<&String> = l.entries.keys().collect();
        assert!(
            !keys
                .iter()
                .any(|k| k.contains("lock") || k.contains("gc.pid") || k.contains("shm"))
        );
        assert!(
            !keys
                .iter()
                .any(|k| k.contains("tmp_") || k.contains("incoming"))
        );
        assert!(!l.entries.contains_key("objects/pack/pack-a.pack"));
        assert!(l.entries.contains_key("objects/pack/pack-b.pack"));
        assert!(l.entries.contains_key("objects/pack/pack-b.idx"));
        assert!(l.entries.contains_key("keep.txt"));
        assert!(is_excluded_name("x.lock", None));
        assert!(is_excluded_name("tmp_abc", Some("objects")));
        assert!(!is_excluded_name("tmp_abc", Some("other")));
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
        l.mount("", r, |_, _| false, |_, _| true);

        let mut index = TreeIndex::default();
        let mut sink = MemSink::default();
        let built = TreeBuilder::new(&mut index, &key)
            .build(&l, &mut sink)
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
            .build(&l, &mut sink)
            .unwrap();
        assert_eq!(built2.stats.files_read, 0);
        assert_eq!(built2.root.sha256, built.root.sha256);

        // Touch a file: only it is re-read, and the tree changes.
        fs::write(r.join("a.txt"), b"alpha2").unwrap();
        let mut l = Listing::default();
        l.mount("", r, |_, _| false, |_, _| true);
        let built3 = TreeBuilder::new(&mut index, &key)
            .build(&l, &mut sink)
            .unwrap();
        assert_eq!(built3.stats.files_read, 1);
        assert_ne!(built3.root.sha256, built.root.sha256);
    }
}
