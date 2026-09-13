//! `Materializer`: bring a workspace to a manifest from a sink, writing only what differs. Git
//! packs go into `.git/objects/pack` (a missing `.idx` is regenerated; a pack already there is
//! left alone), refs into `packed-refs`, the working tree moves from the tree last checked out
//! to the manifest's worktree pseudo-ref through a two-tree `read-tree` (a full checkout when
//! nothing is known about the disk), chunked classes are reassembled file by file with mode and
//! mtime restored and hardlink groups linked. Every object read is verified against its sha256.
//!
//! # Delta
//!
//! A file already on disk is skipped when the [`DiskState`] index — the same `(size, mtime,
//! inode)` + chunk list the engine keeps for CDC — matches both the disk and the plan entry;
//! the materializer records every file it writes there, so a second materialize over the first
//! costs only the difference. A symlink whose text matches and a hardlink member already on the
//! canonical inode are skipped alike. Files, symlinks and empty directories under the capture
//! roots that the plan does not name are removed — and only those: the roots are listed with
//! the engine's own policy ([`ClassRoots`]), so the staging directory, excluded names
//! (`*.lock`, credentials, …), bulk directories of a pending bulk section and everything
//! outside the roots are never touched. A standby executor materializes the project base at
//! boot and applies the head over it at claim (`capture.replan`).

use std::collections::{BTreeSet, HashMap};
use std::fs::{self, File};
use std::io::{self, Write};
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};

use crate::chunk::{ChunkId, sha256_hex};
use crate::gitpack::{self, GitError, GitRepo};
use crate::index::{self, DAEMON_DIR, FileStat, IndexedFile, Listing, TreeIndex};
use crate::keys::key_digest;
use crate::manifest::{EncodedManifest, FsckStatus, INDEX_TREE_REF, Manifest, WORKTREE_TREE_REF};
use crate::pack::{PackError, PackReader};
use crate::roots::ClassRoots;
use crate::sink::{BlobSink, SinkError};
use crate::tree::{DirEntry, DirObject, EntryKind};

/// Which classes to materialize.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MaterializeClass {
    /// Git objects, refs, `HEAD`, the checked-out worktree.
    Git,
    /// `.git` bookkeeping, ignored files, harness home.
    Workspace,
    /// Dependencies and build outputs.
    Bulk,
    /// Everything.
    All,
}

/// Materialize errors.
#[derive(Debug, thiserror::Error)]
pub enum MaterializeError {
    /// An object's bytes did not hash to its key.
    #[error("{key}: bytes hash to {actual}, not the key")]
    Corrupt {
        /// Key.
        key: String,
        /// Observed digest.
        actual: String,
    },
    /// A chunk was in no listed pack.
    #[error("chunk {0} is in no pack the manifest lists")]
    MissingChunk(ChunkId),
    /// A dir object could not be parsed.
    #[error("dir object {key}: {reason}")]
    BadDir {
        /// Key.
        key: String,
        /// Why.
        reason: String,
    },
    /// The manifest bytes do not hash to the expected capture id.
    #[error("manifest hashes to {actual}, expected {expected}")]
    ManifestMismatch {
        /// Expected id.
        expected: String,
        /// Observed id.
        actual: String,
    },
    /// Sink.
    #[error(transparent)]
    Sink(#[from] SinkError),
    /// Pack.
    #[error(transparent)]
    Pack(#[from] PackError),
    /// Git.
    #[error(transparent)]
    Git(#[from] GitError),
    /// I/O.
    #[error(transparent)]
    Io(#[from] io::Error),
}

/// Counters.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct MaterializeReport {
    /// Files written.
    pub files: u64,
    /// Bytes written.
    pub bytes: u64,
    /// Files already on disk as the plan has them (size, mtime and chunks matched the index).
    pub files_skipped: u64,
    /// Bytes those files hold.
    pub bytes_skipped: u64,
    /// Files and symlinks removed because the plan no longer names them.
    pub removed: u64,
    /// Symlinks created.
    pub symlinks: u64,
    /// Hardlinks created.
    pub hardlinks: u64,
    /// Packs fetched from the sink (cache misses).
    pub packs_fetched: u64,
    /// Git packs installed (not counting the ones already there).
    pub git_packs: u64,
    /// Paths the worktree checkout touched: the tree diff for a delta checkout, `None` for a
    /// full one (nothing was known about the disk) or when the git class was not asked for.
    pub git_paths_changed: Option<u64>,
    /// fsck outcome after the git class, when run (a delta that installed no pack skips it).
    pub fsck: Option<FsckStatus>,
}

/// Where the workspace class's virtual roots land.
#[derive(Debug, Clone)]
pub struct MaterializeTargets {
    /// Worktree root.
    pub root: PathBuf,
    /// Harness home (the `harness/` subtree); skipped when `None`.
    pub harness_home: Option<PathBuf>,
    /// Pack cache (verified packs by sha256).
    pub cache_dir: PathBuf,
    /// Scratch space for temporary git indexes.
    pub scratch_dir: PathBuf,
    /// Where [`DiskState`] is kept between materializes (the engine's index dir).
    pub index_dir: PathBuf,
    /// The staging directory, never swept.
    pub staging_dir: PathBuf,
    /// Directory names treated as bulk wherever they appear.
    pub bulk_dirs: Vec<String>,
}

impl MaterializeTargets {
    /// Defaults under `<root>/.sealantd/capture/`.
    #[must_use]
    pub fn new(root: &Path, harness_home: Option<PathBuf>) -> Self {
        let staging = root.join(DAEMON_DIR).join("capture");
        Self {
            root: root.to_path_buf(),
            harness_home,
            cache_dir: staging.join("cache"),
            scratch_dir: staging.join("scratch"),
            index_dir: staging.join("index"),
            staging_dir: staging,
            bulk_dirs: index::DEFAULT_BULK_DIRS
                .iter()
                .map(|s| (*s).to_owned())
                .collect(),
        }
    }

    fn roots(&self) -> ClassRoots {
        ClassRoots {
            root: self.root.clone(),
            harness_home: self.harness_home.clone(),
            bulk_dirs: self.bulk_dirs.clone(),
            staging_dir: self.staging_dir.clone(),
        }
    }
}

/// What the materializer knows about the disk: the tree indexes of the chunked classes as
/// written (the engine's `workspace.json` / `bulk.json`, so a snap after a materialize reuses
/// them) and the worktree tree last checked out. The engine hands its indexes over for a
/// re-plan and takes them back.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct DiskState {
    /// Workspace class index (virtual paths `.git/…`, `tree/…`, `harness/…`).
    pub workspace: TreeIndex,
    /// Bulk class index (paths relative to the root).
    pub bulk: TreeIndex,
    /// The `WORKTREE_TREE_REF` tree the working tree was last brought to.
    pub worktree_tree: Option<String>,
    /// The `INDEX_TREE_REF` tree the index was last read from.
    pub index_tree: Option<String>,
}

#[derive(Debug, Default, Serialize, Deserialize)]
struct MaterializedRecord {
    worktree_tree: Option<String>,
    #[serde(default)]
    index_tree: Option<String>,
}

impl DiskState {
    /// Load from `index_dir`; anything missing or unreadable is empty (a full materialize).
    #[must_use]
    pub fn load(index_dir: &Path) -> Self {
        let record: MaterializedRecord = fs::read(index_dir.join("materialized.json"))
            .ok()
            .and_then(|b| serde_json::from_slice(&b).ok())
            .unwrap_or_default();
        Self {
            workspace: TreeIndex::load(&index_dir.join("workspace.json")),
            bulk: TreeIndex::load(&index_dir.join("bulk.json")),
            worktree_tree: record.worktree_tree,
            index_tree: record.index_tree,
        }
    }

    /// Save to `index_dir` (write-then-rename per file).
    pub fn save(&self, index_dir: &Path) -> io::Result<()> {
        fs::create_dir_all(index_dir)?;
        self.workspace.save(&index_dir.join("workspace.json"))?;
        self.bulk.save(&index_dir.join("bulk.json"))?;
        let path = index_dir.join("materialized.json");
        let tmp = path.with_extension("tmp");
        fs::write(
            &tmp,
            serde_json::to_vec(&MaterializedRecord {
                worktree_tree: self.worktree_tree.clone(),
                index_tree: self.index_tree.clone(),
            })?,
        )?;
        fs::rename(tmp, path)
    }
}

/// Verify `bytes` against a content-addressed key.
fn verify_key(key: &str, bytes: &[u8]) -> Result<(), MaterializeError> {
    if let Some(expected) = key_digest(key)
        && !key.ends_with(".idx")
    {
        let actual = sha256_hex(bytes);
        if actual != expected {
            return Err(MaterializeError::Corrupt {
                key: key.to_owned(),
                actual,
            });
        }
    }
    Ok(())
}

/// Rebuilds a workspace from manifests.
pub struct Materializer<'a> {
    sink: &'a dyn BlobSink,
    targets: MaterializeTargets,
}

impl std::fmt::Debug for Materializer<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Materializer")
            .field("targets", &self.targets)
            .finish_non_exhaustive()
    }
}

struct ChunkStore {
    readers: Vec<PackReader>,
    by_chunk: HashMap<ChunkId, usize>,
}

impl ChunkStore {
    fn read(&self, id: &ChunkId) -> Result<Vec<u8>, MaterializeError> {
        let idx = self
            .by_chunk
            .get(id)
            .ok_or(MaterializeError::MissingChunk(*id))?;
        self.readers[*idx]
            .read(id)?
            .ok_or(MaterializeError::MissingChunk(*id))
    }
}

/// One chunked class being materialized: its index, every virtual path the plan names, the
/// hardlink members to link once the canonical files are in place, and the directory metadata
/// to restore once nothing writes into them any more.
struct ClassWrite<'i> {
    index: &'i mut TreeIndex,
    planned: BTreeSet<String>,
    /// (canonical virtual path, member path on disk, mode).
    links: Vec<(String, PathBuf, u32)>,
    /// (directory on disk, mode, mtime).
    dirs: Vec<(PathBuf, u32, i64)>,
}

fn join_virtual(prefix: &str, name: &str) -> String {
    if prefix.is_empty() {
        name.to_owned()
    } else {
        format!("{prefix}/{name}")
    }
}

impl<'a> Materializer<'a> {
    /// Over `sink`, writing to `targets`.
    #[must_use]
    pub fn new(sink: &'a dyn BlobSink, targets: MaterializeTargets) -> Self {
        Self { sink, targets }
    }

    /// Fetch and verify a manifest by key and expected capture id.
    pub fn fetch_manifest(
        &self,
        key: &str,
        capture_id: &str,
    ) -> Result<EncodedManifest, MaterializeError> {
        let bytes = self.sink.get(key)?;
        let actual = sha256_hex(&bytes);
        if actual != capture_id {
            return Err(MaterializeError::ManifestMismatch {
                expected: capture_id.to_owned(),
                actual,
            });
        }
        Manifest::decode(&bytes).map_err(|e| MaterializeError::BadDir {
            key: key.to_owned(),
            reason: e.to_string(),
        })
    }

    /// Materialize `class` of `manifest` over whatever is on disk, keeping the [`DiskState`]
    /// under the targets' index dir between calls.
    pub fn materialize(
        &self,
        manifest: &Manifest,
        class: MaterializeClass,
    ) -> Result<MaterializeReport, MaterializeError> {
        let mut state = DiskState::load(&self.targets.index_dir);
        let report = self.materialize_with_state(manifest, class, &mut state)?;
        state.save(&self.targets.index_dir)?;
        Ok(report)
    }

    /// Materialize `class` of `manifest` over the disk `state` describes, updating it.
    pub fn materialize_with_state(
        &self,
        manifest: &Manifest,
        class: MaterializeClass,
        state: &mut DiskState,
    ) -> Result<MaterializeReport, MaterializeError> {
        let mut report = MaterializeReport::default();
        fs::create_dir_all(&self.targets.root)?;
        fs::create_dir_all(&self.targets.cache_dir)?;
        let roots = self.targets.roots();
        if matches!(class, MaterializeClass::Git | MaterializeClass::All) {
            self.materialize_git(manifest, state, &mut report)?;
        }
        if matches!(class, MaterializeClass::Workspace | MaterializeClass::All) {
            let ws = &manifest.sections.workspace;
            let store = self.open_packs(&ws.packs, &mut report)?;
            let root = self.fetch_dir(&ws.root)?;
            // A root that is not a repository (the class restored on its own) takes `.git/`
            // literally and is not swept: the sweep needs git's view of what is ignored.
            let repo = GitRepo::open(&self.targets.root).ok();
            let git_dir = repo
                .as_ref()
                .map_or_else(|| self.targets.root.join(".git"), |r| r.git_dir.clone());
            let mut write = ClassWrite {
                index: &mut state.workspace,
                planned: BTreeSet::new(),
                links: Vec::new(),
                dirs: Vec::new(),
            };
            for entry in &root.entries {
                let Some(target) = roots.workspace_path(&git_dir, &entry.name) else {
                    if entry.name != "harness" {
                        tracing::warn!(name = %entry.name, "unknown workspace root entry; skipped");
                    }
                    continue;
                };
                let Some(child) = entry.child.as_ref() else {
                    continue;
                };
                self.write_dir(&store, child, &target, &entry.name, &mut write, &mut report)?;
            }
            let resolve = |v: &str| roots.workspace_path(&git_dir, v);
            Self::link_all(&write.links, &resolve, &mut report)?;
            if let Some(repo) = &repo {
                let gitlinks = repo.nested_repositories(None)?;
                let listing = roots.workspace_listing(repo, &gitlinks)?;
                let keep: Vec<PathBuf> = [
                    Some(self.targets.root.clone()),
                    Some(repo.git_dir.clone()),
                    roots.harness_home.clone(),
                ]
                .into_iter()
                .flatten()
                .collect();
                Self::sweep(&listing, &write.planned, &keep, write.index, &mut report)?;
            }
            Self::restore_dirs(&write.dirs);
        }
        if matches!(class, MaterializeClass::Bulk | MaterializeClass::All)
            && let Some(bulk) = manifest.sections.bulk.section()
        {
            let store = self.open_packs(&bulk.packs, &mut report)?;
            let root = self.targets.root.clone();
            let mut write = ClassWrite {
                index: &mut state.bulk,
                planned: BTreeSet::new(),
                links: Vec::new(),
                dirs: Vec::new(),
            };
            self.write_dir(&store, &bulk.root, &root, "", &mut write, &mut report)?;
            let resolve = |v: &str| Some(root.join(v));
            Self::link_all(&write.links, &resolve, &mut report)?;
            let listing = roots.bulk_listing();
            // Only bulk directories are swept; their ancestors are the worktree's.
            let bulk_only: BTreeSet<String> = listing
                .entries
                .keys()
                .filter(|v| !index::has_component_in(Path::new(v), &roots.bulk_dirs))
                .cloned()
                .chain(write.planned.iter().cloned())
                .collect();
            Self::sweep(
                &listing,
                &bulk_only,
                std::slice::from_ref(&root),
                write.index,
                &mut report,
            )?;
            Self::restore_dirs(&write.dirs);
        }
        // After every class (the workspace class restores `.git/info/exclude` as captured):
        // the daemon directory stays out of the restored tree's index before anything runs in it.
        if matches!(class, MaterializeClass::Git | MaterializeClass::All) {
            GitRepo::open(&self.targets.root)?.exclude_locally(&format!("/{DAEMON_DIR}/"))?;
        }
        Ok(report)
    }

    fn materialize_git(
        &self,
        manifest: &Manifest,
        state: &mut DiskState,
        report: &mut MaterializeReport,
    ) -> Result<(), MaterializeError> {
        let repo = GitRepo::init(&self.targets.root)?;
        let git = &manifest.sections.git;
        for key in &git.packs {
            let Some(sha) = key_digest(key) else { continue };
            if gitpack::pack_installed(&repo, sha) {
                continue;
            }
            let pack = self.sink.get(key)?;
            verify_key(key, &pack)?;
            let idx_key = format!("{key}.idx");
            let idx = match self.sink.get(&idx_key) {
                Ok(b) => Some(b),
                Err(SinkError::NotFound(_)) => None,
                Err(e) => return Err(e.into()),
            };
            if gitpack::install_pack(&repo, sha, &pack, idx.as_deref())? {
                report.git_packs += 1;
            }
        }
        gitpack::write_packed_refs(&repo, &git.refs)?;
        gitpack::write_head(&repo, &git.head)?;
        if let Some(tree) = git.refs.get(WORKTREE_TREE_REF) {
            let excludes = vec![DAEMON_DIR.to_owned()];
            // The tree last checked out is trusted only while its objects are still here.
            let from = state.worktree_tree.clone().filter(|t| {
                repo.existing(std::slice::from_ref(t))
                    .is_ok_and(|e| !e.is_empty())
            });
            match from {
                Some(from) => {
                    let changed =
                        gitpack::checkout_tree_from(&repo, &from, tree, &self.targets.scratch_dir)?;
                    report.git_paths_changed = Some(changed);
                }
                None => {
                    gitpack::checkout_tree(&repo, tree, &self.targets.scratch_dir)?;
                }
            }
            for rel in
                gitpack::untracked_against(&repo, tree, &self.targets.scratch_dir, &excludes)?
            {
                let path = self.targets.root.join(&rel);
                if fs::symlink_metadata(&path).is_ok_and(|m| !m.is_dir()) {
                    fs::remove_file(&path)?;
                    report.removed += 1;
                }
            }
            state.worktree_tree = Some(tree.clone());
        }
        if let Some(tree) = git.refs.get(INDEX_TREE_REF)
            && state.index_tree.as_deref() != Some(tree)
        {
            // The workspace class overwrites this with the captured index bytes when it has them.
            gitpack::read_tree_into_index(&repo, tree)?;
            state.index_tree = Some(tree.clone());
        }
        if report.git_packs > 0 || report.git_paths_changed.is_none() {
            report.fsck = Some(repo.fsck()?);
        }
        Ok(())
    }

    /// Fetch (or reuse from the cache) every pack and index their chunks.
    fn open_packs(
        &self,
        keys: &[String],
        report: &mut MaterializeReport,
    ) -> Result<ChunkStore, MaterializeError> {
        let mut readers = Vec::new();
        let mut by_chunk = HashMap::new();
        for key in keys {
            let Some(sha) = key_digest(key) else { continue };
            let cached = self.targets.cache_dir.join(sha);
            if !cached.exists() {
                let bytes = self.sink.get(key)?;
                verify_key(key, &bytes)?;
                let tmp = self.targets.cache_dir.join(format!("{sha}.tmp"));
                fs::write(&tmp, &bytes)?;
                fs::rename(&tmp, &cached)?;
                report.packs_fetched += 1;
            }
            let reader = PackReader::open(&cached)?;
            let idx = readers.len();
            for id in reader.chunk_ids() {
                by_chunk.entry(*id).or_insert(idx);
            }
            readers.push(reader);
        }
        Ok(ChunkStore { readers, by_chunk })
    }

    fn fetch_dir(&self, key: &str) -> Result<DirObject, MaterializeError> {
        let bytes = self.sink.get(key)?;
        verify_key(key, &bytes)?;
        DirObject::decode(&bytes).map_err(|e| MaterializeError::BadDir {
            key: key.to_owned(),
            reason: e.to_string(),
        })
    }

    /// Whether the file at `path` is already what `entry` describes: a regular file whose stat
    /// matches the index entry for `v` (so its chunks are known) and whose size, mtime and
    /// chunks match the plan.
    fn file_matches(v: &str, entry: &DirEntry, path: &Path, index: &TreeIndex) -> bool {
        let Ok(meta) = fs::symlink_metadata(path) else {
            return false;
        };
        if !meta.is_file() {
            return false;
        }
        let Some(known) = index.files.get(v) else {
            return false;
        };
        let stat = FileStat::of(&meta);
        known.stat == stat
            && stat.size == entry.size
            && stat.mtime == entry.mtime
            && entry
                .chunks
                .as_deref()
                .is_some_and(|c| c == known.chunks.as_slice())
    }

    fn write_dir(
        &self,
        store: &ChunkStore,
        key: &str,
        dir: &Path,
        vdir: &str,
        write: &mut ClassWrite<'_>,
        report: &mut MaterializeReport,
    ) -> Result<(), MaterializeError> {
        let obj = self.fetch_dir(key)?;
        if fs::symlink_metadata(dir).is_ok_and(|m| !m.is_dir()) {
            remove_existing(dir)?;
        }
        fs::create_dir_all(dir)?;
        if !vdir.is_empty() {
            write.planned.insert(vdir.to_owned());
        }
        for entry in &obj.entries {
            let path = dir.join(&entry.name);
            let v = join_virtual(vdir, &entry.name);
            write.planned.insert(v.clone());
            match entry.kind {
                EntryKind::Dir => {
                    if let Some(child) = &entry.child {
                        self.write_dir(store, child, &path, &v, write, report)?;
                        write.dirs.push((path, entry.mode, entry.mtime));
                    }
                }
                EntryKind::File => {
                    if Self::file_matches(&v, entry, &path, write.index) {
                        report.files_skipped += 1;
                        report.bytes_skipped += entry.size;
                        if let Ok(meta) = fs::symlink_metadata(&path)
                            && meta.mode() & 0o7777 != entry.mode
                        {
                            fs::set_permissions(&path, fs::Permissions::from_mode(entry.mode))?;
                        }
                        continue;
                    }
                    let tmp = dir.join(format!(".{}.capture-tmp", entry.name));
                    {
                        let mut f = File::create(&tmp)?;
                        for id in entry.chunks.iter().flatten() {
                            let data = store.read(id)?;
                            f.write_all(&data)?;
                            report.bytes += data.len() as u64;
                        }
                        f.set_permissions(fs::Permissions::from_mode(entry.mode))?;
                        set_mtime(&f, entry.mtime)?;
                    }
                    remove_existing(&path)?;
                    fs::rename(&tmp, &path)?;
                    report.files += 1;
                    let meta = fs::symlink_metadata(&path)?;
                    write.index.files.insert(
                        v,
                        IndexedFile {
                            stat: FileStat::of(&meta),
                            chunks: entry.chunks.clone().unwrap_or_default(),
                        },
                    );
                }
                EntryKind::Symlink => {
                    let target = entry.target.as_deref().unwrap_or("");
                    if fs::read_link(&path).is_ok_and(|t| t == Path::new(target)) {
                        continue;
                    }
                    remove_existing(&path)?;
                    std::os::unix::fs::symlink(target, &path)?;
                    report.symlinks += 1;
                }
                EntryKind::HardlinkGroup => {
                    if let Some(canonical) = &entry.target {
                        write.links.push((canonical.clone(), path, entry.mode));
                    }
                }
            }
        }
        Ok(())
    }

    fn link_all(
        links: &[(String, PathBuf, u32)],
        resolve: &dyn Fn(&str) -> Option<PathBuf>,
        report: &mut MaterializeReport,
    ) -> Result<(), MaterializeError> {
        for (canonical_v, path, mode) in links {
            let Some(canonical) = resolve(canonical_v) else {
                tracing::warn!(canonical = %canonical_v, "hardlink group canonical outside the class roots; skipped");
                continue;
            };
            if let (Ok(a), Ok(b)) = (fs::symlink_metadata(&canonical), fs::symlink_metadata(path))
                && a.is_file()
                && b.is_file()
                && (a.dev(), a.ino()) == (b.dev(), b.ino())
            {
                continue;
            }
            remove_existing(path)?;
            if fs::hard_link(&canonical, path).is_err() {
                // Cross-device or unsupported: copy instead.
                fs::copy(&canonical, path)?;
                fs::set_permissions(path, fs::Permissions::from_mode(*mode))?;
            }
            report.hardlinks += 1;
        }
        Ok(())
    }

    /// Remove what the class would capture but the plan does not name: files and symlinks
    /// first, then directories that emptied out (never a listing root in `keep`). The index
    /// ends up naming the plan's files and nothing else.
    fn sweep(
        listing: &Listing,
        planned: &BTreeSet<String>,
        keep: &[PathBuf],
        index: &mut TreeIndex,
        report: &mut MaterializeReport,
    ) -> Result<(), MaterializeError> {
        let mut stale: Vec<(&String, &index::Source)> = listing
            .entries
            .iter()
            .filter(|(v, _)| !planned.contains(v.as_str()))
            .collect();
        // Children sort before their parents (a child's path is longer), so a directory is
        // tried once everything under it went.
        stale.sort_by(|a, b| b.0.len().cmp(&a.0.len()).then_with(|| a.0.cmp(b.0)));
        for (v, src) in stale {
            if src.meta.is_dir() {
                if keep.iter().any(|k| k == &src.abs) {
                    continue;
                }
                // Only an emptied directory goes; one that still holds something the listing
                // did not cover (an excluded name, a nested mount) stays.
                fs::remove_dir(&src.abs).ok();
            } else {
                match fs::remove_file(&src.abs) {
                    Ok(()) => report.removed += 1,
                    Err(e) if e.kind() == io::ErrorKind::NotFound => {}
                    Err(e) => return Err(e.into()),
                }
                index.files.remove(v.as_str());
            }
        }
        index.files.retain(|v, _| planned.contains(v));
        Ok(())
    }

    /// Restore directory modes and mtimes once nothing writes into them any more.
    fn restore_dirs(dirs: &[(PathBuf, u32, i64)]) {
        for (path, mode, mtime) in dirs {
            fs::set_permissions(path, fs::Permissions::from_mode(*mode)).ok();
            if let Ok(f) = File::open(path) {
                set_mtime(&f, *mtime).ok();
            }
        }
    }
}

fn remove_existing(path: &Path) -> io::Result<()> {
    match fs::symlink_metadata(path) {
        Ok(m) if m.is_dir() => fs::remove_dir_all(path),
        Ok(_) => fs::remove_file(path),
        Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(e) => Err(e),
    }
}

fn set_mtime(f: &File, mtime_ns: i64) -> io::Result<()> {
    f.set_times(fs::FileTimes::new().set_modified(system_time_from_ns(mtime_ns)))
}

/// Convenience: nanoseconds → `SystemTime`, for tests and callers comparing mtimes.
#[must_use]
pub fn system_time_from_ns(mtime_ns: i64) -> SystemTime {
    if mtime_ns >= 0 {
        UNIX_EPOCH + Duration::from_nanos(mtime_ns as u64)
    } else {
        UNIX_EPOCH - Duration::from_nanos(mtime_ns.unsigned_abs())
    }
}
