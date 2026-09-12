//! `Materializer`: rebuild a workspace from a manifest and a sink. Git packs go into
//! `.git/objects/pack` (a missing `.idx` is regenerated), refs into `packed-refs`, the working
//! tree is checked out from the worktree pseudo-ref, chunked classes are reassembled file by file
//! with mode and mtime restored and hardlink groups linked. Every object read is verified against
//! its sha256.

use std::collections::{HashMap, HashSet};
use std::fs::{self, File};
use std::io::{self, Write};
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use crate::chunk::{ChunkId, sha256_hex};
use crate::gitpack::{self, GitError, GitRepo};
use crate::index::DAEMON_DIR;
use crate::keys::key_digest;
use crate::manifest::{EncodedManifest, FsckStatus, INDEX_TREE_REF, Manifest, WORKTREE_TREE_REF};
use crate::pack::{PackError, PackReader};
use crate::sink::{BlobSink, SinkError};
use crate::tree::{DirObject, EntryKind};

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
    /// Symlinks created.
    pub symlinks: u64,
    /// Hardlinks created.
    pub hardlinks: u64,
    /// Packs fetched from the sink (cache misses).
    pub packs_fetched: u64,
    /// Git packs installed.
    pub git_packs: u64,
    /// fsck outcome after the git class, when run.
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
}

impl MaterializeTargets {
    /// Defaults under `<root>/.sealantd/capture/`.
    #[must_use]
    pub fn new(root: &Path, harness_home: Option<PathBuf>) -> Self {
        let staging = root.join(".sealantd").join("capture");
        Self {
            root: root.to_path_buf(),
            harness_home,
            cache_dir: staging.join("cache"),
            scratch_dir: staging.join("scratch"),
        }
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

    /// Materialize `class` of `manifest`.
    pub fn materialize(
        &self,
        manifest: &Manifest,
        class: MaterializeClass,
    ) -> Result<MaterializeReport, MaterializeError> {
        let mut report = MaterializeReport::default();
        fs::create_dir_all(&self.targets.root)?;
        fs::create_dir_all(&self.targets.cache_dir)?;
        if matches!(class, MaterializeClass::Git | MaterializeClass::All) {
            self.materialize_git(manifest, &mut report)?;
        }
        if matches!(class, MaterializeClass::Workspace | MaterializeClass::All) {
            let ws = &manifest.sections.workspace;
            let store = self.open_packs(&ws.packs, &mut report)?;
            let root = self.fetch_dir(&ws.root)?;
            let mut links = Vec::new();
            for entry in &root.entries {
                let target = match entry.name.as_str() {
                    ".git" => Some(self.targets.root.join(".git")),
                    "tree" => Some(self.targets.root.clone()),
                    "harness" => self.targets.harness_home.clone(),
                    other => {
                        tracing::warn!(name = other, "unknown workspace root entry; skipped");
                        None
                    }
                };
                let (Some(target), Some(child)) = (target, entry.child.as_ref()) else {
                    continue;
                };
                fs::create_dir_all(&target)?;
                let class_root = target.clone();
                self.write_dir(&store, child, &target, &class_root, &mut links, &mut report)?;
            }
            self.link_all(&links, &mut report)?;
        }
        if matches!(class, MaterializeClass::Bulk | MaterializeClass::All)
            && let Some(bulk) = manifest.sections.bulk.section()
        {
            let store = self.open_packs(&bulk.packs, &mut report)?;
            let mut links = Vec::new();
            let root = self.targets.root.clone();
            self.write_dir(&store, &bulk.root, &root, &root, &mut links, &mut report)?;
            self.link_all(&links, &mut report)?;
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
        report: &mut MaterializeReport,
    ) -> Result<(), MaterializeError> {
        let repo = GitRepo::init(&self.targets.root)?;
        let git = &manifest.sections.git;
        for key in &git.packs {
            let Some(sha) = key_digest(key) else { continue };
            let pack = self.sink.get(key)?;
            verify_key(key, &pack)?;
            let idx_key = format!("{key}.idx");
            let idx = match self.sink.get(&idx_key) {
                Ok(b) => Some(b),
                Err(SinkError::NotFound(_)) => None,
                Err(e) => return Err(e.into()),
            };
            gitpack::install_pack(&repo, sha, &pack, idx.as_deref())?;
            report.git_packs += 1;
        }
        gitpack::write_packed_refs(&repo, &git.refs)?;
        gitpack::write_head(&repo, &git.head)?;
        if let Some(tree) = git.refs.get(WORKTREE_TREE_REF) {
            gitpack::checkout_tree(&repo, tree, &self.targets.scratch_dir)?;
        }
        if let Some(tree) = git.refs.get(INDEX_TREE_REF) {
            // The workspace class overwrites this with the captured index bytes when it has them.
            gitpack::read_tree_into_index(&repo, tree)?;
        }
        report.fsck = Some(repo.fsck()?);
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

    #[allow(clippy::too_many_arguments)]
    fn write_dir(
        &self,
        store: &ChunkStore,
        key: &str,
        dir: &Path,
        class_root: &Path,
        links: &mut Vec<(PathBuf, PathBuf, u32)>,
        report: &mut MaterializeReport,
    ) -> Result<(), MaterializeError> {
        let obj = self.fetch_dir(key)?;
        fs::create_dir_all(dir)?;
        let mut dir_modes: Vec<(PathBuf, u32, i64)> = Vec::new();
        for entry in &obj.entries {
            let path = dir.join(&entry.name);
            match entry.kind {
                EntryKind::Dir => {
                    if let Some(child) = &entry.child {
                        self.write_dir(store, child, &path, class_root, links, report)?;
                        dir_modes.push((path, entry.mode, entry.mtime));
                    }
                }
                EntryKind::File => {
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
                }
                EntryKind::Symlink => {
                    remove_existing(&path)?;
                    std::os::unix::fs::symlink(entry.target.as_deref().unwrap_or(""), &path)?;
                    report.symlinks += 1;
                }
                EntryKind::HardlinkGroup => {
                    if let Some(canonical) = &entry.target {
                        links.push((class_root.join(canonical), path, entry.mode));
                    }
                }
            }
        }
        for (path, mode, mtime) in dir_modes {
            fs::set_permissions(&path, fs::Permissions::from_mode(mode))?;
            if let Ok(f) = File::open(&path) {
                set_mtime(&f, mtime).ok();
            }
        }
        Ok(())
    }

    fn link_all(
        &self,
        links: &[(PathBuf, PathBuf, u32)],
        report: &mut MaterializeReport,
    ) -> Result<(), MaterializeError> {
        let mut seen: HashSet<&Path> = HashSet::new();
        for (canonical, path, mode) in links {
            remove_existing(path)?;
            if fs::hard_link(canonical, path).is_err() {
                // Cross-device or unsupported: copy instead.
                fs::copy(canonical, path)?;
                fs::set_permissions(path, fs::Permissions::from_mode(*mode))?;
            }
            seen.insert(path);
            report.hardlinks += 1;
        }
        Ok(())
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
    let t = if mtime_ns >= 0 {
        UNIX_EPOCH + Duration::from_nanos(mtime_ns as u64)
    } else {
        UNIX_EPOCH - Duration::from_nanos(mtime_ns.unsigned_abs())
    };
    f.set_times(fs::FileTimes::new().set_modified(t))
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
