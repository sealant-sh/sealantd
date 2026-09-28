//! `Materializer`: bring a workspace to a manifest from a sink, writing only what differs. Git
//! packs go into `.git/objects/pack` (a missing `.idx` is regenerated; a pack already there is
//! left alone), refs into `packed-refs`, the working tree moves from the tree last checked out
//! to the manifest's worktree pseudo-ref through a two-tree `read-tree` (a full checkout when
//! nothing is known about the disk), chunked classes are reassembled file by file with mode and
//! mtime restored and hardlink groups linked. Every object read is verified against its sha256.
//!
//! # Dir objects
//!
//! A section in format 2 lists its dir packs: they are fetched with the content packs (a few
//! GETs, in parallel, each at most once — a pack already in the cache is not fetched again) and
//! every dir object is read from them by digest. A section in format 1 has one object per
//! directory, fetched by its key as the walk reaches it; a head can hold one section of each
//! (a bulk section an older executor or the control plane wrote, under a workspace section this
//! build wrote). A format this build does not know is refused before anything is written.
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
//! outside the roots are never touched; nor is `.git/index`, which the git class rebuilds from
//! the index pseudo-ref and owns whenever the workspace class carries none. A standby executor
//! materializes the project base at boot and applies the head over it at claim
//! (`capture.replan`). A reused file keeps its inode, and every other name that inode has on the
//! disk: before a whole restore links anything, each group of names the capture joins (a single
//! name included) is put on an inode of its own ([`worktree_meta::DesiredInodes`]), and a sealed
//! one checks that no inode holds names of two groups.
//!
//! # Worktree metadata and refs
//!
//! A git checkout restores bytes and the executable bit only. When the workspace section
//! carries `worktree_meta`, the overlay ([`crate::worktree_meta`]) is verified before anything
//! is written and applied after every class: exact modes, nanosecond mtimes, untracked (empty)
//! directories and hardlink groups of the working tree. The bulk class never writes or sweeps a
//! path the worktree tree names (a tracked file under `build/` is the git class's). The ref set
//! is made exactly the manifest's: every loose ref goes, `packed-refs` holds the rest. Metadata
//! that cannot be restored — the overlay's, a chunked class's directory mode or mtime, a
//! symlink's mtime, a hardlink — fails the materialize.

use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::ffi::OsStr;
use std::fs::{self, File};
use std::io::{self, Write};
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};

use crate::chunk::{ChunkId, sha256_hex};
use crate::gitpack::{self, GitError, GitRepo};
use crate::index::{self, DAEMON_DIR, FileStat, IndexedFile, Listing, TreeIndex};
use crate::keys::key_digest;
use crate::longpath;
use crate::manifest::{
    EncodedManifest, FORMAT_DIR_OBJECTS, FORMAT_DIR_PACKS, FsckStatus, MAX_SECTION_FORMAT,
    Manifest, TreeRef, WORKTREE_META_FORMAT, WorktreeMeta,
};
use crate::pack::{PackError, PackReader};
use crate::roots::ClassRoots;
use crate::sink::{BlobSink, SinkError};
use crate::tree::{DirEntry, DirObject, EntryKind};
use crate::worktree_meta::{self, LinkClass, MetaDocument, MetaError, MetaScope};

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
    /// A format-2 dir object was in no dir pack the section lists.
    #[error("dir object {0} is in no dir pack the section lists")]
    MissingDir(String),
    /// A section in a format this build does not read.
    #[error(
        "the {section} section is format {format}; this build reads formats up to {MAX_SECTION_FORMAT}"
    )]
    UnsupportedFormat {
        /// `workspace` or `bulk`.
        section: &'static str,
        /// The section's format.
        format: u32,
    },
    /// A worktree metadata overlay in a format this build does not read.
    #[error(
        "the worktree metadata overlay is format {0}; this build reads formats up to {WORKTREE_META_FORMAT}"
    )]
    UnsupportedMetaFormat(u32),
    /// The worktree metadata overlay could not be read or applied: the restore is incomplete.
    #[error(transparent)]
    WorktreeMeta(#[from] MetaError),
    /// A chunked class entry's metadata (a directory's mode or mtime, a symlink's mtime, a
    /// hardlink) could not be restored: the restore is incomplete.
    #[error("{path}: {reason}")]
    Metadata {
        /// The path on disk.
        path: String,
        /// What failed.
        reason: String,
    },
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

/// An I/O error on `path`, named: a restore that cannot write says where (it said only
/// `Permission denied` to a daemon that could not write the worktree).
trait At<T> {
    fn at(self, op: &'static str, path: &Path) -> Result<T, MaterializeError>;
}

impl<T> At<T> for io::Result<T> {
    fn at(self, op: &'static str, path: &Path) -> Result<T, MaterializeError> {
        self.map_err(|source| MaterializeError::IoAt {
            op,
            path: path.to_path_buf(),
            source,
        })
    }
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
    /// Packs fetched from the sink (cache misses), dir packs included.
    pub packs_fetched: u64,
    /// Format-1 dir objects fetched one by one.
    pub dir_objects_fetched: u64,
    /// Git packs installed (not counting the ones already there).
    pub git_packs: u64,
    /// Paths the worktree checkout touched: the tree diff for a delta checkout, `None` for a
    /// full one (nothing was known about the disk) or when the git class was not asked for.
    pub git_paths_changed: Option<u64>,
    /// fsck outcome after the git class, when run (a delta that installed no pack skips it).
    pub fsck: Option<FsckStatus>,
    /// Worktree paths the metadata overlay changed: directories created or removed, hardlinks
    /// made, modes and mtimes set (0 when the plan carries no overlay, or the disk already
    /// matched it).
    pub worktree_meta: u64,
    /// The workspace class names the repository's `.git/config`: the capture carries a
    /// session's own configuration, remotes included (or their absence), and it is the
    /// repository's. `false` for a base (Mend's capture 0 carries none) or when the workspace
    /// class was not asked for.
    pub git_config: bool,
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
    /// The tree the working tree was last brought to (the git section's raw tree when it has
    /// one, else its worktree tree).
    pub worktree_tree: Option<String>,
    /// The index tree the index was last read from.
    pub index_tree: Option<String>,
    /// The capture the last completed materialize brought the disk to, and under which lease
    /// epoch and executor ([`MaterializedCapture`]). The caller that knows them records it
    /// once a materialize completed ([`DiskState::record_capture`]); a materialize clears it
    /// before it writes anything, so an interrupted one leaves none.
    pub capture: Option<MaterializedCapture>,
}

/// What a completed materialize brought the disk to: the capture id, and the lease epoch and
/// executor (the launch `plan.get` named) it was materialized under. A recovery boot that finds
/// no staging continuing the head resumes a disk only when this names the plan's head, under
/// the plan's executor, at an epoch no later than the plan's (review 2026-09-28 #22): equal
/// worktree trees said nothing of the refs, index, bulk or metadata beside them.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MaterializedCapture {
    /// The capture id.
    pub capture_id: String,
    /// The lease epoch.
    pub epoch: u64,
    /// The executor `plan.get` named, if any.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub executor: Option<String>,
}

#[derive(Debug, Default, Serialize, Deserialize)]
struct MaterializedRecord {
    worktree_tree: Option<String>,
    #[serde(default)]
    index_tree: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    capture: Option<MaterializedCapture>,
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
            capture: record.capture,
        }
    }

    /// Record in `index_dir` that the disk holds `capture` (a materialize of it completed).
    pub fn record_capture(index_dir: &Path, capture: MaterializedCapture) -> io::Result<()> {
        let mut state = Self::load(index_dir);
        state.capture = Some(capture);
        state.save(index_dir)
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
                capture: self.capture.clone(),
            })?,
        )?;
        fs::rename(tmp, path)
    }
}

/// Workspace-class virtual paths the git class owns and the workspace sweep never removes:
/// the index is rebuilt from the index tree (and overwritten by the captured bytes when
/// the workspace class carries them). A plan whose workspace class does not name it — a base
/// capture the control plane authored from a bare repository has an empty workspace root —
/// must not lose it: without an index git takes every tracked path that matches an ignore
/// rule for an ignored file, and the next snap's worktree tree drops it (observed as
/// `D tooling/typescript/core.json` against a `.gitignore` line `core.*`).
const GIT_CLASS_FILES: &[&str] = &[".git/index"];

/// What the workspace sweep leaves of the repository the git class made, beside
/// [`GIT_CLASS_FILES`], when the plan's workspace class does not carry it (a base: Mend's
/// capture 0 carries no `.git/` at all): `.git/config`, which names the object format and ref
/// backend `git init` made the repository in, and a reftable repository's `reftable/`, which
/// holds the refs the git class just wrote. Swept, a SHA-256 restore read as SHA-1 and a
/// reftable one lost every ref (Docker end to end, round 8, F4b). A plan that carries them
/// writes its own, and the sweep treats them as it always did.
fn repository_files(listing: &Listing, planned: &BTreeSet<String>) -> Vec<String> {
    let mut protected: Vec<String> = GIT_CLASS_FILES.iter().map(|f| (*f).to_owned()).collect();
    if !planned.contains(".git/config") {
        protected.push(".git/config".to_owned());
    }
    let in_reftable = |v: &str| v == ".git/reftable" || v.starts_with(".git/reftable/");
    if !planned.iter().any(|v| in_reftable(v)) {
        protected.extend(listing.entries.keys().filter(|v| in_reftable(v)).cloned());
    }
    protected
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

/// Packs fetched at once while materializing.
pub const PACK_GETS_IN_FLIGHT: usize = 8;

struct ChunkStore {
    readers: Vec<PackReader>,
    by_chunk: HashMap<ChunkId, usize>,
}

/// Where a section's dir objects come from.
enum Dirs {
    /// Format 1: one object per directory, fetched by key.
    Objects,
    /// Format 2: the section's dir packs.
    Packs(ChunkStore),
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
    /// Paths the git class owns (the worktree tree's): never written or swept by this class.
    tracked: &'i BTreeSet<String>,
    planned: BTreeSet<String>,
    /// (canonical virtual path, member path on disk, mode).
    links: Vec<(String, PathBuf, u32)>,
    /// (directory on disk, mode, mtime).
    dirs: Vec<(PathBuf, u32, i128)>,
    /// Every file the class restored, written or reused: (virtual path, path on disk, the mode
    /// and mtime it has; `None` for a hardlink member, which has its canonical's).
    files: Vec<ClassFile>,
}

/// A file a chunked class restored: see [`ClassWrite::files`].
type ClassFile = (String, PathBuf, Option<(u32, i128)>);

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
        // What the disk held is about to change: until the caller records the capture this
        // materialize brings it to, it names none.
        if state.capture.take().is_some() {
            state.save(&self.targets.index_dir)?;
        }
        fs::create_dir_all(&self.targets.root).at("mkdir -p", &self.targets.root)?;
        fs::create_dir_all(&self.targets.cache_dir).at("mkdir -p", &self.targets.cache_dir)?;
        let roots = self.targets.roots();
        // Every content and dir pack the asked classes need, fetched up front and in parallel;
        // a format this build does not read is refused before anything is written.
        let mut packs: Vec<&String> = Vec::new();
        if matches!(class, MaterializeClass::Workspace | MaterializeClass::All) {
            let ws = &manifest.sections.workspace;
            check_format("workspace", ws.format)?;
            packs.extend(&ws.packs);
            packs.extend(&ws.dir_packs);
        }
        if matches!(class, MaterializeClass::Bulk | MaterializeClass::All)
            && let Some(bulk) = manifest.sections.bulk.section()
        {
            check_format("bulk", bulk.format)?;
            packs.extend(&bulk.packs);
            packs.extend(&bulk.dir_packs);
        }
        // The worktree metadata overlay goes with the git class (it describes the tree the git
        // class checks out).
        let meta = manifest
            .sections
            .workspace
            .worktree_meta
            .as_ref()
            .filter(|_| matches!(class, MaterializeClass::Git | MaterializeClass::All));
        if let Some(meta) = meta {
            if meta.format == 0 || meta.format > WORKTREE_META_FORMAT {
                return Err(MaterializeError::UnsupportedMetaFormat(meta.format));
            }
            packs.extend(&meta.packs);
        }
        self.fetch_packs(&packs, &mut report)?;
        // The workspace class's root directories — `.git` and the harness home — as captured:
        // set last of all, once nothing the restore writes (refs, the index, a child of the
        // class, `info/exclude`, a relinked name) moves them any more (review 2026-09-28,
        // seventh pass, #2). The worktree root (`tree`) is the overlay's.
        let mut class_roots: Vec<(PathBuf, u32, i128)> = Vec::new();
        // Each class's own hardlink groups, as restored: the worktree metadata's links across
        // classes move a whole group, never one name of it (review 12 #2).
        let mut restored = worktree_meta::RestoredGroups::default();
        // Every file the chunked classes restored, by class: each is a name of the inodes the
        // restore must leave (review 15 #2).
        let mut restored_files: Vec<(LinkClass, ClassFile)> = Vec::new();
        // Read before anything is written: a document that does not verify or decode fails
        // the materialize with the disk untouched.
        let meta = match meta {
            Some(meta) => Some(self.read_worktree_meta(meta, &mut report)?),
            None => None,
        };
        if matches!(class, MaterializeClass::Git | MaterializeClass::All) {
            self.materialize_git(manifest, state, &mut report)?;
        }
        if matches!(class, MaterializeClass::Workspace | MaterializeClass::All) {
            let ws = &manifest.sections.workspace;
            let store = self.open_packs(&ws.packs, &mut report)?;
            let dirs = self.open_dirs("workspace", ws.tree(), &mut report)?;
            let root = self.read_dir(&dirs, &ws.root, &mut report)?;
            // A root that is not a repository (the class restored on its own) takes `.git/`
            // literally and is not swept: the sweep needs git's view of what is ignored.
            let repo = GitRepo::open(&self.targets.root).ok();
            let git_dir = repo
                .as_ref()
                .map_or_else(|| self.targets.root.join(".git"), |r| r.git_dir.clone());
            let none = BTreeSet::new();
            let mut write = ClassWrite {
                index: &mut state.workspace,
                tracked: &none,
                planned: BTreeSet::new(),
                links: Vec::new(),
                dirs: Vec::new(),
                files: Vec::new(),
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
                self.write_dir(
                    &store,
                    &dirs,
                    child,
                    &target,
                    &entry.name,
                    &mut write,
                    &mut report,
                )?;
                if entry.kind == EntryKind::Dir && (entry.name == ".git" || entry.name == "harness")
                {
                    class_roots.push((target, entry.mode, entry.mtime));
                }
            }
            report.git_config = write.planned.contains(".git/config");
            let resolve = |v: &str| roots.workspace_path(&git_dir, v);
            Self::link_all(&write.links, &resolve, &mut report)?;
            restored_groups(&mut restored, LinkClass::Workspace, &write.links, &resolve);
            // A symlink under `refs/` git read through to a loose ref's file came back
            // reaching nothing (the refs are packed): that file is written loose again, with
            // the value the git section holds (review 2026-09-28, ninth pass, #2).
            if class == MaterializeClass::All
                && manifest.sections.git.ref_format() == "files"
                && let Some(repo) = &repo
            {
                let left =
                    gitpack::ground_ref_symlinks(repo, &manifest.sections.git.refs_to_restore())?;
                if !left.is_empty() {
                    if manifest.final_seal.is_some() {
                        return Err(io::Error::other(format!(
                            "symlinks the capture read as refs resolve to nothing restored: {}",
                            left.join(", ")
                        ))
                        .into());
                    }
                    tracing::warn!(
                        links = %left.join(", "),
                        "materialize: symlinks read as refs resolve to nothing restored"
                    );
                }
            }
            if let Some(repo) = &repo {
                let gitlinks = repo.chunked_paths(None)?;
                let listing = roots.workspace_listing(repo, &gitlinks)?;
                let keep: Vec<PathBuf> = [
                    Some(self.targets.root.clone()),
                    Some(repo.git_dir.clone()),
                    roots.harness_home.clone(),
                ]
                .into_iter()
                .flatten()
                .collect();
                let protected = repository_files(&listing, &write.planned);
                let protected: Vec<&str> = protected.iter().map(String::as_str).collect();
                Self::sweep(
                    &listing,
                    &write.planned,
                    &keep,
                    &protected,
                    write.index,
                    &mut report,
                )?;
            }
            refresh_linked(write.index, &write.links, &resolve);
            Self::restore_dirs(&write.dirs)?;
            restored_files.extend(
                std::mem::take(&mut write.files)
                    .into_iter()
                    .map(|f| (LinkClass::Workspace, f)),
            );
        }
        // Every path of the worktree tree: a tracked file under a bulk-named directory
        // (`build/`, `dist/`) is the git class's, and every tracked file is a name of the
        // inodes a whole restore must leave.
        let bulk_section = manifest
            .sections
            .bulk
            .section()
            .filter(|_| matches!(class, MaterializeClass::Bulk | MaterializeClass::All));
        let tracked = if class == MaterializeClass::All || bulk_section.is_some() {
            self.tracked_paths(manifest)?
        } else {
            BTreeSet::new()
        };
        if let Some(bulk) = bulk_section {
            let store = self.open_packs(&bulk.packs, &mut report)?;
            let dirs = self.open_dirs("bulk", bulk.tree(), &mut report)?;
            let root = self.targets.root.clone();
            // A tracked file under a bulk-named directory is the git class's: a bulk section
            // older than the worktree tree must neither write its older bytes over it nor sweep
            // one it never saw.
            let mut write = ClassWrite {
                index: &mut state.bulk,
                tracked: &tracked,
                planned: BTreeSet::new(),
                links: Vec::new(),
                dirs: Vec::new(),
                files: Vec::new(),
            };
            self.write_dir(
                &store,
                &dirs,
                &bulk.root,
                &root,
                "",
                &mut write,
                &mut report,
            )?;
            let resolve = |v: &str| Some(root.join(crate::tree::os_of_key(v)));
            Self::link_all(&write.links, &resolve, &mut report)?;
            restored_groups(&mut restored, LinkClass::Bulk, &write.links, &resolve);
            let listing = roots.bulk_listing();
            // Only bulk directories are swept; their ancestors are the worktree's.
            let bulk_only: BTreeSet<String> = listing
                .entries
                .keys()
                .filter(|v| !index::has_component_in(Path::new(v), &roots.bulk_dirs))
                .cloned()
                .chain(write.planned.iter().cloned())
                .chain(tracked.iter().cloned())
                .collect();
            Self::sweep(
                &listing,
                &bulk_only,
                std::slice::from_ref(&root),
                &[],
                write.index,
                &mut report,
            )?;
            refresh_linked(write.index, &write.links, &resolve);
            Self::restore_dirs(&write.dirs)?;
            restored_files.extend(
                std::mem::take(&mut write.files)
                    .into_iter()
                    .map(|f| (LinkClass::Bulk, f)),
            );
        }
        // After every class (the workspace class restores `.git/info/exclude` as captured):
        // the daemon directory stays out of the restored tree's index before anything runs in it.
        if matches!(class, MaterializeClass::Git | MaterializeClass::All) {
            let repo = GitRepo::open(&self.targets.root)?;
            // The formats the git class made the repository in are the capture's, whatever the
            // other classes wrote since (a captured config, or none): re-asserted before
            // anything reads a ref — the boot's remotes and the engine's seed come next.
            let git = &manifest.sections.git;
            repo.assert_formats(git.object_format(), git.ref_format())?;
            repo.exclude_locally(&format!("/{DAEMON_DIR}/"))?;
            let git_dir = repo.git_dir.clone();
            let resolve = |class: LinkClass, member: &[u8]| -> Option<PathBuf> {
                let member = Path::new(OsStr::from_bytes(member));
                match class {
                    LinkClass::Bulk => Some(self.targets.root.join(member)),
                    LinkClass::Workspace => {
                        let mut parts = member.components();
                        let head = parts.next()?.as_os_str().to_str()?.to_owned();
                        let rest = parts.as_path();
                        let base = match head.as_str() {
                            ".git" => git_dir.clone(),
                            "tree" => self.targets.root.clone(),
                            "harness" => self.targets.harness_home.clone()?,
                            _ => return None,
                        };
                        Some(base.join(rest))
                    }
                }
            };
            // A sealed final capture with every class restored (its bulk section ready)
            // promised its links: one it names that the restored names cannot make, or one the
            // restore left that it does not name, fails the materialize instead of passing in
            // silence.
            let strict = manifest.final_seal.is_some()
                && class == MaterializeClass::All
                && manifest.sections.bulk.section().is_some();
            // Before any link is made or any mtime set: a reused file keeps its inode, and with
            // it every name that inode had on this disk. Each group of names the capture joins
            // (a single name included) gets an inode of its own (review 15 #2).
            let mut desired = None;
            let mut apart: Vec<(LinkClass, String, PathBuf)> = Vec::new();
            if class == MaterializeClass::All {
                let mut inodes = worktree_meta::DesiredInodes::of(
                    &self.targets.root,
                    meta.as_ref(),
                    &resolve,
                    &restored,
                )?;
                for key in &tracked {
                    inodes.name(self.targets.root.join(crate::tree::os_of_key(key)));
                }
                for (_, (_, abs, _)) in &restored_files {
                    inodes.name(abs.clone());
                }
                let touched: BTreeSet<PathBuf> = inodes.separate()?.into_iter().collect();
                // A name that shared its inode with another class's may hold that class's
                // mode: each class's names get their own back.
                for (class, (key, abs, wanted)) in &restored_files {
                    if !touched.contains(abs) {
                        continue;
                    }
                    if let Some((mode, mtime)) = wanted {
                        Self::restore_file_meta(abs, *mode, *mtime)?;
                    }
                    apart.push((*class, key.clone(), abs.clone()));
                }
                desired = Some(inodes);
            }
            // Last of all: restoring the other classes moved the mtimes of the directories they
            // wrote into.
            if let Some(doc) = &meta {
                let scope = self.meta_scope(&repo)?;
                let applied =
                    worktree_meta::apply_over(&repo, doc, &scope, &resolve, &restored, strict)?;
                report.worktree_meta = applied.changed;
                // A relinked name has a new inode: the class's index must say so, or the next
                // delta would take it for changed and write it again.
                for (class, member, meta) in applied.relinked {
                    let index = match class {
                        LinkClass::Workspace => &mut state.workspace,
                        LinkClass::Bulk => &mut state.bulk,
                    };
                    if let Some(known) = index.files.get_mut(&member) {
                        known.stat = FileStat::of(&meta);
                    }
                }
            }
            if strict
                && let Some(inodes) = &mut desired
                && let Some(shared) = inodes.shared_inode()?
            {
                return Err(shared.into());
            }
            // A name given an inode of its own, or left on one that lost names, holds the same
            // bytes under a new inode or ctime: the class's index says so while the size and
            // mtime it knows still hold.
            for (class, key, abs) in apart {
                let index = match class {
                    LinkClass::Workspace => &mut state.workspace,
                    LinkClass::Bulk => &mut state.bulk,
                };
                if let Some(known) = index.files.get_mut(&key)
                    && let Ok(meta) = longpath::symlink_metadata(&abs)
                    && meta.is_file()
                    && meta.len() == known.stat.size
                    && index::mtime_ns(&meta) == known.stat.mtime
                {
                    known.stat = FileStat::of(&meta);
                }
            }
        }
        Self::restore_dirs(&class_roots)?;
        Ok(report)
    }

    /// Every path of the plan's worktree tree (files, symlinks, directories), relative to the
    /// root; empty when the root is not a repository or does not hold the tree.
    fn tracked_paths(&self, manifest: &Manifest) -> Result<BTreeSet<String>, MaterializeError> {
        let Some(tree) = manifest.sections.git.checkout_tree_id().map(str::to_owned) else {
            return Ok(BTreeSet::new());
        };
        let tree = &tree;
        let Ok(repo) = GitRepo::open(&self.targets.root) else {
            return Ok(BTreeSet::new());
        };
        if repo.existing(std::slice::from_ref(tree))?.is_empty() {
            return Ok(BTreeSet::new());
        }
        Ok(gitpack::tree_names(&repo, tree)?)
    }

    /// Fetch (from the pack cache) and verify the worktree metadata overlay.
    fn read_worktree_meta(
        &self,
        meta: &WorktreeMeta,
        report: &mut MaterializeReport,
    ) -> Result<MetaDocument, MaterializeError> {
        let store = self.open_packs(&meta.packs, report)?;
        let mut bytes = Vec::with_capacity(usize::try_from(meta.size).unwrap_or(0));
        for id in &meta.chunks {
            bytes.extend_from_slice(&store.read(id)?);
        }
        let actual = sha256_hex(&bytes);
        if bytes.len() as u64 != meta.size || actual != meta.sha256 {
            return Err(MaterializeError::Corrupt {
                key: format!("worktree_meta {}", meta.sha256),
                actual,
            });
        }
        Ok(MetaDocument::decode(&bytes)?)
    }

    /// What the overlay covers on this disk, as [`crate::CaptureEngine`] scopes it at capture.
    fn meta_scope(&self, repo: &GitRepo) -> Result<MetaScope, MaterializeError> {
        let t = &self.targets;
        let mut excludes = vec![DAEMON_DIR.to_owned()];
        if let Ok(rel) = t.staging_dir.strip_prefix(&t.root) {
            let rel = rel.to_string_lossy().trim_matches('/').to_owned();
            if !rel.is_empty() {
                excludes.push(rel);
            }
        }
        Ok(MetaScope {
            root: t.root.clone(),
            excludes,
            bulk_dirs: t.bulk_dirs.clone(),
            nested: repo.chunked_paths(None)?,
            skip_abs: [Some(t.staging_dir.clone()), t.harness_home.clone()]
                .into_iter()
                .flatten()
                .collect(),
        })
    }

    fn materialize_git(
        &self,
        manifest: &Manifest,
        state: &mut DiskState,
        report: &mut MaterializeReport,
    ) -> Result<(), MaterializeError> {
        let git = &manifest.sections.git;
        // The repository is made in the capture's object format before a pack goes in: a SHA-1
        // repository cannot read a SHA-256 pack (review 2026-09-28, eighth pass, #10).
        let format = git.object_format();
        if !crate::manifest::OBJECT_FORMATS.contains(&format) {
            return Err(io::Error::other(format!(
                "the capture's repository has object format {format}, which this build does not \
                 restore"
            ))
            .into());
        }
        // The refs go into the capture's backend (review 2026-09-28, ninth pass, #1): a reftable
        // repository reads none of `packed-refs` and `HEAD`.
        let ref_format = git.ref_format();
        if !crate::manifest::REF_FORMATS.contains(&ref_format) {
            return Err(io::Error::other(format!(
                "the capture's repository keeps its refs in the {ref_format} backend, which this \
                 build does not restore"
            ))
            .into());
        }
        let repo = GitRepo::init_with_formats(&self.targets.root, format, ref_format)?;
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
        // Every ref the repository held, whatever its name; an older manifest's two pseudo-refs
        // are its trees, not refs.
        if ref_format == "files" {
            gitpack::write_packed_refs(&repo, &git.refs_to_restore(), &git.symrefs)?;
            gitpack::write_head(&repo, &git.head)?;
        } else {
            gitpack::write_refs_through_git(
                &repo,
                &git.refs_to_restore(),
                &git.symrefs,
                &git.head,
            )?;
        }
        if let Some(tree) = git.checkout_tree_id() {
            let tree = &tree.to_owned();
            let excludes = vec![DAEMON_DIR.to_owned()];
            // The tree last checked out is trusted only while its objects are still here.
            let from = state.worktree_tree.clone().filter(|t| {
                repo.existing(std::slice::from_ref(t))
                    .is_ok_and(|e| !e.is_empty())
            });
            // A raw tree's blobs are the captured bytes, written as they are: no filter of the
            // user's runs. A capture from before it holds only the cleaned bytes, which its
            // smudge filters turn back into what was on disk.
            let smudge = git.raw_tree.is_none();
            let written = match from {
                Some(from) => {
                    let changed = gitpack::checkout_tree_changing(
                        &repo,
                        &from,
                        tree,
                        &self.targets.scratch_dir,
                        smudge,
                    )?;
                    report.git_paths_changed = Some(changed.len() as u64);
                    Some(changed)
                }
                None => {
                    gitpack::checkout_tree(&repo, tree, &self.targets.scratch_dir, smudge)?;
                    None
                }
            };
            // A raw tree holds the captured bytes: whatever git's attributes smudged or
            // converted on the way out is written back as it was captured.
            if git.raw_tree.is_some() {
                let rewritten = gitpack::restore_raw_bytes(&repo, tree, written.as_deref())?;
                if rewritten > 0 {
                    tracing::debug!(
                        rewritten,
                        "materialize: wrote captured bytes over git's conversion"
                    );
                }
            }
            for key in
                gitpack::untracked_against(&repo, tree, &self.targets.scratch_dir, &excludes)?
            {
                let rel = crate::tree::os_of_key(&key);
                // A path git cannot reach is the chunked class's to keep or sweep.
                if worktree_meta::beyond_git(rel.as_bytes(), false) {
                    continue;
                }
                let path = self.targets.root.join(&rel);
                if longpath::symlink_metadata(&path).is_ok_and(|m| !m.is_dir()) {
                    longpath::remove_file(&path).at("rm", &path)?;
                    tracing::debug!(path = %path.display(), "materialize: removed a file the worktree tree does not name");
                    report.removed += 1;
                }
            }
            state.worktree_tree = Some(tree.clone());
        }
        if let Some(tree) = git.index_tree_id()
            && state.index_tree.as_deref() != Some(tree)
        {
            // The workspace class overwrites this with the captured index bytes when it has them.
            gitpack::read_tree_into_index(&repo, tree)?;
            state.index_tree = Some(tree.to_owned());
        }
        if report.git_packs > 0 || report.git_paths_changed.is_none() {
            report.fsck = Some(repo.fsck()?);
        }
        Ok(())
    }

    /// Fetch into the cache every pack of `keys` it does not hold yet, [`PACK_GETS_IN_FLIGHT`]
    /// at a time; each is verified against its key before it is kept.
    fn fetch_packs(
        &self,
        keys: &[&String],
        report: &mut MaterializeReport,
    ) -> Result<(), MaterializeError> {
        let mut missing: Vec<(&str, &str)> = keys
            .iter()
            .filter_map(|key| key_digest(key).map(|sha| (key.as_str(), sha)))
            .filter(|(_, sha)| !self.targets.cache_dir.join(sha).exists())
            .collect();
        missing.sort_unstable();
        missing.dedup();
        if missing.is_empty() {
            return Ok(());
        }
        let next = std::sync::atomic::AtomicUsize::new(0);
        let failed: std::sync::Mutex<Option<MaterializeError>> = std::sync::Mutex::new(None);
        let fetched = std::sync::atomic::AtomicU64::new(0);
        std::thread::scope(|scope| {
            for _ in 0..PACK_GETS_IN_FLIGHT.min(missing.len()) {
                scope.spawn(|| {
                    loop {
                        let i = next.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                        let Some((key, sha)) = missing.get(i) else {
                            return;
                        };
                        if failed
                            .lock()
                            .unwrap_or_else(std::sync::PoisonError::into_inner)
                            .is_some()
                        {
                            return;
                        }
                        match self.fetch_pack(key, sha) {
                            Ok(()) => {
                                fetched.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                            }
                            Err(error) => {
                                failed
                                    .lock()
                                    .unwrap_or_else(std::sync::PoisonError::into_inner)
                                    .get_or_insert(error);
                                return;
                            }
                        }
                    }
                });
            }
        });
        report.packs_fetched += fetched.into_inner();
        match failed
            .into_inner()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
        {
            Some(error) => Err(error),
            None => Ok(()),
        }
    }

    /// GET one pack, verify it and move it into the cache under its digest.
    fn fetch_pack(&self, key: &str, sha: &str) -> Result<(), MaterializeError> {
        let bytes = self.sink.get(key)?;
        verify_key(key, &bytes)?;
        let tmp = self.targets.cache_dir.join(format!("{sha}.tmp"));
        fs::write(&tmp, &bytes).at("write", &tmp)?;
        let cached = self.targets.cache_dir.join(sha);
        fs::rename(&tmp, &cached).at("rename into", &cached)?;
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
                self.fetch_pack(key, sha)?;
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

    /// Where a section's dir objects come from: nothing to open in format 1, the (cached) dir
    /// packs in format 2.
    fn open_dirs(
        &self,
        section: &'static str,
        tree: TreeRef<'_>,
        report: &mut MaterializeReport,
    ) -> Result<Dirs, MaterializeError> {
        match tree.format {
            FORMAT_DIR_OBJECTS => Ok(Dirs::Objects),
            FORMAT_DIR_PACKS => Ok(Dirs::Packs(self.open_packs(tree.dir_packs, report)?)),
            format => Err(MaterializeError::UnsupportedFormat { section, format }),
        }
    }

    /// Read one dir object: by key in format 1, by digest from the dir packs in format 2
    /// (verified against the digest either way).
    fn read_dir(
        &self,
        dirs: &Dirs,
        reference: &str,
        report: &mut MaterializeReport,
    ) -> Result<DirObject, MaterializeError> {
        let bytes = match dirs {
            Dirs::Objects => {
                let bytes = self.sink.get(reference)?;
                verify_key(reference, &bytes)?;
                report.dir_objects_fetched += 1;
                bytes
            }
            Dirs::Packs(store) => {
                let id = ChunkId::parse(reference)
                    .ok_or_else(|| MaterializeError::MissingDir(reference.to_owned()))?;
                store.read(&id).map_err(|error| match error {
                    MaterializeError::MissingChunk(_) => {
                        MaterializeError::MissingDir(reference.to_owned())
                    }
                    other => other,
                })?
            }
        };
        DirObject::decode(&bytes).map_err(|e| MaterializeError::BadDir {
            key: reference.to_owned(),
            reason: e.to_string(),
        })
    }

    /// Whether the file at `path` is already what `entry` describes: a regular file whose stat
    /// matches the index entry for `v` (so its chunks are known) and whose size, mtime and
    /// chunks match the plan.
    fn file_matches(v: &str, entry: &DirEntry, path: &Path, index: &TreeIndex) -> bool {
        let Ok(meta) = longpath::symlink_metadata(path) else {
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

    #[allow(clippy::too_many_arguments)]
    fn write_dir(
        &self,
        store: &ChunkStore,
        dirs: &Dirs,
        key: &str,
        dir: &Path,
        vdir: &str,
        write: &mut ClassWrite<'_>,
        report: &mut MaterializeReport,
    ) -> Result<(), MaterializeError> {
        let obj = self.read_dir(dirs, key, report)?;
        if longpath::symlink_metadata(dir).is_ok_and(|m| !m.is_dir()) {
            remove_existing(dir).at("rm", dir)?;
        }
        longpath::create_dir_all(dir).at("mkdir -p", dir)?;
        if !vdir.is_empty() {
            write.planned.insert(vdir.to_owned());
        }
        for entry in &obj.entries {
            let path = dir.join(entry.os_name());
            let v = join_virtual(vdir, &entry.name);
            write.planned.insert(v.clone());
            if entry.kind != EntryKind::Dir && write.tracked.contains(&v) {
                continue;
            }
            match entry.kind {
                EntryKind::Dir => {
                    if let Some(child) = &entry.child {
                        self.write_dir(store, dirs, child, &path, &v, write, report)?;
                        write.dirs.push((path, entry.mode, entry.mtime));
                    }
                }
                EntryKind::File => {
                    write
                        .files
                        .push((v.clone(), path.clone(), Some((entry.mode, entry.mtime))));
                    if Self::file_matches(&v, entry, &path, write.index) {
                        report.files_skipped += 1;
                        report.bytes_skipped += entry.size;
                        if let Ok(meta) = longpath::symlink_metadata(&path)
                            && meta.mode() & 0o7777 != entry.mode
                        {
                            longpath::set_mode(&path, entry.mode).at("chmod", &path)?;
                        }
                        continue;
                    }
                    let tmp = dir.join(tmp_name(&entry.name));
                    {
                        let mut f = longpath::create(&tmp).at("create", &tmp)?;
                        for id in entry.chunks.iter().flatten() {
                            let data = store.read(id)?;
                            f.write_all(&data).at("write", &tmp)?;
                            report.bytes += data.len() as u64;
                        }
                        f.set_permissions(fs::Permissions::from_mode(entry.mode))
                            .at("chmod", &tmp)?;
                        set_mtime(&f, entry.mtime).at("set the mtime of", &tmp)?;
                    }
                    remove_existing(&path).at("rm", &path)?;
                    longpath::rename(&tmp, &path).at("rename into", &path)?;
                    report.files += 1;
                    let meta = longpath::symlink_metadata(&path).at("stat", &path)?;
                    write.index.files.insert(
                        v,
                        IndexedFile {
                            stat: FileStat::of(&meta),
                            chunks: entry.chunks.clone().unwrap_or_default(),
                        },
                    );
                }
                EntryKind::Symlink => {
                    let target = PathBuf::from(entry.os_target().unwrap_or_default());
                    if longpath::read_link(&path).is_ok_and(|t| t == target) {
                        if longpath::symlink_metadata(&path)
                            .is_ok_and(|m| index::mtime_ns(&m) != entry.mtime)
                        {
                            set_symlink_mtime(&path, entry.mtime)?;
                        }
                        continue;
                    }
                    remove_existing(&path).at("rm", &path)?;
                    longpath::symlink(&target, &path).at("symlink", &path)?;
                    set_symlink_mtime(&path, entry.mtime)?;
                    report.symlinks += 1;
                }
                EntryKind::HardlinkGroup => {
                    if let Some(canonical) = &entry.target {
                        write.files.push((v.clone(), path.clone(), None));
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
                return Err(MaterializeError::Metadata {
                    path: path.display().to_string(),
                    reason: format!(
                        "hardlink group canonical {canonical_v} is outside the class roots"
                    ),
                });
            };
            if let (Ok(a), Ok(b)) = (
                longpath::symlink_metadata(&canonical),
                longpath::symlink_metadata(path),
            ) && a.is_file()
                && b.is_file()
                && (a.dev(), a.ino()) == (b.dev(), b.ino())
            {
                continue;
            }
            remove_existing(path).at("rm", path)?;
            match longpath::hard_link(&canonical, path) {
                Ok(()) => {}
                // The class spans directories that can sit on different filesystems here (the
                // harness home beside the worktree): a copy is the closest thing.
                Err(e) if e.kind() == io::ErrorKind::CrossesDevices => {
                    tracing::warn!(canonical = %canonical.display(), member = %path.display(), "hardlink across filesystems; copied");
                    longpath::copy(&canonical, path).at("copy into", path)?;
                    longpath::set_mode(path, *mode).at("chmod", path)?;
                }
                Err(e) => {
                    return Err(MaterializeError::Metadata {
                        path: path.display().to_string(),
                        reason: format!("link to {}: {e}", canonical.display()),
                    });
                }
            }
            report.hardlinks += 1;
        }
        Ok(())
    }

    /// Remove what the class would capture but the plan does not name: files and symlinks
    /// first, then directories that emptied out (never a listing root in `keep`, never a
    /// virtual path in `protected`). The index ends up naming the plan's files and nothing
    /// else.
    fn sweep(
        listing: &Listing,
        planned: &BTreeSet<String>,
        keep: &[PathBuf],
        protected: &[&str],
        index: &mut TreeIndex,
        report: &mut MaterializeReport,
    ) -> Result<(), MaterializeError> {
        let mut stale: Vec<(&String, &index::Source)> = listing
            .entries
            .iter()
            .filter(|(v, _)| !planned.contains(v.as_str()) && !protected.contains(&v.as_str()))
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
                longpath::remove_dir(&src.abs).ok();
            } else {
                match longpath::remove_file(&src.abs) {
                    Ok(()) => {
                        tracing::debug!(path = %src.abs.display(), "materialize: removed a file the plan does not name");
                        report.removed += 1;
                    }
                    Err(e) if e.kind() == io::ErrorKind::NotFound => {}
                    Err(source) => {
                        return Err(MaterializeError::IoAt {
                            op: "rm",
                            path: src.abs.clone(),
                            source,
                        });
                    }
                }
                index.files.remove(v.as_str());
            }
        }
        index.files.retain(|v, _| planned.contains(v));
        Ok(())
    }

    /// Give `path` the mode and mtime its class restored it with, where they differ.
    fn restore_file_meta(path: &Path, mode: u32, mtime: i128) -> Result<(), MaterializeError> {
        let failed = |what: &str, e: io::Error| MaterializeError::Metadata {
            path: path.display().to_string(),
            reason: format!("{what}: {e}"),
        };
        let meta = longpath::symlink_metadata(path).map_err(|e| failed("stat", e))?;
        if meta.mode() & 0o7777 != mode {
            longpath::set_mode(path, mode).map_err(|e| failed("chmod", e))?;
        }
        if index::mtime_ns(&meta) != mtime {
            worktree_meta::set_mtime_nofollow(path, mtime).map_err(|e| failed("mtime", e))?;
        }
        Ok(())
    }

    /// Restore directory modes and mtimes once nothing writes into them any more. A failure
    /// fails the materialize: a directory left with the wrong mode or mtime is not restored.
    fn restore_dirs(dirs: &[(PathBuf, u32, i128)]) -> Result<(), MaterializeError> {
        for (path, mode, mtime) in dirs {
            let failed = |what: &str, e: io::Error| MaterializeError::Metadata {
                path: path.display().to_string(),
                reason: format!("{what}: {e}"),
            };
            longpath::set_mode(path, *mode).map_err(|e| failed("chmod", e))?;
            worktree_meta::set_mtime_nofollow(path, *mtime).map_err(|e| failed("mtime", e))?;
        }
        Ok(())
    }
}

/// Refuse a section format this build does not read.
fn check_format(section: &'static str, format: u32) -> Result<(), MaterializeError> {
    if format == 0 || format > MAX_SECTION_FORMAT {
        return Err(MaterializeError::UnsupportedFormat { section, format });
    }
    Ok(())
}

/// The staging name a file is written under before it is renamed into place: `.<name>.capture-tmp`
/// while that fits in a name (`NAME_MAX`, 255 bytes), else a digest of the name (a name near
/// the limit could not be restored at all).
fn tmp_name(name: &str) -> std::ffi::OsString {
    let bytes = crate::tree::bytes_of(name);
    if bytes.len() + ".capture-tmp".len() < 255 {
        let mut tmp = b".".to_vec();
        tmp.extend_from_slice(&bytes);
        tmp.extend_from_slice(b".capture-tmp");
        return OsStr::from_bytes(&tmp).to_owned();
    }
    format!(".capture-tmp-{}", &sha256_hex(&bytes)[..32]).into()
}

fn remove_existing(path: &Path) -> io::Result<()> {
    match longpath::symlink_metadata(path) {
        Ok(m) if m.is_dir() => longpath::remove_dir_all(path),
        Ok(_) => longpath::remove_file(path),
        Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(e) => Err(e),
    }
}

fn set_mtime(f: &File, mtime_ns: i128) -> io::Result<()> {
    let at = system_time_from_ns(mtime_ns).ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("{mtime_ns} ns since the epoch is past what a file's time holds"),
        )
    })?;
    f.set_times(fs::FileTimes::new().set_modified(at))
}

/// Nanoseconds since the epoch (a recorded time, wide or not) as a `SystemTime`; `None` past
/// what one holds (signed 64-bit seconds).
#[must_use]
pub fn system_time_from_ns(mtime_ns: i128) -> Option<SystemTime> {
    let secs = i64::try_from(mtime_ns.div_euclid(1_000_000_000)).ok()?;
    let nanos = u32::try_from(mtime_ns.rem_euclid(1_000_000_000)).ok()?;
    let whole = Duration::from_secs(secs.unsigned_abs());
    let at = if secs >= 0 {
        UNIX_EPOCH.checked_add(whole)?
    } else {
        UNIX_EPOCH.checked_sub(whole)?
    };
    at.checked_add(Duration::from_nanos(u64::from(nanos)))
}

/// The hardlink groups one class's restore made ([`Materializer::link_all`]'s `links`), for
/// [`worktree_meta::apply_over`]: each canonical name (its key: the class's index holds it) and
/// its members.
fn restored_groups(
    restored: &mut worktree_meta::RestoredGroups,
    class: LinkClass,
    links: &[(String, PathBuf, u32)],
    resolve: &dyn Fn(&str) -> Option<PathBuf>,
) {
    let mut groups: BTreeMap<&str, Vec<worktree_meta::RestoredName>> = BTreeMap::new();
    for (canonical_v, member, _) in links {
        let Some(canonical) = resolve(canonical_v) else {
            continue;
        };
        groups
            .entry(canonical_v.as_str())
            .or_insert_with(|| {
                vec![worktree_meta::RestoredName {
                    class,
                    key: Some(canonical_v.clone()),
                    abs: canonical,
                }]
            })
            .push(worktree_meta::RestoredName {
                class,
                key: None,
                abs: member.clone(),
            });
    }
    for (_, names) in groups {
        restored.add(names);
    }
}

/// Linking a member onto a canonical file, or sweeping one away, moves the canonical's ctime (its
/// link count changed), so the stat the write recorded no longer matches. Record it again once
/// links and sweep are done, or the next delta rewrites the canonical and relinks every member,
/// and the engine reads it again.
fn refresh_linked(
    index: &mut TreeIndex,
    links: &[(String, PathBuf, u32)],
    resolve: &dyn Fn(&str) -> Option<PathBuf>,
) {
    for (canonical_v, _, _) in links {
        if let Some(known) = index.files.get_mut(canonical_v)
            && let Some(path) = resolve(canonical_v)
            && let Ok(meta) = longpath::symlink_metadata(&path)
            && meta.is_file()
            && meta.len() == known.stat.size
            && crate::index::mtime_ns(&meta) == known.stat.mtime
            && meta.ino() == known.stat.ino
        {
            known.stat = FileStat::of(&meta);
        }
    }
}

fn set_symlink_mtime(path: &Path, mtime_ns: i128) -> Result<(), MaterializeError> {
    worktree_meta::set_mtime_nofollow(path, mtime_ns).map_err(|e| MaterializeError::Metadata {
        path: path.display().to_string(),
        reason: format!("symlink mtime: {e}"),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A directory whose metadata cannot be restored fails the materialize (it used to be
    /// ignored, leaving the directory with whatever mode and mtime the writes gave it).
    #[test]
    fn a_directory_metadata_failure_is_an_error() {
        let dir = tempfile::tempdir().unwrap();
        let there = dir.path().join("there");
        fs::create_dir(&there).unwrap();
        Materializer::restore_dirs(&[(there.clone(), 0o700, 1_600_000_000_123_456_789)]).unwrap();
        let meta = fs::metadata(&there).unwrap();
        assert_eq!(meta.mode() & 0o7777, 0o700);
        assert_eq!(index::mtime_ns(&meta), 1_600_000_000_123_456_789);
        let err = Materializer::restore_dirs(&[(dir.path().join("gone"), 0o755, 0)]).unwrap_err();
        assert!(matches!(err, MaterializeError::Metadata { .. }), "{err}");
    }
}
