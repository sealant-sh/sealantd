//! `CaptureEngine`: index the roots, snap, pack, write the manifest, stage.

use std::collections::{BTreeSet, HashMap, HashSet};
use std::fs;
use std::io;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, Instant};

use serde::{Deserialize, Serialize};

use crate::chunk::ChunkId;
use crate::gitpack::{self, GitError, GitRepo};
use crate::index::{
    self, BuildStats, ChunkSink, DAEMON_DIR, Listing, Suspects, TreeBuilder, TreeIndex,
    UnreadablePath, UnreadableWork,
};
use crate::keys::KeyPrefix;
use crate::manifest::{
    BulkSection, BulkState, CaptureKind, DirFormat, EncodedManifest, GitSection, Manifest,
    Sections, WORKTREE_TREE_REF, WorkspaceSection, rfc3339_now,
};
use crate::materialize::{
    DiskState, MaterializeClass, MaterializeError, MaterializeReport, MaterializeTargets,
    Materializer,
};
use crate::pack::{MAX_PACK_BYTES, PackBuilder, PackError};
use crate::registrar::RegisterRequest;
use crate::registrar::Registrar;
use crate::roots::ClassRoots;
use crate::ship::{
    DutyCycle, MultipartConfig, QueueEntry, Restage, ShipError, Shipper, Staging, Upload,
};
use crate::sink::BlobSink;
use crate::tree::EncodedDir;
use crate::watch::{Invalidations, WatchPolicy};

/// Snap cadence (ADR-0015 *Cadence and budgets*).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Cadence {
    /// Quiet period after a change before a small-class snap.
    pub quiet: Duration,
    /// Longest interval between small-class snaps while the tree stays dirty.
    pub max_interval: Duration,
    /// Quiet period after a bulk change before a bulk-class snap.
    pub bulk_quiet: Duration,
    /// Longest interval between bulk-class snaps while the bulk tree stays dirty (and the
    /// polling interval when bulk is not watched).
    pub bulk_max_interval: Duration,
    /// Lease heartbeat interval.
    pub heartbeat: Duration,
    /// Lease TTL: pause the agent once this elapses without a successful heartbeat.
    pub lease_ttl: Duration,
}

impl Default for Cadence {
    fn default() -> Self {
        Self {
            quiet: Duration::from_secs(2),
            max_interval: Duration::from_secs(10),
            bulk_quiet: Duration::from_secs(30),
            bulk_max_interval: Duration::from_secs(120),
            heartbeat: Duration::from_secs(10),
            lease_ttl: Duration::from_secs(30),
        }
    }
}

/// `<os>-<arch>-<libc>` of this build.
#[must_use]
pub fn default_platform() -> String {
    let libc = if cfg!(target_env = "musl") {
        "musl"
    } else {
        "gnu"
    };
    format!("{}-{}-{libc}", std::env::consts::OS, std::env::consts::ARCH)
}

/// Engine configuration.
#[derive(Debug, Clone)]
pub struct CaptureConfig {
    /// Worktree id (the key of the work product).
    pub worktree_id: String,
    /// Lease epoch this executor holds.
    pub epoch: u64,
    /// Worktree root.
    pub root: PathBuf,
    /// Harness home (transcripts, agent state); captured in the workspace class.
    pub harness_home: Option<PathBuf>,
    /// Staging directory; default `<root>/.sealantd/capture`.
    pub staging_dir: Option<PathBuf>,
    /// Directory names treated as bulk wherever they appear.
    pub bulk_dirs: Vec<String>,
    /// Whether bulk snaps are taken at all (open question 1).
    pub capture_bulk: bool,
    /// Cadence.
    pub cadence: Cadence,
    /// How the cadence learns about changes.
    pub watch: WatchPolicy,
    /// CPU budget for snapping and shipping, as a fraction of one core.
    pub cpu_fraction: f64,
    /// How the shipper uploads large objects.
    pub multipart: MultipartConfig,
    /// `<os>-<arch>-<libc>` stamped on bulk captures.
    pub platform: String,
    /// CDC pack cap (dir packs too).
    pub pack_cap: u64,
    /// How dir objects travel: in dir packs (format 2), or one object per directory for a
    /// registrar that does not read dir packs (its `plan.get` announces no `manifest_format`
    /// ≥ 2; [`DirFormat::for_registrar`]).
    pub dir_format: DirFormat,
    /// Single-PUT uploads in flight at once ([`crate::ship::DEFAULT_UPLOADS_IN_FLIGHT`]).
    pub uploads_in_flight: usize,
    /// A file read this close to its last change is read again by the next build rather than
    /// trusted by its stat ([`index::RACY_WINDOW`]; see `index` "When a file is re-read").
    pub racy_window: Duration,
}

impl CaptureConfig {
    /// Defaults for `root`.
    #[must_use]
    pub fn new(worktree_id: &str, epoch: u64, root: &Path) -> Self {
        Self {
            worktree_id: worktree_id.to_owned(),
            epoch,
            root: root.to_path_buf(),
            harness_home: None,
            staging_dir: None,
            bulk_dirs: index::DEFAULT_BULK_DIRS
                .iter()
                .map(|s| (*s).to_owned())
                .collect(),
            capture_bulk: true,
            cadence: Cadence::default(),
            watch: WatchPolicy::default(),
            cpu_fraction: crate::ship::DEFAULT_CPU_FRACTION,
            multipart: MultipartConfig::DEFAULT,
            platform: default_platform(),
            pack_cap: MAX_PACK_BYTES,
            dir_format: DirFormat::Packs,
            uploads_in_flight: crate::ship::DEFAULT_UPLOADS_IN_FLIGHT,
            racy_window: index::RACY_WINDOW,
        }
    }

    /// The staging directory in effect.
    #[must_use]
    pub fn staging_dir(&self) -> PathBuf {
        self.staging_dir
            .clone()
            .unwrap_or_else(|| self.root.join(DAEMON_DIR).join("capture"))
    }

    /// The key prefix.
    #[must_use]
    pub fn prefix(&self) -> KeyPrefix {
        KeyPrefix {
            worktree_id: self.worktree_id.clone(),
            epoch: self.epoch,
        }
    }
}

/// Which class to snap.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Class {
    /// Git pack, `.git` bookkeeping, harness home.
    Small,
    /// Dependencies and build outputs.
    Bulk,
}

/// Engine errors.
#[derive(Debug, thiserror::Error)]
pub enum EngineError {
    /// Git.
    #[error(transparent)]
    Git(#[from] GitError),
    /// Pack.
    #[error(transparent)]
    Pack(#[from] PackError),
    /// Shipping.
    #[error(transparent)]
    Ship(#[from] ShipError),
    /// Materialize.
    #[error(transparent)]
    Materialize(#[from] MaterializeError),
    /// I/O.
    #[error(transparent)]
    Io(#[from] io::Error),
    /// A final flush did not complete ([`crate::cadence::CadenceRunner::flush_final`]).
    #[error("final flush incomplete: {0}")]
    Incomplete(#[from] crate::cadence::Incomplete),
}

impl EngineError {
    /// The work a `final` snap could not read, when that is why it failed: the snap does not
    /// hold those paths, so the capture it would have made is not a complete one.
    #[must_use]
    pub fn unreadable(&self) -> Option<&UnreadableWork> {
        match self {
            Self::Io(e) => UnreadableWork::of(e),
            _ => None,
        }
    }
}

/// Numbers from one snap.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct SnapStats {
    /// Wall time in milliseconds.
    pub elapsed_ms: u64,
    /// Git pack bytes (0 when nothing was new).
    pub git_pack_bytes: u64,
    /// Objects in the git pack.
    pub git_objects: u32,
    /// pack-objects attempts.
    pub git_attempts: u32,
    /// New CDC packs (content chunks; dir packs are counted in `dir_packs`).
    pub cdc_packs: u64,
    /// Bytes of new CDC packs.
    pub cdc_pack_bytes: u64,
    /// Files listed in the chunked class.
    pub files: u64,
    /// Files read this snap.
    pub files_read: u64,
    /// Bytes read this snap.
    pub bytes_read: u64,
    /// Chunks referenced by the tree.
    pub chunks: u64,
    /// Chunks new this snap.
    pub chunks_new: u64,
    /// Dir objects new this snap (staged on their own, or written into a dir pack).
    pub dirs_new: u64,
    /// New dir packs.
    #[serde(default)]
    pub dir_packs: u64,
    /// Bytes of new dir packs.
    #[serde(default)]
    pub dir_pack_bytes: u64,
    /// Bytes staged for upload by this snap (all object files).
    pub staged_bytes: u64,
    /// Files marked torn.
    pub torn: u64,
    /// Paths this snap could not read (listed, stat'ed or opened; a directory counts once):
    /// never taken as deleted. See `index` "Reading honestly".
    #[serde(default)]
    pub unreadable: u64,
    /// Of `unreadable`, the paths whose last captured content this snap carried (marked
    /// `unread` in the chunked class, the previous worktree tree's entry in the git class).
    #[serde(default)]
    pub carried: u64,
    /// The first [`UNREADABLE_PATHS_CAP`] unreadable paths, in path order (`tree/…` under the
    /// worktree, `.git/…`, `harness/…`).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub unreadable_paths: Vec<String>,
}

/// At most this many unreadable paths are named in [`SnapStats`] and [`ReadReport`].
pub const UNREADABLE_PATHS_CAP: usize = 20;

/// What a class's last snap could not read ([`ReadReports`]).
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReadReport {
    /// Paths that could not be read.
    pub unreadable: u64,
    /// Of those, the ones whose last captured content was carried.
    pub carried: u64,
    /// The first [`UNREADABLE_PATHS_CAP`] of them, in path order.
    pub paths: Vec<String>,
}

impl ReadReport {
    fn of(paths: &[UnreadablePath]) -> Self {
        Self {
            unreadable: paths.len() as u64,
            carried: paths.iter().filter(|p| p.carried).count() as u64,
            paths: paths
                .iter()
                .take(UNREADABLE_PATHS_CAP)
                .map(|p| p.path.clone())
                .collect(),
        }
    }
}

/// The last snap's [`ReadReport`] per class, shared with whoever reports status (it never
/// waits on a build in progress).
#[derive(Debug, Default)]
pub struct ReadReports {
    small: std::sync::Mutex<ReadReport>,
    bulk: std::sync::Mutex<ReadReport>,
}

impl ReadReports {
    fn slot(&self, class: Class) -> std::sync::MutexGuard<'_, ReadReport> {
        match class {
            Class::Small => &self.small,
            Class::Bulk => &self.bulk,
        }
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    fn set(&self, class: Class, report: ReadReport) {
        *self.slot(class) = report;
    }

    /// Both classes' last snaps together.
    #[must_use]
    pub fn current(&self) -> ReadReport {
        let small = self.slot(Class::Small).clone();
        let bulk = self.slot(Class::Bulk).clone();
        let mut paths = small.paths;
        paths.extend(bulk.paths);
        paths.truncate(UNREADABLE_PATHS_CAP);
        ReadReport {
            unreadable: small.unreadable + bulk.unreadable,
            carried: small.carried + bulk.carried,
            paths,
        }
    }
}

/// `a` and `b` as one list in path order, a path in both once (carried if either carried it).
fn merge_unreadable(a: Vec<UnreadablePath>, b: Vec<UnreadablePath>) -> Vec<UnreadablePath> {
    let mut by_path: std::collections::BTreeMap<String, UnreadablePath> =
        std::collections::BTreeMap::new();
    for p in a.into_iter().chain(b) {
        by_path
            .entry(p.path.clone())
            .and_modify(|e| e.carried |= p.carried)
            .or_insert(p);
    }
    by_path.into_values().collect()
}

/// A staged capture: its manifest, key and queue entry.
#[derive(Debug, Clone)]
pub struct StagedCapture {
    /// Chain position.
    pub n: u64,
    /// The manifest.
    pub manifest: EncodedManifest,
    /// Manifest key.
    pub manifest_key: String,
    /// Kind.
    pub kind: CaptureKind,
    /// Class snapped.
    pub class: Class,
    /// Numbers.
    pub stats: SnapStats,
    /// Nothing changed since the previous capture: nothing was staged, and `n`, `manifest` and
    /// `manifest_key` name the previous capture.
    pub unchanged: bool,
}

/// A snap request.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SnapRequest {
    /// Kind.
    pub kind: CaptureKind,
    /// Class.
    pub class: Class,
    /// Execution sequence at snap start.
    pub seq: u64,
}

#[derive(Debug, Default, Serialize, Deserialize)]
struct ChunkMap {
    /// chunk → pack key.
    packs: HashMap<ChunkId, String>,
}

/// A section needs at most this many dir packs: past it, the snap writes every dir object of the
/// tree into fresh packs instead of adding one more. Each capture that changes a class adds a
/// small pack (the dir objects on the paths of what changed); a restore fetches every pack the
/// section lists, so without a bound the number of GETs would grow with the chain.
pub const MAX_DIR_PACKS: usize = 16;

/// Where this epoch's dir objects are (format 2), per class: dir object sha256 → dir pack key.
/// Kept per class so a small capture staged ahead of a bulk capture never names a dir pack only
/// that bulk capture uploads.
#[derive(Debug, Default, Serialize, Deserialize)]
struct DirMap {
    #[serde(default)]
    workspace: HashMap<String, String>,
    #[serde(default)]
    bulk: HashMap<String, String>,
}

impl DirMap {
    fn class(&mut self, class: Class) -> &mut HashMap<String, String> {
        match class {
            Class::Small => &mut self.workspace,
            Class::Bulk => &mut self.bulk,
        }
    }

    fn retain(&mut self, keep: impl Fn(&String) -> bool) {
        self.workspace.retain(|_, k| keep(k));
        self.bulk.retain(|_, k| keep(k));
    }
}

/// What a boot does with the disk it finds ([`CaptureEngine::pickup`]).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Pickup {
    /// Nothing on this disk continues the chain: materialize the head.
    Materialize,
    /// The disk is this executor's own, at or past the head: leave it as it is, open the
    /// engine on the head (it continues from the captures still queued) and snap both classes.
    Resume {
        /// Captures staged under this worktree and not shipped.
        queued: usize,
        /// They were staged under another epoch (the lease lapsed while the daemon was down):
        /// they cannot register and are dropped; the next snaps capture the disk afresh.
        epoch_changed: bool,
    },
}

/// The capture this staging directory staged last (`index/last.json`), for [`Pickup`].
#[derive(Debug, Clone, Serialize, Deserialize)]
struct LastStaged {
    worktree_id: String,
    epoch: u64,
    n: u64,
    capture_id: String,
}

impl LastStaged {
    fn load(index_dir: &Path) -> Option<Self> {
        fs::read(index_dir.join("last.json"))
            .ok()
            .and_then(|b| serde_json::from_slice(&b).ok())
    }

    fn save(&self, index_dir: &Path) -> io::Result<()> {
        let tmp = index_dir.join("last.tmp");
        fs::write(&tmp, serde_json::to_vec(self)?)?;
        fs::rename(tmp, index_dir.join("last.json"))
    }
}

/// A built chunked class: what its section names.
struct BuiltClass {
    root: String,
    packs: Vec<String>,
    format: u32,
    dir_packs: Vec<String>,
}

/// Chunk sink over a pack builder plus the known-chunk map (and, for a resumed bulk build, the
/// packs a yielded attempt already wrote).
struct PackSink<'a> {
    builder: PackBuilder,
    known: &'a HashMap<ChunkId, String>,
    carried: &'a HashMap<ChunkId, String>,
    cycle: DutyCycle,
    preempt: Option<&'a (dyn Fn() -> bool + 'a)>,
}

impl ChunkSink for PackSink<'_> {
    fn contains(&self, id: &ChunkId) -> bool {
        self.known.contains_key(id) || self.carried.contains_key(id) || self.builder.contains(id)
    }

    fn put(&mut self, id: ChunkId, data: &[u8]) -> io::Result<()> {
        self.builder.add(id, data).map_err(io::Error::other)?;
        self.cycle.pace();
        Ok(())
    }

    fn should_yield(&self) -> bool {
        self.preempt.is_some_and(|p| p())
    }
}

/// A class build's working set: the index it updates and the packs it finished. For a bulk
/// build this outlives yields (`bulk_work`), holding the packs the yielded attempts wrote. Nothing here is persisted until the capture is staged, so a crash
/// mid-build leaves only unreferenced pack files in staging, never a chunk map pointing at a
/// pack that was not shipped.
#[derive(Debug, Default)]
struct ClassWork {
    index: TreeIndex,
    packs: Vec<Upload>,
    chunks: HashMap<ChunkId, String>,
    /// Paths the watcher reported written that this build has not read yet.
    suspects: Suspects,
}

/// The outcome of a preemptible snap.
#[derive(Debug, Clone)]
pub enum SnapOutcome {
    /// Staged (or unchanged).
    Staged(Box<StagedCapture>),
    /// A bulk build stopped at a chunk boundary because `preempt` asked; call again to resume.
    Preempted,
}

/// The engine.
pub struct CaptureEngine {
    config: CaptureConfig,
    prefix: KeyPrefix,
    staging: Arc<Staging>,
    previous: Option<EncodedManifest>,
    workspace_index: TreeIndex,
    bulk_index: TreeIndex,
    bulk_work: Option<ClassWork>,
    chunks: ChunkMap,
    /// Format 2: where this epoch's dir objects are.
    dirs: DirMap,
    /// Every tip the last git pack covered (refs, reflog entries, index and worktree trees):
    /// the negatives of the next pack. The manifest only carries refs, so reflog-only history
    /// would otherwise be packed again on every snap.
    last_tips: Vec<String>,
    /// The manifest the queued bulk capture was staged on (its parent). A small snap while that
    /// bulk capture's objects upload is staged ahead of it: it takes the bulk capture's place on
    /// the chain with this manifest's bulk section, and the bulk capture moves on top of it. See
    /// [`CaptureEngine::snap_preemptible`].
    below: Option<EncodedManifest>,
    /// Paths the watcher saw written, per class, not yet read again.
    invalidations: Arc<Invalidations>,
    /// What each class's last snap could not read.
    reads: Arc<ReadReports>,
}

impl std::fmt::Debug for CaptureEngine {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CaptureEngine")
            .field("prefix", &self.prefix)
            .field("previous_n", &self.previous.as_ref().map(|p| p.manifest.n))
            .finish_non_exhaustive()
    }
}

fn is_pack_file(name: &str) -> bool {
    let stem = name.strip_suffix(".idx").unwrap_or(name);
    stem.len() == 64 && stem.bytes().all(|b| b.is_ascii_hexdigit())
}

fn is_tree_file(name: &str) -> bool {
    name.strip_prefix("tree-").is_some_and(is_pack_file)
}

/// Worktree-relative paths the git section never indexes: the daemon directory and the staging
/// directory when it lies elsewhere under the root.
fn daemon_excludes(config: &CaptureConfig) -> Vec<String> {
    let mut excludes = vec![DAEMON_DIR.to_owned()];
    if let Ok(rel) = config.staging_dir().strip_prefix(&config.root) {
        let rel = rel.to_string_lossy().trim_matches('/').to_owned();
        if !rel.is_empty()
            && !excludes
                .iter()
                .any(|e| rel == *e || rel.starts_with(&format!("{e}/")))
        {
            excludes.push(rel);
        }
    }
    excludes
}

impl CaptureEngine {
    /// Open the engine. `previous` is the chain head this executor continues from (the plan's
    /// head after materialize), or `None` for an empty chain.
    pub fn open(
        config: CaptureConfig,
        previous: Option<EncodedManifest>,
    ) -> Result<Self, EngineError> {
        let staging = Arc::new(Staging::open(
            &config.staging_dir(),
            &config.worktree_id,
            config.epoch,
        )?);
        // Staging sits inside the worktree: keep it out of the user's index (an agent's or a
        // checkpoint's `git add -A`) through the repository's local excludes, never the user's
        // `.gitignore`. A root that is not a repository yet gets the entry when materialized.
        if let Ok(repo) = GitRepo::open(&config.root) {
            for e in daemon_excludes(&config) {
                if let Err(error) = repo.exclude_locally(&format!("/{e}/")) {
                    tracing::warn!(%error, exclude = %e, "could not add the local git exclude");
                }
            }
        }
        let index_dir = staging.index_dir();
        let workspace_index = TreeIndex::load(&index_dir.join("workspace.json"));
        let bulk_index = TreeIndex::load(&index_dir.join("bulk.json"));
        let chunks: ChunkMap = fs::read(index_dir.join("chunks.json"))
            .ok()
            .and_then(|b| serde_json::from_slice(&b).ok())
            .unwrap_or_default();
        let mut dirs: DirMap = fs::read(index_dir.join("dirs.json"))
            .ok()
            .and_then(|b| serde_json::from_slice(&b).ok())
            .unwrap_or_default();
        let mut last_tips: Vec<String> = fs::read(index_dir.join("git-tips.json"))
            .ok()
            .and_then(|b| serde_json::from_slice(&b).ok())
            .unwrap_or_default();
        // The tips of captures staged under another identity (the lease moved to a new epoch
        // while the daemon was down) are not the chain's: those captures never register, and
        // negatives taken from them would leave their objects out of every later pack.
        if LastStaged::load(&index_dir)
            .is_some_and(|l| l.worktree_id != config.worktree_id || l.epoch != config.epoch)
        {
            last_tips.clear();
        }
        let prefix = config.prefix();
        // Chunk locations from another epoch are never reused (ADR-0015: a new epoch never skips
        // an upload because a prior epoch holds the bytes).
        let base = format!("{}/", prefix.base());
        let chunks = ChunkMap {
            packs: chunks
                .packs
                .into_iter()
                .filter(|(_, k)| k.starts_with(&base))
                .collect(),
        };
        dirs.retain(|k| k.starts_with(&base));
        let mut engine = Self {
            config,
            prefix,
            staging,
            previous,
            workspace_index,
            bulk_index,
            bulk_work: None,
            chunks,
            dirs,
            last_tips,
            below: None,
            invalidations: Arc::new(Invalidations::default()),
            reads: Arc::new(ReadReports::default()),
        };
        // Captures staged under another identity (a lease that moved to a new epoch while the
        // daemon was down) can never register; left queued, a snap would coalesce with one and
        // take its parent. The disk they were taken from is still here and is snapped again.
        let dropped = engine.staging.discard_foreign()?;
        if dropped > 0 {
            tracing::warn!(
                dropped,
                "captures staged under another epoch dropped; the disk is captured again"
            );
        }
        engine.resume_queue()?;
        Ok(engine)
    }

    /// Whether this disk continues the chain at `head` on its own: its staging names this
    /// worktree, and the capture it staged last is the head or descends from it through the
    /// captures still queued. Then the disk is at least as new as the head — it holds every
    /// staged capture and whatever changed after the last snap — and materializing the head
    /// over it would take that work back. Boot asks this before it materializes (a daemon that
    /// restarts on its own disk); a fresh disk, a standby's placeholder staging or a chain that
    /// moved on without this disk answers [`Pickup::Materialize`].
    pub fn pickup(config: &CaptureConfig, head_capture_id: Option<&str>) -> io::Result<Pickup> {
        let staging_dir = config.staging_dir();
        let index_dir = staging_dir.join("index");
        let Some(last) = LastStaged::load(&index_dir) else {
            return Ok(Pickup::Materialize);
        };
        if last.worktree_id != config.worktree_id {
            return Ok(Pickup::Materialize);
        }
        let staging = Staging::open(&staging_dir, &last.worktree_id, last.epoch)?;
        let queued: Vec<QueueEntry> = staging
            .pending()?
            .into_iter()
            .filter(|e| e.register.worktree_id == config.worktree_id)
            .collect();
        let continues = head_capture_id == Some(last.capture_id.as_str())
            || queued.iter().any(|e| {
                e.register.parent.as_deref() == head_capture_id
                    || Some(e.capture_id.as_str()) == head_capture_id
            });
        if !continues {
            return Ok(Pickup::Materialize);
        }
        Ok(Pickup::Resume {
            queued: queued.len(),
            epoch_changed: last.epoch != config.epoch,
        })
    }

    /// Continue from the captures this identity staged and has not shipped (a daemon restarted
    /// on its own disk): when the queue descends from `previous`, the newest queued capture is
    /// the one the next snap names as its parent, and a queued bulk capture can again have a
    /// small one staged ahead of it.
    fn resume_queue(&mut self) -> Result<(), EngineError> {
        let queued: Vec<QueueEntry> = self
            .staging
            .pending()?
            .into_iter()
            .filter(|e| !self.staging.is_foreign(e))
            .collect();
        let Some(newest) = queued.last() else {
            return Ok(());
        };
        let from = self.previous.as_ref().map(|p| p.capture_id.as_str());
        let descends = queued
            .iter()
            .any(|e| e.register.parent.as_deref() == from || Some(e.capture_id.as_str()) == from);
        if !descends {
            return Ok(());
        }
        let encoded = |e: &QueueEntry| {
            let m = e.register.manifest.clone().encode();
            (m.capture_id == e.capture_id).then_some(m)
        };
        let Some(manifest) = encoded(newest) else {
            tracing::warn!(
                n = newest.n,
                "queued manifest does not re-encode to its id; not resumed"
            );
            return Ok(());
        };
        if newest.class == Some(Class::Bulk) {
            let parent = newest.register.parent.as_deref();
            self.below = queued
                .iter()
                .find(|e| Some(e.capture_id.as_str()) == parent)
                .and_then(encoded)
                .or_else(|| {
                    self.previous
                        .clone()
                        .filter(|p| Some(p.capture_id.as_str()) == parent)
                });
        }
        tracing::info!(
            queued = queued.len(),
            n = manifest.manifest.n,
            "capture queue resumed from staging"
        );
        self.previous = Some(manifest);
        Ok(())
    }

    /// After materializing `previous` into the root: record the tips the repository got from
    /// the chain (refs, `HEAD`, reflog entries — [`gitpack::stored_tips`]) as already stored,
    /// so the next pack ships only what is new. The index and worktree trees are not among
    /// them: they are written afresh at every snap and exist only locally until a pack carries
    /// them, so anything the disk differs by from the head (the harness wrote a file between
    /// materialize and this call, a tracked file the head lacked) ships with the next pack.
    /// Call once at pickup; never on a root whose objects did not come from the chain.
    pub fn seed_tips_from_repo(&mut self) -> Result<(), EngineError> {
        let repo = GitRepo::open(&self.config.root)?;
        self.last_tips = gitpack::stored_tips(&repo)?;
        self.persist()?;
        Ok(())
    }

    fn daemon_excludes(&self) -> Vec<String> {
        daemon_excludes(&self.config)
    }

    /// Continue from `previous` as `worktree_id` at `epoch` (a re-plan: the control plane
    /// assigned this executor its worktree, or moved its epoch). Staging follows, entries
    /// staged under the old identity are dropped, chunk locations under the old prefix are
    /// forgotten (a new epoch never skips an upload because a prior one holds the bytes), a
    /// bulk build in progress is abandoned, and the repository's stored tips are re-read as
    /// the negatives of the next pack. Call after the plan's head is on disk.
    pub fn rebase(
        &mut self,
        worktree_id: &str,
        epoch: u64,
        previous: Option<EncodedManifest>,
    ) -> Result<(), EngineError> {
        self.config.worktree_id = worktree_id.to_owned();
        self.config.epoch = epoch;
        self.prefix = self.config.prefix();
        self.staging.set_identity(worktree_id, epoch)?;
        let dropped = self.staging.discard_foreign()?;
        let base = format!("{}/", self.prefix.base());
        self.chunks.packs.retain(|_, k| k.starts_with(&base));
        self.dirs.retain(|k| k.starts_with(&base));
        self.bulk_work = None;
        let seeded = previous.is_some();
        self.previous = previous;
        if seeded {
            self.seed_tips_from_repo()?;
        } else {
            self.last_tips.clear();
            self.persist()?;
        }
        self.below = None;
        tracing::info!(
            worktree = worktree_id,
            epoch,
            dropped,
            "capture engine rebased"
        );
        Ok(())
    }

    /// The materialize targets for this engine's root, staging and roots policy.
    #[must_use]
    pub fn materialize_targets(&self) -> MaterializeTargets {
        let mut targets =
            MaterializeTargets::new(&self.config.root, self.config.harness_home.clone());
        targets.cache_dir = self.staging.cache_dir();
        targets.scratch_dir = self.staging.scratch_dir();
        targets.index_dir = self.staging.index_dir();
        targets.staging_dir = self.config.staging_dir();
        targets.bulk_dirs = self.config.bulk_dirs.clone();
        targets
    }

    /// Bring this engine's root to `manifest` from `sink`, writing only the delta against what
    /// the engine's own indexes say is on disk, and keep the indexes the materializer updated.
    pub fn materialize_delta(
        &mut self,
        sink: &dyn BlobSink,
        manifest: &Manifest,
        class: MaterializeClass,
    ) -> Result<MaterializeReport, EngineError> {
        let targets = self.materialize_targets();
        let mut state = DiskState::load(&targets.index_dir);
        state.workspace = std::mem::take(&mut self.workspace_index);
        state.bulk = std::mem::take(&mut self.bulk_index);
        let result = Materializer::new(sink, targets.clone())
            .materialize_with_state(manifest, class, &mut state);
        let saved = state.save(&targets.index_dir);
        self.workspace_index = state.workspace;
        self.bulk_index = state.bulk;
        let report = result?;
        saved?;
        Ok(report)
    }

    /// Write dir objects as `format` from the next snap on (a re-plan names a registrar that
    /// reads dir packs, or one that does not). The two formats never share a dir object — a
    /// format-2 dir object names its children by digest, a format-1 one by key — so nothing
    /// staged in the other format is reused or disturbed.
    pub fn set_dir_format(&mut self, format: DirFormat) {
        self.config.dir_format = format;
    }

    /// Configuration.
    #[must_use]
    pub fn config(&self) -> &CaptureConfig {
        &self.config
    }

    /// Where the watcher notes written paths for this engine's builds
    /// (`watch::WatchSpec::invalidations`).
    #[must_use]
    pub fn invalidations(&self) -> Arc<Invalidations> {
        Arc::clone(&self.invalidations)
    }

    /// What each class's last snap could not read (`capture.status` reports it).
    #[must_use]
    pub fn read_reports(&self) -> Arc<ReadReports> {
        Arc::clone(&self.reads)
    }

    /// Staging area (shared with the shipper).
    #[must_use]
    pub fn staging(&self) -> Arc<Staging> {
        Arc::clone(&self.staging)
    }

    /// The last staged (or seeded) manifest.
    #[must_use]
    pub fn previous(&self) -> Option<&EncodedManifest> {
        self.previous.as_ref()
    }

    /// A shipper for this engine's staging.
    #[must_use]
    pub fn shipper(&self, sink: Arc<dyn BlobSink>, registrar: Arc<dyn Registrar>) -> Shipper {
        Shipper::new(self.staging(), sink, registrar)
            .with_cpu_fraction(self.config.cpu_fraction)
            .with_multipart(self.config.multipart)
            .with_uploads_in_flight(self.config.uploads_in_flight)
    }

    fn persist(&self) -> io::Result<()> {
        let dir = self.staging.index_dir();
        if let Some(previous) = &self.previous {
            LastStaged {
                worktree_id: self.config.worktree_id.clone(),
                epoch: self.config.epoch,
                n: previous.manifest.n,
                capture_id: previous.capture_id.clone(),
            }
            .save(&dir)?;
        }
        self.workspace_index.save(&dir.join("workspace.json"))?;
        self.bulk_index.save(&dir.join("bulk.json"))?;
        let tmp = dir.join("chunks.tmp");
        fs::write(&tmp, serde_json::to_vec(&self.chunks)?)?;
        fs::rename(tmp, dir.join("chunks.json"))?;
        let tmp = dir.join("dirs.tmp");
        fs::write(&tmp, serde_json::to_vec(&self.dirs)?)?;
        fs::rename(tmp, dir.join("dirs.json"))?;
        let tmp = dir.join("git-tips.tmp");
        fs::write(&tmp, serde_json::to_vec(&self.last_tips)?)?;
        fs::rename(tmp, dir.join("git-tips.json"))
    }

    /// The class roots this engine captures (and a materializer sweeps).
    #[must_use]
    pub fn roots(&self) -> ClassRoots {
        ClassRoots {
            root: self.config.root.clone(),
            harness_home: self.config.harness_home.clone(),
            bulk_dirs: self.config.bulk_dirs.clone(),
            staging_dir: self.config.staging_dir(),
        }
    }

    /// The workspace class listing: `.git/` bookkeeping, `tree/` (ignored files and nested
    /// repositories), `harness/`.
    fn workspace_listing(
        &self,
        repo: &GitRepo,
        gitlinks: &[String],
    ) -> Result<Listing, EngineError> {
        Ok(self.roots().workspace_listing(repo, gitlinks)?)
    }

    /// The bulk class listing: every bulk directory under the root.
    fn bulk_listing(&self) -> Listing {
        self.roots().bulk_listing()
    }

    /// Build a chunked class into new packs; returns what its section names (the root, the
    /// packs the tree needs, and in format 2 its dir packs), or `None` when a bulk build yielded
    /// to `preempt` (its progress is kept in `bulk_work`; the next bulk build resumes it). A
    /// `strict` build (a `final` snap) fails with [`UnreadableWork`] when anything it should
    /// hold cannot be read; any other build carries such a path's last read content forward.
    /// `also_unreadable` is what the git class could not read (the small class), reported and
    /// failed on with the class's own.
    #[allow(clippy::too_many_arguments)]
    fn build_class(
        &mut self,
        listing: &Listing,
        class: Class,
        uploads: &mut Vec<Upload>,
        stats: &mut SnapStats,
        preempt: &dyn Fn() -> bool,
        strict: bool,
        also_unreadable: Vec<UnreadablePath>,
    ) -> Result<Option<BuiltClass>, EngineError> {
        let objects = self.staging.objects_dir();
        let prefix = self.prefix.clone();
        let dir_format = self.config.dir_format;
        // Format 1 names a child dir object by its key, format 2 by its digest.
        let key_for_dir = move |sha: &str| match dir_format {
            DirFormat::Objects => prefix.tree(sha),
            DirFormat::Packs => sha.to_owned(),
        };
        let mut work = match class {
            Class::Small => ClassWork {
                index: std::mem::take(&mut self.workspace_index),
                ..ClassWork::default()
            },
            Class::Bulk => self.bulk_work.take().unwrap_or_else(|| ClassWork {
                index: self.bulk_index.clone(),
                ..ClassWork::default()
            }),
        };
        work.suspects.extend(self.invalidations.take(class));
        let mut sink = PackSink {
            builder: PackBuilder::new(&objects, self.config.pack_cap),
            known: &self.chunks.packs,
            carried: &work.chunks,
            cycle: DutyCycle::new(self.config.cpu_fraction),
            preempt: (class == Class::Bulk).then_some(preempt),
        };
        let built = TreeBuilder::new(&mut work.index, &key_for_dir)
            .strict(strict)
            .racy_window(self.config.racy_window)
            .suspects(&mut work.suspects)
            .build(listing, &mut sink);
        let (mut built, packs) = match built {
            Ok(built) => (built, sink.builder.finish()),
            Err(e) => {
                // What was not read yet stays suspect for the next build.
                self.invalidations
                    .restore(class, std::mem::take(&mut work.suspects));
                if class == Class::Small {
                    self.workspace_index = work.index;
                }
                if let Some(work) = UnreadableWork::of(&e) {
                    let own = work
                        .paths
                        .iter()
                        .map(|(path, error)| UnreadablePath {
                            path: path.clone(),
                            error: error.clone(),
                            carried: false,
                        })
                        .collect();
                    return Err(self.fail_unreadable(class, merge_unreadable(own, also_unreadable)));
                }
                return Err(e.into());
            }
        };
        if let Some(built) = &mut built {
            built.unreadable =
                merge_unreadable(std::mem::take(&mut built.unreadable), also_unreadable);
            if strict && !built.unreadable.is_empty() {
                // The chunked class read everything; the git class did not.
                self.invalidations
                    .restore(class, std::mem::take(&mut work.suspects));
                if class == Class::Small {
                    self.workspace_index = work.index;
                }
                return Err(self.fail_unreadable(class, std::mem::take(&mut built.unreadable)));
            }
        }
        let packs = match packs {
            Ok(packs) => packs,
            Err(e) => {
                if class == Class::Small {
                    self.workspace_index = work.index;
                }
                return Err(e.into());
            }
        };
        for p in &packs {
            let key = self.prefix.pack(&p.sha256);
            for e in &p.entries {
                work.chunks.insert(e.hash, key.clone());
            }
            work.packs.push(Upload {
                key,
                file: p.sha256.clone(),
                bytes: p.bytes,
            });
            stats.cdc_packs += 1;
            stats.cdc_pack_bytes += p.bytes;
        }
        let Some(built) = built else {
            if class == Class::Small {
                // Never asked to yield; keep the index whole if it ever does.
                self.workspace_index = work.index;
                return Err(io::Error::other("small-class build yielded").into());
            }
            // Yielded: keep the progress for the next attempt; nothing is committed.
            self.bulk_work = Some(work);
            return Ok(None);
        };
        // Commit: the index, the chunk map and the pack uploads. A suspect the build did not
        // read is not in this class's listing (removed, or another class's path).
        work.suspects.clear();
        match class {
            Class::Small => self.workspace_index = work.index,
            Class::Bulk => self.bulk_index = work.index,
        }
        self.chunks.packs.extend(work.chunks);
        uploads.extend(work.packs);
        let mut needed: BTreeSet<String> = BTreeSet::new();
        for c in &built.chunks {
            if let Some(k) = self.chunks.packs.get(c) {
                needed.insert(k.clone());
            } else {
                tracing::error!(chunk = %c, "chunk referenced by tree but in no pack");
            }
        }
        let (root, dir_packs) = match dir_format {
            DirFormat::Objects => {
                for (sha, dir) in &built.dirs {
                    let file = format!("tree-{sha}");
                    let path = objects.join(&file);
                    if !path.exists() && !self.staging.is_uploaded(&file) {
                        fs::write(&path, &dir.bytes)?;
                        stats.dirs_new += 1;
                    }
                    if !self.staging.is_uploaded(&file) {
                        uploads.push(Upload {
                            key: self.prefix.tree(sha),
                            file,
                            bytes: dir.bytes.len() as u64,
                        });
                    }
                }
                (self.prefix.tree(&built.root.sha256), Vec::new())
            }
            DirFormat::Packs => (
                built.root.sha256.clone(),
                self.pack_dirs(class, &built.dirs, uploads, stats)?,
            ),
        };
        let BuildStats {
            files,
            files_read,
            bytes_read,
            chunks,
            chunks_new,
            torn,
            ..
        } = built.stats;
        stats.files += files;
        stats.files_read += files_read;
        stats.bytes_read += bytes_read;
        stats.chunks += chunks;
        stats.chunks_new += chunks_new;
        stats.torn += torn;
        let report = ReadReport::of(&built.unreadable);
        stats.unreadable += report.unreadable;
        stats.carried += report.carried;
        stats.unreadable_paths.extend(report.paths.iter().cloned());
        stats.unreadable_paths.truncate(UNREADABLE_PATHS_CAP);
        self.reads.set(class, report);
        Ok(Some(BuiltClass {
            root,
            packs: needed.into_iter().collect(),
            format: dir_format.section_format(),
            dir_packs,
        }))
    }

    /// A strict snap that could not read `paths`: recorded for status, returned as the error.
    fn fail_unreadable(&self, class: Class, paths: Vec<UnreadablePath>) -> EngineError {
        self.reads.set(class, ReadReport::of(&paths));
        EngineError::Io(
            UnreadableWork {
                paths: paths.into_iter().map(|p| (p.path, p.error)).collect(),
            }
            .into_io(),
        )
    }

    /// Format 2: the dir packs a tree of `dirs` needs. A dir object this epoch already packed
    /// for the class is found where it is; the rest go into new dir packs, staged in `uploads`.
    /// A tree that would need more than [`MAX_DIR_PACKS`] packs is packed whole instead, so a
    /// section never lists more than that and a restore stays a handful of GETs. Dir objects are
    /// packed in digest order, so a tree packs to the same bytes whatever order it was built in.
    fn pack_dirs(
        &mut self,
        class: Class,
        dirs: &HashMap<String, EncodedDir>,
        uploads: &mut Vec<Upload>,
        stats: &mut SnapStats,
    ) -> Result<Vec<String>, EngineError> {
        let known = self.dirs.class(class);
        let mut needed: BTreeSet<String> = BTreeSet::new();
        let mut fresh: Vec<&String> = Vec::new();
        for sha in dirs.keys() {
            match known.get(sha) {
                Some(key) => {
                    needed.insert(key.clone());
                }
                None => fresh.push(sha),
            }
        }
        let whole = needed.len() + usize::from(!fresh.is_empty()) > MAX_DIR_PACKS;
        let mut to_pack: Vec<&String> = if whole {
            needed.clear();
            dirs.keys().collect()
        } else {
            fresh
        };
        if to_pack.is_empty() {
            return Ok(needed.into_iter().collect());
        }
        to_pack.sort();
        let mut builder = PackBuilder::new(&self.staging.objects_dir(), self.config.pack_cap);
        for sha in &to_pack {
            let id = ChunkId::parse(sha)
                .ok_or_else(|| io::Error::other(format!("dir object digest {sha} is not hex")))?;
            builder.add(id, &dirs[*sha].bytes)?;
        }
        let known = self.dirs.class(class);
        for p in builder.finish()? {
            let key = self.prefix.pack(&p.sha256);
            for e in &p.entries {
                known.insert(e.hash.to_hex(), key.clone());
            }
            stats.dirs_new += p.entries.len() as u64;
            stats.dir_packs += 1;
            stats.dir_pack_bytes += p.bytes;
            uploads.push(Upload {
                key: key.clone(),
                file: p.sha256.clone(),
                bytes: p.bytes,
            });
            needed.insert(key);
        }
        if whole {
            tracing::debug!(
                ?class,
                dirs = to_pack.len(),
                packs = needed.len(),
                "dir packs compacted: the tree is packed whole"
            );
        }
        Ok(needed.into_iter().collect())
    }

    /// Take a snap and stage it.
    pub fn snap(&mut self, req: SnapRequest) -> Result<StagedCapture, EngineError> {
        match self.snap_preemptible(req, &|| false)? {
            SnapOutcome::Staged(staged) => Ok(*staged),
            SnapOutcome::Preempted => {
                Err(io::Error::other("snap preempted without a preempt hook").into())
            }
        }
    }

    /// Whether a bulk build is paused mid-way (it yielded to a small-class snap).
    #[must_use]
    pub fn bulk_in_progress(&self) -> bool {
        self.bulk_work.is_some()
    }

    /// The queued bulk capture a small snap is staged ahead of, with the manifest it was staged
    /// on: the newest queued capture, when it is a bulk one the shipper is not registering, is
    /// the capture this engine staged last, and names the manifest kept as `below` as its
    /// parent. Call under the staging's coalesce guard.
    fn hoist_target(&self) -> Result<Option<(QueueEntry, EncodedManifest)>, EngineError> {
        let Some(below) = &self.below else {
            return Ok(None);
        };
        let Some(bulk) = self.staging.hoistable()? else {
            return Ok(None);
        };
        let staged_last =
            self.previous.as_ref().map(|p| p.capture_id.as_str()) == Some(bulk.capture_id.as_str());
        let on_below = bulk.register.parent.as_deref() == Some(below.capture_id.as_str());
        Ok((staged_last && on_below).then(|| (bulk, below.clone())))
    }

    /// After `journal` was applied: the bulk capture it wrote is the newest capture, and the
    /// small capture staged ahead of it is the one a later small snap takes its place with.
    fn follow_restage(&mut self, journal: &Restage) {
        let encoded = |e: &QueueEntry| {
            let m = e.register.manifest.clone().encode();
            (m.capture_id == e.capture_id).then_some(m)
        };
        let bulk = journal
            .write
            .iter()
            .find(|e| e.class == Some(Class::Bulk))
            .and_then(encoded);
        let small = journal
            .write
            .iter()
            .find(|e| e.class != Some(Class::Bulk))
            .and_then(encoded);
        if let (Some(bulk), Some(small)) = (bulk, small) {
            self.previous = Some(bulk);
            self.below = Some(small);
        }
    }

    /// `bulk` staged again on top of `small` (a capture taking its place): the same objects, a
    /// new manifest at `small.n + 1` whose parent is `small` and whose git and workspace sections
    /// are `small`'s. Writes the manifest file and returns the queue entry and the manifest; the
    /// caller queues the entry before `small`, so the bulk capture is never missing from the
    /// queue, and sweeps the old manifest once `small` is queued.
    fn restage_bulk(
        &self,
        bulk: &QueueEntry,
        small: &EncodedManifest,
    ) -> Result<(QueueEntry, EncodedManifest), EngineError> {
        let old = &bulk.register.manifest;
        let n = small.manifest.n + 1;
        let manifest = Manifest {
            worktree_id: old.worktree_id.clone(),
            n,
            parent: Some(small.capture_id.clone()),
            epoch: old.epoch,
            seq: old.seq,
            kind: old.kind,
            created_at: old.created_at.clone(),
            sections: Sections {
                git: small.manifest.sections.git.clone(),
                workspace: small.manifest.sections.workspace.clone(),
                bulk: old.sections.bulk.clone(),
                other_bulk: old.sections.other_bulk.clone(),
            },
            checkpoint: None,
        }
        .encode();
        let manifest_key = self.prefix.manifest(&manifest.capture_id);
        let manifest_file = format!("manifest-{}", manifest.capture_id);
        fs::write(
            self.staging.objects_dir().join(&manifest_file),
            &manifest.bytes,
        )?;
        let mut uploads: Vec<Upload> = bulk
            .uploads
            .iter()
            .filter(|u| u.key != bulk.register.manifest_key)
            .cloned()
            .collect();
        uploads.push(Upload {
            key: manifest_key.clone(),
            file: manifest_file,
            bytes: manifest.bytes.len() as u64,
        });
        let entry = QueueEntry {
            n,
            capture_id: manifest.capture_id.clone(),
            kind: bulk.kind,
            class: Some(Class::Bulk),
            uploads,
            register: RegisterRequest {
                worktree_id: bulk.register.worktree_id.clone(),
                epoch: bulk.register.epoch,
                n,
                parent: manifest.manifest.parent.clone(),
                capture_id: manifest.capture_id.clone(),
                manifest_key,
                manifest: manifest.manifest.clone(),
            },
        };
        Ok((entry, manifest))
    }

    /// Take a snap and stage it; a bulk build stops at the next chunk boundary whenever
    /// `preempt` returns `true` and reports [`SnapOutcome::Preempted`], keeping what it read so
    /// far for the next call. Small-class snaps are never preempted.
    pub fn snap_preemptible(
        &mut self,
        req: SnapRequest,
        preempt: &dyn Fn() -> bool,
    ) -> Result<SnapOutcome, EngineError> {
        // A restage this process did not finish (an I/O error after its journal was committed)
        // is finished before this snap takes a chain position.
        {
            let staging = Arc::clone(&self.staging);
            let _guard = staging.coalesce_guard();
            if let Some(journal) = staging.recover()? {
                self.follow_restage(&journal);
            }
        }
        if req.class == Class::Bulk && self.previous.is_none() {
            // A bulk capture copies the small sections from its predecessor; make one first.
            self.snap(SnapRequest {
                class: Class::Small,
                ..req
            })?;
        }
        let start = Instant::now();
        let mut stats = SnapStats::default();
        let mut uploads: Vec<Upload> = Vec::new();
        let objects = self.staging.objects_dir();

        let mut sections = match req.class {
            Class::Small => {
                let repo = GitRepo::open(&self.config.root)?;
                let mut previous_tips = self
                    .previous
                    .as_ref()
                    .map(|p| p.manifest.git_tips())
                    .unwrap_or_default();
                previous_tips.extend(self.last_tips.iter().cloned());
                previous_tips.sort();
                previous_tips.dedup();
                let excludes = self.daemon_excludes();
                // An automatic snap gives what the worktree cannot read the previous capture's
                // entry; a final one carries nothing and fails on it instead.
                let strict = req.kind == CaptureKind::Final;
                let carry_from = self
                    .previous
                    .as_ref()
                    .and_then(|p| p.manifest.sections.git.refs.get(WORKTREE_TREE_REF).cloned())
                    .filter(|_| !strict);
                let git = gitpack::build_git_pack_carrying(
                    &repo,
                    &objects,
                    &previous_tips,
                    &excludes,
                    carry_from.as_deref(),
                )?;
                let git_unreadable: Vec<UnreadablePath> = git
                    .closure
                    .unreadable
                    .iter()
                    .map(|(path, error)| UnreadablePath {
                        path: format!("tree/{}", index::rel_key(Path::new(path))),
                        error: error.clone(),
                        carried: git.closure.carried.contains(path),
                    })
                    .collect();
                stats.git_attempts = git.attempts;
                let mut git_packs: Vec<String> = self
                    .previous
                    .as_ref()
                    .map(|p| p.manifest.sections.git.packs.clone())
                    .unwrap_or_default();
                if let Some(p) = &git.pack {
                    stats.git_pack_bytes = p.bytes;
                    stats.git_objects = p.objects;
                    let key = self.prefix.pack(&p.sha256);
                    uploads.push(Upload {
                        key: key.clone(),
                        file: p.sha256.clone(),
                        bytes: p.bytes,
                    });
                    // The index's length is declared like every other object's, so an I/O
                    // error here fails the snap instead of sizing the upload zero.
                    uploads.push(Upload {
                        key: self.prefix.pack_idx(&p.sha256),
                        file: format!("{}.idx", p.sha256),
                        bytes: fs::metadata(&p.idx_path)?.len(),
                    });
                    git_packs.push(key);
                }
                let listing = self.workspace_listing(&repo, &git.closure.gitlinks)?;
                let Some(built) = self.build_class(
                    &listing,
                    Class::Small,
                    &mut uploads,
                    &mut stats,
                    preempt,
                    strict,
                    git_unreadable,
                )?
                else {
                    return Err(io::Error::other("small-class build yielded").into());
                };
                // Only a snap that goes on to stage its git pack makes that pack's tips the next
                // pack's negatives: a snap that fails here (a final one that cannot read work)
                // stages nothing, and its tips would leave objects out of every later pack.
                self.last_tips = git.closure.tips.clone();
                Sections {
                    git: GitSection {
                        packs: git_packs,
                        refs: git.closure.refs,
                        head: git.closure.head,
                        fsck: git.fsck,
                    },
                    workspace: WorkspaceSection {
                        root: built.root,
                        packs: built.packs,
                        format: built.format,
                        dir_packs: built.dir_packs,
                    },
                    bulk: self
                        .previous
                        .as_ref()
                        .map_or(BulkState::pending(), |p| p.manifest.sections.bulk.clone()),
                    // Other platforms' bulk sections ride along, never dropped.
                    other_bulk: self
                        .previous
                        .as_ref()
                        .map(|p| p.manifest.sections.other_bulk.clone())
                        .unwrap_or_default(),
                }
            }
            Class::Bulk => {
                let listing = self.bulk_listing();
                let Some(built) = self.build_class(
                    &listing,
                    Class::Bulk,
                    &mut uploads,
                    &mut stats,
                    preempt,
                    req.kind == CaptureKind::Final,
                    Vec::new(),
                )?
                else {
                    tracing::debug!(
                        files_read = stats.files_read,
                        cdc_packs = stats.cdc_packs,
                        "bulk build yielded to a small-class snap"
                    );
                    return Ok(SnapOutcome::Preempted);
                };
                let prev = self
                    .previous
                    .as_ref()
                    .map(|p| p.manifest.sections.clone())
                    .ok_or_else(|| io::Error::other("bulk snap without a previous capture"))?;
                let bulk = BulkState::Ready(BulkSection {
                    root: built.root,
                    packs: built.packs,
                    platform: self.config.platform.clone(),
                    format: built.format,
                    dir_packs: built.dir_packs,
                });
                // A bulk section the chain holds for another platform (a head continued from
                // an executor elsewhere) is kept beside this one, so it stays restorable there.
                let other_bulk = Sections::other_bulk_after(&prev, &bulk);
                Sections {
                    git: prev.git,
                    workspace: prev.workspace,
                    bulk,
                    other_bulk,
                }
            }
        };

        // Chain position, decided under the coalesce guard: the shipper cannot claim a capture
        // meanwhile, so what is queued stays what this snap sees.
        let staging = Arc::clone(&self.staging);
        let coalesce_guard = staging.coalesce_guard();
        // A small capture never waits for a bulk capture's upload (hundreds of MB for a
        // dependency tree). While the newest queued capture is a bulk one the shipper is not
        // registering, this capture takes its place on the chain, with the bulk section of the
        // manifest the bulk capture was staged on, and the bulk capture moves on top of it.
        // Before this, every small capture staged after a bulk one named it as its parent and
        // waited for its whole upload (observed: 800 MB of `node_modules` held the chain at
        // the capture before the agent's edits for 20 minutes).
        let hoist = match req.class {
            Class::Small => self.hoist_target()?,
            Class::Bulk => None,
        };
        if let Some((_, below)) = &hoist {
            sections.bulk = below.manifest.sections.bulk.clone();
            sections.other_bulk = below.manifest.sections.other_bulk.clone();
        }
        let follows = match &hoist {
            Some((_, below)) => Some(below),
            None => self.previous.as_ref(),
        };

        // Nothing changed: an `auto` snap stages nothing rather than growing the chain, and nor
        // does a final flush's bulk snap (its small snap is the capture that marks the end), or
        // a final snap over a final capture (the same final flush asked again).
        if (req.kind == CaptureKind::Auto
            || (req.kind == CaptureKind::Final
                && (req.class == Class::Bulk
                    || follows.is_some_and(|p| p.manifest.kind == CaptureKind::Final))))
            && let Some(prev) = follows
            && prev.manifest.sections == sections
        {
            // Only the objects no queued capture lists go: a dir object this build listed
            // again because it is not uploaded yet is, as often as not, staged by an entry the
            // shipper has not reached (a bulk capture ahead of it in the queue takes minutes),
            // and removing its bytes from under that entry stalls shipping for good (observed:
            // `upload …/trees/<sha>: no GET url in plan` on every pass). A pack that is not
            // staged must not be the location of any chunk either (a torn read can leave
            // chunks the final tree does not reference in a pack no capture lists).
            let removed = self.staging.discard_unreferenced(&uploads)?;
            let dropped: HashSet<&String> = uploads
                .iter()
                .filter(|u| removed.contains(&u.file))
                .map(|u| &u.key)
                .collect();
            self.chunks.packs.retain(|_, k| !dropped.contains(k));
            self.dirs.retain(|k| !dropped.contains(k));
            stats.elapsed_ms = start.elapsed().as_millis() as u64;
            return Ok(SnapOutcome::Staged(Box::new(StagedCapture {
                n: prev.manifest.n,
                manifest: prev.clone(),
                manifest_key: self.prefix.manifest(&prev.capture_id),
                kind: req.kind,
                class: req.class,
                stats,
                unchanged: true,
            })));
        }

        // Coalesce with a pending, not-yet-shipping `auto` capture of the same class: a small
        // snap never folds into a bulk capture (it would wait for that upload), nor a bulk
        // snap into a small one. The guard keeps the shipper from claiming that capture until
        // its replacement is in the queue.
        let coalesce = if req.kind == CaptureKind::Auto {
            match &hoist {
                Some((bulk, _)) => self.staging.coalescible_below(bulk)?,
                None => self
                    .staging
                    .coalescible()?
                    .filter(|e| (e.class == Some(Class::Bulk)) == (req.class == Class::Bulk)),
            }
        } else {
            None
        };
        let (n, parent) = match (&coalesce, &hoist) {
            (Some(old), _) => (old.n, old.register.parent.clone()),
            (None, Some((bulk, _))) => (bulk.n, bulk.register.parent.clone()),
            (None, None) => (
                self.previous.as_ref().map_or(0, |p| p.manifest.n + 1),
                self.previous.as_ref().map(|p| p.capture_id.clone()),
            ),
        };
        let manifest = Manifest {
            worktree_id: self.config.worktree_id.clone(),
            n,
            parent: parent.clone(),
            epoch: self.config.epoch,
            seq: req.seq,
            kind: req.kind,
            created_at: rfc3339_now(),
            sections,
            checkpoint: None,
        }
        .encode();
        let manifest_key = self.prefix.manifest(&manifest.capture_id);
        let manifest_file = format!("manifest-{}", manifest.capture_id);
        fs::write(objects.join(&manifest_file), &manifest.bytes)?;
        let mut all_uploads: Vec<Upload> = Vec::new();
        if let Some(old) = &coalesce {
            // Keep the packs the coalesced capture staged (the new manifest may list them).
            // Its dir objects are superseded only when this snap rebuilt the same class: the
            // build lists every dir object of the new tree that is not uploaded yet, shared
            // ones included. Across classes the old class's sections are copied into the new
            // manifest as they are, dir objects and all, so those ride along too; only the old
            // manifest is superseded either way.
            let rebuilt = old.class == Some(req.class);
            all_uploads.extend(
                old.uploads
                    .iter()
                    .filter(|u| is_pack_file(&u.file) || (!rebuilt && is_tree_file(&u.file)))
                    .cloned(),
            );
        }
        for u in uploads {
            if !all_uploads.iter().any(|e| e.file == u.file) {
                all_uploads.push(u);
            }
        }
        all_uploads.push(Upload {
            key: manifest_key.clone(),
            file: manifest_file,
            bytes: manifest.bytes.len() as u64,
        });
        stats.staged_bytes = all_uploads.iter().map(|u| u.bytes).sum();
        let entry = QueueEntry {
            n,
            capture_id: manifest.capture_id.clone(),
            kind: req.kind,
            class: Some(req.class),
            uploads: all_uploads,
            register: RegisterRequest {
                worktree_id: self.config.worktree_id.clone(),
                epoch: self.config.epoch,
                n,
                parent,
                capture_id: manifest.capture_id.clone(),
                manifest_key: manifest_key.clone(),
                manifest: manifest.manifest.clone(),
            },
        };
        if req.class == Class::Bulk {
            match &coalesce {
                // Staged on the newest capture: that is the manifest a small snap takes this
                // bulk capture's place with.
                None => {
                    self.below = self.previous.clone();
                }
                // It replaces a queued bulk capture and keeps that one's parent.
                Some(old) => {
                    if self.below.as_ref().map(|b| &b.capture_id) != old.register.parent.as_ref() {
                        self.below = None;
                    }
                }
            }
        }
        let newest = match &hoist {
            Some((bulk, _)) => {
                // The bulk capture first (at `n + 1`, over its own queue file when this capture
                // coalesced the one below it), then this capture in its place, then the bulk
                // capture's old manifest goes — as one journaled step, so a crash between the
                // two queue writes never leaves the bulk capture naming a parent no entry holds.
                let (moved, moved_manifest) = self.restage_bulk(bulk, &manifest)?;
                let mut superseded = vec![bulk.clone()];
                superseded.extend(coalesce.iter().cloned());
                if let Err(error) = self
                    .staging
                    .restage(&[moved.clone(), entry.clone()], &superseded)
                {
                    // Committed (the journal is on disk): finish it now, or the next snap
                    // does. Not committed: the queue is as it was.
                    if self.staging.restage_pending() {
                        tracing::warn!(%error, "restage interrupted; finishing it from its journal");
                        self.staging.recover()?;
                    } else {
                        return Err(error.into());
                    }
                }
                self.below = Some(manifest.clone());
                tracing::info!(
                    n,
                    bulk_n = moved.n,
                    kind = ?req.kind,
                    "capture staged ahead of the bulk capture still uploading"
                );
                moved_manifest
            }
            None => {
                match &coalesce {
                    Some(old) => self.staging.replace(old, &entry)?,
                    None => self.staging.enqueue(&entry)?,
                }
                manifest.clone()
            }
        };
        drop(coalesce_guard);
        self.previous = Some(newest);
        self.persist()?;
        stats.elapsed_ms = start.elapsed().as_millis() as u64;
        tracing::info!(
            n,
            kind = ?req.kind,
            class = ?req.class,
            elapsed_ms = stats.elapsed_ms,
            staged_bytes = stats.staged_bytes,
            files_read = stats.files_read,
            chunks_new = stats.chunks_new,
            "capture staged"
        );
        Ok(SnapOutcome::Staged(Box::new(StagedCapture {
            n,
            manifest,
            manifest_key,
            kind: req.kind,
            class: req.class,
            stats,
            unchanged: false,
        })))
    }

    /// Final small-class snap, then ship everything pending, bounded by `deadline`.
    pub fn flush(
        &mut self,
        shipper: &Shipper,
        kind: CaptureKind,
        seq: u64,
        deadline: Duration,
    ) -> Result<usize, EngineError> {
        self.snap(SnapRequest {
            kind,
            class: Class::Small,
            seq,
        })?;
        Ok(shipper.flush(deadline)?)
    }

    /// Materialize `manifest` from `sink` into this engine's root (and harness home), against
    /// the disk state on disk rather than this engine's indexes (see [`Self::materialize_delta`]).
    pub fn materialize(
        &self,
        sink: &dyn BlobSink,
        manifest: &Manifest,
        class: MaterializeClass,
    ) -> Result<MaterializeReport, EngineError> {
        Ok(Materializer::new(sink, self.materialize_targets()).materialize(manifest, class)?)
    }
}
