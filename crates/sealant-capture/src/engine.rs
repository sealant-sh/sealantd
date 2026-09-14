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
use crate::index::{self, BuildStats, ChunkSink, DAEMON_DIR, Listing, TreeBuilder, TreeIndex};
use crate::keys::KeyPrefix;
use crate::manifest::{
    BulkSection, BulkState, CaptureKind, EncodedManifest, GitSection, Manifest, Sections,
    WorkspaceSection, rfc3339_now,
};
use crate::materialize::{
    DiskState, MaterializeClass, MaterializeError, MaterializeReport, MaterializeTargets,
    Materializer,
};
use crate::pack::{MAX_PACK_BYTES, PackBuilder, PackError};
use crate::registrar::RegisterRequest;
use crate::registrar::Registrar;
use crate::roots::ClassRoots;
use crate::ship::{DutyCycle, MultipartConfig, QueueEntry, ShipError, Shipper, Staging, Upload};
use crate::sink::BlobSink;
use crate::watch::WatchPolicy;

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
    /// CDC pack cap.
    pub pack_cap: u64,
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
    /// New CDC packs.
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
    /// Dir objects new this snap.
    pub dirs_new: u64,
    /// Bytes staged for upload by this snap (all object files).
    pub staged_bytes: u64,
    /// Files marked torn.
    pub torn: u64,
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
    /// Every tip the last git pack covered (refs, reflog entries, index and worktree trees):
    /// the negatives of the next pack. The manifest only carries refs, so reflog-only history
    /// would otherwise be packed again on every snap.
    last_tips: Vec<String>,
    /// The manifest the oldest queued capture names as its parent — the chain head as far as
    /// this executor knows — and the tips as of that capture. A capture the registrar refuses
    /// for good is dropped with everything staged after it, and the chain continues from here.
    base: Option<EncodedManifest>,
    base_tips: Vec<String>,
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
        let last_tips: Vec<String> = fs::read(index_dir.join("git-tips.json"))
            .ok()
            .and_then(|b| serde_json::from_slice(&b).ok())
            .unwrap_or_default();
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
        Ok(Self {
            config,
            prefix,
            staging,
            base: previous.clone(),
            base_tips: last_tips.clone(),
            previous,
            workspace_index,
            bulk_index,
            bulk_work: None,
            chunks,
            last_tips,
        })
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
        self.bulk_work = None;
        let seeded = previous.is_some();
        self.previous = previous;
        if seeded {
            self.seed_tips_from_repo()?;
        } else {
            self.last_tips.clear();
            self.persist()?;
        }
        let _ = self.staging.take_refusals();
        self.base = self.previous.clone();
        self.base_tips = self.last_tips.clone();
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

    /// Configuration.
    #[must_use]
    pub fn config(&self) -> &CaptureConfig {
        &self.config
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
    }

    fn persist(&self) -> io::Result<()> {
        let dir = self.staging.index_dir();
        self.workspace_index.save(&dir.join("workspace.json"))?;
        self.bulk_index.save(&dir.join("bulk.json"))?;
        let tmp = dir.join("chunks.tmp");
        fs::write(&tmp, serde_json::to_vec(&self.chunks)?)?;
        fs::rename(tmp, dir.join("chunks.json"))?;
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

    /// Build a chunked class into new packs; returns the root key and the pack keys the tree
    /// needs, or `None` when a bulk build yielded to `preempt` (its progress is kept in
    /// `bulk_work`; the next bulk build resumes it).
    fn build_class(
        &mut self,
        listing: &Listing,
        class: Class,
        uploads: &mut Vec<Upload>,
        stats: &mut SnapStats,
        preempt: &dyn Fn() -> bool,
    ) -> Result<Option<(String, Vec<String>)>, EngineError> {
        let objects = self.staging.objects_dir();
        let prefix = self.prefix.clone();
        let key_for_dir = move |sha: &str| prefix.tree(sha);
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
        let mut sink = PackSink {
            builder: PackBuilder::new(&objects, self.config.pack_cap),
            known: &self.chunks.packs,
            carried: &work.chunks,
            cycle: DutyCycle::new(self.config.cpu_fraction),
            preempt: (class == Class::Bulk).then_some(preempt),
        };
        let built = TreeBuilder::new(&mut work.index, &key_for_dir).build(listing, &mut sink);
        let (built, packs) = match built {
            Ok(built) => (built, sink.builder.finish()),
            Err(e) => {
                if class == Class::Small {
                    self.workspace_index = work.index;
                }
                return Err(e.into());
            }
        };
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
        // Commit: the index, the chunk map and the pack uploads.
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
        Ok(Some((
            self.prefix.tree(&built.root.sha256),
            needed.into_iter().collect(),
        )))
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

    /// Apply what the shipper dropped as refused (the registrar answered `byte-quota`): continue
    /// the chain from the refused capture's parent, and forget everything that pointed at its
    /// staged objects — the chunk locations of packs that never went up, and the indexed files
    /// that reference those chunks, which would otherwise be listed in the next tree and packed
    /// into nothing. Called at the head of every snap.
    fn apply_refusals(&mut self) -> Result<(), EngineError> {
        let refusals = self.staging.take_refusals();
        if refusals.is_empty() {
            return Ok(());
        }
        for refusal in &refusals {
            // The refused capture was the oldest queued one, so its parent is the chain head
            // this executor knows: `base`, kept from the snap that emptied the queue.
            let base_is_parent =
                self.base.as_ref().map(|b| b.capture_id.as_str()) == refusal.parent.as_deref();
            if !base_is_parent {
                tracing::warn!(
                    n = refusal.n,
                    parent = ?refusal.parent,
                    base = ?self.base.as_ref().map(|b| b.manifest.n),
                    "refused capture's parent is not the chain head this executor kept; the next \
                     capture may find a wrong parent until a re-plan"
                );
            } else if self
                .previous
                .as_ref()
                .is_some_and(|p| p.manifest.n >= refusal.n)
            {
                self.previous = self.base.clone();
                self.last_tips = self.base_tips.clone();
            }
            let gone: HashSet<&String> = refusal
                .uploads
                .iter()
                .filter(|u| !self.staging.is_uploaded(&u.file))
                .map(|u| &u.key)
                .collect();
            let orphaned: HashSet<ChunkId> = self
                .chunks
                .packs
                .iter()
                .filter(|(_, key)| gone.contains(key))
                .map(|(chunk, _)| *chunk)
                .collect();
            self.chunks.packs.retain(|_, key| !gone.contains(key));
            for index in [&mut self.workspace_index, &mut self.bulk_index] {
                index
                    .files
                    .retain(|_, f| !f.chunks.iter().any(|c| orphaned.contains(c)));
            }
            tracing::warn!(
                n = refusal.n,
                capture = %refusal.capture_id,
                class = ?refusal.class,
                reason = %refusal.reason,
                limit = ?refusal.limit,
                used = ?refusal.used,
                requested = ?refusal.requested,
                continuing_from = ?self.previous.as_ref().map(|p| p.manifest.n),
                "refused capture dropped; chain continues from its parent"
            );
        }
        self.bulk_work = None;
        self.persist()?;
        Ok(())
    }

    /// Take a snap and stage it; a bulk build stops at the next chunk boundary whenever
    /// `preempt` returns `true` and reports [`SnapOutcome::Preempted`], keeping what it read so
    /// far for the next call. Small-class snaps are never preempted.
    pub fn snap_preemptible(
        &mut self,
        req: SnapRequest,
        preempt: &dyn Fn() -> bool,
    ) -> Result<SnapOutcome, EngineError> {
        self.apply_refusals()?;
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
        // The tips as of `previous`, before this snap's pack moves them on.
        let tips_before = self.last_tips.clone();

        let sections = match req.class {
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
                let git = gitpack::build_git_pack(&repo, &objects, &previous_tips, &excludes)?;
                self.last_tips = git.closure.tips.clone();
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
                    uploads.push(Upload {
                        key: self.prefix.pack_idx(&p.sha256),
                        file: format!("{}.idx", p.sha256),
                        bytes: fs::metadata(&p.idx_path).map(|m| m.len()).unwrap_or(0),
                    });
                    git_packs.push(key);
                }
                let listing = self.workspace_listing(&repo, &git.closure.gitlinks)?;
                let Some((root, packs)) =
                    self.build_class(&listing, Class::Small, &mut uploads, &mut stats, preempt)?
                else {
                    return Err(io::Error::other("small-class build yielded").into());
                };
                Sections {
                    git: GitSection {
                        packs: git_packs,
                        refs: git.closure.refs,
                        head: git.closure.head,
                        fsck: git.fsck,
                    },
                    workspace: WorkspaceSection { root, packs },
                    bulk: self
                        .previous
                        .as_ref()
                        .map_or(BulkState::pending(), |p| p.manifest.sections.bulk.clone()),
                }
            }
            Class::Bulk => {
                let listing = self.bulk_listing();
                let Some((root, packs)) =
                    self.build_class(&listing, Class::Bulk, &mut uploads, &mut stats, preempt)?
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
                Sections {
                    git: prev.git,
                    workspace: prev.workspace,
                    bulk: BulkState::Ready(BulkSection {
                        root,
                        packs,
                        platform: self.config.platform.clone(),
                    }),
                }
            }
        };

        // Nothing changed: an `auto` snap stages nothing rather than growing the chain.
        if req.kind == CaptureKind::Auto
            && let Some(prev) = &self.previous
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

        // Chain position: coalesce with a pending, not-yet-shipping auto capture. The guard keeps
        // the shipper from claiming that capture until its replacement is in the queue.
        let staging = Arc::clone(&self.staging);
        let coalesce_guard = staging.coalesce_guard();
        // Nothing queued: this capture becomes the oldest queued one, so its parent is the
        // chain head a refusal would send the engine back to.
        if self.staging.pending()?.is_empty() {
            self.base = self.previous.clone();
            self.base_tips = tips_before;
        }
        let coalesce = if req.kind == CaptureKind::Auto {
            self.staging.coalescible()?
        } else {
            None
        };
        let (n, parent) = match &coalesce {
            Some(old) => (old.n, old.register.parent.clone()),
            None => (
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
        match &coalesce {
            Some(old) => self.staging.replace(old, &entry)?,
            None => self.staging.enqueue(&entry)?,
        }
        drop(coalesce_guard);
        self.previous = Some(manifest.clone());
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
