//! `CaptureEngine`: index the roots, snap, pack, write the manifest, stage.

use std::collections::{BTreeSet, HashMap};
use std::fs;
use std::io;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, Instant};

use serde::{Deserialize, Serialize};

use crate::chunk::ChunkId;
use crate::gitpack::{self, GitError, GitRepo};
use crate::index::{
    self, BuildStats, ChunkSink, DAEMON_DIR, Listing, TreeBuilder, TreeIndex, has_component_in,
};
use crate::keys::KeyPrefix;
use crate::manifest::{
    BulkSection, BulkState, CaptureKind, EncodedManifest, GitSection, Manifest, Sections,
    WorkspaceSection, rfc3339_now,
};
use crate::materialize::{
    MaterializeClass, MaterializeError, MaterializeReport, MaterializeTargets, Materializer,
};
use crate::pack::{MAX_PACK_BYTES, PackBuilder, PackError};
use crate::registrar::RegisterRequest;
use crate::registrar::Registrar;
use crate::ship::{DutyCycle, QueueEntry, ShipError, Shipper, Staging, Upload};
use crate::sink::BlobSink;

/// Snap cadence (ADR-0015 *Cadence and budgets*).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Cadence {
    /// Quiet period after a change before a small-class snap.
    pub quiet: Duration,
    /// Longest interval between small-class snaps while the tree stays dirty.
    pub max_interval: Duration,
    /// Bulk-class interval.
    pub bulk_interval: Duration,
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
            bulk_interval: Duration::from_secs(120),
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
    /// CPU budget for snapping and shipping, as a fraction of one core.
    pub cpu_fraction: f64,
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
            cpu_fraction: crate::ship::DEFAULT_CPU_FRACTION,
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

/// Chunk sink over a pack builder plus the known-chunk map.
struct PackSink<'a> {
    builder: PackBuilder,
    known: &'a HashMap<ChunkId, String>,
    cycle: DutyCycle,
}

impl ChunkSink for PackSink<'_> {
    fn contains(&self, id: &ChunkId) -> bool {
        self.known.contains_key(id) || self.builder.contains(id)
    }

    fn put(&mut self, id: ChunkId, data: &[u8]) -> io::Result<()> {
        self.builder.add(id, data).map_err(io::Error::other)?;
        self.cycle.pace();
        Ok(())
    }
}

/// The engine.
pub struct CaptureEngine {
    config: CaptureConfig,
    prefix: KeyPrefix,
    staging: Arc<Staging>,
    previous: Option<EncodedManifest>,
    workspace_index: TreeIndex,
    bulk_index: TreeIndex,
    chunks: ChunkMap,
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

impl CaptureEngine {
    /// Open the engine. `previous` is the chain head this executor continues from (the plan's
    /// head after materialize), or `None` for an empty chain.
    pub fn open(
        config: CaptureConfig,
        previous: Option<EncodedManifest>,
    ) -> Result<Self, EngineError> {
        let staging = Arc::new(Staging::open(&config.staging_dir())?);
        let index_dir = staging.index_dir();
        let workspace_index = TreeIndex::load(&index_dir.join("workspace.json"));
        let bulk_index = TreeIndex::load(&index_dir.join("bulk.json"));
        let chunks: ChunkMap = fs::read(index_dir.join("chunks.json"))
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
            previous,
            workspace_index,
            bulk_index,
            chunks,
        })
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
        Shipper::new(self.staging(), sink, registrar).with_cpu_fraction(self.config.cpu_fraction)
    }

    fn persist(&self) -> io::Result<()> {
        let dir = self.staging.index_dir();
        self.workspace_index.save(&dir.join("workspace.json"))?;
        self.bulk_index.save(&dir.join("bulk.json"))?;
        let tmp = dir.join("chunks.tmp");
        fs::write(&tmp, serde_json::to_vec(&self.chunks)?)?;
        fs::rename(tmp, dir.join("chunks.json"))
    }

    fn is_daemon_path(&self, abs: &Path) -> bool {
        abs == self.config.staging_dir()
            || abs == self.config.root.join(DAEMON_DIR)
            || self.config.harness_home.as_deref() == Some(abs)
    }

    /// The workspace class listing: `.git/` bookkeeping, `tree/` (ignored files and nested
    /// repositories), `harness/`.
    fn workspace_listing(
        &self,
        repo: &GitRepo,
        gitlinks: &[String],
    ) -> Result<Listing, EngineError> {
        let mut listing = Listing::default();
        let git_prune = |_: &Path, v: &str, _: &str| {
            v == ".git/objects" || v == ".git/worktrees" || v == ".git/lfs"
        };
        let git_include = |_: &Path, v: &str, _: &str| {
            !(v == ".git/HEAD"
                || v == ".git/packed-refs"
                || v == ".git/commondir"
                || v == ".git/gitdir"
                || v.starts_with(".git/refs/"))
        };
        listing.mount(".git", &repo.git_dir, "", git_prune, git_include);
        if repo.common_dir != repo.git_dir {
            listing.mount(".git", &repo.common_dir, "", git_prune, git_include);
        }

        let bulk = self.config.bulk_dirs.clone();
        let root = self.config.root.clone();
        let mut tree_roots: Vec<String> = Vec::new();
        let out = repo.run(&[
            "ls-files",
            "-o",
            "-i",
            "--exclude-standard",
            "--directory",
            "-z",
        ])?;
        for rel in String::from_utf8_lossy(&out.stdout).split('\0') {
            if !rel.is_empty() {
                tree_roots.push(rel.to_owned());
            }
        }
        tree_roots.extend(gitlinks.iter().map(|g| format!("{g}/")));
        for rel in tree_roots {
            let is_dir = rel.ends_with('/');
            let rel = rel.trim_end_matches('/');
            let abs = root.join(rel);
            if has_component_in(Path::new(rel), &bulk)
                || rel == DAEMON_DIR
                || self.is_daemon_path(&abs)
            {
                continue;
            }
            if is_dir {
                listing.mount(
                    "tree",
                    &root,
                    rel,
                    |abs, _, name| bulk.iter().any(|b| b == name) || self.is_daemon_path(abs),
                    |_, _, _| true,
                );
            } else {
                listing.mount_file(&format!("tree/{rel}"), "tree", &root, &abs);
            }
        }
        if let Some(home) = &self.config.harness_home
            && home.is_dir()
        {
            let creds: Vec<PathBuf> = index::CREDENTIAL_FILES
                .iter()
                .map(|c| home.join(c))
                .collect();
            listing.mount(
                "harness",
                home,
                "",
                |_, _, _| false,
                |abs, _, _| !creds.iter().any(|c| c == abs),
            );
        }
        Ok(listing)
    }

    /// The bulk class listing: every bulk directory under the root.
    fn bulk_listing(&self) -> Listing {
        let mut listing = Listing::default();
        let bulk = self.config.bulk_dirs.clone();
        let root = self.config.root.clone();
        listing.mount(
            "",
            &root,
            "",
            |abs, v, name| v == ".git" || name == DAEMON_DIR || self.is_daemon_path(abs),
            |abs, _, _| {
                abs.strip_prefix(&root)
                    .is_ok_and(|rel| has_component_in(rel, &bulk))
            },
        );
        listing
    }

    /// Build a chunked class into new packs; returns the root key, the pack keys the tree needs,
    /// the new dir objects and stats.
    fn build_class(
        &mut self,
        listing: &Listing,
        class: Class,
        uploads: &mut Vec<Upload>,
        stats: &mut SnapStats,
    ) -> Result<(String, Vec<String>), EngineError> {
        let objects = self.staging.objects_dir();
        let prefix = self.prefix.clone();
        let key_for_dir = move |sha: &str| prefix.tree(sha);
        let mut sink = PackSink {
            builder: PackBuilder::new(&objects, self.config.pack_cap),
            known: &self.chunks.packs,
            cycle: DutyCycle::new(self.config.cpu_fraction),
        };
        let index = match class {
            Class::Small => &mut self.workspace_index,
            Class::Bulk => &mut self.bulk_index,
        };
        let built = TreeBuilder::new(index, &key_for_dir).build(listing, &mut sink)?;
        let packs = sink.builder.finish()?;
        for p in &packs {
            let key = self.prefix.pack(&p.sha256);
            for e in &p.entries {
                self.chunks.packs.insert(e.hash, key.clone());
            }
            uploads.push(Upload {
                key,
                file: p.sha256.clone(),
                bytes: p.bytes,
            });
            stats.cdc_packs += 1;
            stats.cdc_pack_bytes += p.bytes;
        }
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
        Ok((
            self.prefix.tree(&built.root.sha256),
            needed.into_iter().collect(),
        ))
    }

    /// Take a snap and stage it.
    pub fn snap(&mut self, req: SnapRequest) -> Result<StagedCapture, EngineError> {
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

        let sections = match req.class {
            Class::Small => {
                let repo = GitRepo::open(&self.config.root)?;
                let previous_tips = self
                    .previous
                    .as_ref()
                    .map(|p| p.manifest.git_tips())
                    .unwrap_or_default();
                let mut excludes = vec![DAEMON_DIR.to_owned()];
                if let Ok(rel) = self.config.staging_dir().strip_prefix(&self.config.root) {
                    excludes.push(rel.to_string_lossy().to_string());
                }
                let git = gitpack::build_git_pack(&repo, &objects, &previous_tips, &excludes)?;
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
                let (root, packs) =
                    self.build_class(&listing, Class::Small, &mut uploads, &mut stats)?;
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
                let (root, packs) =
                    self.build_class(&listing, Class::Bulk, &mut uploads, &mut stats)?;
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

        // Chain position: coalesce with a pending, not-yet-shipping auto capture.
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
            // Keep the packs the coalesced capture staged (the new manifest may list them);
            // its trees and manifest are superseded.
            all_uploads.extend(
                old.uploads
                    .iter()
                    .filter(|u| is_pack_file(&u.file))
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
        Ok(StagedCapture {
            n,
            manifest,
            manifest_key,
            kind: req.kind,
            class: req.class,
            stats,
        })
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

    /// Materialize `manifest` from `sink` into this engine's root (and harness home).
    pub fn materialize(
        &self,
        sink: &dyn BlobSink,
        manifest: &Manifest,
        class: MaterializeClass,
    ) -> Result<MaterializeReport, EngineError> {
        let mut targets =
            MaterializeTargets::new(&self.config.root, self.config.harness_home.clone());
        targets.cache_dir = self.staging.cache_dir();
        targets.scratch_dir = self.staging.scratch_dir();
        Ok(Materializer::new(sink, targets).materialize(manifest, class)?)
    }
}
