//! `CaptureEngine`: index the roots, snap, pack, write the manifest, stage.

use std::collections::{BTreeSet, HashMap, HashSet};
use std::fs;
use std::io;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, Instant};

use serde::{Deserialize, Serialize};

use crate::aliases::{Aliases, LinkedName};
use crate::chunk::{Chunk, ChunkId, chunk_bytes, sha256_hex};
use crate::gitpack::{self, GitError, GitRepo};
use crate::index::{
    self, BuildStats, ChunkSink, DAEMON_DIR, Listing, Suspects, TreeBuilder, TreeIndex,
    UnreadablePath, UnreadableWork,
};
use crate::io_at::IoAt;
use crate::keys::KeyPrefix;
use crate::longpath;
use crate::manifest::{
    BulkSection, BulkState, CaptureKind, DirFormat, EncodedManifest, FORMAT_DIR_PACKS, FinalSeal,
    GitSection, INDEX_TREE_REF, Manifest, Sections, WORKTREE_META_FORMAT, WORKTREE_TREE_REF,
    WorkspaceSection, WorktreeMeta, rfc3339_now,
};
use crate::materialize::{
    DiskState, MaterializeClass, MaterializeError, MaterializeReport, MaterializeTargets,
    Materializer,
};
use crate::pack::{MAX_PACK_BYTES, PackBuilder, PackError, PackReader};
use crate::position::Observer;
use crate::registrar::RegisterRequest;
use crate::registrar::Registrar;
use crate::roots::ClassRoots;
use crate::ship::{
    DutyCycle, MultipartConfig, QueueEntry, Restage, ShipError, Shipper, Staging, Upload,
};
use crate::sink::BlobSink;
use crate::tree::EncodedDir;
use crate::watch::{Invalidations, WatchPolicy};
use crate::worktree_meta::{self, MetaError, MetaScope};

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
    /// Longest interval between small-class snaps while the class is watched and nothing
    /// dirtied it: a snap that reads the class whole (a stat walk; nothing is staged when nothing
    /// changed), for a change no event reported. Watches follow names, and a write can reach a
    /// file through a name no watch sees (review 2026-09-28, sixth pass, #2): the loss window of
    /// such a write is bounded by this, never by the next event.
    pub reconcile: Duration,
    /// [`Cadence::reconcile`] for the bulk class.
    pub bulk_reconcile: Duration,
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
            reconcile: Duration::from_secs(60),
            bulk_reconcile: Duration::from_secs(600),
            heartbeat: Duration::from_secs(10),
            lease_ttl: Duration::from_secs(30),
        }
    }
}

/// The symlinks of `listing` whose inode has more than one name (`ln` of a symlink, `cp -al`
/// over a tree holding one), as its virtual paths.
fn multi_named_symlinks(listing: &Listing) -> Vec<String> {
    use std::os::unix::fs::MetadataExt;
    listing
        .entries
        .iter()
        .filter(|(_, src)| src.meta.is_symlink() && src.meta.nlink() > 1)
        .map(|(v, _)| v.clone())
        .collect()
}

/// Why a final snap over symlinks with more than one name fails.
fn multi_named_error(paths: &[String]) -> String {
    format!(
        "{} symlink(s) share an inode with another name, which no capture carries as one inode \
         (a restore would make each name its own symlink): {}",
        paths.len(),
        paths.join(", ")
    )
}

/// `<os>-<arch>-<libc>` of the workspace this daemon captures, the key its bulk class stamps on
/// its captures and names on `plan.get`: the C library of the userland the dependency tree was
/// built for, never this build's own. sealantd ships as a static musl binary into glibc
/// workspaces, and keying by the build said `linux-x86_64-musl` everywhere: Mend's probe of the
/// same workspace says `-gnu`, so every resume took the head's dependency tree for another
/// platform's, left it `"pending"` and installed it again (observed: 177 files rewritten, 988 MB
/// captured again). Detected once per process ([`platform_of`] over `/`).
#[must_use]
pub fn default_platform() -> String {
    static PLATFORM: std::sync::OnceLock<String> = std::sync::OnceLock::new();
    PLATFORM
        .get_or_init(|| platform_of(Path::new("/"), ldd_version))
        .clone()
}

/// `<os>-<arch>-<libc>` of the userland under `root`, in the form Mend's platform probe gives
/// (`uname -s`, `uname -m`, `ldd --version`): `musl` when the musl dynamic loader
/// (`lib/ld-musl-<arch>.so.1`) is there or `ldd --version` (`ldd`, asked only then) names
/// musl; `gnu` otherwise on Linux; `system` on any other OS.
pub fn platform_of(root: &Path, ldd: impl FnOnce() -> Option<String>) -> String {
    let os = std::env::consts::OS;
    let libc = if os != "linux" {
        "system"
    } else if musl_loader(root) || ldd().is_some_and(|out| out.to_lowercase().contains("musl")) {
        "musl"
    } else {
        "gnu"
    };
    format!("{os}-{}-{libc}", std::env::consts::ARCH)
}

fn musl_loader(root: &Path) -> bool {
    fs::read_dir(root.join("lib")).is_ok_and(|dir| {
        dir.filter_map(Result::ok).any(|e| {
            let name = e.file_name();
            let name = name.to_string_lossy();
            name.starts_with("ld-musl-") && name.ends_with(".so.1")
        })
    })
}

/// What `ldd --version` prints, both streams (musl's `ldd` prints its banner on stderr).
fn ldd_version() -> Option<String> {
    let out = std::process::Command::new("ldd")
        .arg("--version")
        .stdin(std::process::Stdio::null())
        .output()
        .ok()?;
    let mut text = String::from_utf8_lossy(&out.stdout).into_owned();
    text.push_str(&String::from_utf8_lossy(&out.stderr));
    Some(text)
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
    /// The executor this engine captures for, as the session token names it: `plan.get`'s
    /// `executor` (the launch), and nothing else. A complete final flush seals the chain under
    /// it ([`crate::manifest::FinalSeal`]); `None` seals nothing.
    pub executor: Option<String>,
    /// Name the git section's trees in their own fields (`worktree_tree`, `index_tree`,
    /// `raw_tree`; the `git_trees` manifest feature) rather than as pseudo-refs in `refs`: for a
    /// registrar whose `plan.get` lists `git_trees`. Without it the worktree tree is the one
    /// restored, as git checks it out, and a user ref named `refs/sealant/capture/worktree` or
    /// `…/index` is shadowed by the tree. Without it a final flush is never complete
    /// ([`CaptureEngine::fidelity_gap`]).
    pub git_trees: bool,
    /// Manifest features this build writes that the store does not read, validate and keep
    /// ([`crate::registrar::MANIFEST_FEATURES`] less `plan.get`'s `manifest_features`;
    /// [`Self::set_store_features`]). A store that cannot hold what a capture holds restores
    /// less than was captured, so while any is missing a final flush is never complete and
    /// seals nothing (review 2026-09-28, fourth pass, #7).
    pub unread_features: Vec<String>,
    /// The store reads the `object_format` manifest feature (`plan.get`'s
    /// `manifest_features`). Only a repository that is not SHA-1 needs it: a final snap of one
    /// fails without it ([`CaptureEngine::snap`]), and a SHA-1 repository's captures are what
    /// they always were.
    pub reads_object_format: bool,
    /// The store reads the `ref_format` manifest feature (`plan.get`'s `manifest_features`).
    /// Only a repository whose refs are not in the files backend needs it: a final snap of one
    /// fails without it, and a files repository's captures are what they always were.
    pub reads_ref_format: bool,
    /// The store reads the `wide_times` manifest feature (`plan.get`'s `manifest_features`):
    /// it keeps a modification time outside signed 64-bit nanoseconds exactly
    /// ([`crate::index::NARROW_NS`]). Every capture records such a time exactly; a final snap
    /// over one fails without this (`unreadable`), and a disk with none needs nothing.
    pub reads_wide_times: bool,
}

/// The manifest features written only for what one repository or disk holds — a repository
/// that is not SHA-1 (`object_format`), one whose refs are not in the files backend
/// (`ref_format`), a time outside signed 64-bit nanoseconds (`wide_times`) — and decided there,
/// not required of every store ([`CaptureConfig::unread_features`] leaves them out).
pub const PER_REPOSITORY_FEATURES: [&str; 3] = ["object_format", "ref_format", "wide_times"];

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
            executor: None,
            git_trees: true,
            unread_features: Vec::new(),
            reads_object_format: true,
            reads_ref_format: true,
            reads_wide_times: true,
        }
    }

    /// Take the features the store reads (`plan.get`'s `manifest_features`): the git section's
    /// trees in their own fields only for a store that reads `git_trees`, and every feature of
    /// [`crate::registrar::MANIFEST_FEATURES`] it leaves out noted as unread.
    pub fn set_store_features(&mut self, reads: &[String]) {
        self.git_trees = reads.iter().any(|f| f == "git_trees");
        self.reads_object_format = reads.iter().any(|f| f == "object_format");
        self.reads_ref_format = reads.iter().any(|f| f == "ref_format");
        self.reads_wide_times = reads.iter().any(|f| f == "wide_times");
        // `object_format` is written only for a repository that is not SHA-1, `ref_format`
        // only for one whose refs are not in the files backend, `wide_times` only for a time
        // outside signed 64-bit nanoseconds, and each is decided there
        // ([`Self::reads_object_format`], [`Self::reads_ref_format`],
        // [`Self::reads_wide_times`]; the boot decides the first two for the repository it
        // admits writers over, [`Self::repository_gap`]).
        self.unread_features = crate::registrar::MANIFEST_FEATURES
            .iter()
            .filter(|f| !PER_REPOSITORY_FEATURES.contains(f) && !reads.iter().any(|r| r == *f))
            .map(|f| (*f).to_owned())
            .collect();
    }

    /// Why the store cannot hold the repository a boot admits writers over, when it cannot: one
    /// of `object_format` that is not `sha1`, or whose refs are in the `ref_format` backend
    /// that is not `files`, needs the store to read that manifest feature. A final flush over
    /// it would say incomplete ([`CaptureEngine::snap`]); decided at the boot instead, from the
    /// head's git section and the repository already on the disk, so that no user code is
    /// admitted over a store that cannot keep what it writes (decision 16; review 2026-09-28,
    /// tenth pass). A format this build does not restore is refused as well.
    #[must_use]
    pub fn repository_gap(&self, object_format: &str, ref_format: &str) -> Option<String> {
        let mut gaps = Vec::new();
        if object_format != "sha1" {
            if !crate::manifest::OBJECT_FORMATS.contains(&object_format) {
                gaps.push(format!(
                    "the repository's object format {object_format} is not one this build restores"
                ));
            } else if !self.reads_object_format {
                gaps.push(format!(
                    "the repository's object format is {object_format}, and the store does not \
                     read the manifest feature object_format"
                ));
            }
        }
        if ref_format != "files" {
            if !crate::manifest::REF_FORMATS.contains(&ref_format) {
                gaps.push(format!(
                    "the repository keeps its refs in the {ref_format} backend, which this build \
                     does not restore"
                ));
            } else if !self.reads_ref_format {
                gaps.push(format!(
                    "the repository keeps its refs in the {ref_format} backend, and the store \
                     does not read the manifest feature ref_format"
                ));
            }
        }
        (!gaps.is_empty()).then(|| {
            format!(
                "{}: what it would restore is not the repository",
                gaps.join("; ")
            )
        })
    }

    /// Why no user code may be admitted to write over this store, when none may: what the
    /// store does not read of every capture ([`Self::fidelity_gap`]), and what it does not read
    /// of the repository the writers get — the one the chain head's git section (`head`) names,
    /// and the one already at `disk`, when there is one ([`Self::repository_gap`]). A
    /// repository whose formats cannot be read is refused too: nothing says the store can
    /// keep it.
    #[must_use]
    pub fn admission_gap(&self, head: Option<&GitSection>, disk: &Path) -> Option<String> {
        let mut gaps: Vec<String> = self.fidelity_gap().into_iter().collect();
        if let Some(git) = head
            && let Some(gap) = self.repository_gap(git.object_format(), git.ref_format())
        {
            gaps.push(format!("the chain head: {gap}"));
        }
        if disk.join(".git").exists() {
            let formats = GitRepo::open(disk)
                .and_then(|repo| Ok((repo.object_format()?, repo.ref_format()?)));
            match formats {
                Ok((object_format, ref_format)) => {
                    if let Some(gap) = self.repository_gap(&object_format, &ref_format) {
                        gaps.push(format!("the repository at {}: {gap}", disk.display()));
                    }
                }
                Err(error) => gaps.push(format!(
                    "the object format and ref backend of the repository at {} cannot be read \
                     ({error})",
                    disk.display()
                )),
            }
        }
        (!gaps.is_empty()).then(|| gaps.join("; "))
    }

    /// Why the store cannot hold what a capture holds, when it cannot: the features it does not
    /// read ([`Self::unread_features`], `git_trees` when [`Self::git_trees`] is off). While this
    /// is `Some`, no final flush is complete or sealed, and no boot admits user code over it
    /// (decisions 12 and 16).
    #[must_use]
    pub fn fidelity_gap(&self) -> Option<String> {
        let mut missing = self.unread_features.clone();
        if !self.git_trees && !missing.iter().any(|f| f == "git_trees") {
            missing.push("git_trees".to_owned());
        }
        (!missing.is_empty()).then(|| {
            format!(
                "the store does not read the manifest feature(s) {}: what it would restore is \
                 less than the capture holds",
                missing.join(", ")
            )
        })
    }

    /// The staging directory in effect.
    #[must_use]
    pub fn staging_dir(&self) -> PathBuf {
        self.staging_dir
            .clone()
            .unwrap_or_else(|| self.root.join(DAEMON_DIR).join("capture"))
    }

    /// The key prefix, at key generation 0 (the engine takes the staging's own,
    /// [`crate::ship::Staging::key_generation`]).
    #[must_use]
    pub fn prefix(&self) -> KeyPrefix {
        KeyPrefix {
            worktree_id: self.worktree_id.clone(),
            epoch: self.epoch,
            generation: Some(0),
        }
    }
}

/// Which class to snap.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Class {
    /// Git pack, `.git` bookkeeping, harness home.
    Small,
    /// Dependencies and build outputs.
    Bulk,
}

impl Class {
    /// The other class.
    #[must_use]
    pub fn other(self) -> Self {
        match self {
            Self::Small => Self::Bulk,
            Self::Bulk => Self::Small,
        }
    }
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
    /// The worktree metadata overlay.
    #[error(transparent)]
    WorktreeMeta(#[from] MetaError),
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

/// The queued capture a repair snap replaces, and the captures staged after it (folded in).
#[derive(Debug, Clone)]
struct RepairTarget {
    entry: QueueEntry,
    followers: Vec<QueueEntry>,
    /// The keys the registrar refused (or every key of the rebuilt sections, when it named
    /// none): never staged again, never uploaded again (cross-repo decision 6).
    forget: HashSet<String>,
}

/// The chunked-section keys a registered head names: its workspace and bulk packs and dir
/// packs (across epochs, on its chain).
fn chain_keys(head: &EncodedManifest) -> HashSet<String> {
    let s = &head.manifest.sections;
    let mut keys: HashSet<String> = s
        .workspace
        .packs
        .iter()
        .chain(&s.workspace.dir_packs)
        .cloned()
        .collect();
    if let Some(bulk) = s.bulk.section() {
        keys.extend(bulk.packs.iter().chain(&bulk.dir_packs).cloned());
    }
    keys
}

/// A pack the materializer cached (`<cache>/<sha256>`), opened, when it is there and whole.
fn cached_pack(cache: &Path, key: &str) -> Option<PackReader> {
    let sha = crate::keys::key_digest(key)?;
    PackReader::open(&cache.join(sha)).ok()
}

/// The staged file a store key was uploaded from (its ack marker's name).
fn file_of_key(key: &str) -> Option<String> {
    let (dir, last) = key.rsplit_once('/')?;
    let kind = dir.rsplit('/').next()?;
    match kind {
        "packs" => Some(last.to_owned()),
        "trees" => Some(format!("tree-{last}")),
        "manifests" => Some(format!("manifest-{last}")),
        _ => None,
    }
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
    /// The launch it was staged for ([`CaptureConfig::executor`]); absent from a staging
    /// written before it was recorded, or by an executor that was not told its launch.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    executor: Option<String>,
}

impl LastStaged {
    fn load(index_dir: &Path) -> Option<Self> {
        fs::read(index_dir.join("last.json"))
            .ok()
            .and_then(|b| serde_json::from_slice(&b).ok())
    }

    fn save(&self, index_dir: &Path) -> io::Result<()> {
        let tmp = index_dir.join("last.tmp");
        fs::write(&tmp, serde_json::to_vec(self)?).at("write", &tmp)?;
        let path = index_dir.join("last.json");
        fs::rename(tmp, &path).at("rename into", &path)
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
    /// The worktree metadata overlay the last small snap read, in memory: an automatic snap
    /// keeps its entry for a tracked path whose metadata it cannot read (git carries the path's
    /// content). Empty after a restart, when such a path's metadata is left out and the path is
    /// reported unreadable all the same.
    last_meta: Option<worktree_meta::MetaDocument>,
    /// The last small snap found files with names outside their class — a tracked file's inode
    /// another class names, or a workspace-class file whose inode has names the workspace
    /// class does not hold (hardlinks into the bulk class): its overlay names the bulk class's
    /// names as the bulk index had them, so a bulk capture staged after it can change what the
    /// next small snap records.
    shared_outside: bool,
    /// The last small snap left out a link to a bulk name because the bulk index's stat of it
    /// is not the disk's (the file changed, or gained a name, since the last bulk snap): the
    /// bulk class's capture does not hold that name as the link would promise, so the link
    /// waits for a small snap after a bulk snap ([`CaptureEngine::links_deferred`]).
    links_deferred: bool,
    /// A refused capture being rebuilt in its place ([`CaptureEngine::repair`]): the next
    /// snap takes its `n` and parent and folds the captures staged after it into itself.
    repair_target: Option<RepairTarget>,
    /// Git packs the registrar said are missing: the next small snap packs every object
    /// again (no negatives) and names no missing pack.
    repair_git: Option<HashSet<String>>,
    /// The manifest the queued bulk capture was staged on (its parent). A small snap while that
    /// bulk capture's objects upload is staged ahead of it: it takes the bulk capture's place on
    /// the chain with this manifest's bulk section, and the bulk capture moves on top of it. See
    /// [`CaptureEngine::snap_preemptible`].
    below: Option<EncodedManifest>,
    /// Paths the watcher saw written, per class, not yet read again.
    invalidations: Arc<Invalidations>,
    /// What each class's last snap could not read.
    reads: Arc<ReadReports>,
    /// Every multi-link file each class's last snap read ([`crate::aliases`]).
    aliases: Arc<Aliases>,
    /// Where each answer and seal of this boot stands ([`crate::position`]).
    observer: Arc<Observer>,
    /// The multi-link files the snap in progress read, recorded in [`Self::aliases`] once it
    /// staged (or found nothing changed).
    linked: Option<(Class, Vec<LinkedName>)>,
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

/// The nested repositories `listing` carries (a `.git` entry under `prefix`, not inside
/// another `.git`), keyed by the virtual path of their directory, with how each keeps its git
/// storage ([`gitpack::nested_storage`]).
fn nested_repositories(
    repo: &GitRepo,
    workspace: &Path,
    listing: &Listing,
    prefix: &str,
) -> Vec<(String, PathBuf, gitpack::NestedStorage)> {
    listing
        .entries
        .iter()
        .filter_map(|(key, src)| {
            let rel = key.strip_prefix(prefix)?;
            let dir_key = rel.strip_suffix("/.git")?;
            if dir_key.split('/').any(|c| c == ".git") {
                return None;
            }
            let dir = src.abs.parent()?.to_path_buf();
            let storage = gitpack::nested_storage(repo, workspace, &dir);
            Some((format!("{prefix}{dir_key}"), dir, storage))
        })
        .collect()
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
        // One more boot of this disk (decision 17): counted before any answer is given.
        let observer = Arc::new(Observer::open(&config.staging_dir()));
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
        let prefix = KeyPrefix {
            generation: Some(staging.key_generation()),
            ..config.prefix()
        };
        // Chunk locations from another epoch are reused only where the registered head this
        // engine continues names their packs (ADR-0015: a manifest may reference packs from
        // earlier epochs on its chain); anything else an earlier epoch staged may never have
        // reached the store.
        let base = format!("{}/", prefix.base());
        let chain = previous.as_ref().map(chain_keys).unwrap_or_default();
        let chunks = ChunkMap {
            packs: chunks
                .packs
                .into_iter()
                .filter(|(_, k)| k.starts_with(&base) || chain.contains(k))
                .collect(),
        };
        dirs.retain(|k| k.starts_with(&base) || chain.contains(k));
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
            last_meta: None,
            shared_outside: false,
            links_deferred: false,
            repair_target: None,
            repair_git: None,
            below: None,
            invalidations: Arc::new(Invalidations::default()),
            reads: Arc::new(ReadReports::default()),
            aliases: Arc::new(Aliases::default()),
            linked: None,
            observer,
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
        engine.seed_from_chain()?;
        engine.resume_queue()?;
        Ok(engine)
    }

    /// Learn where the registered head's chunks are: every pack its workspace and bulk sections
    /// name (and, writing dir packs, every dir pack) that the materializer left in the pack cache
    /// is opened and its chunks mapped to its key. A restored executor then knows the files it
    /// just wrote are in the store — the materializer recorded their stat in the class indexes —
    /// and its next capture reads and uploads only what changed. Before, every epoch forgot
    /// them: the first bulk capture after a resume read and uploaded the whole dependency tree
    /// again (observed: 119,414 files, 1.4 GB, for one new 300 MB file).
    fn seed_from_chain(&mut self) -> Result<(), EngineError> {
        let Some(previous) = &self.previous else {
            return Ok(());
        };
        let sections = &previous.manifest.sections;
        let cache = self.staging.cache_dir();
        let mut learned = 0usize;
        let mut chunked: Vec<&String> = sections.workspace.packs.iter().collect();
        let bulk = sections.bulk.section();
        if let Some(bulk) = bulk {
            chunked.extend(&bulk.packs);
        }
        for key in chunked {
            let Some(reader) = cached_pack(&cache, key) else {
                continue;
            };
            for id in reader.chunk_ids() {
                if !self.chunks.packs.contains_key(id) {
                    self.chunks.packs.insert(*id, key.clone());
                    learned += 1;
                }
            }
        }
        if self.config.dir_format == DirFormat::Packs {
            let mut dir_packs: Vec<(Class, &String)> = Vec::new();
            if sections.workspace.format == FORMAT_DIR_PACKS {
                dir_packs.extend(
                    sections
                        .workspace
                        .dir_packs
                        .iter()
                        .map(|k| (Class::Small, k)),
                );
            }
            if let Some(bulk) = bulk
                && bulk.format == FORMAT_DIR_PACKS
            {
                dir_packs.extend(bulk.dir_packs.iter().map(|k| (Class::Bulk, k)));
            }
            for (class, key) in dir_packs {
                let Some(reader) = cached_pack(&cache, key) else {
                    continue;
                };
                let known = self.dirs.class(class);
                for id in reader.chunk_ids() {
                    known.entry(id.to_hex()).or_insert_with(|| key.clone());
                }
            }
        }
        if learned > 0 {
            tracing::info!(
                chunks = learned,
                head = previous.manifest.n,
                "chunk locations learned from the restored head"
            );
            self.persist()?;
        }
        Ok(())
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
        // Continuing the head is not enough: the staging must be this launch's (cross-repo
        // decision 11). Across an epoch change only the launch that staged it continues it —
        // an old launch's disk resumed into a replacement's epoch registered its stale state as
        // the replacement's successor (review 2026-09-28, fourth pass, #11) — and a staging
        // that names no launch cannot show it is. Under the same epoch, a launch it names
        // must be this one.
        let epoch_changed = last.epoch != config.epoch;
        let same_launch = match (&last.executor, &config.executor) {
            (Some(staged), Some(this)) => staged == this,
            (None, _) | (_, None) => !epoch_changed,
        };
        if !same_launch {
            tracing::error!(
                staged_launch = ?last.executor,
                staged_epoch = last.epoch,
                launch = ?config.executor,
                epoch = config.epoch,
                queued = queued.len(),
                "this disk's staging is not this launch's continuation of the chain"
            );
            return Ok(Pickup::Materialize);
        }
        Ok(Pickup::Resume {
            queued: queued.len(),
            epoch_changed,
        })
    }

    /// The launch the capture staging at `staging_dir` was last written for, or else the one
    /// its last completed materialize was planned as ([`CaptureConfig::executor`] as it was
    /// then), when either says: what a restarting executor names itself on its first
    /// `plan.get` when its launcher did not ([`crate::registrar::PlanGetRequest::launch`]).
    #[must_use]
    pub fn disk_launch(staging_dir: &Path) -> Option<String> {
        let index = staging_dir.join("index");
        LastStaged::load(&index)
            .and_then(|last| last.executor)
            .or_else(|| DiskState::load(&index).capture.and_then(|c| c.executor))
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
        self.staging.set_identity(worktree_id, epoch)?;
        self.prefix = KeyPrefix {
            generation: Some(self.staging.key_generation()),
            ..self.config.prefix()
        };
        let dropped = self.staging.discard_foreign()?;
        let base = format!("{}/", self.prefix.base());
        let chain = previous.as_ref().map(chain_keys).unwrap_or_default();
        self.chunks
            .packs
            .retain(|_, k| k.starts_with(&base) || chain.contains(k));
        self.dirs
            .retain(|k| k.starts_with(&base) || chain.contains(k));
        self.bulk_work = None;
        let seeded = previous.is_some();
        self.previous = previous;
        self.seed_from_chain()?;
        if seeded {
            self.seed_tips_from_repo()?;
        } else {
            self.last_tips.clear();
            self.persist()?;
        }
        self.last_meta = None;
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

    /// The features the store reads, as a re-plan's `plan.get` answers them
    /// ([`CaptureConfig::set_store_features`]).
    pub fn set_store_features(&mut self, reads: &[String]) {
        self.config.set_store_features(reads);
    }

    /// Why the store cannot hold what a capture holds, when it cannot: the features it does not
    /// read ([`CaptureConfig::unread_features`], `git_trees` when [`CaptureConfig::git_trees`]
    /// is off). A capture still stages and ships — the store has as much as it can take — but a
    /// final flush is never complete and seals nothing while this is `Some` (decision 12: a
    /// lossy capture never completes).
    #[must_use]
    pub fn fidelity_gap(&self) -> Option<String> {
        self.config.fidelity_gap()
    }

    /// The executor this engine seals a completed final flush under (a re-plan names it again:
    /// a standby claimed for a session). See [`CaptureConfig::executor`].
    pub fn set_executor(&mut self, executor: Option<String>) {
        self.config.executor = executor;
    }

    /// The repository's object format as the git section names it: `None` for `sha1`, else
    /// the format (review 2026-09-28, eighth pass, #10). One this build does not restore, or
    /// one the store does not read (`object_format`), fails a final snap — a capture over it
    /// would register and not restore — and an automatic one names it all the same.
    fn object_format(&self, repo: &GitRepo, strict: bool) -> Result<Option<String>, EngineError> {
        let format = repo.object_format()?;
        if format == "sha1" {
            return Ok(None);
        }
        let gap = if !crate::manifest::OBJECT_FORMATS.contains(&format.as_str()) {
            Some(format!(
                "the repository's object format {format} is not one this build restores"
            ))
        } else if !self.config.reads_object_format {
            Some(format!(
                "the repository's object format is {format}, and the store does not read the \
                 manifest feature object_format: what it would restore is not the repository"
            ))
        } else {
            None
        };
        if let Some(gap) = gap {
            if strict {
                return Err(io::Error::other(gap).into());
            }
            tracing::warn!(%gap, "a final flush over this repository is not complete");
        }
        Ok(Some(format))
    }

    /// The repository's ref backend as the git section names it: `None` for `files`, else the
    /// backend (review 2026-09-28, ninth pass, #1). One this build does not restore, or one the
    /// store does not read (`ref_format`), fails a final snap, as [`Self::object_format`] does.
    fn ref_format(&self, found: &str, strict: bool) -> Result<Option<String>, EngineError> {
        if found == "files" {
            return Ok(None);
        }
        let gap = if !crate::manifest::REF_FORMATS.contains(&found) {
            Some(format!(
                "the repository keeps its refs in the {found} backend, which this build does not \
                 restore"
            ))
        } else if !self.config.reads_ref_format {
            Some(format!(
                "the repository keeps its refs in the {found} backend, and the store does not \
                 read the manifest feature ref_format: what it would restore is not the repository"
            ))
        } else {
            None
        };
        if let Some(gap) = gap {
            if strict {
                return Err(io::Error::other(gap).into());
            }
            tracing::warn!(%gap, "a final flush over this repository is not complete");
        }
        Ok(Some(found.to_owned()))
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

    /// Where this boot's answers and seals stand ([`crate::position`]): `capture.status` takes
    /// its answers' positions here, so they and the seals share one order.
    #[must_use]
    pub fn observer(&self) -> Arc<Observer> {
        Arc::clone(&self.observer)
    }

    /// The multi-link files each class's last snap read, shared with the watcher (an event on
    /// one name dirties every class holding another) and the cadence's poll
    /// ([`crate::aliases`]).
    #[must_use]
    pub fn aliases(&self) -> Arc<Aliases> {
        Arc::clone(&self.aliases)
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
                executor: self.config.executor.clone(),
            }
            .save(&dir)?;
        }
        self.workspace_index.save(&dir.join("workspace.json"))?;
        self.bulk_index.save(&dir.join("bulk.json"))?;
        for (name, bytes) in [
            ("chunks", serde_json::to_vec(&self.chunks)?),
            ("dirs", serde_json::to_vec(&self.dirs)?),
            ("git-tips", serde_json::to_vec(&self.last_tips)?),
        ] {
            let tmp = dir.join(format!("{name}.tmp"));
            fs::write(&tmp, bytes).at("write", &tmp)?;
            let path = dir.join(format!("{name}.json"));
            fs::rename(&tmp, &path).at("rename into", &path)?;
        }
        Ok(())
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

    /// The paths of `gitlinks` (nested repositories and paths git could not index, keys) that
    /// hold something on disk and that `listing` carries nowhere: neither at or under
    /// `tree/<path>` nor reported unreadable there. A path under a bulk directory (the bulk
    /// class carries it) or the daemon's own is not the workspace class's to carry; an empty
    /// directory (a submodule never checked out) holds nothing to lose.
    fn uncarried_gitlinks(&self, gitlinks: &[String], listing: &Listing) -> Vec<String> {
        let roots = self.roots();
        let covered = |map_keys: &mut dyn Iterator<Item = &String>, key: &str| {
            let at = format!("tree/{key}");
            let under = format!("{at}/");
            let mut found = false;
            for k in map_keys {
                if *k == at || k.starts_with(&under) || at.starts_with(&format!("{k}/")) {
                    found = true;
                    break;
                }
            }
            found
        };
        gitlinks
            .iter()
            .filter(|key| {
                let rel = PathBuf::from(crate::tree::os_of_key(key));
                let abs = self.config.root.join(&rel);
                if index::has_component_in(&rel, &roots.bulk_dirs)
                    || rel.as_os_str() == DAEMON_DIR
                    || roots.is_daemon_path(&abs)
                {
                    return false;
                }
                let holds = match longpath::symlink_metadata(&abs) {
                    Ok(meta) if meta.is_dir() => {
                        longpath::read_dir(&abs).map_or(true, |names| !names.is_empty())
                    }
                    Ok(_) => true,
                    Err(e) => !index::is_vanished(&e),
                };
                holds
                    && !covered(&mut listing.entries.keys(), key)
                    && !covered(&mut listing.unreadable.keys(), key)
            })
            .cloned()
            .collect()
    }

    /// What the worktree metadata overlay covers: the working tree minus the daemon's paths,
    /// the harness home, bulk directories and the nested repositories in `nested`.
    fn meta_scope(&self, nested: &[String]) -> MetaScope {
        MetaScope {
            root: self.config.root.clone(),
            excludes: self.daemon_excludes(),
            bulk_dirs: self.config.bulk_dirs.clone(),
            nested: nested.to_vec(),
            skip_abs: [
                Some(self.config.staging_dir()),
                self.config.harness_home.clone(),
            ]
            .into_iter()
            .flatten()
            .collect(),
        }
    }

    /// Whether the bulk class's capture holds its name `v` of the inode `key` as the disk has
    /// it: `None` when `v` is not that inode on disk any more; `Some(false)` when it is, but
    /// its stat is not the one the last bulk snap read (the file changed or gained a name
    /// since, so the bulk capture may hold other bytes); `Some(true)` otherwise. A link names
    /// only a member the capture holds as it is (review 2026-09-28, fifth pass, #11).
    fn bulk_member_captured(
        &self,
        v: &str,
        known: &index::IndexedFile,
        key: (u64, u64),
    ) -> Option<bool> {
        use std::os::unix::ffi::OsStrExt;
        use std::os::unix::fs::MetadataExt;
        let abs = self
            .config
            .root
            .join(std::ffi::OsStr::from_bytes(&worktree_meta::bytes_of(v)));
        let meta = crate::longpath::symlink_metadata(&abs)
            .ok()
            .filter(|m| m.is_file() && (m.dev(), m.ino()) == key)?;
        Some(index::FileStat::of(&meta) == known.stat)
    }

    /// The names the workspace class (`listing`, this snap's) and the bulk class (its index,
    /// each name checked on disk) carry of the tracked files in `outside`, whose inodes have
    /// names the overlay does not hold. Also whether a bulk name was left out because the bulk
    /// capture does not hold it as it is ([`Self::bulk_member_captured`]).
    fn shared_links(
        &self,
        outside: &[worktree_meta::OutsideLinks],
        listing: &Listing,
    ) -> (Vec<worktree_meta::SharedLink>, bool) {
        use std::os::unix::fs::MetadataExt;
        if outside.is_empty() {
            return (Vec::new(), false);
        }
        let wanted: HashMap<(u64, u64), &str> = outside
            .iter()
            .map(|o| ((o.dev, o.ino), o.path.as_str()))
            .collect();
        let link = |path: &str, class, member: &str| worktree_meta::SharedLink {
            path: path.to_owned(),
            class,
            member: member.to_owned(),
            raw_member: None,
        };
        let mut shared = Vec::new();
        for (v, src) in &listing.entries {
            if src.meta.is_file()
                && let Some(path) = wanted.get(&(src.meta.dev(), src.meta.ino()))
            {
                shared.push(link(path, worktree_meta::LinkClass::Workspace, v));
            }
        }
        let mut deferred = false;
        for (v, known) in &self.bulk_index.files {
            let key = (known.stat.dev, known.stat.ino);
            let Some(path) = wanted.get(&key) else {
                continue;
            };
            // The index is the last bulk snap's: the inode must still be this one, and the
            // bulk capture must hold it as it is.
            match self.bulk_member_captured(v, known, key) {
                Some(true) => shared.push(link(path, worktree_meta::LinkClass::Bulk, v)),
                Some(false) => deferred = true,
                None => {}
            }
        }
        for s in &mut shared {
            s.raw_member = worktree_meta::raw_of(&s.member);
        }
        shared.sort();
        shared.dedup();
        (shared, deferred)
    }

    /// Inodes the workspace class (`listing`, this snap's) and the bulk class (its index, each
    /// name checked on disk) both name, none of them tracked: the tracked inodes in `outside`
    /// are [`Self::shared_links`]' (and a tracked inode none of whose names is outside the
    /// overlay has no name in either class). Each group lists every name the two classes carry
    /// of the inode, sorted, workspace names first. Also whether any workspace-class file has
    /// names the workspace class does not hold: then what this records depends on the bulk
    /// index (see [`Self::small_depends_on_bulk`]).
    fn cross_links(
        &self,
        outside: &[worktree_meta::OutsideLinks],
        listing: &Listing,
    ) -> (Vec<Vec<worktree_meta::LinkMember>>, bool, bool) {
        use std::os::unix::fs::MetadataExt;
        let tracked: HashSet<(u64, u64)> = outside.iter().map(|o| (o.dev, o.ino)).collect();
        let member = |class, v: &str| worktree_meta::LinkMember {
            class,
            member: v.to_owned(),
            raw_member: worktree_meta::raw_of(v),
        };
        // (dev, ino) → (link count, the workspace class's names).
        let mut inodes: HashMap<(u64, u64), (u64, Vec<worktree_meta::LinkMember>)> = HashMap::new();
        for (v, src) in &listing.entries {
            let key = (src.meta.dev(), src.meta.ino());
            if src.meta.is_file() && src.meta.nlink() > 1 && !tracked.contains(&key) {
                let slot = inodes.entry(key).or_insert((src.meta.nlink(), Vec::new()));
                slot.1.push(member(worktree_meta::LinkClass::Workspace, v));
            }
        }
        inodes.retain(|_, (nlink, names)| *nlink > names.len() as u64);
        if inodes.is_empty() {
            return (Vec::new(), false, false);
        }
        let mut bulk: HashMap<(u64, u64), Vec<worktree_meta::LinkMember>> = HashMap::new();
        let mut deferred = false;
        for (v, known) in &self.bulk_index.files {
            let key = (known.stat.dev, known.stat.ino);
            if !inodes.contains_key(&key) {
                continue;
            }
            // The index is the last bulk snap's: the inode must still be this one, and the
            // bulk capture must hold it as it is. A group never names a member the captures
            // do not hold as the disk does.
            match self.bulk_member_captured(v, known, key) {
                Some(true) => bulk
                    .entry(key)
                    .or_default()
                    .push(member(worktree_meta::LinkClass::Bulk, v)),
                Some(false) => deferred = true,
                None => {}
            }
        }
        let mut groups: Vec<Vec<worktree_meta::LinkMember>> = bulk
            .into_iter()
            .filter_map(|(key, bulk_names)| {
                let (_, mut names) = inodes.remove(&key)?;
                names.extend(bulk_names);
                names.sort();
                names.dedup();
                Some(names)
            })
            .collect();
        groups.sort();
        (groups, true, deferred)
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
        extra: &[Chunk],
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
        // Chunks the section names beside its tree (the worktree metadata overlay) go into the
        // same packs, deduplicated like a file's.
        let mut extra_put = Ok(());
        for chunk in extra {
            if !sink.contains(&chunk.id)
                && let Err(e) = sink.put(chunk.id, &chunk.data)
            {
                extra_put = Err(e);
                break;
            }
        }
        let built = match extra_put {
            Ok(()) => TreeBuilder::new(&mut work.index, &key_for_dir)
                .strict(strict)
                .narrow_times(strict && !self.config.reads_wide_times)
                .racy_window(self.config.racy_window)
                .suspects(&mut work.suspects)
                .build(listing, &mut sink),
            Err(e) => Err(e),
        };
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
        for c in built.chunks.iter().chain(extra.iter().map(|c| &c.id)) {
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
                    let key = self.prefix.tree(sha);
                    if !path.exists() && !self.staging.is_uploaded(&key, &file) {
                        fs::write(&path, &dir.bytes).at("write", &path)?;
                        stats.dirs_new += 1;
                    }
                    if !self.staging.is_uploaded(&key, &file) {
                        uploads.push(Upload {
                            key,
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

    /// Rebuild the capture the registrar refused ([`crate::ship::RepairRequest`], asked for by the shipper)
    /// from disk, in its place: the packs it named are forgotten (their chunks are read and
    /// packed again, a dir object is staged again, a missing git pack makes the next git pack a
    /// full one), then each class whose section named a missing key (the refused capture's own
    /// class when none is attributable) is snapped as a capture at the refused one's `n` with
    /// its parent. The captures staged after it are folded in: the rebuilt capture holds the
    /// disk as it is now and lists every object they staged; nothing is dropped. A final one
    /// among them makes the rebuilt capture final. Returns whether a repair ran. Snaps run it
    /// first ([`Self::snap_preemptible`]); the cadence runner's final flush runs it when the
    /// shipper reports [`crate::ship::ShipError::RepairPending`].
    ///
    /// # Errors
    /// A snap's error; the request stays and is tried again.
    pub fn repair(&mut self) -> Result<bool, EngineError> {
        let Some(request) = self.staging.repair_request() else {
            return Ok(false);
        };
        let staging = Arc::clone(&self.staging);
        let (entry, followers) = {
            let _guard = staging.coalesce_guard();
            let pending = staging.pending()?;
            let Some(at) = pending
                .iter()
                .position(|e| e.n == request.n && e.capture_id == request.capture_id)
            else {
                staging.clear_repair()?;
                return Ok(false);
            };
            (pending[at].clone(), pending[at + 1..].to_vec())
        };
        let sections = &entry.register.manifest.sections;
        let git_keys: HashSet<String> = sections
            .git
            .packs
            .iter()
            .flat_map(|k| [k.clone(), format!("{k}.idx")])
            .collect();
        let mut small_keys: HashSet<String> = sections
            .workspace
            .packs
            .iter()
            .chain(&sections.workspace.dir_packs)
            .cloned()
            .collect();
        small_keys.insert(sections.workspace.root.clone());
        let bulk_keys: HashSet<String> = sections
            .bulk
            .section()
            .map(|b| {
                b.packs
                    .iter()
                    .chain(&b.dir_packs)
                    .cloned()
                    .chain([b.root.clone()])
                    .collect()
            })
            .unwrap_or_default();
        let other_keys: HashSet<&String> = sections
            .other_bulk
            .values()
            .flat_map(|b| b.packs.iter().chain(&b.dir_packs))
            .collect();
        let missing: HashSet<String> = request.missing.iter().cloned().collect();
        let git_missing: HashSet<String> = missing
            .iter()
            .filter(|k| git_keys.contains(*k))
            .map(|k| k.strip_suffix(".idx").unwrap_or(k).to_owned())
            .collect();
        let mut small = !git_missing.is_empty() || missing.iter().any(|k| small_keys.contains(k));
        let mut bulk = missing.iter().any(|k| bulk_keys.contains(k));
        if !small && !bulk {
            match request.class {
                Some(Class::Bulk) => bulk = true,
                _ => small = true,
            }
        }
        let foreign: Vec<&String> = missing.iter().filter(|k| other_keys.contains(k)).collect();
        if !foreign.is_empty() {
            tracing::error!(
                keys = ?foreign,
                "the registrar is missing another platform's bulk packs; they cannot be rebuilt here"
            );
        }
        // Forget what the registrar does not hold. Named: those keys. None named (the tree
        // would not restore): every pack the rebuilt classes' sections name.
        let forget: HashSet<String> = if missing.is_empty() {
            let mut all = HashSet::new();
            if small {
                all.extend(small_keys.iter().cloned());
            }
            if bulk {
                all.extend(bulk_keys.iter().cloned());
            }
            all
        } else {
            missing.clone()
        };
        self.chunks.packs.retain(|_, k| !forget.contains(k));
        self.dirs.workspace.retain(|_, k| !forget.contains(k));
        self.dirs.bulk.retain(|_, k| !forget.contains(k));
        for key in &forget {
            if let Some(file) = file_of_key(key) {
                self.staging.unmark_uploaded(key, &file)?;
            }
        }
        // Nothing the rebuild stages goes up under a key a refusal may have named (cross-repo
        // decision 6): a new key generation first, durably, so a pack of the very same bytes
        // is a new key, and a delete retention paused on a condemned key can only take bytes
        // no live capture names.
        let generation = self.staging.next_key_generation()?;
        self.prefix.generation = Some(generation);
        tracing::warn!(
            generation,
            prefix = %self.prefix,
            "a refused capture is rebuilt under a new key generation"
        );
        if !git_missing.is_empty() {
            self.last_tips.clear();
            self.repair_git = Some(
                git_missing
                    .iter()
                    .flat_map(|k| [k.clone(), format!("{k}.idx")])
                    .collect(),
            );
        }
        if bulk {
            self.bulk_work = None;
        }
        self.persist()?;

        let replaced = std::iter::once(&entry).chain(&followers);
        let kind = if replaced.clone().any(|e| e.kind == CaptureKind::Final) {
            CaptureKind::Final
        } else {
            entry.kind
        };
        let seq = replaced.map(|e| e.register.manifest.seq).max().unwrap_or(0);
        tracing::warn!(
            n = entry.n,
            capture = %entry.capture_id,
            reason = %request.reason,
            missing = ?request.missing,
            small,
            bulk,
            folded = followers.len(),
            "rebuilding a refused capture from disk"
        );
        let mut target = RepairTarget {
            entry,
            followers,
            forget,
        };
        for class in [Class::Small, Class::Bulk] {
            if (class == Class::Small && !small) || (class == Class::Bulk && !bulk) {
                continue;
            }
            self.repair_target = Some(target.clone());
            let staged = self.snap_preemptible(SnapRequest { kind, class, seq }, &|| false);
            self.repair_target = None;
            let staged = match staged? {
                SnapOutcome::Staged(staged) => staged,
                SnapOutcome::Preempted => {
                    return Err(io::Error::other("a repair snap yielded").into());
                }
            };
            // The next class rebuilds the capture just staged in the same place.
            let pending = self.staging.pending()?;
            let Some(rebuilt) = pending
                .into_iter()
                .find(|e| e.n == staged.n && e.capture_id == staged.manifest.capture_id)
            else {
                return Err(io::Error::other("the rebuilt capture is not queued").into());
            };
            target = RepairTarget {
                entry: rebuilt,
                followers: Vec::new(),
                forget: target.forget,
            };
        }
        self.staging.clear_repair()?;
        Ok(true)
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
            final_seal: None,
        }
        .encode();
        let manifest_key = self.prefix.manifest(&manifest.capture_id);
        let manifest_file = format!("manifest-{}", manifest.capture_id);
        let manifest_path = self.staging.objects_dir().join(&manifest_file);
        fs::write(&manifest_path, &manifest.bytes).at("write", &manifest_path)?;
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
        self.linked = None;
        let outcome = self.snap_staging(req, preempt);
        // The multi-link files a snap read stand for its class once it staged, or found the
        // class as its last capture holds it.
        if let (Ok(SnapOutcome::Staged(_)), Some((class, names))) = (&outcome, self.linked.take()) {
            self.aliases.record(class, names);
        }
        outcome
    }

    /// [`Self::snap_preemptible`], but for the multi-link files it read.
    fn snap_staging(
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
        // A capture the registrar refused is rebuilt before anything is staged after it.
        if self.repair_target.is_none()
            && let Err(error) = self.repair()
        {
            tracing::error!(%error, "rebuilding a refused capture failed; asked again at the next snap");
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
                // A git pack the registrar says is missing: pack every object again.
                if self.repair_git.is_some() {
                    previous_tips.clear();
                }
                let excludes = self.daemon_excludes();
                // An automatic snap gives what the worktree cannot read the previous capture's
                // entry; a final one carries nothing and fails on it instead.
                let strict = req.kind == CaptureKind::Final;
                let object_format = self.object_format(&repo, strict)?;
                let previous_git = self
                    .previous
                    .as_ref()
                    .map(|p| &p.manifest.sections.git)
                    .filter(|_| !strict);
                let carry_from = previous_git
                    .and_then(|g| g.worktree_tree_id())
                    .map(str::to_owned);
                let carry_raw_from = previous_git
                    .and_then(|g| g.checkout_tree_id())
                    .map(str::to_owned);
                let raw_cache = self.staging.index_dir().join("raw-blobs.json");
                let git = gitpack::build_git_pack_with(
                    &repo,
                    &objects,
                    &previous_tips,
                    &excludes,
                    gitpack::TreeOptions {
                        carry_from: carry_from.as_deref(),
                        carry_raw_from: carry_raw_from.as_deref(),
                        raw_cache: Some(&raw_cache),
                    },
                )?;
                // What an operation in progress needs and git cannot name as one object: an
                // automatic snap carries what it can; a final one cannot say the capture holds
                // what the resumed operation needs, and fails (review 2026-09-28, fourth pass,
                // #3).
                let unresolved = &git.closure.unresolved_operations;
                if !unresolved.is_empty() {
                    if strict {
                        return Err(io::Error::other(format!(
                            "an operation in progress names objects git cannot resolve to \
                             exactly one, or has state that cannot be read: {}",
                            unresolved.join(", ")
                        ))
                        .into());
                    }
                    tracing::warn!(
                        unresolved = %unresolved.join(", "),
                        "an operation in progress names objects git cannot resolve to exactly \
                         one; a final flush over it is not complete"
                    );
                }
                let ref_format = self.ref_format(&git.closure.ref_format, strict)?;
                // A symlink git reads as `HEAD` or a ref, whose chain a restore cannot make
                // resolve the same way (it ends outside the repository): the symlink comes back
                // reaching nothing (review 2026-09-28, ninth pass, #2; decision 23).
                let unrestorable = &git.closure.unrestorable_ref_links;
                if !unrestorable.is_empty() {
                    let gap = format!(
                        "{} symlink(s) git reads as HEAD or a ref reach what a restore cannot \
                         bring back (outside the repository, or no ref the capture holds): {}",
                        unrestorable.len(),
                        unrestorable.join(", ")
                    );
                    if strict {
                        return Err(io::Error::other(gap).into());
                    }
                    tracing::warn!(%gap, "a final flush over them is not complete");
                }
                let mut git_unreadable: Vec<UnreadablePath> = git
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
                if let Some(missing) = &self.repair_git {
                    git_packs.retain(|k| !missing.contains(k));
                }
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
                let mut listing = self.workspace_listing(&repo, &git.closure.gitlinks)?;
                // Every nested repository and path git could not index is the workspace
                // class's to carry; one on disk that its listing does not hold would be
                // acknowledged as saved and restore as nothing.
                let uncarried = self.uncarried_gitlinks(&git.closure.gitlinks, &listing);
                if !uncarried.is_empty() {
                    if strict {
                        return Err(io::Error::other(format!(
                            "{} path(s) the worktree tree leaves to the workspace class are in \
                             no class: {}",
                            uncarried.len(),
                            uncarried.join(", ")
                        ))
                        .into());
                    }
                    for key in &uncarried {
                        let abs = self.config.root.join(crate::tree::os_of_key(key));
                        listing.note_unreadable(
                            format!("tree/{key}"),
                            abs,
                            &io::Error::other("a nested repository no class carries"),
                        );
                    }
                }
                // Nested repositories that share git storage (review 2026-09-28, tenth pass,
                // #2; decision 29): one that borrows the top-level object store gets the
                // objects its own state reaches there packed beside the closure; one that needs
                // storage outside the workspace cannot come back from this capture.
                let mut borrowed: Vec<String> = Vec::new();
                let mut unrepresentable: Vec<String> = Vec::new();
                for (key, dir, storage) in
                    nested_repositories(&repo, &self.config.root, &listing, "tree/")
                {
                    match storage {
                        gitpack::NestedStorage::BorrowsTop => {
                            let nested = GitRepo::open(&dir)?;
                            let (tips, unresolved) = gitpack::borrowed_objects(
                                &repo,
                                &nested,
                                &objects,
                                &git.closure.tips,
                            )?;
                            borrowed.extend(tips);
                            unrepresentable.extend(unresolved.into_iter().map(|u| {
                                format!("{key}: an operation in progress there names {u}")
                            }));
                        }
                        gitpack::NestedStorage::Unrepresentable(why) => {
                            unrepresentable.push(format!("{key}: {why}"));
                        }
                        gitpack::NestedStorage::Carried | gitpack::NestedStorage::TopWorktree => {}
                    }
                }
                if !unrepresentable.is_empty() {
                    let gap = format!(
                        "{} nested repositor{} keep git state a capture of the workspace cannot                          bring back: {}",
                        unrepresentable.len(),
                        if unrepresentable.len() == 1 {
                            "y"
                        } else {
                            "ies"
                        },
                        unrepresentable.join("; ")
                    );
                    if strict {
                        return Err(io::Error::other(gap).into());
                    }
                    tracing::warn!(%gap, "a final flush over them is not complete");
                }
                borrowed.sort();
                borrowed.dedup();
                if !borrowed.is_empty() {
                    let mut negatives = previous_tips.clone();
                    negatives.extend(git.closure.tips.iter().cloned());
                    if let Some(p) = gitpack::pack_tips(&repo, &objects, &borrowed, &negatives)? {
                        stats.git_pack_bytes += p.bytes;
                        stats.git_objects += p.objects;
                        let key = self.prefix.pack(&p.sha256);
                        uploads.push(Upload {
                            key: key.clone(),
                            file: p.sha256.clone(),
                            bytes: p.bytes,
                        });
                        uploads.push(Upload {
                            key: self.prefix.pack_idx(&p.sha256),
                            file: format!("{}.idx", p.sha256),
                            bytes: fs::metadata(&p.idx_path)?.len(),
                        });
                        if !git_packs.contains(&key) {
                            git_packs.push(key);
                        }
                    }
                }
                // The tree a restore checks out: the raw tree when the manifest names one.
                let checkout_tree = if self.config.git_trees {
                    git.closure.raw_tree.clone()
                } else {
                    git.closure.worktree_tree.clone()
                };
                // What the worktree tree does not carry: modes, mtimes, untracked directories,
                // hardlink groups.
                let meta_doc = match Some(&checkout_tree) {
                    Some(tree) => {
                        let captured = worktree_meta::capture(
                            &repo,
                            tree,
                            &self.meta_scope(&git.closure.gitlinks),
                            self.last_meta.as_ref().filter(|_| !strict),
                        )?;
                        // A path the tree holds as another kind than the disk does: the tree is
                        // not the disk there, and the overlay has no entry for it. A final snap
                        // cannot say it holds the disk (review 2026-09-28, fifth pass, #6).
                        if !captured.changed_kind.is_empty() {
                            if strict {
                                return Err(io::Error::other(format!(
                                    "{} path(s) of the worktree tree are of another kind on \
                                     disk: {}",
                                    captured.changed_kind.len(),
                                    captured.changed_kind.join(", ")
                                ))
                                .into());
                            }
                            tracing::warn!(
                                paths = %captured.changed_kind.join(", "),
                                "paths changed kind while the worktree tree was written; the \
                                 next snap takes them"
                            );
                        }
                        // Metadata the overlay could not read, under no path git already
                        // reported (a directory counts once): unreadable, never gone.
                        let meta_unreadable: Vec<UnreadablePath> = captured
                            .unreadable
                            .iter()
                            .map(|u| UnreadablePath {
                                path: format!("tree/{}", u.path),
                                error: u.error.clone(),
                                carried: u.carried,
                            })
                            .filter(|u| {
                                !git_unreadable.iter().any(|g| {
                                    u.path == g.path
                                        || u.path
                                            .strip_prefix(g.path.as_str())
                                            .is_some_and(|r| r.starts_with('/'))
                                })
                            })
                            .collect();
                        git_unreadable = merge_unreadable(git_unreadable, meta_unreadable);
                        // A wide time (outside signed 64-bit nanoseconds): the overlay records
                        // it exactly, and a store that does not read `wide_times` does not keep
                        // it — a final snap for one does not hold that path as it is (review
                        // 2026-09-28, ninth pass, #3; tenth pass).
                        if !captured.unrecordable_times.is_empty() && !self.config.reads_wide_times
                        {
                            if strict {
                                let times = captured
                                    .unrecordable_times
                                    .iter()
                                    .map(|u| UnreadablePath {
                                        path: format!("tree/{}", u.path),
                                        error: u.error.clone(),
                                        carried: false,
                                    })
                                    .collect();
                                git_unreadable = merge_unreadable(git_unreadable, times);
                            } else {
                                tracing::warn!(
                                    paths = %captured
                                        .unrecordable_times
                                        .iter()
                                        .map(|u| u.path.as_str())
                                        .collect::<Vec<_>>()
                                        .join(", "),
                                    "modification times outside signed 64-bit nanoseconds are \
                                     recorded exactly, and the store does not read wide_times: \
                                     a final flush over them is not complete"
                                );
                            }
                        }
                        // A symlink inode with more than one name: no class carries one
                        // inode for its names, and a restore would make each its own
                        // symlink. A final snap cannot say it holds the disk (review
                        // 2026-09-28, eighth pass, #3; decision 23).
                        let mut multi = captured.linked_symlinks.clone();
                        multi.extend(multi_named_symlinks(&listing));
                        if !multi.is_empty() {
                            if strict {
                                return Err(io::Error::other(multi_named_error(&multi)).into());
                            }
                            tracing::warn!(
                                paths = %multi.join(", "),
                                "symlinks with more than one name are captured as separate \
                                 symlinks; a final flush over them is not complete"
                            );
                        }
                        let mut linked = captured.linked.clone();
                        linked.extend(
                            listing
                                .entries
                                .values()
                                .filter_map(|src| LinkedName::of(&src.abs, &src.meta)),
                        );
                        self.linked = Some((Class::Small, linked));
                        let (cross_links, ws_outside, cross_deferred) =
                            self.cross_links(&captured.outside, &listing);
                        self.shared_outside = !captured.outside.is_empty() || ws_outside;
                        let mut doc = captured.doc;
                        doc.cross_links = cross_links;
                        // A tracked file under a bulk directory is the overlay's own name.
                        let own: HashSet<&str> =
                            doc.entries.iter().map(|e| e.path.as_str()).collect();
                        let (shared, shared_deferred) =
                            self.shared_links(&captured.outside, &listing);
                        self.links_deferred = cross_deferred || shared_deferred;
                        let shared = shared
                            .into_iter()
                            .filter(|l| {
                                l.class != worktree_meta::LinkClass::Bulk
                                    || !own.contains(l.member.as_str())
                            })
                            .collect();
                        doc.shared = shared;
                        // One inode, one mode, one mtime: names of one inode read with
                        // different ones moved while they were read. A final snap cannot say it
                        // holds the disk; any other takes the first name's and the next snap
                        // takes the change. Never a document no restore can keep (review
                        // 2026-09-28, seventh pass, #10).
                        if let Some(conflict) = doc.inode_conflict() {
                            if strict {
                                return Err(io::Error::other(format!(
                                    "a hardlinked file changed while it was read: {conflict}"
                                ))
                                .into());
                            }
                            let settled = doc.settle_inodes();
                            tracing::warn!(
                                %conflict,
                                paths = %settled.join(", "),
                                "hardlinked names read with different metadata; the next snap \
                                 takes the change"
                            );
                        }
                        Some(doc)
                    }
                    None => None,
                };
                let meta_bytes = meta_doc.as_ref().map(worktree_meta::MetaDocument::encode);
                let meta_chunks = meta_bytes.as_deref().map(chunk_bytes).unwrap_or_default();
                let Some(built) = self.build_class(
                    &listing,
                    Class::Small,
                    &meta_chunks,
                    &mut uploads,
                    &mut stats,
                    preempt,
                    strict,
                    git_unreadable,
                )?
                else {
                    return Err(io::Error::other("small-class build yielded").into());
                };
                let worktree_meta = match meta_bytes {
                    Some(bytes) => {
                        let mut packs: Vec<String> = Vec::new();
                        for c in &meta_chunks {
                            let key = self.chunks.packs.get(&c.id).ok_or_else(|| {
                                io::Error::other(format!(
                                    "worktree metadata chunk {} is in no pack",
                                    c.id
                                ))
                            })?;
                            if !packs.contains(key) {
                                packs.push(key.clone());
                            }
                        }
                        packs.sort();
                        Some(WorktreeMeta {
                            format: WORKTREE_META_FORMAT,
                            size: bytes.len() as u64,
                            sha256: sha256_hex(&bytes),
                            chunks: meta_chunks.iter().map(|c| c.id).collect(),
                            packs,
                        })
                    }
                    None => None,
                };
                // Only a snap that goes on to stage its git pack makes that pack's tips the next
                // pack's negatives: a snap that fails here (a final one that cannot read work)
                // stages nothing, and its tips would leave objects out of every later pack.
                self.last_tips = git.closure.tips.clone();
                self.last_tips.extend(borrowed);
                self.last_tips.sort();
                self.last_tips.dedup();
                self.last_meta.clone_from(&meta_doc);
                self.repair_git = None;
                let closure = git.closure;
                let git_section = if self.config.git_trees {
                    GitSection {
                        packs: git_packs,
                        refs: closure.refs,
                        head: closure.head,
                        fsck: git.fsck,
                        symrefs: closure.symrefs,
                        worktree_tree: Some(closure.worktree_tree),
                        index_tree: closure.index_tree,
                        raw_tree: Some(closure.raw_tree),
                        object_format: object_format.clone(),
                        ref_format: ref_format.clone(),
                    }
                } else {
                    // A registrar that does not read `git_trees`: the trees ride `refs` as the
                    // pseudo-refs, as before, over any user ref of the same name.
                    let mut refs = closure.refs;
                    for name in [WORKTREE_TREE_REF, INDEX_TREE_REF] {
                        if refs.contains_key(name) {
                            tracing::warn!(
                                name,
                                "a ref of the repository has the name the registrar reads a tree \
                                 under; it is not captured (the registrar does not read \
                                 git_trees)"
                            );
                        }
                    }
                    refs.insert(WORKTREE_TREE_REF.to_owned(), closure.worktree_tree);
                    match closure.index_tree {
                        Some(tree) => {
                            refs.insert(INDEX_TREE_REF.to_owned(), tree);
                        }
                        None => {
                            refs.remove(INDEX_TREE_REF);
                        }
                    }
                    GitSection {
                        packs: git_packs,
                        refs,
                        head: closure.head,
                        fsck: git.fsck,
                        symrefs: closure.symrefs,
                        worktree_tree: None,
                        index_tree: None,
                        raw_tree: None,
                        object_format: object_format.clone(),
                        ref_format: ref_format.clone(),
                    }
                };
                Sections {
                    git: git_section,
                    workspace: WorkspaceSection {
                        root: built.root,
                        packs: built.packs,
                        format: built.format,
                        dir_packs: built.dir_packs,
                        worktree_meta,
                        root_links: listing
                            .root_links
                            .iter()
                            .map(|(root, link)| {
                                (root.clone(), crate::tree::key_of(link).into_owned())
                            })
                            .collect(),
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
                // A nested repository under a bulk directory whose git storage is not all
                // carried as files: this class cannot join what it borrows from the top-level
                // store to the git section, and nothing carries storage outside the workspace
                // (review 2026-09-28, tenth pass, #2; decision 29).
                if let Ok(repo) = GitRepo::open(&self.config.root) {
                    let shared: Vec<String> =
                        nested_repositories(&repo, &self.config.root, &listing, "")
                            .into_iter()
                            .filter_map(|(key, _, storage)| match storage {
                                gitpack::NestedStorage::Carried
                                | gitpack::NestedStorage::TopWorktree => None,
                                gitpack::NestedStorage::BorrowsTop => Some(format!(
                                    "{key}: it borrows objects from the top-level object store,                                      which a bulk capture does not join to the git section"
                                )),
                                gitpack::NestedStorage::Unrepresentable(why) => {
                                    Some(format!("{key}: {why}"))
                                }
                            })
                            .collect();
                    if !shared.is_empty() {
                        let gap = format!(
                            "{} nested repositor{} under a bulk directory keep git state a                              capture of the workspace cannot bring back: {}",
                            shared.len(),
                            if shared.len() == 1 { "y" } else { "ies" },
                            shared.join("; ")
                        );
                        if req.kind == CaptureKind::Final {
                            return Err(io::Error::other(gap).into());
                        }
                        tracing::warn!(%gap, "a final flush over them is not complete");
                    }
                }
                let multi = multi_named_symlinks(&listing);
                if !multi.is_empty() {
                    if req.kind == CaptureKind::Final {
                        return Err(io::Error::other(multi_named_error(&multi)).into());
                    }
                    tracing::warn!(
                        paths = %multi.join(", "),
                        "symlinks with more than one name are captured as separate symlinks; a \
                         final flush over them is not complete"
                    );
                }
                self.linked = Some((
                    Class::Bulk,
                    listing
                        .entries
                        .values()
                        .filter_map(|src| LinkedName::of(&src.abs, &src.meta))
                        .collect(),
                ));
                let Some(built) = self.build_class(
                    &listing,
                    Class::Bulk,
                    &[],
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
        // A repair snap takes the refused capture's place: no hoist, no coalescing, never
        // "unchanged".
        let repairing = self.repair_target.take();
        let hoist = match req.class {
            Class::Small if repairing.is_none() => self.hoist_target()?,
            _ => None,
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
        // does a final flush's bulk snap (its small snap is the capture that marks the end), a
        // final snap over a final capture (the same final flush asked again), or a suspend snap
        // over a final capture (a suspend flush after the final one: the chain must end on the
        // final capture, and a suspend capture of the same tree after it only hid it).
        let over_final = follows.is_some_and(|p| p.manifest.kind == CaptureKind::Final);
        if repairing.is_none()
            && (req.kind == CaptureKind::Auto
                || (req.kind == CaptureKind::Final && (req.class == Class::Bulk || over_final))
                || (req.kind == CaptureKind::Suspend && over_final))
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
        let coalesce = if req.kind == CaptureKind::Auto && repairing.is_none() {
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
        let (n, parent) = match (&coalesce, &hoist, &repairing) {
            (_, _, Some(target)) => (target.entry.n, target.entry.register.parent.clone()),
            (Some(old), _, None) => (old.n, old.register.parent.clone()),
            (None, Some((bulk, _)), None) => (bulk.n, bulk.register.parent.clone()),
            (None, None, None) => (
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
            final_seal: None,
        }
        .encode();
        let manifest_key = self.prefix.manifest(&manifest.capture_id);
        let manifest_file = format!("manifest-{}", manifest.capture_id);
        let manifest_path = objects.join(&manifest_file);
        fs::write(&manifest_path, &manifest.bytes).at("write", &manifest_path)?;
        let mut all_uploads: Vec<Upload> = Vec::new();
        if let Some(target) = &repairing {
            // Everything the replaced captures staged but their manifests: this manifest may
            // name any of it (a follower's git pack, a bulk section it carries) — but never a
            // key the refusal named: that one is not put again (decision 6); what it held was
            // staged again above under the new key generation.
            for u in std::iter::once(&target.entry)
                .chain(&target.followers)
                .flat_map(|e| &e.uploads)
                .filter(|u| !u.file.starts_with("manifest-") && !target.forget.contains(&u.key))
            {
                if !all_uploads.iter().any(|e| e.key == u.key) {
                    all_uploads.push(u.clone());
                }
            }
        }
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
            if !all_uploads.iter().any(|e| e.key == u.key) {
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
        if repairing.is_some() {
            self.below = None;
        } else if req.class == Class::Bulk {
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
        let newest = match (&hoist, &repairing) {
            (_, Some(target)) => {
                // One journaled step: this capture at the refused one's `n`, the refused one
                // and every capture staged after it superseded (their objects ride along).
                let mut superseded = vec![target.entry.clone()];
                superseded.extend(target.followers.iter().cloned());
                if let Err(error) = self
                    .staging
                    .restage(std::slice::from_ref(&entry), &superseded)
                {
                    if self.staging.restage_pending() {
                        tracing::warn!(%error, "restage interrupted; finishing it from its journal");
                        self.staging.recover()?;
                    } else {
                        return Err(error.into());
                    }
                }
                tracing::warn!(
                    n,
                    replaced = %target.entry.capture_id,
                    folded = target.followers.len(),
                    class = ?req.class,
                    "refused capture rebuilt from disk in its place"
                );
                manifest.clone()
            }
            (Some((bulk, _)), None) => {
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
            (None, None) => {
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

    /// Whether the last small snap's worktree metadata overlay depends on the bulk index: it
    /// found tracked files with names another class carries, or workspace-class files with
    /// names the workspace class does not hold, and records the bulk class's names of them as
    /// the last bulk snap indexed them. A final flush whose bulk snap staged a
    /// capture snaps the small class again then, so the chain's last capture records them as
    /// they are (Docker end to end, round 3: the flush after the one that reported `complete`
    /// registered a final capture whose only difference was these links).
    #[must_use]
    pub fn small_depends_on_bulk(&self) -> bool {
        self.shared_outside
    }

    /// Whether the last small snap left a link to a bulk name out because the bulk capture
    /// does not hold that name as the disk has it (it changed, or gained a name, since the
    /// last bulk snap): a small snap after the next bulk snap records it. A final flush takes
    /// that snap, and is not complete while a link is still left out.
    #[must_use]
    pub fn links_deferred(&self) -> bool {
        self.links_deferred
    }

    /// End the chain in a final capture: when the newest capture is of another kind, stage a
    /// final one with its sections — nothing is read, and the capture holds nothing new. A final
    /// flush calls this after both final snaps, which found the disk as that capture holds it
    /// (a scheduled bulk capture the final small snap was staged ahead of is the newest one, and
    /// the final bulk snap found it unchanged). Without it the flush reported `complete` with a
    /// head of kind `auto`, and the next final flush staged the final capture instead (Docker
    /// end to end, round 3: two captures registered after `complete: true`). `None` when the
    /// newest capture is final already, or there is none.
    ///
    /// # Errors
    /// Staging I/O.
    pub fn seal_final(&mut self, seq: u64) -> Result<Option<StagedCapture>, EngineError> {
        let Some(prev) = self.previous.as_ref() else {
            return Ok(None);
        };
        if prev.manifest.kind == CaptureKind::Final {
            return Ok(None);
        }
        self.stage_over_previous(seq, None).map(Some)
    }

    /// The seal this engine writes once a final flush completed: complete, its epoch and its
    /// executor. `None` without an executor.
    #[must_use]
    pub fn final_seal(&self) -> Option<FinalSeal> {
        self.config.executor.as_ref().map(|executor| FinalSeal {
            complete: true,
            epoch: self.config.epoch,
            executor: executor.clone(),
            boot_id: None,
            boot_generation: None,
            observation: None,
        })
    }

    /// Whether the newest capture carries this engine's seal ([`Self::final_seal`]), so a
    /// complete final flush has nothing left to seal. True without an executor: there is
    /// nothing it could seal under.
    #[must_use]
    pub fn completion_sealed(&self) -> bool {
        match self.final_seal() {
            None => true,
            Some(seal) => self.previous.as_ref().is_some_and(|p| {
                p.manifest
                    .final_seal
                    .as_ref()
                    .is_some_and(|s| s.same_executor(&seal))
            }),
        }
    }

    /// The register of the newest capture when it carries this engine's seal
    /// ([`Self::completion_sealed`]): sent again, it asks the registrar where the seal stands
    /// ([`crate::ship::Shipper::seal_standing`], decision 22). `None` when there is no such
    /// capture (or no executor to seal under).
    #[must_use]
    pub fn sealing_register(&self) -> Option<RegisterRequest> {
        let seal = self.final_seal()?;
        let prev = self.previous.as_ref()?;
        prev.manifest
            .final_seal
            .as_ref()
            .is_some_and(|s| s.same_executor(&seal))
            .then(|| RegisterRequest {
                worktree_id: prev.manifest.worktree_id.clone(),
                epoch: prev.manifest.epoch,
                n: prev.manifest.n,
                parent: prev.manifest.parent.clone(),
                capture_id: prev.capture_id.clone(),
                manifest_key: self.prefix.manifest(&prev.capture_id),
                manifest: prev.manifest.clone(),
            })
    }

    /// Seal a completed final flush on the chain ([`crate::manifest::FinalSeal`]): stage one
    /// more capture over the newest one — its sections unchanged, `kind: final` — carrying this
    /// engine's seal. The caller vouches that the flush completed: every writer stopped, both
    /// classes snapped after that, and everything staged before registered. `None` when the
    /// newest capture carries the seal already ([`Self::completion_sealed`]), there is no
    /// capture, or no executor to seal under.
    ///
    /// # Errors
    /// Staging I/O.
    pub fn seal_complete(&mut self, seq: u64) -> Result<Option<StagedCapture>, EngineError> {
        let Some(seal) = self.final_seal() else {
            return Ok(None);
        };
        if self.previous.is_none() || self.completion_sealed() {
            return Ok(None);
        }
        // Where the seal stands in this executor's order (decision 17): after every answer
        // given before it, before every answer given after.
        let seal = self.observer.observe(|at| FinalSeal {
            boot_id: Some(at.boot_id),
            boot_generation: Some(at.boot_generation),
            observation: Some(at.observation),
            ..seal
        });
        let staged = self.stage_over_previous(seq, Some(seal.clone()))?;
        tracing::info!(
            n = staged.n,
            epoch = seal.epoch,
            executor = %seal.executor,
            boot_generation = ?seal.boot_generation,
            observation = ?seal.observation,
            "final seal staged: the final flush completed"
        );
        Ok(Some(staged))
    }

    /// Stage a final capture over the newest one with its sections, carrying `final_seal`.
    fn stage_over_previous(
        &mut self,
        seq: u64,
        final_seal: Option<FinalSeal>,
    ) -> Result<StagedCapture, EngineError> {
        let Some(prev) = self.previous.clone() else {
            return Err(EngineError::Io(io::Error::other(
                "no capture to stage a final one over",
            )));
        };
        let sealing = final_seal.is_some();
        let staging = Arc::clone(&self.staging);
        let guard = staging.coalesce_guard();
        let n = prev.manifest.n + 1;
        let manifest = Manifest {
            worktree_id: self.config.worktree_id.clone(),
            n,
            parent: Some(prev.capture_id.clone()),
            epoch: self.config.epoch,
            seq,
            kind: CaptureKind::Final,
            created_at: rfc3339_now(),
            sections: prev.manifest.sections.clone(),
            checkpoint: None,
            final_seal,
        }
        .encode();
        let manifest_key = self.prefix.manifest(&manifest.capture_id);
        let manifest_file = format!("manifest-{}", manifest.capture_id);
        let manifest_path = self.staging.objects_dir().join(&manifest_file);
        fs::write(&manifest_path, &manifest.bytes).at("write", &manifest_path)?;
        let uploads = vec![Upload {
            key: manifest_key.clone(),
            file: manifest_file,
            bytes: manifest.bytes.len() as u64,
        }];
        let stats = SnapStats {
            staged_bytes: manifest.bytes.len() as u64,
            ..SnapStats::default()
        };
        let entry = QueueEntry {
            n,
            capture_id: manifest.capture_id.clone(),
            kind: CaptureKind::Final,
            class: Some(Class::Small),
            uploads,
            register: RegisterRequest {
                worktree_id: self.config.worktree_id.clone(),
                epoch: self.config.epoch,
                n,
                parent: manifest.manifest.parent.clone(),
                capture_id: manifest.capture_id.clone(),
                manifest_key: manifest_key.clone(),
                manifest: manifest.manifest.clone(),
            },
        };
        self.staging.enqueue(&entry)?;
        drop(guard);
        self.previous = Some(manifest.clone());
        self.persist()?;
        if !sealing {
            tracing::info!(
                n,
                sealed = prev.manifest.n,
                sealed_kind = ?prev.manifest.kind,
                "final capture staged over the newest capture, which the final snaps found current"
            );
        }
        Ok(StagedCapture {
            n,
            manifest,
            manifest_key,
            kind: CaptureKind::Final,
            class: Class::Small,
            stats,
            unchanged: false,
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

    /// A nested repository (or a path git could not index) that holds something on disk is
    /// the workspace class's to carry: one its listing does not hold is reported, and a final
    /// snap refuses to call it saved. Carried at or under its `tree/` path, under a bulk
    /// directory (the bulk class's), an empty directory (a submodule never checked out) or a
    /// path gone from disk are not.
    #[test]
    fn a_nested_repository_no_class_carries_is_reported() {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path().join("ws");
        std::fs::create_dir_all(root.join("nested")).unwrap();
        std::fs::write(root.join("nested/work.txt"), b"nested work").unwrap();
        std::fs::create_dir_all(root.join("empty")).unwrap();
        std::fs::create_dir_all(root.join("node_modules/dep")).unwrap();
        std::fs::write(root.join("node_modules/dep/x.js"), b"x").unwrap();
        git(&root, &["init", "-q", "-b", "main"]);
        let engine = CaptureEngine::open(CaptureConfig::new("wt", 1, &root), None).unwrap();
        let gitlinks: Vec<String> = ["empty", "gone", "nested", "node_modules/dep"]
            .iter()
            .map(|s| (*s).to_owned())
            .collect();
        let mut listing = Listing::default();
        assert_eq!(
            engine.uncarried_gitlinks(&gitlinks, &listing),
            vec!["nested".to_owned()]
        );
        let meta = std::fs::symlink_metadata(root.join("nested/work.txt")).unwrap();
        listing.entries.insert(
            "tree/nested/work.txt".to_owned(),
            index::Source {
                abs: root.join("nested/work.txt"),
                meta,
            },
        );
        assert!(engine.uncarried_gitlinks(&gitlinks, &listing).is_empty());
    }

    /// Finding 1b of the third Docker end to end, through the engine: a path whose metadata
    /// cannot be read no longer fails the snap. An automatic snap stages the change beside it
    /// and counts it unreadable (its last capture carried); a final snap fails `unreadable`,
    /// naming the path, rather than stage a capture that lacks it.
    #[test]
    fn a_metadata_error_on_one_path_does_not_stop_the_snap() {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path().join("ws");
        std::fs::create_dir_all(root.join("src")).unwrap();
        git(&root, &["init", "-q", "-b", "main"]);
        git(&root, &["config", "user.email", "t@t"]);
        git(&root, &["config", "user.name", "t"]);
        std::fs::write(root.join("src/lib.rs"), "pub fn f() {}\n").unwrap();
        std::fs::write(root.join("notes.txt"), "notes\n").unwrap();
        git(&root, &["add", "-A"]);
        git(&root, &["commit", "-q", "-m", "one"]);
        let mut engine = CaptureEngine::open(CaptureConfig::new("wt", 1, &root), None).unwrap();
        let req = |kind| SnapRequest {
            kind,
            class: Class::Small,
            seq: 1,
        };
        let first = engine.snap(req(CaptureKind::Auto)).unwrap();
        assert_eq!(first.stats.unreadable, 0);

        crate::longpath::inject_fault(&root.join("notes.txt"), nix::libc::EIO);
        std::fs::write(root.join("src/lib.rs"), "pub fn f() { g() }\n").unwrap();
        let second = engine.snap(req(CaptureKind::Auto)).unwrap();
        assert!(!second.unchanged, "the edit beside it is staged");
        assert_eq!(second.stats.unreadable, 1, "{:?}", second.stats);
        assert_eq!(second.stats.carried, 1, "{:?}", second.stats);
        assert_eq!(second.stats.unreadable_paths, ["tree/notes.txt"]);

        let error = engine.snap(req(CaptureKind::Final)).unwrap_err();
        let work = error.unreadable().expect("fails as unreadable work");
        assert_eq!(work.paths.len(), 1, "{work}");
        assert_eq!(work.paths[0].0, "tree/notes.txt");
    }

    /// Docker end to end, round 4: two suspend flushes after a final one staged two `suspend`
    /// captures of the same tree over the final capture, and the chain's head read `suspend`.
    /// A suspend snap over a final capture of an unchanged tree stages nothing, whatever the
    /// watcher says (this is the engine, below it); one over a changed tree still does.
    #[test]
    fn a_suspend_snap_over_a_final_capture_of_the_same_tree_stages_nothing() {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path().join("ws");
        std::fs::create_dir_all(root.join("src")).unwrap();
        git(&root, &["init", "-q", "-b", "main"]);
        git(&root, &["config", "user.email", "t@t"]);
        git(&root, &["config", "user.name", "t"]);
        std::fs::write(root.join("src/lib.rs"), "pub fn f() {}\n").unwrap();
        git(&root, &["add", "-A"]);
        git(&root, &["commit", "-q", "-m", "one"]);
        let mut engine = CaptureEngine::open(CaptureConfig::new("wt", 1, &root), None).unwrap();
        let req = |kind, seq| SnapRequest {
            kind,
            class: Class::Small,
            seq,
        };
        let last = engine.snap(req(CaptureKind::Final, 1)).unwrap();
        assert!(!last.unchanged);
        for seq in 2..4 {
            let again = engine.snap(req(CaptureKind::Suspend, seq)).unwrap();
            assert!(again.unchanged, "nothing staged over the final capture");
            assert_eq!(again.n, last.n);
        }
        assert_eq!(
            engine.previous().unwrap().manifest.kind,
            CaptureKind::Final,
            "the chain still ends on the final capture"
        );

        std::fs::write(root.join("src/lib.rs"), "pub fn f() { g() }\n").unwrap();
        let changed = engine.snap(req(CaptureKind::Suspend, 4)).unwrap();
        assert!(!changed.unchanged, "a change is staged");
        assert_eq!(changed.manifest.manifest.kind, CaptureKind::Suspend);
    }
}
