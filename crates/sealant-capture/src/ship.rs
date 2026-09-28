//! Staging and shipping. Snaps are staged on local disk under `<workspace root>/.sealantd/capture/`
//! (the same filesystem as the tree); a worker uploads oldest-first with retry and coalescing,
//! then registers. One pass runs at a time. A bulk capture's objects upload unclaimed and yield
//! between objects: to a capture staged ahead of it (the engine stages small captures ahead of a
//! bulk one still uploading) and to a waiting flush, which registers every capture ahead of the
//! bulk one and returns. The queue follows the `Spool` discipline of ADR-0007 (append → replay → ack,
//! a disk bound), not its record format: one JSON entry per capture, one ack marker per object.
//! The shipper is throttled to ≤ 50% of one core as a CPU-time duty cycle from `getrusage`;
//! objects at or above [`MultipartConfig::threshold`] go up as multipart uploads with several
//! parts in flight, whose threads' CPU is charged to the same cycle (network waits are not).
//! Smaller objects go up [`DEFAULT_UPLOADS_IN_FLIGHT`] at a time, a batch of URLs minted in one
//! channel call ahead of their PUTs; their threads' CPU is charged to the cycle as well.

use std::collections::{BTreeMap, HashSet};
use std::fs;
use std::io;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};

use serde::{Deserialize, Serialize};

use crate::cpu::thread_cpu;
use crate::engine::Class;
use crate::io_at::IoAt;
use crate::manifest::CaptureKind;
use crate::registrar::{RegisterRequest, Registrar, RegistrarError, opt};
use crate::sink::{BlobSink, BlobSource, SinkError};

/// Lock, taking the value of a poisoned lock as it is.
fn lock<T>(mutex: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    mutex
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
}

/// Which slot of [`Shipper::held`] a class uses (an entry without a class is a small one).
fn class_slot(class: Option<Class>) -> usize {
    usize::from(class == Some(Class::Bulk))
}

/// Default shipper CPU budget: half of one core.
pub const DEFAULT_CPU_FRACTION: f64 = 0.5;

/// Most single-PUT objects whose URLs are minted in one channel call.
pub const PREFETCH_BATCH: usize = 500;

/// After a byte-quota refusal the shipper asks again after 30 s, doubling per refusal in a row
/// up to 10 minutes: each ask is one `upload.urls` (or `capture.register`) call against the
/// registrar's call quota.
pub const HOLD_BACKOFF: (Duration, Duration) = (Duration::from_secs(30), Duration::from_secs(600));

/// After the registrar answers that the worktree lease is not live (409 `lease-lost`) the shipper
/// pauses and asks again after 1 s, doubling per answer in a row up to 30 s. The lease comes back
/// when the control plane renews or re-grants it; until then nothing can register, and nothing
/// staged is dropped either.
pub const LEASE_LOST_BACKOFF: (Duration, Duration) =
    (Duration::from_secs(1), Duration::from_secs(30));

/// Single-PUT uploads in flight at once. A presigned PUT from a MicroVM to S3 is a round trip of
/// ≈ 70 ms whatever the object's size (measured on alpha, 2026-09-27: 20,878 objects in 24
/// minutes one at a time), so the small objects of a capture are latency-bound, not
/// bandwidth-bound.
pub const DEFAULT_UPLOADS_IN_FLIGHT: usize = 8;

/// How large objects are uploaded. Measured (R1, 2026-09): one presigned PUT from a sandbox to
/// R2 runs at 37–47 MB/s, four multipart parts in flight at 63.6 MB/s; AWS single-stream is
/// ≈ 100 MB/s per flow.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MultipartConfig {
    /// Objects at or above this size are uploaded as multipart (below: one PUT).
    pub threshold: u64,
    /// Preferred part size; a store that fixes its own (the registrar's `part_size`) wins.
    pub part_size: u64,
    /// Parts uploading at once per object.
    pub parts_in_flight: usize,
}

impl MultipartConfig {
    /// 16 MiB threshold, 16 MiB parts, 4 in flight.
    pub const DEFAULT: Self = Self {
        threshold: 16 * 1024 * 1024,
        part_size: 16 * 1024 * 1024,
        parts_in_flight: 4,
    };
}

impl Default for MultipartConfig {
    fn default() -> Self {
        Self::DEFAULT
    }
}

/// One object to upload: a key and a file under the staging objects directory.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Upload {
    /// Store key.
    pub key: String,
    /// File name under `objects/`.
    pub file: String,
    /// Bytes.
    pub bytes: u64,
}

/// One staged capture.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct QueueEntry {
    /// Chain position.
    pub n: u64,
    /// Capture id.
    pub capture_id: String,
    /// Kind.
    pub kind: CaptureKind,
    /// The class the snap built; `None` for an entry an older daemon staged.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub class: Option<Class>,
    /// Objects in write order (packs, trees), the manifest last.
    pub uploads: Vec<Upload>,
    /// The register call.
    pub register: RegisterRequest,
}

/// A capture the registrar refused for the session's byte quota. Nothing is dropped: the capture
/// stays queued with every staged byte, its class is reported refused in `capture.status`, and
/// the shipper asks again after a backoff (the budget frees as retention retires packs, or the
/// control plane raises it). Work product is never discarded for a quota.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct HeldCapture {
    /// Chain position of the refused capture.
    pub n: u64,
    /// Its capture id.
    pub capture_id: String,
    /// Its class, when the entry names one.
    pub class: Option<Class>,
    /// The registrar's reason code (`byte-quota`).
    pub reason: String,
    /// The session's budget in bytes, when the answer names it.
    pub limit: Option<u64>,
    /// Bytes priced against the session so far.
    pub used: Option<u64>,
    /// Bytes the refused call asked for.
    pub requested: Option<u64>,
    /// Refusals in a row for this class.
    pub refusals: u32,
    /// When the shipper asks again.
    #[serde(skip)]
    pub retry_at: Instant,
}

/// A capture the registrar refused to register (422 `missing-objects` / `unrestorable`): an
/// object it names is not in the store, or was condemned by retention and is refused by name
/// for good. The engine rebuilds it from disk in its place — same `n`, same parent, the named
/// packs forgotten so their chunks are read and packed again, under a new key generation so no
/// key the refusal named is ever put again ([`crate::keys`]) — and nothing is dropped: the captures staged after it are folded into the
/// rebuilt one, which holds the disk as it is now ([`crate::engine::CaptureEngine::repair`]).
/// Kept in staging (`repair.json`), so a restart finishes it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RepairRequest {
    /// Chain position of the refused capture.
    pub n: u64,
    /// Its capture id.
    pub capture_id: String,
    /// Its class, when the entry names one.
    pub class: Option<Class>,
    /// `missing-objects` or `unrestorable`.
    pub reason: String,
    /// The keys the registrar named (empty: none named).
    pub missing: Vec<String>,
}

/// The register refusal the shipper is working through, for `capture.status`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct RegisterRefusal {
    /// Chain position of the refused capture.
    pub n: u64,
    /// Its capture id.
    pub capture_id: String,
    /// Its class, when the entry names one.
    pub class: Option<Class>,
    /// `missing-objects` or `unrestorable`.
    pub reason: String,
    /// The keys the registrar named.
    pub missing: Vec<String>,
    /// Refusals of this capture in a row.
    pub refusals: u32,
}

/// Shipping errors.
#[derive(Debug, thiserror::Error)]
pub enum ShipError {
    /// The registrar fenced this epoch; shipping stopped.
    #[error("fenced: {0}")]
    Fenced(RegistrarError),
    /// The chain moved under us (another writer with our epoch, or a lost coalesce).
    #[error("chain conflict: {0}")]
    Conflict(RegistrarError),
    /// The registrar answered that the worktree lease is not live (409 `lease-lost`, or a
    /// heartbeat that renewed nothing). Not a conflict: the chain is as it was. The shipper
    /// pauses and asks again after a backoff ([`LEASE_LOST_BACKOFF`]); everything stays staged.
    #[error("lease lost; shipping paused")]
    LeaseLost,
    /// The registrar refused this capture's bytes for the session's byte quota. The entry stays
    /// queued with its staged bytes ([`HeldCapture`]) and is asked for again after a backoff.
    #[error("refused ({reason}): limit {}, used {}, requested {}", opt(.limit), opt(.used), opt(.requested))]
    QuotaRefused {
        /// The registrar's reason code (`byte-quota`).
        reason: String,
        /// The session's budget in bytes, when the answer names it.
        limit: Option<u64>,
        /// Bytes priced against the session so far.
        used: Option<u64>,
        /// Bytes the refused call asked for.
        requested: Option<u64>,
    },
    /// The registrar refused to register this capture (422 `missing-objects` /
    /// `unrestorable`). The entry stays queued; see [`RepairRequest`].
    #[error("register n={n} refused ({reason}): {message}")]
    RegisterRefused {
        /// Position.
        n: u64,
        /// `missing-objects` or `unrestorable`.
        reason: String,
        /// Keys the registrar named.
        missing: Vec<String>,
        /// The registrar's message.
        message: String,
    },
    /// The capture at the head of the queue waits for the engine to rebuild it from disk
    /// ([`RepairRequest`]); nothing behind it can register first.
    #[error("capture n={n} was refused and waits to be rebuilt from disk")]
    RepairPending {
        /// Position.
        n: u64,
    },
    /// The lease was fenced before (or while) this flush ran: nothing staged can register any
    /// more. `pending` captures are still staged on this disk.
    #[error("fenced: the lease is fenced; {pending} captures cannot register")]
    AlreadyFenced {
        /// Captures still staged.
        pending: usize,
    },
    /// The caller's deadline passed with captures still staged.
    #[error("deadline passed with {pending} captures pending")]
    Deadline {
        /// Captures still staged.
        pending: usize,
    },
    /// Upload failed after retries.
    #[error("upload {key}: {source}")]
    Upload {
        /// Key.
        key: String,
        /// Cause.
        source: SinkError,
    },
    /// Register failed after retries.
    #[error("register n={n}: {source}")]
    Register {
        /// Position.
        n: u64,
        /// Cause.
        source: RegistrarError,
    },
    /// Staging I/O.
    #[error(transparent)]
    Io(#[from] io::Error),
    /// A queue entry could not be parsed.
    #[error("bad queue entry {path}: {reason}")]
    BadEntry {
        /// Path.
        path: PathBuf,
        /// Why.
        reason: String,
    },
}

/// The file (beside `queue/`) that makes a restage one step: see [`Staging::restage`].
const RESTAGE_JOURNAL: &str = "restage.json";

/// The file (beside `queue/`) holding every identity's key generation (`<worktree>/<epoch>` →
/// generation; [`Staging::key_generation`]).
const KEY_GENERATIONS: &str = "key-generations.json";

/// The file (beside `queue/`) holding a [`RepairRequest`].
const REPAIR_REQUEST: &str = "repair.json";

/// Queue writes that land together or not at all ([`Staging::restage`]).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Restage {
    /// Entries written, in this order (a queue file per entry, over whatever held its `n`).
    pub write: Vec<QueueEntry>,
    /// Entries they supersede: the queue file of one whose `n` no written entry takes is
    /// removed, and object files no queued entry lists any more are swept.
    pub superseded: Vec<QueueEntry>,
}

/// Write `bytes` to `path` and flush them to the disk.
fn write_synced(path: &Path, bytes: &[u8]) -> io::Result<()> {
    use std::io::Write;
    let mut file = fs::File::create(path).at("create", path)?;
    file.write_all(bytes).at("write", path)?;
    file.sync_all().at("sync", path)
}

/// Flush a directory's entries (a rename, a removal) to the disk. Best effort: some
/// filesystems refuse to open a directory for it.
fn sync_dir(dir: &Path) {
    if let Ok(d) = fs::File::open(dir) {
        let _ = d.sync_all();
    }
}

/// The staging area.
#[derive(Debug)]
pub struct Staging {
    dir: PathBuf,
    /// The worktree and epoch this executor stages under. A re-plan (`capture.replan`) moves
    /// it; entries staged under another identity are foreign and never shipped.
    identity: Mutex<(String, u64)>,
    in_flight: Mutex<Option<u64>>,
    /// Held by the engine from `coalescible` to `replace` / `enqueue`, and by the shipper while
    /// it claims an entry: a pending `auto` capture is never coalesced away under a shipper that
    /// has started on it, and never claimed once replaced.
    coalesce: Mutex<()>,
    /// Bumped on every queue change (an entry staged, replaced, acked or dropped). A shipper
    /// uploading a bulk capture's objects checks it between objects, so a capture staged ahead
    /// of that bulk capture ships first.
    generation: AtomicU64,
    /// Test hook: a restage fails as a crash would after this many of its steps (0: never).
    crash_at: AtomicU64,
    /// Restage steps taken since the hook was set.
    steps: AtomicU64,
}

impl Staging {
    /// Open (and create) staging at `dir` for `worktree_id` at `epoch`. Upload acks are kept
    /// per worktree and epoch: an object acked under a prior identity was written under a
    /// prior prefix and must be uploaded again.
    pub fn open(dir: &Path, worktree_id: &str, epoch: u64) -> io::Result<Self> {
        for sub in ["objects", "queue", "scratch", "index", "cache"] {
            fs::create_dir_all(dir.join(sub))?;
        }
        let staging = Self {
            dir: dir.to_path_buf(),
            identity: Mutex::new((worktree_id.to_owned(), epoch)),
            in_flight: Mutex::new(None),
            coalesce: Mutex::new(()),
            generation: AtomicU64::new(0),
            crash_at: AtomicU64::new(0),
            steps: AtomicU64::new(0),
        };
        fs::create_dir_all(staging.marker_dir())?;
        // A restage the process did not finish (it died between two of its renames) is
        // finished before anything reads the queue.
        if let Some(journal) = staging.recover()? {
            tracing::warn!(
                written = ?journal.write.iter().map(|e| e.n).collect::<Vec<_>>(),
                "an interrupted restage was finished from its journal"
            );
        }
        Ok(staging)
    }

    /// Stage several queue changes as one step: a small capture staged ahead of a queued bulk
    /// capture writes the bulk capture again at `n + 1` (its parent the small capture) and the
    /// small capture in the bulk capture's old slot. A process that died between those two
    /// renames left a queue whose bulk capture named a parent no entry held — it could never
    /// register, and nothing behind it could either. Now the whole change is written first as a
    /// journal (`restage.json`, synced, then renamed into place: the commit point), then
    /// applied; a restage the process did not finish is finished by [`Staging::recover`], which
    /// [`Staging::open`] runs, so a crash anywhere leaves either the queue as it was or the
    /// queue as the restage makes it. Every object file an entry lists must be on disk before
    /// this is called. Call under [`Staging::coalesce_guard`].
    pub fn restage(&self, write: &[QueueEntry], superseded: &[QueueEntry]) -> io::Result<()> {
        let journal = Restage {
            write: write.to_vec(),
            superseded: superseded.to_vec(),
        };
        let path = self.dir.join(RESTAGE_JOURNAL);
        let tmp = path.with_extension("tmp");
        write_synced(&tmp, &serde_json::to_vec(&journal)?)?;
        self.step()?;
        fs::rename(&tmp, &path).at("rename into", &path)?;
        sync_dir(&self.dir);
        self.step()?;
        self.apply_restage(&journal)
    }

    /// Finish a restage the journal holds, if one does (a process died before it was done).
    /// Idempotent: each step writes or removes what the journal names. Returns the journal it
    /// finished.
    ///
    /// # Errors
    /// I/O, or a journal that does not parse (it is written whole before it is renamed into
    /// place, so that is corruption, and the queue is left as it is for a person to look at).
    pub fn recover(&self) -> io::Result<Option<Restage>> {
        let path = self.dir.join(RESTAGE_JOURNAL);
        let bytes = match fs::read(&path) {
            Ok(bytes) => bytes,
            Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(None),
            Err(e) => return Err(e),
        };
        let journal: Restage = serde_json::from_slice(&bytes).map_err(|e| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                format!("{}: {e}", path.display()),
            )
        })?;
        self.apply_restage(&journal)?;
        Ok(Some(journal))
    }

    /// Whether a restage is committed and not applied yet: the queue may be half-way, so
    /// nothing ships until it is finished.
    #[must_use]
    pub fn restage_pending(&self) -> bool {
        self.dir.join(RESTAGE_JOURNAL).exists()
    }

    fn apply_restage(&self, journal: &Restage) -> io::Result<()> {
        for entry in &journal.write {
            let path = self.queue_path(entry.n);
            let tmp = path.with_extension("tmp");
            write_synced(&tmp, &serde_json::to_vec(entry)?)?;
            fs::rename(tmp, &path).at("rename into", &path)?;
            self.step()?;
        }
        let written: HashSet<u64> = journal.write.iter().map(|e| e.n).collect();
        for old in &journal.superseded {
            if !written.contains(&old.n) {
                match fs::remove_file(self.queue_path(old.n)) {
                    Err(e) if e.kind() != io::ErrorKind::NotFound => return Err(e),
                    _ => {}
                }
                self.step()?;
            }
        }
        sync_dir(&self.dir.join("queue"));
        self.bump();
        for old in &journal.superseded {
            self.sweep(old)?;
        }
        self.step()?;
        match fs::remove_file(self.dir.join(RESTAGE_JOURNAL)) {
            Err(e) if e.kind() != io::ErrorKind::NotFound => return Err(e),
            _ => {}
        }
        sync_dir(&self.dir);
        Ok(())
    }

    /// One restage step; from the step the test hook names on, every step fails, as nothing
    /// runs any more in a process that died there.
    fn step(&self) -> io::Result<()> {
        let at = self.crash_at.load(Ordering::SeqCst);
        let n = self.steps.fetch_add(1, Ordering::SeqCst) + 1;
        if at != 0 && n >= at {
            return Err(io::Error::other(format!(
                "injected crash after restage step {at}"
            )));
        }
        Ok(())
    }

    /// Test hook: restages fail, as a process dying there would, after `step` of their steps
    /// (1: the journal is written but not committed; 2: committed; then one per queue file
    /// written or removed; then the sweep), and every step after it fails too. 0 turns it off.
    #[doc(hidden)]
    pub fn crash_restage_after(&self, step: u64) {
        self.steps.store(0, Ordering::SeqCst);
        self.crash_at.store(step, Ordering::SeqCst);
    }

    /// The worktree and epoch entries are staged under.
    #[must_use]
    pub fn identity(&self) -> (String, u64) {
        self.identity
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clone()
    }

    /// Move to `worktree_id` at `epoch` (a re-plan). Ack markers of the previous identity stay
    /// on disk and stop counting; entries already queued become foreign.
    pub fn set_identity(&self, worktree_id: &str, epoch: u64) -> io::Result<()> {
        *self
            .identity
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = (worktree_id.to_owned(), epoch);
        fs::create_dir_all(self.marker_dir())
    }

    /// Whether `entry` was staged under another identity than the current one.
    #[must_use]
    pub fn is_foreign(&self, entry: &QueueEntry) -> bool {
        let (worktree_id, epoch) = self.identity();
        entry.register.worktree_id != worktree_id || entry.register.epoch != epoch
    }

    /// Drop every queued entry staged under another identity that the shipper is not on right
    /// now, with the object files only they referenced. Returns how many went. Call with the
    /// engine held: a later `auto` snap must not coalesce with a foreign entry.
    pub fn discard_foreign(&self) -> io::Result<usize> {
        let _g = self.coalesce_guard();
        let in_flight = *self
            .in_flight
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let mut dropped = 0;
        for entry in self.pending()? {
            if !self.is_foreign(&entry) || in_flight == Some(entry.n) {
                continue;
            }
            fs::remove_file(self.queue_path(entry.n)).ok();
            self.bump();
            self.sweep(&entry)?;
            dropped += 1;
        }
        Ok(dropped)
    }

    /// Changes whenever the queue does.
    #[must_use]
    pub fn generation(&self) -> u64 {
        self.generation.load(Ordering::SeqCst)
    }

    fn bump(&self) {
        self.generation.fetch_add(1, Ordering::SeqCst);
    }

    fn in_flight(&self) -> Option<u64> {
        *self
            .in_flight
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    /// Root.
    #[must_use]
    pub fn dir(&self) -> &Path {
        &self.dir
    }

    /// Where packs, trees and manifests are written before upload.
    #[must_use]
    pub fn objects_dir(&self) -> PathBuf {
        self.dir.join("objects")
    }

    /// Scratch space (temporary git indexes).
    #[must_use]
    pub fn scratch_dir(&self) -> PathBuf {
        self.dir.join("scratch")
    }

    /// Persisted tree indexes and the chunk map.
    #[must_use]
    pub fn index_dir(&self) -> PathBuf {
        self.dir.join("index")
    }

    /// Materialize-side pack cache.
    #[must_use]
    pub fn cache_dir(&self) -> PathBuf {
        self.dir.join("cache")
    }

    fn queue_path(&self, n: u64) -> PathBuf {
        self.dir.join("queue").join(format!("{n:020}.json"))
    }

    /// Where the acks of objects uploaded under the current identity and key `generation` are
    /// kept (`None`: keys written before generations, whose acks sit directly under the
    /// identity, where an older build left them).
    fn marker_dir_of(&self, generation: Option<u64>) -> PathBuf {
        let (worktree_id, epoch) = self.identity();
        let dir = self
            .dir
            .join("uploaded")
            .join(worktree_id.replace('/', "_"))
            .join(epoch.to_string());
        match generation {
            Some(generation) => dir.join(format!("g{generation}")),
            None => dir,
        }
    }

    fn marker_dir(&self) -> PathBuf {
        self.marker_dir_of(Some(self.key_generation()))
    }

    /// The ack of `file` uploaded to `key`: kept per key generation, since an object file (named
    /// by its content) goes up under a new key in each generation it is staged in.
    fn marker_path(&self, key: &str, file: &str) -> PathBuf {
        self.marker_dir_of(crate::keys::key_generation(key))
            .join(file)
    }

    /// Whether an object file was acked as uploaded to `key`.
    #[must_use]
    pub fn is_uploaded(&self, key: &str, file: &str) -> bool {
        self.marker_path(key, file).exists()
    }

    /// Whether an object file was acked as uploaded under the current key generation.
    #[must_use]
    pub fn is_uploaded_now(&self, file: &str) -> bool {
        self.marker_dir().join(file).exists()
    }

    /// Ack an object file uploaded to `key`.
    pub fn mark_uploaded(&self, key: &str, file: &str) -> io::Result<()> {
        let path = self.marker_path(key, file);
        if let Some(dir) = path.parent() {
            fs::create_dir_all(dir).at("mkdir -p", dir)?;
        }
        fs::write(&path, b"").at("write", &path)
    }

    /// Drop an object file's ack for `key` (the registrar said the store does not hold it): a
    /// build stages it again.
    pub fn unmark_uploaded(&self, key: &str, file: &str) -> io::Result<()> {
        match fs::remove_file(self.marker_path(key, file)) {
            Err(e) if e.kind() != io::ErrorKind::NotFound => Err(e),
            _ => Ok(()),
        }
    }

    /// The key generation objects are staged under now, for the current identity
    /// ([`crate::keys`]): 0 until a refused capture is first rebuilt.
    #[must_use]
    pub fn key_generation(&self) -> u64 {
        let (worktree_id, epoch) = self.identity();
        self.key_generations()
            .get(&format!("{worktree_id}/{epoch}"))
            .copied()
            .unwrap_or(0)
    }

    fn key_generations(&self) -> BTreeMap<String, u64> {
        fs::read(self.dir.join(KEY_GENERATIONS))
            .ok()
            .and_then(|b| serde_json::from_slice(&b).ok())
            .unwrap_or_default()
    }

    /// Move the current identity's key generation on, durably, before anything is staged under
    /// it (a refused capture is about to be rebuilt): nothing staged from now on reuses a key
    /// the registrar may have condemned. Returns the new generation.
    pub fn next_key_generation(&self) -> io::Result<u64> {
        let (worktree_id, epoch) = self.identity();
        let mut all = self.key_generations();
        let slot = all.entry(format!("{worktree_id}/{epoch}")).or_insert(0);
        *slot += 1;
        let next = *slot;
        let path = self.dir.join(KEY_GENERATIONS);
        let tmp = path.with_extension("tmp");
        write_synced(&tmp, &serde_json::to_vec(&all)?)?;
        fs::rename(&tmp, &path).at("rename into", &path)?;
        sync_dir(&self.dir);
        fs::create_dir_all(self.marker_dir())?;
        Ok(next)
    }

    /// Ask the engine to rebuild a refused capture from disk ([`RepairRequest`]).
    pub fn request_repair(&self, request: &RepairRequest) -> io::Result<()> {
        let path = self.dir.join(REPAIR_REQUEST);
        let tmp = path.with_extension("tmp");
        write_synced(&tmp, &serde_json::to_vec(request)?)?;
        fs::rename(&tmp, &path).at("rename into", &path)?;
        sync_dir(&self.dir);
        self.bump();
        Ok(())
    }

    /// The pending [`RepairRequest`], if any (one that does not parse reads as none, and is
    /// asked for again at the next refusal).
    #[must_use]
    pub fn repair_request(&self) -> Option<RepairRequest> {
        fs::read(self.dir.join(REPAIR_REQUEST))
            .ok()
            .and_then(|b| serde_json::from_slice(&b).ok())
    }

    /// The repair is done (or its capture is no longer queued).
    pub fn clear_repair(&self) -> io::Result<()> {
        match fs::remove_file(self.dir.join(REPAIR_REQUEST)) {
            Err(e) if e.kind() != io::ErrorKind::NotFound => Err(e),
            _ => {
                self.bump();
                Ok(())
            }
        }
    }

    /// Append an entry (write-then-rename).
    pub fn enqueue(&self, entry: &QueueEntry) -> io::Result<()> {
        let path = self.queue_path(entry.n);
        let tmp = path.with_extension("tmp");
        fs::write(&tmp, serde_json::to_vec(entry)?).at("write", &tmp)?;
        fs::rename(tmp, &path).at("rename into", &path)?;
        self.bump();
        Ok(())
    }

    /// Pending entries, oldest first. Unparseable entries are skipped with a warning.
    pub fn pending(&self) -> io::Result<Vec<QueueEntry>> {
        let mut entries = Vec::new();
        for d in fs::read_dir(self.dir.join("queue"))? {
            let d = d?;
            let path = d.path();
            if path.extension().is_some_and(|e| e == "json") {
                match fs::read(&path).map(|b| serde_json::from_slice::<QueueEntry>(&b)) {
                    Ok(Ok(e)) => entries.push(e),
                    Ok(Err(e)) => {
                        tracing::warn!(path = %path.display(), error = %e, "bad queue entry")
                    }
                    Err(e) => {
                        tracing::warn!(path = %path.display(), error = %e, "unreadable queue entry")
                    }
                }
            }
        }
        entries.sort_by_key(|e| e.n);
        Ok(entries)
    }

    /// Hold while deciding to coalesce and until the replacement is enqueued
    /// ([`Staging::coalescible`] → [`Staging::replace`]); the shipper waits on it to claim.
    pub fn coalesce_guard(&self) -> std::sync::MutexGuard<'_, ()> {
        self.coalesce
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    fn read_entry(&self, n: u64) -> Option<QueueEntry> {
        fs::read(self.queue_path(n))
            .ok()
            .and_then(|b| serde_json::from_slice(&b).ok())
    }

    /// Claim `entry` for shipping: mark it in flight if it is still queued unchanged. `false`
    /// when it was coalesced away (or acked) meanwhile; the caller re-reads the queue.
    #[must_use]
    pub fn claim(&self, entry: &QueueEntry) -> bool {
        let _g = self.coalesce_guard();
        let current = self.read_entry(entry.n);
        let mut in_flight = self
            .in_flight
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        match current {
            Some(e) if e.capture_id == entry.capture_id => {
                *in_flight = Some(entry.n);
                true
            }
            _ => {
                *in_flight = None;
                false
            }
        }
    }

    /// The shipper is done with the claimed entry (shipped or failed).
    pub fn release(&self) {
        *self
            .in_flight
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = None;
    }

    /// The newest pending entry if it is an `auto` capture not yet being shipped: the one a new
    /// `auto` snap may coalesce with (taking its `n` and parent). Call under
    /// [`Staging::coalesce_guard`] and keep the guard until the replacement is enqueued.
    pub fn coalescible(&self) -> io::Result<Option<QueueEntry>> {
        let pending = self.pending()?;
        let Some(last) = pending.last() else {
            return Ok(None);
        };
        if last.kind == CaptureKind::Auto && self.in_flight() != Some(last.n) {
            Ok(Some(last.clone()))
        } else {
            Ok(None)
        }
    }

    /// The entry right below `top` (the bulk capture a small snap is staged ahead of) if it is
    /// an `auto` small-class capture not being shipped: the one that small snap may coalesce
    /// with. Call under [`Staging::coalesce_guard`].
    pub fn coalescible_below(&self, top: &QueueEntry) -> io::Result<Option<QueueEntry>> {
        let pending = self.pending()?;
        let Some(below) = pending.iter().rev().find(|e| e.n < top.n) else {
            return Ok(None);
        };
        if below.kind == CaptureKind::Auto
            && below.class != Some(Class::Bulk)
            && self.in_flight() != Some(below.n)
        {
            Ok(Some(below.clone()))
        } else {
            Ok(None)
        }
    }

    /// The bulk capture a small snap may be staged ahead of: the newest pending entry, when it
    /// is a bulk capture under this identity that the shipper is not registering. Its objects
    /// may be uploading; they are content-addressed and stay with it, only its manifest (its
    /// `n` and parent) moves. Call under [`Staging::coalesce_guard`].
    pub fn hoistable(&self) -> io::Result<Option<QueueEntry>> {
        let pending = self.pending()?;
        Ok(pending
            .last()
            .filter(|e| {
                e.class == Some(Class::Bulk) && self.in_flight() != Some(e.n) && !self.is_foreign(e)
            })
            .cloned())
    }

    /// Remove an entry and every object file no remaining entry references.
    pub fn ack(&self, entry: &QueueEntry) -> io::Result<()> {
        fs::remove_file(self.queue_path(entry.n)).or_else(|e| {
            if e.kind() == io::ErrorKind::NotFound {
                Ok(())
            } else {
                Err(e)
            }
        })?;
        self.bump();
        self.sweep(entry)
    }

    /// Replace `old` by `new` (coalescing): the old queue entry is removed, objects only it
    /// referenced are deleted.
    pub fn replace(&self, old: &QueueEntry, new: &QueueEntry) -> io::Result<()> {
        self.enqueue(new)?;
        if old.n != new.n {
            fs::remove_file(self.queue_path(old.n)).ok();
        }
        self.sweep(old)
    }

    /// Remove the object files of `removed` (an entry no longer queued at its `n`) that no queued
    /// entry lists.
    pub fn sweep(&self, removed: &QueueEntry) -> io::Result<()> {
        self.discard_unreferenced(&removed.uploads).map(|_| ())
    }

    /// Remove the object files of `uploads` that no queued entry lists; the names removed.
    /// Object bytes go; the ack markers stay, so an unchanged dir object or pack listed by a
    /// later capture is neither re-staged nor re-uploaded within this epoch. A file a queued
    /// entry still lists stays: the shipper reads it from here when that entry's turn comes.
    pub fn discard_unreferenced(&self, uploads: &[Upload]) -> io::Result<HashSet<String>> {
        let still: HashSet<String> = self
            .pending()?
            .iter()
            .flat_map(|e| e.uploads.iter().map(|u| u.file.clone()))
            .collect();
        let mut removed = HashSet::new();
        for u in uploads {
            if !still.contains(&u.file) {
                fs::remove_file(self.objects_dir().join(&u.file)).ok();
                removed.insert(u.file.clone());
            }
        }
        Ok(removed)
    }

    /// Bytes `entries` still have to upload: every object they list that is not acked as
    /// uploaded, an object two entries share counted once. What would be lost if this disk went
    /// now (the objects themselves stay on disk until their entries register).
    #[must_use]
    pub fn pending_bytes(&self, entries: &[QueueEntry]) -> u64 {
        let mut seen: HashSet<&str> = HashSet::new();
        entries
            .iter()
            .flat_map(|e| &e.uploads)
            .filter(|u| seen.insert(u.key.as_str()) && !self.is_uploaded(&u.key, &u.file))
            .map(|u| u.bytes)
            .sum()
    }

    /// Bytes of staged objects not yet acked.
    pub fn staged_bytes(&self) -> io::Result<u64> {
        let mut total = 0;
        for d in fs::read_dir(self.objects_dir())? {
            let d = d?;
            if d.file_type()?.is_file() {
                total += d.metadata()?.len();
            }
        }
        Ok(total)
    }

    /// Bytes staged on this disk that no queued entry lists and no upload took: the packs a
    /// bulk build in progress has written so far (they join a capture when the build ends). What
    /// a drain must still count while the build runs.
    pub fn unqueued_bytes(&self, queued: &[QueueEntry]) -> io::Result<u64> {
        let listed: HashSet<&str> = queued
            .iter()
            .flat_map(|e| e.uploads.iter().map(|u| u.file.as_str()))
            .collect();
        let mut total = 0;
        for d in fs::read_dir(self.objects_dir())? {
            let d = d?;
            let name = d.file_name();
            let name = name.to_string_lossy();
            if d.file_type()?.is_file()
                && !listed.contains(name.as_ref())
                && !self.is_uploaded_now(&name)
            {
                total += d.metadata()?.len();
            }
        }
        Ok(total)
    }
}

/// A CPU-time duty cycle (amendment decision 12): after each unit of work, if this thread's CPU
/// time since the cycle began exceeds `fraction` of the wall time, sleep the difference.
#[derive(Debug)]
pub struct DutyCycle {
    fraction: f64,
    started: Instant,
    cpu_start: Duration,
    /// CPU burnt on this cycle's behalf by other threads.
    charged: Duration,
    /// Total time slept.
    pub slept: Duration,
}

impl DutyCycle {
    /// A cycle allowing `fraction` (0 < f ≤ 1) of one core; `≥ 1.0` never sleeps.
    #[must_use]
    pub fn new(fraction: f64) -> Self {
        Self {
            fraction: fraction.clamp(0.01, 1.0),
            started: Instant::now(),
            cpu_start: thread_cpu(),
            charged: Duration::ZERO,
            slept: Duration::ZERO,
        }
    }

    /// Count CPU time another thread burnt for this cycle (part-upload workers).
    pub fn charge(&mut self, cpu: Duration) {
        self.charged += cpu;
    }

    /// Sleep if over budget.
    pub fn pace(&mut self) {
        let sleep = self.debt(thread_cpu());
        if !sleep.is_zero() {
            thread::sleep(sleep);
        }
    }

    /// The sleep that brings the cycle back under budget (at most half a second), with
    /// `own_cpu` the owning thread's CPU clock now; counted as slept. A helper thread that
    /// charged its CPU sleeps this itself, outside any lock, while the owner waits for it.
    fn debt(&mut self, own_cpu: Duration) -> Duration {
        if self.fraction >= 1.0 {
            return Duration::ZERO;
        }
        let cpu = (own_cpu.saturating_sub(self.cpu_start) + self.charged).as_secs_f64();
        let wall = self.started.elapsed().as_secs_f64();
        let allowed = wall * self.fraction;
        if cpu <= allowed {
            return Duration::ZERO;
        }
        let sleep = Duration::from_secs_f64((cpu / self.fraction - wall).min(0.5));
        self.slept += sleep;
        sleep
    }
}

/// Live counters.
#[derive(Debug, Default)]
pub struct ShipStatus {
    /// Objects uploaded.
    pub uploaded_objects: AtomicU64,
    /// Bytes uploaded.
    pub uploaded_bytes: AtomicU64,
    /// Objects skipped as already present.
    pub already_present: AtomicU64,
    /// Captures registered.
    pub registered: AtomicU64,
    /// Highest registered n (u64::MAX = none).
    pub head_n: AtomicU64,
    /// Whether the epoch was fenced.
    pub fenced: AtomicBool,
    /// Failed attempts (uploads and registers).
    pub failures: AtomicU64,
    /// A small capture the registrar refused for the session's byte quota is held: queued with
    /// its bytes and asked for again after a backoff. Cleared when the class registers.
    pub refused_small: AtomicBool,
    /// A bulk capture is held for the byte quota, as `refused_small`. The class keeps snapping
    /// (a newer bulk capture replaces the held one) and nothing is dropped.
    pub refused_bulk: AtomicBool,
    /// The registrar answered that the worktree lease is not live (409 `lease-lost`): shipping
    /// is paused and asked again after a backoff. Cleared by the next upload or register that
    /// goes through.
    pub lease_lost: AtomicBool,
    /// Register refusals (422 `missing-objects` / `unrestorable`) seen.
    pub register_refusals: AtomicU64,
    /// The capture at the head of the queue waits to be rebuilt from disk ([`RepairRequest`]).
    pub repair_pending: AtomicBool,
}

impl ShipStatus {
    /// Snapshot as plain numbers.
    #[must_use]
    pub fn snapshot(&self) -> ShipSnapshot {
        ShipSnapshot {
            uploaded_objects: self.uploaded_objects.load(Ordering::Relaxed),
            uploaded_bytes: self.uploaded_bytes.load(Ordering::Relaxed),
            already_present: self.already_present.load(Ordering::Relaxed),
            registered: self.registered.load(Ordering::Relaxed),
            head_n: Some(self.head_n.load(Ordering::Relaxed)).filter(|n| *n != u64::MAX),
            fenced: self.fenced.load(Ordering::Relaxed),
            failures: self.failures.load(Ordering::Relaxed),
            refused_small: self.refused_small.load(Ordering::Relaxed),
            refused_bulk: self.refused_bulk.load(Ordering::Relaxed),
            lease_lost: self.lease_lost.load(Ordering::Relaxed),
            register_refusals: self.register_refusals.load(Ordering::Relaxed),
            repair_pending: self.repair_pending.load(Ordering::Relaxed),
        }
    }

    /// The flag for `class`.
    #[must_use]
    pub fn refused_flag(&self, class: Class) -> &AtomicBool {
        match class {
            Class::Small => &self.refused_small,
            Class::Bulk => &self.refused_bulk,
        }
    }
}

/// A point-in-time copy of [`ShipStatus`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct ShipSnapshot {
    /// Objects uploaded.
    pub uploaded_objects: u64,
    /// Bytes uploaded.
    pub uploaded_bytes: u64,
    /// Objects already present.
    pub already_present: u64,
    /// Captures registered.
    pub registered: u64,
    /// Highest registered n.
    pub head_n: Option<u64>,
    /// Fenced.
    pub fenced: bool,
    /// Failed attempts.
    pub failures: u64,
    /// The small class was refused for the byte quota.
    pub refused_small: bool,
    /// The bulk class was refused for the byte quota.
    pub refused_bulk: bool,
    /// The registrar answered that the lease is not live; shipping is paused.
    pub lease_lost: bool,
    /// Register refusals (422 `missing-objects` / `unrestorable`) seen.
    pub register_refusals: u64,
    /// The capture at the head of the queue waits to be rebuilt from disk.
    pub repair_pending: bool,
}

/// Retry policy for one pass.
#[derive(Debug, Clone, Copy)]
pub struct RetryPolicy {
    /// Attempts per object / register within one pass.
    pub attempts: u32,
    /// First backoff; doubles per attempt.
    pub backoff: Duration,
    /// Backoff cap.
    pub max_backoff: Duration,
}

impl Default for RetryPolicy {
    fn default() -> Self {
        Self {
            attempts: 5,
            backoff: Duration::from_millis(200),
            max_backoff: Duration::from_secs(5),
        }
    }
}

/// Why a pass stopped uploading a bulk capture's objects.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Stop {
    /// The queue changed: re-read it (a capture was staged ahead, or the bulk capture moved).
    Changed,
    /// A flush is waiting for the pass.
    Waiting,
    /// The caller's deadline passed.
    Deadline,
}

/// Which captures a pass is after.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Scope {
    /// Everything pending.
    All,
    /// Every capture ahead of a bulk capture whose objects are still uploading: what a change
    /// or a diff needs. The bulk capture keeps uploading in the worker.
    AheadOfBulk,
}

/// What one pass got through.
#[derive(Debug, Clone, Copy, Default)]
struct Pass {
    shipped: usize,
    /// The scope is shipped: the queue is empty, or only bulk captures still uploading are left.
    done: bool,
    /// The pass stopped uploading a bulk capture's objects for a waiting flush.
    yielded: bool,
    /// The pass stopped at a refused capture waiting for the engine to rebuild it.
    repair: Option<u64>,
}

/// Uploads staged captures oldest-first and registers each, one pass at a time.
pub struct Shipper {
    staging: Arc<Staging>,
    sink: Arc<dyn BlobSink>,
    registrar: Arc<dyn Registrar>,
    cpu_fraction: f64,
    retry: RetryPolicy,
    multipart: MultipartConfig,
    /// Single-PUT uploads in flight at once.
    uploads_in_flight: usize,
    /// Held by a pass. Two passes over one queue raced for the same objects: each consumed PUT
    /// URLs the other had minted, the loser minted one key per call, and the registrar's
    /// `upload.urls` call quota ran out (observed: `no url for …/trees/<sha>` after a flush ran
    /// beside the worker through an 800 MB bulk upload).
    pass: Mutex<()>,
    /// Flushes waiting for the pass; the worker's bulk upload yields to them.
    waiting: AtomicUsize,
    /// Per class, the capture held for the byte quota and when to ask again.
    held: Mutex<[Option<HeldCapture>; 2]>,
    /// First wait after a byte-quota refusal and its cap; doubles per refusal in a row.
    hold_backoff: (Duration, Duration),
    /// Lease-lost answers in a row, and when shipping asks again.
    lease: Mutex<(u32, Option<Instant>)>,
    /// First wait after a lease-lost answer and its cap; doubles per answer in a row.
    lease_backoff: (Duration, Duration),
    /// The register refusal being worked through (cleared when that capture registers or is
    /// no longer queued).
    refusal: Mutex<Option<RegisterRefusal>>,
    /// Called when a refused capture needs the engine ([`RepairRequest`]): the cadence runner
    /// wakes its small-class loop, whose next snap rebuilds it.
    repair_hook: Mutex<Option<Arc<dyn Fn() + Send + Sync>>>,
    /// Counters.
    pub status: Arc<ShipStatus>,
}

impl std::fmt::Debug for Shipper {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Shipper")
            .field("staging", &self.staging.dir)
            .finish_non_exhaustive()
    }
}

impl Shipper {
    /// A shipper over `staging`.
    #[must_use]
    pub fn new(
        staging: Arc<Staging>,
        sink: Arc<dyn BlobSink>,
        registrar: Arc<dyn Registrar>,
    ) -> Self {
        let status = Arc::new(ShipStatus::default());
        status.head_n.store(u64::MAX, Ordering::Relaxed);
        Self {
            staging,
            sink,
            registrar,
            cpu_fraction: DEFAULT_CPU_FRACTION,
            retry: RetryPolicy::default(),
            multipart: MultipartConfig::DEFAULT,
            uploads_in_flight: DEFAULT_UPLOADS_IN_FLIGHT,
            pass: Mutex::new(()),
            waiting: AtomicUsize::new(0),
            held: Mutex::new([None, None]),
            hold_backoff: HOLD_BACKOFF,
            lease: Mutex::new((0, None)),
            lease_backoff: LEASE_LOST_BACKOFF,
            refusal: Mutex::new(None),
            repair_hook: Mutex::new(None),
            status,
        }
    }

    /// Multipart threshold, part size and parts in flight.
    #[must_use]
    pub fn with_multipart(mut self, multipart: MultipartConfig) -> Self {
        self.multipart = multipart;
        self
    }

    /// Single-PUT uploads in flight at once (1 = one at a time).
    #[must_use]
    pub fn with_uploads_in_flight(mut self, uploads: usize) -> Self {
        self.uploads_in_flight = uploads.max(1);
        self
    }

    /// CPU budget as a fraction of one core.
    #[must_use]
    pub fn with_cpu_fraction(mut self, fraction: f64) -> Self {
        self.cpu_fraction = fraction;
        self
    }

    /// Retry policy.
    #[must_use]
    pub fn with_retry(mut self, retry: RetryPolicy) -> Self {
        self.retry = retry;
        self
    }

    /// The wait after a byte-quota refusal (`first`, doubling up to `max`); [`HOLD_BACKOFF`].
    #[must_use]
    pub fn with_hold_backoff(mut self, first: Duration, max: Duration) -> Self {
        self.hold_backoff = (first, max);
        self
    }

    /// The wait after a lease-lost answer (`first`, doubling up to `max`);
    /// [`LEASE_LOST_BACKOFF`].
    #[must_use]
    pub fn with_lease_backoff(mut self, first: Duration, max: Duration) -> Self {
        self.lease_backoff = (first, max);
        self
    }

    /// The registrar answered that the lease is not live: pause shipping until the backoff
    /// runs out. Nothing is dropped and nothing is a conflict; the harness is paused by the
    /// heartbeat, not here.
    fn lease_lost(&self) {
        let mut lease = lock(&self.lease);
        lease.0 += 1;
        let (first, max) = self.lease_backoff;
        let wait = first.saturating_mul(1u32 << (lease.0 - 1).min(16)).min(max);
        lease.1 = Some(Instant::now() + wait);
        let answers = lease.0;
        drop(lease);
        self.status.lease_lost.store(true, Ordering::Relaxed);
        tracing::warn!(
            answers,
            retry_in_ms = wait.as_millis() as u64,
            "the registrar answered lease-lost; shipping paused, everything stays staged"
        );
    }

    /// An upload or a register went through: the lease is live again.
    fn lease_ok(&self) {
        if self.status.lease_lost.swap(false, Ordering::Relaxed) {
            *lock(&self.lease) = (0, None);
            tracing::info!("the lease is live again; shipping resumed");
        }
    }

    /// When shipping asks again after a lease-lost answer, while that is still ahead.
    fn lease_retry_at(&self) -> Option<Instant> {
        lock(&self.lease).1.filter(|at| Instant::now() < *at)
    }

    /// The captures held for the byte quota, per class: queued with their bytes, asked for
    /// again at `retry_at`.
    #[must_use]
    pub fn held(&self) -> Vec<HeldCapture> {
        lock(&self.held).iter().flatten().cloned().collect()
    }

    /// Whether `entry`'s class is held for the byte quota and its backoff has not run out.
    /// The register refusal being worked through, if any.
    #[must_use]
    pub fn register_refusal(&self) -> Option<RegisterRefusal> {
        lock(&self.refusal).clone()
    }

    /// Set what is called when a refused capture needs the engine to rebuild it.
    pub fn set_repair_hook(&self, hook: Arc<dyn Fn() + Send + Sync>) {
        *lock(&self.repair_hook) = Some(hook);
    }

    fn call_repair_hook(&self) {
        let hook = lock(&self.repair_hook).clone();
        if let Some(hook) = hook {
            hook();
        }
    }

    /// Whether `entry` waits for the engine to rebuild it ([`RepairRequest`]).
    fn awaiting_repair(&self, entry: &QueueEntry) -> bool {
        self.staging
            .repair_request()
            .is_some_and(|r| r.n == entry.n && r.capture_id == entry.capture_id)
    }

    /// The registrar refused `entry`: ask the engine to rebuild it from disk (nothing registers
    /// until it has). Never by putting the same keys again (cross-repo decision 6):
    /// a key a register was refused for may be one retention condemned, which the registrar
    /// refuses for good — and a delete retention paused would take it back out of the store
    /// under any capture that named it again. The rebuild moves the key generation on first
    /// ([`Staging::next_key_generation`]), so what it uploads, even the same bytes, goes up
    /// under keys no refusal ever named. (Before, the first refusal of a capture whose named
    /// keys it had staged itself put those same keys again.)
    fn after_refusal(
        &self,
        entry: &QueueEntry,
        reason: &str,
        missing: &[String],
    ) -> io::Result<()> {
        self.status
            .register_refusals
            .fetch_add(1, Ordering::Relaxed);
        let refusals = {
            let mut refusal = lock(&self.refusal);
            let refusals = refusal
                .as_ref()
                .filter(|r| r.capture_id == entry.capture_id)
                .map_or(0, |r| r.refusals)
                + 1;
            *refusal = Some(RegisterRefusal {
                n: entry.n,
                capture_id: entry.capture_id.clone(),
                class: entry.class,
                reason: reason.to_owned(),
                missing: missing.to_vec(),
                refusals,
            });
            refusals
        };
        tracing::warn!(
            n = entry.n,
            capture = %entry.capture_id,
            class = ?entry.class,
            reason,
            missing = ?missing,
            refusals,
            "capture register refused; the capture stays queued"
        );
        self.staging.request_repair(&RepairRequest {
            n: entry.n,
            capture_id: entry.capture_id.clone(),
            class: entry.class,
            reason: reason.to_owned(),
            missing: missing.to_vec(),
        })?;
        self.status.repair_pending.store(true, Ordering::Relaxed);
        tracing::warn!(
            n = entry.n,
            capture = %entry.capture_id,
            "the refused capture is rebuilt from disk in its place"
        );
        self.call_repair_hook();
        Ok(())
    }

    fn held_back(&self, entry: &QueueEntry) -> bool {
        lock(&self.held)[class_slot(entry.class)]
            .as_ref()
            .is_some_and(|h| Instant::now() < h.retry_at)
    }

    /// Whether shipping is fenced.
    #[must_use]
    pub fn is_fenced(&self) -> bool {
        self.status.fenced.load(Ordering::Relaxed)
    }

    /// Whether a capture of `class` is held for the session's byte quota (queued with its bytes,
    /// asked for again after a backoff).
    #[must_use]
    pub fn is_refused(&self, class: Class) -> bool {
        self.status.refused_flag(class).load(Ordering::Relaxed)
    }

    /// Lift the fence and the byte-quota refusals after a re-plan gave this executor a fresh
    /// identity: what was fenced (and what was refused) belonged to the previous epoch. `head_n`
    /// is the plan's head, or none for an empty chain.
    pub fn reset_after_replan(&self, head_n: Option<u64>) {
        self.status.fenced.store(false, Ordering::Relaxed);
        self.status.refused_small.store(false, Ordering::Relaxed);
        self.status.refused_bulk.store(false, Ordering::Relaxed);
        *lock(&self.held) = [None, None];
        self.status
            .head_n
            .store(head_n.unwrap_or(u64::MAX), Ordering::Relaxed);
    }

    fn backoff(&self, attempt: u32) -> Duration {
        let mult = 1u32 << attempt.min(10);
        (self.retry.backoff * mult).min(self.retry.max_backoff)
    }

    /// Upload one object on this thread, charging the sink's helper threads (multipart parts)
    /// to `cycle` and pacing after it.
    fn upload_one(&self, u: &Upload, cycle: &mut DutyCycle) -> Result<(), ShipError> {
        let helper_before = self.sink.helper_cpu();
        let result = self.put_object(u);
        cycle.charge(self.sink.helper_cpu().saturating_sub(helper_before));
        if result.is_ok() {
            cycle.pace();
        }
        result
    }

    /// Upload one object with retry and ack it; nothing is paced here.
    fn put_object(&self, u: &Upload) -> Result<(), ShipError> {
        if self.staging.is_uploaded(&u.key, &u.file) {
            return Ok(());
        }
        let path = self.staging.objects_dir().join(&u.file);
        let mut last: Option<SinkError> = None;
        for attempt in 0..self.retry.attempts {
            if !path.exists() {
                // The bytes were swept after an earlier ack of another entry; the store has them.
                match self.sink.exists(&u.key) {
                    Ok(true) => {
                        self.staging.mark_uploaded(&u.key, &u.file)?;
                        return Ok(());
                    }
                    Ok(false) => {
                        return Err(ShipError::Upload {
                            key: u.key.clone(),
                            source: SinkError::NotFound(u.file.clone()),
                        });
                    }
                    Err(e) => {
                        last = Some(e);
                    }
                }
            } else {
                let result = if u.bytes >= self.multipart.threshold {
                    self.sink.put_multipart(
                        &u.key,
                        &path,
                        self.multipart.part_size,
                        self.multipart.parts_in_flight,
                    )
                } else {
                    self.sink.put_if_absent(&u.key, BlobSource::File(&path))
                };
                match result {
                    Ok(outcome) => {
                        match outcome {
                            crate::sink::PutOutcome::Stored => {
                                self.status.uploaded_objects.fetch_add(1, Ordering::Relaxed);
                                self.status
                                    .uploaded_bytes
                                    .fetch_add(u.bytes, Ordering::Relaxed);
                            }
                            crate::sink::PutOutcome::AlreadyPresent => {
                                self.status.already_present.fetch_add(1, Ordering::Relaxed);
                            }
                        }
                        self.staging.mark_uploaded(&u.key, &u.file)?;
                        self.lease_ok();
                        return Ok(());
                    }
                    Err(SinkError::LeaseLost { .. }) => return Err(ShipError::LeaseLost),
                    Err(e) if e.is_retryable() => {
                        self.status.failures.fetch_add(1, Ordering::Relaxed);
                        tracing::warn!(key = %u.key, attempt, error = %e, "upload failed; retrying");
                        last = Some(e);
                    }
                    Err(SinkError::QuotaRefused {
                        reason,
                        limit,
                        used,
                        requested,
                    }) => {
                        return Err(ShipError::QuotaRefused {
                            reason,
                            limit,
                            used,
                            requested,
                        });
                    }
                    Err(e) => {
                        self.status.failures.fetch_add(1, Ordering::Relaxed);
                        return Err(ShipError::Upload {
                            key: u.key.clone(),
                            source: e,
                        });
                    }
                }
            }
            thread::sleep(self.backoff(attempt));
        }
        Err(ShipError::Upload {
            key: u.key.clone(),
            source: last.unwrap_or_else(|| SinkError::NotFound(u.key.clone())),
        })
    }

    /// Upload `uploads`, a batch at a time: the PUT URLs of a batch's single-PUT objects are
    /// minted in one channel call ahead of the PUTs ([`BlobSink::prefetch_put`]), so a capture
    /// with thousands of objects costs a handful of `upload.urls` calls, not one per object
    /// (each call still counts every URL against the registrar's quota), and the batch goes up
    /// `uploads_in_flight` PUTs at a time. A batch holds at most [`PREFETCH_BATCH`] objects and
    /// ends at an object that is uploaded already, missing from staging, or multipart-sized: its
    /// parts mint their own URLs (and are in flight in parallel themselves), and a URL minted
    /// ahead of a minutes-long upload could expire before its PUT. Order within a batch is not
    /// kept; nothing depends on it before the register, which follows every object.
    fn upload_all(&self, uploads: &[Upload], cycle: &mut DutyCycle) -> Result<(), ShipError> {
        self.upload_until(uploads, cycle, &|| None).map(|_| ())
    }

    /// [`Self::upload_all`], asking `stop` before every object; the reason it gave, or `None`
    /// once every object is up. Objects already in flight when `stop` answers finish first.
    fn upload_until(
        &self,
        uploads: &[Upload],
        cycle: &mut DutyCycle,
        stop: &(dyn Fn() -> Option<Stop> + Sync),
    ) -> Result<Option<Stop>, ShipError> {
        let objects = self.staging.objects_dir();
        let single_put = |u: &Upload| {
            u.bytes < self.multipart.threshold
                && !self.staging.is_uploaded(&u.key, &u.file)
                && objects.join(&u.file).exists()
        };
        let mut start = 0;
        while start < uploads.len() {
            if let Some(why) = stop() {
                return Ok(Some(why));
            }
            let mut end = start;
            while end < uploads.len() && end - start < PREFETCH_BATCH && single_put(&uploads[end]) {
                end += 1;
            }
            if end == start {
                self.upload_one(&uploads[start], cycle)?;
                start += 1;
                continue;
            }
            let keys: Vec<(String, u64)> = uploads[start..end]
                .iter()
                .map(|u| (u.key.clone(), u.bytes))
                .collect();
            self.prefetch(&keys)?;
            if let Some(why) = self.upload_batch(&uploads[start..end], cycle, stop)? {
                return Ok(Some(why));
            }
            start = end;
        }
        Ok(None)
    }

    /// Upload a batch of single-PUT objects, `uploads_in_flight` at a time, asking `stop` before
    /// each. The first failure stops the batch (objects already in flight finish); a byte-quota
    /// refusal is reported over any other failure, since it decides what happens to the entry.
    /// Each worker charges its CPU to `cycle` and sleeps what the cycle owes outside the lock.
    fn upload_batch(
        &self,
        batch: &[Upload],
        cycle: &mut DutyCycle,
        stop: &(dyn Fn() -> Option<Stop> + Sync),
    ) -> Result<Option<Stop>, ShipError> {
        let workers = self.uploads_in_flight.min(batch.len());
        if workers <= 1 {
            for u in batch {
                if let Some(why) = stop() {
                    return Ok(Some(why));
                }
                self.upload_one(u, cycle)?;
            }
            return Ok(None);
        }
        let next = AtomicUsize::new(0);
        let halt = AtomicBool::new(false);
        let stopped: Mutex<Option<Stop>> = Mutex::new(None);
        let failed: Mutex<Option<ShipError>> = Mutex::new(None);
        // The owner only waits while the workers run: its CPU clock stands still.
        let own_cpu = thread_cpu();
        let cycle = Mutex::new(cycle);
        thread::scope(|scope| {
            for _ in 0..workers {
                scope.spawn(|| {
                    while !halt.load(Ordering::SeqCst) {
                        if let Some(why) = stop() {
                            lock(&stopped).get_or_insert(why);
                            halt.store(true, Ordering::SeqCst);
                            return;
                        }
                        let Some(u) = batch.get(next.fetch_add(1, Ordering::SeqCst)) else {
                            return;
                        };
                        let cpu_before = thread_cpu();
                        let result = self.put_object(u);
                        let used = thread_cpu().saturating_sub(cpu_before);
                        let owed = {
                            let mut cycle = lock(&cycle);
                            cycle.charge(used);
                            cycle.debt(own_cpu)
                        };
                        if let Err(error) = result {
                            let mut first = lock(&failed);
                            let refusal = matches!(error, ShipError::QuotaRefused { .. });
                            if first.is_none() || refusal {
                                *first = Some(error);
                            }
                            halt.store(true, Ordering::SeqCst);
                            return;
                        }
                        if !owed.is_zero() {
                            thread::sleep(owed);
                        }
                    }
                });
            }
        });
        if let Some(error) = lock(&failed).take() {
            return Err(error);
        }
        Ok(lock(&stopped).take())
    }

    /// Mint a batch's PUT URLs. A transient failure (transport, 5xx, 429) is retried with
    /// backoff and then fails the pass: falling back to one mint per key would turn one refused
    /// call into hundreds against the registrar's call quota.
    fn prefetch(&self, keys: &[(String, u64)]) -> Result<(), ShipError> {
        let mut attempt = 0;
        loop {
            match self.sink.prefetch_put(keys) {
                Ok(()) => return Ok(()),
                // The registrar priced the batch and refused it: nothing was minted, and no
                // later attempt at these bytes can pass.
                Err(SinkError::QuotaRefused {
                    reason,
                    limit,
                    used,
                    requested,
                }) => {
                    return Err(ShipError::QuotaRefused {
                        reason,
                        limit,
                        used,
                        requested,
                    });
                }
                Err(SinkError::LeaseLost { .. }) => return Err(ShipError::LeaseLost),
                Err(error) if error.is_retryable() => {
                    self.status.failures.fetch_add(1, Ordering::Relaxed);
                    attempt += 1;
                    if attempt >= self.retry.attempts {
                        return Err(ShipError::Upload {
                            key: keys.first().map(|(k, _)| k.clone()).unwrap_or_default(),
                            source: error,
                        });
                    }
                    tracing::warn!(keys = keys.len(), attempt, %error, "batch URL mint failed; retrying");
                    thread::sleep(self.backoff(attempt - 1));
                }
                // Each PUT mints its own then, and reports what stands in the way.
                Err(error) => {
                    tracing::warn!(keys = keys.len(), %error, "batch URL mint failed");
                    return Ok(());
                }
            }
        }
    }

    fn register_one(&self, entry: &QueueEntry) -> Result<(), ShipError> {
        let mut last = None;
        for attempt in 0..self.retry.attempts {
            match self.registrar.capture_register(&entry.register) {
                Ok(resp) => {
                    self.status.registered.fetch_add(1, Ordering::Relaxed);
                    self.status.head_n.store(resp.head_n, Ordering::Relaxed);
                    self.lease_ok();
                    return Ok(());
                }
                // Not live right now: pause and ask again, never a conflict (before, a 409
                // `lease-lost` read as a wrong parent and ended a final flush).
                Err(RegistrarError::LeaseLost) => return Err(ShipError::LeaseLost),
                Err(e @ RegistrarError::Fenced { .. }) => {
                    // A fence on an entry staged under a previous identity is that identity's
                    // (a re-plan raced the shipper), not this executor's.
                    if !self.staging.is_foreign(entry) {
                        self.status.fenced.store(true, Ordering::Relaxed);
                    }
                    return Err(ShipError::Fenced(e));
                }
                Err(e @ RegistrarError::WrongParent { .. }) => return Err(ShipError::Conflict(e)),
                Err(RegistrarError::RegisterRefused {
                    reason,
                    missing,
                    message,
                }) => {
                    return Err(ShipError::RegisterRefused {
                        n: entry.n,
                        reason,
                        missing,
                        message,
                    });
                }
                Err(RegistrarError::QuotaRefused {
                    reason,
                    limit,
                    used,
                    requested,
                }) => {
                    return Err(ShipError::QuotaRefused {
                        reason,
                        limit,
                        used,
                        requested,
                    });
                }
                Err(e) if e.is_retryable() => {
                    self.status.failures.fetch_add(1, Ordering::Relaxed);
                    tracing::warn!(n = entry.n, attempt, error = %e, "register failed; retrying");
                    last = Some(e);
                    thread::sleep(self.backoff(attempt));
                }
                Err(e) => {
                    return Err(ShipError::Register {
                        n: entry.n,
                        source: e,
                    });
                }
            }
        }
        Err(ShipError::Register {
            n: entry.n,
            source: last.unwrap_or(RegistrarError::Transport("exhausted".into())),
        })
    }

    /// One pass: ship every pending entry in order. Stops at the first entry that cannot be
    /// shipped (its error is returned; the queue keeps it and everything after it). A bulk
    /// capture's objects go up unclaimed: when a capture is staged ahead of it meanwhile, the
    /// pass ships that one first and then resumes the bulk upload where it stopped.
    pub fn ship_pending(&self) -> Result<usize, ShipError> {
        Ok(self.pass(Scope::All, None, false)?.shipped)
    }

    /// Whether `entry` is a bulk capture with objects still to upload.
    fn uploading_bulk(&self, entry: &QueueEntry) -> bool {
        entry.class == Some(Class::Bulk)
            && entry
                .uploads
                .iter()
                .any(|u| !self.staging.is_uploaded(&u.key, &u.file))
    }

    /// One pass over the queue for `scope`, holding the pass lock. `flushing`: the caller is a
    /// flush (counted as waiting while it waits for the lock); otherwise the pass is the
    /// worker's, and its bulk upload yields to a waiting flush.
    fn pass(
        &self,
        scope: Scope,
        deadline: Option<Instant>,
        flushing: bool,
    ) -> Result<Pass, ShipError> {
        let guard = if flushing {
            self.waiting.fetch_add(1, Ordering::SeqCst);
            let guard = self.pass.lock();
            self.waiting.fetch_sub(1, Ordering::SeqCst);
            guard
        } else {
            self.pass.lock()
        };
        let _pass = guard.unwrap_or_else(std::sync::PoisonError::into_inner);
        let mut pass = Pass::default();
        if self.is_fenced() {
            pass.done = true;
            return Ok(pass);
        }
        // Paused after a lease-lost answer: nothing can register until the backoff runs out.
        if self.lease_retry_at().is_some() {
            return Ok(pass);
        }
        // A restage is half-way (its journal is committed, the engine finishes it at its next
        // snap): the queue may name a parent no entry holds yet. Nothing ships meanwhile.
        if self.staging.restage_pending() {
            return Ok(pass);
        }
        let past = |deadline: Option<Instant>| deadline.is_some_and(|d| Instant::now() >= d);
        let mut cycle = DutyCycle::new(self.cpu_fraction);
        loop {
            let pending = self.staging.pending()?;
            // A repair asked for a capture that is no longer queued (the engine rebuilt it, or
            // a re-plan dropped it) is done.
            match self.staging.repair_request() {
                Some(request)
                    if !pending
                        .iter()
                        .any(|e| e.n == request.n && e.capture_id == request.capture_id) =>
                {
                    self.staging.clear_repair()?;
                    self.status.repair_pending.store(false, Ordering::Relaxed);
                }
                Some(_) => {}
                None => self.status.repair_pending.store(false, Ordering::Relaxed),
            }
            let Some(entry) = pending.first() else {
                pass.done = true;
                return Ok(pass);
            };
            // Refused, and waiting for the engine to rebuild it from disk: nothing behind it
            // can register first (the chain is ordered).
            if self.awaiting_repair(entry) {
                self.status.repair_pending.store(true, Ordering::Relaxed);
                self.call_repair_hook();
                pass.repair = Some(entry.n);
                return Ok(pass);
            }
            // A capture held for the byte quota waits out its backoff; nothing behind it can
            // register first (the chain is ordered), but a small capture is staged ahead of a
            // held bulk capture as ahead of any queued one.
            if !self.staging.is_foreign(entry) && self.held_back(entry) {
                pass.done = scope == Scope::AheadOfBulk
                    && pending.iter().all(|e| e.class == Some(Class::Bulk));
                return Ok(pass);
            }
            if !self.staging.is_foreign(entry) && self.uploading_bulk(entry) {
                if scope == Scope::AheadOfBulk
                    && pending.iter().all(|e| e.class == Some(Class::Bulk))
                {
                    pass.done = true;
                    return Ok(pass);
                }
                let generation = self.staging.generation();
                let stop = || {
                    if self.staging.generation() != generation {
                        Some(Stop::Changed)
                    } else if !flushing && self.waiting.load(Ordering::SeqCst) > 0 {
                        Some(Stop::Waiting)
                    } else if past(deadline) {
                        Some(Stop::Deadline)
                    } else {
                        None
                    }
                };
                match self.upload_until(&entry.uploads, &mut cycle, &stop) {
                    // Every object is up (the next round registers it), or the queue changed.
                    Ok(None | Some(Stop::Changed)) => continue,
                    Ok(Some(Stop::Waiting)) => {
                        pass.yielded = true;
                        return Ok(pass);
                    }
                    Ok(Some(Stop::Deadline)) => return Ok(pass),
                    Err(ShipError::QuotaRefused {
                        reason,
                        limit,
                        used,
                        requested,
                    }) => {
                        self.hold(entry, &reason, limit, used, requested);
                        return Ok(pass);
                    }
                    Err(ShipError::LeaseLost) => {
                        self.lease_lost();
                        return Ok(pass);
                    }
                    // The entry was coalesced or re-staged under the upload (a later bulk snap
                    // swept an object it no longer lists): start again from the queue.
                    Err(_) if self.staging.generation() != generation => continue,
                    Err(e) => return Err(e),
                }
            }
            if !self.staging.claim(entry) {
                // Coalesced away since the queue was read: the replacement sits at the same
                // `n`; the next pass ships it (never skip ahead — the chain is ordered).
                return Ok(pass);
            }
            if self.staging.is_foreign(entry) {
                // Staged under an identity a re-plan replaced: nothing of it can register.
                self.staging.release();
                self.staging.ack(entry)?;
                tracing::info!(n = entry.n, worktree = %entry.register.worktree_id, epoch = entry.register.epoch, "foreign capture dropped");
                continue;
            }
            let result = self
                .upload_all(&entry.uploads, &mut cycle)
                .and_then(|()| self.register_one(entry));
            match result {
                Ok(()) => {
                    // Acked before it is released: a snap must never coalesce with, or be
                    // staged ahead of, a capture the registrar already holds.
                    let acked = self.staging.ack(entry);
                    self.staging.release();
                    acked?;
                    pass.shipped += 1;
                    if let Some(class) = entry.class {
                        self.status
                            .refused_flag(class)
                            .store(false, Ordering::Relaxed);
                    }
                    lock(&self.held)[class_slot(entry.class)] = None;
                    {
                        let mut refusal = lock(&self.refusal);
                        if refusal.as_ref().is_some_and(|r| r.n <= entry.n) {
                            *refusal = None;
                        }
                    }
                    tracing::info!(n = entry.n, capture = %entry.capture_id, kind = ?entry.kind, class = ?entry.class, "capture registered");
                }
                Err(ShipError::QuotaRefused {
                    reason,
                    limit,
                    used,
                    requested,
                }) => {
                    self.staging.release();
                    self.hold(entry, &reason, limit, used, requested);
                    return Ok(pass);
                }
                Err(ShipError::LeaseLost) => {
                    self.staging.release();
                    self.lease_lost();
                    return Ok(pass);
                }
                // Never dropped: rebuilt from disk in its place, under fresh keys.
                Err(ShipError::RegisterRefused {
                    reason, missing, ..
                }) => {
                    self.staging.release();
                    self.after_refusal(entry, &reason, &missing)?;
                    pass.repair = Some(entry.n);
                    return Ok(pass);
                }
                Err(e) => {
                    self.staging.release();
                    return Err(e);
                }
            }
            if past(deadline) {
                return Ok(pass);
            }
        }
    }

    /// The registrar refused `entry` for the session's byte quota. Nothing is dropped: the entry
    /// keeps its place and its staged bytes, the class is reported refused, and the shipper asks
    /// again once the backoff runs out (30 s, doubling per refusal in a row, 10 min at most).
    /// Before this a refusal dropped the capture with every capture staged after it — a bulk
    /// capture's dependency tree, or the edits of a small one, discarded for a quota.
    fn hold(
        &self,
        entry: &QueueEntry,
        reason: &str,
        limit: Option<u64>,
        used: Option<u64>,
        requested: Option<u64>,
    ) {
        let slot = class_slot(entry.class);
        let mut held = lock(&self.held);
        let refusals = held[slot].as_ref().map_or(0, |h| h.refusals) + 1;
        let (first, max) = self.hold_backoff;
        let wait = first
            .saturating_mul(1u32 << (refusals - 1).min(16))
            .min(max);
        held[slot] = Some(HeldCapture {
            n: entry.n,
            capture_id: entry.capture_id.clone(),
            class: entry.class,
            reason: reason.to_owned(),
            limit,
            used,
            requested,
            refusals,
            retry_at: Instant::now() + wait,
        });
        drop(held);
        self.status
            .refused_flag(entry.class.unwrap_or(Class::Small))
            .store(true, Ordering::Relaxed);
        tracing::warn!(
            n = entry.n,
            capture = %entry.capture_id,
            class = ?entry.class,
            reason,
            limit,
            used,
            requested,
            refusals,
            retry_in_secs = wait.as_secs(),
            staged_bytes = entry.uploads.iter().map(|u| u.bytes).sum::<u64>(),
            "capture refused for the byte quota; held with its staged bytes and asked for again"
        );
    }

    /// Ship until the queue is empty or an error is not retryable, bounded by `deadline` (also
    /// inside a pass: a bulk upload stops between objects when it passes).
    pub fn flush(&self, deadline: Duration) -> Result<usize, ShipError> {
        self.flush_scope(Scope::All, Some(deadline))
    }

    /// Register every capture staged ahead of a bulk capture whose objects are still uploading,
    /// bounded by `deadline` (none: until they are, retrying what fails), and return: that is
    /// the git pack, the worktree tree and the workspace class — what a change or a diff needs.
    /// The bulk capture keeps uploading in the worker and registers after them; until then the
    /// chain head's bulk section is the one before it (or `"pending"`).
    pub fn flush_small(&self, deadline: Option<Duration>) -> Result<usize, ShipError> {
        self.flush_scope(Scope::AheadOfBulk, deadline)
    }

    /// Ship and register everything pending, bulk captures included: the executor is going away
    /// (`final`), and what is staged on its disk goes with it unless it is in the store. `Ok`
    /// only once the queue is empty and the lease is not fenced; anything short of that is an
    /// error that says why, never a success with work still staged: a fence
    /// ([`ShipError::Fenced`], or [`ShipError::AlreadyFenced`] when the lease was fenced before
    /// this pass — an already-fenced shipper used to answer "done" and the flush succeeded with
    /// captures still staged), a chain conflict, the caller's `deadline`
    /// ([`ShipError::Deadline`]; a pass stops between objects when it passes), or the error
    /// shipping kept failing with when the deadline came. What is left stays staged. A
    /// transport failure is retried with backoff, a capture held for the byte quota is asked
    /// for again when its backoff runs out, and a lease-lost answer pauses and asks again — for
    /// as long as the process lives when there is no deadline.
    ///
    /// # Errors
    /// See above.
    pub fn flush_final(&self, deadline: Option<Duration>) -> Result<usize, ShipError> {
        let until = deadline.map(|d| Instant::now() + d);
        let past = || until.is_some_and(|u| Instant::now() >= u);
        let left = || {
            until.map_or(Duration::MAX, |u| {
                u.saturating_duration_since(Instant::now())
            })
        };
        let pending = || {
            self.staging
                .pending()
                .map(|p| p.len())
                .unwrap_or(usize::MAX)
        };
        let mut total = 0;
        let mut failures = 0u32;
        loop {
            match self.pass(Scope::All, until, true) {
                Ok(pass) => {
                    total += pass.shipped;
                    if self.is_fenced() {
                        return Err(ShipError::AlreadyFenced { pending: pending() });
                    }
                    // The engine has to rebuild the head capture first: the caller (the cadence
                    // runner) does, and flushes again.
                    if let Some(n) = pass.repair {
                        return Err(ShipError::RepairPending { n });
                    }
                    if pass.done {
                        return Ok(total);
                    }
                    if past() {
                        return Err(ShipError::Deadline { pending: pending() });
                    }
                    if pass.shipped > 0 {
                        failures = 0;
                        continue;
                    }
                    // Held for the byte quota, paused on a lost lease, or a claim lost to a
                    // coalescing snap: wait for the nearest backoff (a second at a time, so a
                    // snap staged meanwhile ships).
                    thread::sleep(self.idle_wait().min(left()));
                }
                Err(e @ (ShipError::Fenced(_) | ShipError::Conflict(_))) => return Err(e),
                Err(error) => {
                    if past() {
                        // The caller's deadline, with shipping failing: what is left stays
                        // staged, and the failure is the answer.
                        tracing::warn!(%error, "final flush: deadline reached while shipping failed");
                        return Err(error);
                    }
                    failures += 1;
                    let wait = self.backoff(failures.min(10));
                    tracing::warn!(%error, failures, "final flush: shipping failed; retrying");
                    thread::sleep(wait.min(left()));
                }
            }
        }
    }

    /// How long a flush waits when a pass moved nothing: until the nearest held capture or
    /// lease-lost backoff runs out, a second at most, 10 ms at least.
    fn idle_wait(&self) -> Duration {
        let now = Instant::now();
        self.held()
            .iter()
            .map(|h| h.retry_at)
            .chain(self.lease_retry_at())
            .map(|at| at.saturating_duration_since(now))
            .min()
            .unwrap_or(self.retry.backoff)
            .clamp(Duration::from_millis(10), Duration::from_secs(1))
    }

    fn flush_scope(&self, scope: Scope, deadline: Option<Duration>) -> Result<usize, ShipError> {
        let until = deadline.map(|d| Instant::now() + d);
        let past = || until.is_some_and(|u| Instant::now() >= u);
        let left = || {
            until.map_or(Duration::MAX, |u| {
                u.saturating_duration_since(Instant::now())
            })
        };
        let mut total = 0;
        loop {
            match self.pass(scope, until, true) {
                Ok(pass) => {
                    total += pass.shipped;
                    if pass.done {
                        return Ok(total);
                    }
                    if pass.shipped == 0 && !past() {
                        // Nothing moved (a claim lost to a coalescing snap, a held capture, a
                        // lost lease): not a hot loop.
                        thread::sleep(self.idle_wait().min(left()));
                    }
                }
                Err(ShipError::Fenced(e)) => return Err(ShipError::Fenced(e)),
                Err(ShipError::Conflict(e)) => return Err(ShipError::Conflict(e)),
                Err(e) => {
                    if past() {
                        return Err(e);
                    }
                    thread::sleep(self.retry.backoff.min(left()));
                }
            }
            if past() {
                return Ok(total);
            }
        }
    }
}

/// A background worker thread that runs [`Shipper::ship_pending`] on a wake-up or a tick, and
/// straight away again after its bulk upload yielded to a flush.
#[derive(Debug)]
pub struct ShipWorker {
    stop: Arc<AtomicBool>,
    wake: Arc<(Mutex<bool>, std::sync::Condvar)>,
    handle: Option<thread::JoinHandle<()>>,
}

impl ShipWorker {
    /// Spawn a worker polling every `tick`.
    pub fn spawn(shipper: Arc<Shipper>, tick: Duration) -> io::Result<Self> {
        let stop = Arc::new(AtomicBool::new(false));
        let wake = Arc::new((Mutex::new(false), std::sync::Condvar::new()));
        let (stop2, wake2) = (Arc::clone(&stop), Arc::clone(&wake));
        let handle = thread::Builder::new()
            .name("capture-ship".into())
            .spawn(move || {
                while !stop2.load(Ordering::Relaxed) {
                    match shipper.pass(Scope::All, None, false) {
                        // A flush took the pass; the bulk upload resumes once it is done (the
                        // next pass waits for the lock).
                        Ok(pass) if pass.yielded => {
                            thread::yield_now();
                            continue;
                        }
                        Ok(_) => {}
                        Err(e) => tracing::warn!(error = %e, "ship pass failed"),
                    }
                    let (lock, cv) = &*wake2;
                    let mut woken = lock
                        .lock()
                        .unwrap_or_else(std::sync::PoisonError::into_inner);
                    if !*woken {
                        let (guard, _) = cv
                            .wait_timeout(woken, tick)
                            .unwrap_or_else(std::sync::PoisonError::into_inner);
                        woken = guard;
                    }
                    *woken = false;
                }
            })?;
        Ok(Self {
            stop,
            wake,
            handle: Some(handle),
        })
    }

    /// Wake the worker now.
    pub fn wake(&self) {
        let (lock, cv) = &*self.wake;
        *lock
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = true;
        cv.notify_one();
    }

    /// Stop and join.
    pub fn stop(mut self) {
        self.stop.store(true, Ordering::Relaxed);
        self.wake();
        if let Some(h) = self.handle.take() {
            let _ = h.join();
        }
    }
}

impl Drop for ShipWorker {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Relaxed);
        self.wake();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn entry(n: u64, id: &str) -> QueueEntry {
        QueueEntry {
            n,
            capture_id: id.to_owned(),
            kind: CaptureKind::Auto,
            class: None,
            uploads: Vec::new(),
            register: crate::registrar::RegisterRequest {
                worktree_id: "wt".into(),
                epoch: 1,
                n,
                parent: None,
                capture_id: id.to_owned(),
                manifest_key: String::new(),
                manifest: crate::manifest::Manifest {
                    worktree_id: "wt".into(),
                    n,
                    parent: None,
                    epoch: 1,
                    seq: 0,
                    kind: CaptureKind::Auto,
                    created_at: String::new(),
                    sections: crate::manifest::Sections {
                        git: crate::manifest::GitSection {
                            packs: Vec::new(),
                            refs: std::collections::BTreeMap::new(),
                            head: "HEAD".into(),
                            fsck: crate::manifest::FsckStatus::Unverified,
                            symrefs: std::collections::BTreeMap::new(),
                            worktree_tree: None,
                            index_tree: None,
                            raw_tree: None,
                        },
                        workspace: crate::manifest::WorkspaceSection::objects(
                            String::new(),
                            Vec::new(),
                        ),
                        bulk: crate::manifest::BulkState::pending(),
                        other_bulk: Default::default(),
                    },
                    checkpoint: None,
                    final_seal: None,
                },
            },
        }
    }

    /// A claimed entry is not coalescible; a replaced entry cannot be claimed.
    #[test]
    fn claim_and_coalesce_exclude_each_other() {
        let dir = tempfile::tempdir().unwrap();
        let staging = Staging::open(dir.path(), "wt", 1).unwrap();
        let first = entry(0, "a");
        staging.enqueue(&first).unwrap();
        assert_eq!(
            staging.coalescible().unwrap().map(|e| e.capture_id),
            Some("a".into())
        );
        assert!(staging.claim(&first));
        assert!(staging.coalescible().unwrap().is_none(), "in flight");
        staging.release();
        let second = entry(0, "b");
        staging.replace(&first, &second).unwrap();
        assert!(!staging.claim(&first), "replaced entries are never shipped");
        assert!(staging.claim(&second));
        staging.release();
        staging.ack(&second).unwrap();
        assert!(staging.pending().unwrap().is_empty());
    }

    #[test]
    fn duty_cycle_sleeps_when_over_budget() {
        let mut c = DutyCycle::new(0.5);
        // Burn CPU.
        let mut x = 0u64;
        let start = Instant::now();
        while start.elapsed() < Duration::from_millis(40) {
            x = x
                .wrapping_mul(6364136223846793005)
                .wrapping_add(1442695040888963407);
        }
        assert!(x != 1);
        c.pace();
        assert!(c.slept >= Duration::from_millis(20), "slept {:?}", c.slept);
        let mut never = DutyCycle::new(1.0);
        never.pace();
        assert_eq!(never.slept, Duration::ZERO);
    }

    /// CPU charged from helper threads counts like the cycle's own.
    #[test]
    fn duty_cycle_counts_charged_cpu() {
        let mut c = DutyCycle::new(0.5);
        c.charge(Duration::from_millis(100));
        c.pace();
        assert!(c.slept >= Duration::from_millis(50), "slept {:?}", c.slept);
    }
}
