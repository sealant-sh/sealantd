//! Staging and shipping. Snaps are staged on local disk under `<workspace root>/.sealantd/capture/`
//! (the same filesystem as the tree); a worker uploads oldest-first with retry and coalescing,
//! then registers. The queue follows the `Spool` discipline of ADR-0007 (append → replay → ack,
//! a disk bound), not its record format: one JSON entry per capture, one ack marker per object.
//! The shipper is throttled to ≤ 50% of one core as a CPU-time duty cycle from `getrusage`;
//! objects at or above [`MultipartConfig::threshold`] go up as multipart uploads with several
//! parts in flight, whose threads' CPU is charged to the same cycle (network waits are not).

use std::collections::HashSet;
use std::fs;
use std::io;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};

use serde::{Deserialize, Serialize};

use crate::cpu::thread_cpu;
use crate::engine::Class;
use crate::manifest::CaptureKind;
use crate::registrar::{RegisterRequest, Registrar, RegistrarError, opt};
use crate::sink::{BlobSink, BlobSource, SinkError};

/// Default shipper CPU budget: half of one core.
pub const DEFAULT_CPU_FRACTION: f64 = 0.5;

/// Most single-PUT objects whose URLs are minted in one channel call.
pub const PREFETCH_BATCH: usize = 500;

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

/// A capture the registrar refused for the session's byte quota. The shipper dropped it and
/// every queued capture that descends from it; the engine reads this at its next snap, continues
/// the chain from the refused capture's parent, and forgets the chunks whose packs went with it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RefusedCapture {
    /// Chain position the refused capture held.
    pub n: u64,
    /// Its capture id.
    pub capture_id: String,
    /// Its parent (the chain head the executor continues from).
    pub parent: Option<String>,
    /// The class that was refused, when the entry names one.
    pub class: Option<Class>,
    /// The registrar's reason code (`byte-quota`).
    pub reason: String,
    /// The session's budget in bytes, when the answer names it.
    pub limit: Option<u64>,
    /// Bytes priced against the session so far.
    pub used: Option<u64>,
    /// Bytes the refused call asked for.
    pub requested: Option<u64>,
    /// Every object the dropped captures staged.
    pub uploads: Vec<Upload>,
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
    /// The registrar refused this capture's bytes for the session's byte quota. Terminal: the
    /// entry and its staged bytes are dropped and the class stops.
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
    /// Captures the registrar refused, for the engine to read at its next snap.
    refusals: Mutex<Vec<RefusedCapture>>,
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
            refusals: Mutex::new(Vec::new()),
        };
        fs::create_dir_all(staging.marker_dir())?;
        Ok(staging)
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
            self.sweep(&entry)?;
            dropped += 1;
        }
        Ok(dropped)
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

    fn marker_dir(&self) -> PathBuf {
        let (worktree_id, epoch) = self.identity();
        self.dir
            .join("uploaded")
            .join(worktree_id.replace('/', "_"))
            .join(epoch.to_string())
    }

    fn marker_path(&self, file: &str) -> PathBuf {
        self.marker_dir().join(file)
    }

    /// Whether an object file was acked as uploaded.
    #[must_use]
    pub fn is_uploaded(&self, file: &str) -> bool {
        self.marker_path(file).exists()
    }

    /// Ack an object file.
    pub fn mark_uploaded(&self, file: &str) -> io::Result<()> {
        fs::write(self.marker_path(file), b"")
    }

    /// Append an entry (write-then-rename).
    pub fn enqueue(&self, entry: &QueueEntry) -> io::Result<()> {
        let path = self.queue_path(entry.n);
        let tmp = path.with_extension("tmp");
        fs::write(&tmp, serde_json::to_vec(entry)?)?;
        fs::rename(tmp, path)
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
        let in_flight = *self
            .in_flight
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if last.kind == CaptureKind::Auto && in_flight != Some(last.n) {
            Ok(Some(last.clone()))
        } else {
            Ok(None)
        }
    }

    /// Drop `entry` because the registrar refused it for good, with every queued capture after
    /// it (they name it as their parent and can never register) and all their staged bytes.
    /// The refusal is kept for the engine, which continues the chain from `entry`'s parent.
    pub fn drop_refused(&self, entry: &QueueEntry, refusal: RefusedCapture) -> io::Result<usize> {
        let _g = self.coalesce_guard();
        let mut refusal = refusal;
        let mut dropped = 0;
        for queued in self.pending()? {
            if queued.n < entry.n {
                continue;
            }
            fs::remove_file(self.queue_path(queued.n)).ok();
            refusal.uploads.extend(queued.uploads.iter().cloned());
            dropped += 1;
        }
        let uploads = refusal.uploads.clone();
        self.refusals
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .push(refusal);
        self.discard_unreferenced(&uploads)?;
        Ok(dropped)
    }

    /// Take the refusals recorded since the last call (the engine applies them).
    #[must_use]
    pub fn take_refusals(&self) -> Vec<RefusedCapture> {
        std::mem::take(
            &mut *self
                .refusals
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner),
        )
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

    fn sweep(&self, removed: &QueueEntry) -> io::Result<()> {
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
        if self.fraction >= 1.0 {
            return;
        }
        let cpu = (thread_cpu().saturating_sub(self.cpu_start) + self.charged).as_secs_f64();
        let wall = self.started.elapsed().as_secs_f64();
        let allowed = wall * self.fraction;
        if cpu > allowed {
            let sleep = Duration::from_secs_f64((cpu / self.fraction - wall).min(0.5));
            thread::sleep(sleep);
            self.slept += sleep;
        }
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
    /// The small class was refused for the session's byte quota.
    pub refused_small: AtomicBool,
    /// The bulk class was refused for the session's byte quota; no bulk snap runs until the
    /// next epoch or `capture.replan`.
    pub refused_bulk: AtomicBool,
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

/// Uploads staged captures oldest-first and registers each.
pub struct Shipper {
    staging: Arc<Staging>,
    sink: Arc<dyn BlobSink>,
    registrar: Arc<dyn Registrar>,
    cpu_fraction: f64,
    retry: RetryPolicy,
    multipart: MultipartConfig,
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
            status,
        }
    }

    /// Multipart threshold, part size and parts in flight.
    #[must_use]
    pub fn with_multipart(mut self, multipart: MultipartConfig) -> Self {
        self.multipart = multipart;
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

    /// Whether shipping is fenced.
    #[must_use]
    pub fn is_fenced(&self) -> bool {
        self.status.fenced.load(Ordering::Relaxed)
    }

    /// Whether `class` was refused for the session's byte quota (no snap, no ship until the
    /// next epoch or a re-plan).
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
        self.status
            .head_n
            .store(head_n.unwrap_or(u64::MAX), Ordering::Relaxed);
    }

    fn backoff(&self, attempt: u32) -> Duration {
        let mult = 1u32 << attempt.min(10);
        (self.retry.backoff * mult).min(self.retry.max_backoff)
    }

    fn upload_one(&self, u: &Upload, cycle: &mut DutyCycle) -> Result<(), ShipError> {
        if self.staging.is_uploaded(&u.file) {
            return Ok(());
        }
        let path = self.staging.objects_dir().join(&u.file);
        let mut last: Option<SinkError> = None;
        for attempt in 0..self.retry.attempts {
            if !path.exists() {
                // The bytes were swept after an earlier ack of another entry; the store has them.
                match self.sink.exists(&u.key) {
                    Ok(true) => {
                        self.staging.mark_uploaded(&u.file)?;
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
                let helper_before = self.sink.helper_cpu();
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
                cycle.charge(self.sink.helper_cpu().saturating_sub(helper_before));
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
                        self.staging.mark_uploaded(&u.file)?;
                        cycle.pace();
                        return Ok(());
                    }
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

    /// Upload `uploads` in order, a batch at a time: the PUT URLs of a batch's single-PUT
    /// objects are minted in one channel call ahead of the PUTs ([`BlobSink::prefetch_put`]),
    /// so a capture with thousands of dir objects costs a handful of `upload.urls` calls, not
    /// one per object (each call still counts every URL against the registrar's quota). A
    /// batch holds at most [`PREFETCH_BATCH`] objects and ends at an object that is uploaded
    /// already, missing from staging, or multipart-sized: its parts mint their own URLs, and a
    /// URL minted ahead of a minutes-long upload could expire before its PUT.
    fn upload_all(&self, uploads: &[Upload], cycle: &mut DutyCycle) -> Result<(), ShipError> {
        let objects = self.staging.objects_dir();
        let single_put = |u: &Upload| {
            u.bytes < self.multipart.threshold
                && !self.staging.is_uploaded(&u.file)
                && objects.join(&u.file).exists()
        };
        let mut start = 0;
        while start < uploads.len() {
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
            match self.sink.prefetch_put(&keys) {
                Ok(()) => {}
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
                // Each PUT mints its own then, and reports what stands in the way.
                Err(error) => tracing::warn!(keys = keys.len(), %error, "batch URL mint failed"),
            }
            for u in &uploads[start..end] {
                self.upload_one(u, cycle)?;
            }
            start = end;
        }
        Ok(())
    }

    fn register_one(&self, entry: &QueueEntry) -> Result<(), ShipError> {
        let mut last = None;
        for attempt in 0..self.retry.attempts {
            match self.registrar.capture_register(&entry.register) {
                Ok(resp) => {
                    self.status.registered.fetch_add(1, Ordering::Relaxed);
                    self.status.head_n.store(resp.head_n, Ordering::Relaxed);
                    return Ok(());
                }
                Err(e @ RegistrarError::Fenced { .. }) => {
                    // A fence on an entry staged under a previous identity is that identity's
                    // (a re-plan raced the shipper), not this executor's.
                    if !self.staging.is_foreign(entry) {
                        self.status.fenced.store(true, Ordering::Relaxed);
                    }
                    return Err(ShipError::Fenced(e));
                }
                Err(e @ RegistrarError::WrongParent { .. }) => return Err(ShipError::Conflict(e)),
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
    /// shipped (its error is returned; the queue keeps it and everything after it).
    pub fn ship_pending(&self) -> Result<usize, ShipError> {
        if self.is_fenced() {
            return Ok(0);
        }
        let mut shipped = 0;
        let mut cycle = DutyCycle::new(self.cpu_fraction);
        for entry in self.staging.pending()? {
            if !self.staging.claim(&entry) {
                // Coalesced away since the queue was read: the replacement sits at the same
                // `n`; the next pass ships it (never skip ahead — the chain is ordered).
                break;
            }
            if self.staging.is_foreign(&entry) {
                // Staged under an identity a re-plan replaced: nothing of it can register.
                self.staging.release();
                self.staging.ack(&entry)?;
                tracing::info!(n = entry.n, worktree = %entry.register.worktree_id, epoch = entry.register.epoch, "foreign capture dropped");
                continue;
            }
            let result = self
                .upload_all(&entry.uploads, &mut cycle)
                .and_then(|()| self.register_one(&entry));
            self.staging.release();
            match result {
                Ok(()) => {
                    self.staging.ack(&entry)?;
                    shipped += 1;
                    if let Some(class) = entry.class {
                        self.status
                            .refused_flag(class)
                            .store(false, Ordering::Relaxed);
                    }
                    tracing::info!(n = entry.n, capture = %entry.capture_id, kind = ?entry.kind, "capture registered");
                }
                Err(ShipError::QuotaRefused {
                    reason,
                    limit,
                    used,
                    requested,
                }) => {
                    self.refuse(&entry, &reason, limit, used, requested)?;
                    return Ok(shipped);
                }
                Err(e) => return Err(e),
            }
        }
        Ok(shipped)
    }

    /// The registrar refused `entry` for the session's byte quota: drop it, its staged bytes and
    /// every queued capture that descends from it, and stop the class. The engine picks the
    /// refusal up at its next snap and continues the chain from the refused capture's parent; a
    /// refused bulk class takes no further snap until the next epoch or `capture.replan`, while
    /// the small class keeps going (its batches are small enough to fit what is left).
    fn refuse(
        &self,
        entry: &QueueEntry,
        reason: &str,
        limit: Option<u64>,
        used: Option<u64>,
        requested: Option<u64>,
    ) -> Result<(), ShipError> {
        let dropped = self.staging.drop_refused(
            entry,
            RefusedCapture {
                n: entry.n,
                capture_id: entry.capture_id.clone(),
                parent: entry.register.parent.clone(),
                class: entry.class,
                reason: reason.to_owned(),
                limit,
                used,
                requested,
                uploads: entry.uploads.clone(),
            },
        )?;
        if let Some(class) = entry.class {
            self.status
                .refused_flag(class)
                .store(true, Ordering::Relaxed);
        }
        tracing::warn!(
            n = entry.n,
            capture = %entry.capture_id,
            class = ?entry.class,
            reason,
            limit,
            used,
            requested,
            dropped,
            "capture refused; dropped with its staged bytes"
        );
        Ok(())
    }

    /// Ship until the queue is empty or an error is not retryable, bounded by `deadline`.
    pub fn flush(&self, deadline: Duration) -> Result<usize, ShipError> {
        let start = Instant::now();
        let mut total = 0;
        loop {
            match self.ship_pending() {
                Ok(n) => {
                    total += n;
                    if self.staging.pending()?.is_empty() {
                        return Ok(total);
                    }
                }
                Err(ShipError::Fenced(e)) => return Err(ShipError::Fenced(e)),
                Err(ShipError::Conflict(e)) => return Err(ShipError::Conflict(e)),
                Err(e) => {
                    if start.elapsed() >= deadline {
                        return Err(e);
                    }
                    thread::sleep(self.retry.backoff);
                }
            }
            if start.elapsed() >= deadline {
                return Ok(total);
            }
        }
    }
}

/// A background worker thread that runs [`Shipper::ship_pending`] on a wake-up or a tick.
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
                    if let Err(e) = shipper.ship_pending() {
                        tracing::warn!(error = %e, "ship pass failed");
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
                        },
                        workspace: crate::manifest::WorkspaceSection {
                            root: String::new(),
                            packs: Vec::new(),
                        },
                        bulk: crate::manifest::BulkState::pending(),
                    },
                    checkpoint: None,
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
