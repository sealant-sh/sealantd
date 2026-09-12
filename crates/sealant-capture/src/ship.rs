//! Staging and shipping. Snaps are staged on local disk under `<workspace root>/.sealantd/capture/`
//! (the same filesystem as the tree); a worker uploads oldest-first with retry and coalescing,
//! then registers. The queue follows the `Spool` discipline of ADR-0007 (append → replay → ack,
//! a disk bound), not its record format: one JSON entry per capture, one ack marker per object.
//! The shipper is throttled to ≤ 50% of one core as a CPU-time duty cycle from `getrusage`.

use std::collections::HashSet;
use std::fs;
use std::io;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};

use nix::sys::resource::{UsageWho, getrusage};
use serde::{Deserialize, Serialize};

use crate::manifest::CaptureKind;
use crate::registrar::{RegisterRequest, Registrar, RegistrarError};
use crate::sink::{BlobSink, BlobSource, SinkError};

/// Default shipper CPU budget: half of one core.
pub const DEFAULT_CPU_FRACTION: f64 = 0.5;

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
    /// Objects in write order (packs, trees), the manifest last.
    pub uploads: Vec<Upload>,
    /// The register call.
    pub register: RegisterRequest,
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
    epoch: u64,
    in_flight: Mutex<Option<u64>>,
    /// Held by the engine from `coalescible` to `replace` / `enqueue`, and by the shipper while
    /// it claims an entry: a pending `auto` capture is never coalesced away under a shipper that
    /// has started on it, and never claimed once replaced.
    coalesce: Mutex<()>,
}

impl Staging {
    /// Open (and create) staging at `dir` for `epoch`. Upload acks are kept per epoch: an object
    /// acked under a prior epoch was written under a prior prefix and must be uploaded again.
    pub fn open(dir: &Path, epoch: u64) -> io::Result<Self> {
        for sub in ["objects", "queue", "scratch", "index", "cache"] {
            fs::create_dir_all(dir.join(sub))?;
        }
        fs::create_dir_all(dir.join("uploaded").join(epoch.to_string()))?;
        Ok(Self {
            dir: dir.to_path_buf(),
            epoch,
            in_flight: Mutex::new(None),
            coalesce: Mutex::new(()),
        })
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

    fn marker_path(&self, file: &str) -> PathBuf {
        self.dir
            .join("uploaded")
            .join(self.epoch.to_string())
            .join(file)
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
        let still: HashSet<String> = self
            .pending()?
            .iter()
            .flat_map(|e| e.uploads.iter().map(|u| u.file.clone()))
            .collect();
        // Object bytes go; the ack markers stay, so an unchanged dir object or pack listed by a
        // later capture is neither re-staged nor re-uploaded within this epoch.
        for u in &removed.uploads {
            if !still.contains(&u.file) {
                fs::remove_file(self.objects_dir().join(&u.file)).ok();
            }
        }
        Ok(())
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

/// CPU time of the calling thread.
fn thread_cpu() -> Duration {
    match getrusage(UsageWho::RUSAGE_THREAD) {
        Ok(u) => {
            let ut = u.user_time();
            let st = u.system_time();
            let micros = (ut.tv_sec() as i128 * 1_000_000 + ut.tv_usec() as i128)
                + (st.tv_sec() as i128 * 1_000_000 + st.tv_usec() as i128);
            Duration::from_micros(u64::try_from(micros.max(0)).unwrap_or(0))
        }
        Err(_) => Duration::ZERO,
    }
}

/// A CPU-time duty cycle (amendment decision 12): after each unit of work, if this thread's CPU
/// time since the cycle began exceeds `fraction` of the wall time, sleep the difference.
#[derive(Debug)]
pub struct DutyCycle {
    fraction: f64,
    started: Instant,
    cpu_start: Duration,
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
            slept: Duration::ZERO,
        }
    }

    /// Sleep if over budget.
    pub fn pace(&mut self) {
        if self.fraction >= 1.0 {
            return;
        }
        let cpu = thread_cpu().saturating_sub(self.cpu_start).as_secs_f64();
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
            status,
        }
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
                match self.sink.put_if_absent(&u.key, BlobSource::File(&path)) {
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
                    self.status.fenced.store(true, Ordering::Relaxed);
                    return Err(ShipError::Fenced(e));
                }
                Err(e @ RegistrarError::WrongParent { .. }) => return Err(ShipError::Conflict(e)),
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
            let result = (|| {
                for u in &entry.uploads {
                    self.upload_one(u, &mut cycle)?;
                }
                self.register_one(&entry)
            })();
            self.staging.release();
            match result {
                Ok(()) => {
                    self.staging.ack(&entry)?;
                    shipped += 1;
                    tracing::info!(n = entry.n, capture = %entry.capture_id, kind = ?entry.kind, "capture registered");
                }
                Err(e) => return Err(e),
            }
        }
        Ok(shipped)
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
        let staging = Staging::open(dir.path(), 1).unwrap();
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
}
