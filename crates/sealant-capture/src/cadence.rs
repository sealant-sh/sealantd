//! The cadence runner (ADR-0015 *Cadence and budgets*): owns the engine, feeds it from the
//! watcher, and decides when each class is snapped.
//!
//! Small class: any change marks it dirty and (re)arms a quiet timer (`Cadence::quiet`); a dirty
//! class also has a maximum-interval deadline (`Cadence::max_interval`) from its first change.
//! Either firing snaps it; a snap that stages nothing clears dirty. Bulk class: the same shape
//! on its own, longer clocks (`bulk_quiet` / `bulk_max_interval`), at most one bulk snap in
//! flight. A due small-class snap is never behind a bulk build: it flags the engine, the bulk
//! build yields at the next chunk boundary ([`CaptureEngine::snap_preemptible`]) and resumes
//! after the small snap. Forced snaps (turn boundaries, checkpoints, flushes) go through the same
//! gate. A class that cannot be watched — budget not met, `IN_Q_OVERFLOW`, no backend — polls:
//! it is snapped at its maximum interval unconditionally (the engine's stat walk stages nothing
//! when unchanged). A class the registrar refused for the session's byte quota keeps snapping:
//! its capture is held in the queue ([`Shipper::held`]) and a newer one replaces it, so what is
//! on disk is always what goes up once the quota allows.

use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Condvar, Mutex, MutexGuard, PoisonError, Weak};
use std::thread;
use std::time::{Duration, Instant, SystemTime};

use crate::engine::{CaptureEngine, Class, EngineError, SnapOutcome, SnapRequest, StagedCapture};
use crate::manifest::CaptureKind;
use crate::ship::{ShipError, ShipWorker, Shipper, Staging};
use crate::watch::{self, ChangeSignal, Mode, WatchHandle, WatchSpec};

/// How often the ship worker polls when nothing woke it.
pub const SHIP_TICK: Duration = Duration::from_secs(5);

/// Rounds of snaps a final flush takes when the disk changed after them, before it gives up
/// and seals nothing ([`Incomplete::Changed`]).
const FINAL_ROUNDS: u32 = 3;

/// How long a final flush waits for the watcher's fence ([`WatchHandle::settle`]).
const SETTLE_TIMEOUT: Duration = Duration::from_secs(10);

/// Why a final flush is not complete. [`Incomplete::reason`] is the code the daemon reports.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum Incomplete {
    /// A final snap failed: what it would have captured is on the disk only.
    #[error("the final {class:?}-class snap failed: {error}")]
    SnapshotFailed {
        /// The class whose snap failed (the first, when both did).
        class: Class,
        /// The engine's error.
        error: String,
    },
    /// The lease is fenced: nothing staged can register any more.
    #[error("{0}")]
    Fenced(String),
    /// The chain moved under this executor.
    #[error("{0}")]
    Conflict(String),
    /// The caller's deadline passed with captures still staged.
    #[error("deadline passed with {pending} captures pending")]
    Deadline {
        /// Captures still staged.
        pending: usize,
    },
    /// Shipping kept failing until the deadline.
    #[error("shipping failed: {0}")]
    ShipFailed(String),
    /// Everything registered, but the capture that seals the completed flush on the chain
    /// ([`crate::manifest::FinalSeal`]) did not: staging it failed, or it never registered.
    #[error("the final seal did not register: {0}")]
    Sealing(String),
    /// A final snap met work it could not read (it would have been left out of the capture).
    #[error("unreadable work: {0}")]
    Unreadable(String),
    /// The store cannot hold what the capture holds ([`CaptureEngine::fidelity_gap`]): what it
    /// would restore is less than the disk, so the flush is never complete and nothing is
    /// sealed, whatever registered.
    #[error("{0}")]
    StoreFidelity(String),
    /// The disk changed after the flush's snaps (the watcher delivered a change, overflowed,
    /// or could not be settled), and snapping again did not end on a disk that held still:
    /// what the captures hold is not the disk, and nothing is sealed.
    #[error("the disk changed during the final flush: {0}")]
    Changed(String),
}

impl Incomplete {
    /// The reason code: `snapshot-failed`, `fenced`, `conflict`, `deadline`, `ship-failed`,
    /// `unreadable`, `sealing`, `store-fidelity` or `changed`.
    #[must_use]
    pub fn reason(&self) -> &'static str {
        match self {
            Self::SnapshotFailed { .. } => "snapshot-failed",
            Self::Fenced(_) => "fenced",
            Self::Conflict(_) => "conflict",
            Self::Deadline { .. } => "deadline",
            Self::ShipFailed(_) => "ship-failed",
            Self::Unreadable(_) => "unreadable",
            Self::Sealing(_) => "sealing",
            Self::StoreFidelity(_) => "store-fidelity",
            Self::Changed(_) => "changed",
        }
    }

    fn from_snap(class: Class, error: &EngineError) -> Self {
        // The snap failed because it could not read work (`EngineError::unreadable`): say so,
        // so the control plane can name the paths instead of a generic snapshot failure.
        if error.unreadable().is_some() {
            return Self::Unreadable(error.to_string());
        }
        Self::SnapshotFailed {
            class,
            error: error.to_string(),
        }
    }

    fn from_ship(error: &ShipError) -> Self {
        match error {
            ShipError::Fenced(_) | ShipError::AlreadyFenced { .. } => {
                Self::Fenced(error.to_string())
            }
            ShipError::Conflict(_) => Self::Conflict(error.to_string()),
            ShipError::Deadline { pending } => Self::Deadline { pending: *pending },
            _ => Self::ShipFailed(error.to_string()),
        }
    }
}

/// What a final flush did ([`CadenceRunner::flush_final`]).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FinalFlush {
    /// Captures registered by its shipping.
    pub shipped: usize,
    /// Why it is not complete; `None` when both classes were snapped and everything staged is
    /// registered.
    pub incomplete: Option<Incomplete>,
}

impl FinalFlush {
    /// Both final snaps succeeded and nothing is left staged.
    #[must_use]
    pub fn complete(&self) -> bool {
        self.incomplete.is_none()
    }
}

/// One class's snaps, failed and not ([`CadenceRunner::snap_health`]): a snap that fails for
/// any reason — scheduled or forced — is counted and its error kept until one succeeds, so a
/// class that cannot be captured is visible, never only a line in the log.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct SnapHealth {
    /// Snaps of the class that failed since the runner was made.
    pub failed: u64,
    /// The last snap's error, while the last snap failed.
    pub last_error: Option<String>,
    /// When the current run of failed snaps began, while the last snap failed.
    pub failing_since: Option<SystemTime>,
}

impl SnapHealth {
    /// Whether the class's last snap failed.
    #[must_use]
    pub fn failing(&self) -> bool {
        self.last_error.is_some()
    }

    fn record(&mut self, class: Class, result: Result<(), String>) {
        match result {
            Ok(()) => {
                if let Some(error) = self.last_error.take() {
                    tracing::info!(?class, %error, "capture snaps of the class succeed again");
                }
                self.failing_since = None;
            }
            Err(error) => {
                self.failed += 1;
                if self.last_error.is_none() {
                    tracing::error!(
                        ?class,
                        %error,
                        "capture snaps of the class are failing: what changes is on this disk only"
                    );
                    self.failing_since = Some(SystemTime::now());
                }
                self.last_error = Some(error);
            }
        }
    }
}

/// Why a scheduled snap fired.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Trigger {
    /// The quiet period after the last change elapsed.
    Quiet,
    /// The maximum interval since the first change elapsed.
    MaxInterval,
    /// The class polls; its interval elapsed.
    Poll,
}

/// One class's clock.
#[derive(Debug, Clone, Copy)]
struct Clock {
    first_change: Option<Instant>,
    last_change: Option<Instant>,
    last_snap: Instant,
    quiet: Duration,
    max: Duration,
}

impl Clock {
    fn new(quiet: Duration, max: Duration) -> Self {
        Self {
            first_change: None,
            last_change: None,
            last_snap: Instant::now(),
            quiet,
            max,
        }
    }

    fn dirty(&mut self, now: Instant) {
        self.first_change.get_or_insert(now);
        self.last_change = Some(now);
    }

    fn clear(&mut self) {
        self.first_change = None;
        self.last_change = None;
    }

    /// When the next snap is due and why, or `None` when nothing is pending. A class that polls
    /// is still watched outside the directories it could not watch: a change seen there is due
    /// on the quiet clock as in a watched class, the poll covers the rest.
    fn due(&self, mode: Mode) -> Option<(Instant, Trigger)> {
        match mode {
            Mode::Polled => {
                let poll = (self.last_snap + self.max, Trigger::Poll);
                Some(match self.due(Mode::Watched) {
                    Some(seen) if seen.0 < poll.0 => seen,
                    _ => poll,
                })
            }
            Mode::Watched => {
                let first = self.first_change?;
                let last = self.last_change.unwrap_or(first);
                let quiet_at = last + self.quiet;
                let max_at = first + self.max;
                Some(if quiet_at <= max_at {
                    (quiet_at, Trigger::Quiet)
                } else {
                    (max_at, Trigger::MaxInterval)
                })
            }
        }
    }
}

#[derive(Debug)]
struct State {
    small: Clock,
    bulk: Clock,
    small_mode: Mode,
    bulk_mode: Mode,
    /// The watcher overflowed: the cadence thread drops it.
    overflowed: bool,
    /// The shipper asked for a refused capture to be rebuilt from disk: the small-class loop
    /// runs [`CaptureEngine::repair`] next.
    repair: bool,
    stop: bool,
}

/// Counters, for status and tests.
#[derive(Debug, Default)]
struct Counters {
    small_snaps: AtomicU64,
    small_staged: AtomicU64,
    bulk_snaps: AtomicU64,
    bulk_staged: AtomicU64,
    quiet_fired: AtomicU64,
    max_fired: AtomicU64,
    poll_fired: AtomicU64,
    forced: AtomicU64,
    preemptions: AtomicU64,
    overflows: AtomicU64,
    /// Directories found unwatchable after the watcher started.
    unwatched: AtomicU64,
    bulk_running: AtomicBool,
}

/// A snapshot of the runner's counters and modes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CadenceSnapshot {
    /// Small-class mode.
    pub small_mode: Mode,
    /// Bulk-class mode.
    pub bulk_mode: Mode,
    /// Small-class snaps taken (scheduled and forced).
    pub small_snaps: u64,
    /// Small-class snaps that staged something.
    pub small_staged: u64,
    /// Bulk-class snaps completed.
    pub bulk_snaps: u64,
    /// Bulk-class snaps that staged something.
    pub bulk_staged: u64,
    /// Scheduled snaps fired by the quiet timer.
    pub quiet_fired: u64,
    /// Scheduled snaps fired by the maximum interval.
    pub max_fired: u64,
    /// Scheduled snaps fired by polling.
    pub poll_fired: u64,
    /// Forced snaps (turn, checkpoint, flush).
    pub forced: u64,
    /// Times a bulk build yielded to a small-class snap.
    pub preemptions: u64,
    /// Watcher overflows seen.
    pub overflows: u64,
    /// Whether a bulk build is paused mid-way.
    pub bulk_in_progress: bool,
    /// Whether a bulk snap is running (building, or waiting to resume after a yield).
    pub bulk_running: bool,
    /// Whether the small class is dirty.
    pub small_dirty: bool,
    /// Whether the bulk class is dirty.
    pub bulk_dirty: bool,
}

struct Shared {
    engine: Mutex<CaptureEngine>,
    staging: Arc<Staging>,
    shipper: Arc<Shipper>,
    worker: Mutex<Option<ShipWorker>>,
    state: Mutex<State>,
    cv: Condvar,
    /// Small-class snaps waiting for (or holding) the engine; a bulk build yields while > 0.
    small_waiting: AtomicUsize,
    /// Forced bulk snaps (a final flush) waiting for (or holding) the engine; a scheduled bulk
    /// build yields to them, and the forced snap resumes its progress.
    forced_bulk: AtomicUsize,
    yield_lock: Mutex<()>,
    yield_cv: Condvar,
    watch: Mutex<Option<WatchHandle>>,
    /// `false` while snaps must not be taken (the daemon is hard-stopping).
    allow: Mutex<Option<Arc<dyn Fn() -> bool + Send + Sync>>>,
    capture_bulk: bool,
    started: AtomicBool,
    seq: AtomicU64,
    counters: Counters,
    /// Each class's snaps, failed and not: small, bulk.
    health: Mutex<[SnapHealth; 2]>,
    /// Change signals the watcher delivered (either class), for [`CadenceRunner::final_is_current`].
    changes: AtomicU64,
    /// Captures staged by snaps (either class, any kind) and by sealing, for
    /// [`CadenceRunner::chain_sealed`].
    staged: AtomicU64,
    /// The last final flush snapped every class without an error. `None` until one does, and
    /// after a final flush whose snaps failed.
    sealed: Mutex<Option<Seal>>,
}

/// What a final flush that snapped every class left: the change count before its first snap,
/// the staged count once it had sealed the chain with a final capture, and whether the chain's
/// newest capture carries the executor's final seal, registered
/// ([`CadenceRunner::final_sealed`]).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Seal {
    changes: u64,
    staged: u64,
    completion: bool,
}

impl Shared {
    fn record(&self, class: Class, result: Result<(), String>) {
        let mut health = self.health.lock().unwrap_or_else(PoisonError::into_inner);
        health[usize::from(class == Class::Bulk)].record(class, result);
    }

    fn state(&self) -> MutexGuard<'_, State> {
        self.state.lock().unwrap_or_else(PoisonError::into_inner)
    }

    fn engine(&self) -> MutexGuard<'_, CaptureEngine> {
        self.engine.lock().unwrap_or_else(PoisonError::into_inner)
    }

    fn allowed(&self) -> bool {
        self.allow
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .as_ref()
            .is_none_or(|f| f())
    }

    fn signal(&self, signal: ChangeSignal) {
        let now = Instant::now();
        // Every signal counts (a change, an overflow, an unwatched directory): a final flush
        // after it snaps again.
        self.changes.fetch_add(1, Ordering::SeqCst);
        let mut st = self.state();
        match signal {
            ChangeSignal::Changed(Class::Small) => st.small.dirty(now),
            ChangeSignal::Changed(Class::Bulk) => st.bulk.dirty(now),
            ChangeSignal::Overflow => {
                self.counters.overflows.fetch_add(1, Ordering::Relaxed);
                if !st.overflowed {
                    tracing::warn!(
                        "capture watcher overflowed (IN_Q_OVERFLOW); polling at the maximum \
                         intervals from now on"
                    );
                }
                st.overflowed = true;
                st.small_mode = Mode::Polled;
                st.bulk_mode = Mode::Polled;
                // Reconcile now: the next poll is due immediately.
                st.small.last_snap = now.checked_sub(st.small.max).unwrap_or(now);
                st.bulk.last_snap = now.checked_sub(st.bulk.max).unwrap_or(now);
            }
            ChangeSignal::Unwatched(class) => {
                self.counters.unwatched.fetch_add(1, Ordering::Relaxed);
                let st = &mut *st;
                let (mode, clock) = match class {
                    Class::Small => (&mut st.small_mode, &mut st.small),
                    Class::Bulk => (&mut st.bulk_mode, &mut st.bulk),
                };
                if *mode == Mode::Watched {
                    tracing::warn!(
                        ?class,
                        "a directory of the class could not be watched; it polls at its \
                         maximum interval until the watcher watches it (the rest of the class \
                         stays watched)"
                    );
                }
                *mode = Mode::Polled;
                // What changed there is unseen: the next poll is due now.
                clock.last_snap = now.checked_sub(clock.max).unwrap_or(now);
            }
            ChangeSignal::Rewatched(class) => {
                let st = &mut *st;
                let (mode, clock) = match class {
                    Class::Small => (&mut st.small_mode, &mut st.small),
                    Class::Bulk => (&mut st.bulk_mode, &mut st.bulk),
                };
                // After an overflow every class polls for good: events were lost.
                if !st.overflowed {
                    if *mode == Mode::Polled {
                        tracing::info!(?class, "the class is watched again");
                    }
                    *mode = Mode::Watched;
                }
                // What changed while it polled went unseen: a snap on the quiet clock reads it.
                clock.dirty(now);
            }
        }
        drop(st);
        self.cv.notify_all();
    }

    /// A small-class snap of `kind`: flags the engine so a bulk build yields, clears the small
    /// clock (a change during the snap re-dirties it), snaps, wakes the shipper.
    fn small_snap(&self, kind: CaptureKind) -> Result<StagedCapture, EngineError> {
        self.state().small.clear();
        self.small_waiting.fetch_add(1, Ordering::SeqCst);
        let seq = self.seq.fetch_add(1, Ordering::Relaxed);
        let result = self.engine().snap(SnapRequest {
            kind,
            class: Class::Small,
            seq,
        });
        self.small_waiting.fetch_sub(1, Ordering::SeqCst);
        {
            let _g = self
                .yield_lock
                .lock()
                .unwrap_or_else(PoisonError::into_inner);
            self.yield_cv.notify_all();
        }
        self.state().small.last_snap = Instant::now();
        self.counters.small_snaps.fetch_add(1, Ordering::Relaxed);
        self.record(
            Class::Small,
            result.as_ref().map(|_| ()).map_err(ToString::to_string),
        );
        if let Ok(staged) = &result
            && !staged.unchanged
        {
            self.staged.fetch_add(1, Ordering::SeqCst);
            self.counters.small_staged.fetch_add(1, Ordering::Relaxed);
            self.wake_worker();
        }
        self.cv.notify_all();
        result
    }

    /// A bulk-class snap, yielding to small-class snaps until it completes. A `forced` one (a
    /// final flush) also preempts a scheduled bulk build in progress: that build yields at its
    /// next chunk boundary and this snap resumes its progress, reading only what changed since
    /// (a file's size, mtime or inode moved), so it captures the tree as it is now without
    /// waiting for the scheduled build to finish first.
    fn bulk_snap(&self, forced: bool) -> Result<StagedCapture, EngineError> {
        if forced {
            self.forced_bulk.fetch_add(1, Ordering::SeqCst);
        }
        let result = self.bulk_snap_inner(forced);
        if forced {
            self.forced_bulk.fetch_sub(1, Ordering::SeqCst);
            let _g = self
                .yield_lock
                .lock()
                .unwrap_or_else(PoisonError::into_inner);
            self.yield_cv.notify_all();
        }
        result
    }

    fn bulk_snap_inner(&self, forced: bool) -> Result<StagedCapture, EngineError> {
        self.state().bulk.clear();
        self.counters.bulk_running.store(true, Ordering::SeqCst);
        let seq = self.seq.fetch_add(1, Ordering::Relaxed);
        let preempt = || {
            self.small_waiting.load(Ordering::SeqCst) > 0
                || (!forced && self.forced_bulk.load(Ordering::SeqCst) > 0)
        };
        let result = loop {
            // Let a waiting small snap take the engine first.
            {
                let mut g = self
                    .yield_lock
                    .lock()
                    .unwrap_or_else(PoisonError::into_inner);
                while preempt() && (forced || !self.state().stop) {
                    g = self
                        .yield_cv
                        .wait_timeout(g, Duration::from_millis(50))
                        .unwrap_or_else(PoisonError::into_inner)
                        .0;
                }
            }
            // A forced snap runs on a stopped runner (the daemon is shutting down, and this is
            // the capture that must reach the store); a scheduled one does not, nor one that
            // is no longer allowed (a final flush stopped every writer while it yielded: the
            // forced snap took its progress, and resuming would only build again after it).
            if !forced && (self.state().stop || !self.allowed()) {
                self.counters.bulk_running.store(false, Ordering::SeqCst);
                return Err(EngineError::Io(std::io::Error::other(
                    "scheduled bulk snap stopped: the runner stopped or snaps are not allowed",
                )));
            }
            let outcome = self.engine().snap_preemptible(
                SnapRequest {
                    // A final flush's forced snap is a `final` one, as its small snap is: the
                    // engine holds a final capture to stricter rules than a scheduled one.
                    kind: if forced {
                        CaptureKind::Final
                    } else {
                        CaptureKind::Auto
                    },
                    class: Class::Bulk,
                    seq,
                },
                &preempt,
            );
            match outcome {
                Ok(SnapOutcome::Preempted) => {
                    self.counters.preemptions.fetch_add(1, Ordering::Relaxed);
                }
                Ok(SnapOutcome::Staged(staged)) => break Ok(*staged),
                Err(e) => break Err(e),
            }
        };
        self.counters.bulk_running.store(false, Ordering::SeqCst);
        self.state().bulk.last_snap = Instant::now();
        self.counters.bulk_snaps.fetch_add(1, Ordering::Relaxed);
        self.record(
            Class::Bulk,
            result.as_ref().map(|_| ()).map_err(ToString::to_string),
        );
        if let Ok(staged) = &result
            && !staged.unchanged
        {
            self.staged.fetch_add(1, Ordering::SeqCst);
            self.counters.bulk_staged.fetch_add(1, Ordering::Relaxed);
            self.wake_worker();
        }
        self.cv.notify_all();
        result
    }

    fn wake_worker(&self) {
        if let Some(w) = self
            .worker
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .as_ref()
        {
            w.wake();
        }
    }

    /// Wait until the watcher delivered every change made before now
    /// ([`WatchHandle::settle`]); `Ok` at once without a watcher (every class polls, and a
    /// snap reads it whole). `Err` says why nothing can be said of what is still queued.
    fn settle_watcher(&self) -> Result<(), String> {
        match self
            .watch
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .as_ref()
        {
            Some(handle) if !handle.settle(SETTLE_TIMEOUT) => Err(format!(
                "the watcher did not deliver its fence within {SETTLE_TIMEOUT:?}"
            )),
            _ => Ok(()),
        }
    }

    fn drop_watch(&self) {
        let _ = self
            .watch
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .take();
    }

    /// The small-class loop.
    fn run_small(&self) {
        loop {
            let (due, overflowed, repair) = {
                let mut st = self.state();
                if st.stop {
                    return;
                }
                let repair = std::mem::take(&mut st.repair);
                (st.small.due(st.small_mode), st.overflowed, repair)
            };
            if repair {
                match self.engine().repair() {
                    Ok(true) => self.wake_worker(),
                    Ok(false) => {}
                    Err(error) => {
                        tracing::error!(%error, "rebuilding a refused capture failed");
                    }
                }
                continue;
            }
            if overflowed {
                self.drop_watch();
            }
            let now = Instant::now();
            match due {
                Some((at, trigger)) if at <= now => {
                    if !self.allowed() || self.shipper.is_fenced() {
                        // Not now: clear the clock so a polled class does not spin, and let
                        // the next change (or poll) try again.
                        let mut st = self.state();
                        st.small.clear();
                        st.small.last_snap = now;
                        drop(st);
                        continue;
                    }
                    match trigger {
                        Trigger::Quiet => &self.counters.quiet_fired,
                        Trigger::MaxInterval => &self.counters.max_fired,
                        Trigger::Poll => &self.counters.poll_fired,
                    }
                    .fetch_add(1, Ordering::Relaxed);
                    match self.small_snap(CaptureKind::Auto) {
                        Ok(staged) if !staged.unchanged => {
                            tracing::debug!(n = staged.n, ?trigger, "auto capture staged");
                        }
                        Ok(_) => {}
                        Err(error) => tracing::warn!(%error, ?trigger, "auto capture failed"),
                    }
                }
                Some((at, _)) => {
                    let st = self.state();
                    if !st.stop {
                        drop(
                            self.cv
                                .wait_timeout(st, at.saturating_duration_since(now))
                                .unwrap_or_else(PoisonError::into_inner),
                        );
                    }
                }
                None => {
                    let st = self.state();
                    if !st.stop {
                        drop(self.cv.wait(st).unwrap_or_else(PoisonError::into_inner));
                    }
                }
            }
        }
    }

    /// The bulk-class loop.
    fn run_bulk(&self) {
        loop {
            let due = {
                let st = self.state();
                if st.stop {
                    return;
                }
                st.bulk.due(st.bulk_mode)
            };
            let now = Instant::now();
            match due {
                Some((at, trigger)) if at <= now => {
                    // A bulk class held for the byte quota still snaps: the newer capture
                    // replaces the held one in the queue, and nothing is dropped.
                    if !self.allowed() || self.shipper.is_fenced() {
                        let mut st = self.state();
                        st.bulk.clear();
                        st.bulk.last_snap = now;
                        drop(st);
                        continue;
                    }
                    match self.bulk_snap(false) {
                        Ok(staged) if !staged.unchanged => {
                            tracing::debug!(n = staged.n, ?trigger, "bulk capture staged");
                        }
                        Ok(_) => {}
                        Err(error) => tracing::warn!(%error, ?trigger, "bulk capture failed"),
                    }
                }
                Some((at, _)) => {
                    let st = self.state();
                    if !st.stop {
                        drop(
                            self.cv
                                .wait_timeout(st, at.saturating_duration_since(now))
                                .unwrap_or_else(PoisonError::into_inner),
                        );
                    }
                }
                None => {
                    let st = self.state();
                    if !st.stop {
                        drop(self.cv.wait(st).unwrap_or_else(PoisonError::into_inner));
                    }
                }
            }
        }
    }
}

/// The cadence runner: the engine, its watcher, the two class clocks and the ship worker.
pub struct CadenceRunner {
    shared: Arc<Shared>,
    threads: Mutex<Vec<thread::JoinHandle<()>>>,
}

impl std::fmt::Debug for CadenceRunner {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CadenceRunner")
            .field("snapshot", &self.snapshot())
            .finish_non_exhaustive()
    }
}

impl CadenceRunner {
    /// Wrap an engine and its shipper. Nothing runs until [`CadenceRunner::start`].
    #[must_use]
    pub fn new(engine: CaptureEngine, shipper: Arc<Shipper>) -> Self {
        let config = engine.config();
        let cadence = config.cadence;
        let capture_bulk = config.capture_bulk;
        let staging = engine.staging();
        let runner = Self {
            shared: Arc::new(Shared {
                engine: Mutex::new(engine),
                staging,
                shipper,
                worker: Mutex::new(None),
                state: Mutex::new(State {
                    small: Clock::new(cadence.quiet, cadence.max_interval),
                    bulk: Clock::new(cadence.bulk_quiet, cadence.bulk_max_interval),
                    small_mode: Mode::Polled,
                    bulk_mode: Mode::Polled,
                    overflowed: false,
                    repair: false,
                    stop: false,
                }),
                cv: Condvar::new(),
                small_waiting: AtomicUsize::new(0),
                forced_bulk: AtomicUsize::new(0),
                yield_lock: Mutex::new(()),
                yield_cv: Condvar::new(),
                watch: Mutex::new(None),
                allow: Mutex::new(None),
                capture_bulk,
                started: AtomicBool::new(false),
                seq: AtomicU64::new(0),
                counters: Counters::default(),
                health: Mutex::new([SnapHealth::default(), SnapHealth::default()]),
                changes: AtomicU64::new(0),
                staged: AtomicU64::new(0),
                sealed: Mutex::new(None),
            }),
            threads: Mutex::new(Vec::new()),
        };
        // A refused capture the shipper cannot fix by uploading again wakes the small-class
        // loop, which rebuilds it from disk.
        let weak = Arc::downgrade(&runner.shared);
        runner.shared.shipper.set_repair_hook(Arc::new(move || {
            if let Some(shared) = weak.upgrade() {
                shared.state().repair = true;
                shared.cv.notify_all();
            }
        }));
        runner
    }

    /// Start the watcher, the ship worker and the class loops. `allow` is asked before every
    /// scheduled snap (the daemon answers `false` while hard-stopping); forced snaps ignore it.
    /// Idempotent.
    pub fn start(&self, allow: Option<Arc<dyn Fn() -> bool + Send + Sync>>) {
        if self.shared.started.swap(true, Ordering::SeqCst) {
            return;
        }
        *self
            .shared
            .allow
            .lock()
            .unwrap_or_else(PoisonError::into_inner) = allow;
        match ShipWorker::spawn(Arc::clone(&self.shared.shipper), SHIP_TICK) {
            Ok(worker) => {
                *self
                    .shared
                    .worker
                    .lock()
                    .unwrap_or_else(PoisonError::into_inner) = Some(worker);
            }
            Err(error) => tracing::error!(%error, "capture ship worker failed to start"),
        }

        let spec = {
            let engine = self.shared.engine();
            let config = engine.config();
            WatchSpec {
                root: config.root.clone(),
                harness_home: config.harness_home.clone(),
                staging_dir: config.staging_dir(),
                bulk_dirs: config.bulk_dirs.clone(),
                capture_bulk: config.capture_bulk,
                policy: config.watch.clone(),
                invalidations: Some(engine.invalidations()),
            }
        };
        let weak: Weak<Shared> = Arc::downgrade(&self.shared);
        let on_signal: Arc<dyn Fn(ChangeSignal) + Send + Sync> = Arc::new(move |signal| {
            if let Some(shared) = weak.upgrade() {
                shared.signal(signal);
            }
        });
        let (small_mode, bulk_mode) = match watch::start(&spec, on_signal) {
            Ok(started) => {
                *self
                    .shared
                    .watch
                    .lock()
                    .unwrap_or_else(PoisonError::into_inner) = started.handle;
                (started.small, started.bulk)
            }
            Err(error) => {
                tracing::warn!(%error, "capture watcher could not start; polling at the maximum intervals");
                (Mode::Polled, Mode::Polled)
            }
        };
        {
            let mut st = self.shared.state();
            st.small_mode = small_mode;
            st.bulk_mode = bulk_mode;
            let now = Instant::now();
            st.small.last_snap = now;
            st.bulk.last_snap = now;
        }

        let mut threads = self.threads.lock().unwrap_or_else(PoisonError::into_inner);
        let shared = Arc::clone(&self.shared);
        if let Ok(h) = thread::Builder::new()
            .name("capture-cadence".into())
            .spawn(move || shared.run_small())
        {
            threads.push(h);
        }
        if self.shared.capture_bulk {
            let shared = Arc::clone(&self.shared);
            if let Ok(h) = thread::Builder::new()
                .name("capture-bulk".into())
                .spawn(move || shared.run_bulk())
            {
                threads.push(h);
            }
        }
    }

    /// Feed a change signal by hand (tests; a daemon-side event source).
    pub fn signal(&self, signal: ChangeSignal) {
        self.shared.signal(signal);
    }

    /// A forced small-class snap of `kind` (turn boundary, checkpoint): ahead of the timers and
    /// of any bulk build. Blocking.
    ///
    /// # Errors
    /// The engine's error.
    pub fn snap(&self, kind: CaptureKind) -> Result<StagedCapture, EngineError> {
        self.shared.counters.forced.fetch_add(1, Ordering::Relaxed);
        self.shared.small_snap(kind)
    }

    /// A forced small-class snap of `kind`, then ship and register it and every capture ahead
    /// of it, bounded by `deadline` (none: until they are registered). Blocking. A bulk capture
    /// whose objects are still uploading does not hold the flush: the snap is staged ahead of
    /// it and the flush returns once the snap is registered, while the worker keeps uploading
    /// the bulk capture (`capture.status` counts it in `pending` and `pending_bulk`).
    ///
    /// `kind` [`CaptureKind::Final`] is [`CadenceRunner::flush_final`], and anything short of
    /// complete is an error ([`EngineError::Incomplete`]).
    ///
    /// # Errors
    /// The engine's error, or the shipper's when shipping stops on a fence or a conflict.
    pub fn flush(
        &self,
        kind: CaptureKind,
        deadline: Option<Duration>,
    ) -> Result<usize, EngineError> {
        if kind == CaptureKind::Final {
            let flushed = self.flush_final(deadline);
            return match flushed.incomplete {
                None => Ok(flushed.shipped),
                Some(incomplete) => Err(EngineError::Incomplete(incomplete)),
            };
        }
        let until = deadline.map(|d| Instant::now() + d);
        if self.sealed_and_current() {
            // After a complete final flush, over the disk it captured: a snap would only add
            // a capture of the same tree after the final one, and the chain would no longer
            // end on it (observed: Mend's Stop sent two suspend flushes after a final one, and
            // the head read `suspend`). Nothing is snapped; what is left ships.
            tracing::info!(
                ?kind,
                "flush after a complete final flush over an unchanged disk: nothing to snap"
            );
        } else {
            self.snap(kind)?;
        }
        Ok(self
            .shared
            .shipper
            .flush_small(until.map(|u| u.saturating_duration_since(Instant::now())))?)
    }

    /// Whether a final flush now would find the disk as the last one captured it, so it need
    /// snap nothing: the last final flush snapped every class without an error, snaps are no
    /// longer allowed (the daemon's hook says so once a final flush stopped every writer and
    /// admission is closed), and the watcher — watching both classes, never overflowed — has
    /// delivered no change since before that flush's first snap. Not a guess from "the writers
    /// are stopped": a class that polls, a change the watcher saw, or a runner without the
    /// hook answers `false`, and the flush snaps again.
    ///
    /// It says nothing of the chain: a capture staged after that flush (a turn boundary) leaves
    /// the disk current and the chain unsealed ([`Self::chain_sealed`]).
    #[must_use]
    pub fn final_is_current(&self) -> bool {
        self.every_class_watched() && self.final_is_current_as_snapped()
    }

    /// Whether the watcher sees every class now: watching both (the bulk class only when it is
    /// captured), never overflowed. A class that polls delivers no change, so nothing it holds
    /// can be known unchanged since a snap.
    #[must_use]
    pub fn every_class_watched(&self) -> bool {
        let st = self.shared.state();
        !st.overflowed
            && st.small_mode == Mode::Watched
            && (!self.shared.capture_bulk || st.bulk_mode == Mode::Watched)
    }

    /// [`Self::final_is_current`] as of the last final flush's own snaps: nothing the watcher
    /// delivered since before its first snap, no repair asked for, no bulk build paused mid-way,
    /// snaps no longer allowed — whether or not every class is watched. A final flush answers by
    /// this: its snaps, taken after every writer stopped, read every class as it was, a polled
    /// one included; only a later read ([`Self::final_is_current`]) cannot vouch for a class
    /// that polls.
    #[must_use]
    pub fn final_is_current_as_snapped(&self) -> bool {
        // A bulk build paused mid-way holds progress no capture lists yet; never waits for the
        // engine (`capture.status` reads this).
        !self.shared.allowed()
            && self.snaps_still_current(
                self.shared
                    .engine
                    .try_lock()
                    .is_ok_and(|e| !e.bulk_in_progress()),
            )
    }

    /// Whether nothing moved since the last final flush's snaps: no change signal since before
    /// its first snap, no repair still asked for, no bulk build paused mid-way. What a final
    /// flush checks before it seals, and what [`Self::final_is_current_as_snapped`] reads,
    /// whether or not the caller's admission hook is installed (decision 15: a seal is written
    /// under the predicate `complete` is answered by).
    fn unchanged_since_final_snaps(&self) -> bool {
        let bulk_idle = !self.shared.engine().bulk_in_progress();
        self.snaps_still_current(bulk_idle)
    }

    /// [`Self::unchanged_since_final_snaps`], `bulk_idle` read by the caller. A repair is still
    /// asked for while the staging holds its request (the worker's wake-up flag for it is only
    /// that: a final flush's shipping rebuilds a refused capture itself).
    fn snaps_still_current(&self, bulk_idle: bool) -> bool {
        let Some(sealed) = *self
            .shared
            .sealed
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
        else {
            return false;
        };
        bulk_idle
            && self.shared.changes.load(Ordering::SeqCst) == sealed.changes
            && self.shared.staging.repair_request().is_none()
    }

    /// Whether the chain ends on the final capture of the last final flush that snapped every
    /// class: nothing was staged after it. A capture staged since (a turn boundary, a
    /// checkpoint) is the chain's head until the next final flush seals it.
    #[must_use]
    pub fn chain_sealed(&self) -> bool {
        self.shared
            .sealed
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .is_some_and(|seal| seal.staged == self.shared.staged.load(Ordering::SeqCst))
    }

    /// [`Self::final_is_current`] and [`Self::chain_sealed`]: a complete final flush's capture
    /// is the chain's head and the disk is as it captured it.
    #[must_use]
    pub fn sealed_and_current(&self) -> bool {
        self.final_is_current() && self.chain_sealed()
    }

    /// The final flush — the executor is going away, and its disk with it; the caller has
    /// stopped every writer first. A forced small-class snap AND a forced bulk-class snap (the
    /// dependency tree as it is now, whatever the bulk clocks say; a scheduled bulk build in
    /// progress yields to it and the forced snap resumes its progress; not taken when the small
    /// snap failed, since the flush cannot complete then), then ship and register everything,
    /// bulk included ([`Shipper::flush_final`]). Complete only when both snaps
    /// succeeded and nothing is left staged: a failed snap no longer passes for success because
    /// older captures drained (a failed bulk snap was logged and ignored), and neither does a
    /// fence, a conflict or the deadline. Whatever fails, what could be staged still ships
    /// before this returns (bounded by `deadline`, none: until the process ends), and the rest
    /// stays staged. Blocking.
    ///
    /// The chain ends as the disk is: a small snap whose overlay names the bulk class's names
    /// of tracked files is taken again after a bulk snap that staged a capture
    /// ([`CaptureEngine::small_depends_on_bulk`]), and a newest capture of another kind is
    /// sealed with a final one ([`CaptureEngine::seal_final`]) — so once this reports complete,
    /// a final flush asked again stages nothing. When [`Self::final_is_current`], it snaps
    /// nothing at all and only ships what is left.
    pub fn flush_final(&self, deadline: Option<Duration>) -> FinalFlush {
        self.flush_final_sealing(deadline, true)
    }

    /// One round of a final flush's snaps ([`Self::flush_final_sealing`]): nothing when the
    /// disk is as the last final flush captured it (a newest capture of another kind sealed with
    /// a final one), else a forced small snap, a forced bulk snap, the small class again when
    /// its overlay depends on the bulk class, and a final capture sealing the chain. Why the
    /// flush cannot complete, when it cannot.
    fn final_snaps(&self) -> Option<Incomplete> {
        let mut incomplete = None;
        if self.final_is_current() {
            tracing::info!(
                "final flush: the disk is as the last final flush captured it (the writers are \
                 stopped and the watcher saw no change since); nothing to snap"
            );
            // Something was staged after that flush's final capture (a turn boundary, a
            // suspend flush over a disk the watcher does not see): the chain ends on it, not
            // on a final capture. Seal it with one (the disk is as it was, so the final capture
            // lists what the newest one does) before this reports complete.
            if !self.chain_sealed() {
                let seq = self.shared.seq.fetch_add(1, Ordering::Relaxed);
                let sealed = self.shared.engine().seal_final(seq);
                match sealed {
                    Ok(staged) => {
                        if staged.is_some() {
                            self.shared.staged.fetch_add(1, Ordering::SeqCst);
                            self.shared.wake_worker();
                        }
                        if let Some(seal) = self
                            .shared
                            .sealed
                            .lock()
                            .unwrap_or_else(PoisonError::into_inner)
                            .as_mut()
                        {
                            seal.staged = self.shared.staged.load(Ordering::SeqCst);
                        }
                    }
                    Err(error) => {
                        tracing::error!(%error, "staging the final capture failed");
                        incomplete = Some(Incomplete::from_snap(Class::Small, &error));
                    }
                }
            }
        } else {
            *self
                .shared
                .sealed
                .lock()
                .unwrap_or_else(PoisonError::into_inner) = None;
            let changes = self.shared.changes.load(Ordering::SeqCst);
            if let Err(error) = self.snap(CaptureKind::Final) {
                tracing::error!(%error, "final small-class snap failed");
                incomplete = Some(Incomplete::from_snap(Class::Small, &error));
            }
            let mut bulk_staged = false;
            // The small snap failed: this flush is incomplete whatever the bulk snap does, and
            // nothing it stages would be read as saved. The bulk class is snapped by the flush
            // that can complete (a dependency tree is 2.5 s or more to walk; a kept executor
            // asked again and again spent it every time).
            if self.shared.capture_bulk && incomplete.is_none() {
                match self.shared.bulk_snap(true) {
                    Ok(staged) => bulk_staged = !staged.unchanged,
                    Err(error) => {
                        tracing::error!(%error, "final bulk-class snap failed");
                        incomplete.get_or_insert(Incomplete::from_snap(Class::Bulk, &error));
                    }
                }
            }
            // A link to a bulk name the first small snap left out (the bulk capture did not
            // hold it as it is) is recorded by a small snap after the bulk snap, whether or not
            // that one staged anything.
            if incomplete.is_none()
                && (bulk_staged || self.shared.engine().links_deferred())
                && self.shared.engine().small_depends_on_bulk()
                && let Err(error) = self.shared.small_snap(CaptureKind::Final)
            {
                tracing::error!(%error, "final small-class snap after the bulk capture failed");
                incomplete = Some(Incomplete::from_snap(Class::Small, &error));
            }
            // Still left out: the captures do not hold the disk's hardlinks as they are.
            if incomplete.is_none() && self.shared.engine().links_deferred() {
                incomplete = Some(Incomplete::SnapshotFailed {
                    class: Class::Small,
                    error: "a hardlink the workspace shares with the bulk class is not in the \
                            bulk capture as it is on disk"
                        .to_owned(),
                });
            }
            if incomplete.is_none() {
                let seq = self.shared.seq.fetch_add(1, Ordering::Relaxed);
                let sealed = self.shared.engine().seal_final(seq);
                match sealed {
                    Ok(Some(_)) => {
                        self.shared.staged.fetch_add(1, Ordering::SeqCst);
                        self.shared.wake_worker();
                    }
                    Ok(None) => {}
                    Err(error) => {
                        tracing::error!(%error, "staging the final capture failed");
                        incomplete = Some(Incomplete::from_snap(Class::Small, &error));
                    }
                }
            }
            if incomplete.is_none() {
                *self
                    .shared
                    .sealed
                    .lock()
                    .unwrap_or_else(PoisonError::into_inner) = Some(Seal {
                    changes,
                    staged: self.shared.staged.load(Ordering::SeqCst),
                    completion: false,
                });
            }
        }
        incomplete
    }

    /// [`Self::flush_final`], sealing the chain ([`crate::manifest::FinalSeal`]) only when
    /// `writers_stopped`: the caller vouches that every writer was stopped before it. Once both
    /// snaps succeeded and everything staged registered, one more capture — the newest one's
    /// sections, `kind: final` — carrying the engine's seal is staged and shipped, and the flush
    /// is complete only once it registered ([`Incomplete::Sealing`] otherwise). A flush asked
    /// again over a sealed chain stages nothing more. Without an executor
    /// ([`crate::engine::CaptureConfig::executor`]) nothing is sealed. When the writers were
    /// not stopped, nothing is sealed either: the caller reports the flush incomplete. Nor when
    /// the disk changed after the snaps: they are taken again, at most [`FINAL_ROUNDS`] rounds,
    /// and a disk still changing is [`Incomplete::Changed`] (decision 15).
    pub fn flush_final_sealing(
        &self,
        deadline: Option<Duration>,
        writers_stopped: bool,
    ) -> FinalFlush {
        let until = deadline.map(|d| Instant::now() + d);
        let mut shipped = 0;
        let mut round = 0;
        let mut incomplete = loop {
            round += 1;
            // Every change made before the flush was asked for is counted before its snaps take
            // their baseline: a write the snaps read, delivered only after them, would read as a
            // change since and cost a round.
            if let Err(error) = self.shared.settle_watcher() {
                tracing::warn!(%error, "final flush: the watcher could not be settled");
            }
            let mut incomplete = self.final_snaps();
            shipped += self.ship_final(until, &mut incomplete);
            // A store that cannot hold what was captured: everything shipped all the same (it
            // is the most the store can take), but nothing is sealed and the flush is not
            // complete.
            if incomplete.is_none()
                && let Some(gap) = self.shared.engine().fidelity_gap()
            {
                tracing::error!(%gap, "final flush: the store cannot hold what the capture holds");
                incomplete = Some(Incomplete::StoreFidelity(gap));
            }
            // Complete means current, and so does a seal (decision 15): the flush's snaps must be
            // the disk as it is now. Every change the watcher saw happen before now is counted
            // first (a fence through its event stream); one counted since the first snap (a
            // write that raced the snaps, an overflow) and the classes are snapped again,
            // bounded; still changing, and the flush is incomplete and nothing is sealed.
            // Nothing the flush runs changes the disk (no filter or hook of the user's runs in a
            // capture's git), so with the writers stopped the second round holds still.
            if incomplete.is_none() && writers_stopped {
                let changed = match self.shared.settle_watcher() {
                    Ok(()) => (!self.unchanged_since_final_snaps())
                        .then(|| "the watcher saw a change after the final snaps".to_owned()),
                    Err(error) => Some(error),
                };
                if let Some(change) = changed {
                    let time_left = until.is_none_or(|u| Instant::now() < u);
                    if round < FINAL_ROUNDS && time_left {
                        tracing::warn!(
                            round,
                            %change,
                            "final flush: the disk changed after its snaps; snapping again"
                        );
                        continue;
                    }
                    tracing::error!(%change, "final flush: the disk kept changing; no seal");
                    incomplete = Some(Incomplete::Changed(change));
                }
            }
            break incomplete;
        };
        // Everything registered: seal the completed flush on the chain, and say `complete` only
        // once the sealing capture registered. Bounded: a register refused and rebuilt in its
        // place loses the seal, and it is staged once more.
        let mut attempts = 0;
        while incomplete.is_none() && writers_stopped && !self.completion_sealed() {
            attempts += 1;
            if attempts > 3 {
                incomplete = Some(Incomplete::Sealing(
                    "the sealing capture was staged three times and did not register".to_owned(),
                ));
                break;
            }
            let seq = self.shared.seq.fetch_add(1, Ordering::Relaxed);
            let staged = self.shared.engine().seal_complete(seq);
            match staged {
                Ok(Some(_)) => {
                    self.shared.staged.fetch_add(1, Ordering::SeqCst);
                    self.with_seal(|seal| seal.staged = self.shared.staged.load(Ordering::SeqCst));
                    self.shared.wake_worker();
                }
                Ok(None) => break,
                Err(error) => {
                    tracing::error!(%error, "staging the final seal failed");
                    incomplete = Some(Incomplete::Sealing(error.to_string()));
                    break;
                }
            }
            shipped += self.ship_final(until, &mut incomplete);
        }
        // Sealed: nothing to seal under (no executor), or this flush completed with the
        // writers stopped and the newest capture carries the seal, registered.
        let sealed = {
            let engine = self.shared.engine();
            engine.final_seal().is_none()
                || (incomplete.is_none() && writers_stopped && engine.completion_sealed())
        };
        self.with_seal(|seal| seal.completion = sealed);
        FinalFlush {
            shipped,
            incomplete,
        }
    }

    /// Ship and register everything staged ([`Shipper::flush_final`]) until `until`, rebuilding
    /// a refused capture from disk when the registrar asks for it; the first failure lands in
    /// `incomplete`. Returns the captures registered.
    fn ship_final(&self, until: Option<Instant>, incomplete: &mut Option<Incomplete>) -> usize {
        let left = || until.map(|u| u.saturating_duration_since(Instant::now()));
        let mut shipped = 0;
        let mut repairs = 0u32;
        loop {
            match self.shared.shipper.flush_final(left()) {
                Ok(n) => {
                    shipped += n;
                    break;
                }
                // A refused capture waits to be rebuilt from disk (the writers are stopped, so
                // the disk is what the final capture must hold): rebuild it, ship again.
                Err(ShipError::RepairPending { n }) => {
                    repairs += 1;
                    if repairs > 1 {
                        // Refused again after a rebuild: back off, never give up while there
                        // is time (the daemon's own flush has no deadline).
                        let wait = Duration::from_secs(1 << (repairs - 2).min(5));
                        thread::sleep(left().map_or(wait, |l| wait.min(l)));
                    }
                    if until.is_some_and(|u| Instant::now() >= u) {
                        incomplete.get_or_insert(Incomplete::Deadline {
                            pending: self.shared.staging.pending().map_or(0, |p| p.len()),
                        });
                        break;
                    }
                    tracing::warn!(n, repairs, "final flush: rebuilding a refused capture");
                    if let Err(error) = self.shared.engine().repair() {
                        tracing::error!(%error, "final flush: rebuilding a refused capture failed");
                        incomplete.get_or_insert(Incomplete::from_snap(Class::Small, &error));
                        break;
                    }
                }
                Err(error) => {
                    tracing::error!(%error, "final flush: shipping did not finish");
                    incomplete.get_or_insert(Incomplete::from_ship(&error));
                    break;
                }
            }
        }
        shipped
    }

    /// Whether the chain's newest capture carries this executor's final seal
    /// ([`CaptureEngine::completion_sealed`]); true when there is no executor to seal under.
    fn completion_sealed(&self) -> bool {
        self.shared.engine().completion_sealed()
    }

    /// Change the last complete final flush's [`Seal`], when there is one.
    fn with_seal(&self, f: impl FnOnce(&mut Seal)) {
        if let Some(seal) = self
            .shared
            .sealed
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .as_mut()
        {
            f(seal);
        }
    }

    /// Whether the last final flush completed and sealed the chain, and the chain still ends
    /// on its sealing capture: [`Self::chain_sealed`], and the newest capture carries this
    /// executor's final seal ([`crate::manifest::FinalSeal`]) and registered (true without an
    /// executor to seal under). Never waits for the engine: `capture.status` reads it. A final
    /// flush that returned at its deadline before it could stage the sealing capture is not
    /// sealed until a final flush is asked again.
    #[must_use]
    pub fn final_sealed(&self) -> bool {
        self.shared
            .sealed
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .is_some_and(|seal| {
                seal.completion && seal.staged == self.shared.staged.load(Ordering::SeqCst)
            })
    }

    /// Ship everything pending now, bounded by `deadline`, without a snap.
    ///
    /// # Errors
    /// The shipper's error.
    pub fn ship(&self, deadline: Duration) -> Result<usize, ShipError> {
        self.shared.shipper.flush(deadline)
    }

    /// The shipper.
    #[must_use]
    pub fn shipper(&self) -> &Arc<Shipper> {
        &self.shared.shipper
    }

    /// The staging area.
    #[must_use]
    pub fn staging(&self) -> &Arc<Staging> {
        &self.shared.staging
    }

    /// Run `f` with the engine (blocks forced and scheduled snaps meanwhile).
    pub fn with_engine<R>(&self, f: impl FnOnce(&CaptureEngine) -> R) -> R {
        f(&self.shared.engine())
    }

    /// Run `f` with the engine mutably (a re-plan); no snap runs meanwhile, and the clocks
    /// resume where they were once `f` returns.
    pub fn with_engine_mut<R>(&self, f: impl FnOnce(&mut CaptureEngine) -> R) -> R {
        f(&mut self.shared.engine())
    }

    /// Whether the bulk class is captured at all.
    #[must_use]
    pub fn captures_bulk(&self) -> bool {
        self.shared.capture_bulk
    }

    /// Each class's snaps, failed and not: `(small, bulk)`.
    #[must_use]
    pub fn snap_health(&self) -> (SnapHealth, SnapHealth) {
        let health = self
            .shared
            .health
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        (health[0].clone(), health[1].clone())
    }

    /// Counters and modes.
    #[must_use]
    pub fn snapshot(&self) -> CadenceSnapshot {
        let c = &self.shared.counters;
        let st = self.shared.state();
        let bulk_in_progress = self
            .shared
            .engine
            .try_lock()
            .map(|e| e.bulk_in_progress())
            .unwrap_or(false);
        CadenceSnapshot {
            small_mode: st.small_mode,
            bulk_mode: st.bulk_mode,
            small_snaps: c.small_snaps.load(Ordering::Relaxed),
            small_staged: c.small_staged.load(Ordering::Relaxed),
            bulk_snaps: c.bulk_snaps.load(Ordering::Relaxed),
            bulk_staged: c.bulk_staged.load(Ordering::Relaxed),
            quiet_fired: c.quiet_fired.load(Ordering::Relaxed),
            max_fired: c.max_fired.load(Ordering::Relaxed),
            poll_fired: c.poll_fired.load(Ordering::Relaxed),
            forced: c.forced.load(Ordering::Relaxed),
            preemptions: c.preemptions.load(Ordering::Relaxed),
            overflows: c.overflows.load(Ordering::Relaxed),
            bulk_in_progress,
            bulk_running: c.bulk_running.load(Ordering::SeqCst),
            small_dirty: st.small.first_change.is_some(),
            bulk_dirty: st.bulk.first_change.is_some(),
        }
    }

    /// Stop the loops, the watcher and the ship worker; joins the loops.
    pub fn stop(&self) {
        {
            let mut st = self.shared.state();
            st.stop = true;
        }
        self.shared.cv.notify_all();
        {
            let _g = self
                .shared
                .yield_lock
                .lock()
                .unwrap_or_else(PoisonError::into_inner);
            self.shared.yield_cv.notify_all();
        }
        self.shared.drop_watch();
        let threads: Vec<_> = self
            .threads
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .drain(..)
            .collect();
        for h in threads {
            let _ = h.join();
        }
        if let Some(w) = self
            .shared
            .worker
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .take()
        {
            w.stop();
        }
    }
}

impl Drop for CadenceRunner {
    fn drop(&mut self) {
        self.stop();
    }
}
