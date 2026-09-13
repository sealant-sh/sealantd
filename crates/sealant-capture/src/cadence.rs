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
//! when unchanged).

use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Condvar, Mutex, MutexGuard, PoisonError, Weak};
use std::thread;
use std::time::{Duration, Instant};

use crate::engine::{CaptureEngine, Class, EngineError, SnapOutcome, SnapRequest, StagedCapture};
use crate::manifest::CaptureKind;
use crate::ship::{ShipError, ShipWorker, Shipper, Staging};
use crate::watch::{self, ChangeSignal, Mode, WatchHandle, WatchSpec};

/// How often the ship worker polls when nothing woke it.
pub const SHIP_TICK: Duration = Duration::from_secs(5);

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

    /// When the next snap is due and why, or `None` when nothing is pending.
    fn due(&self, mode: Mode) -> Option<(Instant, Trigger)> {
        match mode {
            Mode::Polled => Some((self.last_snap + self.max, Trigger::Poll)),
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
    yield_lock: Mutex<()>,
    yield_cv: Condvar,
    watch: Mutex<Option<WatchHandle>>,
    /// `false` while snaps must not be taken (the daemon is hard-stopping).
    allow: Mutex<Option<Arc<dyn Fn() -> bool + Send + Sync>>>,
    capture_bulk: bool,
    started: AtomicBool,
    seq: AtomicU64,
    counters: Counters,
}

impl Shared {
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
        if let Ok(staged) = &result
            && !staged.unchanged
        {
            self.counters.small_staged.fetch_add(1, Ordering::Relaxed);
            self.wake_worker();
        }
        self.cv.notify_all();
        result
    }

    /// A bulk-class snap, yielding to small-class snaps until it completes.
    fn bulk_snap(&self) -> Result<StagedCapture, EngineError> {
        self.state().bulk.clear();
        self.counters.bulk_running.store(true, Ordering::SeqCst);
        let seq = self.seq.fetch_add(1, Ordering::Relaxed);
        let preempt = || self.small_waiting.load(Ordering::SeqCst) > 0;
        let result = loop {
            // Let a waiting small snap take the engine first.
            {
                let mut g = self
                    .yield_lock
                    .lock()
                    .unwrap_or_else(PoisonError::into_inner);
                while preempt() && !self.state().stop {
                    g = self
                        .yield_cv
                        .wait_timeout(g, Duration::from_millis(50))
                        .unwrap_or_else(PoisonError::into_inner)
                        .0;
                }
            }
            if self.state().stop {
                self.counters.bulk_running.store(false, Ordering::SeqCst);
                return Err(EngineError::Io(std::io::Error::other("runner stopped")));
            }
            let outcome = self.engine().snap_preemptible(
                SnapRequest {
                    kind: CaptureKind::Auto,
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
        if let Ok(staged) = &result
            && !staged.unchanged
        {
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
            let (due, overflowed) = {
                let st = self.state();
                if st.stop {
                    return;
                }
                (st.small.due(st.small_mode), st.overflowed)
            };
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
                    if !self.allowed() || self.shipper.is_fenced() {
                        let mut st = self.state();
                        st.bulk.clear();
                        st.bulk.last_snap = now;
                        drop(st);
                        continue;
                    }
                    match self.bulk_snap() {
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
        Self {
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
                    stop: false,
                }),
                cv: Condvar::new(),
                small_waiting: AtomicUsize::new(0),
                yield_lock: Mutex::new(()),
                yield_cv: Condvar::new(),
                watch: Mutex::new(None),
                allow: Mutex::new(None),
                capture_bulk,
                started: AtomicBool::new(false),
                seq: AtomicU64::new(0),
                counters: Counters::default(),
            }),
            threads: Mutex::new(Vec::new()),
        }
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

    /// A forced small-class snap of `kind`, then ship and register everything pending, bounded
    /// by `deadline`. Blocking.
    ///
    /// # Errors
    /// The engine's error, or the shipper's when shipping stops on a fence or a conflict.
    pub fn flush(&self, kind: CaptureKind, deadline: Duration) -> Result<usize, EngineError> {
        self.snap(kind)?;
        Ok(self.shared.shipper.flush(deadline)?)
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
