//! Where the capture engine's schedules and deadlines read the time ([`Clock`]): the real clock,
//! or, in tests, a manual clock the test moves by hand (`ManualClock`, behind the `test-support`
//! feature).
//!
//! A schedule is *when* something is due: a class's quiet and maximum-interval timers, the ship
//! worker's tick. A deadline is when something gives up or tries again: a flush's deadline, the
//! shipper's backoffs and cutoff. How fast the work itself runs (a snap's reads, the CPU duty
//! cycle) stays on the real clock. Under a manual clock that work takes no time at all, so a test
//! can hold each timer and each deadline to its configured length exactly, whatever CPU the test
//! gets.
//!
//! Without `test-support` (every build of the daemon) the real clock is the only one: nothing
//! can name the manual clock or put a clock in a `CaptureConfig` (`scripts/ci-test-support-gate.sh`).
//!
//! A manual clock knows the threads it started ([`Clock::spawn`], [`Clock::spawn_scoped`]), the
//! threads that entered it to wait on it ([`Clock::enter`]: a flush on its caller's thread), and
//! what each one waits for ([`Clock::wait_until`], [`Clock::sleep`], [`Clock::notify_all`]), so
//! `ManualClock::settle` can tell when every one of them is asleep until a later time and nothing
//! woke one: nothing more happens until the clock moves. A thread it counts must wait only on
//! the clock while another of its threads sleeps on it: one blocked on a lock, or joining a
//! thread, keeps `settle` waiting.

use std::io;
use std::sync::{Condvar, MutexGuard, PoisonError};
use std::thread;
use std::time::{Duration, Instant};

#[cfg(feature = "test-support")]
pub use manual::ManualClock;

/// The time the capture engine's schedules read: the real clock, unless a test gave it a manual
/// one (`test-support`).
#[derive(Clone, Default)]
pub struct Clock {
    #[cfg(feature = "test-support")]
    manual: Option<std::sync::Arc<manual::Manual>>,
}

impl std::fmt::Debug for Clock {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        #[cfg(feature = "test-support")]
        if let Some(m) = &self.manual {
            return write!(f, "Clock::Manual(+{:?})", m.offset());
        }
        f.write_str("Clock::Real")
    }
}

impl Clock {
    /// The real clock.
    #[must_use]
    pub fn real() -> Self {
        Self::default()
    }

    /// Now.
    #[must_use]
    pub fn now(&self) -> Instant {
        #[cfg(feature = "test-support")]
        if let Some(m) = &self.manual {
            return m.now();
        }
        Instant::now()
    }

    /// Wait on `cv` (releasing `guard`) until it is notified through [`Clock::notify_all`] or
    /// `until` passes; with no `until`, until it is notified. It may return early, as a
    /// condition variable may: the caller checks what it waits for again.
    pub fn wait_until<'a, T>(
        &self,
        cv: &Condvar,
        guard: MutexGuard<'a, T>,
        until: Option<Instant>,
    ) -> MutexGuard<'a, T> {
        #[cfg(feature = "test-support")]
        if let Some(m) = &self.manual {
            return m.wait_until(cv, guard, until);
        }
        match until {
            Some(at) => {
                cv.wait_timeout(guard, at.saturating_duration_since(Instant::now()))
                    .unwrap_or_else(PoisonError::into_inner)
                    .0
            }
            None => cv.wait(guard).unwrap_or_else(PoisonError::into_inner),
        }
    }

    /// Notify every waiter on `cv`. Under a manual clock each one counts as running from now
    /// until it has woken, so the clock's `settle` waits for what the notification starts.
    pub fn notify_all(&self, cv: &Condvar) {
        #[cfg(feature = "test-support")]
        if let Some(m) = &self.manual {
            m.notified(cv);
        }
        cv.notify_all();
    }

    /// Sleep for `wait` of this clock: [`std::thread::sleep`] on the real clock. Under a manual
    /// clock it is a wait until the clock has moved on by `wait`, which its `settle` sees.
    pub fn sleep(&self, wait: Duration) {
        #[cfg(feature = "test-support")]
        if let Some(m) = &self.manual {
            let at = m.now() + wait;
            let (lock, cv) = (std::sync::Mutex::new(()), Condvar::new());
            let mut guard = lock.lock().unwrap_or_else(PoisonError::into_inner);
            while m.now() < at {
                guard = m.wait_until(&cv, guard, Some(at));
            }
            return;
        }
        thread::sleep(wait);
    }

    /// Count the calling thread as one of this clock's own until the guard drops: a thread the
    /// clock did not start (a flush's caller) that is about to wait on it. Nothing on the real
    /// clock, nor on a thread the clock already counts. Under a manual clock its `settle` waits
    /// for the thread meanwhile, as for a thread it spawned.
    pub fn enter(&self) -> Entered {
        #[cfg(feature = "test-support")]
        if let Some(m) = &self.manual {
            return Entered {
                manual: manual::Manual::enter(m),
            };
        }
        Entered {
            #[cfg(feature = "test-support")]
            manual: None,
        }
    }

    /// Spawn a thread whose waits this clock accounts for (a manual clock's `settle`).
    ///
    /// # Errors
    /// The thread could not be spawned.
    pub fn spawn<F>(&self, name: &str, f: F) -> io::Result<thread::JoinHandle<()>>
    where
        F: FnOnce() + Send + 'static,
    {
        let builder = thread::Builder::new().name(name.to_owned());
        #[cfg(feature = "test-support")]
        if let Some(m) = &self.manual {
            return manual::Manual::spawn(m, builder, f);
        }
        builder.spawn(f)
    }

    /// [`Clock::spawn`] on a [`thread::Scope`]: counted from before it starts until `f`
    /// returns. The thread that waits for it must wait on the clock (`f` notifying it through
    /// [`Clock::notify_all`] before it returns), not by joining it, or a manual clock's `settle`
    /// waits for the joining thread too.
    pub fn spawn_scoped<'scope, F>(
        &self,
        scope: &'scope thread::Scope<'scope, '_>,
        f: F,
    ) -> thread::ScopedJoinHandle<'scope, ()>
    where
        F: FnOnce() + Send + 'scope,
    {
        #[cfg(feature = "test-support")]
        if let Some(m) = &self.manual {
            return manual::Manual::spawn_scoped(m, scope, f);
        }
        scope.spawn(f)
    }
}

/// A thread counted by its clock ([`Clock::enter`]) until this drops.
#[must_use = "the thread is counted only while the guard lives"]
pub struct Entered {
    #[cfg(feature = "test-support")]
    manual: Option<std::sync::Arc<manual::Manual>>,
}

impl std::fmt::Debug for Entered {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Entered")
    }
}

#[cfg(feature = "test-support")]
impl Drop for Entered {
    fn drop(&mut self) {
        if let Some(m) = self.manual.take() {
            m.leave();
        }
    }
}

/// The manual clock: test support only.
#[cfg(feature = "test-support")]
mod manual {
    use std::collections::BTreeMap;
    use std::io;
    use std::sync::{Arc, Condvar, Mutex, MutexGuard, PoisonError};
    use std::thread;
    use std::time::{Duration, Instant};

    use super::Clock;

    /// How often a waiter under a manual clock looks at the time (real time).
    const POLL: Duration = Duration::from_millis(2);

    /// How long [`ManualClock::settle`] waits, in real time, before it says what still runs.
    const SETTLE_LIMIT: Duration = Duration::from_secs(120);

    /// A clock that moves only when the test moves it ([`ManualClock::advance`]). Its
    /// [`ManualClock::clock`] goes in [`crate::CaptureConfig::clock`].
    #[derive(Clone, Debug)]
    pub struct ManualClock {
        clock: Clock,
    }

    impl Default for ManualClock {
        fn default() -> Self {
            Self::new()
        }
    }

    impl ManualClock {
        /// A manual clock at the real time now.
        #[must_use]
        pub fn new() -> Self {
            Self {
                clock: Clock {
                    manual: Some(Arc::new(Manual {
                        state: Mutex::new(State {
                            base: Instant::now(),
                            offset: Duration::ZERO,
                            threads: 0,
                            entries: 0,
                            entered: 0,
                            waiters: BTreeMap::new(),
                            next_id: 0,
                        }),
                        changed: Condvar::new(),
                    })),
                },
            }
        }

        /// The [`Clock`] the engine reads.
        #[must_use]
        pub fn clock(&self) -> Clock {
            self.clock.clone()
        }

        /// Now, on this clock.
        #[must_use]
        pub fn now(&self) -> Instant {
            self.clock.now()
        }

        fn manual(&self) -> &Manual {
            self.clock
                .manual
                .as_deref()
                .unwrap_or_else(|| unreachable!("a ManualClock is always manual"))
        }

        /// Wait (in real time) until every thread the clock spawned is waiting until a later
        /// time, or for a notification, and no notification is still to be taken: nothing more
        /// happens until the clock moves. A thread that is busy (snapping, shipping, blocked on
        /// a lock) keeps it waiting.
        ///
        /// # Panics
        /// When the threads do not settle within two minutes of real time, naming what still
        /// runs.
        pub fn settle(&self) {
            let m = self.manual();
            let start = Instant::now();
            let mut st = m.lock();
            while !st.idle() {
                assert!(
                    start.elapsed() < SETTLE_LIMIT,
                    "the clock's threads did not settle in {SETTLE_LIMIT:?}: {} threads, \
                     waiting: {:?}",
                    st.threads,
                    st.waiters
                );
                st = m
                    .changed
                    .wait_timeout(st, POLL)
                    .unwrap_or_else(PoisonError::into_inner)
                    .0;
            }
        }

        /// Settle, then move to the earliest time a waiter waits for, or to `limit` when that
        /// is sooner (or no waiter waits for a time), and settle again. Never moves back.
        /// Returns the time it moved to: each timer due by `limit` fires at its own time.
        pub fn advance_next(&self, limit: Instant) -> Instant {
            self.settle();
            let to = {
                let m = self.manual();
                let mut st = m.lock();
                let now = st.now();
                let next = st
                    .waiters
                    .values()
                    .filter_map(|w| w.until)
                    .filter(|u| *u > now)
                    .min();
                let to = next.map_or(limit, |n| n.min(limit)).max(now);
                st.offset += to - now;
                to
            };
            self.settle();
            to
        }

        /// Move forward by `by`, stopping at each time a waiter waits for on the way
        /// ([`Self::advance_next`]).
        pub fn advance(&self, by: Duration) {
            let to = self.now() + by;
            while self.advance_next(to) < to {}
        }

        /// How many times a thread entered the clock ([`Clock::enter`]) since it was made: a
        /// test that started a flush on another thread knows it is counted once this moved.
        #[must_use]
        pub fn entries(&self) -> u64 {
            self.manual().lock().entries
        }

        /// Threads inside [`Clock::enter`] now: after [`Self::settle`], zero once every flush
        /// that entered has left (it waits on the clock no more).
        #[must_use]
        pub fn entered(&self) -> usize {
            self.manual().lock().entered
        }
    }

    pub(super) struct Manual {
        state: Mutex<State>,
        /// A waiter left or a thread ended.
        changed: Condvar,
    }

    impl Manual {
        fn lock(&self) -> MutexGuard<'_, State> {
            self.state.lock().unwrap_or_else(PoisonError::into_inner)
        }

        pub(super) fn offset(&self) -> Duration {
            self.lock().offset
        }

        pub(super) fn now(&self) -> Instant {
            self.lock().now()
        }

        /// The calling thread counts as one of the clock's own until [`Self::leave`]; `None` when
        /// it already does.
        pub(super) fn enter(this: &Arc<Self>) -> Option<Arc<Self>> {
            if SPAWNED.with(std::cell::Cell::get) == this.id() {
                return None;
            }
            SPAWNED.with(|s| s.set(this.id()));
            let mut st = this.lock();
            st.threads += 1;
            st.entries += 1;
            st.entered += 1;
            Some(Arc::clone(this))
        }

        pub(super) fn leave(&self) {
            SPAWNED.with(|s| s.set(0));
            let mut st = self.lock();
            st.threads -= 1;
            st.entered -= 1;
            drop(st);
            self.changed.notify_all();
        }

        /// Which clock a thread is counted by ([`SPAWNED`]).
        fn id(&self) -> usize {
            std::ptr::from_ref(self) as usize
        }

        pub(super) fn wait_until<'a, T>(
            &self,
            cv: &Condvar,
            guard: MutexGuard<'a, T>,
            until: Option<Instant>,
        ) -> MutexGuard<'a, T> {
            let spawned = SPAWNED.with(std::cell::Cell::get) == self.id();
            let id = self.lock().enter(cv, until, spawned);
            let mut guard = guard;
            loop {
                guard = cv
                    .wait_timeout(guard, POLL)
                    .unwrap_or_else(PoisonError::into_inner)
                    .0;
                let mut st = self.lock();
                if st.due(id) {
                    st.waiters.remove(&id);
                    drop(st);
                    self.changed.notify_all();
                    return guard;
                }
            }
        }

        pub(super) fn notified(&self, cv: &Condvar) {
            let key = key(cv);
            for w in self.lock().waiters.values_mut().filter(|w| w.cv == key) {
                w.woken = true;
            }
        }

        pub(super) fn spawn<F>(
            this: &Arc<Self>,
            builder: thread::Builder,
            f: F,
        ) -> io::Result<thread::JoinHandle<()>>
        where
            F: FnOnce() + Send + 'static,
        {
            this.lock().threads += 1;
            // Dropped with the closure when the spawn fails, too: the count is back either way.
            let exit = Exit(Arc::clone(this));
            let id = this.id();
            builder.spawn(move || {
                let _exit = exit;
                SPAWNED.with(|s| s.set(id));
                f();
            })
        }

        pub(super) fn spawn_scoped<'scope, F>(
            this: &Arc<Self>,
            scope: &'scope thread::Scope<'scope, '_>,
            f: F,
        ) -> thread::ScopedJoinHandle<'scope, ()>
        where
            F: FnOnce() + Send + 'scope,
        {
            // Counted before it starts, so a `settle` meanwhile waits for it.
            this.lock().threads += 1;
            let exit = Exit(Arc::clone(this));
            let id = this.id();
            scope.spawn(move || {
                let _exit = exit;
                SPAWNED.with(|s| s.set(id));
                f();
            })
        }
    }

    struct State {
        base: Instant,
        offset: Duration,
        /// Threads [`Clock::spawn`] and [`Clock::spawn_scoped`] started that have not ended, and
        /// threads inside [`Clock::enter`].
        threads: usize,
        /// Times a thread entered ([`ManualClock::entries`]).
        entries: u64,
        /// Threads inside [`Clock::enter`] now.
        entered: usize,
        waiters: BTreeMap<u64, Waiter>,
        next_id: u64,
    }

    #[derive(Debug)]
    struct Waiter {
        /// The condition variable it waits on ([`key`]).
        cv: usize,
        until: Option<Instant>,
        /// Notified, and not yet woken.
        woken: bool,
        /// The waiter is one of the threads the clock counts.
        spawned: bool,
    }

    impl State {
        fn now(&self) -> Instant {
            self.base + self.offset
        }

        fn enter(&mut self, cv: &Condvar, until: Option<Instant>, spawned: bool) -> u64 {
            let id = self.next_id;
            self.next_id += 1;
            self.waiters.insert(
                id,
                Waiter {
                    cv: key(cv),
                    until,
                    woken: false,
                    spawned,
                },
            );
            id
        }

        /// Whether waiter `id` is to wake: notified, or its time came.
        fn due(&self, id: u64) -> bool {
            let now = self.now();
            self.waiters
                .get(&id)
                .is_none_or(|w| w.woken || w.until.is_some_and(|u| u <= now))
        }

        fn idle(&self) -> bool {
            let now = self.now();
            self.waiters.values().filter(|w| w.spawned).count() == self.threads
                && self
                    .waiters
                    .values()
                    .all(|w| !w.woken && w.until.is_none_or(|u| u > now))
        }
    }

    thread_local! {
        /// The manual clock that counts this thread ([`Manual::id`]; 0: none): it started it
        /// ([`Clock::spawn`], [`Clock::spawn_scoped`]), or the thread entered it
        /// ([`Clock::enter`]).
        static SPAWNED: std::cell::Cell<usize> = const { std::cell::Cell::new(0) };
    }

    /// Counts a spawned thread out when it ends (or when its spawn failed).
    struct Exit(Arc<Manual>);

    impl Drop for Exit {
        fn drop(&mut self) {
            self.0.lock().threads -= 1;
            self.0.changed.notify_all();
        }
    }

    /// A waiter's condition variable, by address: only compared while the waiter borrows it.
    fn key(cv: &Condvar) -> usize {
        std::ptr::from_ref(cv) as usize
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        /// A spawned thread waiting until a time wakes when the clock reaches it, not before,
        /// and `advance_next` stops at that time.
        #[test]
        fn a_waiter_wakes_at_its_time_and_advance_stops_there() {
            let manual = ManualClock::new();
            let clock = manual.clock();
            let start = manual.now();
            let pair = Arc::new((Mutex::new(None::<Instant>), Condvar::new()));
            let (c, p) = (clock.clone(), Arc::clone(&pair));
            let h = clock
                .spawn("waiter", move || {
                    let (lock, cv) = &*p;
                    let at = c.now() + Duration::from_secs(3);
                    let mut g = lock.lock().unwrap();
                    while c.now() < at {
                        g = c.wait_until(cv, g, Some(at));
                    }
                    *g = Some(c.now());
                })
                .unwrap();
            manual.settle();
            assert_eq!(
                manual.advance_next(start + Duration::from_secs(1)),
                start + Duration::from_secs(1)
            );
            assert!(pair.0.lock().unwrap().is_none(), "not before its time");
            assert_eq!(
                manual.advance_next(start + Duration::from_secs(10)),
                start + Duration::from_secs(3)
            );
            h.join().unwrap();
            assert_eq!(
                *pair.0.lock().unwrap(),
                Some(start + Duration::from_secs(3))
            );
        }

        /// A notification counts its waiter as running until it woke: settle waits for it.
        #[test]
        fn settle_waits_for_a_notified_waiter() {
            let manual = ManualClock::new();
            let clock = manual.clock();
            let pair = Arc::new((Mutex::new(0u32), Condvar::new()));
            let (c, p) = (clock.clone(), Arc::clone(&pair));
            let h = clock
                .spawn("counter", move || {
                    let (lock, cv) = &*p;
                    let mut g = lock.lock().unwrap();
                    while *g < 2 {
                        let seen = *g;
                        while *g == seen {
                            g = c.wait_until(cv, g, None);
                        }
                        // Work that takes real time, and none on the clock.
                        drop(g);
                        thread::sleep(Duration::from_millis(50));
                        g = lock.lock().unwrap();
                        *g += 10;
                    }
                })
                .unwrap();
            manual.settle();
            *pair.0.lock().unwrap() = 1;
            clock.notify_all(&pair.1);
            manual.settle();
            assert_eq!(
                *pair.0.lock().unwrap(),
                11,
                "settle returned before the work"
            );
            h.join().unwrap();
            manual.settle();
        }

        /// A sleep on the clock ends when the clock has moved on by its length, not before, and
        /// `advance_next` stops there. On the real clock it is a real sleep.
        #[test]
        fn a_sleep_ends_when_the_clock_moved_on_by_its_length() {
            let real = Clock::real();
            let before = Instant::now();
            real.sleep(Duration::from_millis(20));
            assert!(before.elapsed() >= Duration::from_millis(20));

            let manual = ManualClock::new();
            let clock = manual.clock();
            let start = manual.now();
            let woke = Arc::new(Mutex::new(None::<Instant>));
            let (c, w) = (clock.clone(), Arc::clone(&woke));
            let h = clock
                .spawn("sleeper", move || {
                    c.sleep(Duration::from_secs(3));
                    *w.lock().unwrap() = Some(c.now());
                })
                .unwrap();
            manual.settle();
            assert_eq!(
                manual.advance_next(start + Duration::from_secs(2)),
                start + Duration::from_secs(2)
            );
            assert!(woke.lock().unwrap().is_none(), "not before its length");
            assert_eq!(
                manual.advance_next(start + Duration::from_secs(10)),
                start + Duration::from_secs(3)
            );
            h.join().unwrap();
            assert_eq!(*woke.lock().unwrap(), Some(start + Duration::from_secs(3)));
            // A zero sleep does not wait.
            clock.sleep(Duration::ZERO);
        }

        /// A thread the clock did not start counts once it entered: `settle` waits for its
        /// work, then sees its sleep, and it is counted out when it leaves. Entering twice
        /// counts it once.
        #[test]
        fn an_entered_thread_is_waited_for_until_it_leaves() {
            let manual = ManualClock::new();
            let clock = manual.clock();
            let start = manual.now();
            let worked = Arc::new(Mutex::new(false));
            let (c, w) = (clock.clone(), Arc::clone(&worked));
            let h = thread::spawn(move || {
                let _entered = c.enter();
                let _again = c.enter();
                // Work that takes real time, and none on the clock.
                thread::sleep(Duration::from_millis(50));
                *w.lock().unwrap() = true;
                c.sleep(Duration::from_secs(2));
            });
            while manual.entries() == 0 {
                thread::sleep(Duration::from_millis(1));
            }
            manual.settle();
            assert!(*worked.lock().unwrap(), "settle returned before the work");
            assert_eq!(manual.entered(), 1);
            assert_eq!(manual.entries(), 1, "entering again counts it once");
            assert_eq!(
                manual.advance_next(start + Duration::from_secs(10)),
                start + Duration::from_secs(2)
            );
            h.join().unwrap();
            assert_eq!(manual.entered(), 0);
            manual.settle();
            // Nothing on the real clock.
            drop(Clock::real().enter());
        }

        /// A scoped thread counts from before it starts until it returns: its sleeps hold
        /// `advance_next`, and the thread waiting for it on the clock wakes once it is done.
        #[test]
        fn a_scoped_thread_is_counted_from_before_it_starts() {
            let manual = ManualClock::new();
            let clock = manual.clock();
            let start = manual.now();
            let ended = Arc::new(Mutex::new(None::<Instant>));
            let (c, e) = (clock.clone(), Arc::clone(&ended));
            let h = clock
                .spawn("owner", move || {
                    let done = (Mutex::new(0usize), Condvar::new());
                    thread::scope(|scope| {
                        for secs in [1, 2] {
                            let (c, done) = (&c, &done);
                            c.spawn_scoped(scope, move || {
                                c.sleep(Duration::from_secs(secs));
                                *done.0.lock().unwrap() += 1;
                                c.notify_all(&done.1);
                            });
                        }
                        let mut n = done.0.lock().unwrap();
                        while *n < 2 {
                            n = c.wait_until(&done.1, n, None);
                        }
                    });
                    *e.lock().unwrap() = Some(c.now());
                })
                .unwrap();
            let limit = start + Duration::from_secs(10);
            assert_eq!(manual.advance_next(limit), start + Duration::from_secs(1));
            assert!(ended.lock().unwrap().is_none());
            assert_eq!(manual.advance_next(limit), start + Duration::from_secs(2));
            h.join().unwrap();
            assert_eq!(*ended.lock().unwrap(), Some(start + Duration::from_secs(2)));
        }
    }
}
