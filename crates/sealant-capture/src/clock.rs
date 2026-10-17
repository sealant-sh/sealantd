//! Where the capture engine's schedules read the time ([`Clock`]): the real clock, or a
//! [`ManualClock`] a test moves by hand.
//!
//! A schedule is *when* something is due: a class's quiet and maximum-interval timers, the ship
//! worker's tick. How fast the work itself runs (a snap's reads, the CPU duty cycle) stays on the
//! real clock. Under a manual clock that work takes no time at all, so a test can hold each
//! timer to its configured period exactly, whatever CPU the test gets.
//!
//! A manual clock knows the threads it started ([`Clock::spawn`]) and what each one waits for
//! ([`Clock::wait_until`], [`Clock::notify_all`]), so [`ManualClock::settle`] can tell when every
//! one of them is asleep until a later time and nothing woke one: nothing more happens until
//! the clock moves.

use std::collections::BTreeMap;
use std::io;
use std::sync::{Arc, Condvar, Mutex, MutexGuard, PoisonError};
use std::thread;
use std::time::{Duration, Instant};

/// How often a waiter under a manual clock looks at the time (real time).
const POLL: Duration = Duration::from_millis(2);

/// How long [`ManualClock::settle`] waits, in real time, before it says what still runs.
const SETTLE_LIMIT: Duration = Duration::from_secs(120);

/// The time the capture engine's schedules read: real by default.
#[derive(Clone, Default)]
pub struct Clock {
    manual: Option<Arc<Manual>>,
}

impl std::fmt::Debug for Clock {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match &self.manual {
            None => f.write_str("Clock::Real"),
            Some(m) => write!(f, "Clock::Manual(+{:?})", m.lock().offset),
        }
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
        match &self.manual {
            None => Instant::now(),
            Some(m) => m.lock().now(),
        }
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
        let Some(m) = &self.manual else {
            return match until {
                Some(at) => {
                    cv.wait_timeout(guard, at.saturating_duration_since(Instant::now()))
                        .unwrap_or_else(PoisonError::into_inner)
                        .0
                }
                None => cv.wait(guard).unwrap_or_else(PoisonError::into_inner),
            };
        };
        let id = m.lock().enter(cv, until);
        let mut guard = guard;
        loop {
            guard = cv
                .wait_timeout(guard, POLL)
                .unwrap_or_else(PoisonError::into_inner)
                .0;
            let mut st = m.lock();
            if st.due(id) {
                st.waiters.remove(&id);
                drop(st);
                m.changed.notify_all();
                return guard;
            }
        }
    }

    /// Notify every waiter on `cv`. Under a manual clock each one counts as running from now
    /// until it has woken, so [`ManualClock::settle`] waits for what the notification starts.
    pub fn notify_all(&self, cv: &Condvar) {
        if let Some(m) = &self.manual {
            let key = key(cv);
            for w in m.lock().waiters.values_mut().filter(|w| w.cv == key) {
                w.woken = true;
            }
        }
        cv.notify_all();
    }

    /// Spawn a thread whose waits this clock accounts for ([`ManualClock::settle`]).
    ///
    /// # Errors
    /// The thread could not be spawned.
    pub fn spawn<F>(&self, name: &str, f: F) -> io::Result<thread::JoinHandle<()>>
    where
        F: FnOnce() + Send + 'static,
    {
        let builder = thread::Builder::new().name(name.to_owned());
        let Some(m) = &self.manual else {
            return builder.spawn(f);
        };
        m.lock().threads += 1;
        // Dropped with the closure when the spawn fails, too: the count is back either way.
        let exit = Exit(Arc::clone(m));
        builder.spawn(move || {
            let _exit = exit;
            SPAWNED.with(|s| s.set(true));
            f();
        })
    }
}

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

    /// Wait (in real time) until every thread the clock spawned is waiting until a later time,
    /// or for a notification, and no notification is still to be taken: nothing more happens
    /// until the clock moves. A thread that is busy (snapping, shipping, blocked on a lock)
    /// keeps it waiting.
    ///
    /// # Panics
    /// When the threads do not settle within two minutes of real time, naming what still runs.
    pub fn settle(&self) {
        let m = self.manual();
        let start = Instant::now();
        let mut st = m.lock();
        while !st.idle() {
            assert!(
                start.elapsed() < SETTLE_LIMIT,
                "the clock's threads did not settle in {SETTLE_LIMIT:?}: {} threads, waiting: {:?}",
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

    /// Settle, then move to the earliest time a waiter waits for, or to `limit` when that is
    /// sooner (or no waiter waits for a time), and settle again. Never moves back. Returns the
    /// time it moved to: each timer due by `limit` fires at its own time.
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
}

struct Manual {
    state: Mutex<State>,
    /// A waiter left or a thread ended.
    changed: Condvar,
}

impl Manual {
    fn lock(&self) -> MutexGuard<'_, State> {
        self.state.lock().unwrap_or_else(PoisonError::into_inner)
    }
}

struct State {
    base: Instant,
    offset: Duration,
    /// Threads [`Clock::spawn`] started that have not ended.
    threads: usize,
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
    /// The waiter is one of the threads the clock spawned.
    spawned: bool,
}

impl State {
    fn now(&self) -> Instant {
        self.base + self.offset
    }

    fn enter(&mut self, cv: &Condvar, until: Option<Instant>) -> u64 {
        let id = self.next_id;
        self.next_id += 1;
        self.waiters.insert(
            id,
            Waiter {
                cv: key(cv),
                until,
                woken: false,
                spawned: SPAWNED.with(std::cell::Cell::get),
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
    /// This thread was started by [`Clock::spawn`] of a manual clock.
    static SPAWNED: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
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

    /// A spawned thread waiting until a time wakes when the clock reaches it, not before, and
    /// `advance_next` stops at that time.
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
}
