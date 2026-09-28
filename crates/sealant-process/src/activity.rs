//! Long steps and bounded helpers that are running now, and which of them has run past its bound.
//!
//! Docker end to end, round 8 (F1): a capture helper (`git cat-file --batch-check`) and the
//! daemon's cadence thread waited on each other's pipes for 17 minutes, and every answer the
//! daemon gave meanwhile read like an idle, healthy capture (`status: running`, nothing
//! pending, no failed snap). Nothing was failing; something was simply not finishing, and
//! nothing said so.
//!
//! A step registers itself for as long as it runs, with the time it is expected to take at
//! most ([`scope`] for a step made of several, such as a snap, on the thread that runs it;
//! [`enter`] for one piece of work, such as a helper process, from any thread). [`overdue`]
//! names the step that has run past its bound, if one has. That is an observation (this has
//! been running for this long, past that bound), not a verdict: a very large repository can
//! legitimately take longer, and the step may still finish.

use std::cell::RefCell;
use std::collections::BTreeMap;
use std::marker::PhantomData;
use std::sync::{Mutex, MutexGuard, OnceLock, PoisonError};
use std::time::{Duration, Instant, SystemTime};

/// A step that has run past its bound.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Overdue {
    /// What is running: the enclosing scopes and the step, `›`-separated (`small snap › git
    /// cat-file --batch-check`).
    pub step: String,
    /// When it started (wall clock).
    pub started: SystemTime,
    /// How long it has been running.
    pub running: Duration,
    /// How long it was expected to take at most.
    pub bound: Duration,
}

#[derive(Debug)]
struct Entry {
    step: String,
    started_wall: SystemTime,
    started: Instant,
    bound: Duration,
    reported: bool,
}

#[derive(Debug, Default)]
struct Registry {
    next: u64,
    running: BTreeMap<u64, Entry>,
}

fn registry() -> MutexGuard<'static, Registry> {
    static REGISTRY: OnceLock<Mutex<Registry>> = OnceLock::new();
    REGISTRY
        .get_or_init(|| Mutex::new(Registry::default()))
        .lock()
        .unwrap_or_else(PoisonError::into_inner)
}

thread_local! {
    /// The scopes open on this thread, outermost first.
    static SCOPES: RefCell<Vec<String>> = const { RefCell::new(Vec::new()) };
}

fn register(step: String, bound: Duration) -> u64 {
    let mut registry = registry();
    registry.next += 1;
    let id = registry.next;
    registry.running.insert(
        id,
        Entry {
            step,
            started_wall: SystemTime::now(),
            started: Instant::now(),
            bound,
            reported: false,
        },
    );
    id
}

fn qualified(label: &str) -> String {
    SCOPES.with(|scopes| {
        let scopes = scopes.borrow();
        if scopes.is_empty() {
            label.to_owned()
        } else {
            format!("{} › {label}", scopes.join(" › "))
        }
    })
}

/// A running step ([`enter`]); it stops running when dropped.
#[derive(Debug)]
#[must_use = "the step is over when the guard is dropped"]
pub struct Step(u64);

impl Step {
    /// Log the step once, the first time it is seen past its bound (the helper's watchdog
    /// calls this when the bound passes; [`overdue`] when it finds it).
    pub fn report_if_overdue(&self) {
        report(self.0);
    }
}

impl Drop for Step {
    fn drop(&mut self) {
        registry().running.remove(&self.0);
    }
}

/// A running scope ([`scope`]): a step whose own steps on this thread are named under it. Not
/// `Send`: it is closed on the thread that opened it.
#[derive(Debug)]
#[must_use = "the scope is over when the guard is dropped"]
pub struct Scope {
    id: u64,
    _thread_bound: PhantomData<*const ()>,
}

impl Drop for Scope {
    fn drop(&mut self) {
        registry().running.remove(&self.id);
        SCOPES.with(|scopes| {
            scopes.borrow_mut().pop();
        });
    }
}

/// Register `label` as running on this thread until the guard drops, expected to take at most
/// `bound`; steps entered on this thread meanwhile are named under it.
pub fn scope(label: &str, bound: Duration) -> Scope {
    let id = register(qualified(label), bound);
    SCOPES.with(|scopes| scopes.borrow_mut().push(label.to_owned()));
    Scope {
        id,
        _thread_bound: PhantomData,
    }
}

/// Register `label` (under this thread's open scopes) as running until the guard drops,
/// expected to take at most `bound`.
pub fn enter(label: &str, bound: Duration) -> Step {
    Step(register(qualified(label), bound))
}

fn report(id: u64) {
    let mut registry = registry();
    let Some(entry) = registry.running.get_mut(&id) else {
        return;
    };
    let running = entry.started.elapsed();
    if entry.reported || running <= entry.bound {
        return;
    }
    entry.reported = true;
    tracing::warn!(
        step = %entry.step,
        running_s = running.as_secs(),
        bound_s = entry.bound.as_secs(),
        "a step has run past its bound and is still running"
    );
}

/// The step that has run past its bound, if any: of several, the one that started last (the
/// innermost: a helper inside an overdue snap is the more precise answer). Logged once per
/// step.
#[must_use]
pub fn overdue() -> Option<Overdue> {
    let id = {
        let registry = registry();
        registry
            .running
            .iter()
            .filter(|(_, e)| e.started.elapsed() > e.bound)
            .max_by_key(|(id, e)| (e.started, **id))
            .map(|(id, _)| *id)?
    };
    report(id);
    let registry = registry();
    let entry = registry.running.get(&id)?;
    Some(Overdue {
        step: entry.step.clone(),
        started: entry.started_wall,
        running: entry.started.elapsed(),
        bound: entry.bound,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn named(step: &str) -> Option<Overdue> {
        // Other tests of this crate run steps too: look only for this one.
        let registry = registry();
        registry
            .running
            .values()
            .find(|e| e.step == step)
            .map(|e| Overdue {
                step: e.step.clone(),
                started: e.started_wall,
                running: e.started.elapsed(),
                bound: e.bound,
            })
    }

    #[test]
    fn a_step_is_named_under_its_scope_and_gone_when_it_ends() {
        let scope = scope("activity-test snap", Duration::from_secs(600));
        let step = enter("git activity-test", Duration::ZERO);
        std::thread::sleep(Duration::from_millis(5));
        let found = named("activity-test snap › git activity-test").expect("registered");
        assert!(found.running > found.bound);
        let overdue = overdue().expect("a step past a zero bound is overdue");
        assert!(overdue.running > overdue.bound, "{overdue:?}");
        drop(step);
        assert!(named("activity-test snap › git activity-test").is_none());
        assert!(named("activity-test snap").is_some());
        drop(scope);
        assert!(named("activity-test snap").is_none());
        // The scope is closed: a step entered now is named on its own.
        let alone = enter("git activity-test alone", Duration::from_secs(600));
        assert!(named("git activity-test alone").is_some());
        drop(alone);
    }
}
