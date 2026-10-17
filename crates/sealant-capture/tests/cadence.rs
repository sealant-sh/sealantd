//! Runtime-level proofs of the cadence (ADR-0015 *Cadence and budgets*) against a fake
//! registrar and a `LocalDir` sink: real files, the real watcher, and timers on the wall clock
//! or, where a test says so, on a [`ManualClock`] (sealantd#167).

use std::cell::RefCell;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

use sealant_capture::cadence::SHIP_TICK;
use sealant_capture::manifest::CaptureKind;
use sealant_capture::registrar::HeadInfo;
use sealant_capture::{
    Cadence, CadenceRunner, CaptureConfig, CaptureEngine, ChangeSignal, Class, InMemoryRegistrar,
    LocalDir, ManualClock, SnapOutcome, SnapRequest, WatchMode,
};
use sealant_process::CommandGateExt;

fn git(root: &Path, args: &[&str]) {
    let out = Command::new("git")
        .current_dir(root)
        .env("GIT_OPTIONAL_LOCKS", "0")
        .args(args)
        .stdin(Stdio::null())
        .output_gated()
        .expect("git");
    assert!(
        out.status.success(),
        "git {args:?} failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );
}

fn pseudo_random(len: usize, seed: u64) -> Vec<u8> {
    let mut x = seed | 1;
    (0..len)
        .map(|_| {
            x ^= x << 13;
            x ^= x >> 7;
            x ^= x << 17;
            ((x >> 24) & 0xff) as u8
        })
        .collect()
}

struct Fixture {
    _tmp: tempfile::TempDir,
    base: PathBuf,
    root: PathBuf,
    home: PathBuf,
    registrar: Arc<InMemoryRegistrar>,
}

impl Fixture {
    fn build() -> Self {
        let tmp = tempfile::tempdir().unwrap();
        let base = tmp.path().to_path_buf();
        let root = base.join("ws");
        let home = base.join("home");
        fs::create_dir_all(&root).unwrap();
        fs::create_dir_all(&home).unwrap();
        git(&root, &["init", "-q", "-b", "main"]);
        git(&root, &["config", "user.email", "t@t"]);
        git(&root, &["config", "user.name", "t"]);
        fs::write(root.join(".gitignore"), "node_modules/\n").unwrap();
        fs::create_dir_all(root.join("src")).unwrap();
        fs::write(root.join("src/lib.rs"), "pub fn f() {}\n").unwrap();
        git(&root, &["add", "-A"]);
        git(&root, &["commit", "-q", "-m", "one"]);
        fs::create_dir_all(root.join("node_modules/pkg/lib")).unwrap();
        fs::write(
            root.join("node_modules/pkg/lib/index.js"),
            "module.exports = 1;\n",
        )
        .unwrap();
        fs::write(home.join("transcript.jsonl"), "{}\n").unwrap();
        Self {
            _tmp: tmp,
            base,
            root,
            home,
            registrar: Arc::new(InMemoryRegistrar::new("wt-cadence", 1, None)),
        }
    }

    fn config(&self, cadence: Cadence) -> CaptureConfig {
        let mut c = CaptureConfig::new("wt-cadence", 1, &self.root);
        c.harness_home = Some(self.home.clone());
        c.cadence = cadence;
        c
    }

    fn runner(&self, config: CaptureConfig) -> CadenceRunner {
        let sink = Arc::new(LocalDir::new(&self.base.join("store")).unwrap());
        let engine = CaptureEngine::open(config, None).unwrap();
        let registrar: Arc<dyn sealant_capture::Registrar> = self.registrar.clone();
        let shipper = Arc::new(engine.shipper(sink, registrar));
        let runner = CadenceRunner::new(engine, shipper);
        runner.start(None);
        runner
    }

    fn chain(&self) -> Vec<HeadInfo> {
        self.registrar.chain()
    }

    /// Wait until the chain has at least `n` captures; the wall time it took.
    fn wait_for_chain(&self, n: usize, timeout: Duration) -> Option<Duration> {
        let start = Instant::now();
        while start.elapsed() < timeout {
            if self.chain().len() >= n {
                return Some(start.elapsed());
            }
            std::thread::sleep(Duration::from_millis(25));
        }
        None
    }
}

/// A runner whose timers and ship worker run on a [`ManualClock`], and what it was seen to do,
/// each at the virtual time since the runner settled it was first seen.
///
/// The clock moves only when the test moves it, and stops at each time one of the runner's
/// threads waits for ([`ManualClock::advance_next`]), so a timer fires at its own time and is
/// seen then. The work after it — the snap, the worker's wake-up, the ship, the registration —
/// takes no virtual time: the clock waits for it to finish before it moves on
/// ([`ManualClock::settle`]). A capture that waits for anything on the clock (the worker's
/// tick, after a missed wake-up) registers that much later in virtual time, whatever CPU the
/// test gets.
struct OnClock<'a> {
    fx: &'a Fixture,
    runner: CadenceRunner,
    clock: ManualClock,
    start: Instant,
    /// When the chain grew.
    registered: Vec<Duration>,
    /// When the max-interval timer, and the quiet timer, fired (each time its counter rose).
    max_fired: Vec<Duration>,
    quiet_fired: Vec<Duration>,
}

impl<'a> OnClock<'a> {
    fn start(fx: &'a Fixture, mut config: CaptureConfig) -> Self {
        let clock = ManualClock::new();
        config.clock = clock.clock();
        let runner = fx.runner(config);
        clock.settle();
        let start = clock.now();
        Self {
            fx,
            runner,
            clock,
            start,
            registered: Vec::new(),
            max_fired: Vec::new(),
            quiet_fired: Vec::new(),
        }
    }

    /// Virtual time since the start.
    fn now(&self) -> Duration {
        self.clock.now() - self.start
    }

    fn sample(&mut self) {
        let now = self.now();
        let snap = self.runner.snapshot();
        while self.max_fired.len() < snap.max_fired as usize {
            self.max_fired.push(now);
        }
        while self.quiet_fired.len() < snap.quiet_fired as usize {
            self.quiet_fired.push(now);
        }
        while self.registered.len() < self.fx.chain().len() {
            self.registered.push(now);
        }
    }

    /// Move the clock once: to the next time a thread waits for, or to `at` if that is sooner.
    fn step(&mut self, at: Duration) {
        self.clock.advance_next(self.start + at);
        self.sample();
    }

    /// Move the clock to `at`, seeing what happens at each time on the way.
    fn run_to(&mut self, at: Duration) {
        while self.now() < at {
            self.step(at);
        }
    }

    /// Move the clock until the chain holds `n` captures, for at most `timeout`; how long it
    /// took, `None` past `timeout`.
    fn wait_for_chain(&mut self, n: usize, timeout: Duration) -> Option<Duration> {
        let from = self.now();
        self.sample();
        while self.registered.len() < n {
            if self.now() >= from + timeout {
                return None;
            }
            self.step(from + timeout);
        }
        Some(self.registered[n - 1].saturating_sub(from))
    }

    /// Write `contents` to `rel` now: back once the watcher delivered it and the runner did
    /// what it does on it, so the change is at this virtual time.
    fn write(&mut self, rel: &str, contents: &str) {
        fs::write(self.fx.root.join(rel), contents).unwrap();
        self.runner
            .settle_watcher()
            .expect("the watcher delivers the write");
        self.clock.settle();
        self.sample();
    }
}

fn fast_bulk(mut cadence: Cadence, quiet_ms: u64, max_ms: u64) -> Cadence {
    cadence.bulk_quiet = Duration::from_millis(quiet_ms);
    cadence.bulk_max_interval = Duration::from_millis(max_ms);
    cadence
}

/// The same work as a timer's capture, forced, with no timer and no wake-up: the first capture
/// of an identical workspace, snapped and shipped on this machine. What a timer's snap, ship
/// and registration are held to, instead of a wall-clock constant: on a runner with a slow disk
/// every fsync and git spawn is slower, for both alike.
fn forced_capture() -> Duration {
    let twin = Fixture::build();
    let twin_runner = twin.runner(twin.config(Cadence::default()));
    fs::write(twin.root.join("src/new.rs"), "fn n() {}\n").unwrap();
    let t1 = Instant::now();
    assert!(!twin_runner.snap(CaptureKind::Turn).unwrap().unchanged);
    twin_runner.ship(Duration::from_secs(30)).unwrap();
    let forced = t1.elapsed();
    assert_eq!(twin.chain().len(), 1, "the forced capture registered");
    twin_runner.stop();
    forced
}

/// How long a timer's capture may take to register after the timer fired: three times the same
/// work forced, and half a second (the worker's wake-up, scheduling).
fn after_timer_bound(forced: Duration) -> Duration {
    forced * 3 + Duration::from_millis(500)
}

/// Wait until the chain holds `n` captures, noting when `fired` (a timer's counter in the
/// runner's snapshot) first rose above `before`. Both from `t0`; `None` for a registration past
/// `timeout`.
fn wait_timer_and_chain(
    fx: &Fixture,
    runner: &CadenceRunner,
    n: usize,
    t0: Instant,
    timeout: Duration,
    fired: impl Fn(&sealant_capture::CadenceSnapshot) -> u64,
    before: u64,
) -> (Option<Duration>, Option<Duration>) {
    let mut fired_at = None;
    while t0.elapsed() < timeout {
        if fired_at.is_none() && fired(&runner.snapshot()) > before {
            fired_at = Some(t0.elapsed());
        }
        if fx.chain().len() >= n {
            return (fired_at.or(Some(t0.elapsed())), Some(t0.elapsed()));
        }
        std::thread::sleep(Duration::from_millis(5));
    }
    (fired_at, None)
}

/// (a) A change registers within the quiet period (2 s) plus the snap and a local ship.
///
/// The quiet timer is held to the configured period (it does no I/O). What follows it — the
/// snap, the worker's wake-up, the ship and the registration — is held to the same work forced
/// (an identical workspace's first capture, snapped and shipped right after on the same
/// machine), not to a wall-clock constant: on a runner with a slow disk every fsync and git
/// spawn is slower, for both alike. The change is written as the runner starts, so a missed
/// wake-up (the capture waiting for the ship worker's tick, [`SHIP_TICK`] after its first pass
/// at the start) costs ≈ 3 s after the timer: held to at least 2 s, one forced capture measured
/// once is not the only yardstick on a loaded runner (a scheduling stall of a second or so
/// failed it), and a missed wake-up still fails it.
#[test]
fn a_change_registers_within_the_quiet_period() {
    let fx = Fixture::build();
    let cadence = Cadence::default();
    let quiet = cadence.quiet;
    let runner = fx.runner(fx.config(cadence));
    // The ship worker made its first pass as the runner started; it ticks next about SHIP_TICK
    // after this.
    let started = Instant::now();
    assert_eq!(runner.snapshot().small_mode, WatchMode::Watched);
    assert!(fx.chain().is_empty(), "no snap without a change");

    let t0 = Instant::now();
    fs::write(fx.root.join("src/new.rs"), "fn n() {}\n").unwrap();
    let mut fired = None;
    let registered = loop {
        assert!(
            t0.elapsed() < quiet + Duration::from_secs(30),
            "no capture registered (quiet timer fired after {fired:?})"
        );
        if fired.is_none() && runner.snapshot().quiet_fired > 0 {
            fired = Some(t0.elapsed());
        }
        if !fx.chain().is_empty() {
            break t0.elapsed();
        }
        std::thread::sleep(Duration::from_millis(5));
    };
    let fired = fired.unwrap_or(registered);
    let after_quiet = registered.saturating_sub(fired);
    let snap = runner.snapshot();
    assert_eq!(snap.quiet_fired, 1);
    assert_eq!(snap.max_fired, 0);
    assert!(!snap.small_dirty, "a snap clears dirty");

    // The same work forced, right after on this machine.
    let forced = forced_capture();
    eprintln!(
        "(a) change → quiet timer {fired:?} → registered {after_quiet:?} later; \
         forced snap + ship {forced:?}"
    );

    // The event arrives after the write, and the timer runs from the event.
    assert!(fired >= quiet, "not before the quiet period: {fired:?}");
    assert!(
        fired <= quiet + Duration::from_secs(1),
        "the quiet timer fires at the quiet period: {fired:?}"
    );
    // A missed wake-up registers at the worker's next tick, about this long after the timer.
    let tick_after_timer = (started + SHIP_TICK).saturating_duration_since(t0 + fired);
    assert!(
        after_quiet <= after_timer_bound(forced).max(Duration::from_secs(2)),
        "snap + ship after the quiet timer took {after_quiet:?}; forced, the same work took \
         {forced:?}; the worker's next tick was {tick_after_timer:?} after the timer"
    );

    // Nothing changes after it: nothing more is captured.
    std::thread::sleep(quiet + Duration::from_millis(500));
    assert_eq!(fx.chain().len(), 1, "no snap without a change");
    assert_eq!(runner.snapshot().quiet_fired, 1);
    runner.stop();
}

/// (b) Writes every 500 ms for 15 s: captures register at most every `max_interval` (10 s),
/// never more than one per quiet period, then one more once the writer stops.
///
/// On a [`ManualClock`] ([`OnClock`]): the writes and every timer are at their virtual times, so
/// the timers are held to the configured periods whatever CPU the test gets (sealantd#160). What
/// follows each timer — the snap, the worker's wake-up, the ship, the registration — takes no
/// virtual time, so it is held to none: a capture that waited for the worker's tick (a missed
/// wake-up) registers seconds after its timer.
#[test]
fn continuous_writes_register_at_the_max_interval() {
    let fx = Fixture::build();
    let cadence = Cadence::default();
    let (quiet, max_interval) = (cadence.quiet, cadence.max_interval);
    let mut t = OnClock::start(&fx, fx.config(cadence));
    // The snap, ship and registration after a timer, in virtual time.
    let bound = Duration::ZERO;
    let mut i = 0u32;
    let mut last_write = Duration::ZERO;
    while t.now() < Duration::from_secs(15) {
        t.write("src/busy.rs", &format!("// {i}\n"));
        last_write = t.now();
        i += 1;
        t.run_to(last_write + Duration::from_millis(500));
    }
    let during = t.registered.clone();
    // The writer stopped: the quiet timer fires once more.
    let settle = t.now();
    t.run_to(settle + Duration::from_secs(5));
    while t.registered.len() == during.len() {
        assert!(
            t.now() < settle + Duration::from_secs(60),
            "the quiet timer fires once the writer stops: {:?}",
            t.registered
        );
        t.step(settle + Duration::from_secs(60));
    }
    let (registered, max_fired, quiet_fired) = (&t.registered, &t.max_fired, &t.quiet_fired);
    eprintln!(
        "(b) registrations at {registered:?}; max timer at {max_fired:?}; quiet timer at \
         {quiet_fired:?}; last write {last_write:?} (virtual time)"
    );
    assert!(
        (1..=2).contains(&during.len()),
        "one (maybe two) captures while writing: {during:?}"
    );
    // The first while writing: the max-interval timer, never quiet meanwhile.
    let first_timer = *max_fired.first().expect("the max-interval timer fired");
    assert!(
        first_timer >= max_interval - Duration::from_secs(1),
        "not before the max interval while never quiet: {first_timer:?}"
    );
    assert!(
        first_timer <= max_interval + Duration::from_secs(1),
        "the max-interval timer fires at the max interval: {first_timer:?}"
    );
    assert!(
        during[0] >= first_timer && during[0] - first_timer <= bound,
        "snap + ship after the max-interval timer took {:?} of virtual time",
        during[0].saturating_sub(first_timer)
    );
    for w in registered.windows(2) {
        let gap = w[1] - w[0];
        assert!(
            gap >= quiet,
            "never more than one per quiet period: {gap:?}"
        );
        assert!(
            gap <= max_interval + Duration::from_secs(1) + bound,
            "≤ max interval (and the capture's own time): {gap:?}"
        );
    }
    // The last: the quiet timer, the quiet period after the last write.
    let last_timer = *quiet_fired.last().expect("the quiet timer fired");
    assert!(
        last_timer >= last_write + quiet
            && last_timer <= last_write + quiet + Duration::from_secs(1),
        "quiet timer ≈ {quiet:?} after the last write ({last_write:?}): {last_timer:?}"
    );
    let last = *registered.last().unwrap();
    assert!(
        last >= last_timer && last - last_timer <= bound,
        "snap + ship after the quiet timer took {:?} of virtual time",
        last.saturating_sub(last_timer)
    );
    let snap = t.runner.snapshot();
    assert!(snap.max_fired >= 1, "{snap:?}");
    assert!(snap.quiet_fired >= 1, "{snap:?}");
    t.runner.stop();
}

/// (c) An overflow drops the watcher: snaps still happen, at the max interval; a budget of 0
/// polls from the start.
///
/// The poll timer is held to the max interval; the reconciliation, and each snap and ship after
/// a timer, to the same work forced on this machine ([`after_timer_bound`]), as in (a).
#[test]
fn overflow_and_a_missing_budget_fall_back_to_polling() {
    let forced = forced_capture();
    let bound = after_timer_bound(forced);
    let fx = Fixture::build();
    let cadence = Cadence {
        quiet: Duration::from_millis(500),
        max_interval: Duration::from_secs(3),
        ..Cadence::default()
    };
    let runner = fx.runner(fx.config(cadence));
    assert_eq!(runner.snapshot().small_mode, WatchMode::Watched);

    runner.signal(ChangeSignal::Overflow);
    // The overflow reconciles both classes at once (a small and a bulk snap, which coalesce
    // into one or two captures depending on who ships first), then polls. Two snaps and their
    // ships: held to twice the forced one's bound.
    let settle = Instant::now();
    loop {
        let snap = runner.snapshot();
        if snap.small_snaps >= 1 && snap.bulk_snaps >= 1 && !snap.bulk_running {
            break;
        }
        assert!(
            settle.elapsed() < bound * 2,
            "overflow reconciles now: {snap:?} after {:?}; forced, one capture took {forced:?}",
            settle.elapsed()
        );
        std::thread::sleep(Duration::from_millis(10));
    }
    let reconciled = fx.wait_for_chain(1, bound * 2);
    assert!(
        reconciled.is_some(),
        "the reconciliation registers; forced, one capture took {forced:?}"
    );
    let snap = runner.snapshot();
    assert_eq!(snap.small_mode, WatchMode::Polled);
    assert_eq!(snap.bulk_mode, WatchMode::Polled);
    assert_eq!(snap.overflows, 1);
    std::thread::sleep(Duration::from_millis(300));
    let n = fx.chain().len();
    assert!(
        fx.chain()
            .last()
            .unwrap()
            .manifest
            .sections
            .bulk
            .section()
            .is_some(),
        "the bulk class was reconciled too"
    );

    let polls = runner.snapshot().poll_fired;
    let t0 = Instant::now();
    fs::write(fx.root.join("src/after.rs"), "fn a() {}\n").unwrap();
    let (fired, took) = wait_timer_and_chain(
        &fx,
        &runner,
        n + 1,
        t0,
        cadence.max_interval + Duration::from_secs(30),
        |s| s.poll_fired,
        polls,
    );
    let Some(took) = took else {
        panic!(
            "polled snap registers the change: {:?} chain {:?}",
            runner.snapshot(),
            fx.chain()
                .iter()
                .map(|h| (
                    h.n,
                    h.manifest.kind,
                    h.manifest.sections.bulk.section().is_some()
                ))
                .collect::<Vec<_>>()
        );
    };
    let fired = fired.unwrap_or(took);
    eprintln!(
        "(c) after overflow: change → poll timer {fired:?} → registered {took:?}; forced \
         snap + ship {forced:?}"
    );
    assert!(
        took >= Duration::from_millis(1000),
        "not on the quiet timer (the watcher is gone): {took:?}"
    );
    assert!(
        fired <= cadence.max_interval + Duration::from_secs(1),
        "the poll timer fires at the max interval: {fired:?}"
    );
    assert!(
        took - fired <= bound,
        "snap + ship after the poll timer took {:?}; forced, the same work took {forced:?}",
        took - fired
    );
    runner.stop();

    // Budget 0: polled from the start.
    let fx = Fixture::build();
    let mut config = fx.config(cadence);
    config.watch.budget = Some(0);
    let runner = fx.runner(config);
    assert_eq!(runner.snapshot().small_mode, WatchMode::Polled);
    let t0 = Instant::now();
    fs::write(fx.root.join("src/polled.rs"), "fn p() {}\n").unwrap();
    let (fired, took) = wait_timer_and_chain(
        &fx,
        &runner,
        1,
        t0,
        cadence.max_interval + Duration::from_secs(30),
        |s| s.poll_fired,
        0,
    );
    let took = took.expect("polled snap registers");
    let fired = fired.unwrap_or(took);
    eprintln!("(c) budget 0: change → poll timer {fired:?} → registered {took:?}");
    assert!(took >= Duration::from_millis(1000), "{took:?}");
    assert!(
        fired <= cadence.max_interval + Duration::from_secs(1),
        "the poll timer fires at the max interval: {fired:?}"
    );
    assert!(
        took - fired <= bound,
        "snap + ship after the poll timer took {:?}; forced, the same work took {forced:?}",
        took - fired
    );
    assert!(runner.snapshot().poll_fired >= 1);
    runner.stop();
}

/// (d) Bulk changes alone produce no small-class capture and exactly one coalesced bulk capture
/// that carries the previous git/workspace sections.
///
/// On a [`ManualClock`] ([`OnClock`]): the burst is twenty writes 75 ms apart in virtual time,
/// well inside the bulk quiet period, however long the test's real writes take (sealantd#160,
/// `ci` run 39029483289).
#[test]
fn bulk_changes_alone_produce_one_coalesced_bulk_capture() {
    let fx = Fixture::build();
    let mut t = OnClock::start(&fx, fx.config(fast_bulk(Cadence::default(), 1000, 4000)));
    let snap = t.runner.snapshot();
    assert_eq!(snap.small_mode, WatchMode::Watched);
    assert_eq!(snap.bulk_mode, WatchMode::Watched);
    let base = t.runner.snap(CaptureKind::Checkpoint).unwrap();
    assert!(!base.unchanged);
    t.wait_for_chain(1, Duration::from_secs(5)).unwrap();

    // A burst of bulk writes.
    for i in 0..20 {
        t.write(
            &format!("node_modules/pkg/lib/m{i}.js"),
            &format!("module.exports = {i};\n"),
        );
        let next = t.now() + Duration::from_millis(75);
        t.run_to(next);
    }
    let took = t
        .wait_for_chain(2, Duration::from_secs(8))
        .expect("one bulk capture registers");
    eprintln!("(d) bulk burst → bulk capture registered {took:?} after the burst (virtual time)");
    let after = t.now() + Duration::from_secs(3);
    t.run_to(after);
    let chain = fx.chain();
    assert_eq!(chain.len(), 2, "one coalesced bulk capture: {chain:#?}");
    let head = &chain[1].manifest;
    assert_eq!(head.kind, CaptureKind::Auto);
    assert!(head.sections.bulk.section().is_some(), "bulk is ready");
    assert_eq!(
        head.sections.workspace, chain[0].manifest.sections.workspace,
        "the workspace section is copied from the checkpoint"
    );
    assert_eq!(head.sections.git, chain[0].manifest.sections.git);
    let snap = t.runner.snapshot();
    assert_eq!(snap.small_snaps, 1, "only the forced checkpoint: {snap:?}");
    assert_eq!(snap.bulk_snaps, 1, "{snap:?}");
    assert_eq!(snap.bulk_staged, 1, "{snap:?}");
    t.runner.stop();
}

/// (e) A due small snap is not delayed by an in-progress bulk build beyond one chunk's work:
/// a forced turn snap during a slow bulk build lands in well under the bulk build's time.
#[test]
fn a_due_small_snap_is_not_delayed_by_a_bulk_build() {
    let fx = Fixture::build();
    // 30 MB of incompressible bulk at a 5 % duty cycle: several seconds of bulk hashing.
    for i in 0..300 {
        fs::write(
            fx.root.join(format!("node_modules/pkg/lib/blob{i}.bin")),
            pseudo_random(100_000, 1000 + i),
        )
        .unwrap();
    }
    let mut config = fx.config(fast_bulk(Cadence::default(), 200, 1000));
    config.cpu_fraction = 0.05;
    let runner = fx.runner(config);
    runner.snap(CaptureKind::Checkpoint).unwrap();
    fx.wait_for_chain(1, Duration::from_secs(5)).unwrap();

    fs::write(fx.root.join("node_modules/pkg/lib/one-more.js"), "1\n").unwrap();
    let bulk_start = Instant::now();
    while !runner.snapshot().bulk_running {
        assert!(
            bulk_start.elapsed() < Duration::from_secs(5),
            "bulk snap starts"
        );
        std::thread::sleep(Duration::from_millis(10));
    }
    // The turn snap is asked for as soon as the build is seen running, not after a wait: the
    // build that reads the 30 MB starts with the runner, and on a fast runner it was over
    // within 700 ms of being seen.
    let t0 = Instant::now();
    let turn = runner.snap(CaptureKind::Turn).unwrap();
    let latency = t0.elapsed();
    assert_eq!(turn.kind, CaptureKind::Turn);
    let snap = runner.snapshot();
    eprintln!(
        "(e) turn snap latency during bulk build: {latency:?} (preemptions so far {})",
        snap.preemptions
    );
    assert!(snap.preemptions >= 1, "the bulk build yielded: {snap:?}");
    assert!(
        latency <= Duration::from_millis(1500),
        "one chunk (≤ 4 MiB) plus a pack finish plus a small snap: {latency:?}"
    );

    // The bulk build resumes and completes. Its wall time is 30 MB of hashing at a 5 % duty
    // cycle, which is slower on some runners (arm64 CI took over 60 s); what this test holds is
    // the turn snap's latency above, so this bound only has to catch a build that never ends.
    let done = Instant::now();
    while runner.snapshot().bulk_snaps < 1 {
        assert!(done.elapsed() < Duration::from_secs(180), "bulk completes");
        std::thread::sleep(Duration::from_millis(50));
    }
    let bulk_wall = bulk_start.elapsed();
    eprintln!("(e) bulk build wall time {bulk_wall:?}");
    assert!(
        bulk_wall > latency * 2,
        "the bulk build took much longer than the turn snap waited"
    );
    // The shipper runs at the same duty cycle; give the 30 MB its time.
    fx.wait_for_chain(3, Duration::from_secs(120))
        .expect("checkpoint, turn and bulk register");
    let chain = fx.chain();
    let head = &chain.last().unwrap().manifest;
    assert!(head.sections.bulk.section().is_some());
    assert_eq!(chain[1].manifest.kind, CaptureKind::Turn);
    let snap = runner.snapshot();
    assert!(!snap.bulk_in_progress);
    runner.stop();
}

/// sealantd#195: whether a bulk build is paused mid-way, as the runner reads it without the
/// engine (`capture.status`, a final flush's currency check), is what the engine answers after
/// every transition: the build yields, resumes and finishes. Another holder of the engine does
/// not hide a paused build.
#[test]
fn a_paused_bulk_build_reads_as_paused_whoever_holds_the_engine() {
    let fx = Fixture::build();
    let mut engine = CaptureEngine::open(fx.config(Cadence::default()), None).unwrap();
    let bulk = |seq| SnapRequest {
        kind: CaptureKind::Auto,
        class: Class::Bulk,
        seq,
    };
    let yielded = engine.snap_preemptible(bulk(1), &|| true).unwrap();
    assert!(
        matches!(yielded, SnapOutcome::Preempted),
        "the build yields at its first read"
    );
    let sink = Arc::new(LocalDir::new(&fx.base.join("store")).unwrap());
    let registrar: Arc<dyn sealant_capture::Registrar> = fx.registrar.clone();
    let shipper = Arc::new(engine.shipper(sink, registrar));
    let runner = CadenceRunner::new(engine, shipper);
    let paused = |runner: &CadenceRunner| {
        (
            runner.with_engine(CaptureEngine::bulk_in_progress),
            runner.snapshot().bulk_in_progress,
        )
    };
    assert_eq!(paused(&runner), (true, true), "paused");
    assert!(
        runner.with_engine(|_| runner.snapshot().bulk_in_progress),
        "paused while another holds the engine"
    );

    let seen = RefCell::new(Vec::new());
    let resumed = runner
        .with_engine_mut(|engine| {
            engine.snap_preemptible(bulk(2), &|| {
                seen.borrow_mut().push(runner.snapshot().bulk_in_progress);
                false
            })
        })
        .unwrap();
    assert!(
        matches!(resumed, SnapOutcome::Staged(_)),
        "the build resumes and stages"
    );
    let seen = seen.into_inner();
    assert!(
        !seen.is_empty() && seen.iter().all(|paused| !paused),
        "running, not paused, while it resumes: {seen:?}"
    );
    assert_eq!(paused(&runner), (false, false), "finished");
}

/// sealantd#195, the other way round: a bulk build paused after a complete final flush (the
/// bulk class had a file to read again) is never read as the disk the flush captured, whoever
/// holds the engine. A failed try at the engine's lock must not pass for an idle bulk class.
#[test]
fn a_bulk_build_paused_after_a_final_flush_is_never_current() {
    let fx = Fixture::build();
    let sink = Arc::new(LocalDir::new(&fx.base.join("store")).unwrap());
    let engine = CaptureEngine::open(fx.config(Cadence::default()), None).unwrap();
    let registrar: Arc<dyn sealant_capture::Registrar> = fx.registrar.clone();
    let shipper = Arc::new(engine.shipper(sink, registrar));
    let runner = CadenceRunner::new(engine, shipper);
    let allowed = Arc::new(AtomicBool::new(true));
    let hook = Arc::clone(&allowed);
    runner.start(Some(Arc::new(move || hook.load(Ordering::SeqCst))));
    // The writers stop, then the final flush.
    allowed.store(false, Ordering::SeqCst);
    let flushed = runner.flush_final(Some(Duration::from_secs(60)));
    assert!(flushed.incomplete.is_none(), "{:?}", flushed.incomplete);
    assert!(
        runner.final_is_current_as_snapped(),
        "current after the flush"
    );

    let yielded = runner
        .with_engine_mut(|engine| {
            engine
                .invalidations()
                .note(Class::Bulk, &fx.root.join("node_modules/pkg/lib/index.js"));
            engine.snap_preemptible(
                SnapRequest {
                    kind: CaptureKind::Auto,
                    class: Class::Bulk,
                    seq: 1_000,
                },
                &|| true,
            )
        })
        .unwrap();
    assert!(
        matches!(yielded, SnapOutcome::Preempted),
        "the build yields at its read"
    );
    assert!(
        !runner.final_is_current_as_snapped(),
        "a paused bulk build is not current"
    );
    assert!(
        !runner.with_engine(|_| runner.final_is_current_as_snapped()),
        "a paused bulk build is not current while another holds the engine"
    );
    runner.stop();
}
