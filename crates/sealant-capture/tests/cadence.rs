//! Runtime-level proofs of the cadence (ADR-0015 *Cadence and budgets*) against a fake
//! registrar and a `LocalDir` sink: real files, the real watcher, wall-clock timers.

use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::Arc;
use std::time::{Duration, Instant};

use sealant_capture::manifest::CaptureKind;
use sealant_capture::registrar::HeadInfo;
use sealant_capture::{
    Cadence, CadenceRunner, CaptureConfig, CaptureEngine, ChangeSignal, InMemoryRegistrar,
    LocalDir, WatchMode,
};

fn git(root: &Path, args: &[&str]) {
    let out = Command::new("git")
        .current_dir(root)
        .env("GIT_OPTIONAL_LOCKS", "0")
        .args(args)
        .output()
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

fn fast_bulk(mut cadence: Cadence, quiet_ms: u64, max_ms: u64) -> Cadence {
    cadence.bulk_quiet = Duration::from_millis(quiet_ms);
    cadence.bulk_max_interval = Duration::from_millis(max_ms);
    cadence
}

/// (a) A change registers within the quiet period (2 s) plus the snap and a local ship.
#[test]
fn a_change_registers_within_the_quiet_period() {
    let fx = Fixture::build();
    let runner = fx.runner(fx.config(Cadence::default()));
    assert_eq!(runner.snapshot().small_mode, WatchMode::Watched);
    // Nothing changes: nothing is captured.
    std::thread::sleep(Duration::from_millis(1500));
    assert!(fx.chain().is_empty(), "no snap without a change");

    let t0 = Instant::now();
    fs::write(fx.root.join("src/new.rs"), "fn n() {}\n").unwrap();
    let took = fx
        .wait_for_chain(1, Duration::from_secs(6))
        .expect("a capture registers");
    eprintln!("(a) change → registered in {took:?}");
    assert!(
        took >= Duration::from_millis(1800),
        "not before the quiet period: {took:?}"
    );
    assert!(
        took <= Duration::from_millis(3000),
        "quiet + snap + ship: {took:?}"
    );
    let snap = runner.snapshot();
    assert_eq!(snap.quiet_fired, 1);
    assert_eq!(snap.max_fired, 0);
    assert!(!snap.small_dirty, "a snap clears dirty");
    let _ = t0;
    runner.stop();
}

/// (b) Writes every 500 ms for 15 s: captures register at most every `max_interval` (10 s),
/// never more than one per quiet period, then one more once the writer stops.
#[test]
fn continuous_writes_register_at_the_max_interval() {
    let fx = Fixture::build();
    let runner = fx.runner(fx.config(Cadence::default()));
    let start = Instant::now();
    let mut registered: Vec<Duration> = Vec::new();
    let mut seen = 0usize;
    let mut i = 0u32;
    while start.elapsed() < Duration::from_secs(15) {
        fs::write(fx.root.join("src/busy.rs"), format!("// {i}\n")).unwrap();
        i += 1;
        let until = start.elapsed() + Duration::from_millis(500);
        while start.elapsed() < until {
            let n = fx.chain().len();
            if n > seen {
                registered.push(start.elapsed());
                seen = n;
            }
            std::thread::sleep(Duration::from_millis(25));
        }
    }
    let during = registered.clone();
    // The writer stopped: the quiet timer fires once more.
    let settle = Instant::now();
    while settle.elapsed() < Duration::from_secs(5) {
        let n = fx.chain().len();
        if n > seen {
            registered.push(start.elapsed());
            seen = n;
        }
        std::thread::sleep(Duration::from_millis(25));
    }
    eprintln!("(b) registrations at {registered:?}");
    assert!(
        (1..=2).contains(&during.len()),
        "one (maybe two) captures while writing: {during:?}"
    );
    assert!(
        during[0] <= Duration::from_millis(11_000),
        "the first at the max interval: {:?}",
        during[0]
    );
    assert!(
        during[0] >= Duration::from_millis(9_000),
        "not before the max interval while never quiet: {:?}",
        during[0]
    );
    for w in registered.windows(2) {
        let gap = w[1] - w[0];
        assert!(
            gap >= Duration::from_secs(2),
            "never more than one per quiet period: {gap:?}"
        );
        assert!(
            gap <= Duration::from_millis(11_000),
            "≤ max interval: {gap:?}"
        );
    }
    assert!(
        registered.len() > during.len(),
        "the quiet timer fires once the writer stops"
    );
    let last = *registered.last().unwrap();
    assert!(
        last >= Duration::from_millis(16_000) && last <= Duration::from_millis(18_500),
        "quiet snap ≈ 2 s after the last write (at 14.5–15 s): {last:?}"
    );
    let snap = runner.snapshot();
    assert!(snap.max_fired >= 1, "{snap:?}");
    assert!(snap.quiet_fired >= 1, "{snap:?}");
    runner.stop();
}

/// (c) An overflow drops the watcher: snaps still happen, at the max interval; a budget of 0
/// polls from the start.
#[test]
fn overflow_and_a_missing_budget_fall_back_to_polling() {
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
    // into one or two captures depending on who ships first), then polls.
    let settle = Instant::now();
    loop {
        let snap = runner.snapshot();
        if snap.small_snaps >= 1 && snap.bulk_snaps >= 1 && !snap.bulk_running {
            break;
        }
        assert!(
            settle.elapsed() < Duration::from_secs(4),
            "overflow reconciles now: {snap:?}"
        );
        std::thread::sleep(Duration::from_millis(10));
    }
    fx.wait_for_chain(1, Duration::from_secs(4))
        .expect("the reconciliation registers");
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

    let t0 = Instant::now();
    fs::write(fx.root.join("src/after.rs"), "fn a() {}\n").unwrap();
    let took = fx.wait_for_chain(n + 1, Duration::from_secs(8));
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
    eprintln!("(c) after overflow: change → registered in {took:?}");
    assert!(
        took >= Duration::from_millis(1000),
        "not on the quiet timer (the watcher is gone): {took:?}"
    );
    assert!(
        took <= Duration::from_millis(4500),
        "at the max interval: {took:?}"
    );
    let _ = t0;
    runner.stop();

    // Budget 0: polled from the start.
    let fx = Fixture::build();
    let mut config = fx.config(cadence);
    config.watch.budget = Some(0);
    let runner = fx.runner(config);
    assert_eq!(runner.snapshot().small_mode, WatchMode::Polled);
    fs::write(fx.root.join("src/polled.rs"), "fn p() {}\n").unwrap();
    let took = fx
        .wait_for_chain(1, Duration::from_secs(8))
        .expect("polled snap registers");
    eprintln!("(c) budget 0: change → registered in {took:?}");
    assert!(took >= Duration::from_millis(1000) && took <= Duration::from_millis(4500));
    assert!(runner.snapshot().poll_fired >= 1);
    runner.stop();
}

/// (d) Bulk changes alone produce no small-class capture and exactly one coalesced bulk capture
/// that carries the previous git/workspace sections.
#[test]
fn bulk_changes_alone_produce_one_coalesced_bulk_capture() {
    let fx = Fixture::build();
    let runner = fx.runner(fx.config(fast_bulk(Cadence::default(), 1000, 4000)));
    let snap = runner.snapshot();
    assert_eq!(snap.small_mode, WatchMode::Watched);
    assert_eq!(snap.bulk_mode, WatchMode::Watched);
    let base = runner.snap(CaptureKind::Checkpoint).unwrap();
    assert!(!base.unchanged);
    fx.wait_for_chain(1, Duration::from_secs(5)).unwrap();

    // A burst of bulk writes.
    for i in 0..20 {
        fs::write(
            fx.root.join(format!("node_modules/pkg/lib/m{i}.js")),
            format!("module.exports = {i};\n"),
        )
        .unwrap();
        std::thread::sleep(Duration::from_millis(75));
    }
    let took = fx
        .wait_for_chain(2, Duration::from_secs(8))
        .expect("one bulk capture registers");
    eprintln!("(d) bulk burst → bulk capture registered {took:?} after the burst");
    std::thread::sleep(Duration::from_secs(3));
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
    let snap = runner.snapshot();
    assert_eq!(snap.small_snaps, 1, "only the forced checkpoint: {snap:?}");
    assert_eq!(snap.bulk_snaps, 1, "{snap:?}");
    assert_eq!(snap.bulk_staged, 1, "{snap:?}");
    runner.stop();
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
    std::thread::sleep(Duration::from_millis(700));
    assert!(
        runner.snapshot().bulk_running,
        "the bulk build is still running"
    );

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

    // The bulk build resumes and completes.
    let done = Instant::now();
    while runner.snapshot().bulk_snaps < 1 {
        assert!(done.elapsed() < Duration::from_secs(60), "bulk completes");
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
