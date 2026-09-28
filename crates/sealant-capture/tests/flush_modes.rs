//! `capture.flush` has two kinds, and neither loses work product.
//!
//! - `final` (the executor is going away): a small-class AND a bulk-class snap — the bulk one
//!   forced, whatever the bulk clocks say, and ahead of a scheduled bulk build in progress —
//!   then ship until nothing is pending, bulk included. A deadline, when the caller gives one,
//!   is honoured as given; whatever is left stays staged and is reported.
//! - `suspend`: unchanged from #98 — returns once every capture ahead of a bulk capture still
//!   uploading is registered.
//! - `pending_bytes`: what is staged and not uploaded yet, each object counted once.
//! - A lost lease (409 `lease-lost`) pauses shipping and asks again; it is never a chain
//!   conflict, which would end a final flush with everything still staged.

use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

use sealant_capture::manifest::{BulkState, DirFormat};
use sealant_capture::sink::{BlobSource, PutOutcome, SinkError};
use sealant_capture::{
    BlobSink, Cadence, CadenceRunner, CaptureConfig, CaptureEngine, CaptureKind, Class,
    InMemoryRegistrar, LocalDir, MaterializeClass, MaterializeTargets, Materializer, Registrar,
    SnapRequest,
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

fn workspace(root: &Path, packages: usize) {
    fs::create_dir_all(root.join("src")).unwrap();
    git(root, &["init", "-q", "-b", "main"]);
    git(root, &["config", "user.email", "t@t"]);
    git(root, &["config", "user.name", "t"]);
    fs::write(root.join(".gitignore"), "node_modules/\n").unwrap();
    fs::write(root.join("src/lib.rs"), "pub fn f() {}\n").unwrap();
    git(root, &["add", "-A"]);
    git(root, &["commit", "-q", "-m", "one"]);
    for p in 0..packages {
        let dir = root.join(format!("node_modules/pkg{p}/lib"));
        fs::create_dir_all(&dir).unwrap();
        for f in 0..3 {
            fs::write(
                dir.join(format!("m{f}.js")),
                format!("module.exports = [{p}, {f}];\n").repeat(5),
            )
            .unwrap();
        }
    }
}

/// Every file under `dir` with its bytes, sorted; `.sealantd` and `.git` left out.
fn files(dir: &Path) -> Vec<(String, Vec<u8>)> {
    let mut out: Vec<(String, Vec<u8>)> = walkdir::WalkDir::new(dir)
        .into_iter()
        .filter_entry(|e| e.file_name() != ".sealantd" && e.file_name() != ".git")
        .map(Result::unwrap)
        .filter(|e| e.file_type().is_file())
        .map(|e| {
            (
                e.path().strip_prefix(dir).unwrap().display().to_string(),
                fs::read(e.path()).unwrap(),
            )
        })
        .collect();
    out.sort();
    out
}

/// A sink that spends `delay` on every PUT.
struct Slow {
    inner: Arc<LocalDir>,
    delay: Duration,
    puts: AtomicU64,
}

impl BlobSink for Slow {
    fn put_if_absent(&self, key: &str, source: BlobSource<'_>) -> Result<PutOutcome, SinkError> {
        self.puts.fetch_add(1, Ordering::SeqCst);
        std::thread::sleep(self.delay);
        self.inner.put_if_absent(key, source)
    }

    fn get(&self, key: &str) -> Result<Vec<u8>, SinkError> {
        self.inner.get(key)
    }

    fn exists(&self, key: &str) -> Result<bool, SinkError> {
        self.inner.exists(key)
    }
}

struct Fixture {
    _tmp: tempfile::TempDir,
    base: PathBuf,
    root: PathBuf,
    store: Arc<LocalDir>,
    registrar: Arc<InMemoryRegistrar>,
}

fn fixture(packages: usize) -> Fixture {
    let tmp = tempfile::tempdir().unwrap();
    let base = tmp.path().to_path_buf();
    let root = base.join("ws");
    workspace(&root, packages);
    Fixture {
        store: Arc::new(LocalDir::new(&base.join("store")).unwrap()),
        registrar: Arc::new(InMemoryRegistrar::new("wt", 1, None)),
        _tmp: tmp,
        base,
        root,
    }
}

/// One object per directory, one PUT at a time: a bulk upload that takes a while behind `Slow`.
fn slow_config(root: &Path) -> CaptureConfig {
    let mut config = CaptureConfig::new("wt", 1, root);
    config.dir_format = DirFormat::Objects;
    config.uploads_in_flight = 1;
    config
}

fn runner(config: CaptureConfig, sink: Arc<dyn BlobSink>, fx: &Fixture) -> CadenceRunner {
    let engine = CaptureEngine::open(config, None).unwrap();
    let registrar: Arc<dyn Registrar> = fx.registrar.clone();
    let shipper = Arc::new(engine.shipper(sink, registrar));
    CadenceRunner::new(engine, shipper)
}

fn restore_head(fx: &Fixture, into: &Path) {
    Materializer::new(fx.store.as_ref(), MaterializeTargets::new(into, None))
        .materialize(
            &fx.registrar.head().unwrap().manifest,
            MaterializeClass::All,
        )
        .unwrap();
}

/// The dependency tree changed a moment ago — the bulk clocks (30 s quiet here, and a watcher
/// running) have not fired — and the executor is going away. A final flush snaps the bulk class
/// anyway and does not return before that capture is registered, behind a sink that spends
/// 20 ms on every object: the head restores the tree as it is now, byte for byte.
#[test]
fn a_final_flush_snaps_a_freshly_changed_bulk_dir_and_waits_for_it() {
    let fx = fixture(40);
    let slow = Arc::new(Slow {
        inner: fx.store.clone(),
        delay: Duration::from_millis(20),
        puts: AtomicU64::new(0),
    });
    let runner = runner(slow_config(&fx.root), slow.clone(), &fx);
    runner.start(None);
    // The first final flush captures everything as it was.
    runner.flush(CaptureKind::Final, None).unwrap();
    let before = fx.registrar.head().unwrap();
    assert!(matches!(before.manifest.sections.bulk, BulkState::Ready(_)));

    // A fresh change to the dependency tree: rewritten, added, removed.
    fs::write(fx.root.join("node_modules/pkg3/lib/m1.js"), "rebuilt\n").unwrap();
    fs::create_dir_all(fx.root.join("node_modules/fresh")).unwrap();
    fs::write(fx.root.join("node_modules/fresh/index.js"), "new\n").unwrap();
    fs::remove_file(fx.root.join("node_modules/pkg7/lib/m0.js")).unwrap();
    let puts = slow.puts.load(Ordering::SeqCst);
    let start = Instant::now();
    runner.flush(CaptureKind::Final, None).unwrap();
    eprintln!(
        "final flush: {} PUTs in {:?}",
        slow.puts.load(Ordering::SeqCst) - puts,
        start.elapsed()
    );
    assert!(runner.staging().pending().unwrap().is_empty());
    let head = fx.registrar.head().unwrap();
    assert!(head.n > before.n);
    assert_ne!(
        head.manifest.sections.bulk, before.manifest.sections.bulk,
        "the bulk section was snapped again"
    );
    let fresh = fx.base.join("fresh");
    restore_head(&fx, &fresh);
    assert_eq!(
        files(&fresh.join("node_modules")),
        files(&fx.root.join("node_modules"))
    );
    let snap = runner.snapshot();
    assert_eq!((snap.forced, snap.bulk_staged), (2, 2), "{snap:?}");
    runner.stop();
}

/// A scheduled bulk build is running when the final flush arrives (bulk clocks of a few
/// milliseconds, a tree that changes under it): the forced bulk snap preempts it, resumes its
/// progress, and captures the tree as it is when the flush was asked for.
#[test]
fn a_final_flush_preempts_a_scheduled_bulk_build() {
    let fx = fixture(150);
    let mut config = CaptureConfig::new("wt", 1, &fx.root);
    config.cadence = Cadence {
        quiet: Duration::from_millis(5),
        max_interval: Duration::from_millis(20),
        bulk_quiet: Duration::from_millis(5),
        bulk_max_interval: Duration::from_millis(20),
        ..Cadence::default()
    };
    let runner = runner(config, fx.store.clone(), &fx);
    runner.start(None);
    // Keep the bulk class busy: every change re-arms its clocks.
    for i in 0..20 {
        fs::write(
            fx.root.join(format!("node_modules/pkg{i}/lib/m2.js")),
            format!("churn {i}\n"),
        )
        .unwrap();
        std::thread::sleep(Duration::from_millis(3));
    }
    fs::write(fx.root.join("node_modules/pkg0/lib/last.js"), "the last\n").unwrap();
    runner.flush(CaptureKind::Final, None).unwrap();
    let fresh = fx.base.join("fresh");
    restore_head(&fx, &fresh);
    assert_eq!(
        fs::read_to_string(fresh.join("node_modules/pkg0/lib/last.js")).unwrap(),
        "the last\n"
    );
    runner.stop();
    // Whatever the scheduled build did meanwhile, the head is the disk.
    let fresh = fx.base.join("fresh2");
    restore_head(&fx, &fresh);
    assert_eq!(
        files(&fresh.join("node_modules")),
        files(&fx.root.join("node_modules"))
    );
}

/// A final flush given a deadline returns at it — the rest stays staged and is reported, never
/// dropped, and the flush is not complete (it answered `Ok` before, like a finished one) — and
/// a final flush without one then finishes the job.
#[test]
fn a_final_flush_with_a_deadline_returns_at_it_and_keeps_the_rest_staged() {
    let fx = fixture(60);
    let slow = Arc::new(Slow {
        inner: fx.store.clone(),
        delay: Duration::from_millis(20),
        puts: AtomicU64::new(0),
    });
    let runner = runner(slow_config(&fx.root), slow.clone(), &fx);
    let start = Instant::now();
    let flushed = runner.flush(CaptureKind::Final, Some(Duration::from_millis(300)));
    let took = start.elapsed();
    let error = flushed.expect_err("a flush cut short by its deadline is not complete");
    assert!(error.to_string().contains("deadline"), "{error}");
    assert!(
        took < Duration::from_secs(2),
        "returned at its deadline: {took:?}"
    );
    let pending = runner.staging().pending().unwrap();
    assert!(
        pending.iter().any(|e| e.class == Some(Class::Bulk)),
        "the bulk capture is still staged: {pending:?}"
    );
    assert!(runner.staging().pending_bytes(&pending) > 0);

    runner.flush(CaptureKind::Final, None).unwrap();
    assert!(runner.staging().pending().unwrap().is_empty());
    let fresh = fx.base.join("fresh");
    restore_head(&fx, &fresh);
    assert_eq!(
        files(&fresh.join("node_modules")),
        files(&fx.root.join("node_modules"))
    );
}

/// A suspend flush is what #98 made it: it snaps the small class only and returns once every
/// capture ahead of the bulk capture still uploading is registered, with or without a deadline.
#[test]
fn a_suspend_flush_returns_ahead_of_a_bulk_upload() {
    let fx = fixture(60);
    let slow = Arc::new(Slow {
        inner: fx.store.clone(),
        delay: Duration::from_millis(20),
        puts: AtomicU64::new(0),
    });
    let mut engine = CaptureEngine::open(slow_config(&fx.root), None).unwrap();
    for (class, seq) in [(Class::Small, 1), (Class::Bulk, 2)] {
        engine
            .snap(SnapRequest {
                kind: CaptureKind::Auto,
                class,
                seq,
            })
            .unwrap();
    }
    let sink: Arc<dyn BlobSink> = slow.clone();
    let registrar: Arc<dyn Registrar> = fx.registrar.clone();
    let shipper = Arc::new(engine.shipper(sink, registrar));
    let runner = CadenceRunner::new(engine, shipper);
    fs::write(fx.root.join("src/lib.rs"), "pub fn f() { edited() }\n").unwrap();
    let start = Instant::now();
    runner.flush(CaptureKind::Suspend, None).unwrap();
    let took = start.elapsed();
    let pending = runner.staging().pending().unwrap();
    assert_eq!(
        pending.len(),
        1,
        "only the bulk capture is left: {pending:?}"
    );
    assert_eq!(pending[0].class, Some(Class::Bulk));
    let head = fx.registrar.head().unwrap();
    assert_eq!(head.manifest.kind, CaptureKind::Suspend);
    assert!(
        took < Duration::from_secs(2),
        "did not wait for the bulk upload: {took:?}"
    );
    assert!(runner.staging().pending_bytes(&pending) > 0);
}

/// `pending_bytes` is what the queue still has to upload: every object not acked, an object two
/// captures share counted once. It falls as objects go up and is 0 once they all have.
#[test]
fn pending_bytes_counts_what_is_not_uploaded_yet() {
    let fx = fixture(30);
    let slow = Arc::new(Slow {
        inner: fx.store.clone(),
        delay: Duration::from_millis(10),
        puts: AtomicU64::new(0),
    });
    let mut engine = CaptureEngine::open(slow_config(&fx.root), None).unwrap();
    for (class, seq) in [(Class::Small, 1), (Class::Bulk, 2)] {
        engine
            .snap(SnapRequest {
                kind: CaptureKind::Checkpoint,
                class,
                seq,
            })
            .unwrap();
    }
    let staging = engine.staging();
    let pending = staging.pending().unwrap();
    let mut unique = std::collections::BTreeMap::new();
    for u in pending.iter().flat_map(|e| &e.uploads) {
        unique.insert(u.file.clone(), u.bytes);
    }
    let all: u64 = unique.values().sum();
    assert!(all > 0);
    assert_eq!(staging.pending_bytes(&pending), all);
    // Summed per entry instead, a shared object would count twice.
    let listed: u64 = pending
        .iter()
        .flat_map(|e| &e.uploads)
        .map(|u| u.bytes)
        .sum();
    assert!(listed >= all);

    let sink: Arc<dyn BlobSink> = slow.clone();
    let registrar: Arc<dyn Registrar> = fx.registrar.clone();
    let shipper = engine.shipper(sink, registrar);
    shipper.flush(Duration::from_millis(150)).unwrap();
    let left = staging.pending().unwrap();
    let partial = staging.pending_bytes(&left);
    assert!(
        partial > 0 && partial < all,
        "part uploaded: {partial} of {all}"
    );
    shipper.flush(Duration::from_secs(60)).unwrap();
    let left = staging.pending().unwrap();
    assert!(left.is_empty());
    assert_eq!(staging.pending_bytes(&left), 0);
}

/// The registrar answers `lease-lost` (the lease lapsed, or was released before the executor
/// was done): shipping pauses and asks again, nothing is dropped and nothing reads as a chain
/// conflict. A final flush waits it out and returns once the lease is back and everything is
/// registered.
#[test]
fn a_lost_lease_pauses_shipping_and_a_final_flush_waits_it_out() {
    let fx = fixture(5);
    let engine = CaptureEngine::open(CaptureConfig::new("wt", 1, &fx.root), None).unwrap();
    let sink: Arc<dyn BlobSink> = fx.store.clone();
    let registrar: Arc<dyn Registrar> = fx.registrar.clone();
    let shipper = Arc::new(
        engine
            .shipper(sink, registrar)
            .with_lease_backoff(Duration::from_millis(20), Duration::from_millis(100)),
    );
    let runner = CadenceRunner::new(engine, shipper.clone());
    runner.snap(CaptureKind::Turn).unwrap();

    fx.registrar.set_lease_alive(false);
    assert_eq!(
        shipper.ship_pending().unwrap(),
        0,
        "a pass pauses, it does not fail"
    );
    assert!(shipper.status.snapshot().lease_lost);
    assert!(!shipper.is_fenced());
    assert_eq!(runner.staging().pending().unwrap().len(), 1, "still staged");

    let lift = {
        let registrar = fx.registrar.clone();
        std::thread::spawn(move || {
            std::thread::sleep(Duration::from_millis(400));
            registrar.set_lease_alive(true);
            Instant::now()
        })
    };
    runner.flush(CaptureKind::Final, None).unwrap();
    let returned = Instant::now();
    let lifted = lift.join().unwrap();
    assert!(returned >= lifted, "returned before the lease came back");
    assert!(runner.staging().pending().unwrap().is_empty());
    assert!(!shipper.status.snapshot().lease_lost);
    let chain = fx.registrar.chain();
    assert_eq!(chain[0].manifest.kind, CaptureKind::Turn);
    assert!(matches!(
        chain.last().unwrap().manifest.sections.bulk,
        BulkState::Ready(_)
    ));
}

/// Review finding #11: a final flush whose forced bulk snap failed logged it and went on; older
/// captures drained and the flush answered success, while the dependency tree as it was then
/// was on the disk only. Now a failed final snap of either class makes the flush incomplete
/// (`snapshot-failed`), and what could be staged still ships.
///
/// The bulk snap is made to fail where it writes: the pack it produces has a name fixed by its
/// bytes, so the same tree snapped elsewhere names it, and a directory in its place makes the
/// rename fail.
#[test]
fn a_failed_final_bulk_snap_is_not_a_complete_flush() {
    // The same tree, snapped elsewhere: the packs a bulk snap of it writes.
    let probe = fixture(20);
    let runner_probe = runner(
        CaptureConfig::new("wt", 1, &probe.root),
        probe.store.clone(),
        &probe,
    );
    runner_probe.flush(CaptureKind::Final, None).unwrap();
    let BulkState::Ready(bulk) = probe.registrar.head().unwrap().manifest.sections.bulk else {
        panic!("the probe snapped the bulk class");
    };
    runner_probe.stop();

    let fx = fixture(20);
    let config = CaptureConfig::new("wt", 1, &fx.root);
    let objects = config.staging_dir().join("objects");
    for key in &bulk.packs {
        let sha = key.rsplit('/').next().unwrap();
        fs::create_dir_all(objects.join(sha).join("taken")).unwrap();
    }
    let runner = runner(config, fx.store.clone(), &fx);
    let flushed = runner.flush(CaptureKind::Final, None);
    let error = flushed.expect_err("a failed final bulk snap is not a complete flush");
    assert!(error.to_string().contains("snap failed"), "{error}");
    let reported = runner.flush_final(None);
    assert_eq!(
        reported.incomplete.as_ref().map(|i| i.reason()),
        Some("snapshot-failed"),
        "{reported:?}"
    );
    // The small class still shipped: the edit-level work is in the store.
    assert!(runner.staging().pending().unwrap().is_empty());
    assert!(matches!(
        fx.registrar.head().unwrap().manifest.sections.bulk,
        BulkState::Pending(_)
    ));
}

/// Review finding #11: once the shipper had been fenced, a pass answered "done" and the next
/// final flush succeeded with the capture still staged. A final flush on a fenced lease is now
/// an error every time, and the capture stays staged.
#[test]
fn a_final_flush_after_a_fence_is_not_a_success() {
    let fx = fixture(3);
    let engine = CaptureEngine::open(CaptureConfig::new("wt", 1, &fx.root), None).unwrap();
    let sink: Arc<dyn BlobSink> = fx.store.clone();
    let registrar: Arc<dyn Registrar> = fx.registrar.clone();
    let shipper = Arc::new(engine.shipper(sink, registrar));
    let runner = CadenceRunner::new(engine, shipper.clone());
    runner.snap(CaptureKind::Turn).unwrap();
    fx.registrar.set_live_epoch(2);
    assert!(shipper.ship_pending().is_err(), "the fence is found");
    assert!(shipper.is_fenced());

    let flushed = runner.flush(CaptureKind::Final, None);
    let error = flushed.expect_err("a fenced final flush is not a success");
    assert!(error.to_string().contains("fenced"), "{error}");
    assert!(
        !runner.staging().pending().unwrap().is_empty(),
        "still staged"
    );
    assert!(fx.registrar.chain().is_empty());
}

/// A final flush that meets work it cannot read is incomplete *because* of that work
/// (`unreadable`), not as a generic snapshot failure: the control plane can name it. Nothing
/// that would drop the file registers, and the staging directory is kept.
#[test]
fn a_final_flush_over_unreadable_work_is_incomplete_for_that_reason() {
    use std::os::unix::fs::PermissionsExt;
    let fx = fixture(3);
    let notes = fx.root.join("notes.txt");
    fs::write(&notes, b"KEEP").unwrap();
    let config = CaptureConfig::new("wt", 1, &fx.root);
    let staging_dir = config.staging_dir();
    let runner = runner(config, fx.store.clone(), &fx);
    runner.snap(CaptureKind::Turn).unwrap();
    runner.ship(Duration::from_secs(30)).unwrap();

    fs::set_permissions(&notes, fs::Permissions::from_mode(0o000)).unwrap();
    if fs::read(&notes).is_ok() {
        fs::set_permissions(&notes, fs::Permissions::from_mode(0o644)).unwrap();
        eprintln!("skipped: permission bits do not bind this process");
        return;
    }
    let reported = runner.flush_final(None);
    fs::set_permissions(&notes, fs::Permissions::from_mode(0o644)).unwrap();

    assert!(!reported.complete(), "{reported:?}");
    assert_eq!(
        reported.incomplete.as_ref().map(|i| i.reason()),
        Some("unreadable"),
        "{reported:?}"
    );
    assert!(
        reported
            .incomplete
            .as_ref()
            .is_some_and(|i| i.to_string().contains("notes.txt")),
        "names the path: {reported:?}"
    );
    assert!(staging_dir.is_dir(), "the staging directory is kept");
    let out = fx.base.join("restored");
    restore_head(&fx, &out);
    assert_eq!(
        fs::read(out.join("notes.txt")).unwrap(),
        b"KEEP",
        "the head still holds the file's last read bytes"
    );
    runner.stop();
}
