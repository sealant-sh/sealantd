//! No work product is lost: the dependency tree and every other ignored file always come back.
//!
//! - A `"pending"` bulk section is never taken for "nothing there": a materialize from such a
//!   head leaves the bulk directories on disk as they are, and the next bulk snap captures them.
//! - A `final` flush (the executor and its disk are going away) snaps the bulk class and ships
//!   everything, bulk included; without a deadline it returns only once nothing is pending, and
//!   a capture held for the byte quota keeps it waiting instead of being abandoned.
//! - A daemon that restarts on its own disk resumes it: the head is not materialized over
//!   captures that were staged and not shipped, or over edits made after the last snap; the
//!   queue ships, and a lease that moved to a new epoch meanwhile gets the disk captured afresh.

use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

use sealant_capture::engine::Pickup;
use sealant_capture::manifest::BulkState;
use sealant_capture::sink::{BlobSource, PutOutcome, SinkError};
use sealant_capture::{
    BlobSink, CadenceRunner, CaptureConfig, CaptureEngine, CaptureKind, Class, InMemoryRegistrar,
    LocalDir, MaterializeClass, MaterializeTargets, Materializer, Registrar, SnapRequest,
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
    fs::write(root.join(".gitignore"), ".env\nnode_modules/\ndist/\n").unwrap();
    fs::write(root.join("src/lib.rs"), "pub fn f() {}\n").unwrap();
    git(root, &["add", "-A"]);
    git(root, &["commit", "-q", "-m", "one"]);
    fs::write(root.join(".env"), "SECRET=1\n").unwrap();
    for p in 0..packages {
        let dir = root.join(format!("node_modules/pkg{p}/lib"));
        fs::create_dir_all(&dir).unwrap();
        for f in 0..4 {
            fs::write(
                dir.join(format!("m{f}.js")),
                format!("module.exports = [{p}, {f}];\n").repeat(3),
            )
            .unwrap();
        }
    }
    fs::create_dir_all(root.join("dist")).unwrap();
    fs::write(root.join("dist/app.js"), "console.log('built');\n").unwrap();
}

/// Every file and symlink under `dir` with its bytes (or link text); `.sealantd` left out.
fn files(dir: &Path) -> Vec<(String, Vec<u8>)> {
    let mut out: Vec<(String, Vec<u8>)> = walkdir::WalkDir::new(dir)
        .into_iter()
        .filter_entry(|e| e.file_name() != ".sealantd" && e.file_name() != ".git")
        .map(Result::unwrap)
        .filter(|e| !e.file_type().is_dir())
        .map(|e| {
            let bytes = if e.path_is_symlink() {
                fs::read_link(e.path())
                    .unwrap()
                    .to_string_lossy()
                    .into_owned()
                    .into_bytes()
            } else {
                fs::read(e.path()).unwrap()
            };
            (
                e.path().strip_prefix(dir).unwrap().display().to_string(),
                bytes,
            )
        })
        .collect();
    out.sort();
    out
}

fn snap(engine: &mut CaptureEngine, kind: CaptureKind, class: Class, seq: u64) {
    engine.snap(SnapRequest { kind, class, seq }).unwrap();
}

fn ship(engine: &CaptureEngine, sink: &Arc<LocalDir>, registrar: &Arc<InMemoryRegistrar>) -> usize {
    let sink: Arc<dyn BlobSink> = sink.clone();
    let registrar: Arc<dyn Registrar> = registrar.clone();
    engine.shipper(sink, registrar).ship_pending().unwrap()
}

fn restore(sink: &LocalDir, registrar: &InMemoryRegistrar, into: &Path) {
    Materializer::new(sink, MaterializeTargets::new(into, None))
        .materialize(&registrar.head().unwrap().manifest, MaterializeClass::All)
        .unwrap();
}

struct Fixture {
    _tmp: tempfile::TempDir,
    base: PathBuf,
    root: PathBuf,
    store: Arc<LocalDir>,
}

fn fixture(packages: usize) -> Fixture {
    let tmp = tempfile::tempdir().unwrap();
    let base = tmp.path().to_path_buf();
    let root = base.join("ws");
    workspace(&root, packages);
    Fixture {
        store: Arc::new(LocalDir::new(&base.join("store")).unwrap()),
        _tmp: tmp,
        base,
        root,
    }
}

/// A head whose bulk section is `"pending"` (only the small class ever registered) restores the
/// small class and leaves the bulk directories on the disk exactly as they are — never swept as
/// "not in the plan" — and the engine's next bulk snap captures them, so the head after it
/// restores them byte for byte.
#[test]
fn a_pending_bulk_section_is_never_swept_and_is_captured_next() {
    let fx = fixture(10);
    let registrar = Arc::new(InMemoryRegistrar::new("wt", 1, None));
    let mut engine = CaptureEngine::open(CaptureConfig::new("wt", 1, &fx.root), None).unwrap();
    snap(&mut engine, CaptureKind::Auto, Class::Small, 1);
    ship(&engine, &fx.store, &registrar);
    let head = registrar.head().unwrap();
    assert_eq!(head.manifest.sections.bulk, BulkState::pending());

    // Another disk that already holds a dependency tree (a standby's, an install's).
    let other = fx.base.join("other");
    fs::create_dir_all(other.join("node_modules/local/lib")).unwrap();
    fs::write(other.join("node_modules/local/lib/x.js"), "kept\n").unwrap();
    fs::create_dir_all(other.join("dist")).unwrap();
    fs::write(other.join("dist/out.js"), "kept too\n").unwrap();
    let before = files(&other.join("node_modules"));
    restore(&fx.store, &registrar, &other);
    assert_eq!(files(&other.join("node_modules")), before, "not swept");
    assert_eq!(
        fs::read_to_string(other.join("dist/out.js")).unwrap(),
        "kept too\n"
    );
    assert_eq!(
        fs::read_to_string(other.join(".env")).unwrap(),
        "SECRET=1\n"
    );

    // The bulk class is captured at its next snap, and restores whole.
    snap(&mut engine, CaptureKind::Auto, Class::Bulk, 2);
    ship(&engine, &fx.store, &registrar);
    assert!(matches!(
        registrar.head().unwrap().manifest.sections.bulk,
        BulkState::Ready(_)
    ));
    let fresh = fx.base.join("fresh");
    restore(&fx.store, &registrar, &fresh);
    assert_eq!(
        files(&fresh.join("node_modules")),
        files(&fx.root.join("node_modules"))
    );
    assert_eq!(files(&fresh.join("dist")), files(&fx.root.join("dist")));
}

/// A directory store that spends `delay` on every PUT: a bulk upload that outlasts any
/// deadline a caller would give a flush.
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

/// A `final` flush snaps the bulk class — the dependency tree was never snapped here, the bulk
/// clocks had not fired — and, given no deadline, does not return before the bulk capture is
/// registered: the disk goes with the executor.
#[test]
fn a_final_flush_without_a_deadline_ships_the_bulk_class() {
    let fx = fixture(60);
    let registrar = Arc::new(InMemoryRegistrar::new("wt", 1, None));
    let slow = Arc::new(Slow {
        inner: fx.store.clone(),
        delay: Duration::from_millis(20),
        puts: AtomicU64::new(0),
    });
    let mut config = CaptureConfig::new("wt", 1, &fx.root);
    // One object per directory: well over a hundred objects to upload.
    config.dir_format = sealant_capture::manifest::DirFormat::Objects;
    config.uploads_in_flight = 1;
    let engine = CaptureEngine::open(config, None).unwrap();
    let sink: Arc<dyn BlobSink> = slow.clone();
    let dyn_registrar: Arc<dyn Registrar> = registrar.clone();
    let shipper = Arc::new(engine.shipper(sink, dyn_registrar));
    let runner = CadenceRunner::new(engine, shipper);

    let start = Instant::now();
    runner.flush(CaptureKind::Final, None).unwrap();
    let took = start.elapsed();
    let puts = slow.puts.load(Ordering::SeqCst);
    eprintln!("final flush: {puts} PUTs in {took:?}");
    assert!(puts > 100, "{puts}");
    assert!(
        runner.staging().pending().unwrap().is_empty(),
        "nothing left staged"
    );
    let head = registrar.head().unwrap();
    assert!(matches!(head.manifest.sections.bulk, BulkState::Ready(_)));
    let fresh = fx.base.join("fresh");
    restore(&fx.store, &registrar, &fresh);
    assert_eq!(
        files(&fresh.join("node_modules")),
        files(&fx.root.join("node_modules"))
    );
    runner.stop();
}

/// A `final` flush whose captures the registrar refuses for the byte quota waits for them
/// instead of returning with them staged: once the budget allows, they register (the bulk
/// capture among them) and the flush returns.
#[test]
fn a_final_flush_waits_for_a_held_bulk_capture() {
    let fx = fixture(20);
    let registrar = Arc::new(InMemoryRegistrar::new("wt", 1, None));
    let engine = CaptureEngine::open(CaptureConfig::new("wt", 1, &fx.root), None).unwrap();
    let sink: Arc<dyn BlobSink> = fx.store.clone();
    let dyn_registrar: Arc<dyn Registrar> = registrar.clone();
    let shipper = Arc::new(
        engine
            .shipper(sink.clone(), dyn_registrar)
            .with_hold_backoff(Duration::from_millis(50), Duration::from_millis(100)),
    );
    let runner = CadenceRunner::new(engine, shipper.clone());
    runner.snap(CaptureKind::Auto).unwrap();
    runner.ship(Duration::from_secs(10)).unwrap();
    registrar.set_byte_quota(Some(registrar.used_bytes() + 512), Some(sink));

    let lift = {
        let registrar = registrar.clone();
        let shipper = shipper.clone();
        std::thread::spawn(move || {
            let start = Instant::now();
            while shipper.held().is_empty() {
                assert!(start.elapsed() < Duration::from_secs(20), "never refused");
                std::thread::sleep(Duration::from_millis(10));
            }
            std::thread::sleep(Duration::from_millis(300));
            registrar.set_byte_quota(None, None);
            Instant::now()
        })
    };
    runner.flush(CaptureKind::Final, None).unwrap();
    let returned = Instant::now();
    let lifted = lift.join().unwrap();
    assert!(
        returned >= lifted,
        "the flush returned before the budget allowed the bulk capture"
    );
    assert!(runner.staging().pending().unwrap().is_empty());
    assert!(matches!(
        registrar.head().unwrap().manifest.sections.bulk,
        BulkState::Ready(_)
    ));
    runner.stop();
}

/// A daemon that restarts on its own disk finds captures staged and not shipped, and edits made
/// after its last snap. The boot does not materialize the head over them ([`Pickup::Resume`]):
/// the engine continues from the newest queued capture, the queue ships, the next snaps capture
/// the edits, and the head restores all of it.
#[test]
fn a_restart_on_the_same_disk_resumes_the_queue_and_keeps_the_edits() {
    let fx = fixture(10);
    let registrar = Arc::new(InMemoryRegistrar::new("wt", 1, None));
    let config = || CaptureConfig::new("wt", 1, &fx.root);
    {
        let mut engine = CaptureEngine::open(config(), None).unwrap();
        snap(&mut engine, CaptureKind::Auto, Class::Small, 1);
        snap(&mut engine, CaptureKind::Auto, Class::Bulk, 2);
        ship(&engine, &fx.store, &registrar);
        // Staged, never shipped: an edit, and a change to the dependency tree.
        fs::write(fx.root.join("src/lib.rs"), "pub fn f() { staged() }\n").unwrap();
        snap(&mut engine, CaptureKind::Turn, Class::Small, 3);
        fs::write(fx.root.join("node_modules/pkg3/lib/m1.js"), "staged bulk\n").unwrap();
        snap(&mut engine, CaptureKind::Auto, Class::Bulk, 4);
        assert_eq!(engine.staging().pending().unwrap().len(), 2);
    } // The daemon dies.
    // Edits after the last snap, never seen by a watcher.
    fs::write(fx.root.join(".env"), "SECRET=after the last snap\n").unwrap();
    fs::write(
        fx.root.join("node_modules/pkg4/lib/new.js"),
        "added after\n",
    )
    .unwrap();
    let disk = files(&fx.root);

    // The boot, again: the head is the capture before the staged ones.
    let head = registrar.head().unwrap();
    assert_eq!(head.n, 1);
    assert_eq!(
        CaptureEngine::pickup(&config(), Some(&head.capture_id)).unwrap(),
        Pickup::Resume {
            queued: 2,
            epoch_changed: false
        }
    );
    let encoded = Materializer::new(fx.store.as_ref(), MaterializeTargets::new(&fx.root, None))
        .fetch_manifest(&head.manifest_key, &head.capture_id)
        .unwrap();
    let mut engine = CaptureEngine::open(config(), Some(encoded)).unwrap();
    assert_eq!(
        engine.previous().unwrap().manifest.n,
        3,
        "continues from the queue"
    );
    assert_eq!(files(&fx.root), disk, "the disk is left as it was");
    assert_eq!(ship(&engine, &fx.store, &registrar), 2, "the queue ships");
    snap(&mut engine, CaptureKind::Auto, Class::Small, 5);
    snap(&mut engine, CaptureKind::Auto, Class::Bulk, 6);
    assert_eq!(ship(&engine, &fx.store, &registrar), 2);

    let fresh = fx.base.join("fresh");
    restore(&fx.store, &registrar, &fresh);
    assert_eq!(files(&fresh), disk, "every edit, staged or not, comes back");
}

/// The lease lapsed while the daemon was down and the plan names a new epoch: the captures
/// staged under the old one can never register, but the disk holds everything they held and
/// more. It is resumed all the same, and the next snaps capture it whole under the new epoch.
#[test]
fn a_restart_under_a_new_epoch_captures_the_disk_afresh() {
    let fx = fixture(10);
    let registrar = Arc::new(InMemoryRegistrar::new("wt", 1, None));
    {
        let mut engine = CaptureEngine::open(CaptureConfig::new("wt", 1, &fx.root), None).unwrap();
        snap(&mut engine, CaptureKind::Auto, Class::Small, 1);
        ship(&engine, &fx.store, &registrar);
        fs::write(fx.root.join("src/lib.rs"), "pub fn f() { staged() }\n").unwrap();
        snap(&mut engine, CaptureKind::Turn, Class::Small, 2);
        snap(&mut engine, CaptureKind::Auto, Class::Bulk, 3);
    }
    fs::write(fx.root.join(".env"), "SECRET=after\n").unwrap();
    let disk = files(&fx.root);
    registrar.set_live_epoch(2);
    let head = registrar.head().unwrap();
    let config = CaptureConfig::new("wt", 2, &fx.root);
    assert_eq!(
        CaptureEngine::pickup(&config, Some(&head.capture_id)).unwrap(),
        Pickup::Resume {
            queued: 2,
            epoch_changed: true
        }
    );
    let encoded = Materializer::new(fx.store.as_ref(), MaterializeTargets::new(&fx.root, None))
        .fetch_manifest(&head.manifest_key, &head.capture_id)
        .unwrap();
    let mut engine = CaptureEngine::open(config, Some(encoded)).unwrap();
    assert_eq!(engine.previous().unwrap().capture_id, head.capture_id);
    snap(&mut engine, CaptureKind::Auto, Class::Small, 4);
    snap(&mut engine, CaptureKind::Auto, Class::Bulk, 5);
    ship(&engine, &fx.store, &registrar);
    let head = registrar.head().unwrap();
    assert_eq!(head.manifest.epoch, 2);
    let fresh = fx.base.join("fresh");
    restore(&fx.store, &registrar, &fresh);
    assert_eq!(files(&fresh), disk);
}

/// A disk whose staging does not continue the chain — the chain moved on under another
/// executor, or the staging names another worktree, or there is none — is materialized over.
#[test]
fn a_disk_that_does_not_continue_the_chain_is_materialized_over() {
    let fx = fixture(2);
    let registrar = Arc::new(InMemoryRegistrar::new("wt", 1, None));
    let config = CaptureConfig::new("wt", 1, &fx.root);
    assert_eq!(
        CaptureEngine::pickup(&config, None).unwrap(),
        Pickup::Materialize,
        "no staging"
    );
    let mut engine = CaptureEngine::open(CaptureConfig::new("wt", 1, &fx.root), None).unwrap();
    snap(&mut engine, CaptureKind::Auto, Class::Small, 1);
    ship(&engine, &fx.store, &registrar);
    let head = registrar.head().unwrap();
    assert!(matches!(
        CaptureEngine::pickup(&config, Some(&head.capture_id)).unwrap(),
        Pickup::Resume { queued: 0, .. }
    ));
    assert_eq!(
        CaptureEngine::pickup(&config, Some(&"f".repeat(64))).unwrap(),
        Pickup::Materialize,
        "the chain moved on without this disk"
    );
    assert_eq!(
        CaptureEngine::pickup(
            &CaptureConfig::new("another", 1, &fx.root),
            Some(&head.capture_id)
        )
        .unwrap(),
        Pickup::Materialize,
        "another worktree's staging"
    );
}
