//! A small capture never waits for a bulk capture's upload. The shape of alpha session 7d37da6a
//! (2026-09-27): the session's `pnpm install` left ≈ 800 MB / 20k objects of `node_modules`,
//! and the bulk capture that carried them took the shipper twenty minutes. Every small capture
//! staged after it named it as its parent and waited behind it, `capture.flush` timed out or
//! answered `pending 5, headN 16`, and every checkpoint Mend derived pointed at a capture from
//! before the agent's edits (`0 files · +0 −0`). A flush that ran beside the ship worker raced it
//! for PUT URLs until `upload.urls` answered 429, which surfaced as `no url for …/trees/<sha>`.
//!
//! Scaled down, same shape: many small ignored files behind a sink that takes its time per
//! object, and an edit to a tracked file once the bulk upload has started. The bulk captures
//! here are written for a registrar that does not read dir packs (one object per directory,
//! `DirFormat::Objects`): with dir packs the same tree is a handful of objects
//! (`tests/dir_packs.rs`), and the many-object upload is what these tests need.

mod common;

use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::Arc;
use std::sync::atomic::{AtomicU32, AtomicU64, Ordering};
use std::time::{Duration, Instant};

use sealant_capture::manifest::{BulkState, DirFormat};
use sealant_capture::registrar::{
    ChangeSummaryRequest, HeartbeatRequest, HeartbeatResponse, PlanGetRequest, PlanGetResponse,
    RegisterRequest, RegisterResponse, RegistrarMinter, UploadCompleteRequest,
    UploadCompleteResponse, UploadUrlsRequest, UploadUrlsResponse,
};
use sealant_capture::ship::RetryPolicy;
use sealant_capture::sink::{BlobSource, PutOutcome, SinkError};
use sealant_capture::{
    BlobSink, Cadence, CadenceRunner, CaptureConfig, CaptureEngine, CaptureKind, Class,
    InMemoryRegistrar, LocalDir, MaterializeClass, MaterializeTargets, Materializer, PresignedHttp,
    Registrar, RegistrarError, SnapRequest,
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

/// A repository with a tracked source file and an ignored `node_modules/` of `packages`
/// packages holding `files` files each: many small files, many dir objects.
fn workspace(root: &Path, packages: usize, files: usize) {
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
        for f in 0..files {
            fs::write(
                dir.join(format!("m{f}.js")),
                format!("module.exports = [{p}, {f}];\n").repeat(4),
            )
            .unwrap();
        }
    }
}

/// A sink that takes `delay` per object stored: the bucket at the far end of a slow link.
struct Slow {
    inner: Arc<dyn BlobSink>,
    delay: Duration,
    puts: AtomicU64,
}

impl Slow {
    fn new(inner: Arc<dyn BlobSink>, delay: Duration) -> Arc<Self> {
        Arc::new(Self {
            inner,
            delay,
            puts: AtomicU64::new(0),
        })
    }

    fn puts(&self) -> u64 {
        self.puts.load(Ordering::SeqCst)
    }
}

impl BlobSink for Slow {
    fn put_if_absent(&self, key: &str, source: BlobSource<'_>) -> Result<PutOutcome, SinkError> {
        std::thread::sleep(self.delay);
        self.puts.fetch_add(1, Ordering::SeqCst);
        self.inner.put_if_absent(key, source)
    }

    fn put_multipart(
        &self,
        key: &str,
        file: &Path,
        part_size: u64,
        parts_in_flight: usize,
    ) -> Result<PutOutcome, SinkError> {
        std::thread::sleep(self.delay);
        self.puts.fetch_add(1, Ordering::SeqCst);
        self.inner
            .put_multipart(key, file, part_size, parts_in_flight)
    }

    fn prefetch_put(&self, keys: &[(String, u64)]) -> Result<(), SinkError> {
        self.inner.prefetch_put(keys)
    }

    fn get(&self, key: &str) -> Result<Vec<u8>, SinkError> {
        self.inner.get(key)
    }

    fn exists(&self, key: &str) -> Result<bool, SinkError> {
        self.inner.exists(key)
    }

    fn helper_cpu(&self) -> Duration {
        self.inner.helper_cpu()
    }
}

fn snap(engine: &mut CaptureEngine, class: Class, seq: u64) -> sealant_capture::StagedCapture {
    engine
        .snap(SnapRequest {
            kind: CaptureKind::Auto,
            class,
            seq,
        })
        .unwrap()
}

fn wait_until(what: &str, timeout: Duration, mut done: impl FnMut() -> bool) {
    let start = Instant::now();
    while !done() {
        assert!(start.elapsed() < timeout, "{what}: not within {timeout:?}");
        std::thread::sleep(Duration::from_millis(10));
    }
}

/// Only forced snaps: the scheduled clocks never fire during the test.
fn quiet_cadence() -> Cadence {
    Cadence {
        quiet: Duration::from_secs(600),
        max_interval: Duration::from_secs(600),
        bulk_quiet: Duration::from_secs(600),
        bulk_max_interval: Duration::from_secs(600),
        ..Cadence::default()
    }
}

struct Session {
    _tmp: tempfile::TempDir,
    base: PathBuf,
    root: PathBuf,
    store: Arc<LocalDir>,
    slow: Arc<Slow>,
    registrar: Arc<InMemoryRegistrar>,
}

impl Session {
    fn materialize_head(&self, into: &str) -> PathBuf {
        let head = self.registrar.head().unwrap();
        let restore = self.base.join(into);
        Materializer::new(self.store.as_ref(), MaterializeTargets::new(&restore, None))
            .materialize(&head.manifest, MaterializeClass::All)
            .unwrap();
        restore
    }
}

/// The session: capture 0 registered, then a bulk capture of the dependency tree staged and the
/// ship worker started on it behind a sink that spends `delay` on every object.
fn session(delay: Duration) -> (Session, CadenceRunner, u64) {
    let tmp = tempfile::tempdir().unwrap();
    let base = tmp.path().to_path_buf();
    let root = base.join("ws");
    workspace(&root, 80, 5);
    let store = Arc::new(LocalDir::new(&base.join("store")).unwrap());
    let slow = Slow::new(store.clone(), delay);
    let registrar = Arc::new(InMemoryRegistrar::new("wt", 1, None));
    let mut config = CaptureConfig::new("wt", 1, &root);
    config.cadence = quiet_cadence();
    // The shipper's duty cycle is not what this test measures.
    config.cpu_fraction = 1.0;
    config.dir_format = DirFormat::Objects;
    let mut engine = CaptureEngine::open(config, None).unwrap();
    let sink: Arc<dyn BlobSink> = slow.clone();
    let dyn_registrar: Arc<dyn Registrar> = registrar.clone();
    let shipper = Arc::new(engine.shipper(sink, dyn_registrar));

    snap(&mut engine, Class::Small, 1);
    assert_eq!(shipper.ship_pending().unwrap(), 1);
    let bulk = snap(&mut engine, Class::Bulk, 2);
    assert_eq!(bulk.n, 1);
    let bulk_objects = engine.staging().pending().unwrap()[0].uploads.len() as u64;
    assert!(bulk_objects > 150, "{bulk_objects} bulk objects");

    let runner = CadenceRunner::new(engine, shipper);
    let before = slow.puts();
    runner.start(None);
    // The worker is on the bulk capture.
    wait_until("the bulk upload starts", Duration::from_secs(10), || {
        slow.puts() >= before + 5
    });
    (
        Session {
            _tmp: tmp,
            base,
            root,
            store,
            slow,
            registrar,
        },
        runner,
        bulk_objects,
    )
}

fn bulk_still_uploading(runner: &CadenceRunner) -> bool {
    let pending = runner.staging().pending().unwrap();
    pending.len() == 1 && pending[0].class == Some(Class::Bulk)
}

/// A turn-boundary snap taken while the bulk capture uploads registers within a second or two
/// (the worker stops between objects, ships it, and resumes the bulk upload), and a flush
/// returns once its capture is registered — both with the bulk capture still uploading. The
/// bulk capture then registers on top of them, and the head carries the edit and the tree.
#[test]
fn a_small_capture_registers_while_a_bulk_capture_uploads() {
    // ≈ 170 objects at 250 ms each, eight in flight: about 5 s of bulk upload.
    let (s, runner, bulk_objects) = session(Duration::from_millis(250));

    // The agent edits a tracked file; the turn boundary snaps.
    fs::write(s.root.join("src/lib.rs"), "pub fn f() { edited() }\n").unwrap();
    let t0 = Instant::now();
    let turn = runner.snap(CaptureKind::Turn).unwrap();
    assert!(!turn.unchanged);
    wait_until(
        "the turn capture registers ahead of the bulk capture",
        Duration::from_secs(5),
        || {
            s.registrar
                .head()
                .is_some_and(|h| h.capture_id == turn.manifest.capture_id)
        },
    );
    let registered_in = t0.elapsed();
    eprintln!("turn capture registered in {registered_in:?} during the bulk upload");
    assert!(
        registered_in < Duration::from_secs(3),
        "not behind the bulk upload: {registered_in:?}"
    );
    assert_eq!(turn.n, 1, "the turn capture took the bulk capture's slot");
    assert_eq!(turn.manifest.manifest.sections.bulk, BulkState::pending());
    assert!(
        bulk_still_uploading(&runner),
        "the bulk capture is still uploading ({} of {bulk_objects} objects)",
        s.slow.puts()
    );

    // A checkpoint's flush: back once its capture is registered, well inside Mend's 20 s.
    fs::write(s.root.join("src/lib.rs"), "pub fn f() { edited_twice() }\n").unwrap();
    let t1 = Instant::now();
    runner
        .flush(CaptureKind::Suspend, Some(Duration::from_secs(20)))
        .unwrap();
    let flushed_in = t1.elapsed();
    eprintln!("flush returned in {flushed_in:?} during the bulk upload");
    assert!(
        flushed_in < Duration::from_secs(3),
        "the flush does not wait for the bulk upload: {flushed_in:?}"
    );
    let head = s.registrar.head().unwrap();
    assert_eq!(head.n, 2);
    assert_eq!(head.manifest.kind, CaptureKind::Suspend);
    assert_eq!(head.manifest.sections.bulk, BulkState::pending());
    assert!(
        bulk_still_uploading(&runner),
        "flush left the bulk capture to the worker"
    );
    let queued = runner.staging().pending().unwrap();
    assert_eq!(queued[0].n, 3);
    assert_eq!(
        queued[0].register.parent.as_deref(),
        Some(head.capture_id.as_str())
    );

    // What a change or a diff reads is in the store: the edit, and no dependency tree swept or
    // restored (the head's bulk section is "pending").
    let restore = s.materialize_head("restore-small");
    assert_eq!(
        fs::read_to_string(restore.join("src/lib.rs")).unwrap(),
        "pub fn f() { edited_twice() }\n"
    );
    assert!(!restore.join("node_modules").exists());

    // The bulk capture registers on top.
    wait_until(
        "the bulk capture registers",
        Duration::from_secs(120),
        || s.registrar.chain().len() == 4,
    );
    let head = s.registrar.head().unwrap();
    assert!(matches!(head.manifest.sections.bulk, BulkState::Ready(_)));
    let restore = s.materialize_head("restore-all");
    assert_eq!(
        fs::read_to_string(restore.join("src/lib.rs")).unwrap(),
        "pub fn f() { edited_twice() }\n"
    );
    assert!(restore.join("node_modules/pkg79/lib/m4.js").exists());
    runner.stop();
}

/// Counts `upload.urls` calls, and answers the first `throttle` of them as the registrar's call
/// quota does (429).
struct Throttled {
    inner: Arc<InMemoryRegistrar>,
    throttle: AtomicU32,
    calls: AtomicU64,
}

impl Registrar for Throttled {
    fn plan_get(&self, req: &PlanGetRequest) -> Result<PlanGetResponse, RegistrarError> {
        self.inner.plan_get(req)
    }

    fn upload_urls(&self, req: &UploadUrlsRequest) -> Result<UploadUrlsResponse, RegistrarError> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        if self
            .throttle
            .fetch_update(Ordering::SeqCst, Ordering::SeqCst, |n| n.checked_sub(1))
            .is_ok()
        {
            // What `HttpRegistrar` makes of Mend's 429 `quota-exceeded`.
            return Err(RegistrarError::Transport("upload.urls: http 429".into()));
        }
        self.inner.upload_urls(req)
    }

    fn upload_complete(
        &self,
        req: &UploadCompleteRequest,
    ) -> Result<UploadCompleteResponse, RegistrarError> {
        self.inner.upload_complete(req)
    }

    fn capture_register(&self, req: &RegisterRequest) -> Result<RegisterResponse, RegistrarError> {
        self.inner.capture_register(req)
    }

    fn lease_heartbeat(&self, req: &HeartbeatRequest) -> Result<HeartbeatResponse, RegistrarError> {
        self.inner.lease_heartbeat(req)
    }

    fn change_summary(&self, req: &ChangeSummaryRequest) -> Result<(), RegistrarError> {
        self.inner.change_summary(req)
    }
}

/// A presigned sink over a counting registrar, slowed by `delay` per object.
fn presigned(
    server: &common::Server,
    delay: Duration,
    throttle: u32,
) -> (Arc<Throttled>, Arc<Slow>) {
    let inner = Arc::new(InMemoryRegistrar::new("wt", 1, Some(server.base.clone())));
    let registrar = Arc::new(Throttled {
        inner,
        throttle: AtomicU32::new(throttle),
        calls: AtomicU64::new(0),
    });
    let dyn_registrar: Arc<dyn Registrar> = registrar.clone();
    let minter = Arc::new(RegistrarMinter::new(
        dyn_registrar,
        "wt",
        1,
        Default::default(),
    ));
    let http: Arc<dyn BlobSink> = Arc::new(PresignedHttp::new(
        Box::new(minter),
        Duration::from_secs(30),
    ));
    (registrar, Slow::new(http, delay))
}

/// The `no url for …/trees/<sha>` refusal. A flush ran its pass beside the worker's, over the
/// same bulk capture: each pass took the PUT URLs the other had minted, the one that lost the
/// race minted one key per `upload.urls` call, and the registrar's call quota (600 an hour at
/// Mend) answered 429 — which the minter reported as "no url", a failure the shipper does not
/// retry. One pass runs at a time now, and the flush picks up the URLs the worker minted.
#[test]
fn a_flush_beside_the_worker_does_not_multiply_url_mints() {
    let server = common::serve();
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path().join("ws");
    workspace(&root, 80, 5);
    let (registrar, slow) = presigned(&server, Duration::from_millis(15), 0);
    let mut config = CaptureConfig::new("wt", 1, &root);
    config.cpu_fraction = 1.0;
    config.dir_format = DirFormat::Objects;
    let mut engine = CaptureEngine::open(config, None).unwrap();
    let sink: Arc<dyn BlobSink> = slow.clone();
    let dyn_registrar: Arc<dyn Registrar> = registrar.clone();
    let shipper = Arc::new(engine.shipper(sink, dyn_registrar));

    snap(&mut engine, Class::Small, 1);
    assert_eq!(shipper.ship_pending().unwrap(), 1);
    let small_calls = registrar.calls.load(Ordering::SeqCst);
    let bulk = snap(&mut engine, Class::Bulk, 2);
    let objects = engine.staging().pending().unwrap()[0].uploads.len();
    assert!(objects > 150 && objects < sealant_capture::ship::PREFETCH_BATCH);

    // The worker's pass is on the bulk capture when a flush arrives.
    let before = slow.puts();
    let worker = {
        let shipper = Arc::clone(&shipper);
        std::thread::spawn(move || shipper.ship_pending())
    };
    wait_until("the bulk upload starts", Duration::from_secs(10), || {
        slow.puts() >= before + 5
    });
    let flushed = shipper.flush(Duration::from_secs(60)).unwrap();
    let from_worker = worker.join().unwrap().unwrap();
    let bulk_calls = registrar.calls.load(Ordering::SeqCst) - small_calls;
    eprintln!("{objects} bulk objects shipped with {bulk_calls} upload.urls call(s)");
    assert_eq!(
        bulk_calls, 1,
        "one batch, minted once, whoever of the two passes uploads it"
    );
    assert_eq!(flushed + from_worker, 1, "the bulk capture registered once");
    let head = registrar.inner.head().unwrap();
    assert_eq!(head.capture_id, bulk.manifest.capture_id);
    assert_eq!(
        slow.puts() - before,
        objects as u64,
        "every object went up once"
    );
}

/// A 429 on `upload.urls` is the registrar's call quota: transient. The batch mint is retried
/// with backoff and the pass goes on, instead of failing on `no url for <key>`.
#[test]
fn a_throttled_url_mint_is_retried_not_reported_as_no_url() {
    let server = common::serve();
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path().join("ws");
    workspace(&root, 2, 2);
    let (registrar, slow) = presigned(&server, Duration::ZERO, 2);
    let mut engine = CaptureEngine::open(CaptureConfig::new("wt", 1, &root), None).unwrap();
    let sink: Arc<dyn BlobSink> = slow.clone();
    let dyn_registrar: Arc<dyn Registrar> = registrar.clone();
    let shipper = engine
        .shipper(sink, dyn_registrar)
        .with_retry(RetryPolicy {
            attempts: 5,
            backoff: Duration::from_millis(1),
            max_backoff: Duration::from_millis(5),
        })
        .with_outage_backoff(Duration::from_millis(200), Duration::from_millis(200));
    let small = snap(&mut engine, Class::Small, 1);
    assert_eq!(shipper.ship_pending().unwrap(), 1);
    assert_eq!(
        registrar.inner.head().unwrap().capture_id,
        small.manifest.capture_id
    );
    assert_eq!(
        registrar.calls.load(Ordering::SeqCst),
        3,
        "two throttled calls, then the batch"
    );
    assert!(shipper.status.snapshot().failures >= 2);

    // Throttled for longer than a pass retries: the pass fails as a transport error the next
    // pass retries, never as a missing URL.
    registrar.throttle.store(100, Ordering::SeqCst);
    fs::write(root.join("src/lib.rs"), "pub fn f() { g() }\n").unwrap();
    snap(&mut engine, Class::Small, 2);
    match shipper.ship_pending() {
        Err(sealant_capture::ship::ShipError::Upload { source, .. }) => {
            assert!(source.is_retryable(), "{source}");
            assert!(!matches!(source, SinkError::NoUrl { .. }), "{source}");
        }
        other => panic!("expected a retryable upload error: {other:?}"),
    }
    registrar.throttle.store(0, Ordering::SeqCst);
    // The next pass waits out the backoff after a failed one (it does not go straight back to
    // the registrar), then ships.
    let calls = registrar.calls.load(Ordering::SeqCst);
    assert_eq!(shipper.ship_pending().unwrap(), 0, "within the backoff");
    assert_eq!(
        registrar.calls.load(Ordering::SeqCst),
        calls,
        "no call meanwhile"
    );
    std::thread::sleep(Duration::from_millis(250));
    assert_eq!(shipper.ship_pending().unwrap(), 1);
}
