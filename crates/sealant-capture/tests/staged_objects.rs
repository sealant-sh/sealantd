//! Staged objects stay until every capture that lists them has shipped, and the shipper mints
//! PUT URLs a batch at a time. The shape of the first real cluster session: a bulk capture
//! (774 MB, 134k files) sat in the queue for minutes while the cadence kept taking unchanged
//! small snaps, each of which deleted the dir objects the bulk entry had yet to upload; every
//! ship pass then failed on `upload …/trees/<sha>: no GET url in plan` (the file was gone, and
//! the existence probe needs a GET URL the plan never carries for a new key).

mod common;

use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use sealant_capture::manifest::BulkState;
use sealant_capture::registrar::{CompletedPart, MultipartUrls, RegistrarMinter};
use sealant_capture::ship::{PREFETCH_BATCH, ShipError};
use sealant_capture::sink::{Completed, SinkError, UrlMinter};
use sealant_capture::{
    BlobSink, CaptureConfig, CaptureEngine, CaptureKind, Class, InMemoryRegistrar, LocalDir,
    MaterializeClass, MaterializeTargets, Materializer, PresignedHttp, Registrar, SnapRequest,
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

struct Fixture {
    _tmp: tempfile::TempDir,
    base: PathBuf,
    root: PathBuf,
    home: PathBuf,
}

/// A repository with an ignored file, a harness home and `bulk_dirs` bulk directories of
/// `files_per_dir` files each.
fn fixture(bulk_dirs: usize, files_per_dir: usize) -> Fixture {
    let tmp = tempfile::tempdir().unwrap();
    let base = tmp.path().to_path_buf();
    let root = base.join("ws");
    let home = base.join("home");
    fs::create_dir_all(root.join("src")).unwrap();
    fs::create_dir_all(home.join(".claude")).unwrap();
    git(&root, &["init", "-q", "-b", "main"]);
    git(&root, &["config", "user.email", "t@t"]);
    git(&root, &["config", "user.name", "t"]);
    fs::write(root.join(".gitignore"), ".env\nnode_modules/\n").unwrap();
    fs::write(root.join("src/lib.rs"), "pub fn f() {}\n").unwrap();
    git(&root, &["add", "-A"]);
    git(&root, &["commit", "-q", "-m", "one"]);
    fs::write(root.join(".env"), "SECRET=1\n").unwrap();
    fs::write(home.join("transcript.jsonl"), "{\"seq\":0}\n").unwrap();
    fs::write(home.join(".claude/settings.json"), "{}").unwrap();
    for d in 0..bulk_dirs {
        let dir = root.join(format!("node_modules/pkg{d}/lib"));
        fs::create_dir_all(&dir).unwrap();
        for f in 0..files_per_dir {
            fs::write(
                dir.join(format!("m{f}.js")),
                format!("module.exports = [{d}, {f}];\n").repeat(8),
            )
            .unwrap();
        }
    }
    Fixture {
        _tmp: tmp,
        base,
        root,
        home,
    }
}

impl Fixture {
    fn config(&self) -> CaptureConfig {
        let mut c = CaptureConfig::new("wt", 1, &self.root);
        c.harness_home = Some(self.home.clone());
        c
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

/// An unchanged `auto` snap lists the dir objects a queued capture has not uploaded yet (they
/// are not uploaded, so the build lists them again) and must leave their bytes in staging.
#[test]
fn an_unchanged_snap_keeps_the_objects_a_queued_capture_lists() {
    let fx = fixture(3, 2);
    let sink = Arc::new(LocalDir::new(&fx.base.join("store")).unwrap());
    let registrar = Arc::new(InMemoryRegistrar::new("wt", 1, None));
    let mut engine = CaptureEngine::open(fx.config(), None).unwrap();

    let first = snap(&mut engine, Class::Small, 1);
    assert!(!first.unchanged);
    let staging = engine.staging();
    let queued = staging.pending().unwrap();
    assert_eq!(queued.len(), 1);
    let trees: Vec<String> = queued[0]
        .uploads
        .iter()
        .filter(|u| u.file.starts_with("tree-"))
        .map(|u| u.file.clone())
        .collect();
    assert!(trees.len() >= 3, "{trees:?}");

    // The shipper has not run (a large upload ahead in the real queue); the cadence snaps again.
    let again = snap(&mut engine, Class::Small, 2);
    assert!(again.unchanged);
    assert_eq!(again.n, first.n);
    for file in &trees {
        assert!(
            staging.objects_dir().join(file).exists(),
            "{file} is still listed by capture {} and must stay staged",
            first.n
        );
    }
    let dyn_registrar: Arc<dyn Registrar> = registrar.clone();
    let shipper = engine.shipper(sink.clone(), dyn_registrar);
    assert_eq!(shipper.ship_pending().unwrap(), 1);
    assert!(staging.pending().unwrap().is_empty());
    // Objects nobody lists any more are swept after the ack; a later unchanged snap stages
    // and keeps nothing.
    for file in &trees {
        assert!(
            !staging.objects_dir().join(file).exists(),
            "{file} swept after ack"
        );
        assert!(staging.is_uploaded(file));
    }
    let third = snap(&mut engine, Class::Small, 3);
    assert!(third.unchanged);
    let left: Vec<String> = fs::read_dir(staging.objects_dir())
        .unwrap()
        .map(|d| d.unwrap().file_name().to_string_lossy().into_owned())
        .collect();
    assert!(left.is_empty(), "staging holds {left:?}");

    let restore = fx.base.join("restore");
    Materializer::new(
        sink.as_ref(),
        MaterializeTargets::new(&restore, Some(fx.base.join("home2"))),
    )
    .materialize(&registrar.head().unwrap().manifest, MaterializeClass::All)
    .unwrap();
    assert_eq!(
        fs::read_to_string(restore.join(".env")).unwrap(),
        "SECRET=1\n"
    );
}

/// A small `auto` snap that coalesces with a queued bulk capture carries the bulk section as
/// it is, dir objects included, so the combined capture materializes.
#[test]
fn a_small_snap_coalescing_a_queued_bulk_capture_keeps_its_dir_objects() {
    let fx = fixture(4, 3);
    let sink = Arc::new(LocalDir::new(&fx.base.join("store")).unwrap());
    let registrar = Arc::new(InMemoryRegistrar::new("wt", 1, None));
    let mut engine = CaptureEngine::open(fx.config(), None).unwrap();
    let dyn_registrar: Arc<dyn Registrar> = registrar.clone();
    let shipper = engine.shipper(sink.clone(), dyn_registrar);
    snap(&mut engine, Class::Small, 1);
    assert_eq!(shipper.ship_pending().unwrap(), 1);

    let bulk = snap(&mut engine, Class::Bulk, 2);
    assert_eq!(bulk.n, 1);
    assert!(bulk.stats.dirs_new >= 4, "{:?}", bulk.stats);
    let queued = engine.staging().pending().unwrap();
    assert_eq!(queued.len(), 1);
    let bulk_trees = queued[0]
        .uploads
        .iter()
        .filter(|u| u.file.starts_with("tree-"))
        .count();
    assert!(bulk_trees >= 4);

    // Before the shipper claims it, the workspace class changes and a small snap coalesces.
    fs::write(fx.root.join(".env"), "SECRET=2\n").unwrap();
    let small = snap(&mut engine, Class::Small, 3);
    assert_eq!(small.n, 1, "coalesced into the bulk capture's slot");
    assert!(matches!(
        small.manifest.manifest.sections.bulk,
        BulkState::Ready(_)
    ));
    let queued = engine.staging().pending().unwrap();
    assert_eq!(queued.len(), 1);
    assert_eq!(queued[0].capture_id, small.manifest.capture_id);
    let carried = queued[0]
        .uploads
        .iter()
        .filter(|u| u.file.starts_with("tree-"))
        .count();
    assert!(
        carried >= bulk_trees,
        "the bulk dir objects ride along: {carried} < {bulk_trees}"
    );

    assert_eq!(shipper.ship_pending().unwrap(), 1);
    let head = registrar.head().unwrap();
    assert_eq!(head.n, 1);
    assert_eq!(head.capture_id, small.manifest.capture_id);
    let restore = fx.base.join("restore");
    let report = Materializer::new(
        sink.as_ref(),
        MaterializeTargets::new(&restore, Some(fx.base.join("home2"))),
    )
    .materialize(&head.manifest, MaterializeClass::All)
    .unwrap();
    assert!(report.files >= 12, "{report:?}");
    assert_eq!(
        fs::read_to_string(restore.join(".env")).unwrap(),
        "SECRET=2\n"
    );
    assert!(restore.join("node_modules/pkg3/lib/m2.js").exists());
}

/// A minter that counts what the sink asked of it.
struct Recording {
    inner: Arc<RegistrarMinter<dyn Registrar>>,
    puts: AtomicU64,
    gets: AtomicU64,
    prefetches: AtomicU64,
    prefetched_keys: AtomicU64,
}

impl UrlMinter for Recording {
    fn put_url(&self, key: &str) -> Result<String, String> {
        self.puts.fetch_add(1, Ordering::SeqCst);
        self.inner.put_url(key)
    }

    fn prefetch_put(&self, keys: &[String]) -> Result<(), String> {
        self.prefetches.fetch_add(1, Ordering::SeqCst);
        self.prefetched_keys
            .fetch_add(keys.len() as u64, Ordering::SeqCst);
        self.inner.prefetch_put(keys)
    }

    fn get_url(&self, key: &str) -> Result<String, String> {
        self.gets.fetch_add(1, Ordering::SeqCst);
        self.inner.get_url(key)
    }

    fn multipart_urls(&self, key: &str, size: u64) -> Result<Option<MultipartUrls>, String> {
        self.inner.multipart_urls(key, size)
    }

    fn complete_multipart(
        &self,
        key: &str,
        upload_id: &str,
        parts: &[CompletedPart],
    ) -> Result<Completed, SinkError> {
        self.inner.complete_multipart(key, upload_id, parts)
    }
}

/// Over a presigned sink: every object's PUT URL comes from `upload.urls`, minted a batch at
/// a time, never from the plan's GET URLs; a bulk capture with many dir objects costs one
/// channel call per [`PREFETCH_BATCH`] objects; a later bulk capture lists only the dir
/// objects that changed.
#[test]
fn shipping_mints_put_urls_in_batches_and_never_falls_back_to_get_urls() {
    let server = common::serve();
    let fx = fixture(60, 2);
    let registrar = Arc::new(InMemoryRegistrar::new("wt", 1, Some(server.base.clone())));
    let dyn_registrar: Arc<dyn Registrar> = registrar.clone();
    let minter = Arc::new(Recording {
        inner: Arc::new(RegistrarMinter::new(
            dyn_registrar.clone(),
            "wt",
            1,
            Default::default(),
        )),
        puts: AtomicU64::new(0),
        gets: AtomicU64::new(0),
        prefetches: AtomicU64::new(0),
        prefetched_keys: AtomicU64::new(0),
    });
    let sink: Arc<dyn BlobSink> = Arc::new(PresignedHttp::new(
        Box::new(minter.clone()),
        std::time::Duration::from_secs(30),
    ));
    let mut engine = CaptureEngine::open(fx.config(), None).unwrap();
    let shipper = engine.shipper(sink.clone(), dyn_registrar);

    let staged_objects = |engine: &CaptureEngine| -> usize {
        let queued = engine.staging().pending().unwrap();
        assert_eq!(queued.len(), 1);
        queued[0].uploads.len()
    };
    let small = snap(&mut engine, Class::Small, 1);
    let small_objects = staged_objects(&engine);
    assert_eq!(shipper.ship_pending().unwrap(), 1);
    let bulk = snap(&mut engine, Class::Bulk, 2);
    assert_eq!(bulk.n, 1);
    let bulk_objects = staged_objects(&engine);
    // 60 packages × (pkg, lib) + node_modules + root, a pack and the manifest.
    assert!(bulk_objects > 120, "{bulk_objects} objects staged");
    assert!(
        bulk_objects < PREFETCH_BATCH,
        "one batch per capture in this fixture"
    );
    assert_eq!(shipper.ship_pending().unwrap(), 1);
    let objects = small_objects + bulk_objects;
    let uploaded = shipper.status.snapshot().uploaded_objects;
    assert_eq!(uploaded, objects as u64);
    assert_eq!(server.counters.single_puts.load(Ordering::SeqCst), uploaded);
    assert_eq!(
        minter.gets.load(Ordering::SeqCst),
        0,
        "no GET URL is ever asked for"
    );
    assert_eq!(minter.puts.load(Ordering::SeqCst), uploaded);
    assert_eq!(
        minter.prefetches.load(Ordering::SeqCst),
        2,
        "one batch per capture"
    );
    assert_eq!(minter.prefetched_keys.load(Ordering::SeqCst), uploaded);
    assert_eq!(
        registrar.url_requests(),
        2,
        "every PUT URL came from one of two upload.urls calls"
    );
    assert!(
        server
            .objects
            .lock()
            .unwrap()
            .contains_key(&small.manifest_key)
    );
    assert!(
        server
            .objects
            .lock()
            .unwrap()
            .contains_key(&bulk.manifest_key)
    );

    // One bulk file changes: only the dir objects on its path and one pack are listed.
    fs::write(
        fx.root.join("node_modules/pkg7/lib/m1.js"),
        "module.exports = 'changed';\n",
    )
    .unwrap();
    let again = snap(&mut engine, Class::Bulk, 3);
    assert!(!again.unchanged);
    assert_eq!(again.n, 2);
    let queued = engine.staging().pending().unwrap();
    assert_eq!(queued.len(), 1);
    let listed: Vec<&str> = queued[0].uploads.iter().map(|u| u.file.as_str()).collect();
    let trees = listed.iter().filter(|f| f.starts_with("tree-")).count();
    assert_eq!(trees, 4, "root, node_modules, pkg7, lib: {listed:?}");
    assert_eq!(
        listed.len(),
        6,
        "one pack, four dir objects, the manifest: {listed:?}"
    );
    assert_eq!(shipper.ship_pending().unwrap(), 1);
    assert_eq!(registrar.url_requests(), 3);
    assert_eq!(minter.gets.load(Ordering::SeqCst), 0);
    assert_eq!(shipper.status.snapshot().uploaded_objects, uploaded + 6);
}

/// The observed failure, kept as a regression: an object a queued entry lists but staging no
/// longer holds is unshippable over a presigned sink — the probe has no GET URL. With the
/// staging fixes it cannot arise from the engine; this pins what the shipper reports if it
/// ever does.
#[test]
fn a_missing_staged_object_fails_the_pass_without_a_get_url() {
    let server = common::serve();
    let fx = fixture(1, 1);
    let registrar = Arc::new(InMemoryRegistrar::new("wt", 1, Some(server.base.clone())));
    let dyn_registrar: Arc<dyn Registrar> = registrar.clone();
    let minter: Arc<RegistrarMinter<dyn Registrar>> = Arc::new(RegistrarMinter::new(
        dyn_registrar.clone(),
        "wt",
        1,
        Default::default(),
    ));
    let sink: Arc<dyn BlobSink> = Arc::new(PresignedHttp::new(
        Box::new(minter),
        std::time::Duration::from_secs(30),
    ));
    let mut engine = CaptureEngine::open(fx.config(), None).unwrap();
    let shipper =
        engine
            .shipper(sink, dyn_registrar)
            .with_retry(sealant_capture::ship::RetryPolicy {
                attempts: 1,
                backoff: std::time::Duration::from_millis(1),
                max_backoff: std::time::Duration::from_millis(1),
            });
    snap(&mut engine, Class::Small, 1);
    let queued = engine.staging().pending().unwrap();
    let tree = queued[0]
        .uploads
        .iter()
        .find(|u| u.file.starts_with("tree-"))
        .unwrap()
        .clone();
    fs::remove_file(engine.staging().objects_dir().join(&tree.file)).unwrap();
    match shipper.ship_pending() {
        Err(ShipError::Upload { key, source }) => {
            assert_eq!(key, tree.key);
            assert!(
                source.to_string().contains("no GET url in plan"),
                "{source}"
            );
        }
        other => panic!("expected the upload of {} to fail: {other:?}", tree.key),
    }
}
