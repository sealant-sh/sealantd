//! Byte-quota refusals never lose work. The shape of the first real cluster session: a 775 MB
//! bulk capture went up in full, `capture.register` answered 413, and the ship worker re-ran the
//! same register every 5 s for good. For a while a refused capture was then dropped with its
//! staged bytes and every capture staged after it — a dependency tree, or the edits of a small
//! capture, discarded for a quota. Now a refused capture is held: it keeps its place in the queue
//! and its staged bytes, its class is reported refused in `capture.status`, the shipper asks
//! again after a backoff (not every tick), a small capture is still staged ahead of a held bulk
//! one, a newer bulk snap replaces the held capture, and once the budget allows it registers.

mod common;

use std::fs;
use std::path::Path;
use std::process::Command;
use std::sync::Arc;
use std::sync::atomic::Ordering;
use std::time::Duration;

use sealant_capture::manifest::BulkState;
use sealant_capture::registrar::{FlushMarker, RegistrarMinter};
use sealant_capture::{
    BlobSink, CadenceRunner, CaptureConfig, CaptureEngine, CaptureKind, Class, InMemoryRegistrar,
    LocalDir, MaterializeClass, MaterializeTargets, Materializer, PresignedHttp, Registrar,
    Shipper, SnapRequest,
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

/// Bytes that do not compress away, so a byte budget means what it says.
fn noise(seed: u64, len: usize) -> Vec<u8> {
    let mut x = seed.wrapping_mul(6364136223846793005).wrapping_add(1);
    (0..len)
        .map(|_| {
            x = x
                .wrapping_mul(6364136223846793005)
                .wrapping_add(1442695040888963407);
            (x >> 33) as u8
        })
        .collect()
}

/// A repository with `bulk_files` files of 4 KiB under `node_modules/` (the bulk class) beside a
/// tracked source file (the small class).
fn workspace(root: &Path, bulk_files: usize) {
    fs::create_dir_all(root.join("src")).unwrap();
    git(root, &["init", "-q", "-b", "main"]);
    git(root, &["config", "user.email", "t@t"]);
    git(root, &["config", "user.name", "t"]);
    fs::write(root.join(".gitignore"), "node_modules/\n").unwrap();
    fs::write(root.join("src/lib.rs"), "pub fn f() {}\n").unwrap();
    git(root, &["add", "-A"]);
    git(root, &["commit", "-q", "-m", "one"]);
    let dir = root.join("node_modules/pkg/lib");
    fs::create_dir_all(&dir).unwrap();
    for f in 0..bulk_files {
        fs::write(dir.join(format!("m{f}.js")), noise(f as u64, 4096)).unwrap();
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

/// The backoff after a refusal, short enough for a test.
const BACKOFF: Duration = Duration::from_millis(150);

fn shipper(
    engine: &CaptureEngine,
    sink: Arc<dyn BlobSink>,
    registrar: Arc<dyn Registrar>,
) -> Shipper {
    engine
        .shipper(sink, registrar)
        .with_hold_backoff(BACKOFF, BACKOFF * 4)
}

/// Every file under `dir`, with its bytes.
fn files(dir: &Path) -> Vec<(String, Vec<u8>)> {
    let mut out: Vec<(String, Vec<u8>)> = walkdir::WalkDir::new(dir)
        .into_iter()
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

/// A presigned sink over the registrar. With `plan`, it holds the GET URLs of the head's plan
/// (what a boot reads the head through).
fn presigned(registrar: &Arc<InMemoryRegistrar>, plan: bool) -> Arc<dyn BlobSink> {
    let dyn_registrar: Arc<dyn Registrar> = registrar.clone();
    let get_urls = if plan {
        registrar
            .plan_get(&sealant_capture::registrar::PlanGetRequest::booting(None))
            .unwrap()
            .get_urls
    } else {
        Default::default()
    };
    let minter = Arc::new(RegistrarMinter::new(dyn_registrar, "wt", 1, get_urls));
    Arc::new(PresignedHttp::new(
        Box::new(minter),
        std::time::Duration::from_secs(30),
    ))
}

/// `upload.urls` refuses the bulk batch before it mints anything (413 `byte-quota`): not one
/// PUT goes out, and the capture is held — queued with its staged bytes, the bulk class
/// reported refused, asked for again only after the backoff, which doubles per refusal. A
/// small capture is staged ahead of it and registers meanwhile. Once the budget allows, the
/// held capture registers and the head restores the dependency tree byte for byte.
#[test]
fn a_refusal_at_upload_urls_holds_the_bulk_capture_until_the_budget_allows() {
    let server = common::serve();
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path().join("ws");
    workspace(&root, 200);

    let registrar = Arc::new(InMemoryRegistrar::new("wt", 1, Some(server.base.clone())));
    let sink = presigned(&registrar, false);
    let mut engine = CaptureEngine::open(CaptureConfig::new("wt", 1, &root), None).unwrap();
    let shipper = shipper(&engine, sink.clone(), registrar.clone());

    // Capture 0 (small) ships; from here the session has 64 KiB left — room for another small
    // capture, nowhere near the bulk tree.
    snap(&mut engine, Class::Small, 1);
    assert_eq!(shipper.ship_pending().unwrap(), 1);
    registrar.set_byte_quota(Some(registrar.used_bytes() + 64 * 1024), None);
    let head = registrar.head().unwrap();
    let puts_after_small = server.counters.single_puts.load(Ordering::SeqCst);

    let bulk = snap(&mut engine, Class::Bulk, 2);
    assert_eq!(bulk.n, 1);
    let staging = engine.staging();
    let staged = staging.staged_bytes().unwrap();
    assert!(staged > 200 * 4096, "{staged} bytes staged");
    assert_eq!(shipper.ship_pending().unwrap(), 0, "nothing registered");

    let queued = staging.pending().unwrap();
    assert_eq!(queued.len(), 1, "the refused capture is held, not dropped");
    assert_eq!(queued[0].capture_id, bulk.manifest.capture_id);
    assert_eq!(
        staging.staged_bytes().unwrap(),
        staged,
        "every staged byte kept"
    );
    assert_eq!(
        server.counters.single_puts.load(Ordering::SeqCst),
        puts_after_small,
        "not one PUT was issued for the refused batch"
    );
    let status = shipper.status.snapshot();
    assert!(status.refused_bulk, "{status:?}");
    assert!(!status.refused_small, "{status:?}");
    let held = shipper.held();
    assert_eq!(held.len(), 1);
    assert_eq!(held[0].class, Some(Class::Bulk));
    assert_eq!(held[0].reason, "byte-quota");
    assert!(
        held[0].requested.is_some() && held[0].limit.is_some(),
        "{held:?}"
    );
    assert_eq!(registrar.head().unwrap().capture_id, head.capture_id);

    // Within the backoff a pass does not ask again: one `upload.urls` call per backoff, not per
    // tick, against the registrar's call quota.
    let asked = registrar.url_requests();
    assert_eq!(shipper.ship_pending().unwrap(), 0);
    assert_eq!(registrar.url_requests(), asked);
    // After it, it asks again, is refused again, and waits twice as long.
    std::thread::sleep(BACKOFF);
    assert_eq!(shipper.ship_pending().unwrap(), 0);
    assert_eq!(registrar.url_requests(), asked + 1);
    assert_eq!(shipper.held()[0].refusals, 2);
    assert_eq!(staging.pending().unwrap().len(), 1);

    // The small class keeps working: its capture is staged ahead of the held bulk capture and
    // registers against the head the chain has.
    fs::write(root.join("src/lib.rs"), "pub fn f() { g() }\n").unwrap();
    let small = snap(&mut engine, Class::Small, 3);
    assert_eq!(small.n, 1, "the held bulk capture's slot");
    assert_eq!(small.manifest.manifest.sections.bulk, BulkState::pending());
    assert_eq!(shipper.ship_pending().unwrap(), 1);
    assert_eq!(
        registrar.head().unwrap().capture_id,
        small.manifest.capture_id
    );
    let queued = staging.pending().unwrap();
    assert_eq!(queued.len(), 1);
    assert_eq!(queued[0].class, Some(Class::Bulk));
    assert_eq!(queued[0].n, 2, "the bulk capture moved on top");

    // The budget is raised: at the next ask the bulk capture registers, and the refusal clears.
    registrar.set_byte_quota(None, None);
    std::thread::sleep(BACKOFF * 4);
    assert_eq!(shipper.ship_pending().unwrap(), 1);
    assert!(staging.pending().unwrap().is_empty());
    assert!(shipper.held().is_empty());
    assert!(!shipper.status.snapshot().refused_bulk);
    let head = registrar.head().unwrap();
    assert!(matches!(head.manifest.sections.bulk, BulkState::Ready(_)));
    let restore = tmp.path().join("restore");
    Materializer::new(
        presigned(&registrar, true).as_ref(),
        MaterializeTargets::new(&restore, None),
    )
    .materialize(&head.manifest, MaterializeClass::All)
    .unwrap();
    assert_eq!(
        files(&restore.join("node_modules")),
        files(&root.join("node_modules"))
    );
    assert_eq!(
        fs::read_to_string(restore.join("src/lib.rs")).unwrap(),
        "pub fn f() { g() }\n"
    );
}

/// The backstop: a sink that mints nothing (a directory) declares no sizes, so the packs land and
/// `capture.register` refuses them with 409 `byte-quota`. The capture is held all the same, and
/// registers once the budget allows, without uploading anything again.
#[test]
fn a_refusal_at_register_holds_the_capture_after_the_packs_landed() {
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path().join("ws");
    workspace(&root, 200);
    let store = Arc::new(LocalDir::new(&tmp.path().join("store")).unwrap());
    let sink: Arc<dyn BlobSink> = store.clone();
    let registrar = Arc::new(InMemoryRegistrar::new("wt", 1, None));
    let mut engine = CaptureEngine::open(CaptureConfig::new("wt", 1, &root), None).unwrap();
    let shipper = shipper(&engine, sink.clone(), registrar.clone());

    snap(&mut engine, Class::Small, 1);
    assert_eq!(shipper.ship_pending().unwrap(), 1);
    let head = registrar.head().unwrap();

    // From here the session may hold nothing more.
    registrar.set_byte_quota(Some(registrar.used_bytes()), Some(sink.clone()));
    let bulk = snap(&mut engine, Class::Bulk, 2);
    let staging = engine.staging();
    assert_eq!(shipper.ship_pending().unwrap(), 0);
    let landed = bulk
        .manifest
        .manifest
        .sections
        .bulk
        .section()
        .expect("bulk section")
        .packs
        .clone();
    assert!(!landed.is_empty());
    for key in &landed {
        assert!(
            store.exists(key).unwrap(),
            "{key} landed before the refusal"
        );
    }
    assert_eq!(staging.pending().unwrap().len(), 1, "held, not dropped");
    assert!(shipper.is_refused(Class::Bulk));
    assert_eq!(registrar.head().unwrap().capture_id, head.capture_id);

    // Within the backoff nothing is re-registered: the loop the cluster saw is gone.
    let uploaded = shipper.status.snapshot().uploaded_objects;
    assert_eq!(shipper.ship_pending().unwrap(), 0);
    assert_eq!(registrar.chain().len(), 1);

    registrar.set_byte_quota(None, None);
    std::thread::sleep(BACKOFF);
    assert_eq!(shipper.ship_pending().unwrap(), 1);
    assert_eq!(
        registrar.head().unwrap().capture_id,
        bulk.manifest.capture_id
    );
    assert_eq!(
        shipper.status.snapshot().uploaded_objects,
        uploaded,
        "every object was up already; only the register ran again"
    );
    assert!(!shipper.is_refused(Class::Bulk));
}

/// A bulk class held for the byte quota keeps snapping: a newer bulk capture replaces the held
/// one in the queue (same chain position), so what registers once the budget allows is the
/// dependency tree as it is on disk, not the one that was refused.
#[test]
fn a_held_bulk_capture_is_replaced_by_the_newer_one() {
    let server = common::serve();
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path().join("ws");
    workspace(&root, 50);
    let registrar = Arc::new(InMemoryRegistrar::new("wt", 1, Some(server.base.clone())));
    let sink = presigned(&registrar, false);
    let mut engine = CaptureEngine::open(CaptureConfig::new("wt", 1, &root), None).unwrap();
    let shipper = shipper(&engine, sink.clone(), registrar.clone());
    snap(&mut engine, Class::Small, 1);
    assert_eq!(shipper.ship_pending().unwrap(), 1);
    registrar.set_byte_quota(Some(registrar.used_bytes() + 1024), None);

    let first = snap(&mut engine, Class::Bulk, 2);
    assert_eq!(shipper.ship_pending().unwrap(), 0);
    assert!(shipper.is_refused(Class::Bulk));

    fs::write(
        root.join("node_modules/pkg/lib/m7.js"),
        b"edited while held",
    )
    .unwrap();
    fs::write(
        root.join("node_modules/pkg/lib/new.js"),
        b"added while held",
    )
    .unwrap();
    let second = snap(&mut engine, Class::Bulk, 3);
    assert!(!second.unchanged);
    assert_eq!(
        second.n, first.n,
        "the newer bulk capture takes the held one's place"
    );
    let queued = engine.staging().pending().unwrap();
    assert_eq!(queued.len(), 1);
    assert_eq!(queued[0].capture_id, second.manifest.capture_id);

    registrar.set_byte_quota(None, None);
    std::thread::sleep(BACKOFF);
    assert_eq!(shipper.ship_pending().unwrap(), 1);
    let head = registrar.head().unwrap();
    assert_eq!(head.capture_id, second.manifest.capture_id);
    let restore = tmp.path().join("restore");
    Materializer::new(
        presigned(&registrar, true).as_ref(),
        MaterializeTargets::new(&restore, None),
    )
    .materialize(&head.manifest, MaterializeClass::All)
    .unwrap();
    assert_eq!(
        files(&restore.join("node_modules")),
        files(&root.join("node_modules"))
    );
}

/// A small capture refused for the byte quota is held too, and so is everything staged after
/// it — a turn capture and a bulk capture: nothing is dropped, nothing registers out of order,
/// and once the budget allows all of it registers and the head restores every edit.
#[test]
fn a_held_small_capture_drops_nothing_staged_after_it() {
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path().join("ws");
    workspace(&root, 20);
    let store = Arc::new(LocalDir::new(&tmp.path().join("store")).unwrap());
    let sink: Arc<dyn BlobSink> = store.clone();
    let registrar = Arc::new(InMemoryRegistrar::new("wt", 1, None));
    let mut engine = CaptureEngine::open(CaptureConfig::new("wt", 1, &root), None).unwrap();
    let shipper = shipper(&engine, sink.clone(), registrar.clone());
    snap(&mut engine, Class::Small, 1);
    assert_eq!(shipper.ship_pending().unwrap(), 1);
    registrar.set_byte_quota(Some(registrar.used_bytes()), Some(sink.clone()));

    fs::write(root.join("src/lib.rs"), "pub fn f() { one() }\n").unwrap();
    fs::write(root.join("src/big.bin"), noise(9, 256 * 1024)).unwrap();
    snap(&mut engine, Class::Small, 2);
    assert_eq!(shipper.ship_pending().unwrap(), 0);
    assert!(shipper.is_refused(Class::Small));
    fs::write(root.join("src/lib.rs"), "pub fn f() { two() }\n").unwrap();
    engine
        .snap(SnapRequest {
            kind: CaptureKind::Turn,
            class: Class::Small,
            seq: 3,
        })
        .unwrap();
    snap(&mut engine, Class::Bulk, 4);
    assert_eq!(shipper.ship_pending().unwrap(), 0);
    assert_eq!(
        engine.staging().pending().unwrap().len(),
        3,
        "nothing dropped"
    );

    registrar.set_byte_quota(None, None);
    std::thread::sleep(BACKOFF * 4);
    assert_eq!(shipper.ship_pending().unwrap(), 3);
    assert!(!shipper.is_refused(Class::Small));
    let head = registrar.head().unwrap();
    assert_eq!(head.n, 3);
    let restore = tmp.path().join("restore");
    Materializer::new(sink.as_ref(), MaterializeTargets::new(&restore, None))
        .materialize(&head.manifest, MaterializeClass::All)
        .unwrap();
    assert_eq!(
        fs::read_to_string(restore.join("src/lib.rs")).unwrap(),
        "pub fn f() { two() }\n"
    );
    assert_eq!(
        fs::read(restore.join("src/big.bin")).unwrap(),
        noise(9, 256 * 1024)
    );
    assert_eq!(
        files(&restore.join("node_modules")),
        files(&root.join("node_modules"))
    );
}

/// A final flush names itself on the wire (decision 35; review 2026-09-28, eleventh pass,
/// carried review 10 #6): from the moment it begins, every `upload.urls` the minter sends and
/// every `capture.register` the shipper sends carries `flush: final` — the bulk capture the
/// budget held included, and nothing before it does. A registrar that reads the marker
/// exempts it from the byte quota, and the final flush saves the held dependency tree; one
/// from before it ignores the marker and meters the request as it always did: the capture
/// stays held, the flush is incomplete, and nothing is dropped.
#[test]
fn a_final_flush_names_itself_on_upload_urls_and_register() {
    for exempting in [true, false] {
        let server = common::serve();
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path().join("ws");
        workspace(&root, 200);
        let registrar = InMemoryRegistrar::new("wt", 1, Some(server.base.clone()));
        let registrar = Arc::new(if exempting {
            registrar.exempting_final_flushes()
        } else {
            registrar
        });
        let dyn_registrar: Arc<dyn Registrar> = registrar.clone();
        let minter = Arc::new(RegistrarMinter::new(
            dyn_registrar,
            "wt",
            1,
            Default::default(),
        ));
        let preserving = minter.preserving();
        let sink: Arc<dyn BlobSink> = Arc::new(PresignedHttp::new(
            Box::new(minter),
            std::time::Duration::from_secs(30),
        ));
        let mut engine = CaptureEngine::open(CaptureConfig::new("wt", 1, &root), None).unwrap();
        let shipper = shipper(&engine, sink, registrar.clone()).with_preserving(preserving);

        snap(&mut engine, Class::Small, 1);
        assert_eq!(shipper.ship_pending().unwrap(), 1);
        registrar.set_byte_quota(Some(registrar.used_bytes() + 64 * 1024), None);
        snap(&mut engine, Class::Bulk, 2);
        assert_eq!(
            shipper.ship_pending().unwrap(),
            0,
            "the bulk capture is held"
        );
        let before = registrar.flush_seen();
        assert!(
            before.iter().any(|(call, _)| *call == "upload.urls")
                && before.iter().any(|(call, _)| *call == "capture.register"),
            "{before:?}"
        );
        assert!(
            before.iter().all(|(_, flush)| flush.is_none()),
            "no request before the final flush is marked: {before:?}"
        );

        let runner = CadenceRunner::new(engine, Arc::new(shipper));
        let deadline = Duration::from_secs(if exempting { 60 } else { 3 });
        let result = runner.flush_final(Some(deadline));
        let during = registrar.flush_seen()[before.len()..].to_vec();
        assert!(
            during.iter().any(|(call, _)| *call == "upload.urls")
                && during.iter().any(|(call, _)| *call == "capture.register"),
            "{exempting}: {during:?}"
        );
        assert!(
            during
                .iter()
                .all(|(_, flush)| *flush == Some(FlushMarker::Final)),
            "{exempting}: every request of the final flush is marked: {during:?}"
        );
        if exempting {
            assert!(result.complete(), "{result:?}");
            assert!(runner.staging().pending().unwrap().is_empty());
            assert!(matches!(
                registrar.head().unwrap().manifest.sections.bulk,
                BulkState::Ready(_)
            ));
        } else {
            assert!(!result.complete(), "{result:?}");
            assert!(
                !runner.staging().pending().unwrap().is_empty(),
                "the held capture is kept"
            );
        }
    }
}
