//! Byte-quota refusals are terminal. The shape of the first real cluster session: a 775 MB bulk
//! capture went up in full, `capture.register` answered 413, and the ship worker re-ran the same
//! register every 5 s for good. A refused capture is now dropped with its staged bytes, the class
//! is marked refused, and the chain continues from the refused capture's parent — so the small
//! class keeps shipping while the bulk class waits for the next epoch or a `capture.replan`.

mod common;

use std::fs;
use std::path::Path;
use std::process::Command;
use std::sync::Arc;
use std::sync::atomic::Ordering;

use sealant_capture::registrar::RegistrarMinter;
use sealant_capture::{
    BlobSink, CaptureConfig, CaptureEngine, CaptureKind, Class, InMemoryRegistrar, LocalDir,
    PresignedHttp, Registrar, SnapRequest,
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

/// `upload.urls` refuses the batch before it mints anything (413 `byte-quota`): the entry and its
/// staged bytes are dropped, not one PUT reaches the store, the bulk class is marked refused —
/// and the small class carries on, its next capture taking the refused capture's chain slot.
#[test]
fn a_refusal_at_upload_urls_drops_the_capture_and_leaves_the_small_class_working() {
    let server = common::serve();
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path().join("ws");
    workspace(&root, 200);

    let registrar = Arc::new(InMemoryRegistrar::new("wt", 1, Some(server.base.clone())));
    let dyn_registrar: Arc<dyn Registrar> = registrar.clone();
    let minter = Arc::new(RegistrarMinter::new(
        dyn_registrar.clone(),
        "wt",
        1,
        Default::default(),
    ));
    let sink: Arc<dyn BlobSink> = Arc::new(PresignedHttp::new(
        Box::new(minter),
        std::time::Duration::from_secs(30),
    ));
    let mut engine = CaptureEngine::open(CaptureConfig::new("wt", 1, &root), None).unwrap();
    let shipper = engine.shipper(sink, dyn_registrar);

    // Capture 0 (small) ships; from here the session has 64 KiB left — room for another small
    // capture, nowhere near the bulk tree.
    snap(&mut engine, Class::Small, 1);
    assert_eq!(shipper.ship_pending().unwrap(), 1);
    registrar.set_byte_quota(Some(registrar.used_bytes() + 64 * 1024), None);
    let head = registrar.head().unwrap();
    assert_eq!(head.n, 0);
    let puts_after_small = server.counters.single_puts.load(Ordering::SeqCst);
    assert!(puts_after_small > 0, "the small capture went up");

    // Capture 1 (bulk) is over the budget: the batch is priced and refused whole.
    let bulk = snap(&mut engine, Class::Bulk, 2);
    assert_eq!(bulk.n, 1);
    let staging = engine.staging();
    assert_eq!(staging.pending().unwrap().len(), 1);
    assert_eq!(shipper.ship_pending().unwrap(), 0, "nothing shipped");

    assert!(
        staging.pending().unwrap().is_empty(),
        "the refused capture is dropped, not retried"
    );
    assert_eq!(
        staging.staged_bytes().unwrap(),
        0,
        "its staged bytes went with it"
    );
    assert_eq!(
        server.counters.single_puts.load(Ordering::SeqCst),
        puts_after_small,
        "not one PUT was issued for the refused capture"
    );
    let status = shipper.status.snapshot();
    assert!(status.refused_bulk, "{status:?}");
    assert!(!status.refused_small, "{status:?}");
    assert!(shipper.is_refused(Class::Bulk));
    assert_eq!(registrar.head().unwrap().capture_id, head.capture_id);

    // The small class keeps working: the next capture takes the refused capture's slot and
    // registers against the head the chain actually has.
    fs::write(root.join("src/lib.rs"), "pub fn f() { g() }\n").unwrap();
    let small = snap(&mut engine, Class::Small, 3);
    assert_eq!(small.n, 1, "the refused capture's slot");
    assert_eq!(
        small.manifest.manifest.parent.as_deref(),
        Some(head.capture_id.as_str())
    );
    assert_eq!(shipper.ship_pending().unwrap(), 1);
    let new_head = registrar.head().unwrap();
    assert_eq!(new_head.n, 1);
    assert_eq!(new_head.capture_id, small.manifest.capture_id);
    assert!(
        new_head
            .manifest
            .sections
            .bulk
            .section()
            .is_none_or(|b| b.packs.iter().all(|k| *k != bulk.manifest_key)),
        "the refused bulk section is not carried into the chain"
    );
    // Every key the chain names is in the store.
    let objects = server.objects.lock().unwrap();
    for key in new_head
        .manifest
        .sections
        .git
        .packs
        .iter()
        .chain(new_head.manifest.sections.workspace.packs.iter())
        .chain([&new_head.manifest.sections.workspace.root])
    {
        assert!(objects.contains_key(key), "{key} never went up");
    }
}

/// The backstop: a sink that mints nothing (a directory) declares no sizes, so the packs land and
/// `capture.register` refuses them with 409 `byte-quota`. The capture is dropped all the same.
#[test]
fn a_refusal_at_register_drops_the_capture_after_the_packs_landed() {
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path().join("ws");
    workspace(&root, 200);
    let store = Arc::new(LocalDir::new(&tmp.path().join("store")).unwrap());
    let sink: Arc<dyn BlobSink> = store.clone();
    let registrar = Arc::new(InMemoryRegistrar::new("wt", 1, None));
    let dyn_registrar: Arc<dyn Registrar> = registrar.clone();
    let mut engine = CaptureEngine::open(CaptureConfig::new("wt", 1, &root), None).unwrap();
    let shipper = engine.shipper(sink.clone(), dyn_registrar);

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
    assert!(
        staging.pending().unwrap().is_empty(),
        "the refused capture is dropped, not re-registered every tick"
    );
    assert!(shipper.is_refused(Class::Bulk));
    assert_eq!(registrar.head().unwrap().capture_id, head.capture_id);

    // A second pass has nothing to do — the loop the cluster saw is gone.
    assert_eq!(shipper.ship_pending().unwrap(), 0);
    assert_eq!(registrar.chain().len(), 1);
}
