//! A register refused for missing objects never stops the chain and never drops a capture.
//! Mend's `capture.register` answers 422 `missing-objects` (an object the manifest names is not
//! in the bucket, the keys in `missing`) or `unrestorable` (a section's tree would not restore)
//! rather than acknowledge a capture it cannot restore — review 2026-09-27 #4: retention removed
//! a pack no live capture named while the executor's chunk index still pointed at it. The
//! shipper used to retry that register forever: the chain stopped, and a final flush never
//! completed. Now the engine rebuilds a refused capture from disk in its place with the named
//! packs forgotten — under a new key generation, so no key a refusal named is ever put again
//! (review 2026-09-28, cross-repo decision 6: a refused key may be one retention condemned; the
//! registrar refuses it for good, and a delete retention paused would remove it again).

use std::collections::BTreeSet;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::{Arc, Mutex};

use sealant_capture::keys::{key_digest, key_generation};
use sealant_capture::registrar::{
    ChangeSummaryRequest, HeartbeatRequest, HeartbeatResponse, PlanGetRequest, PlanGetResponse,
    RegisterRequest, RegisterResponse, UploadCompleteRequest, UploadCompleteResponse,
    UploadUrlsRequest, UploadUrlsResponse,
};
use sealant_capture::{
    BlobSink, CadenceRunner, CaptureConfig, CaptureEngine, CaptureKind, Class, InMemoryRegistrar,
    LocalDir, MaterializeClass, MaterializeTargets, Materializer, Registrar, RegistrarError,
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

/// Bytes that do not compress or chunk away.
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

/// A repository with a tracked source file and an ignored directory (the workspace class,
/// chunked into CDC packs).
fn workspace(root: &Path) {
    fs::create_dir_all(root.join("src")).unwrap();
    fs::create_dir_all(root.join("ignored")).unwrap();
    git(root, &["init", "-q", "-b", "main"]);
    git(root, &["config", "user.email", "t@t"]);
    git(root, &["config", "user.name", "t"]);
    fs::write(root.join(".gitignore"), "ignored/\n").unwrap();
    fs::write(root.join("src/lib.rs"), "pub fn f() {}\n").unwrap();
    git(root, &["add", "-A"]);
    git(root, &["commit", "-q", "-m", "one"]);
    fs::write(root.join("ignored/big.bin"), noise(1, 200_000)).unwrap();
}

/// What Mend checks before it acknowledges a register: every pack (and git pack index) the
/// manifest names, and the manifest itself, is in the bucket, and none is a key retention
/// condemned. `refuse` more registers are refused `unrestorable` whatever the bucket holds;
/// `drop_first` names a key removed from the bucket just before the first register (retention
/// running under the executor). A key a register is refused for is tombstoned for good
/// (cross-repo decision 6): refused by name ever after, whatever the bucket holds, and its
/// bytes deleted — as a paused retention delete would, later.
struct Mend {
    inner: Arc<InMemoryRegistrar>,
    store: Arc<LocalDir>,
    refuse: AtomicU32,
    drop_first: Mutex<Option<String>>,
    refusals: Mutex<Vec<(String, Vec<String>)>>,
    tombstones: Mutex<BTreeSet<String>>,
    /// Tombstoned keys a register found in the bucket again: written after they were condemned.
    revived: Mutex<Vec<String>>,
}

impl Mend {
    fn new(store: Arc<LocalDir>) -> Arc<Self> {
        Arc::new(Self {
            inner: Arc::new(InMemoryRegistrar::new("wt", 1, None)),
            store,
            refuse: AtomicU32::new(0),
            drop_first: Mutex::new(None),
            refusals: Mutex::new(Vec::new()),
            tombstones: Mutex::new(BTreeSet::new()),
            revived: Mutex::new(Vec::new()),
        })
    }

    /// Every tombstoned key is still gone from the bucket: nothing ever wrote one again.
    fn assert_no_tombstone_revived(&self) {
        assert_eq!(
            self.revived.lock().unwrap().clone(),
            Vec::<String>::new(),
            "condemned keys written again"
        );
        for key in self.tombstones.lock().unwrap().iter() {
            assert!(
                !self.store.exists(key).unwrap(),
                "{key} was condemned and written again"
            );
        }
    }

    fn named_keys(req: &RegisterRequest) -> Vec<String> {
        let s = &req.manifest.sections;
        let mut keys: Vec<String> = s
            .git
            .packs
            .iter()
            .flat_map(|k| [k.clone(), format!("{k}.idx")])
            .collect();
        keys.extend(s.workspace.packs.iter().cloned());
        keys.extend(s.workspace.dir_packs.iter().cloned());
        if let Some(bulk) = s.bulk.section() {
            keys.extend(bulk.packs.iter().cloned());
            keys.extend(bulk.dir_packs.iter().cloned());
        }
        keys.push(req.manifest_key.clone());
        keys
    }

    fn remove(&self, key: &str) {
        fs::remove_file(self.store.dir().join(key)).unwrap();
        assert!(!self.store.exists(key).unwrap());
    }
}

impl Registrar for Mend {
    fn plan_get(&self, req: &PlanGetRequest) -> Result<PlanGetResponse, RegistrarError> {
        self.inner.plan_get(req)
    }

    fn upload_urls(&self, req: &UploadUrlsRequest) -> Result<UploadUrlsResponse, RegistrarError> {
        self.inner.upload_urls(req)
    }

    fn upload_complete(
        &self,
        req: &UploadCompleteRequest,
    ) -> Result<UploadCompleteResponse, RegistrarError> {
        self.inner.upload_complete(req)
    }

    fn capture_register(&self, req: &RegisterRequest) -> Result<RegisterResponse, RegistrarError> {
        if let Some(key) = self.drop_first.lock().unwrap().take() {
            self.remove(&key);
        }
        let refuse = |reason: &str, missing: Vec<String>| {
            self.refusals
                .lock()
                .unwrap()
                .push((reason.to_owned(), missing.clone()));
            Err(RegistrarError::RegisterRefused {
                reason: reason.to_owned(),
                missing,
                message: "not acknowledged".to_owned(),
            })
        };
        if self
            .refuse
            .fetch_update(Ordering::SeqCst, Ordering::SeqCst, |n| n.checked_sub(1))
            .is_ok()
        {
            return refuse("unrestorable", Vec::new());
        }
        let missing: Vec<String> = {
            let tombstones = self.tombstones.lock().unwrap();
            Self::named_keys(req)
                .into_iter()
                .filter(|k| tombstones.contains(k) || !self.store.exists(k).unwrap())
                .collect()
        };
        if !missing.is_empty() {
            let mut tombstones = self.tombstones.lock().unwrap();
            for key in &missing {
                if self.store.exists(key).unwrap() {
                    if tombstones.contains(key) {
                        self.revived.lock().unwrap().push(key.clone());
                    }
                    fs::remove_file(self.store.dir().join(key)).unwrap();
                }
                tombstones.insert(key.clone());
            }
            drop(tombstones);
            return refuse("missing-objects", missing);
        }
        self.inner.capture_register(req)
    }

    fn lease_heartbeat(&self, req: &HeartbeatRequest) -> Result<HeartbeatResponse, RegistrarError> {
        self.inner.lease_heartbeat(req)
    }

    fn change_summary(&self, req: &ChangeSummaryRequest) -> Result<(), RegistrarError> {
        self.inner.change_summary(req)
    }
}

struct Fixture {
    _tmp: tempfile::TempDir,
    base: PathBuf,
    root: PathBuf,
    store: Arc<LocalDir>,
    mend: Arc<Mend>,
}

fn fixture() -> Fixture {
    let tmp = tempfile::tempdir().unwrap();
    let base = tmp.path().to_path_buf();
    let root = base.join("ws");
    workspace(&root);
    let store = Arc::new(LocalDir::new(&base.join("store")).unwrap());
    Fixture {
        mend: Mend::new(store.clone()),
        store,
        _tmp: tmp,
        base,
        root,
    }
}

impl Fixture {
    fn engine(&self) -> CaptureEngine {
        let mut config = CaptureConfig::new("wt", 1, &self.root);
        config.capture_bulk = false;
        CaptureEngine::open(config, None).unwrap()
    }

    fn shipper(&self, engine: &CaptureEngine) -> Arc<sealant_capture::Shipper> {
        let sink: Arc<dyn BlobSink> = self.store.clone();
        let registrar: Arc<dyn Registrar> = self.mend.clone();
        Arc::new(engine.shipper(sink, registrar))
    }

    fn restore(&self, name: &str) -> PathBuf {
        let out = self.base.join(name);
        let head = self.mend.inner.head().expect("a registered head");
        Materializer::new(self.store.as_ref(), MaterializeTargets::new(&out, None))
            .materialize(&head.manifest, MaterializeClass::All)
            .unwrap();
        out
    }
}

fn snap(engine: &mut CaptureEngine, kind: CaptureKind, seq: u64) {
    engine
        .snap(SnapRequest {
            kind,
            class: Class::Small,
            seq,
        })
        .unwrap();
}

/// Refused for an object the capture staged itself (the upload never landed, or retention
/// removed it between the upload and the register): the key may be one retention condemned, so
/// it is never put again (decision 6). The capture is rebuilt from disk in its place under a
/// new key generation — the same bytes, a new key — and registers at the same `n`. Before, the
/// shipper put the same key again: a condemned key was revived, refused for good, and the
/// capture never registered.
#[test]
fn a_refused_key_is_never_put_again_and_the_rebuild_registers_under_new_keys() {
    let fx = fixture();
    let mut engine = fx.engine();
    let shipper = fx.shipper(&engine);
    snap(&mut engine, CaptureKind::Turn, 1);
    let entry = engine.staging().pending().unwrap().remove(0);
    let own_pack = entry
        .register
        .manifest
        .sections
        .workspace
        .packs
        .first()
        .cloned()
        .expect("the workspace class packed big.bin");
    assert_eq!(key_generation(&own_pack), Some(0));
    // The objects are up; the pack goes before the register.
    *fx.mend.drop_first.lock().unwrap() = Some(own_pack.clone());

    assert_eq!(shipper.ship_pending().unwrap(), 0, "refused, not dropped");
    fx.mend.assert_no_tombstone_revived();
    assert_eq!(
        fx.mend.refusals.lock().unwrap().clone(),
        vec![("missing-objects".to_owned(), vec![own_pack.clone()])]
    );
    assert!(shipper.status.snapshot().repair_pending);

    // The next snap rebuilds it, under generation 1.
    snap(&mut engine, CaptureKind::Auto, 2);
    let rebuilt = engine.staging().pending().unwrap();
    assert_eq!(rebuilt.len(), 1);
    assert_eq!(rebuilt[0].n, entry.n);
    let packs = &rebuilt[0].register.manifest.sections.workspace.packs;
    assert!(!packs.contains(&own_pack), "{packs:?}");
    // What the rebuild staged is under the new generation; what it carries from the refused
    // capture (its git pack, which no refusal named) keeps its key; the refused key is in
    // neither.
    assert!(
        rebuilt[0].uploads.iter().all(|u| u.key != own_pack
            && (key_generation(&u.key) == Some(1) || entry.uploads.iter().any(|o| o.key == u.key))),
        "{:?}",
        rebuilt[0].uploads
    );
    assert!(
        packs
            .iter()
            .any(|k| key_digest(k) == key_digest(&own_pack) && *k != own_pack),
        "the same bytes under a new key: {packs:?}"
    );
    assert_eq!(shipper.ship_pending().unwrap(), 1);
    fx.mend.assert_no_tombstone_revived();
    assert_eq!(shipper.status.snapshot().register_refusals, 1);
    assert!(
        shipper.register_refusal().is_none(),
        "cleared once registered"
    );
    assert!(engine.staging().pending().unwrap().is_empty());
    let out = fx.restore("restored");
    assert_eq!(
        fs::read(out.join("ignored/big.bin")).unwrap(),
        noise(1, 200_000)
    );
    // A restart keeps the generation: nothing staged later reuses generation 0.
    drop(shipper);
    drop(engine);
    let mut engine = fx.engine();
    fs::write(fx.root.join("ignored/later"), b"after a restart\n").unwrap();
    snap(&mut engine, CaptureKind::Turn, 3);
    let later = engine.staging().pending().unwrap();
    assert!(
        later
            .iter()
            .flat_map(|e| &e.uploads)
            .all(|u| key_generation(&u.key) == Some(1)),
        "{later:?}"
    );
}

/// Review #4's shape: a pack an earlier capture uploaded is gone from the bucket while this
/// executor's chunk index still points into it, so the next capture names it without staging
/// it. Uploading again cannot help: the engine rebuilds that capture from disk in its place,
/// reading the file again into a new pack, and the rebuilt capture registers at the same `n`.
#[test]
fn a_capture_naming_a_pack_the_store_lost_is_rebuilt_from_disk_in_its_place() {
    let fx = fixture();
    let mut engine = fx.engine();
    let shipper = fx.shipper(&engine);
    snap(&mut engine, CaptureKind::Turn, 1);
    assert_eq!(shipper.ship_pending().unwrap(), 1);
    let first = fx.mend.inner.head().unwrap();
    let lost: BTreeSet<String> = first
        .manifest
        .sections
        .workspace
        .packs
        .iter()
        .cloned()
        .collect();
    for key in &lost {
        fx.mend.remove(key);
    }

    fs::write(fx.root.join("ignored/other"), b"a second file\n").unwrap();
    snap(&mut engine, CaptureKind::Turn, 2);
    let refused = engine.staging().pending().unwrap().remove(0);
    assert!(
        refused
            .register
            .manifest
            .sections
            .workspace
            .packs
            .iter()
            .any(|k| lost.contains(k)),
        "big.bin's chunks are deduplicated against the lost pack"
    );
    assert_eq!(shipper.ship_pending().unwrap(), 0, "refused, not dropped");
    let status = shipper.status.snapshot();
    assert!(status.repair_pending, "{status:?}");
    let refusal = shipper.register_refusal().expect("reported");
    assert_eq!(refusal.reason, "missing-objects");
    assert_eq!(refusal.n, refused.n);
    assert_eq!(engine.staging().pending().unwrap().len(), 1, "still queued");

    // The next snap rebuilds it first.
    snap(&mut engine, CaptureKind::Auto, 3);
    let rebuilt = engine.staging().pending().unwrap();
    assert_eq!(
        rebuilt.len(),
        1,
        "rebuilt in place, nothing added behind it"
    );
    assert_eq!(rebuilt[0].n, refused.n);
    assert_eq!(rebuilt[0].register.parent, refused.register.parent);
    assert_eq!(rebuilt[0].kind, CaptureKind::Turn);
    // The file is read again and packed again, under a new key generation: a pack of the same
    // chunks is a new key, and no lost key is named again.
    let named_lost: Vec<&String> = rebuilt[0]
        .register
        .manifest
        .sections
        .workspace
        .packs
        .iter()
        .filter(|k| lost.contains(*k))
        .collect();
    assert!(named_lost.is_empty(), "{named_lost:?}");
    assert_eq!(shipper.ship_pending().unwrap(), 1);
    fx.mend.assert_no_tombstone_revived();
    assert!(!shipper.status.snapshot().repair_pending);
    let head = fx.mend.inner.head().unwrap();
    assert_eq!(head.n, refused.n);
    let out = fx.restore("restored");
    assert_eq!(
        fs::read(out.join("ignored/big.bin")).unwrap(),
        noise(1, 200_000),
        "read from disk again"
    );
    assert_eq!(
        fs::read(out.join("ignored/other")).unwrap(),
        b"a second file\n"
    );
}

/// A capture refused with no key named (the tree does not restore, whatever is uploaded):
/// rebuilt from disk with every pack its section named forgotten, under a new key generation,
/// then registered; refused again, rebuilt again under the next one.
#[test]
fn a_capture_refused_twice_is_rebuilt_from_disk() {
    let fx = fixture();
    let mut engine = fx.engine();
    let shipper = fx.shipper(&engine);
    snap(&mut engine, CaptureKind::Turn, 1);
    let refused = engine.staging().pending().unwrap().remove(0);
    fx.mend.refuse.store(2, Ordering::SeqCst);

    assert_eq!(shipper.ship_pending().unwrap(), 0);
    assert_eq!(fx.mend.refusals.lock().unwrap().len(), 1, "never put again");
    assert!(shipper.status.snapshot().repair_pending);
    snap(&mut engine, CaptureKind::Auto, 2);
    assert_eq!(shipper.ship_pending().unwrap(), 0, "refused again");
    assert_eq!(fx.mend.refusals.lock().unwrap().len(), 2);
    snap(&mut engine, CaptureKind::Auto, 3);
    let rebuilt = engine.staging().pending().unwrap();
    assert_eq!(rebuilt.len(), 1);
    assert_eq!(rebuilt[0].n, refused.n);
    // Refused with no key named: every key of its workspace section is forgotten, and none
    // is staged or put again; its content is under generation 2.
    let section: BTreeSet<&String> = refused
        .register
        .manifest
        .sections
        .workspace
        .packs
        .iter()
        .collect();
    assert!(
        rebuilt[0].uploads.iter().all(|u| !section.contains(&u.key)),
        "{:?}",
        rebuilt[0].uploads
    );
    assert!(
        rebuilt[0]
            .register
            .manifest
            .sections
            .workspace
            .packs
            .iter()
            .all(|k| key_generation(k) == Some(2)),
        "{:?}",
        rebuilt[0].register.manifest.sections.workspace.packs
    );
    assert_eq!(shipper.ship_pending().unwrap(), 1);
    assert_eq!(shipper.status.snapshot().register_refusals, 2);
    let out = fx.restore("restored");
    assert_eq!(
        fs::read(out.join("ignored/big.bin")).unwrap(),
        noise(1, 200_000)
    );
}

/// A final flush meets the refusal: it rebuilds the refused capture (and folds the final
/// captures staged after it into it) and completes, the head a final capture holding the disk.
#[test]
fn a_final_flush_rebuilds_a_refused_capture_and_completes() {
    let fx = fixture();
    let mut engine = fx.engine();
    let shipper = fx.shipper(&engine);
    snap(&mut engine, CaptureKind::Turn, 1);
    assert_eq!(shipper.ship_pending().unwrap(), 1);
    for key in &fx
        .mend
        .inner
        .head()
        .unwrap()
        .manifest
        .sections
        .workspace
        .packs
    {
        fx.mend.remove(key);
    }
    fs::write(fx.root.join("ignored/other"), b"written before the end\n").unwrap();
    snap(&mut engine, CaptureKind::Turn, 2);
    let runner = CadenceRunner::new(engine, shipper.clone());
    fs::write(fx.root.join("src/lib.rs"), "pub fn f() { last() }\n").unwrap();

    let flushed = runner.flush_final(None);
    assert!(flushed.complete(), "{flushed:?}");
    let head = fx.mend.inner.head().unwrap();
    assert_eq!(head.manifest.kind, CaptureKind::Final);
    assert!(runner.staging().pending().unwrap().is_empty());
    let out = fx.restore("restored");
    assert_eq!(
        fs::read(out.join("ignored/big.bin")).unwrap(),
        noise(1, 200_000)
    );
    assert_eq!(
        fs::read(out.join("ignored/other")).unwrap(),
        b"written before the end\n"
    );
    assert_eq!(
        fs::read_to_string(out.join("src/lib.rs")).unwrap(),
        "pub fn f() { last() }\n"
    );
    runner.stop();
}
