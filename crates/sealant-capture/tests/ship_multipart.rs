//! The shipper uploading large objects as multipart: the in-memory registrar mints part URLs
//! and completes server-side, the in-process object server takes the parts.

mod common;

use std::collections::BTreeMap;
use std::sync::Arc;
use std::sync::atomic::Ordering;
use std::time::Duration;

use sealant_capture::manifest::{
    BulkState, CaptureKind, FsckStatus, GitSection, Manifest, Sections, WorkspaceSection,
};
use sealant_capture::registrar::{
    InMemoryRegistrar, MultipartPolicy, RegisterRequest, RegistrarMinter,
};
use sealant_capture::ship::{MultipartConfig, QueueEntry, Shipper, Staging, Upload};
use sealant_capture::sink::{BlobSink, PartRetry, PresignedHttp};

use common::{Server, serve};

const PART: u64 = 64 * 1024;
const THRESHOLD: u64 = 256 * 1024;

fn bytes(n: usize, seed: u32) -> Vec<u8> {
    (0..n as u32).map(|i| ((i ^ seed) % 251) as u8).collect()
}

fn entry(n: u64, uploads: Vec<Upload>) -> QueueEntry {
    let id = format!("cap-{n}");
    QueueEntry {
        n,
        capture_id: id.clone(),
        kind: CaptureKind::Auto,
        uploads,
        register: RegisterRequest {
            worktree_id: "wt".into(),
            epoch: 1,
            n,
            parent: (n > 0).then(|| format!("cap-{}", n - 1)),
            capture_id: id.clone(),
            manifest_key: format!("captures/wt/1/manifests/{id}"),
            manifest: Manifest {
                worktree_id: "wt".into(),
                n,
                parent: None,
                epoch: 1,
                seq: 0,
                kind: CaptureKind::Auto,
                created_at: String::new(),
                sections: Sections {
                    git: GitSection {
                        packs: Vec::new(),
                        refs: BTreeMap::new(),
                        head: "HEAD".into(),
                        fsck: FsckStatus::Unverified,
                    },
                    workspace: WorkspaceSection {
                        root: String::new(),
                        packs: Vec::new(),
                    },
                    bulk: BulkState::pending(),
                },
                checkpoint: None,
            },
        },
    }
}

struct Fixture {
    _dir: tempfile::TempDir,
    staging: Arc<Staging>,
    server: Server,
    registrar: Arc<InMemoryRegistrar>,
    completer: Arc<common::Completer>,
    shipper: Shipper,
}

fn fixture(multipart: bool) -> Fixture {
    let dir = tempfile::tempdir().unwrap();
    let staging = Arc::new(Staging::open(&dir.path().join("staging"), 1).unwrap());
    let server = serve();
    let completer = server.completer();
    let registrar = InMemoryRegistrar::new("wt", 1, Some(server.base.clone()));
    let registrar = Arc::new(if multipart {
        registrar.with_multipart(
            MultipartPolicy {
                threshold: THRESHOLD,
                part_size: PART,
            },
            Some(completer.clone()),
        )
    } else {
        registrar
    });
    let minter = RegistrarMinter::new(registrar.clone(), "wt", 1, BTreeMap::new());
    let sink: Arc<dyn BlobSink> = Arc::new(
        PresignedHttp::new(Box::new(minter), Duration::from_secs(10)).with_part_retry(PartRetry {
            attempts: 3,
            backoff: Duration::from_millis(10),
            max_backoff: Duration::from_millis(50),
        }),
    );
    let shipper =
        Shipper::new(staging.clone(), sink, registrar.clone()).with_multipart(MultipartConfig {
            threshold: THRESHOLD,
            part_size: PART,
            parts_in_flight: 4,
        });
    Fixture {
        _dir: dir,
        staging,
        server,
        registrar,
        completer,
        shipper,
    }
}

impl Fixture {
    fn stage(&self, name: &str, body: &[u8]) -> Upload {
        std::fs::write(self.staging.objects_dir().join(name), body).unwrap();
        Upload {
            key: format!("captures/wt/1/packs/{name}"),
            file: name.to_owned(),
            bytes: body.len() as u64,
        }
    }
}

/// A large object goes up as parts with several in flight, its ETags are reported, the
/// registrar completes it once; a small object in the same capture is a single PUT.
#[test]
fn large_objects_ship_as_multipart_with_parts_in_flight() {
    let fx = fixture(true);
    let big = bytes(5 * PART as usize - 100, 7);
    let small = bytes(1000, 3);
    let uploads = vec![fx.stage("big", &big), fx.stage("small", &small)];
    fx.staging.enqueue(&entry(0, uploads)).unwrap();

    assert_eq!(fx.shipper.ship_pending().unwrap(), 1);

    let c = &fx.server.counters;
    assert_eq!(c.part_puts.load(Ordering::SeqCst), 5);
    assert_eq!(c.single_puts.load(Ordering::SeqCst), 1);
    assert!(
        c.max_in_flight.load(Ordering::SeqCst) >= 2,
        "parts in flight at once: {}",
        c.max_in_flight.load(Ordering::SeqCst)
    );
    let objects = fx.server.objects.lock().unwrap();
    assert_eq!(objects["captures/wt/1/packs/big"], big);
    assert_eq!(objects["captures/wt/1/packs/small"], small);
    drop(objects);
    let calls = fx.completer.calls.lock().unwrap();
    assert_eq!(calls.len(), 1, "complete called once");
    let (key, _, parts) = &calls[0];
    assert_eq!(key, "captures/wt/1/packs/big");
    assert_eq!(
        parts.iter().map(|p| p.part_number).collect::<Vec<_>>(),
        [1, 2, 3, 4, 5]
    );
    let expected: Vec<String> = big.chunks(PART as usize).map(common::etag).collect();
    assert_eq!(
        parts.iter().map(|p| p.etag.clone()).collect::<Vec<_>>(),
        expected,
        "ETags reported verbatim"
    );
    assert_eq!(fx.registrar.completes(), 1);
    assert_eq!(fx.registrar.open_uploads(), 0);
    let status = fx.shipper.status.snapshot();
    assert_eq!(status.uploaded_objects, 2);
    assert_eq!(status.already_present, 0);
    assert_eq!(status.head_n, Some(0));
    assert!(fx.staging.pending().unwrap().is_empty());
}

/// A key the store already holds: the registrar's write-once complete answers `exists`, which
/// counts as already present (content-addressed keys hold identical bytes).
#[test]
fn existing_key_completes_as_already_present() {
    let fx = fixture(true);
    let big = bytes(5 * PART as usize, 11);
    let upload = fx.stage("big", &big);
    fx.server
        .objects
        .lock()
        .unwrap()
        .insert(upload.key.clone(), big.clone());
    fx.staging.enqueue(&entry(0, vec![upload])).unwrap();

    assert_eq!(fx.shipper.ship_pending().unwrap(), 1);

    let status = fx.shipper.status.snapshot();
    assert_eq!(status.already_present, 1);
    assert_eq!(status.uploaded_objects, 0);
    assert_eq!(status.failures, 0);
    assert_eq!(fx.registrar.completes(), 1);
    assert_eq!(fx.server.counters.part_puts.load(Ordering::SeqCst), 5);
    assert_eq!(
        fx.server.objects.lock().unwrap()["captures/wt/1/packs/big"],
        big
    );
    assert!(fx.staging.pending().unwrap().is_empty());
}

/// A part that fails once is retried on its own; the object still assembles from one upload.
#[test]
fn a_failed_part_is_retried() {
    let fx = fixture(true);
    fx.server.counters.fail_part_once.store(3, Ordering::SeqCst);
    let big = bytes(4 * PART as usize + 17, 5);
    let upload = fx.stage("big", &big);
    fx.staging.enqueue(&entry(0, vec![upload])).unwrap();

    assert_eq!(fx.shipper.ship_pending().unwrap(), 1);

    assert!(fx.server.counters.failed_once.load(Ordering::SeqCst));
    assert_eq!(
        fx.server.counters.part_puts.load(Ordering::SeqCst),
        6,
        "five parts, one of them twice"
    );
    assert_eq!(fx.registrar.completes(), 1);
    assert_eq!(
        fx.server.objects.lock().unwrap()["captures/wt/1/packs/big"],
        big
    );
    assert_eq!(fx.shipper.status.snapshot().uploaded_objects, 1);
}

/// A registrar that answers `sizes` with a plain PUT URL (no multipart) gets a single PUT.
#[test]
fn registrar_without_multipart_gets_a_single_put() {
    let fx = fixture(false);
    let big = bytes(3 * PART as usize, 2);
    let upload = fx.stage("big", &big);
    fx.staging.enqueue(&entry(0, vec![upload])).unwrap();

    assert_eq!(fx.shipper.ship_pending().unwrap(), 1);

    assert_eq!(fx.server.counters.part_puts.load(Ordering::SeqCst), 0);
    assert_eq!(fx.server.counters.single_puts.load(Ordering::SeqCst), 1);
    assert_eq!(fx.registrar.completes(), 0);
    assert_eq!(
        fx.server.objects.lock().unwrap()["captures/wt/1/packs/big"],
        big
    );
}
