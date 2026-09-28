//! Stored objects are write-once (cross-repo decision 19): Mend's `upload.urls` mints no URL for
//! a key the bucket already holds and answers it in `present` (its bytes verified against the
//! key), and every presigned PUT carries `If-None-Match: *`. The shipper takes a `present` key,
//! and a PUT answered 412, as uploaded and goes on; a key answered in none of `urls`,
//! `multipart` and `present` stays an error, never an upload taken as done.

mod common;

use std::collections::BTreeMap;
use std::sync::atomic::Ordering;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use sealant_capture::manifest::{
    BulkState, CaptureKind, FsckStatus, GitSection, Manifest, Sections, WorkspaceSection,
};
use sealant_capture::registrar::{
    ChangeSummaryRequest, HeartbeatRequest, HeartbeatResponse, InMemoryRegistrar, MultipartPolicy,
    PlanGetRequest, PlanGetResponse, RegisterRequest, RegisterResponse, Registrar, RegistrarError,
    RegistrarMinter, UploadCompleteRequest, UploadCompleteResponse, UploadUrlsRequest,
    UploadUrlsResponse,
};
use sealant_capture::ship::{MultipartConfig, QueueEntry, ShipError, Shipper, Staging, Upload};
use sealant_capture::sink::{BlobSink, PartRetry, PresignedHttp, SinkError};

use common::{Server, serve};

const PART: u64 = 64 * 1024;
const THRESHOLD: u64 = 256 * 1024;

/// How the registrar answers a key the bucket already holds.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Answer {
    /// As Mend does: in `present`, with no URL.
    Present,
    /// A URL all the same (the object landed after the mint): the PUT meets a 412.
    Url,
}

/// The in-memory registrar, answering `upload.urls` for keys the object server already holds
/// the way `answer` says, and leaving out of its answer altogether the keys in `drop`.
struct Bucketed {
    inner: Arc<InMemoryRegistrar>,
    server: Arc<Mutex<std::collections::HashMap<String, Vec<u8>>>>,
    answer: Answer,
    drop: Vec<String>,
}

impl Registrar for Bucketed {
    fn plan_get(&self, req: &PlanGetRequest) -> Result<PlanGetResponse, RegistrarError> {
        self.inner.plan_get(req)
    }
    fn upload_urls(&self, req: &UploadUrlsRequest) -> Result<UploadUrlsResponse, RegistrarError> {
        let mut resp = self.inner.upload_urls(req)?;
        for key in &req.keys {
            if self.drop.contains(key) {
                resp.urls.remove(key);
                resp.multipart.remove(key);
                continue;
            }
            let stored = self.server.lock().unwrap().contains_key(key);
            if stored && self.answer == Answer::Present {
                resp.urls.remove(key);
                resp.multipart.remove(key);
                resp.present.push(key.clone());
            }
        }
        Ok(resp)
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

fn bytes(n: usize, seed: u32) -> Vec<u8> {
    (0..n as u32).map(|i| ((i ^ seed) % 251) as u8).collect()
}

fn entry(uploads: Vec<Upload>) -> QueueEntry {
    let id = "cap-0".to_owned();
    QueueEntry {
        n: 0,
        capture_id: id.clone(),
        kind: CaptureKind::Auto,
        class: None,
        uploads,
        register: RegisterRequest {
            worktree_id: "wt".into(),
            epoch: 1,
            n: 0,
            parent: None,
            capture_id: id.clone(),
            manifest_key: format!("captures/wt/1/manifests/{id}"),
            manifest: Manifest {
                worktree_id: "wt".into(),
                n: 0,
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
                        symrefs: Default::default(),
                        worktree_tree: None,
                        index_tree: None,
                        raw_tree: None,
                        object_format: None,
                        ref_format: None,
                    },
                    workspace: WorkspaceSection::objects(String::new(), Vec::new()),
                    bulk: BulkState::pending(),
                    other_bulk: Default::default(),
                },
                checkpoint: None,
                final_seal: None,
            },
            flush: None,
        },
    }
}

struct Fixture {
    _dir: tempfile::TempDir,
    staging: Arc<Staging>,
    server: Server,
    registrar: Arc<InMemoryRegistrar>,
    shipper: Shipper,
}

fn fixture(answer: Answer, drop: &[&str]) -> Fixture {
    let dir = tempfile::tempdir().unwrap();
    let staging = Arc::new(Staging::open(&dir.path().join("staging"), "wt", 1).unwrap());
    let server = serve();
    let completer = server.completer();
    let registrar = Arc::new(
        InMemoryRegistrar::new("wt", 1, Some(server.base.clone())).with_multipart(
            MultipartPolicy {
                threshold: THRESHOLD,
                part_size: PART,
            },
            Some(completer),
        ),
    );
    let bucketed: Arc<dyn Registrar> = Arc::new(Bucketed {
        inner: registrar.clone(),
        server: server.objects.clone(),
        answer,
        drop: drop.iter().map(|k| (*k).to_owned()).collect(),
    });
    let minter = RegistrarMinter::new(bucketed.clone(), "wt", 1, BTreeMap::new());
    let sink: Arc<dyn BlobSink> = Arc::new(
        PresignedHttp::new(Box::new(minter), Duration::from_secs(10)).with_part_retry(PartRetry {
            attempts: 2,
            backoff: Duration::from_millis(10),
            max_backoff: Duration::from_millis(20),
        }),
    );
    let shipper = Shipper::new(staging.clone(), sink, bucketed).with_multipart(MultipartConfig {
        threshold: THRESHOLD,
        part_size: PART,
        parts_in_flight: 2,
    });
    Fixture {
        _dir: dir,
        staging,
        server,
        registrar,
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

    /// The bucket holds `key` with `body` already (an earlier executor put it there).
    fn stored(&self, key: &str, body: &[u8]) {
        self.server
            .objects
            .lock()
            .unwrap()
            .insert(key.to_owned(), body.to_vec());
    }
}

/// Keys answered `present` — a single-PUT one and a multipart-sized one — are taken as uploaded
/// with nothing sent: no PUT, no part, the bucket's bytes untouched; the key minted beside them
/// goes up; the capture registers.
#[test]
fn a_key_answered_present_is_uploaded_without_a_put() {
    let fx = fixture(Answer::Present, &[]);
    let small = bytes(1000, 1);
    let big = bytes(5 * PART as usize - 7, 2);
    let fresh = bytes(700, 3);
    let uploads = vec![
        fx.stage("small", &small),
        fx.stage("big", &big),
        fx.stage("fresh", &fresh),
    ];
    fx.stored("captures/wt/1/packs/small", &small);
    fx.stored("captures/wt/1/packs/big", &big);
    fx.staging.enqueue(&entry(uploads)).unwrap();

    assert_eq!(fx.shipper.ship_pending().unwrap(), 1);

    let c = &fx.server.counters;
    assert_eq!(
        c.single_puts.load(Ordering::SeqCst),
        1,
        "only the fresh key was PUT"
    );
    assert_eq!(
        c.part_puts.load(Ordering::SeqCst),
        0,
        "no part of a present key"
    );
    let status = fx.shipper.status.snapshot();
    assert_eq!(status.already_present, 2, "{status:?}");
    assert_eq!(status.uploaded_objects, 1, "{status:?}");
    for (name, body) in [("small", &small), ("big", &big), ("fresh", &fresh)] {
        assert_eq!(
            fx.server.objects.lock().unwrap()[&format!("captures/wt/1/packs/{name}")],
            *body
        );
    }
    assert_eq!(fx.registrar.chain().len(), 1, "the capture registered");
}

/// A PUT URL minted for a key that landed since meets the write-once PUT's 412: taken as the
/// object already there, and the capture registers.
#[test]
fn a_put_answered_412_is_already_uploaded() {
    let fx = fixture(Answer::Url, &[]);
    let small = bytes(1000, 4);
    let uploads = vec![fx.stage("small", &small)];
    fx.stored("captures/wt/1/packs/small", &small);
    fx.staging.enqueue(&entry(uploads)).unwrap();

    assert_eq!(fx.shipper.ship_pending().unwrap(), 1);

    assert_eq!(
        fx.server.counters.single_puts.load(Ordering::SeqCst),
        1,
        "the PUT was sent, and refused"
    );
    let status = fx.shipper.status.snapshot();
    assert_eq!(status.already_present, 1, "{status:?}");
    assert_eq!(status.uploaded_objects, 0, "{status:?}");
    assert_eq!(
        fx.server.objects.lock().unwrap()["captures/wt/1/packs/small"],
        small,
        "the stored bytes stand"
    );
    assert_eq!(fx.registrar.chain().len(), 1, "the capture registered");
}

/// A key the registrar answers neither with a URL nor as present is an error: not marked
/// uploaded, nothing registered.
#[test]
fn a_key_neither_minted_nor_present_is_an_error() {
    let fx = fixture(Answer::Present, &["captures/wt/1/packs/lost"]);
    let lost = bytes(1000, 5);
    let uploads = vec![fx.stage("lost", &lost)];
    fx.staging.enqueue(&entry(uploads)).unwrap();

    let error = fx.shipper.ship_pending().unwrap_err();
    match &error {
        ShipError::Upload {
            key,
            source: SinkError::NoUrl { reason, .. },
        } => {
            assert_eq!(key, "captures/wt/1/packs/lost");
            assert!(reason.contains("neither a URL nor `present`"), "{reason}");
        }
        other => panic!("expected no URL for the key, got {other:?}"),
    }
    assert!(!fx.staging.is_uploaded("captures/wt/1/packs/lost", "lost"));
    assert_eq!(fx.server.counters.single_puts.load(Ordering::SeqCst), 0);
    assert!(fx.registrar.chain().is_empty(), "nothing registered");
}
