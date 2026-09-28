//! Docker end to end, round 5 (session HS): the object store went down during a stop, and the
//! shipper spent the registrar's `upload.urls` call quota (560 calls in about three minutes)
//! while it retried. Every retry of a PUT minted a fresh URL (a minted URL was taken out of the
//! cache on first use), every retry of a multipart upload created a new upload, and a pass that
//! failed was followed at once by the next. Now a URL minted for a key is used again until the
//! upload of that key settles (or the URL is five minutes old), a multipart upload resumes under
//! the same upload, and a pass the store or the registrar refused waits out a backoff.

mod common;

use std::collections::BTreeMap;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::time::{Duration, Instant};

use sealant_capture::manifest::{
    BulkState, CaptureKind, FsckStatus, GitSection, Manifest, Sections, WorkspaceSection,
};
use sealant_capture::registrar::{
    ChangeSummaryRequest, HeartbeatRequest, HeartbeatResponse, InMemoryRegistrar, MultipartPolicy,
    PlanGetRequest, PlanGetResponse, RegisterRequest, RegisterResponse, RegistrarMinter,
    UploadCompleteRequest, UploadCompleteResponse, UploadUrlsRequest, UploadUrlsResponse,
};
use sealant_capture::ship::{MultipartConfig, QueueEntry, RetryPolicy, Shipper, Staging, Upload};
use sealant_capture::sink::{BlobSink, PartRetry, PresignedHttp};
use sealant_capture::{Registrar, RegistrarError};

use common::serve;

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
        class: None,
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
                        symrefs: Default::default(),
                        worktree_tree: None,
                        index_tree: None,
                        raw_tree: None,
                    },
                    workspace: WorkspaceSection::objects(String::new(), Vec::new()),
                    bulk: BulkState::pending(),
                    other_bulk: Default::default(),
                },
                checkpoint: None,
                final_seal: None,
            },
        },
    }
}

/// A registrar in front of the in-memory one that answers `upload.urls` like a throttled
/// control plane (429, retryable) while `throttled`, and counts every `upload.urls` call.
struct Throttle {
    inner: Arc<InMemoryRegistrar>,
    throttled: AtomicBool,
    url_calls: AtomicU64,
}

impl Registrar for Throttle {
    fn plan_get(&self, req: &PlanGetRequest) -> Result<PlanGetResponse, RegistrarError> {
        self.inner.plan_get(req)
    }
    fn upload_urls(&self, req: &UploadUrlsRequest) -> Result<UploadUrlsResponse, RegistrarError> {
        self.url_calls.fetch_add(1, Ordering::SeqCst);
        if self.throttled.load(Ordering::SeqCst) {
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

struct Fixture {
    _dir: tempfile::TempDir,
    staging: Arc<Staging>,
    server: common::Server,
    registrar: Arc<Throttle>,
    shipper: Shipper,
}

/// A shipper over the in-process object server, the registrar minting through the throttle.
/// Retries are quick (so a tight loop would show), the backoff between failed passes is the
/// shipper's own.
fn fixture() -> Fixture {
    let dir = tempfile::tempdir().unwrap();
    let staging = Arc::new(Staging::open(&dir.path().join("staging"), "wt", 1).unwrap());
    let server = serve();
    let completer = server.completer();
    let inner = Arc::new(
        InMemoryRegistrar::new("wt", 1, Some(server.base.clone())).with_multipart(
            MultipartPolicy {
                threshold: THRESHOLD,
                part_size: PART,
            },
            Some(completer),
        ),
    );
    let registrar = Arc::new(Throttle {
        inner,
        throttled: AtomicBool::new(false),
        url_calls: AtomicU64::new(0),
    });
    let minter = RegistrarMinter::new(registrar.clone(), "wt", 1, BTreeMap::new());
    let sink: Arc<dyn BlobSink> = Arc::new(
        PresignedHttp::new(Box::new(minter), Duration::from_secs(10)).with_part_retry(PartRetry {
            attempts: 2,
            backoff: Duration::from_millis(5),
            max_backoff: Duration::from_millis(10),
        }),
    );
    let shipper = Shipper::new(staging.clone(), sink, registrar.clone())
        .with_multipart(MultipartConfig {
            threshold: THRESHOLD,
            part_size: PART,
            parts_in_flight: 4,
        })
        .with_retry(RetryPolicy {
            attempts: 3,
            backoff: Duration::from_millis(5),
            max_backoff: Duration::from_millis(20),
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

    fn url_calls(&self) -> u64 {
        self.registrar.url_calls.load(Ordering::SeqCst)
    }
}

/// The store down for 2.5 s under a final flush: the small objects' URLs are minted once, in
/// one batch, and every retry uses them; once the store is back the flush completes on the same
/// URLs. The large object's multipart upload is created once and resumed.
#[test]
fn a_store_outage_reuses_minted_urls_and_backs_off() {
    for large in [false, true] {
        let fx = fixture();
        let uploads = if large {
            vec![fx.stage("big", &bytes(5 * PART as usize - 100, 7))]
        } else {
            (0..20)
                .map(|i| fx.stage(&format!("o{i}"), &bytes(500 + i, i as u32)))
                .collect()
        };
        fx.staging.enqueue(&entry(0, uploads)).unwrap();
        fx.server.counters.down.store(true, Ordering::SeqCst);

        let started = Instant::now();
        let failed = fx.shipper.flush_final(Some(Duration::from_millis(2_500)));
        assert!(failed.is_err(), "the store is down: {failed:?}");
        let refused = fx.server.counters.refused.load(Ordering::SeqCst);
        let minted = fx.url_calls();
        eprintln!(
            "large={large}: {minted} upload.urls calls, {refused} PUTs refused in {:?}",
            started.elapsed()
        );
        assert!(refused > 0, "it tried");
        assert_eq!(
            minted, 1,
            "large={large}: one mint, every retry on the URLs it minted ({refused} PUTs)"
        );

        fx.server.counters.down.store(false, Ordering::SeqCst);
        fx.shipper
            .flush_final(Some(Duration::from_secs(40)))
            .expect("the store is back");
        assert_eq!(
            fx.url_calls(),
            1,
            "large={large}: the same URLs, once it is back"
        );
        assert_eq!(fx.registrar.inner.chain().len(), 1);
        assert!(fx.staging.pending().unwrap().is_empty());
    }
}

/// The registrar throttled (`upload.urls` 429) for 3 s under a final flush: every pass spends
/// its retries, then the next waits out a backoff (1 s, doubling) — a handful of calls, not a
/// tight loop that runs the call quota down.
#[test]
fn a_throttled_registrar_is_asked_again_after_a_backoff() {
    let fx = fixture();
    let uploads = (0..5)
        .map(|i| fx.stage(&format!("o{i}"), &bytes(500 + i, i as u32)))
        .collect();
    fx.staging.enqueue(&entry(0, uploads)).unwrap();
    fx.registrar.throttled.store(true, Ordering::SeqCst);

    let failed = fx.shipper.flush_final(Some(Duration::from_secs(3)));
    assert!(failed.is_err(), "throttled throughout: {failed:?}");
    let calls = fx.url_calls();
    eprintln!("{calls} upload.urls calls in 3 s of 429s");
    // Passes at 0 s, 1 s and 3 s (the backoff doubles), three tries each.
    assert!(
        calls <= 9,
        "a failed pass is followed by a backoff, not the next pass at once: {calls} calls"
    );

    fx.registrar.throttled.store(false, Ordering::SeqCst);
    fx.shipper
        .flush_final(Some(Duration::from_secs(40)))
        .expect("the registrar is back");
    assert_eq!(fx.registrar.inner.chain().len(), 1);
}
