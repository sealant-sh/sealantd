//! A capture the shipper has in flight when a re-plan rebases the engine (SLNT-1059).
//!
//! A standby stages a capture of its base under its placeholder identity; it holds no lease,
//! so the shipper keeps it and asks again. At the claim, `capture.replan` rebases the engine
//! onto the session's worktree and epoch; `Staging::discard_foreign` skips the entry the
//! shipper is on right now (`dropped=0` in the log). Before this fix the next `auto` snap
//! coalesced with it once the shipper let go: the session's capture took the placeholder
//! capture's parent (on no chain of the session's worktree: `wrong-parent`) and its packs,
//! staged under the placeholder prefix, which the registrar never mints a URL for (`no url for
//! captures/standby-…`). The final flush never finished, and the stop read `not saved ·
//! workspace kept`.
//!
//! The chain's rule fixes the session's first capture at the placeholder's `n` (the head's
//! `n + 1`), so the two share a queue slot. Every order of the shipper's claim (`C`), the
//! re-plan's rebase (`R`), the shipper letting go (`L`), the session's snap (`S`) and the
//! placeholder's ack (`A`) is a test below; in each, the session's capture names the session's
//! head, lists only keys under the session's prefix, registers, and the placeholder's objects
//! are swept.

use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::{Arc, Mutex};

use sealant_capture::registrar::{
    ChangeSummaryRequest, HeartbeatRequest, HeartbeatResponse, PlanGetRequest, PlanGetResponse,
    RegisterRequest, RegisterResponse, UploadCompleteRequest, UploadCompleteResponse,
    UploadUrlsRequest, UploadUrlsResponse,
};
use sealant_capture::ship::QueueEntry;
use sealant_capture::{
    BlobSink, CaptureConfig, CaptureEngine, CaptureKind, Class, EncodedManifest, InMemoryRegistrar,
    LocalDir, MaterializeTargets, Materializer, Registrar, RegistrarError, SnapRequest, Staging,
};
use sealant_process::CommandGateExt;

const STANDBY: &str = "standby-0a2845ff";
const STANDBY_EPOCH: u64 = 1_794_810_574_792;
const SESSION: &str = "wt-real";
const SESSION_EPOCH: u64 = 2;

fn git(root: &Path, args: &[&str]) {
    let out = Command::new("git")
        .current_dir(root)
        .env("GIT_OPTIONAL_LOCKS", "0")
        .args(args)
        .stdin(Stdio::null())
        .output_gated()
        .expect("git");
    assert!(
        out.status.success(),
        "git {args:?} failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );
}

fn workspace(root: &Path) {
    fs::create_dir_all(root.join("src")).unwrap();
    git(root, &["init", "-q", "-b", "main"]);
    git(root, &["config", "user.email", "t@t"]);
    git(root, &["config", "user.name", "t"]);
    fs::write(root.join("src/lib.rs"), "pub fn f() {}\n").unwrap();
    git(root, &["add", "-A"]);
    git(root, &["commit", "-q", "-m", "one"]);
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

/// The channel as the executor sees it: one registrar, answering each call for the worktree it
/// names (Mend answers by the session's token; the placeholder holds no lease). A hook can run
/// inside the placeholder's register, to land a re-plan while the shipper is on it.
struct Channel {
    standby: Arc<InMemoryRegistrar>,
    session: Arc<InMemoryRegistrar>,
    current: Mutex<String>,
    on_standby_register: Mutex<Option<Box<dyn FnOnce() + Send>>>,
}

impl Channel {
    fn by(&self, worktree_id: &str) -> &InMemoryRegistrar {
        if worktree_id == SESSION {
            &self.session
        } else {
            &self.standby
        }
    }
}

impl Registrar for Channel {
    fn plan_get(&self, req: &PlanGetRequest) -> Result<PlanGetResponse, RegistrarError> {
        let current = self.current.lock().unwrap().clone();
        self.by(&current).plan_get(req)
    }

    fn upload_urls(&self, req: &UploadUrlsRequest) -> Result<UploadUrlsResponse, RegistrarError> {
        self.by(&req.worktree_id).upload_urls(req)
    }

    fn upload_complete(
        &self,
        req: &UploadCompleteRequest,
    ) -> Result<UploadCompleteResponse, RegistrarError> {
        self.by(&req.worktree_id).upload_complete(req)
    }

    fn capture_register(&self, req: &RegisterRequest) -> Result<RegisterResponse, RegistrarError> {
        if req.worktree_id == STANDBY {
            let hook = self.on_standby_register.lock().unwrap().take();
            if let Some(hook) = hook {
                hook();
            }
        }
        self.by(&req.worktree_id).capture_register(req)
    }

    fn lease_heartbeat(&self, req: &HeartbeatRequest) -> Result<HeartbeatResponse, RegistrarError> {
        let current = self.current.lock().unwrap().clone();
        self.by(&current).lease_heartbeat(req)
    }

    fn change_summary(&self, req: &ChangeSummaryRequest) -> Result<(), RegistrarError> {
        let current = self.current.lock().unwrap().clone();
        self.by(&current).change_summary(req)
    }
}

/// The box's state at the claim: the session's chain at capture 0; the standby booted on the
/// base under its placeholder (its capture 0 registered), and an `auto` capture of its first
/// minute staged at n = 1 that no registrar takes (the placeholder holds no lease).
struct World {
    _tmp: tempfile::TempDir,
    root: PathBuf,
    store: Arc<LocalDir>,
    channel: Arc<Channel>,
    head: EncodedManifest,
    engine: Arc<Mutex<Option<CaptureEngine>>>,
    staging: Arc<Staging>,
    placeholder: QueueEntry,
}

fn world() -> World {
    let tmp = tempfile::tempdir().unwrap();
    let store = Arc::new(LocalDir::new(&tmp.path().join("store")).unwrap());
    let sink: Arc<dyn BlobSink> = store.clone();

    let session_root = tmp.path().join("session");
    workspace(&session_root);
    let session = Arc::new(InMemoryRegistrar::new(SESSION, SESSION_EPOCH, None));
    {
        let mut engine = CaptureEngine::open(
            CaptureConfig::new(SESSION, SESSION_EPOCH, &session_root),
            None,
        )
        .unwrap();
        snap(&mut engine, CaptureKind::Checkpoint, 0);
        let registrar: Arc<dyn Registrar> = session.clone();
        assert_eq!(
            engine
                .shipper(sink.clone(), registrar)
                .ship_pending()
                .unwrap(),
            1
        );
    }
    let head = session.head().unwrap();
    let head = Materializer::new(store.as_ref(), MaterializeTargets::new(&session_root, None))
        .fetch_manifest(&head.manifest_key, &head.capture_id)
        .unwrap();

    let root = tmp.path().join("standby");
    workspace(&root);
    let standby = Arc::new(InMemoryRegistrar::new(STANDBY, STANDBY_EPOCH, None));
    let mut engine =
        CaptureEngine::open(CaptureConfig::new(STANDBY, STANDBY_EPOCH, &root), None).unwrap();
    snap(&mut engine, CaptureKind::Checkpoint, 0);
    {
        let registrar: Arc<dyn Registrar> = standby.clone();
        assert_eq!(engine.shipper(sink, registrar).ship_pending().unwrap(), 1);
    }
    // Unclaimed, the standby holds no lease: everything it stages from now on is refused.
    standby.set_lease_alive(false);
    fs::write(root.join(".mend-standby"), "staged under the placeholder\n").unwrap();
    snap(&mut engine, CaptureKind::Auto, 1);
    let staging = engine.staging();
    let pending = staging.pending().unwrap();
    assert_eq!(pending.len(), 1);
    let placeholder = pending[0].clone();
    assert_eq!(placeholder.register.worktree_id, STANDBY);
    assert_eq!(placeholder.n, 1);
    assert_eq!(
        head.manifest.n, 0,
        "the session's first capture is the placeholder's n"
    );

    World {
        _tmp: tmp,
        root,
        store,
        channel: Arc::new(Channel {
            standby,
            session,
            current: Mutex::new(STANDBY.to_owned()),
            on_standby_register: Mutex::new(None),
        }),
        head,
        engine: Arc::new(Mutex::new(Some(engine))),
        staging,
        placeholder,
    }
}

impl World {
    fn with_engine<T>(&self, f: impl FnOnce(&mut CaptureEngine) -> T) -> T {
        f(self
            .engine
            .lock()
            .unwrap()
            .as_mut()
            .expect("the engine is open"))
    }

    /// `capture.replan`'s rebase onto the session (the head is the disk's base already).
    fn rebase(&self) {
        rebase(&self.engine, &self.channel, &self.head);
    }

    /// The session writes; the next `auto` snap stages it.
    fn session_snap(&self, seq: u64) {
        fs::write(
            self.root.join("src/lib.rs"),
            format!("pub fn f() {{ session_work({seq}) }}\n"),
        )
        .unwrap();
        self.with_engine(|engine| snap(engine, CaptureKind::Auto, seq));
    }

    fn shipper(&self) -> sealant_capture::Shipper {
        let sink: Arc<dyn BlobSink> = self.store.clone();
        let registrar: Arc<dyn Registrar> = self.channel.clone();
        self.with_engine(|engine| engine.shipper(sink, registrar))
    }

    /// Every queued capture is the session's: on the session's chain from its head, every key
    /// under the session's prefix (or the head's own chain).
    fn assert_queue_is_the_sessions(&self) {
        let prefix = format!("captures/{SESSION}/{SESSION_EPOCH}/");
        let pending = self.staging.pending().unwrap();
        assert!(!pending.is_empty(), "the session's work is queued");
        let mut parent = Some(self.head.capture_id.clone());
        let mut n = self.head.manifest.n;
        for entry in &pending {
            assert_eq!(entry.register.worktree_id, SESSION, "n={}", entry.n);
            assert_eq!(entry.register.epoch, SESSION_EPOCH, "n={}", entry.n);
            n += 1;
            assert_eq!(entry.n, n, "the queue continues the session's chain");
            assert_eq!(
                entry.register.parent, parent,
                "capture n={} must name the session's chain as its parent",
                entry.n
            );
            let stale: Vec<&str> = entry
                .uploads
                .iter()
                .map(|u| u.key.as_str())
                .filter(|key| !key.starts_with(&prefix))
                .collect();
            assert!(
                stale.is_empty(),
                "capture n={} uploads keys outside {prefix}: {stale:?}",
                entry.n
            );
            parent = Some(entry.capture_id.clone());
        }
    }

    /// The placeholder's objects that no queued capture lists are gone from staging.
    fn assert_placeholder_swept(&self) {
        let listed: Vec<String> = self
            .staging
            .pending()
            .unwrap()
            .iter()
            .flat_map(|e| e.uploads.iter().map(|u| u.file.clone()))
            .collect();
        for u in &self.placeholder.uploads {
            if !listed.contains(&u.file) {
                assert!(
                    !self.staging.objects_dir().join(&u.file).exists(),
                    "the placeholder's {} is left on disk",
                    u.file
                );
            }
        }
    }

    /// The session's captures register on the session's chain, and nothing stays queued.
    fn assert_ships(&self) {
        *self.channel.current.lock().unwrap() = SESSION.to_owned();
        self.shipper()
            .ship_pending()
            .expect("the session's captures ship");
        assert!(self.staging.pending().unwrap().is_empty());
        let head = self.channel.session.head().unwrap();
        assert_eq!(head.manifest.epoch, SESSION_EPOCH);
        assert!(head.n >= 1, "the session's work registered");
        assert!(
            self.channel.standby.chain().len() == 1,
            "nothing registered as the standby"
        );
    }
}

fn rebase(engine: &Mutex<Option<CaptureEngine>>, channel: &Channel, head: &EncodedManifest) {
    engine
        .lock()
        .unwrap()
        .as_mut()
        .unwrap()
        .rebase(SESSION, SESSION_EPOCH, Some(head.clone()))
        .unwrap();
    *channel.current.lock().unwrap() = SESSION.to_owned();
}

/// `R`, `S`: never in flight; the rebase drops it.
#[test]
fn a_placeholder_capture_not_in_flight_is_dropped_by_the_rebase() {
    let w = world();
    w.rebase();
    assert!(
        w.staging.pending().unwrap().is_empty(),
        "dropped by the rebase"
    );
    w.assert_placeholder_swept();
    w.session_snap(2);
    w.assert_queue_is_the_sessions();
    w.assert_ships();
}

/// `C`, `L`, `R`, `S`: let go before the rebase, which then drops it.
#[test]
fn a_placeholder_capture_released_before_the_rebase_is_dropped_by_it() {
    let w = world();
    assert!(w.staging.claim(&w.placeholder));
    w.staging.release();
    assert_eq!(
        w.staging.pending().unwrap().len(),
        1,
        "still the standby's own"
    );
    w.rebase();
    assert!(w.staging.pending().unwrap().is_empty());
    w.session_snap(2);
    w.assert_queue_is_the_sessions();
    w.assert_placeholder_swept();
    w.assert_ships();
}

/// `C`, `R`, `L`, `S`: the box (r2c2c, r2c3b). The rebase skips the entry in flight; the
/// shipper letting go of it drops it, so the snap never meets it.
#[test]
fn a_capture_in_flight_at_a_replan_never_folds_into_the_sessions_capture() {
    let w = world();
    assert!(w.staging.claim(&w.placeholder));
    w.rebase();
    assert_eq!(w.staging.pending().unwrap().len(), 1, "skipped: in flight");
    w.staging.release();
    assert!(
        w.staging.pending().unwrap().is_empty(),
        "dropped once the shipper let go of it"
    );
    w.assert_placeholder_swept();
    w.session_snap(2);
    w.assert_queue_is_the_sessions();
    w.assert_ships();
}

/// `C`, `R`, `S`, `L`: the session's capture takes the placeholder's `n` while the shipper is
/// still on the placeholder, and writes over its queue file. Letting go of the placeholder
/// must not remove the session's capture, and sweeps the placeholder's objects.
#[test]
fn letting_go_of_a_placeholder_capture_written_over_keeps_the_sessions_capture() {
    let w = world();
    assert!(w.staging.claim(&w.placeholder));
    w.rebase();
    w.session_snap(2);
    let pending = w.staging.pending().unwrap();
    assert_eq!(pending.len(), 1);
    assert_eq!(pending[0].n, w.placeholder.n, "the same chain position");
    assert_ne!(pending[0].capture_id, w.placeholder.capture_id);
    let session = pending[0].clone();
    w.staging.release();
    assert_eq!(w.staging.pending().unwrap(), vec![session]);
    w.assert_queue_is_the_sessions();
    w.assert_placeholder_swept();
    w.assert_ships();
}

/// `C`, `R`, `S`, `A`: the placeholder's register went through after all (a lease that was live
/// for it) and the shipper acks it after the session's capture wrote over its queue file. An
/// ack removes only the capture it shipped.
#[test]
fn an_ack_of_a_placeholder_capture_written_over_keeps_the_sessions_capture() {
    let w = world();
    assert!(w.staging.claim(&w.placeholder));
    w.rebase();
    w.session_snap(2);
    let session = w.staging.pending().unwrap();
    w.staging.ack(&w.placeholder).unwrap();
    w.staging.release();
    assert_eq!(
        w.staging.pending().unwrap(),
        session,
        "the session's capture stays"
    );
    w.assert_queue_is_the_sessions();
    w.assert_placeholder_swept();
    w.assert_ships();
}

/// `R`, then a claim by a shipper that read the queue before it: the entry is gone, nothing is
/// claimed, and the session's capture at that `n` is not claimed as if it were the placeholder.
#[test]
fn a_claim_read_before_the_rebase_claims_nothing_after_it() {
    let w = world();
    let read = w.staging.pending().unwrap();
    w.rebase();
    assert!(!w.staging.claim(&read[0]), "dropped by the rebase");
    w.session_snap(2);
    assert!(!w.staging.claim(&read[0]), "another capture at that n");
    w.assert_queue_is_the_sessions();
    w.assert_ships();
}

/// The box on the real shipper: its pass claims the placeholder capture and, while the register
/// is on the wire, the claim's re-plan rebases the engine; the register answers lease-lost.
/// That answer is the placeholder's: the pass drops it and pauses nothing.
#[test]
fn the_shipper_drops_a_placeholder_capture_a_replan_made_foreign_under_it() {
    let w = world();
    let (engine, channel, head) = (w.engine.clone(), Arc::downgrade(&w.channel), w.head.clone());
    *w.channel.on_standby_register.lock().unwrap() = Some(Box::new(move || {
        rebase(&engine, &channel.upgrade().unwrap(), &head);
    }));
    let shipper = w.shipper();
    assert_eq!(shipper.ship_pending().unwrap(), 0);
    assert!(
        w.staging.pending().unwrap().is_empty(),
        "dropped in the pass"
    );
    assert!(
        !shipper.status.snapshot().lease_lost,
        "the placeholder's lease-lost pauses nothing"
    );
    w.assert_placeholder_swept();
    w.session_snap(2);
    w.assert_queue_is_the_sessions();
    assert_eq!(
        shipper.ship_pending().unwrap(),
        1,
        "the same shipper ships it"
    );
    assert_eq!(w.channel.session.head().unwrap().n, 1);
}

/// The same, with the session's first snap landing while the register is on the wire: the pass
/// lets go of the placeholder, leaves the session's capture at that `n`, and ships it.
#[test]
fn the_shipper_ships_the_sessions_capture_written_over_a_placeholder_in_flight() {
    let w = world();
    let (engine, channel, head, root) = (
        w.engine.clone(),
        Arc::downgrade(&w.channel),
        w.head.clone(),
        w.root.clone(),
    );
    *w.channel.on_standby_register.lock().unwrap() = Some(Box::new(move || {
        rebase(&engine, &channel.upgrade().unwrap(), &head);
        fs::write(root.join("src/lib.rs"), "pub fn f() { session_work() }\n").unwrap();
        snap(
            engine.lock().unwrap().as_mut().unwrap(),
            CaptureKind::Auto,
            2,
        );
    }));
    let shipper = w.shipper();
    assert_eq!(
        shipper.ship_pending().unwrap(),
        1,
        "the session's capture, in the same pass"
    );
    assert!(w.staging.pending().unwrap().is_empty());
    w.assert_placeholder_swept();
    let head = w.channel.session.head().unwrap();
    assert_eq!(head.n, 1);
    assert_eq!(
        head.manifest.parent.as_deref(),
        Some(w.head.capture_id.as_str())
    );
}

/// A re-plan onto the identity the executor has (`capture.replan` answers `unchanged` without a
/// rebase; a rebase onto it changes nothing either): nothing the session staged is foreign, in
/// flight or not, and nothing is dropped.
#[test]
fn a_replan_onto_the_same_identity_drops_nothing_of_the_sessions() {
    let w = world();
    assert!(w.staging.claim(&w.placeholder));
    w.rebase();
    w.staging.release();
    w.session_snap(2);
    w.session_snap(3);
    let before = w.staging.pending().unwrap();
    assert!(w.staging.claim(&before[0]));
    // A second re-plan naming the same worktree, epoch and head.
    let previous = w.with_engine(|engine| engine.previous().cloned());
    w.with_engine(|engine| engine.rebase(SESSION, SESSION_EPOCH, previous).unwrap());
    assert_eq!(w.staging.discard_foreign().unwrap(), 0);
    w.staging.release();
    assert_eq!(w.staging.pending().unwrap(), before, "nothing dropped");
    w.assert_queue_is_the_sessions();
    w.assert_ships();
}

/// The daemon restarts between the rebase and the session's first snap, the placeholder still
/// queued (the shipper was on it): the engine opens under the session's identity and drops it,
/// and the next snap continues the session's head.
#[test]
fn a_restart_between_the_rebase_and_the_next_snap_drops_the_placeholder_capture() {
    let w = world();
    assert!(w.staging.claim(&w.placeholder));
    w.rebase();
    assert_eq!(w.staging.pending().unwrap().len(), 1);
    // The process dies with the claim held.
    let config = w.with_engine(|engine| engine.config().clone());
    drop(w.engine.lock().unwrap().take());
    let engine = CaptureEngine::open(config, Some(w.head.clone())).unwrap();
    let staging = engine.staging();
    assert!(staging.pending().unwrap().is_empty(), "dropped at open");
    *w.engine.lock().unwrap() = Some(engine);
    let w = World { staging, ..w };
    w.assert_placeholder_swept();
    w.session_snap(2);
    w.assert_queue_is_the_sessions();
    w.assert_ships();
}

/// A re-plan that fails before its rebase (the plan, the admission check, the materialize)
/// moves no identity: the placeholder capture is still the standby's own, kept and coalesced
/// with as before. The retry's rebase drops it.
#[test]
fn a_replan_that_fails_before_its_rebase_moves_nothing_and_its_retry_drops_the_placeholder() {
    let w = world();
    assert!(w.staging.claim(&w.placeholder));
    // The re-plan fails: no rebase. The shipper lets go.
    w.staging.release();
    assert_eq!(w.staging.pending().unwrap(), vec![w.placeholder.clone()]);
    assert!(!w.staging.is_foreign(&w.placeholder));
    // The retry lands while the shipper is on it again.
    assert!(w.staging.claim(&w.placeholder));
    w.rebase();
    w.staging.release();
    assert!(w.staging.pending().unwrap().is_empty());
    w.session_snap(2);
    w.assert_queue_is_the_sessions();
    w.assert_placeholder_swept();
    w.assert_ships();
}
