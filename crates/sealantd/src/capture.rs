//! The capture engine inside the daemon (ADR-0015): the cadence runner (watcher-fed small and
//! bulk clocks, the shipper worker), lease heartbeats with the fence that pauses the harness
//! (`SIGSTOP`, never kill), the `capture.*` / `lease.epoch` control commands, and the re-plan
//! that moves a standby executor onto the worktree the control plane assigned it.

use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use sealant_capture::manifest::BulkState;
use sealant_capture::registrar::{HeartbeatRequest, PlanGetRequest, RegistrarError};
use sealant_capture::{
    BlobSink, CadenceRunner, CaptureKind as EngineKind, MaterializeClass, Materializer, Registrar,
};
use sealant_protocol::{
    CaptureClass, CaptureKind, CaptureReplanned, CaptureStaged, CaptureStatusReport, ControlError,
    LeaseEpochReport, ProcessId, Signal,
};

use crate::boot::capture::{CaptureBoot, SharedMinter};
use crate::runtime::Runtime;

/// The error a capture command gets on a workspace without a capture store.
#[must_use]
pub fn not_enabled() -> ControlError {
    ControlError::feature_unavailable(
        "capture store is not enabled (SEALANT_WORKSPACE_SOURCE=capture)".to_owned(),
    )
}

fn engine_kind(kind: CaptureKind) -> EngineKind {
    match kind {
        CaptureKind::Auto => EngineKind::Auto,
        CaptureKind::Turn => EngineKind::Turn,
        CaptureKind::Checkpoint => EngineKind::Checkpoint,
        CaptureKind::Suspend => EngineKind::Suspend,
        CaptureKind::Final => EngineKind::Final,
    }
}

fn now_unix_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_millis() as u64)
}

/// The capture engine and its background loops.
pub struct CaptureRuntime {
    runner: CadenceRunner,
    registrar: Arc<dyn Registrar>,
    sink: Arc<dyn BlobSink>,
    minter: Option<SharedMinter>,
    /// The worktree and lease epoch this executor acts under; a re-plan moves them.
    identity: Mutex<(String, u64)>,
    grace: Duration,
    paused: AtomicBool,
    last_snap_unix_ms: AtomicU64,
    harness: Mutex<Option<ProcessId>>,
}

impl std::fmt::Debug for CaptureRuntime {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let (worktree_id, epoch) = self.identity();
        f.debug_struct("CaptureRuntime")
            .field("worktree_id", &worktree_id)
            .field("epoch", &epoch)
            .field("cadence", &self.runner.snapshot())
            .finish_non_exhaustive()
    }
}

impl CaptureRuntime {
    /// Wrap a materialized boot. `grace_ms` bounds every flush.
    #[must_use]
    pub fn new(boot: CaptureBoot, grace_ms: u64) -> Arc<Self> {
        let shipper = Arc::new(
            boot.engine
                .shipper(boot.sink.clone(), boot.registrar.clone()),
        );
        Arc::new(Self {
            runner: CadenceRunner::new(boot.engine, shipper),
            registrar: boot.registrar,
            sink: boot.sink,
            minter: boot.minter,
            identity: Mutex::new((boot.worktree_id, boot.epoch)),
            grace: Duration::from_millis(grace_ms),
            paused: AtomicBool::new(false),
            last_snap_unix_ms: AtomicU64::new(0),
            harness: Mutex::new(None),
        })
    }

    fn identity(&self) -> (String, u64) {
        self.identity
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .clone()
    }

    /// Start the cadence runner (watcher, class clocks, ship worker) and the heartbeat loop.
    /// `harness` is the process the fence pauses and resumes.
    pub fn start(self: &Arc<Self>, runtime: Arc<Runtime>, harness: ProcessId) {
        *self.harness.lock().unwrap_or_else(|e| e.into_inner()) = Some(harness);
        let cadence = self.runner.with_engine(|e| e.config().cadence);

        // Scheduled snaps stop once the daemon is hard-stopping; forced ones (flush) still run.
        let rt = runtime.clone();
        self.runner
            .start(Some(Arc::new(move || !rt.shutdown().is_hard())));

        // Heartbeat and fence (amendment decision 8): pause on a 409 or once the lease TTL
        // elapses without a successful heartbeat; resume when a later heartbeat succeeds with
        // the same epoch.
        let this = Arc::clone(self);
        tokio::spawn(async move {
            let mut ticker = tokio::time::interval(cadence.heartbeat);
            ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
            let mut last_ok = Instant::now();
            loop {
                ticker.tick().await;
                let registrar = this.registrar.clone();
                let (worktree_id, epoch) = this.identity();
                let req = HeartbeatRequest { worktree_id, epoch };
                let result =
                    tokio::task::spawn_blocking(move || registrar.lease_heartbeat(&req)).await;
                match result {
                    Ok(Ok(_)) => {
                        last_ok = Instant::now();
                        if this.paused.load(Ordering::Relaxed) && !this.runner.shipper().is_fenced()
                        {
                            this.resume(&runtime);
                        }
                    }
                    Ok(Err(error @ RegistrarError::Fenced { .. })) => {
                        // A fence answered to an identity a re-plan replaced meanwhile is stale.
                        if this.identity().1 != epoch {
                            continue;
                        }
                        tracing::warn!(%error, "lease fenced; pausing the harness");
                        this.runner
                            .shipper()
                            .status
                            .fenced
                            .store(true, Ordering::Relaxed);
                        this.pause(&runtime);
                    }
                    Ok(Err(error)) => {
                        tracing::warn!(%error, "lease heartbeat failed");
                        if last_ok.elapsed() >= cadence.lease_ttl {
                            this.pause(&runtime);
                        }
                    }
                    Err(error) => tracing::warn!(%error, "heartbeat task failed"),
                }
            }
        });
    }

    fn pause(&self, runtime: &Runtime) {
        if self.paused.swap(true, Ordering::Relaxed) {
            return;
        }
        let harness = self
            .harness
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .clone();
        if let Some(id) = harness
            && let Err(error) = runtime.signal_process(&id, Signal::Stop)
        {
            tracing::warn!(%error, "could not pause the harness");
        }
    }

    fn resume(&self, runtime: &Runtime) {
        if !self.paused.swap(false, Ordering::Relaxed) {
            return;
        }
        let harness = self
            .harness
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .clone();
        if let Some(id) = harness
            && let Err(error) = runtime.signal_process(&id, Signal::Cont)
        {
            tracing::warn!(%error, "could not resume the harness");
        }
        tracing::info!("lease heartbeat succeeded; harness resumed");
    }

    /// Take a small-class snap ahead of the timers (a turn boundary, a checkpoint) and stage
    /// it; the worker ships it. A bulk build in progress yields to it. Blocking.
    ///
    /// # Errors
    /// Returns [`ControlError`] when the snap fails.
    pub fn snap(&self, kind: CaptureKind) -> Result<CaptureStaged, ControlError> {
        let staged = self
            .runner
            .snap(engine_kind(kind))
            .map_err(|error| ControlError::internal(error.to_string()))?;
        self.last_snap_unix_ms
            .store(now_unix_ms(), Ordering::Relaxed);
        Ok(CaptureStaged {
            n: staged.n,
            capture_id: staged.manifest.capture_id,
            kind,
            unchanged: staged.unchanged,
        })
    }

    /// Final snap of `kind`, then ship and register everything pending, bounded by
    /// `min(deadline, grace)`. Blocking.
    ///
    /// # Errors
    /// Returns [`ControlError`] when the snap fails or shipping stops on a fence.
    pub fn flush(
        &self,
        kind: CaptureKind,
        deadline: Duration,
    ) -> Result<CaptureStatusReport, ControlError> {
        let deadline = deadline.min(self.grace);
        self.runner
            .flush(engine_kind(kind), deadline)
            .map_err(|error| ControlError::internal(error.to_string()))?;
        self.last_snap_unix_ms
            .store(now_unix_ms(), Ordering::Relaxed);
        Ok(self.status())
    }

    /// Fetch the plan again and bring the workspace to it (`capture.replan`). A standby booted
    /// on the project base under a placeholder identity; once the control plane assigns it a
    /// worktree the plan names that worktree, its lease epoch and its chain head, and the head
    /// is materialized as a delta over what is on disk. No snap runs meanwhile; entries staged
    /// under the old identity are dropped, the fence lifted, the cadence resumes. Idempotent:
    /// a plan naming what the executor already has changes nothing. Blocking.
    ///
    /// # Errors
    /// Returns [`ControlError`] when the channel refuses the plan or the head cannot be
    /// materialized; the identity is unchanged then.
    pub fn replan(&self) -> Result<CaptureReplanned, ControlError> {
        let internal = |error: &dyn std::fmt::Display| ControlError::internal(error.to_string());
        self.runner.with_engine_mut(|engine| {
            // Epoch 0: the plan of an executor that holds nothing yet; the registrar answers
            // the lease it holds for this executor, or claims the worktree for it.
            let plan = self
                .registrar
                .plan_get(&PlanGetRequest::booting(None))
                .map_err(|e| internal(&format!("capture plan.get failed: {e}")))?;
            let (worktree_id, epoch) = self.identity();
            let same_identity = plan.worktree_id == worktree_id && plan.epoch == epoch;
            let same_head = plan.head.as_ref().map(|h| h.capture_id.as_str())
                == engine.previous().map(|p| p.capture_id.as_str());
            let head_n = plan.head.as_ref().map(|h| h.n);
            let head_capture_id = plan.head.as_ref().map(|h| h.capture_id.clone());
            if same_identity && same_head {
                return Ok(CaptureReplanned {
                    worktree_id,
                    epoch,
                    head_n,
                    head_capture_id,
                    files_written: 0,
                    bytes_written: 0,
                    files_skipped: 0,
                    bytes_skipped: 0,
                    removed: 0,
                    unchanged: true,
                });
            }
            tracing::info!(
                from_worktree = %worktree_id,
                from_epoch = epoch,
                worktree = %plan.worktree_id,
                epoch = plan.epoch,
                head = ?head_n,
                "capture re-plan"
            );
            if let Some(minter) = &self.minter {
                minter.reset(&plan.worktree_id, plan.epoch, plan.get_urls.clone());
            }
            let (previous, report) = match &plan.head {
                Some(head) => {
                    let targets = engine.materialize_targets();
                    let mut manifest = Materializer::new(self.sink.as_ref(), targets)
                        .fetch_manifest(&head.manifest_key, &head.capture_id)
                        .map_err(|e| internal(&format!("capture head manifest: {e}")))?;
                    // The plan's answer decides the bulk section (another platform's stays
                    // pending), as at boot.
                    if head.manifest.sections.bulk.section().is_none() {
                        manifest.manifest.sections.bulk = BulkState::pending();
                    }
                    let report = engine
                        .materialize_delta(
                            self.sink.as_ref(),
                            &manifest.manifest,
                            MaterializeClass::All,
                        )
                        .map_err(|e| internal(&format!("capture materialize failed: {e}")))?;
                    tracing::info!(
                        files = report.files,
                        bytes = report.bytes,
                        files_skipped = report.files_skipped,
                        bytes_skipped = report.bytes_skipped,
                        removed = report.removed,
                        git_packs = report.git_packs,
                        git_paths_changed = ?report.git_paths_changed,
                        fsck = ?report.fsck,
                        "capture head materialized over the disk"
                    );
                    (Some(manifest), report)
                }
                None => {
                    tracing::warn!(
                        "capture chain is empty after re-plan; continuing from capture 0"
                    );
                    (None, Default::default())
                }
            };
            engine
                .rebase(&plan.worktree_id, plan.epoch, previous)
                .map_err(|e| internal(&format!("capture engine rebase: {e}")))?;
            self.runner.shipper().reset_after_replan(head_n);
            *self.identity.lock().unwrap_or_else(|e| e.into_inner()) =
                (plan.worktree_id.clone(), plan.epoch);
            Ok(CaptureReplanned {
                worktree_id: plan.worktree_id,
                epoch: plan.epoch,
                head_n,
                head_capture_id,
                files_written: report.files,
                bytes_written: report.bytes,
                files_skipped: report.files_skipped,
                bytes_skipped: report.bytes_skipped,
                removed: report.removed,
                unchanged: false,
            })
        })
    }

    /// Current state.
    #[must_use]
    pub fn status(&self) -> CaptureStatusReport {
        let ship = self.runner.shipper().status.snapshot();
        let staging = self.runner.staging();
        let pending = staging.pending().map(|p| p.len() as u64).unwrap_or(0);
        let staged_bytes = staging.staged_bytes().unwrap_or(0);
        let last = self.last_snap_unix_ms.load(Ordering::Relaxed);
        let (worktree_id, epoch) = self.identity();
        CaptureStatusReport {
            epoch,
            worktree_id,
            head_n: ship.head_n,
            pending,
            staged_bytes,
            uploaded_objects: ship.uploaded_objects,
            uploaded_bytes: ship.uploaded_bytes,
            registered: ship.registered,
            fenced: ship.fenced,
            paused: self.paused.load(Ordering::Relaxed),
            last_snap_unix_ms: (last != 0).then_some(last),
            refused: [
                ship.refused_small.then_some(CaptureClass::Small),
                ship.refused_bulk.then_some(CaptureClass::Bulk),
            ]
            .into_iter()
            .flatten()
            .collect(),
        }
    }

    /// The cadence runner (its counters, a manual signal).
    #[must_use]
    pub fn runner(&self) -> &CadenceRunner {
        &self.runner
    }

    /// The lease epoch.
    #[must_use]
    pub fn lease_epoch(&self) -> LeaseEpochReport {
        let (worktree_id, epoch) = self.identity();
        LeaseEpochReport {
            epoch,
            worktree_id,
            fenced: self.runner.shipper().is_fenced(),
        }
    }
}

#[cfg(test)]
mod tests {
    use std::path::Path;
    use std::process::Command as Proc;
    use std::time::Instant;

    use sealant_capture::registrar::HeadInfo;
    use sealant_capture::{
        BlobSink, CaptureConfig, CaptureEngine, CaptureKind as EngineKind, Class,
        InMemoryRegistrar, LocalDir, SnapRequest,
    };
    use sealant_protocol::{Command, CommandResult, ControlRequest, RequestId, ResponseOutcome};
    use sealant_runtime_core::{RuntimeConfig, new_runtime_id};

    use super::*;
    use crate::boot::capture::boot_from;
    use crate::boot::config::CaptureSourceConfig;
    use crate::shutdown::ShutdownSignal;

    fn git(root: &Path, args: &[&str]) {
        let out = Proc::new("git")
            .current_dir(root)
            .env("GIT_OPTIONAL_LOCKS", "0")
            .args(args)
            .output()
            .expect("git");
        assert!(out.status.success(), "git {args:?}");
    }

    fn boot(base: &Path) -> (CaptureBoot, Arc<InMemoryRegistrar>) {
        let root = base.join("ws");
        std::fs::create_dir_all(root.join("src")).unwrap();
        git(&root, &["init", "-q", "-b", "main"]);
        git(&root, &["config", "user.email", "t@t"]);
        git(&root, &["config", "user.name", "t"]);
        std::fs::write(root.join("src/lib.rs"), "pub fn f() {}\n").unwrap();
        git(&root, &["add", "-A"]);
        git(&root, &["commit", "-q", "-m", "one"]);
        let registrar = Arc::new(InMemoryRegistrar::new("wt-hooks", 1, None));
        let sink: Arc<dyn BlobSink> = Arc::new(LocalDir::new(&base.join("store")).unwrap());
        let engine = CaptureEngine::open(CaptureConfig::new("wt-hooks", 1, &root), None).unwrap();
        let dyn_registrar: Arc<dyn Registrar> = registrar.clone();
        (
            CaptureBoot {
                engine,
                sink,
                registrar: dyn_registrar,
                minter: None,
                worktree_id: "wt-hooks".to_owned(),
                epoch: 1,
            },
            registrar,
        )
    }

    fn wait_chain(registrar: &InMemoryRegistrar, n: usize) -> Vec<HeadInfo> {
        let start = Instant::now();
        loop {
            let chain = registrar.chain();
            if chain.len() >= n {
                return chain;
            }
            assert!(
                start.elapsed() < Duration::from_secs(10),
                "chain reaches {n}"
            );
            std::thread::sleep(Duration::from_millis(25));
        }
    }

    /// `capture.now {kind: turn}`, `capture.flush`, `runtime.gracefulShutdown` and the signal
    /// listener's `flush_captures` each force a small-class snap ahead of the timers (the tree
    /// is quiet throughout: no scheduled snap would fire).
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn control_hooks_force_a_small_snap_ahead_of_the_timers() {
        let tmp = tempfile::tempdir().unwrap();
        let (boot, registrar) = boot(tmp.path());
        let mut config = RuntimeConfig::new(new_runtime_id());
        config.workspace_root = tmp.path().join("ws");
        let runtime = Runtime::new(config, Arc::new(ShutdownSignal::new(5_000)));
        runtime.mark_healthy();
        let capture = CaptureRuntime::new(boot, 5_000);
        assert!(runtime.install_capture(capture.clone()));
        capture.start(runtime.clone(), ProcessId::new("p-harness"));
        let before = capture.runner().snapshot();
        assert_eq!(before.small_snaps, 0);

        // Turn boundary: staged now, shipped by the worker.
        let resp = runtime
            .dispatch(ControlRequest::new(
                RequestId::new("r1"),
                Command::CaptureNow {
                    kind: CaptureKind::Turn,
                },
            ))
            .await;
        let ResponseOutcome::Ok {
            result: Some(CommandResult::CaptureStaged(staged)),
        } = resp.outcome
        else {
            panic!("capture.now: {:?}", resp.outcome);
        };
        assert_eq!(staged.kind, CaptureKind::Turn);
        assert!(!staged.unchanged);
        let chain = wait_chain(&registrar, 1);
        assert_eq!(chain[0].manifest.kind, EngineKind::Turn);
        assert_eq!(capture.runner().snapshot().forced, 1);

        // Flush: a suspend snap, then everything pending registered before it returns.
        let resp = runtime
            .dispatch(ControlRequest::new(
                RequestId::new("r2"),
                Command::CaptureFlush,
            ))
            .await;
        let ResponseOutcome::Ok {
            result: Some(CommandResult::CaptureStatus(report)),
        } = resp.outcome
        else {
            panic!("capture.flush: {:?}", resp.outcome);
        };
        assert_eq!(report.pending, 0);
        let chain = registrar.chain();
        assert_eq!(chain.len(), 2);
        assert_eq!(chain[1].manifest.kind, EngineKind::Suspend);

        // The signal listener's path (SIGTERM / SIGINT): a final snap, flushed.
        runtime.flush_captures(CaptureKind::Final).await;
        let chain = registrar.chain();
        assert_eq!(chain.len(), 3);
        assert_eq!(chain[2].manifest.kind, EngineKind::Final);

        // `runtime.gracefulShutdown` flushes before requesting the shutdown.
        let resp = runtime
            .dispatch(ControlRequest::new(
                RequestId::new("r3"),
                Command::RuntimeGracefulShutdown {
                    grace_millis: Some(1_000),
                },
            ))
            .await;
        assert!(matches!(
            resp.outcome,
            ResponseOutcome::Ok {
                result: Some(CommandResult::ShutdownAccepted(_))
            }
        ));
        let chain = registrar.chain();
        assert_eq!(chain.len(), 4);
        assert_eq!(chain[3].manifest.kind, EngineKind::Final);
        let snap = capture.runner().snapshot();
        assert_eq!(snap.forced, 4, "{snap:?}");
        assert_eq!(snap.small_snaps, 4, "no scheduled snap fired: {snap:?}");
    }

    /// A class the registrar refused for the session's byte quota is named in `capture.status`,
    /// and a re-plan lifts it (the refusal belonged to the previous epoch).
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn capture_status_names_the_refused_classes() {
        let tmp = tempfile::tempdir().unwrap();
        let (boot, _registrar) = boot(tmp.path());
        let capture = CaptureRuntime::new(boot, 5_000);
        assert!(capture.status().refused.is_empty());

        capture
            .runner()
            .shipper()
            .status
            .refused_bulk
            .store(true, Ordering::Relaxed);
        assert_eq!(capture.status().refused, vec![CaptureClass::Bulk]);

        capture.runner().shipper().reset_after_replan(Some(0));
        assert!(capture.status().refused.is_empty());
    }

    /// The standby flow end to end: the project base is captured for `wt-real` (epoch 1); a
    /// standby boots against the placeholder `standby-1` (epoch 7) and materializes that base;
    /// the session then moves the chain on (an edit, a new bulk file) and the control plane
    /// assigns the standby the real worktree; `capture.replan` fetches the plan, materializes
    /// the head as a delta, takes the identity, and the next capture continues the chain under
    /// `captures/wt-real/1/`. A second `capture.replan` changes nothing.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn replan_moves_a_standby_onto_its_worktree() {
        let tmp = tempfile::tempdir().unwrap();
        let src = tmp.path().join("src");
        std::fs::create_dir_all(src.join("node_modules/pkg")).unwrap();
        git(&src, &["init", "-q", "-b", "main"]);
        git(&src, &["config", "user.email", "t@t"]);
        git(&src, &["config", "user.name", "t"]);
        std::fs::write(src.join(".gitignore"), "node_modules/\n").unwrap();
        std::fs::write(src.join("lib.rs"), "pub fn f() {}\n").unwrap();
        for i in 0..50 {
            std::fs::write(
                src.join(format!("node_modules/pkg/m{i}.js")),
                format!("module.exports = {i};\n").repeat(40),
            )
            .unwrap();
        }
        git(&src, &["add", "-A"]);
        git(&src, &["commit", "-q", "-m", "one"]);
        let store = Arc::new(LocalDir::new(&tmp.path().join("store")).unwrap());
        let sink: Arc<dyn BlobSink> = store.clone();
        // The base chain belongs to wt-real at epoch 1.
        let registrar = Arc::new(InMemoryRegistrar::new("wt-real", 1, None));
        let dyn_registrar: Arc<dyn Registrar> = registrar.clone();
        let mut source = CaptureEngine::open(CaptureConfig::new("wt-real", 1, &src), None).unwrap();
        let shipper = source.shipper(sink.clone(), dyn_registrar.clone());
        for (class, seq) in [(Class::Small, 1), (Class::Bulk, 2)] {
            source
                .snap(SnapRequest {
                    kind: EngineKind::Checkpoint,
                    class,
                    seq,
                })
                .unwrap();
        }
        shipper.ship_pending().unwrap();
        let base = registrar.head().unwrap();
        assert_eq!(base.n, 1);

        // A standby boots against the placeholder and materializes the base.
        registrar.set_worktree_id("standby-1");
        registrar.set_live_epoch(7);
        let ws = tmp.path().join("ws");
        let boot = boot_from(
            dyn_registrar.clone(),
            Some(sink.clone()),
            &CaptureSourceConfig {
                endpoint: "http://unused".to_owned(),
                worktree_id: None,
                harness_home: None,
                raise_inotify_limit: false,
            },
            &ws,
        )
        .unwrap();
        assert_eq!((boot.worktree_id.as_str(), boot.epoch), ("standby-1", 7));
        assert_eq!(
            std::fs::read_to_string(ws.join("lib.rs")).unwrap(),
            "pub fn f() {}\n"
        );
        assert!(ws.join("node_modules/pkg/m49.js").exists());
        let mut config = RuntimeConfig::new(new_runtime_id());
        config.workspace_root = ws.clone();
        let runtime = Runtime::new(config, Arc::new(ShutdownSignal::new(5_000)));
        runtime.mark_healthy();
        let capture = CaptureRuntime::new(boot, 5_000);
        assert!(runtime.install_capture(capture.clone()));
        capture.start(runtime.clone(), ProcessId::new("p-harness"));
        assert_eq!(capture.lease_epoch().worktree_id, "standby-1");

        // The chain moves on under wt-real while the standby waits.
        registrar.set_worktree_id("wt-real");
        registrar.set_live_epoch(1);
        std::fs::write(src.join("lib.rs"), "pub fn f() { g() }\n").unwrap();
        git(&src, &["commit", "-q", "-am", "two"]);
        std::fs::write(src.join("node_modules/pkg/extra.js"), "extra\n").unwrap();
        std::fs::remove_file(src.join("node_modules/pkg/m0.js")).unwrap();
        for (class, seq) in [(Class::Small, 3), (Class::Bulk, 4)] {
            source
                .snap(SnapRequest {
                    kind: EngineKind::Checkpoint,
                    class,
                    seq,
                })
                .unwrap();
        }
        shipper.ship_pending().unwrap();
        let head = registrar.head().unwrap();
        assert_eq!(head.n, 3);

        // Claim: the plan now names wt-real at epoch 1 with head n=3.
        let resp = runtime
            .dispatch(ControlRequest::new(
                RequestId::new("r1"),
                Command::CaptureReplan,
            ))
            .await;
        let ResponseOutcome::Ok {
            result: Some(CommandResult::CaptureReplanned(replanned)),
        } = resp.outcome
        else {
            panic!("capture.replan: {:?}", resp.outcome);
        };
        eprintln!("replanned: {replanned:?}");
        assert_eq!(replanned.worktree_id, "wt-real");
        assert_eq!(replanned.epoch, 1);
        assert_eq!(replanned.head_n, Some(3));
        assert_eq!(
            replanned.head_capture_id.as_deref(),
            Some(head.capture_id.as_str())
        );
        assert!(!replanned.unchanged);
        // extra.js plus the `.git` bookkeeping a commit touches (index, reflogs, COMMIT_EDITMSG).
        assert!(
            (1..=8).contains(&replanned.files_written),
            "extra.js and .git bookkeeping: {replanned:?}"
        );
        assert!(
            replanned.files_skipped >= 49,
            "the untouched bulk files: {replanned:?}"
        );
        assert_eq!(replanned.removed, 1, "m0.js: {replanned:?}");
        assert!(replanned.bytes_skipped > replanned.bytes_written * 10);
        assert_eq!(
            std::fs::read_to_string(ws.join("lib.rs")).unwrap(),
            "pub fn f() { g() }\n"
        );
        assert!(ws.join("node_modules/pkg/extra.js").exists());
        assert!(!ws.join("node_modules/pkg/m0.js").exists());
        let lease = capture.lease_epoch();
        assert_eq!(
            (lease.worktree_id.as_str(), lease.epoch, lease.fenced),
            ("wt-real", 1, false)
        );
        assert_eq!(capture.status().head_n, Some(3));

        // The next capture continues the chain as wt-real at epoch 1 from the head.
        std::fs::write(ws.join("agent.txt"), "written by the session\n").unwrap();
        let resp = runtime
            .dispatch(ControlRequest::new(
                RequestId::new("r2"),
                Command::CaptureNow {
                    kind: CaptureKind::Turn,
                },
            ))
            .await;
        let ResponseOutcome::Ok {
            result: Some(CommandResult::CaptureStaged(staged)),
        } = resp.outcome
        else {
            panic!("capture.now: {:?}", resp.outcome);
        };
        assert_eq!(staged.n, 4);
        let chain = wait_chain(&registrar, 5);
        let next = &chain[4].manifest;
        assert_eq!(
            (next.worktree_id.as_str(), next.epoch, next.n),
            ("wt-real", 1, 4)
        );
        assert_eq!(next.parent.as_deref(), Some(head.capture_id.as_str()));
        assert!(
            next.sections
                .workspace
                .packs
                .iter()
                .all(|k| k.starts_with("captures/wt-real/1/"))
        );
        assert!(
            next.sections
                .git
                .packs
                .iter()
                .any(|k| k.starts_with("captures/wt-real/1/")),
            "the session's commit pack ships under its own prefix"
        );
        assert_eq!(
            next.sections.bulk, head.manifest.sections.bulk,
            "bulk carried from the head"
        );

        // Same plan again: nothing to do.
        let resp = runtime
            .dispatch(ControlRequest::new(
                RequestId::new("r3"),
                Command::CaptureReplan,
            ))
            .await;
        let ResponseOutcome::Ok {
            result: Some(CommandResult::CaptureReplanned(again)),
        } = resp.outcome
        else {
            panic!("capture.replan: {:?}", resp.outcome);
        };
        assert!(again.unchanged);
        assert_eq!(again.head_n, Some(4));
        assert_eq!(capture.status().pending, 0);
    }
}
