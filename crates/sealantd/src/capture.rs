//! The capture engine inside the daemon (ADR-0015): the cadence runner (watcher-fed small and
//! bulk clocks, the shipper worker), lease heartbeats with the fence that pauses the harness
//! (`SIGSTOP`, never kill), the `capture.*` / `lease.epoch` control commands, and the re-plan
//! that moves a standby executor onto the worktree the control plane assigned it.

use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use sealant_capture::manifest::DirFormat;
use sealant_capture::registrar::{HeartbeatRequest, PlanGetRequest, RegistrarError};
use sealant_capture::{
    BlobSink, CadenceRunner, CaptureKind as EngineKind, Class, MaterializeClass, Materializer,
    Registrar,
};
use sealant_protocol::{
    CaptureClass, CaptureClassSnaps, CaptureKind, CaptureReplanned, CaptureStaged,
    CaptureStatusReport, ControlError, ControlErrorCode, LeaseEpochReport, ProcessId, Signal,
};

use crate::boot::capture::{CaptureBoot, SharedMinter, SourceLayout};
use crate::boot::remotes;
use crate::boot::sources;
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

/// What the last final flush on this executor came to.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum FinalOutcome {
    /// No final flush has run.
    NotRun,
    /// A final flush is running (stopping the writers, snapping, shipping), and the disk is
    /// not known to be as a completed one left it.
    Running,
    /// Every writer stopped and both classes snapped after that: complete once nothing is
    /// pending (the ship worker keeps going after a flush that returned at its deadline).
    /// `shipping` is why that flush returned with captures pending (`deadline`,
    /// `ship-failed`), reported while they are.
    Snapped { shipping: Option<&'static str> },
    /// It cannot complete as it went; the reason code.
    Incomplete(&'static str),
}

/// How a report judges whether the disk is still as the last final flush captured it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Currency {
    /// As that flush's own answer: its snaps read every class after every writer stopped.
    AsSnapped,
    /// Now: only a class the watcher sees can be vouched for since those snaps.
    Now,
}

/// The capture engine and its background loops.
pub struct CaptureRuntime {
    runner: CadenceRunner,
    registrar: Arc<dyn Registrar>,
    sink: Arc<dyn BlobSink>,
    minter: Option<SharedMinter>,
    /// The worktree and lease epoch this executor acts under; a re-plan moves them.
    identity: Mutex<(String, u64)>,
    /// Where content the plan names beside the worktree lands.
    layout: SourceLayout,
    paused: AtomicBool,
    last_snap_unix_ms: AtomicU64,
    /// What each class's last snap could not read (never waits on a build in progress).
    reads: Arc<sealant_capture::ReadReports>,
    harness: Mutex<Option<ProcessId>>,
    /// The boot left a disk that continued the chain as it was (`CaptureBoot::resumed`).
    resumed: bool,
    /// The last final flush's outcome, reported as `complete` / `incomplete_reason`.
    final_outcome: Mutex<FinalOutcome>,
    /// The executor `plan.get` named (the launch); a re-plan moves it.
    launch: Mutex<Option<String>>,
    /// Where each answer stands ([`sealant_capture::position`]), shared with the engine's seals.
    observer: Arc<sealant_capture::position::Observer>,
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
    /// Wrap a materialized boot.
    #[must_use]
    pub fn new(boot: CaptureBoot) -> Arc<Self> {
        let shipper = Arc::new(
            boot.engine
                .shipper(boot.sink.clone(), boot.registrar.clone()),
        );
        let resumed = boot.resumed;
        let reads = boot.engine.read_reports();
        let launch = boot.engine.config().executor.clone();
        let observer = boot.engine.observer();
        Arc::new(Self {
            runner: CadenceRunner::new(boot.engine, shipper),
            resumed,
            registrar: boot.registrar,
            sink: boot.sink,
            minter: boot.minter,
            identity: Mutex::new((boot.worktree_id, boot.epoch)),
            layout: boot.layout,
            paused: AtomicBool::new(false),
            last_snap_unix_ms: AtomicU64::new(0),
            reads,
            harness: Mutex::new(None),
            final_outcome: Mutex::new(FinalOutcome::NotRun),
            launch: Mutex::new(launch),
            observer,
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
        self.start_with(runtime, Some(harness));
    }

    /// [`Self::start`] with no harness to pause on a fence: a recovery boot runs none, and a boot
    /// starts the engine this way before any user code runs, attaching the harness once it is
    /// launched ([`Self::attach_harness`]).
    pub fn start_without_harness(self: &Arc<Self>, runtime: Arc<Runtime>) {
        self.start_with(runtime, None);
    }

    /// The harness this boot launched after the engine started ([`Self::start_without_harness`]
    /// runs first, before any user code): the process the fence pauses and resumes from now
    /// on. A fence that paused the engine before the harness existed pauses it at once.
    pub fn attach_harness(&self, runtime: &Runtime, harness: ProcessId) {
        *self.harness.lock().unwrap_or_else(|e| e.into_inner()) = Some(harness.clone());
        if self.paused.load(Ordering::Relaxed)
            && let Err(error) = runtime.signal_process(&harness, Signal::Stop)
        {
            tracing::warn!(%error, "could not pause the harness");
        }
    }

    fn start_with(self: &Arc<Self>, runtime: Arc<Runtime>, harness: Option<ProcessId>) {
        *self.harness.lock().unwrap_or_else(|e| e.into_inner()) = harness;
        let cadence = self.runner.with_engine(|e| e.config().cadence);

        // Scheduled snaps stop once the daemon is hard-stopping, and once a final flush stopped
        // every writer: its forced snaps are the last, and a scheduled one after them (a bulk
        // build resuming after the forced one, the clocks firing on what the watcher saw) only
        // kept a build running past `complete`. Forced ones (flush, turn) still run.
        let rt = runtime.clone();
        self.runner.start(Some(Arc::new(move || {
            !rt.shutdown().is_hard() && !rt.writers_stopped()
        })));
        // No process alive at a final flush's seal (review 2026-09-28, sixth pass, #1).
        let rt = runtime.clone();
        self.runner
            .set_census(Some(Arc::new(move || rt.census_writers())));
        // A disk the boot resumed may have changed after its last snap, while no watcher ran:
        // both classes are snapped on their quiet clocks, as after any change.
        if self.resumed {
            self.runner
                .signal(sealant_capture::ChangeSignal::Changed(Class::Small));
            self.runner
                .signal(sealant_capture::ChangeSignal::Changed(Class::Bulk));
        }

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
                    // 404 (or 409) `lease-lost`: the lease is not live. Pause now, adopt no
                    // epoch, and resume when a heartbeat under this identity succeeds again
                    // (Mend round 4).
                    Ok(Err(error @ RegistrarError::LeaseLost)) => {
                        if this.identity().1 != epoch {
                            continue;
                        }
                        tracing::warn!(%error, "lease lost; pausing the harness");
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

    /// A suspend flush: a forced small-class snap, then ship and register every capture ahead
    /// of a bulk capture still uploading, bounded by `deadline` as the caller gave it (or the
    /// shutdown grace) — never clamped to the grace when given (it once was, to 10 s, which cut
    /// every flush of a dependency tree short). The report says what is left (`pending`,
    /// `pending_bulk`, `pending_bytes`, `refused`). Blocking.
    ///
    /// # Errors
    /// Returns [`ControlError`] when the snap fails or shipping stops on a fence or a conflict.
    pub fn flush_suspend(&self, deadline: Duration) -> Result<CaptureStatusReport, ControlError> {
        // After a complete final flush, over the disk it captured, a suspend flush is a status
        // read: it answers the final flush's report and stages nothing (a suspend capture of
        // the same tree after the final one left the chain's head reading `suspend`).
        if self.runner.sealed_and_current() {
            return Ok(self.status());
        }
        self.runner
            .flush(EngineKind::Suspend, Some(deadline))
            .map_err(|error| ControlError::internal(error.to_string()))?;
        self.last_snap_unix_ms
            .store(now_unix_ms(), Ordering::Relaxed);
        Ok(self.status())
    }

    /// The capture half of a final flush ([`Runtime::final_flush`] stops the writers first; when
    /// it could not stop them all, or cannot know it did, `quiesce` is why: `processes-remain`,
    /// `sweep-unavailable`): a small-class and a bulk-class snap, both forced, then ship
    /// everything, bulk included, bounded by `deadline` (none: until it is complete, or never
    /// can be). Records the outcome and reports it as `complete` / `incomplete_reason`: the
    /// quiesce's reason first, else `snapshot-failed`, `fenced`, `conflict`, `deadline` or
    /// `ship-failed`. Never an error: an incomplete flush is an answer, not a failure to answer.
    /// Blocking.
    pub fn flush_final(
        &self,
        deadline: Option<Duration>,
        quiesce: Option<&'static str>,
    ) -> CaptureStatusReport {
        // The chain is sealed ([`sealant_capture::FinalSeal`]) only when every writer stopped.
        let flushed = self.runner.flush_final_sealing(deadline, quiesce.is_none());
        self.last_snap_unix_ms
            .store(now_unix_ms(), Ordering::Relaxed);
        let outcome = match (quiesce, &flushed.incomplete) {
            (Some(reason), _) => FinalOutcome::Incomplete(reason),
            (None, None) => FinalOutcome::Snapped { shipping: None },
            // Shipping did not finish by the deadline: the worker keeps shipping, and the
            // flush is complete once it has (`capture.status`, or the same flush again).
            (
                None,
                Some(
                    incomplete @ (sealant_capture::Incomplete::Deadline { .. }
                    | sealant_capture::Incomplete::ShipFailed(_)),
                ),
            ) => FinalOutcome::Snapped {
                shipping: Some(incomplete.reason()),
            },
            (None, Some(incomplete)) => FinalOutcome::Incomplete(incomplete.reason()),
        };
        if let Some(incomplete) = &flushed.incomplete {
            tracing::error!(reason = incomplete.reason(), %incomplete, "final capture flush incomplete");
        }
        *self.final_outcome.lock().unwrap_or_else(|e| e.into_inner()) = outcome;
        // The flush's own answer: its snaps, taken after every writer stopped, read every
        // class as it was — a class that polls included (before, a polled class made every
        // final flush answer `changed`, and a daemon whose bulk class polled never exited 0).
        self.report(Currency::AsSnapped)
    }

    /// A final flush begins ([`Runtime::final_flush`], before it stops the writers):
    /// `capture.status` reads `in-progress` until it ends — unless the last one completed, the
    /// disk is as it left it and the chain still ends on its final capture
    /// ([`CadenceRunner::sealed_and_current`]), when this one snaps nothing and the status stays
    /// `complete` throughout.
    pub fn begin_final(&self) {
        let mut outcome = self.final_outcome.lock().unwrap_or_else(|e| e.into_inner());
        let current = matches!(*outcome, FinalOutcome::Snapped { .. })
            && self.runner.sealed_and_current()
            && self.runner.final_sealed();
        if !current {
            *outcome = FinalOutcome::Running;
        }
    }

    /// The daemon's shutdown deadline ([`Runtime::shutdown_final_flush`]): no flush ships past
    /// `at`, whatever deadline its caller gave (a control plane's final flush without one
    /// included), and what is left stays staged.
    pub fn set_shutdown_cutoff(&self, at: Instant) {
        self.runner.shipper().set_cutoff(at);
    }

    /// Record a final flush that could not finish for a reason outside the engine (its task
    /// failed).
    pub fn record_final_incomplete(&self, reason: &'static str) {
        *self.final_outcome.lock().unwrap_or_else(|e| e.into_inner()) =
            FinalOutcome::Incomplete(reason);
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
            // No writer admission without full fidelity (decision 16; review 2026-09-28, fifth
            // pass, #5): a standby claimed onto a store that cannot hold what a capture holds
            // is refused before it touches the disk, and no harness is started on it.
            let mut assigned = engine.config().clone();
            assigned.set_store_features(&plan.manifest_features);
            if let Some(gap) = assigned.fidelity_gap() {
                tracing::error!(
                    %gap,
                    worktree = %plan.worktree_id,
                    "capture re-plan refused: the store cannot hold what a capture holds"
                );
                return Err(ControlError::new(
                    ControlErrorCode::PolicyDenied,
                    format!(
                        "capture re-plan refused: {gap}; no user code is admitted over this \
                         store (nothing was materialized)"
                    ),
                )
                .with_detail(serde_json::json!({
                    "reason": "store-unfit",
                    "unread": assigned.unread_features,
                })));
            }
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
                    // The plan's answer decides the bulk section restored here; another
                    // platform's is carried on the chain, as at boot.
                    let platform = engine.config().platform.clone();
                    crate::boot::capture::continue_bulk(
                        &mut manifest.manifest.sections,
                        &head.manifest.sections.bulk,
                        &platform,
                    );
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
                    // What a recovery boot on this disk binds to.
                    sealant_capture::materialize::DiskState::record_capture(
                        &engine.materialize_targets().index_dir,
                        sealant_capture::materialize::MaterializedCapture {
                            capture_id: head.capture_id.clone(),
                            epoch: plan.epoch,
                            executor: plan.executor.clone(),
                        },
                    )
                    .map_err(|e| internal(&format!("capture materialize record: {e}")))?;
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
            // The executor a completed final flush is sealed under, as this plan names it, and
            // nothing else: a seal never carries over from the placeholder's plan to another
            // launch (cross-repo decision 5). A plan that names none seals nothing.
            engine.set_executor(plan.executor.clone());
            *self.launch.lock().unwrap_or_else(|e| e.into_inner()) = plan.executor.clone();
            // The registrar of the assigned worktree decides whether dir objects travel in
            // dir packs from the next snap on, and whether it can hold what a capture holds
            // (a final flush over a store that cannot is never complete).
            engine.set_dir_format(DirFormat::for_registrar(plan.manifest_format));
            engine.set_store_features(&plan.manifest_features);
            // A standby executor boots under a placeholder worktree, so the sources of the
            // session it is assigned arrive with this plan, not the boot's.
            sources::apply(self.sink.as_ref(), &plan.sources, &self.layout)
                .map_err(|e| internal(&format!("capture sources: {e}")))?;
            // Likewise its remotes: the placeholder has none, and the repository here was built
            // by this executor, never cloned. A base (a head that carries no `.git/config`) gets
            // the ones it lacks; a head that carries one is a session's own configuration, and
            // it is authoritative (review 2026-09-28, fourth pass, #8).
            if !report.git_config {
                remotes::apply(&self.layout.working_directory, &plan.remotes)
                    .map_err(|e| internal(&format!("capture remotes: {e}")))?;
            }
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
        self.report(Currency::Now)
    }

    /// The state, its currency judged as `currency` says, at its position in this executor's
    /// order (cross-repo decision 17): computed under the observation number it carries, so a
    /// later number never describes an older state. Every answer — `capture.status`, a flush's —
    /// is one of these.
    fn report(&self, currency: Currency) -> CaptureStatusReport {
        self.observer.observe(|at| {
            let launch = self
                .launch
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .clone();
            CaptureStatusReport {
                launch,
                boot_id: Some(at.boot_id),
                boot_generation: Some(at.boot_generation),
                observation: Some(at.observation),
                ..self.observed(currency)
            }
        })
    }

    /// [`Self::report`]'s content. Takes no position and waits for no engine.
    fn observed(&self, currency: Currency) -> CaptureStatusReport {
        // The final flush's outcome first, then the queue: a flush sets its outcome once it has
        // shipped, so the queue read after it is at least as new. Read the other way round, a
        // queue read while the flush ran met the outcome it set on its way out, and the report
        // said `pending` between `in-progress` and `complete`.
        let outcome = *self.final_outcome.lock().unwrap_or_else(|e| e.into_inner());
        let ship = self.runner.shipper().status.snapshot();
        let staging = self.runner.staging();
        let queued = staging.pending().unwrap_or_default();
        let pending = queued.len() as u64;
        let pending_bulk = queued
            .iter()
            .filter(|e| e.class == Some(Class::Bulk))
            .count() as u64;
        // A bulk build in progress has staged packs no queued capture lists yet: they are on
        // this disk only, and a drain that read `pending_bytes` 0 mid-build stopped too early.
        let cadence = self.runner.snapshot();
        let bulk_building = cadence.bulk_running || cadence.bulk_in_progress;
        let pending_bytes = staging.pending_bytes(&queued)
            + if bulk_building {
                staging.unqueued_bytes(&queued).unwrap_or(0)
            } else {
                0
            };
        let staged_bytes = staging.staged_bytes().unwrap_or(0);
        let last = self.last_snap_unix_ms.load(Ordering::Relaxed);
        let (worktree_id, epoch) = self.identity();
        // Each class's snaps: a class whose last snap failed has changes on this disk only.
        let (small_health, bulk_health) = self.runner.snap_health();
        let captures_bulk = self.runner.captures_bulk();
        let snap_failing = small_health.failing() || (captures_bulk && bulk_health.failing());
        let snaps: Vec<CaptureClassSnaps> = [
            (CaptureClass::Small, small_health),
            (CaptureClass::Bulk, bulk_health),
        ]
        .into_iter()
        .filter(|(class, _)| *class == CaptureClass::Small || captures_bulk)
        .map(|(class, health)| CaptureClassSnaps {
            class,
            snaps_failed: health.failed,
            last_snap_error: health.last_error,
            snap_failing_since_unix_ms: health.failing_since.map(|at| {
                at.duration_since(UNIX_EPOCH)
                    .map_or(0, |d| d.as_millis() as u64)
            }),
        })
        .collect();
        // Complete only after a final flush stopped every writer and snapped both classes, and
        // only once everything is registered: nothing pending or being built, the lease not
        // fenced, no class whose last snap failed.
        let incomplete_reason = match outcome {
            FinalOutcome::NotRun => Some("not-final"),
            FinalOutcome::Running => Some("in-progress"),
            FinalOutcome::Incomplete(reason) => Some(reason),
            FinalOutcome::Snapped { .. } if ship.fenced => Some("fenced"),
            FinalOutcome::Snapped { .. } if snap_failing => Some("snapshot-failed"),
            FinalOutcome::Snapped { shipping } if pending > 0 => {
                Some(shipping.unwrap_or("pending"))
            }
            // A capture staged after the final one (a turn boundary): the chain no longer ends
            // on the final capture until the next final flush seals it.
            FinalOutcome::Snapped { .. } if !self.runner.chain_sealed() => Some("pending"),
            // A capture being built after the final one: staged, not queued yet.
            FinalOutcome::Snapped { .. } if bulk_building => Some("pending"),
            // Everything registered, but not the capture that seals the completed flush on the
            // chain (the flush returned at its deadline before it could stage it): the final
            // flush asked again stages it.
            FinalOutcome::Snapped { .. } if !self.runner.final_sealed() => Some("sealing"),
            // Complete means current (cross-repo decision 7): a change the watcher delivered
            // after the flush's first snap, an overflow, a class that polls, a repair asked
            // for, a bulk build paused mid-way — anything that makes a final flush asked again
            // snap again — and what is on this disk is no longer all in the store. The same
            // predicate the repeated final flush decides by; it snaps and answers complete.
            FinalOutcome::Snapped { .. } if !self.runner.final_is_current_as_snapped() => {
                Some("changed")
            }
            // Nothing seen changed, but a class polls (a directory it could not watch, an
            // overflow): read after the flush that snapped it, whether it is still as that
            // flush captured it is unknown until a final flush asked again snaps it.
            FinalOutcome::Snapped { .. }
                if currency == Currency::Now && !self.runner.every_class_watched() =>
            {
                Some("unwatched")
            }
            FinalOutcome::Snapped { .. } => None,
        };
        let reads = self.reads.current();
        let refusal = self.runner.shipper().register_refusal();
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
            pending_bulk,
            pending_bytes,
            complete: incomplete_reason.is_none(),
            incomplete_reason: incomplete_reason.map(str::to_owned),
            unreadable: Some(reads.unreadable),
            carried: Some(reads.carried),
            unreadable_paths: reads.paths,
            register_refused: refusal.as_ref().map(|r| r.reason.clone()),
            register_refused_n: refusal.as_ref().map(|r| r.n),
            register_missing: refusal
                .map(|r| r.missing.into_iter().take(20).collect())
                .unwrap_or_default(),
            register_refusals: Some(ship.register_refusals),
            repairing: ship.repair_pending,
            bulk_building,
            snaps,
            launch: None,
            boot_id: None,
            boot_generation: None,
            observation: None,
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

    use sealant_capture::registrar::{HeadInfo, PlanRemote, PlanSource};
    use sealant_capture::sink::BlobSource;
    use sealant_capture::{
        BlobSink, CaptureConfig, CaptureEngine, CaptureKind as EngineKind, Class,
        InMemoryRegistrar, LocalDir, Materializer, SnapRequest,
    };
    use sealant_protocol::{
        CaptureFlushKind, Command, CommandResult, ControlRequest, RequestId, ResponseOutcome,
    };
    use sealant_runtime_core::{RuntimeConfig, new_runtime_id};
    use sha2::{Digest, Sha256};

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

    /// The executor the test registrar's token is scoped to (a test engine seals under it only
    /// when its configuration names it).
    const EXECUTOR: &str = "exec-hooks";

    fn boot(base: &Path) -> (CaptureBoot, Arc<InMemoryRegistrar>) {
        boot_with(base, |store| store)
    }

    /// [`boot`] over the sink `wrap` makes of the local store.
    fn boot_with(
        base: &Path,
        wrap: impl FnOnce(Arc<dyn BlobSink>) -> Arc<dyn BlobSink>,
    ) -> (CaptureBoot, Arc<InMemoryRegistrar>) {
        boot_tuned(base, wrap, |_| {})
    }

    /// [`boot_with`], its engine's configuration as `tune` leaves it.
    fn boot_tuned(
        base: &Path,
        wrap: impl FnOnce(Arc<dyn BlobSink>) -> Arc<dyn BlobSink>,
        tune: impl FnOnce(&mut CaptureConfig),
    ) -> (CaptureBoot, Arc<InMemoryRegistrar>) {
        let root = base.join("ws");
        std::fs::create_dir_all(root.join("src")).unwrap();
        git(&root, &["init", "-q", "-b", "main"]);
        git(&root, &["config", "user.email", "t@t"]);
        git(&root, &["config", "user.name", "t"]);
        std::fs::write(root.join("src/lib.rs"), "pub fn f() {}\n").unwrap();
        git(&root, &["add", "-A"]);
        git(&root, &["commit", "-q", "-m", "one"]);
        let registrar =
            Arc::new(InMemoryRegistrar::new("wt-hooks", 1, None).with_executor(EXECUTOR));
        let sink = wrap(Arc::new(LocalDir::new(&base.join("store")).unwrap()));
        let mut config = CaptureConfig::new("wt-hooks", 1, &root);
        tune(&mut config);
        let engine = CaptureEngine::open(config, None).unwrap();
        let dyn_registrar: Arc<dyn Registrar> = registrar.clone();
        (
            CaptureBoot {
                engine,
                sink,
                registrar: dyn_registrar,
                minter: None,
                worktree_id: "wt-hooks".to_owned(),
                epoch: 1,
                layout: SourceLayout {
                    workspace_root: base.to_path_buf(),
                    working_directory: root.clone(),
                    staging_dir: root.join(".sealantd/capture"),
                },
                resumed: false,
            },
            registrar,
        )
    }

    /// A store that refuses every PUT (403, not retried) until `opens`, then takes them: an
    /// upload that cannot finish before then, whatever a flush does meanwhile.
    struct Gate {
        inner: Arc<dyn BlobSink>,
        opens: Instant,
    }

    impl BlobSink for Gate {
        fn put_if_absent(
            &self,
            key: &str,
            source: BlobSource<'_>,
        ) -> Result<sealant_capture::sink::PutOutcome, sealant_capture::sink::SinkError> {
            if Instant::now() < self.opens {
                return Err(sealant_capture::sink::SinkError::Http {
                    method: "PUT",
                    key: key.to_owned(),
                    status: 403,
                });
            }
            self.inner.put_if_absent(key, source)
        }

        fn get(&self, key: &str) -> Result<Vec<u8>, sealant_capture::sink::SinkError> {
            self.inner.get(key)
        }

        fn exists(&self, key: &str) -> Result<bool, sealant_capture::sink::SinkError> {
            self.inner.exists(key)
        }
    }

    fn flush_report(resp: sealant_protocol::ControlResponse) -> CaptureStatusReport {
        let ResponseOutcome::Ok {
            result: Some(CommandResult::CaptureStatus(report)),
        } = resp.outcome
        else {
            panic!("capture.flush: {:?}", resp.outcome);
        };
        *report
    }

    /// The daemon used to clamp every flush's deadline to its shutdown grace (10 s, never
    /// configured), so a flush the caller gave 30 s ended at 10 s with the capture still staged.
    /// Here the store takes nothing for 11 s: a suspend flush with a 30 s deadline keeps going
    /// past 10 s and returns with the capture registered, under the default grace.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_flush_deadline_is_honoured_past_the_ten_second_grace() {
        let tmp = tempfile::tempdir().unwrap();
        let opens = Instant::now() + Duration::from_millis(11_000);
        let (boot, registrar) = boot_with(tmp.path(), |inner| Arc::new(Gate { inner, opens }));
        let mut config = RuntimeConfig::new(new_runtime_id());
        config.workspace_root = tmp.path().join("ws");
        assert_eq!(config.shutdown_grace_ms, 10_000, "the default grace");
        let runtime = Runtime::new(
            config.clone(),
            Arc::new(ShutdownSignal::new(config.shutdown_grace_ms)),
        );
        runtime.mark_healthy();
        let capture = CaptureRuntime::new(boot);
        assert!(runtime.install_capture(capture.clone()));

        let start = Instant::now();
        let report = flush_report(
            runtime
                .dispatch(ControlRequest::new(
                    RequestId::new("r1"),
                    Command::CaptureFlush {
                        kind: CaptureFlushKind::Suspend,
                        deadline_ms: Some(30_000),
                        grace_ms: None,
                    },
                ))
                .await,
        );
        let took = start.elapsed();
        assert!(Instant::now() >= opens, "returned once the store took it");
        assert!(
            took > Duration::from_millis(10_500),
            "past the old clamp: {took:?}"
        );
        assert!(took < Duration::from_secs(25), "{took:?}");
        assert_eq!(report.pending, 0, "{report:?}");
        assert_eq!(report.pending_bytes, 0, "{report:?}");
        assert_eq!(registrar.chain().len(), 1);
    }

    /// Without a deadline a suspend flush is bounded by the shutdown grace, as it always was
    /// (here configured to 2 s), and reports what is left, `pending_bytes` included. A final
    /// flush without a deadline is bounded by nothing: it snaps the bulk class too and returns
    /// once everything is registered, however long the store refuses.
    ///
    /// The grace has to hold the suspend flush's snap and its first refused pass: a pass that
    /// ends past the grace answers with its error (on a loaded runner a 300 ms grace was spent
    /// before the pass ended, and the flush answered the store's 403). The store opens well
    /// after the grace.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn without_a_deadline_suspend_takes_the_grace_and_final_takes_what_it_needs() {
        let tmp = tempfile::tempdir().unwrap();
        let opens = Instant::now() + Duration::from_secs(6);
        let (boot, registrar) = boot_with(tmp.path(), |inner| Arc::new(Gate { inner, opens }));
        let mut config = RuntimeConfig::new(new_runtime_id());
        config.workspace_root = tmp.path().join("ws");
        let runtime = Runtime::new(config, Arc::new(ShutdownSignal::new(2_000)));
        runtime.mark_healthy();
        let capture = CaptureRuntime::new(boot);
        assert!(runtime.install_capture(capture.clone()));
        // Started, as every boot does: a runner that watches nothing cannot say the disk is
        // still as its final flush captured it, and never answers complete.
        capture.start_without_harness(runtime.clone());

        let start = Instant::now();
        let report = flush_report(
            runtime
                .dispatch(ControlRequest::new(
                    RequestId::new("r1"),
                    Command::CaptureFlush {
                        kind: CaptureFlushKind::Suspend,
                        deadline_ms: None,
                        grace_ms: None,
                    },
                ))
                .await,
        );
        let took = start.elapsed();
        assert!(
            took < Duration::from_millis(4_500),
            "the grace bounds it: {took:?}"
        );
        assert!(Instant::now() < opens, "the store still refuses");
        assert_eq!(report.pending, 1, "{report:?}");
        assert_eq!(report.pending_bulk, 0, "{report:?}");
        assert!(report.pending_bytes > 0, "{report:?}");
        assert!(!report.complete);
        assert_eq!(report.incomplete_reason.as_deref(), Some("not-final"));
        assert_eq!(capture.status().pending_bytes, report.pending_bytes);
        assert!(registrar.chain().is_empty());

        let report = flush_report(
            runtime
                .dispatch(ControlRequest::new(
                    RequestId::new("r2"),
                    Command::CaptureFlush {
                        kind: CaptureFlushKind::Final,
                        deadline_ms: None,
                        grace_ms: None,
                    },
                ))
                .await,
        );
        assert!(Instant::now() >= opens);
        assert_eq!(
            (report.pending, report.pending_bulk, report.pending_bytes),
            (0, 0, 0),
            "{report:?}"
        );
        assert!(report.refused.is_empty());
        assert!(report.complete, "{report:?}");
        let chain = registrar.chain();
        assert_eq!(chain.last().unwrap().manifest.kind, EngineKind::Final);
        assert!(
            chain
                .last()
                .unwrap()
                .manifest
                .sections
                .bulk
                .section()
                .is_some(),
            "the final flush snapped and shipped the bulk class"
        );
        assert!(chain.iter().any(|h| h.manifest.kind == EngineKind::Final));
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
    /// listener's `final_flush` each force a small-class snap ahead of the timers (the tree
    /// is quiet throughout: no scheduled snap would fire).
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn control_hooks_force_a_small_snap_ahead_of_the_timers() {
        let tmp = tempfile::tempdir().unwrap();
        let (boot, registrar) = boot(tmp.path());
        let mut config = RuntimeConfig::new(new_runtime_id());
        config.workspace_root = tmp.path().join("ws");
        let runtime = Runtime::new(config, Arc::new(ShutdownSignal::new(5_000)));
        runtime.mark_healthy();
        let capture = CaptureRuntime::new(boot);
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
                Command::CaptureFlush {
                    kind: CaptureFlushKind::Suspend,
                    deadline_ms: None,
                    grace_ms: None,
                },
            ))
            .await;
        let ResponseOutcome::Ok {
            result: Some(CommandResult::CaptureStatus(report)),
        } = resp.outcome
        else {
            panic!("capture.flush: {:?}", resp.outcome);
        };
        assert_eq!(report.pending, 0);
        assert_eq!(report.pending_bulk, 0);
        let chain = registrar.chain();
        assert_eq!(chain.len(), 2);
        assert_eq!(chain[1].manifest.kind, EngineKind::Suspend);

        // The signal listener's path (SIGTERM / SIGINT): a final snap, and a bulk snap — the
        // bulk class had never been captured, so the chain now records it (empty here) — both
        // registered before the flush returns.
        let report = runtime
            .final_flush(None, None)
            .await
            .expect("a capture engine");
        assert!(report.complete, "{report:?}");
        assert_eq!(report.incomplete_reason, None);
        let chain = registrar.chain();
        assert_eq!(chain.len(), 4);
        assert_eq!(chain[2].manifest.kind, EngineKind::Final);
        assert_eq!(
            chain[3].manifest.kind,
            EngineKind::Final,
            "a final flush's bulk snap is a final one"
        );
        assert!(chain[3].manifest.sections.bulk.section().is_some());
        assert!(capture.runner().staging().pending().unwrap().is_empty());

        // `runtime.gracefulShutdown` flushes before requesting the shutdown: the same final
        // flush again, over a disk nothing changed since, so it stages nothing.
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
        assert_eq!(
            registrar.chain().len(),
            4,
            "a final flush over a final capture of an unchanged disk stages nothing"
        );
        assert!(capture.status().complete);
        // Both classes are watched (the bulk class with no bulk directory yet), so the repeat
        // final flush snaps nothing at all: three forced snaps (turn, suspend, final).
        let snap = capture.runner().snapshot();
        assert_eq!(snap.forced, 3, "{snap:?}");
        assert_eq!(snap.small_snaps, 3, "no scheduled snap fired: {snap:?}");
    }

    /// A class the registrar refused for the session's byte quota is named in `capture.status`,
    /// and a re-plan lifts it (the refusal belonged to the previous epoch).
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn capture_status_names_the_refused_classes() {
        let tmp = tempfile::tempdir().unwrap();
        let (boot, _registrar) = boot(tmp.path());
        let capture = CaptureRuntime::new(boot);
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

        // Register refusals (422 `missing-objects` / `unrestorable`) and a capture waiting to be
        // rebuilt from disk are reported too.
        let status = capture.status();
        assert_eq!(status.register_refusals, Some(0));
        assert!(!status.repairing);
        assert_eq!(status.register_refused, None);
        let ship = &capture.runner().shipper().status;
        ship.register_refusals.store(2, Ordering::Relaxed);
        ship.repair_pending.store(true, Ordering::Relaxed);
        let status = capture.status();
        assert_eq!(status.register_refusals, Some(2));
        assert!(status.repairing);
    }

    /// What the last snap could not read is in `capture.status`: how many paths, how many were
    /// carried, and their names; a later snap that reads everything clears it.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn capture_status_counts_unreadable_and_carried_paths() {
        use std::os::unix::fs::PermissionsExt;
        let tmp = tempfile::tempdir().unwrap();
        let (boot, _registrar) = boot(tmp.path());
        let root = boot.layout.working_directory.clone();
        let probe = tmp.path().join("probe");
        std::fs::write(&probe, b"p").unwrap();
        std::fs::set_permissions(&probe, std::fs::Permissions::from_mode(0o000)).unwrap();
        if std::fs::File::open(&probe).is_ok() {
            eprintln!("skipped: permission bits do not bind this process");
            return;
        }
        std::fs::create_dir_all(root.join("notes")).unwrap();
        std::fs::write(root.join("notes/n.md"), "work\n").unwrap();
        let capture = CaptureRuntime::new(boot);
        assert_eq!(capture.status().unreadable, Some(0));
        capture.snap(CaptureKind::Turn).unwrap();

        let notes = root.join("notes");
        std::fs::set_permissions(&notes, std::fs::Permissions::from_mode(0o000)).unwrap();
        let snapped = capture.snap(CaptureKind::Turn);
        std::fs::set_permissions(&notes, std::fs::Permissions::from_mode(0o755)).unwrap();
        snapped.unwrap();
        let status = capture.status();
        assert_eq!(status.unreadable, Some(1), "{status:?}");
        assert_eq!(status.carried, Some(1), "{status:?}");
        assert_eq!(status.unreadable_paths, vec!["tree/notes".to_owned()]);

        capture.snap(CaptureKind::Turn).unwrap();
        let status = capture.status();
        assert_eq!((status.unreadable, status.carried), (Some(0), Some(0)));
        assert!(status.unreadable_paths.is_empty());
    }

    /// Docker end to end, round 3: every automatic snap failed for the rest of the session and
    /// every suspend flush was refused, while `capture.status` read `pending 0`, `unreadable 0`,
    /// and nothing surfaced it. A snap that fails for any reason is now in `snaps` — counted,
    /// its error and the moment the class started failing kept until one succeeds — and an
    /// executor whose class's last snap failed is not `complete`, even after a final flush.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn capture_status_reports_a_class_whose_snaps_fail() {
        let tmp = tempfile::tempdir().unwrap();
        let (boot, _registrar) = boot(tmp.path());
        let root = boot.layout.working_directory.clone();
        let mut config = RuntimeConfig::new(new_runtime_id());
        config.workspace_root = root.clone();
        let runtime = Runtime::new(config, Arc::new(ShutdownSignal::new(2_000)));
        runtime.mark_healthy();
        let capture = CaptureRuntime::new(boot);
        assert!(runtime.install_capture(capture.clone()));
        // Started, as every boot does: a runner that watches nothing cannot say the disk is
        // still as its final flush captured it, and never answers complete.
        capture.start_without_harness(runtime.clone());
        let small = |status: &CaptureStatusReport| {
            status
                .snaps
                .iter()
                .find(|s| s.class == CaptureClass::Small)
                .cloned()
                .expect("the small class is reported")
        };
        let status = capture.status();
        assert_eq!(small(&status).snaps_failed, 0, "{status:?}");
        assert_eq!(small(&status).last_snap_error, None);
        assert!(status.snaps.iter().any(|s| s.class == CaptureClass::Bulk));

        // Something every snap of the class trips over (here the repository itself).
        let head = std::fs::read(root.join(".git/HEAD")).unwrap();
        std::fs::write(root.join(".git/HEAD"), "not a ref\n").unwrap();
        let before = now_unix_ms();
        assert!(capture.snap(CaptureKind::Turn).is_err());
        assert!(capture.snap(CaptureKind::Turn).is_err());
        let status = capture.status();
        let failing = small(&status);
        assert_eq!(failing.snaps_failed, 2, "{status:?}");
        assert!(failing.last_snap_error.is_some(), "{status:?}");
        let since = failing.snap_failing_since_unix_ms.expect("failing since");
        assert!(since >= before, "{since} {before}");
        assert!(!status.complete);

        // A final flush over it is incomplete, and says why.
        let report = runtime.final_flush(None, Some(2_000)).await.unwrap();
        assert!(!report.complete, "{report:?}");
        assert_eq!(report.incomplete_reason.as_deref(), Some("snapshot-failed"));
        assert_eq!(small(&report).snaps_failed, 3, "{report:?}");

        // Once a snap succeeds, the class is healthy again; the count stays. The watcher
        // delivers the repair first: a final flush that raced it answered `changed`.
        std::fs::write(root.join(".git/HEAD"), &head).unwrap();
        watcher_saw_small_change(&capture).await;
        let report = runtime.final_flush(None, Some(2_000)).await.unwrap();
        assert!(report.complete, "{report:?}");
        let healthy = small(&report);
        assert_eq!(healthy.snaps_failed, 3, "{report:?}");
        assert_eq!(healthy.last_snap_error, None);
        assert_eq!(healthy.snap_failing_since_unix_ms, None);

        // A snap that fails after the final flush was complete takes `complete` back.
        std::fs::write(root.join(".git/HEAD"), "not a ref\n").unwrap();
        assert!(capture.snap(CaptureKind::Turn).is_err());
        let status = capture.status();
        assert!(!status.complete, "{status:?}");
        assert_eq!(status.incomplete_reason.as_deref(), Some("snapshot-failed"));
        std::fs::write(root.join(".git/HEAD"), &head).unwrap();
    }

    /// A bulk build in progress has staged packs no queued capture lists: `capture.status`
    /// says a build is running and counts those bytes, so a drain never reads "nothing pending"
    /// mid-build (Docker end to end: `pending 0 / pending_bulk 0` with 463 MB staged).
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn capture_status_reports_a_bulk_build_in_progress() {
        use std::sync::atomic::AtomicUsize;
        let tmp = tempfile::tempdir().unwrap();
        let (boot, _registrar) = boot(tmp.path());
        let root = boot.layout.working_directory.clone();
        std::fs::write(root.join(".gitignore"), "node_modules/\n").unwrap();
        for p in 0..20 {
            let dir = root.join(format!("node_modules/pkg{p}"));
            std::fs::create_dir_all(&dir).unwrap();
            for f in 0..20 {
                std::fs::write(
                    dir.join(format!("m{f}.js")),
                    format!("module.exports = [{p}, {f}];\n").repeat(200),
                )
                .unwrap();
            }
        }
        let capture = CaptureRuntime::new(boot);
        capture.snap(CaptureKind::Turn).unwrap();
        capture.runner().shipper().ship_pending().unwrap();
        let idle = capture.status();
        assert!(!idle.bulk_building, "{idle:?}");
        assert_eq!((idle.pending, idle.pending_bytes), (0, 0));

        // A bulk build that yields part-way (a small capture wanted the engine).
        let calls = AtomicUsize::new(0);
        let outcome = capture.runner().with_engine_mut(|engine| {
            engine.snap_preemptible(
                SnapRequest {
                    kind: EngineKind::Auto,
                    class: Class::Bulk,
                    seq: 99,
                },
                &|| calls.fetch_add(1, Ordering::SeqCst) > 100,
            )
        });
        assert!(
            matches!(outcome, Ok(sealant_capture::SnapOutcome::Preempted)),
            "{outcome:?}"
        );
        let status = capture.status();
        assert!(status.bulk_building, "{status:?}");
        assert_eq!(
            (status.pending, status.pending_bulk),
            (0, 0),
            "not queued yet"
        );
        assert!(
            status.pending_bytes > 0,
            "what the build staged is counted: {status:?}"
        );
    }

    /// A path no capture has read yet that cannot be read now has nothing to carry: an automatic
    /// snap leaves it out, and `capture.status` counts it (not carried) so the control plane can
    /// name it; the next snap that can read it captures it.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn capture_status_counts_a_never_captured_unreadable_path() {
        use std::os::unix::fs::PermissionsExt;
        let tmp = tempfile::tempdir().unwrap();
        let (boot, registrar) = boot(tmp.path());
        let root = boot.layout.working_directory.clone();
        let probe = tmp.path().join("probe");
        std::fs::write(&probe, b"p").unwrap();
        std::fs::set_permissions(&probe, std::fs::Permissions::from_mode(0o000)).unwrap();
        if std::fs::File::open(&probe).is_ok() {
            eprintln!("skipped: permission bits do not bind this process");
            return;
        }
        let fresh = root.join("fresh.md");
        std::fs::write(&fresh, "never read yet\n").unwrap();
        std::fs::set_permissions(&fresh, std::fs::Permissions::from_mode(0o000)).unwrap();
        let capture = CaptureRuntime::new(boot);
        let snapped = capture.snap(CaptureKind::Turn);
        std::fs::set_permissions(&fresh, std::fs::Permissions::from_mode(0o644)).unwrap();
        snapped.expect("an automatic capture does not fail on it");
        let status = capture.status();
        assert_eq!(status.unreadable, Some(1), "{status:?}");
        assert_eq!(status.carried, Some(0), "nothing to carry: {status:?}");
        assert_eq!(status.unreadable_paths, vec!["tree/fresh.md".to_owned()]);

        capture.snap(CaptureKind::Turn).unwrap();
        let status = capture.status();
        assert_eq!(status.unreadable, Some(0), "{status:?}");
        capture.runner().shipper().ship_pending().unwrap();
        let head = registrar.head().expect("registered");
        let tree = head
            .manifest
            .sections
            .git
            .worktree_tree_id()
            .map(str::to_owned)
            .expect("a worktree tree");
        let out = Proc::new("git")
            .current_dir(&root)
            .args(["cat-file", "-p", &format!("{tree}:fresh.md")])
            .output()
            .unwrap();
        assert_eq!(
            String::from_utf8_lossy(&out.stdout),
            "never read yet\n",
            "captured once it can be read"
        );
    }

    /// The standby flow end to end: the project base is captured for `wt-real` (epoch 1); a
    /// standby boots against the placeholder `standby-1` (epoch 7) and materializes that base;
    /// the session then moves the chain on (an edit, a new bulk file) and the control plane
    /// assigns the standby the real worktree; `capture.replan` fetches the plan, materializes
    /// the head as a delta, takes the identity, and the next capture continues the chain under
    /// `captures/wt-real/1/`. A second `capture.replan` changes nothing.
    /// A registrar whose `plan.get` stops answering `git_trees` once `lossy` is set: the store
    /// of the worktree a standby is assigned is one that cannot hold what a capture holds.
    struct LossyAfter {
        inner: Arc<InMemoryRegistrar>,
        lossy: std::sync::atomic::AtomicBool,
    }

    impl Registrar for LossyAfter {
        fn plan_get(
            &self,
            req: &sealant_capture::registrar::PlanGetRequest,
        ) -> Result<sealant_capture::registrar::PlanGetResponse, sealant_capture::RegistrarError>
        {
            let mut plan = self.inner.plan_get(req)?;
            if self.lossy.load(Ordering::SeqCst) {
                plan.manifest_features.retain(|f| f != "git_trees");
            }
            Ok(plan)
        }
        fn upload_urls(
            &self,
            req: &sealant_capture::registrar::UploadUrlsRequest,
        ) -> Result<sealant_capture::registrar::UploadUrlsResponse, sealant_capture::RegistrarError>
        {
            self.inner.upload_urls(req)
        }
        fn upload_complete(
            &self,
            req: &sealant_capture::registrar::UploadCompleteRequest,
        ) -> Result<
            sealant_capture::registrar::UploadCompleteResponse,
            sealant_capture::RegistrarError,
        > {
            self.inner.upload_complete(req)
        }
        fn capture_register(
            &self,
            req: &sealant_capture::registrar::RegisterRequest,
        ) -> Result<sealant_capture::registrar::RegisterResponse, sealant_capture::RegistrarError>
        {
            self.inner.capture_register(req)
        }
        fn lease_heartbeat(
            &self,
            req: &sealant_capture::registrar::HeartbeatRequest,
        ) -> Result<sealant_capture::registrar::HeartbeatResponse, sealant_capture::RegistrarError>
        {
            self.inner.lease_heartbeat(req)
        }
        fn change_summary(
            &self,
            req: &sealant_capture::registrar::ChangeSummaryRequest,
        ) -> Result<(), sealant_capture::RegistrarError> {
            self.inner.change_summary(req)
        }
    }

    /// No writer admission without full fidelity (decision 16; review 2026-09-28, fifth pass,
    /// #5), a standby included: a re-plan onto a worktree whose store cannot hold what a
    /// capture holds is refused before it touches the disk (`policy-denied`, detail reason
    /// `store-unfit`), and the standby keeps its placeholder identity — no harness is started
    /// on it. Before, the re-plan materialized the head and admitted the session's code over a
    /// store every periodic capture of it was lossy for.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_replan_onto_a_store_that_cannot_hold_a_capture_is_refused() {
        let tmp = tempfile::tempdir().unwrap();
        let src = tmp.path().join("src");
        std::fs::create_dir_all(&src).unwrap();
        git(&src, &["init", "-q", "-b", "main"]);
        git(&src, &["config", "user.email", "t@t"]);
        git(&src, &["config", "user.name", "t"]);
        std::fs::write(src.join("lib.rs"), "pub fn f() {}\n").unwrap();
        git(&src, &["add", "-A"]);
        git(&src, &["commit", "-q", "-m", "one"]);
        let sink: Arc<dyn BlobSink> = Arc::new(LocalDir::new(&tmp.path().join("store")).unwrap());
        let inner = Arc::new(InMemoryRegistrar::new("wt-real", 1, None));
        let registrar = Arc::new(LossyAfter {
            inner: inner.clone(),
            lossy: std::sync::atomic::AtomicBool::new(false),
        });
        let dyn_registrar: Arc<dyn Registrar> = registrar.clone();
        let mut source = CaptureEngine::open(CaptureConfig::new("wt-real", 1, &src), None).unwrap();
        let shipper = source.shipper(sink.clone(), dyn_registrar.clone());
        source
            .snap(SnapRequest {
                kind: EngineKind::Checkpoint,
                class: Class::Small,
                seq: 1,
            })
            .unwrap();
        shipper.ship_pending().unwrap();

        // A standby boots against the placeholder, whose store reads every feature.
        inner.set_worktree_id("standby-1");
        inner.set_live_epoch(7);
        let ws = tmp.path().join("ws");
        let boot = boot_from(
            dyn_registrar.clone(),
            Some(sink.clone()),
            &CaptureSourceConfig {
                endpoint: "http://unused".to_owned(),
                worktree_id: None,
                harness_home: None,
                raise_inotify_limit: false,
                allow_plaintext: false,
                ca_pem: None,
                ca_file: None,
                object_ca_pem: None,
                object_ca_file: None,
                recovery: false,
                launch_id: None,
            },
            &ws,
            tmp.path(),
        )
        .unwrap();
        let mut config = RuntimeConfig::new(new_runtime_id());
        config.workspace_root = ws.clone();
        let runtime = Runtime::new(config, Arc::new(ShutdownSignal::new(5_000)));
        runtime.mark_healthy();
        let capture = CaptureRuntime::new(boot);
        assert!(runtime.install_capture(capture.clone()));

        // The worktree it is assigned moved on, and its store cannot hold what a capture holds.
        inner.set_worktree_id("wt-real");
        inner.set_live_epoch(1);
        std::fs::write(src.join("lib.rs"), "pub fn f() { g() }\n").unwrap();
        source
            .snap(SnapRequest {
                kind: EngineKind::Checkpoint,
                class: Class::Small,
                seq: 2,
            })
            .unwrap();
        shipper.ship_pending().unwrap();
        registrar
            .lossy
            .store(true, std::sync::atomic::Ordering::SeqCst);

        let refused = capture.replan().expect_err("refused");
        assert_eq!(
            refused.code(),
            sealant_protocol::ControlErrorCode::PolicyDenied
        );
        assert!(refused.message.contains("git_trees"), "{refused}");
        assert_eq!(
            refused.detail.as_ref().and_then(|d| d["reason"].as_str()),
            Some("store-unfit")
        );
        // Nothing was materialized, and the standby is still the placeholder's.
        assert_eq!(
            std::fs::read_to_string(ws.join("lib.rs")).unwrap(),
            "pub fn f() {}\n"
        );
        assert_eq!(capture.lease_epoch().worktree_id, "standby-1");
    }

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
        // A base as Mend registers one carries no repository configuration of a session's (so
        // the plan's remotes are the ones a re-plan sets).
        std::fs::remove_file(src.join(".git/config")).unwrap();
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
                allow_plaintext: false,
                ca_pem: None,
                ca_file: None,
                object_ca_pem: None,
                object_ca_file: None,
                recovery: false,
                launch_id: None,
            },
            &ws,
            tmp.path(),
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
        let capture = CaptureRuntime::new(boot);
        assert!(runtime.install_capture(capture.clone()));
        capture.start(runtime.clone(), ProcessId::new("p-harness"));
        assert_eq!(capture.lease_epoch().worktree_id, "standby-1");

        // The chain moves on under wt-real while the standby waits.
        registrar.set_worktree_id("wt-real");
        registrar.set_live_epoch(1);
        std::fs::write(src.join("lib.rs"), "pub fn f() { g() }\n").unwrap();
        git(
            &src,
            &[
                "-c",
                "user.email=t@t",
                "-c",
                "user.name=t",
                "commit",
                "-q",
                "-am",
                "two",
            ],
        );
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

        // The session's own content beside the worktree arrives with the plan that assigns the
        // worktree: a standby booted under the placeholder, so the boot's plan had none.
        let tree = tmp.path().join("publish");
        std::fs::create_dir_all(&tree).unwrap();
        std::fs::write(tree.join("NOTES.md"), "team docs\n").unwrap();
        let archive = tmp.path().join("docs.tar.gz");
        assert!(
            Proc::new("tar")
                .args([
                    "-czf".as_ref(),
                    archive.as_os_str(),
                    "-C".as_ref(),
                    tree.as_os_str(),
                    ".".as_ref()
                ])
                .output()
                .expect("tar -czf")
                .status
                .success()
        );
        let bytes = std::fs::read(&archive).unwrap();
        let sha256 = format!("{:x}", Sha256::digest(&bytes));
        let key = format!("projects/p/sources/{sha256}");
        sink.put_if_absent(&key, BlobSource::Bytes(&bytes)).unwrap();
        let docs = tmp.path().join("home/docs");
        registrar.set_sources(vec![PlanSource {
            name: "docs".to_owned(),
            path: docs.display().to_string(),
            key,
            sha256,
            bytes: bytes.len() as u64,
            read_only: true,
        }]);
        registrar.set_remotes(vec![PlanRemote {
            name: "origin".to_owned(),
            url: "git@example.invalid:acme/api.git".to_owned(),
        }]);

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
        assert_eq!(
            std::fs::read_to_string(docs.join("NOTES.md")).unwrap(),
            "team docs\n",
            "the assigned worktree's sources land on the re-plan"
        );
        let origin = std::process::Command::new("git")
            .arg("-C")
            .arg(&ws)
            .args(["remote", "get-url", "origin"])
            .output()
            .expect("git remote get-url");
        assert_eq!(
            String::from_utf8_lossy(&origin.stdout).trim(),
            "git@example.invalid:acme/api.git",
            "the assigned worktree's remotes are set on the re-plan"
        );
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

    fn sh(script: &str, cwd: &Path) -> sealant_protocol::ExecArgs {
        sealant_protocol::ExecArgs {
            execution_id: None,
            session_id: None,
            executable: "/bin/sh".to_owned(),
            args: vec!["-c".to_owned(), script.to_owned()],
            cwd: Some(cwd.display().to_string()),
            // `sleep` from this process's PATH (the child's base environment has none).
            env: vec![sealant_protocol::EnvVar {
                key: "PATH".to_owned(),
                value: std::env::var("PATH").unwrap_or_default(),
            }],
            stdin: false,
            attach: false,
            timeout_millis: None,
            background: false,
            capture: None,
            graceful_signal: None,
        }
    }

    /// A writer that keeps writing (`counter.txt`, every 20 ms) and writes its last word from
    /// its `SIGTERM` handler (`term.txt`).
    const WRITER: &str = "trap 'echo last words > term.txt; exit 0' TERM; i=0; \
                          while true; do i=$((i+1)); echo $i > counter.txt; sleep 0.02; done";

    /// A runtime with a capture engine over a fresh workspace, and the writer running in it as
    /// the harness. Returns the runtime, the capture, the registrar, and the workspace.
    async fn with_writer(
        base: &Path,
    ) -> (
        Arc<Runtime>,
        Arc<CaptureRuntime>,
        Arc<InMemoryRegistrar>,
        std::path::PathBuf,
    ) {
        let (boot, registrar) = boot(base);
        let ws = base.join("ws");
        let mut config = RuntimeConfig::new(new_runtime_id());
        config.workspace_root = ws.clone();
        let runtime = Runtime::new(config, Arc::new(ShutdownSignal::new(5_000)));
        runtime.mark_healthy();
        let capture = CaptureRuntime::new(boot);
        assert!(runtime.install_capture(capture.clone()));
        let harness = runtime
            .spawn_managed(sh(WRITER, &ws))
            .expect("spawn the writer");
        capture.start(runtime.clone(), harness.process_id);
        let start = Instant::now();
        while !ws.join("counter.txt").exists() {
            assert!(start.elapsed() < Duration::from_secs(10), "the writer runs");
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        (runtime, capture, registrar, ws)
    }

    /// The head, materialized into a fresh directory under `base`.
    fn restore_head(base: &Path, registrar: &InMemoryRegistrar, name: &str) -> std::path::PathBuf {
        let store = LocalDir::new(&base.join("store")).unwrap();
        let fresh = base.join(name);
        Materializer::new(
            &store,
            sealant_capture::MaterializeTargets::new(&fresh, None),
        )
        .materialize(
            &registrar.head().expect("a head").manifest,
            sealant_capture::MaterializeClass::All,
        )
        .unwrap();
        fresh
    }

    /// Review finding #2: the daemon snapped, then terminated its processes, so a writer that
    /// wrote during the upload or from its `SIGTERM` handler lost it. A final `capture.flush`
    /// now closes admission, terminates every managed process and waits for it, and only then
    /// snaps: the head holds the handler's file and the counter's last value, byte for byte,
    /// nothing runs any more, and nothing new is admitted.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_final_flush_stops_the_writers_before_it_snaps() {
        let tmp = tempfile::tempdir().unwrap();
        let (runtime, _capture, registrar, ws) = with_writer(tmp.path()).await;

        let report = flush_report(
            runtime
                .dispatch(ControlRequest::new(
                    RequestId::new("r1"),
                    Command::CaptureFlush {
                        kind: CaptureFlushKind::Final,
                        deadline_ms: None,
                        grace_ms: Some(5_000),
                    },
                ))
                .await,
        );
        assert!(report.complete, "{report:?}");
        assert_eq!(report.incomplete_reason, None);
        assert_eq!(report.pending, 0);
        assert_eq!(
            runtime.health_report().active_processes,
            0,
            "the writer is gone"
        );
        assert!(!runtime.capture_incomplete());

        let fresh = restore_head(tmp.path(), &registrar, "fresh");
        assert_eq!(
            std::fs::read_to_string(fresh.join("term.txt"))
                .ok()
                .as_deref(),
            Some("last words\n"),
            "what the writer wrote on SIGTERM is in the head"
        );
        assert_eq!(
            std::fs::read_to_string(fresh.join("counter.txt")).unwrap(),
            std::fs::read_to_string(ws.join("counter.txt")).unwrap(),
            "the head is the disk as the writer left it"
        );

        // Admission is closed for good: no exec, no session, no re-plan.
        let refused = runtime
            .dispatch(ControlRequest::new(
                RequestId::new("r2"),
                Command::Exec(sh("echo late > late.txt", &ws)),
            ))
            .await;
        assert!(
            matches!(refused.outcome, ResponseOutcome::Error { .. }),
            "{:?}",
            refused.outcome
        );
        assert!(runtime.spawn_managed(sh("true", &ws)).is_err());
        tokio::time::sleep(Duration::from_millis(200)).await;
        assert!(!ws.join("late.txt").exists());
    }

    /// Finding #2 on the daemon's own way out: `runtime.gracefulShutdown` (and SIGTERM/SIGINT,
    /// and the harness exiting, which run the same `final_flush`) used to snap first and
    /// terminate after. The writer's `SIGTERM` handler now runs before the last snap.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn graceful_shutdown_stops_the_writers_before_the_final_capture() {
        let tmp = tempfile::tempdir().unwrap();
        let (runtime, capture, registrar, ws) = with_writer(tmp.path()).await;

        let resp = runtime
            .dispatch(ControlRequest::new(
                RequestId::new("r1"),
                Command::RuntimeGracefulShutdown {
                    grace_millis: Some(5_000),
                },
            ))
            .await;
        assert!(matches!(
            resp.outcome,
            ResponseOutcome::Ok {
                result: Some(CommandResult::ShutdownAccepted(_))
            }
        ));
        assert!(capture.status().complete, "{:?}", capture.status());
        assert!(!runtime.capture_incomplete());
        let fresh = restore_head(tmp.path(), &registrar, "fresh");
        assert_eq!(
            std::fs::read_to_string(fresh.join("term.txt"))
                .ok()
                .as_deref(),
            Some("last words\n")
        );
        assert_eq!(
            std::fs::read_to_string(fresh.join("counter.txt")).unwrap(),
            std::fs::read_to_string(ws.join("counter.txt")).unwrap()
        );
    }

    /// Review finding #11: once the lease was fenced, a final flush answered success with a
    /// capture still staged (the shipper read "fenced" as "done"). Every final flush on a
    /// fenced lease now answers `complete: false`, `incomplete_reason: "fenced"`, the capture
    /// stays staged, and the daemon would exit with `EXIT_CAPTURE_INCOMPLETE`.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_final_flush_on_a_fenced_lease_is_incomplete() {
        let tmp = tempfile::tempdir().unwrap();
        let (boot, registrar) = boot(tmp.path());
        let mut config = RuntimeConfig::new(new_runtime_id());
        config.workspace_root = tmp.path().join("ws");
        let runtime = Runtime::new(config, Arc::new(ShutdownSignal::new(1_000)));
        runtime.mark_healthy();
        let capture = CaptureRuntime::new(boot);
        assert!(runtime.install_capture(capture.clone()));
        registrar.set_live_epoch(2);

        for rid in ["r1", "r2"] {
            let report = flush_report(
                runtime
                    .dispatch(ControlRequest::new(
                        RequestId::new(rid),
                        Command::CaptureFlush {
                            kind: CaptureFlushKind::Final,
                            deadline_ms: None,
                            grace_ms: None,
                        },
                    ))
                    .await,
            );
            assert!(!report.complete, "{rid}: {report:?}");
            assert_eq!(report.incomplete_reason.as_deref(), Some("fenced"), "{rid}");
            assert!(report.pending > 0, "{rid}: still staged: {report:?}");
        }
        assert!(registrar.chain().is_empty());
        assert!(runtime.capture_incomplete());
        assert!(capture.status().fenced);
    }

    /// A final flush whose deadline passes while the store refuses every PUT is
    /// `complete: false`, `incomplete_reason: "ship-failed"` (it answered like a finished flush
    /// before, with the capture still staged), and a final flush without a deadline then
    /// completes it once the store takes it.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_final_flush_that_cannot_ship_by_its_deadline_is_incomplete() {
        let tmp = tempfile::tempdir().unwrap();
        let opens = Instant::now() + Duration::from_millis(1_500);
        let (boot, _registrar) = boot_with(tmp.path(), |inner| Arc::new(Gate { inner, opens }));
        let mut config = RuntimeConfig::new(new_runtime_id());
        config.workspace_root = tmp.path().join("ws");
        let runtime = Runtime::new(config, Arc::new(ShutdownSignal::new(1_000)));
        runtime.mark_healthy();
        let capture = CaptureRuntime::new(boot);
        assert!(runtime.install_capture(capture.clone()));
        // Started, as every boot does: a runner that watches nothing cannot say the disk is
        // still as its final flush captured it, and never answers complete.
        capture.start_without_harness(runtime.clone());

        let flush = |rid: &'static str, deadline_ms| {
            runtime.dispatch(ControlRequest::new(
                RequestId::new(rid),
                Command::CaptureFlush {
                    kind: CaptureFlushKind::Final,
                    deadline_ms,
                    grace_ms: None,
                },
            ))
        };
        let report = flush_report(flush("r1", Some(300)).await);
        assert!(!report.complete, "{report:?}");
        assert_eq!(report.incomplete_reason.as_deref(), Some("ship-failed"));
        assert!(report.pending > 0 && report.pending_bytes > 0, "{report:?}");
        assert!(runtime.capture_incomplete());

        let report = flush_report(flush("r2", None).await);
        assert!(report.complete, "{report:?}");
        assert_eq!(report.pending, 0);
        assert!(!runtime.capture_incomplete());
    }

    /// A fake Docker Engine on a Unix socket: `GET /containers/json` lists what runs, `POST
    /// /containers/{id}/stop?t=N` records the stop and, unless the container is `stubborn`,
    /// stops it.
    #[derive(Default)]
    struct FakeDocker {
        running: Vec<String>,
        stubborn: Vec<String>,
        stops: Vec<String>,
        /// What a container does while it stops ([`ContainerExit`]).
        exit: Option<ContainerExit>,
    }

    /// A container that prints `last` into `log` `delay` into its stop (what `docker logs -f`
    /// would stream) and exits `delay` after that; and a container `late` that starts once `trigger`
    /// exists (a process started it on its way out).
    #[derive(Clone)]
    struct ContainerExit {
        delay: Duration,
        log: std::path::PathBuf,
        last: &'static str,
        trigger: std::path::PathBuf,
        late: &'static str,
    }

    fn fake_docker(socket: &Path, running: &[&str], stubborn: &[&str]) -> Arc<Mutex<FakeDocker>> {
        fake_docker_with(socket, running, stubborn, None)
    }

    fn fake_docker_with(
        socket: &Path,
        running: &[&str],
        stubborn: &[&str],
        exit: Option<ContainerExit>,
    ) -> Arc<Mutex<FakeDocker>> {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let state = Arc::new(Mutex::new(FakeDocker {
            running: running.iter().map(|s| (*s).to_owned()).collect(),
            stubborn: stubborn.iter().map(|s| (*s).to_owned()).collect(),
            stops: Vec::new(),
            exit,
        }));
        let listener = tokio::net::UnixListener::bind(socket).unwrap();
        let shared = state.clone();
        tokio::spawn(async move {
            loop {
                let Ok((mut conn, _)) = listener.accept().await else {
                    return;
                };
                let state = shared.clone();
                tokio::spawn(async move {
                    let mut buf = Vec::new();
                    let mut chunk = [0u8; 1024];
                    while !buf.windows(4).any(|w| w == b"\r\n\r\n") {
                        match conn.read(&mut chunk).await {
                            Ok(0) | Err(_) => return,
                            Ok(n) => buf.extend_from_slice(&chunk[..n]),
                        }
                    }
                    let head = String::from_utf8_lossy(&buf).to_string();
                    let mut words = head.split_whitespace();
                    let (method, path) = (words.next().unwrap_or(""), words.next().unwrap_or(""));
                    let exit = state.lock().unwrap().exit.clone();
                    if let Some(exit) = &exit
                        && method == "POST"
                        && path.starts_with("/containers/")
                        && path.split('/').nth(2) != Some(exit.late)
                    {
                        tokio::time::sleep(exit.delay).await;
                        let mut log = std::fs::OpenOptions::new()
                            .append(true)
                            .open(&exit.log)
                            .unwrap();
                        std::io::Write::write_all(&mut log, exit.last.as_bytes()).unwrap();
                        // Its last lines out, the container takes a moment more to exit.
                        tokio::time::sleep(exit.delay).await;
                    }
                    let (status, body) = {
                        let mut st = state.lock().unwrap();
                        if let Some(exit) = &exit
                            && exit.trigger.exists()
                            && !st.stops.iter().any(|s| s.contains(exit.late))
                            && !st.running.iter().any(|r| r == exit.late)
                        {
                            st.running.push(exit.late.to_owned());
                        }
                        if method == "GET" && path == "/containers/json" {
                            let list: Vec<_> = st
                                .running
                                .iter()
                                .map(|id| serde_json::json!({"Id": id}))
                                .collect();
                            ("200 OK", serde_json::to_string(&list).unwrap())
                        } else if method == "POST" && path.starts_with("/containers/") {
                            st.stops.push(path.to_owned());
                            let id = path.split('/').nth(2).unwrap_or("").to_owned();
                            if !st.stubborn.contains(&id) {
                                st.running.retain(|r| *r != id);
                            }
                            ("204 No Content", String::new())
                        } else {
                            ("404 Not Found", String::new())
                        }
                    };
                    let answer = format!(
                        "HTTP/1.1 {status}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                        body.len()
                    );
                    let _ = conn.write_all(answer.as_bytes()).await;
                });
            }
        });
        state
    }

    /// A runtime with a capture engine over a fresh workspace and nothing running.
    fn quiet_runtime(base: &Path) -> (Arc<Runtime>, Arc<CaptureRuntime>, Arc<InMemoryRegistrar>) {
        let (boot, registrar) = boot(base);
        let mut config = RuntimeConfig::new(new_runtime_id());
        config.workspace_root = base.join("ws");
        let runtime = Runtime::new(config, Arc::new(ShutdownSignal::new(3_000)));
        runtime.mark_healthy();
        let capture = CaptureRuntime::new(boot);
        assert!(runtime.install_capture(capture.clone()));
        (runtime, capture, registrar)
    }

    /// A container of the workspace's own Docker daemon (Docker-in-MicroVM, a dind sidecar) can
    /// bind-mount the worktree and keeps writing after the last snap unless it is stopped:
    /// the final flush stops every running container (`docker stop -t <grace>`) before it
    /// snaps, and is complete once the daemon reports none running.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_final_flush_stops_every_container_of_the_workspace_docker_daemon() {
        let tmp = tempfile::tempdir().unwrap();
        let (runtime, capture, _registrar) = quiet_runtime(tmp.path());
        // Started, as every boot does: a runner that watches nothing cannot say the disk is
        // still as its final flush captured it, and never answers complete.
        capture.start_without_harness(runtime.clone());
        let socket = tmp.path().join("docker.sock");
        let docker = fake_docker(&socket, &["c1", "c2"], &[]);
        runtime.set_workspace_docker(Some(crate::docker::DockerEndpoint::Unix(socket)));

        let report = runtime.final_flush(None, Some(3_000)).await.unwrap();
        assert!(report.complete, "{report:?}");
        let docker = docker.lock().unwrap();
        let mut stops = docker.stops.clone();
        stops.sort();
        assert_eq!(
            stops,
            ["/containers/c1/stop?t=3", "/containers/c2/stop?t=3"],
            "every container, with the flush's grace"
        );
        assert!(docker.running.is_empty());
    }

    /// Docker end to end, round 2: the workspace daemon's containers were stopped at the same
    /// time as the processes, so what a container printed while it stopped — streamed into the
    /// worktree by a workspace process (`docker logs -f > file`) — lost its tail: the process
    /// streaming it was already gone. The containers now stop first (with the grace), then the
    /// processes, then the containers are checked again: one a process started on its way out
    /// is stopped too.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn containers_stop_before_the_processes_that_stream_them() {
        // The follower replaces its copy whole (a copy into a new file, renamed over it), as a
        // stream appends: `cp` straight onto it truncated it first, and a stop that landed
        // between the truncation and the write left it empty. On its way out it copies once
        // more, as `docker logs -f` drains what the container printed before it exited.
        const FOLLOWER: &str = "follow() { cp container.log followed.tmp && \
                                mv followed.tmp followed.txt; }; \
                                trap 'follow; touch start-late; exit 0' TERM; \
                                while true; do follow; sleep 0.02; done";
        let tmp = tempfile::tempdir().unwrap();
        let (boot, registrar) = boot(tmp.path());
        let ws = tmp.path().join("ws");
        std::fs::write(ws.join("container.log"), "first line\n").unwrap();
        let mut config = RuntimeConfig::new(new_runtime_id());
        config.workspace_root = ws.clone();
        let runtime = Runtime::new(config, Arc::new(ShutdownSignal::new(3_000)));
        runtime.mark_healthy();
        let capture = CaptureRuntime::new(boot);
        assert!(runtime.install_capture(capture.clone()));
        let socket = tmp.path().join("docker.sock");
        let docker = fake_docker_with(
            &socket,
            &["c1"],
            &[],
            Some(ContainerExit {
                delay: Duration::from_millis(300),
                log: ws.join("container.log"),
                last: "last line\n",
                trigger: ws.join("start-late"),
                late: "late",
            }),
        );
        runtime.set_workspace_docker(Some(crate::docker::DockerEndpoint::Unix(socket)));
        let harness = runtime
            .spawn_managed(sh(FOLLOWER, &ws))
            .expect("spawn the follower");
        capture.start(runtime.clone(), harness.process_id);
        let start = Instant::now();
        while !ws.join("followed.txt").exists() {
            assert!(
                start.elapsed() < Duration::from_secs(10),
                "the follower runs"
            );
            tokio::time::sleep(Duration::from_millis(20)).await;
        }

        let report = runtime.final_flush(None, Some(3_000)).await.unwrap();
        assert!(report.complete, "{report:?}");
        let fresh = restore_head(tmp.path(), &registrar, "fresh");
        assert_eq!(
            std::fs::read_to_string(fresh.join("followed.txt")).unwrap(),
            "first line\nlast line\n",
            "what the container printed as it stopped reached the worktree before its follower \
             stopped"
        );
        let docker = docker.lock().unwrap();
        assert_eq!(
            docker.stops,
            ["/containers/c1/stop?t=3", "/containers/late/stop?t=3"],
            "the container a process started on its way out is stopped too"
        );
        assert!(docker.running.is_empty());
    }

    /// Docker end to end, round 2: `bulk_building` was true 0.6–11.4 s after a final flush
    /// answered `complete: true` — a scheduled bulk build resumed after the forced one, or the
    /// clocks fired on what the watcher saw after the last snap. Once a final flush stopped
    /// every writer, nothing snaps on a schedule any more (a forced snap still does), and a
    /// capture being built or staged after the final one is not complete until it has shipped.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn after_a_final_flush_nothing_snaps_on_a_schedule() {
        let tmp = tempfile::tempdir().unwrap();
        let (boot, _registrar) = boot_tuned(
            tmp.path(),
            |store| store,
            |config| {
                config.cadence.quiet = Duration::from_millis(50);
                config.cadence.max_interval = Duration::from_millis(200);
                config.cadence.bulk_quiet = Duration::from_millis(50);
                config.cadence.bulk_max_interval = Duration::from_millis(200);
            },
        );
        let ws = boot.layout.working_directory.clone();
        std::fs::write(ws.join(".gitignore"), "node_modules/\n").unwrap();
        std::fs::create_dir_all(ws.join("node_modules/pkg")).unwrap();
        for f in 0..50 {
            std::fs::write(
                ws.join(format!("node_modules/pkg/m{f}.js")),
                format!("module.exports = {f};\n").repeat(100),
            )
            .unwrap();
        }
        let mut config = RuntimeConfig::new(new_runtime_id());
        config.workspace_root = ws.clone();
        let runtime = Runtime::new(config, Arc::new(ShutdownSignal::new(3_000)));
        runtime.mark_healthy();
        let capture = CaptureRuntime::new(boot);
        assert!(runtime.install_capture(capture.clone()));
        let harness = runtime
            .spawn_managed(sh("exec sleep 3600", &ws))
            .expect("spawn");
        capture.start(runtime.clone(), harness.process_id);

        let report = runtime.final_flush(None, Some(3_000)).await.unwrap();
        assert!(report.complete, "{report:?}");
        assert!(capture.status().complete, "current until something changes");
        let after_final = capture.runner().snapshot();

        // Something changes after the last snap anyway, in both classes, and the clocks see it.
        // Nothing snaps on a schedule, and the executor is no longer complete: what changed is
        // on this disk only (review 2026-09-28 #15: status said complete through all of it).
        std::fs::write(ws.join("after.txt"), "after the final flush\n").unwrap();
        std::fs::write(ws.join("node_modules/pkg/late.js"), "late\n").unwrap();
        for _ in 0..5 {
            capture
                .runner()
                .signal(sealant_capture::ChangeSignal::Changed(Class::Small));
            capture
                .runner()
                .signal(sealant_capture::ChangeSignal::Changed(Class::Bulk));
            tokio::time::sleep(Duration::from_millis(300)).await;
            let status = capture.status();
            assert!(!status.bulk_building, "{status:?}");
            assert!(!status.complete, "{status:?}");
            assert_eq!(status.incomplete_reason.as_deref(), Some("changed"));
        }
        let later = capture.runner().snapshot();
        assert_eq!(
            (later.small_snaps, later.bulk_snaps),
            (after_final.small_snaps, after_final.bulk_snaps),
            "no scheduled snap after the final flush: {later:?}"
        );

        // A bulk capture being built after the final one is not complete until it is done.
        let calls = std::sync::atomic::AtomicUsize::new(0);
        let outcome = capture.runner().with_engine_mut(|engine| {
            engine.snap_preemptible(
                SnapRequest {
                    kind: EngineKind::Auto,
                    class: Class::Bulk,
                    seq: 99,
                },
                &|| calls.fetch_add(1, Ordering::SeqCst) > 10,
            )
        });
        assert!(
            matches!(outcome, Ok(sealant_capture::SnapOutcome::Preempted)),
            "{outcome:?}"
        );
        let building = capture.status();
        assert!(building.bulk_building, "{building:?}");
        assert!(!building.complete, "{building:?}");
        assert_eq!(building.incomplete_reason.as_deref(), Some("pending"));

        // The final flush again: the build is finished, shipped, and the executor complete.
        let again = runtime.final_flush(None, Some(3_000)).await.unwrap();
        assert!(again.complete, "{again:?}");
        assert!(!again.bulk_building, "{again:?}");
        let saved = capture.runner().snapshot();
        assert!(
            saved.small_snaps > after_final.small_snaps,
            "the final flush asked again snapped what changed: {saved:?}"
        );
        assert!(capture.status().complete);

        // An overflow after it (events lost) invalidates it the same way.
        capture
            .runner()
            .signal(sealant_capture::ChangeSignal::Overflow);
        let status = capture.status();
        assert!(!status.complete, "{status:?}");
        assert_eq!(status.incomplete_reason.as_deref(), Some("changed"));
    }

    /// A container that is still running after its stop, or a daemon that is known and cannot
    /// be reached, leaves the flush incomplete (`processes-remain`): nobody knows it stopped
    /// writing.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_container_left_running_or_an_unreachable_daemon_is_incomplete() {
        let tmp = tempfile::tempdir().unwrap();
        let (runtime, _capture, _registrar) = quiet_runtime(tmp.path());
        let socket = tmp.path().join("docker.sock");
        let docker = fake_docker(&socket, &["c1", "stuck"], &["stuck"]);
        runtime.set_workspace_docker(Some(crate::docker::DockerEndpoint::Unix(socket)));
        let report = runtime.final_flush(None, Some(1_000)).await.unwrap();
        assert!(!report.complete, "{report:?}");
        assert_eq!(
            report.incomplete_reason.as_deref(),
            Some("processes-remain")
        );
        assert_eq!(docker.lock().unwrap().running, ["stuck"]);

        let tmp = tempfile::tempdir().unwrap();
        let (runtime, _capture, _registrar) = quiet_runtime(tmp.path());
        runtime.set_workspace_docker(Some(crate::docker::DockerEndpoint::Unix(
            tmp.path().join("no-daemon.sock"),
        )));
        let report = runtime.final_flush(None, Some(1_000)).await.unwrap();
        assert!(!report.complete, "{report:?}");
        assert_eq!(
            report.incomplete_reason.as_deref(),
            Some("processes-remain")
        );
    }

    /// Without `PR_SET_CHILD_SUBREAPER`, and not PID 1 of its PID namespace, the daemon cannot
    /// see an orphaned writer: every final flush is incomplete (`sweep-unavailable`), however
    /// well everything else went.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn without_a_subreaper_every_final_flush_is_incomplete() {
        let tmp = tempfile::tempdir().unwrap();
        let (runtime, _capture, registrar) = quiet_runtime(tmp.path());
        runtime.set_subreaper_for_test(false);
        assert!(runtime.sweep_unavailable());
        for _ in 0..2 {
            let report = runtime.final_flush(None, None).await.unwrap();
            assert!(!report.complete, "{report:?}");
            assert_eq!(
                report.incomplete_reason.as_deref(),
                Some("sweep-unavailable")
            );
            assert_eq!(report.pending, 0, "everything still ships: {report:?}");
        }
        assert!(!registrar.chain().is_empty());
        assert!(runtime.capture_incomplete());
    }

    /// A store that spends `delay` on every PUT.
    struct Slow {
        inner: Arc<dyn BlobSink>,
        delay: Duration,
    }

    impl BlobSink for Slow {
        fn put_if_absent(
            &self,
            key: &str,
            source: BlobSource<'_>,
        ) -> Result<sealant_capture::sink::PutOutcome, sealant_capture::sink::SinkError> {
            std::thread::sleep(self.delay);
            self.inner.put_if_absent(key, source)
        }

        fn get(&self, key: &str) -> Result<Vec<u8>, sealant_capture::sink::SinkError> {
            self.inner.get(key)
        }

        fn exists(&self, key: &str) -> Result<bool, sealant_capture::sink::SinkError> {
            self.inner.exists(key)
        }
    }

    /// Every `complete` / `incomplete_reason` reading of `capture.status`, every millisecond, from
    /// another thread until the returned flag is set (and one after); the readings come back
    /// from the handle.
    type Readings = Vec<(bool, Option<String>)>;

    fn watch_status(
        capture: &Arc<CaptureRuntime>,
    ) -> (Arc<AtomicBool>, std::thread::JoinHandle<Readings>) {
        let stop = Arc::new(AtomicBool::new(false));
        let (flag, capture) = (stop.clone(), capture.clone());
        let handle = std::thread::spawn(move || {
            let mut seen = Vec::new();
            loop {
                // One reading after the flag, too: the state the caller stopped in.
                let done = flag.load(Ordering::SeqCst);
                let status = capture.status();
                seen.push((status.complete, status.incomplete_reason));
                if done {
                    return seen;
                }
                std::thread::sleep(Duration::from_millis(1));
            }
        });
        (stop, handle)
    }

    /// Docker end to end, round 3: every stop ran four final flushes (Mend's, Core's drain, the
    /// SIGTERM handler, the boot's own on the harness's exit), and each after the first walked
    /// the bulk class again — 2.5–3 s each, `complete: false` / `bulk_building: true` meanwhile.
    /// Once a final flush snapped everything with the writers stopped and admission closed, a
    /// final flush asked again, while the watcher has seen no change, snaps nothing: it answers
    /// in milliseconds and `capture.status` reads `complete` throughout. A change the watcher
    /// sees makes the next one snap again.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_final_flush_after_a_complete_one_snaps_nothing_and_stays_complete() {
        let tmp = tempfile::tempdir().unwrap();
        let (boot, registrar) = boot(tmp.path());
        let ws = boot.layout.working_directory.clone();
        std::fs::write(ws.join(".gitignore"), "node_modules/\n").unwrap();
        for p in 0..100 {
            let dir = ws.join(format!("node_modules/pkg{p}"));
            std::fs::create_dir_all(&dir).unwrap();
            for f in 0..40 {
                std::fs::write(dir.join(format!("m{f}.js")), format!("// {p} {f}\n")).unwrap();
            }
        }
        let mut config = RuntimeConfig::new(new_runtime_id());
        config.workspace_root = ws.clone();
        let runtime = Runtime::new(config, Arc::new(ShutdownSignal::new(3_000)));
        runtime.mark_healthy();
        let capture = CaptureRuntime::new(boot);
        assert!(runtime.install_capture(capture.clone()));
        let harness = runtime
            .spawn_managed(sh("exec sleep 3600", &ws))
            .expect("spawn");
        capture.start(runtime.clone(), harness.process_id);
        let modes = capture.runner().snapshot();
        assert_eq!(
            (modes.small_mode, modes.bulk_mode),
            (
                sealant_capture::WatchMode::Watched,
                sealant_capture::WatchMode::Watched
            ),
            "both classes are watched"
        );

        let first = runtime.final_flush(None, Some(3_000)).await.unwrap();
        assert!(first.complete, "{first:?}");
        let registered = registrar.chain().len();

        for _ in 0..3 {
            let (stop, watcher) = watch_status(&capture);
            let before = capture.runner().snapshot();
            let start = Instant::now();
            let again = runtime.final_flush(None, Some(3_000)).await.unwrap();
            let took = start.elapsed();
            let after = capture.runner().snapshot();
            stop.store(true, Ordering::SeqCst);
            let seen = watcher.join().unwrap();
            assert!(again.complete, "{again:?}");
            let not_complete: Vec<_> = seen.iter().filter(|(complete, _)| !complete).collect();
            assert!(
                not_complete.is_empty(),
                "complete throughout: {} of {} readings were not: {:?}",
                not_complete.len(),
                seen.len(),
                not_complete.first()
            );
            // It snaps nothing (and so answers in milliseconds, not the seconds a walk of the
            // bulk class takes): read from the runner's counters, not from the wall clock a
            // loaded runner stretches past any bound.
            assert_eq!(
                (after.small_snaps, after.bulk_snaps),
                (before.small_snaps, before.bulk_snaps),
                "a repeat final flush snaps nothing (it took {took:?})"
            );
        }
        assert_eq!(
            registrar.chain().len(),
            registered,
            "nothing new was captured"
        );
        assert_eq!(runtime.quiesce_count(), 1);

        // Something changes after all (nothing sealantd admitted): the watcher sees it, and
        // the next final flush captures it.
        std::fs::write(ws.join("node_modules/pkg0/late.js"), "late\n").unwrap();
        let start = Instant::now();
        while !capture.runner().snapshot().bulk_dirty {
            assert!(
                start.elapsed() < Duration::from_secs(10),
                "the watcher sees it"
            );
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        let report = runtime.final_flush(None, Some(3_000)).await.unwrap();
        assert!(report.complete, "{report:?}");
        assert_eq!(registrar.chain().len(), registered + 1);
        let fresh = restore_head(tmp.path(), &registrar, "fresh");
        assert_eq!(
            std::fs::read_to_string(fresh.join("node_modules/pkg0/late.js")).unwrap(),
            "late\n"
        );
    }

    /// Docker end to end, round 3: `incomplete_reason` read `not-final` for the whole 38 s of a
    /// running final flush, as if none had been asked for. It reads `in-progress` from the moment
    /// the flush starts (before it stops the writers) until it answers.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_running_final_flush_reads_in_progress() {
        let tmp = tempfile::tempdir().unwrap();
        let (boot, _registrar) = boot_with(tmp.path(), |inner| {
            Arc::new(Slow {
                inner,
                delay: Duration::from_millis(100),
            })
        });
        let ws = tmp.path().join("ws");
        let mut config = RuntimeConfig::new(new_runtime_id());
        config.workspace_root = ws.clone();
        let runtime = Runtime::new(config, Arc::new(ShutdownSignal::new(3_000)));
        runtime.mark_healthy();
        let capture = CaptureRuntime::new(boot);
        assert!(runtime.install_capture(capture.clone()));
        let harness = runtime
            .spawn_managed(sh("exec sleep 600", &ws))
            .expect("spawn");
        capture.start(runtime.clone(), harness.process_id);
        assert_eq!(
            capture.status().incomplete_reason.as_deref(),
            Some("not-final")
        );

        let (stop, watcher) = watch_status(&capture);
        let report = runtime.final_flush(None, Some(2_000)).await.unwrap();
        stop.store(true, Ordering::SeqCst);
        let seen = watcher.join().unwrap();
        assert!(report.complete, "{report:?}");
        // Readings taken before the flush began say `not-final`; from its first moment to its
        // answer, `in-progress`; then nothing (complete).
        let reasons: Vec<Option<String>> = seen.into_iter().map(|(_, reason)| reason).collect();
        let mut distinct: Vec<Option<&str>> = reasons.iter().map(Option::as_deref).collect();
        distinct.dedup();
        assert_eq!(
            distinct.last(),
            Some(&None),
            "complete once it answered: {distinct:?}"
        );
        let running: Vec<Option<&str>> = distinct
            .iter()
            .copied()
            .skip_while(|r| *r == Some("not-final"))
            .collect();
        assert_eq!(
            running,
            [Some("in-progress"), None],
            "`in-progress` while the flush runs, never `not-final` after it began: {distinct:?}"
        );
        assert!(
            reasons
                .iter()
                .filter(|r| r.as_deref() == Some("in-progress"))
                .count()
                > 20,
            "read many times while it ran"
        );
    }

    /// Core's drain sends a final flush with a deadline and polls. A final flush that returns at
    /// its deadline with captures still uploading is `complete: false` (`deadline`) and ends
    /// nothing: the daemon stays up, admission stays closed, the writers stay stopped, and the
    /// ship worker keeps uploading until `capture.status` says `complete`. The same final flush
    /// asked again then answers `complete` without stopping the writers again or taking a new
    /// capture of the unchanged disk.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_final_flush_past_its_deadline_resumes_to_complete() {
        let tmp = tempfile::tempdir().unwrap();
        let (boot, registrar) = boot_with(tmp.path(), |inner| {
            Arc::new(Slow {
                inner,
                delay: Duration::from_millis(150),
            })
        });
        let ws = tmp.path().join("ws");
        let mut config = RuntimeConfig::new(new_runtime_id());
        config.workspace_root = ws.clone();
        let runtime = Runtime::new(config, Arc::new(ShutdownSignal::new(3_000)));
        runtime.mark_healthy();
        let capture = CaptureRuntime::new(boot);
        assert!(runtime.install_capture(capture.clone()));
        let harness = runtime
            .spawn_managed(sh("exec sleep 600", &ws))
            .expect("spawn");
        capture.start(runtime.clone(), harness.process_id);

        let flush = |rid: &'static str, deadline_ms| {
            runtime.dispatch(ControlRequest::new(
                RequestId::new(rid),
                Command::CaptureFlush {
                    kind: CaptureFlushKind::Final,
                    deadline_ms,
                    grace_ms: Some(2_000),
                },
            ))
        };
        let report = flush_report(flush("r1", Some(100)).await);
        assert!(!report.complete, "{report:?}");
        assert_eq!(report.incomplete_reason.as_deref(), Some("deadline"));
        assert!(report.pending > 0, "{report:?}");
        assert_eq!(runtime.quiesce_count(), 1);

        // Still up, still closed, and the worker ships the rest.
        assert_eq!(runtime.state(), sealant_protocol::RuntimeState::Healthy);
        assert!(runtime.admission_is_closed());
        assert_eq!(runtime.health_report().active_processes, 0);
        let start = Instant::now();
        let status = loop {
            let status = capture.status();
            if status.complete {
                break status;
            }
            assert_eq!(
                status.incomplete_reason.as_deref(),
                Some("deadline"),
                "{status:?}"
            );
            assert!(start.elapsed() < Duration::from_secs(60), "{status:?}");
            tokio::time::sleep(Duration::from_millis(100)).await;
        };
        assert_eq!(status.pending, 0);
        let registered = registrar.chain().len();

        let report = flush_report(flush("r2", Some(10_000)).await);
        assert!(report.complete, "{report:?}");
        assert_eq!(runtime.quiesce_count(), 1, "no second quiesce");
        assert_eq!(
            registrar.chain().len(),
            registered,
            "no new capture of an unchanged disk"
        );
        assert!(!runtime.capture_incomplete());
    }

    /// Cross-repo decision 1: a completed final flush is a store-side fact. The flush that
    /// completes registers a sealing capture carrying `final_seal` (complete, its epoch, its
    /// executor) and answers `complete` only once that register is acknowledged. A flush that
    /// returned at its deadline has not sealed: once the worker has shipped the rest,
    /// `capture.status` reads `sealing` (never `complete`), and the final flush asked again
    /// seals without a second quiesce; a third stages nothing.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_complete_final_flush_is_sealed_in_the_store_before_it_says_complete() {
        let tmp = tempfile::tempdir().unwrap();
        let (boot, registrar) = boot_tuned(
            tmp.path(),
            |inner| {
                Arc::new(Slow {
                    inner,
                    delay: Duration::from_millis(150),
                })
            },
            |config| config.executor = Some(EXECUTOR.to_owned()),
        );
        let ws = tmp.path().join("ws");
        let mut config = RuntimeConfig::new(new_runtime_id());
        config.workspace_root = ws.clone();
        let runtime = Runtime::new(config, Arc::new(ShutdownSignal::new(3_000)));
        runtime.mark_healthy();
        let capture = CaptureRuntime::new(boot);
        assert!(runtime.install_capture(capture.clone()));
        let harness = runtime
            .spawn_managed(sh("exec sleep 600", &ws))
            .expect("spawn");
        capture.start(runtime.clone(), harness.process_id);
        let flush = |rid: &'static str, deadline_ms| {
            runtime.dispatch(ControlRequest::new(
                RequestId::new(rid),
                Command::CaptureFlush {
                    kind: CaptureFlushKind::Final,
                    deadline_ms,
                    grace_ms: Some(2_000),
                },
            ))
        };
        let report = flush_report(flush("r1", Some(100)).await);
        assert!(!report.complete, "{report:?}");
        assert_eq!(report.incomplete_reason.as_deref(), Some("deadline"));
        // The worker ships the rest; nothing is sealed, so nothing reads complete.
        let start = Instant::now();
        let status = loop {
            let status = capture.status();
            assert!(
                !status.complete,
                "complete before the seal registered: {status:?}"
            );
            if status.pending == 0 && status.incomplete_reason.as_deref() == Some("sealing") {
                break status;
            }
            assert!(start.elapsed() < Duration::from_secs(60), "{status:?}");
            tokio::time::sleep(Duration::from_millis(100)).await;
        };
        assert!(registrar.seals().is_empty(), "{status:?}");
        assert!(runtime.capture_incomplete());

        // Core, on an empty but unconfirmed queue, asks again: the flush seals and says so.
        let report = flush_report(flush("r2", Some(30_000)).await);
        assert!(report.complete, "{report:?}");
        assert_eq!(runtime.quiesce_count(), 1, "no second quiesce");
        let chain = registrar.chain();
        let head = chain.last().unwrap();
        let seal = sealant_capture::FinalSeal {
            complete: true,
            epoch: 1,
            executor: EXECUTOR.to_owned(),
            boot_id: None,
            boot_generation: None,
            observation: None,
        };
        let sealed = head.manifest.final_seal.clone().unwrap();
        assert!(sealed.same_executor(&seal), "{sealed:?}");
        assert_eq!(head.manifest.kind, sealant_capture::CaptureKind::Final);
        assert_eq!(
            head.manifest.sections,
            chain[chain.len() - 2].manifest.sections,
            "the sealing capture holds the newest capture's sections"
        );
        assert_eq!(registrar.seals(), vec![(head.n, sealed.clone())]);
        // Where the seal and the answers stand (decision 17): one boot, one order, the answer
        // after the seal it reports.
        assert_eq!(report.launch.as_deref(), Some(EXECUTOR));
        assert_eq!(report.boot_id, sealed.boot_id);
        assert_eq!(report.boot_generation, sealed.boot_generation);
        assert_eq!(report.boot_generation, Some(1));
        assert!(
            report.observation > sealed.observation,
            "{report:?} {sealed:?}"
        );
        let later = capture.status();
        assert!(later.observation > report.observation);
        assert_eq!(
            report.head_n,
            Some(head.n),
            "complete after the seal registered"
        );
        assert!(capture.status().complete);
        assert!(!runtime.capture_incomplete());

        // Asked again: nothing staged, the same seal.
        let registered = chain.len();
        let report = flush_report(flush("r3", Some(30_000)).await);
        assert!(report.complete, "{report:?}");
        assert_eq!(registrar.chain().len(), registered);
        assert_eq!(registrar.seals().len(), 1);
    }

    /// A heartbeat answered `lease-lost` (404, Mend round 4) pauses at once — not after the lease
    /// TTL, as any other heartbeat failure — and adopts no epoch; a heartbeat that succeeds again
    /// under the same identity resumes. A re-plan refused as `worktree-leased` changes nothing.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_lost_lease_pauses_at_once_and_a_leased_replan_changes_nothing() {
        let tmp = tempfile::tempdir().unwrap();
        let (boot, registrar) = boot_tuned(
            tmp.path(),
            |store| store,
            |config| {
                config.cadence.heartbeat = Duration::from_millis(50);
                config.cadence.lease_ttl = Duration::from_secs(600);
            },
        );
        let ws = boot.layout.working_directory.clone();
        let mut config = RuntimeConfig::new(new_runtime_id());
        config.workspace_root = ws;
        let runtime = Runtime::new(config, Arc::new(ShutdownSignal::new(3_000)));
        runtime.mark_healthy();
        let capture = CaptureRuntime::new(boot);
        assert!(runtime.install_capture(capture.clone()));
        capture.start_without_harness(runtime.clone());
        let until = |want: bool| {
            let capture = capture.clone();
            async move {
                let deadline = Instant::now() + Duration::from_secs(5);
                while capture.status().paused != want {
                    assert!(Instant::now() < deadline, "paused never became {want}");
                    tokio::time::sleep(Duration::from_millis(20)).await;
                }
            }
        };
        registrar.set_lease_alive(false);
        until(true).await;
        let status = capture.status();
        assert!(!status.fenced);
        assert_eq!((status.worktree_id.as_str(), status.epoch), ("wt-hooks", 1));
        registrar.set_lease_alive(true);
        until(false).await;
        assert_eq!(capture.status().epoch, 1);

        registrar.set_live_epoch(9);
        registrar.refuse_plans_leased(1);
        let refused = tokio::task::spawn_blocking({
            let capture = capture.clone();
            move || capture.replan()
        })
        .await
        .unwrap();
        assert!(refused.is_err());
        assert_eq!(capture.status().epoch, 1, "no epoch adopted");
        capture.runner().stop();
    }

    /// A recovery boot (Core restarted a retained executor): admission is closed from the start
    /// and no harness runs, so nothing but the capture engine touches the disk. An exec is
    /// refused; the final flush snaps the disk as the executor left it — the work it never
    /// snapped included — ships, seals, and answers complete.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_recovery_boot_admits_nothing_and_its_final_flush_saves_the_disk() {
        let tmp = tempfile::tempdir().unwrap();
        let (boot, registrar) = boot_tuned(
            tmp.path(),
            |store| store,
            |config| config.executor = Some(EXECUTOR.to_owned()),
        );
        let ws = boot.layout.working_directory.clone();
        std::fs::write(
            ws.join("src/unsaved.rs"),
            "// never snapped before the exit\n",
        )
        .unwrap();
        let mut config = RuntimeConfig::new(new_runtime_id());
        config.workspace_root = ws.clone();
        let runtime = Runtime::new(config, Arc::new(ShutdownSignal::new(3_000)));
        runtime.mark_healthy();
        runtime.close_admission();
        // A recovery in Docker: sealantd is PID 1 of the container (the unit test's mark keeps
        // the sweep to nothing). Not PID 1 and with no agent's helper list, a recovery cannot
        // see the dead daemon's orphans and is never complete.
        runtime.set_sweep_scope_for_test(crate::sweep::Scope::Namespace);
        let capture = CaptureRuntime::new(boot);
        assert!(runtime.install_capture(capture.clone()));
        capture.start_without_harness(runtime.clone());

        let refused = runtime
            .spawn_managed(sh("echo late > src/late.rs", &ws))
            .expect_err("nothing is admitted");
        assert!(
            format!("{refused:?}").contains("closed admission"),
            "{refused:?}"
        );
        let report = runtime
            .final_flush(None, Some(1_000))
            .await
            .expect("a capture engine");
        assert!(report.complete, "{report:?}");
        assert!(!runtime.capture_incomplete());
        assert_eq!(registrar.seals().len(), 1);
        let fresh = restore_head(tmp.path(), &registrar, "restored");
        assert_eq!(
            std::fs::read_to_string(fresh.join("src/unsaved.rs")).unwrap(),
            "// never snapped before the exit\n"
        );
        assert!(!ws.join("src/late.rs").exists());
    }

    /// A final flush whose quiesce could not stop every writer (here: no subreaper, so an
    /// orphan could not be seen) is incomplete, and writes no seal.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn an_incomplete_quiesce_writes_no_seal() {
        let tmp = tempfile::tempdir().unwrap();
        let (boot, registrar) = boot_tuned(
            tmp.path(),
            |store| store,
            |config| config.executor = Some(EXECUTOR.to_owned()),
        );
        let ws = tmp.path().join("ws");
        let mut config = RuntimeConfig::new(new_runtime_id());
        config.workspace_root = ws.clone();
        let runtime = Runtime::new(config, Arc::new(ShutdownSignal::new(3_000)));
        runtime.mark_healthy();
        runtime.set_subreaper_for_test(false);
        let capture = CaptureRuntime::new(boot);
        assert!(runtime.install_capture(capture.clone()));
        let report = runtime
            .final_flush(None, Some(1_000))
            .await
            .expect("a capture engine");
        assert!(!report.complete, "{report:?}");
        assert_eq!(
            report.incomplete_reason.as_deref(),
            Some("sweep-unavailable")
        );
        assert!(
            registrar
                .chain()
                .iter()
                .all(|h| h.manifest.final_seal.is_none())
        );
        assert!(registrar.seals().is_empty());
    }

    /// A runtime over a workspace with a dependency tree (both classes watched) and a harness
    /// that sleeps: the shape of a Docker end to end's executor.
    async fn watched_runtime(
        base: &Path,
    ) -> (
        Arc<Runtime>,
        Arc<CaptureRuntime>,
        Arc<InMemoryRegistrar>,
        std::path::PathBuf,
    ) {
        let (boot, registrar) = boot(base);
        let ws = boot.layout.working_directory.clone();
        std::fs::write(ws.join(".gitignore"), "node_modules/\n").unwrap();
        for p in 0..20 {
            let dir = ws.join(format!("node_modules/pkg{p}"));
            std::fs::create_dir_all(&dir).unwrap();
            for f in 0..20 {
                std::fs::write(dir.join(format!("m{f}.js")), format!("// {p} {f}\n")).unwrap();
            }
        }
        let mut config = RuntimeConfig::new(new_runtime_id());
        config.workspace_root = ws.clone();
        let runtime = Runtime::new(config, Arc::new(ShutdownSignal::new(3_000)));
        runtime.mark_healthy();
        let capture = CaptureRuntime::new(boot);
        assert!(runtime.install_capture(capture.clone()));
        let harness = runtime
            .spawn_managed(sh("exec sleep 3600", &ws))
            .expect("spawn");
        capture.start(runtime.clone(), harness.process_id);
        let modes = capture.runner().snapshot();
        assert_eq!(
            (modes.small_mode, modes.bulk_mode),
            (
                sealant_capture::WatchMode::Watched,
                sealant_capture::WatchMode::Watched
            ),
            "both classes are watched"
        );
        (runtime, capture, registrar, ws)
    }

    /// Docker end to end, round 4: `sealantctl capture flush --final` inside the executor, then
    /// Mend's Stop sent two suspend flushes, which staged n=22 and n=23 as `suspend` captures
    /// of the unchanged disk; the final flush after them took the no-snap path and sealed
    /// nothing, so the head's kind was `suspend` and Mend concluded the executor was lost. A
    /// suspend flush after a complete final one, over a disk nothing changed since, stages
    /// nothing: it reads the final flush's report.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_suspend_flush_after_a_complete_final_one_stages_nothing() {
        let tmp = tempfile::tempdir().unwrap();
        let (runtime, capture, registrar, _ws) = watched_runtime(tmp.path()).await;

        let first = runtime.final_flush(None, Some(3_000)).await.unwrap();
        assert!(first.complete, "{first:?}");
        let chain = registrar.chain();
        assert_eq!(
            chain.last().unwrap().manifest.kind,
            EngineKind::Final,
            "the final flush ends the chain"
        );
        let registered = chain.len();

        for rid in ["s1", "s2"] {
            let report = flush_report(
                runtime
                    .dispatch(ControlRequest::new(
                        RequestId::new(rid),
                        Command::CaptureFlush {
                            kind: CaptureFlushKind::Suspend,
                            deadline_ms: Some(10_000),
                            grace_ms: None,
                        },
                    ))
                    .await,
            );
            assert!(report.complete, "{report:?}");
            assert_eq!(report.pending, 0, "{report:?}");
        }
        assert_eq!(
            registrar.chain().len(),
            registered,
            "a suspend flush over the final capture of an unchanged disk stages nothing"
        );

        let last = runtime.final_flush(None, Some(3_000)).await.unwrap();
        assert!(last.complete, "{last:?}");
        let chain = registrar.chain();
        assert_eq!(chain.len(), registered);
        assert_eq!(chain.last().unwrap().manifest.kind, EngineKind::Final);
        assert!(capture.status().complete);
    }

    /// Whatever stages a capture after a complete final flush (a turn boundary here), the chain
    /// no longer ends on a final capture: `capture.status` stops saying `complete` (`pending`,
    /// a capture staged after the final flush), and the next final flush seals the chain with
    /// a final capture before it reports `complete` — even though the disk is as the last one
    /// captured it and it snaps nothing.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_capture_staged_after_a_final_flush_is_sealed_by_the_next() {
        let tmp = tempfile::tempdir().unwrap();
        let (runtime, capture, registrar, _ws) = watched_runtime(tmp.path()).await;

        let first = runtime.final_flush(None, Some(3_000)).await.unwrap();
        assert!(first.complete, "{first:?}");
        let registered = registrar.chain().len();

        let resp = runtime
            .dispatch(ControlRequest::new(
                RequestId::new("t1"),
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
        assert!(!staged.unchanged, "a turn capture is staged");
        let chain = wait_chain(&registrar, registered + 1);
        assert_eq!(chain.last().unwrap().manifest.kind, EngineKind::Turn);
        let status = capture.status();
        assert!(!status.complete, "{status:?}");
        assert_eq!(status.incomplete_reason.as_deref(), Some("pending"));

        let start = Instant::now();
        let sealed = runtime.final_flush(None, Some(3_000)).await.unwrap();
        assert!(sealed.complete, "{sealed:?}");
        assert!(
            start.elapsed() < Duration::from_millis(500),
            "nothing to snap: {:?}",
            start.elapsed()
        );
        let chain = registrar.chain();
        assert_eq!(chain.len(), registered + 2);
        assert_eq!(
            chain.last().unwrap().manifest.kind,
            EngineKind::Final,
            "the chain ends on a final capture again"
        );
        assert!(capture.status().complete);
        assert_eq!(runtime.quiesce_count(), 1);
    }

    /// Docker end to end, round 4, on a full disk: every snap failed with `No space left on
    /// device (os error 28)`, which named neither the file nor the step, and every final flush
    /// of the kept executor, its small snap failed already, walked the bulk class for 2.4 s
    /// more. The error names what was written and where; a final flush whose small snap failed
    /// is incomplete without a bulk snap.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_snap_on_a_full_disk_names_the_file_and_the_final_flush_stops_there() {
        let tmp = tempfile::tempdir().unwrap();
        let (runtime, capture, _registrar, ws) = watched_runtime(tmp.path()).await;
        // The first file the snap writes after its objects, made to fail as a full disk does:
        // a write to /dev/full is ENOSPC, for root too.
        let full = ws.join(".sealantd/capture/index/last.tmp");
        std::os::unix::fs::symlink("/dev/full", &full).unwrap();

        let bulk_snaps = capture.runner().snapshot().bulk_snaps;
        let report = runtime.final_flush(None, Some(3_000)).await.unwrap();
        assert!(!report.complete, "{report:?}");
        assert_eq!(
            report.incomplete_reason.as_deref(),
            Some("snapshot-failed"),
            "{report:?}"
        );
        let small = report
            .snaps
            .iter()
            .find(|s| s.class == CaptureClass::Small)
            .expect("the small class's snaps");
        let error = small.last_snap_error.as_deref().expect("a snap error");
        let expected = format!("write {}: No space left on device", full.display());
        assert!(
            error.starts_with(&expected),
            "the error names the operation and the path: {error:?}"
        );
        assert_eq!(
            capture.runner().snapshot().bulk_snaps,
            bulk_snaps,
            "no bulk snap after the small one failed"
        );
    }

    /// Docker end to end, round 4: a session's first executor boots before its `pnpm install`,
    /// so there was no bulk directory at boot, the bulk class polled for the executor's life
    /// (`capture watches registered … bulk=Polled`), and every final flush after a complete one
    /// walked the dependency tree again (a Stop took 15 s, not 6–7 s). A dependency tree made
    /// after the watcher started is watched, and a final flush after a complete one snaps
    /// nothing.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_dependency_tree_installed_after_boot_is_watched_and_a_repeat_final_snaps_nothing() {
        let tmp = tempfile::tempdir().unwrap();
        let (boot, registrar) = boot(tmp.path());
        let ws = boot.layout.working_directory.clone();
        std::fs::write(ws.join(".gitignore"), "node_modules/\n").unwrap();
        let mut config = RuntimeConfig::new(new_runtime_id());
        config.workspace_root = ws.clone();
        let runtime = Runtime::new(config, Arc::new(ShutdownSignal::new(3_000)));
        runtime.mark_healthy();
        let capture = CaptureRuntime::new(boot);
        assert!(runtime.install_capture(capture.clone()));
        let harness = runtime
            .spawn_managed(sh("exec sleep 3600", &ws))
            .expect("spawn");
        capture.start(runtime.clone(), harness.process_id);

        // The install, after boot: a tree made in a staging directory and renamed in, then
        // more made inside it.
        let staged = tmp.path().join("install");
        for p in 0..30 {
            let dir = staged.join(format!(".pnpm/pkg{p}@1/node_modules/pkg{p}"));
            std::fs::create_dir_all(&dir).unwrap();
            for f in 0..10 {
                std::fs::write(dir.join(format!("m{f}.js")), format!("// {p} {f}\n")).unwrap();
            }
        }
        std::fs::rename(&staged, ws.join("node_modules")).unwrap();
        std::fs::create_dir_all(ws.join("node_modules/.bin")).unwrap();
        std::fs::write(ws.join("node_modules/.bin/tool"), "#!/bin/sh\n").unwrap();
        let start = Instant::now();
        while !capture.runner().snapshot().bulk_dirty {
            assert!(
                start.elapsed() < Duration::from_secs(10),
                "the watcher sees the install"
            );
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        let modes = capture.runner().snapshot();
        assert_eq!(
            (modes.small_mode, modes.bulk_mode),
            (
                sealant_capture::WatchMode::Watched,
                sealant_capture::WatchMode::Watched
            ),
            "both classes are watched"
        );

        let first = runtime.final_flush(None, Some(3_000)).await.unwrap();
        assert!(first.complete, "{first:?}");
        let registered = registrar.chain().len();
        let before = capture.runner().snapshot();

        let again = runtime.final_flush(None, Some(3_000)).await.unwrap();
        assert!(again.complete, "{again:?}");
        let after = capture.runner().snapshot();
        assert_eq!(
            (after.small_snaps, after.bulk_snaps),
            (before.small_snaps, before.bulk_snaps),
            "a repeat final flush snaps nothing"
        );
        assert_eq!(registrar.chain().len(), registered);
        let fresh = restore_head(tmp.path(), &registrar, "fresh");
        assert_eq!(
            std::fs::read_to_string(
                fresh.join("node_modules/.pnpm/pkg0@1/node_modules/pkg0/m0.js")
            )
            .unwrap(),
            "// 0 0\n"
        );
        assert!(fresh.join("node_modules/.bin/tool").exists());
    }

    /// Wait until the watcher delivered a write the test just made. It marks the small class
    /// dirty on the write's first event, and the write's other events follow: a final flush
    /// taken before they land reads them as a change after its snaps (`changed`), which on a
    /// loaded runner it did. So the wait goes on a while after the first one.
    async fn watcher_saw_small_change(capture: &CaptureRuntime) {
        let start = Instant::now();
        while !capture.runner().snapshot().small_dirty {
            assert!(
                start.elapsed() < Duration::from_secs(10),
                "the watcher sees it"
            );
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        tokio::time::sleep(Duration::from_millis(250)).await;
    }

    /// Docker end to end, round 5 (session A0): the bulk class polled (a directory `pnpm install`
    /// renamed away before its watch was added), a final flush answered complete, and in the
    /// same millisecond the daemon exited 75: its exit decision re-read the live status, which
    /// a final flush queued behind its own had just reset to `in-progress`. On the review-3
    /// head it was worse: a class that polls made every final flush answer `changed`, so a
    /// daemon whose bulk class polled could never exit 0. The exit follows the outcome of the
    /// daemon's own last completed final flush; a final flush's own answer is complete when
    /// its snaps, taken after every writer stopped, captured the disk; and the status after it
    /// says the polled class leaves currency unknown (`unwatched`), not complete.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn the_exit_follows_the_daemons_own_final_flush_when_a_class_polls() {
        let tmp = tempfile::tempdir().unwrap();
        let (boot, registrar) = boot_tuned(
            tmp.path(),
            |store| store,
            |config| config.executor = Some(EXECUTOR.to_owned()),
        );
        let ws = boot.layout.working_directory.clone();
        std::fs::write(ws.join(".gitignore"), "node_modules/\n").unwrap();
        std::fs::create_dir_all(ws.join("node_modules/pkg")).unwrap();
        std::fs::write(ws.join("node_modules/pkg/index.js"), "// one\n").unwrap();
        let mut config = RuntimeConfig::new(new_runtime_id());
        config.workspace_root = ws.clone();
        let runtime = Runtime::new(config, Arc::new(ShutdownSignal::new(3_000)));
        runtime.mark_healthy();
        let capture = CaptureRuntime::new(boot);
        assert!(runtime.install_capture(capture.clone()));
        let harness = runtime
            .spawn_managed(sh("exec sleep 3600", &ws))
            .expect("spawn");
        capture.start(runtime.clone(), harness.process_id);
        // A directory of the bulk class could not be watched: the class polls.
        capture
            .runner()
            .signal(sealant_capture::ChangeSignal::Unwatched(Class::Bulk));
        assert_eq!(
            capture.runner().snapshot().bulk_mode,
            sealant_capture::WatchMode::Polled
        );

        let first = runtime.final_flush(None, Some(3_000)).await.unwrap();
        assert!(
            first.complete,
            "a final flush over a polled class: {first:?}"
        );
        assert!(!runtime.capture_incomplete());
        assert_eq!(registrar.seals().len(), 1, "sealed");

        // A final flush queued behind that one begins: it cannot know the polled class is as
        // it was, so it snaps again, and the live status reads `in-progress` meanwhile.
        capture.begin_final();
        assert_eq!(
            capture.status().incomplete_reason.as_deref(),
            Some("in-progress")
        );
        assert!(
            !runtime.capture_incomplete(),
            "the exit follows the daemon's own last completed final flush"
        );
        let again = runtime.final_flush(None, Some(3_000)).await.unwrap();
        assert!(again.complete, "{again:?}");
        assert!(!runtime.capture_incomplete());

        // Read later, the status cannot claim the polled class is as the flush left it.
        let status = capture.status();
        assert!(!status.complete, "{status:?}");
        assert_eq!(status.incomplete_reason.as_deref(), Some("unwatched"));
        let fresh = restore_head(tmp.path(), &registrar, "fresh");
        assert_eq!(
            std::fs::read_to_string(fresh.join("node_modules/pkg/index.js")).unwrap(),
            "// one\n"
        );
    }

    /// Docker end to end, round 5: after `pnpm install` in a fresh session the bulk class
    /// polled for the executor's life (a package's `_tmp_` directory was renamed into place
    /// before its watch was added), ~750 MB stayed uncaptured for minutes, and every repeat
    /// final flush walked the dependency tree again (~2.6 s each). An install as `pnpm` does
    /// it — unpack into `<name>_tmp_<pid>_<n>`, rename into place, link from the top — leaves
    /// both classes watched, the final flush's answer stays current, and a repeat final flush
    /// snaps nothing.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_pnpm_install_keeps_the_bulk_class_watched_and_a_repeat_final_snaps_nothing() {
        let tmp = tempfile::tempdir().unwrap();
        let (boot, registrar) = boot(tmp.path());
        let ws = boot.layout.working_directory.clone();
        std::fs::write(ws.join(".gitignore"), "node_modules/\n").unwrap();
        std::fs::create_dir_all(ws.join("node_modules/.pnpm")).unwrap();
        let mut config = RuntimeConfig::new(new_runtime_id());
        config.workspace_root = ws.clone();
        let runtime = Runtime::new(config, Arc::new(ShutdownSignal::new(3_000)));
        runtime.mark_healthy();
        let capture = CaptureRuntime::new(boot);
        assert!(runtime.install_capture(capture.clone()));
        let harness = runtime
            .spawn_managed(sh("exec sleep 3600", &ws))
            .expect("spawn");
        capture.start(runtime.clone(), harness.process_id);

        let modules = ws.join("node_modules");
        for i in 0..300 {
            let store = modules.join(format!(".pnpm/p{i}@1.0.0/node_modules"));
            let staged = store.join(format!("p{i}_tmp_4242_{i}"));
            for sub in [
                "dist/cjs/internal",
                "dist/esm/internal",
                "dist/dts",
                "src/internal",
            ] {
                std::fs::create_dir_all(staged.join(sub)).unwrap();
                std::fs::write(staged.join(sub).join("index.js"), format!("// {i}\n")).unwrap();
            }
            std::fs::rename(&staged, store.join(format!("p{i}"))).unwrap();
            std::os::unix::fs::symlink(
                format!(".pnpm/p{i}@1.0.0/node_modules/p{i}"),
                modules.join(format!("p{i}")),
            )
            .unwrap();
        }
        tokio::time::sleep(Duration::from_millis(500)).await;
        let modes = capture.runner().snapshot();
        assert_eq!(
            (modes.small_mode, modes.bulk_mode),
            (
                sealant_capture::WatchMode::Watched,
                sealant_capture::WatchMode::Watched
            ),
            "both classes are watched after the install"
        );

        let first = runtime.final_flush(None, Some(3_000)).await.unwrap();
        assert!(first.complete, "{first:?}");
        assert!(capture.status().complete, "{:?}", capture.status());
        let before = capture.runner().snapshot();
        let again = runtime.final_flush(None, Some(3_000)).await.unwrap();
        assert!(again.complete, "{again:?}");
        let after = capture.runner().snapshot();
        assert_eq!(
            (after.small_snaps, after.bulk_snaps),
            (before.small_snaps, before.bulk_snaps),
            "a repeat final flush snaps nothing"
        );
        let fresh = restore_head(tmp.path(), &registrar, "fresh");
        assert_eq!(
            std::fs::read_to_string(
                fresh.join("node_modules/.pnpm/p299@1.0.0/node_modules/p299/dist/dts/index.js")
            )
            .unwrap(),
            "// 299\n"
        );
    }

    /// Docker end to end, round 4: a directory past `PATH_MAX` cannot be named to
    /// `inotify_add_watch`, so the small class polled and every final flush after a complete one
    /// snapped it again. It is watched through its descriptor: a repeat final flush snaps
    /// nothing, and a change in it is still captured by the next.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_directory_past_path_max_is_watched_and_a_repeat_final_snaps_nothing() {
        let tmp = tempfile::tempdir().unwrap();
        let (boot, registrar) = boot(tmp.path());
        let ws = boot.layout.working_directory.clone();
        let mut deep = ws.join("notes");
        std::fs::create_dir_all(&deep).unwrap();
        for i in 0..18 {
            deep = deep.join(format!("d{i:02}{}", "x".repeat(240)));
            sealant_capture::longpath::create_dir(&deep).unwrap();
        }
        let file = deep.join("note.txt");
        std::io::Write::write_all(
            &mut sealant_capture::longpath::create(&file).unwrap(),
            b"one\n",
        )
        .unwrap();
        let mut config = RuntimeConfig::new(new_runtime_id());
        config.workspace_root = ws.clone();
        let runtime = Runtime::new(config, Arc::new(ShutdownSignal::new(3_000)));
        runtime.mark_healthy();
        let capture = CaptureRuntime::new(boot);
        assert!(runtime.install_capture(capture.clone()));
        let harness = runtime
            .spawn_managed(sh("exec sleep 3600", &ws))
            .expect("spawn");
        capture.start(runtime.clone(), harness.process_id);
        let modes = capture.runner().snapshot();
        assert_eq!(
            (modes.small_mode, modes.bulk_mode),
            (
                sealant_capture::WatchMode::Watched,
                sealant_capture::WatchMode::Watched
            ),
            "both classes are watched"
        );

        let first = runtime.final_flush(None, Some(3_000)).await.unwrap();
        assert!(first.complete, "{first:?}");
        let registered = registrar.chain().len();
        let before = capture.runner().snapshot();
        let again = runtime.final_flush(None, Some(3_000)).await.unwrap();
        assert!(again.complete, "{again:?}");
        let after = capture.runner().snapshot();
        assert_eq!(
            (after.small_snaps, after.bulk_snaps),
            (before.small_snaps, before.bulk_snaps),
            "a repeat final flush snaps nothing"
        );
        assert_eq!(registrar.chain().len(), registered);

        // A change down there after all: seen, and captured by the next final flush.
        std::io::Write::write_all(
            &mut sealant_capture::longpath::create(&file).unwrap(),
            b"two\n",
        )
        .unwrap();
        watcher_saw_small_change(&capture).await;
        let last = runtime.final_flush(None, Some(3_000)).await.unwrap();
        assert!(last.complete, "{last:?}");
        assert!(registrar.chain().len() > registered);
        let fresh = restore_head(tmp.path(), &registrar, "fresh");
        let restored = fresh.join(file.strip_prefix(&ws).unwrap());
        let mut text = String::new();
        std::io::Read::read_to_string(
            &mut sealant_capture::longpath::open(&restored).unwrap(),
            &mut text,
        )
        .unwrap();
        assert_eq!(text, "two\n");
    }
}
