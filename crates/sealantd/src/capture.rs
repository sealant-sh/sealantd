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
    CaptureClass, CaptureKind, CaptureReplanned, CaptureStaged, CaptureStatusReport, ControlError,
    LeaseEpochReport, ProcessId, Signal,
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
    /// Every writer stopped and both classes snapped after that: complete once nothing is
    /// pending (the ship worker keeps going after a flush that returned at its deadline).
    /// `shipping` is why that flush returned with captures pending (`deadline`,
    /// `ship-failed`), reported while they are.
    Snapped { shipping: Option<&'static str> },
    /// It cannot complete as it went; the reason code.
    Incomplete(&'static str),
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
        let flushed = self.runner.flush_final(deadline);
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
        self.status()
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
            // The registrar of the assigned worktree decides whether dir objects travel in
            // dir packs from the next snap on.
            engine.set_dir_format(DirFormat::for_registrar(plan.manifest_format));
            // A standby executor boots under a placeholder worktree, so the sources of the
            // session it is assigned arrive with this plan, not the boot's.
            sources::apply(self.sink.as_ref(), &plan.sources, &self.layout)
                .map_err(|e| internal(&format!("capture sources: {e}")))?;
            // Likewise its remotes: the placeholder has none, and the repository here was built
            // by this executor, never cloned.
            remotes::apply(&self.layout.working_directory, &plan.remotes)
                .map_err(|e| internal(&format!("capture remotes: {e}")))?;
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
        // Complete only after a final flush stopped every writer and snapped both classes, and
        // only once everything is registered: nothing pending, the lease not fenced.
        let outcome = *self.final_outcome.lock().unwrap_or_else(|e| e.into_inner());
        let incomplete_reason = match outcome {
            FinalOutcome::NotRun => Some("not-final"),
            FinalOutcome::Incomplete(reason) => Some(reason),
            FinalOutcome::Snapped { .. } if ship.fenced => Some("fenced"),
            FinalOutcome::Snapped { shipping } if pending > 0 => {
                Some(shipping.unwrap_or("pending"))
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

    fn boot(base: &Path) -> (CaptureBoot, Arc<InMemoryRegistrar>) {
        boot_with(base, |store| store)
    }

    /// [`boot`] over the sink `wrap` makes of the local store.
    fn boot_with(
        base: &Path,
        wrap: impl FnOnce(Arc<dyn BlobSink>) -> Arc<dyn BlobSink>,
    ) -> (CaptureBoot, Arc<InMemoryRegistrar>) {
        let root = base.join("ws");
        std::fs::create_dir_all(root.join("src")).unwrap();
        git(&root, &["init", "-q", "-b", "main"]);
        git(&root, &["config", "user.email", "t@t"]);
        git(&root, &["config", "user.name", "t"]);
        std::fs::write(root.join("src/lib.rs"), "pub fn f() {}\n").unwrap();
        git(&root, &["add", "-A"]);
        git(&root, &["commit", "-q", "-m", "one"]);
        let registrar = Arc::new(InMemoryRegistrar::new("wt-hooks", 1, None));
        let sink = wrap(Arc::new(LocalDir::new(&base.join("store")).unwrap()));
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
            .refs
            .get(sealant_capture::manifest::WORKTREE_TREE_REF)
            .cloned()
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
                allow_plaintext: false,
                ca_pem: None,
                ca_file: None,
                object_ca_pem: None,
                object_ca_file: None,
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
    }

    fn fake_docker(socket: &Path, running: &[&str], stubborn: &[&str]) -> Arc<Mutex<FakeDocker>> {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let state = Arc::new(Mutex::new(FakeDocker {
            running: running.iter().map(|s| (*s).to_owned()).collect(),
            stubborn: stubborn.iter().map(|s| (*s).to_owned()).collect(),
            stops: Vec::new(),
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
                    let (status, body) = {
                        let mut st = state.lock().unwrap();
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
        let (runtime, _capture, _registrar) = quiet_runtime(tmp.path());
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
}
