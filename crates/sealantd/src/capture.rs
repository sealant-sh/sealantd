//! The capture engine inside the daemon (ADR-0015): cadence snaps, the shipper worker, lease
//! heartbeats with the fence that pauses the harness (`SIGSTOP`, never kill), and the
//! `capture.*` / `lease.epoch` control commands.

use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use sealant_capture::registrar::{HeartbeatRequest, RegistrarError};
use sealant_capture::{
    CaptureEngine, CaptureKind as EngineKind, Class, Registrar, ShipWorker, Shipper, SnapRequest,
};
use sealant_protocol::{
    CaptureKind, CaptureStaged, CaptureStatusReport, ControlError, LeaseEpochReport, ProcessId,
    Signal,
};

use crate::boot::capture::CaptureBoot;
use crate::runtime::Runtime;

/// How often the ship worker polls when nothing woke it.
const SHIP_TICK: Duration = Duration::from_secs(5);

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
    engine: Mutex<CaptureEngine>,
    shipper: Arc<Shipper>,
    worker: Mutex<Option<ShipWorker>>,
    registrar: Arc<dyn Registrar>,
    worktree_id: String,
    epoch: u64,
    grace: Duration,
    seq: AtomicU64,
    paused: AtomicBool,
    last_snap_unix_ms: AtomicU64,
    harness: Mutex<Option<ProcessId>>,
}

impl std::fmt::Debug for CaptureRuntime {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CaptureRuntime")
            .field("worktree_id", &self.worktree_id)
            .field("epoch", &self.epoch)
            .finish_non_exhaustive()
    }
}

impl CaptureRuntime {
    /// Wrap a materialized boot. `grace_ms` bounds every flush.
    #[must_use]
    pub fn new(boot: CaptureBoot, grace_ms: u64) -> Arc<Self> {
        let shipper = Arc::new(boot.engine.shipper(boot.sink, boot.registrar.clone()));
        Arc::new(Self {
            engine: Mutex::new(boot.engine),
            shipper,
            worker: Mutex::new(None),
            registrar: boot.registrar,
            worktree_id: boot.worktree_id,
            epoch: boot.epoch,
            grace: Duration::from_millis(grace_ms),
            seq: AtomicU64::new(0),
            paused: AtomicBool::new(false),
            last_snap_unix_ms: AtomicU64::new(0),
            harness: Mutex::new(None),
        })
    }

    /// Start the ship worker, the cadence loop and the heartbeat loop. `harness` is the process
    /// the fence pauses and resumes.
    pub fn start(self: &Arc<Self>, runtime: Arc<Runtime>, harness: ProcessId) {
        *self.harness.lock().unwrap_or_else(|e| e.into_inner()) = Some(harness);
        match ShipWorker::spawn(self.shipper.clone(), SHIP_TICK) {
            Ok(worker) => *self.worker.lock().unwrap_or_else(|e| e.into_inner()) = Some(worker),
            Err(error) => tracing::error!(%error, "capture ship worker failed to start"),
        }
        let cadence = self
            .engine
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .config()
            .cadence;

        // Cadence: a small-class auto snap at most every `max_interval`; an unchanged tree
        // stages nothing. (The 2 s quiet trigger needs the watcher feed; a later commit.)
        let this = Arc::clone(self);
        let rt = runtime.clone();
        tokio::spawn(async move {
            let mut ticker = tokio::time::interval(cadence.max_interval);
            ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
            ticker.tick().await;
            loop {
                ticker.tick().await;
                if rt.shutdown().is_hard() || this.shipper.is_fenced() {
                    continue;
                }
                let snap = Arc::clone(&this);
                match tokio::task::spawn_blocking(move || snap.snap(CaptureKind::Auto)).await {
                    Ok(Ok(staged)) if !staged.unchanged => {
                        tracing::debug!(n = staged.n, "auto capture staged");
                    }
                    Ok(Ok(_)) => {}
                    Ok(Err(error)) => tracing::warn!(%error, "auto capture failed"),
                    Err(error) => tracing::warn!(%error, "auto capture task failed"),
                }
            }
        });

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
                let req = HeartbeatRequest {
                    worktree_id: this.worktree_id.clone(),
                    epoch: this.epoch,
                };
                let result =
                    tokio::task::spawn_blocking(move || registrar.lease_heartbeat(&req)).await;
                match result {
                    Ok(Ok(_)) => {
                        last_ok = Instant::now();
                        if this.paused.load(Ordering::Relaxed) && !this.shipper.is_fenced() {
                            this.resume(&runtime);
                        }
                    }
                    Ok(Err(error @ RegistrarError::Fenced { .. })) => {
                        tracing::warn!(%error, "lease fenced; pausing the harness");
                        this.shipper.status.fenced.store(true, Ordering::Relaxed);
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

    /// Take a small-class snap and stage it; the worker ships it. Blocking.
    ///
    /// # Errors
    /// Returns [`ControlError`] when the snap fails.
    pub fn snap(&self, kind: CaptureKind) -> Result<CaptureStaged, ControlError> {
        let seq = self.seq.fetch_add(1, Ordering::Relaxed);
        let staged = self
            .engine
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .snap(SnapRequest {
                kind: engine_kind(kind),
                class: Class::Small,
                seq,
            })
            .map_err(|error| ControlError::internal(error.to_string()))?;
        self.last_snap_unix_ms
            .store(now_unix_ms(), Ordering::Relaxed);
        if !staged.unchanged
            && let Some(worker) = self
                .worker
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .as_ref()
        {
            worker.wake();
        }
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
        let seq = self.seq.fetch_add(1, Ordering::Relaxed);
        self.engine
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .snap(SnapRequest {
                kind: engine_kind(kind),
                class: Class::Small,
                seq,
            })
            .map_err(|error| ControlError::internal(error.to_string()))?;
        self.last_snap_unix_ms
            .store(now_unix_ms(), Ordering::Relaxed);
        self.shipper
            .flush(deadline)
            .map_err(|error| ControlError::internal(error.to_string()))?;
        Ok(self.status())
    }

    /// Current state.
    #[must_use]
    pub fn status(&self) -> CaptureStatusReport {
        let ship = self.shipper.status.snapshot();
        let engine = self.engine.lock().unwrap_or_else(|e| e.into_inner());
        let staging = engine.staging();
        let pending = staging.pending().map(|p| p.len() as u64).unwrap_or(0);
        let staged_bytes = staging.staged_bytes().unwrap_or(0);
        drop(engine);
        let last = self.last_snap_unix_ms.load(Ordering::Relaxed);
        CaptureStatusReport {
            epoch: self.epoch,
            worktree_id: self.worktree_id.clone(),
            head_n: ship.head_n,
            pending,
            staged_bytes,
            uploaded_objects: ship.uploaded_objects,
            uploaded_bytes: ship.uploaded_bytes,
            registered: ship.registered,
            fenced: ship.fenced,
            paused: self.paused.load(Ordering::Relaxed),
            last_snap_unix_ms: (last != 0).then_some(last),
        }
    }

    /// The lease epoch.
    #[must_use]
    pub fn lease_epoch(&self) -> LeaseEpochReport {
        LeaseEpochReport {
            epoch: self.epoch,
            worktree_id: self.worktree_id.clone(),
            fenced: self.shipper.is_fenced(),
        }
    }
}
