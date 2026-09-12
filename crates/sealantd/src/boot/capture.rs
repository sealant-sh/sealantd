//! Capture-store workspaces (ADR-0015): at boot, fetch the plan through the session channel,
//! materialize the chain head onto local disk, and hand back an engine seeded to continue the
//! chain under this session's lease epoch.

use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

use sealant_capture::gitpack::GitRepo;
use sealant_capture::registrar::{PlanGetRequest, RegistrarMinter};
use sealant_capture::{
    BlobSink, CaptureConfig, CaptureEngine, HttpRegistrar, MaterializeClass, MaterializeTargets,
    Materializer, PresignedHttp, Registrar,
};

use crate::boot::config::CaptureSourceConfig;
use crate::boot::error::BootError;

/// The secret-environment key carrying the session token.
pub const TOKEN_KEY: &str = "SEALANT_CAPTURE_TOKEN";

/// Per-call timeout for the session channel.
const CHANNEL_TIMEOUT: Duration = Duration::from_secs(60);
/// Per-object timeout for presigned PUT/GET (a 64 MiB pack on a slow link).
const OBJECT_TIMEOUT: Duration = Duration::from_secs(600);

/// A materialized capture-store workspace, ready to run.
pub struct CaptureBoot {
    /// The engine, seeded with the chain head.
    pub engine: CaptureEngine,
    /// Presigned-URL sink over the registrar.
    pub sink: Arc<dyn BlobSink>,
    /// The session channel.
    pub registrar: Arc<dyn Registrar>,
    /// Worktree the lease is on.
    pub worktree_id: String,
    /// Lease epoch this session holds.
    pub epoch: u64,
}

impl std::fmt::Debug for CaptureBoot {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CaptureBoot")
            .field("worktree_id", &self.worktree_id)
            .field("epoch", &self.epoch)
            .finish_non_exhaustive()
    }
}

/// Fetch the plan, materialize the head into `working_directory`, and open the engine.
///
/// # Errors
/// Returns [`BootError::Config`] when the channel refuses the token or the plan cannot be
/// materialized; the workspace is left as far as materialize got.
pub fn materialize(
    source: &CaptureSourceConfig,
    token: &str,
    working_directory: &Path,
) -> Result<CaptureBoot, BootError> {
    let registrar = Arc::new(HttpRegistrar::new(&source.endpoint, token, CHANNEL_TIMEOUT));
    let plan = registrar
        .plan_get(&PlanGetRequest {
            worktree_id: source.worktree_id.clone(),
            epoch: 0,
        })
        .map_err(|error| BootError::config(format!("capture plan.get failed: {error}")))?;
    let worktree_id = source
        .worktree_id
        .clone()
        .unwrap_or_else(|| plan.worktree_id.clone());
    if plan.worktree_id != worktree_id {
        return Err(BootError::config(format!(
            "SEALANT_CAPTURE_WORKTREE_ID is {worktree_id} but the session token is scoped to {}",
            plan.worktree_id
        )));
    }
    let epoch = plan.epoch;
    tracing::info!(worktree = %worktree_id, epoch, head = ?plan.head.as_ref().map(|h| h.n), "capture plan fetched");

    let minter = RegistrarMinter::new(
        registrar.clone(),
        &worktree_id,
        epoch,
        plan.get_urls.clone(),
    );
    let sink: Arc<dyn BlobSink> = Arc::new(PresignedHttp::new(Box::new(minter), OBJECT_TIMEOUT));

    let mut config = CaptureConfig::new(&worktree_id, epoch, working_directory);
    config.harness_home = source.harness_home.clone();

    let previous = match &plan.head {
        Some(head) => {
            let targets = MaterializeTargets::new(working_directory, source.harness_home.clone());
            let materializer = Materializer::new(sink.as_ref(), targets);
            let manifest = materializer
                .fetch_manifest(&head.manifest_key, &head.capture_id)
                .map_err(|error| BootError::config(format!("capture head manifest: {error}")))?;
            let report = materializer
                .materialize(&manifest.manifest, MaterializeClass::All)
                .map_err(|error| {
                    BootError::config(format!("capture materialize failed: {error}"))
                })?;
            tracing::info!(
                files = report.files,
                bytes = report.bytes,
                git_packs = report.git_packs,
                fsck = ?report.fsck,
                "capture head materialized"
            );
            Some(manifest)
        }
        None => {
            // An empty chain: the session was created without a base capture. Start from an
            // empty repository so the harness has a workspace; the first capture is capture 0.
            tracing::warn!("capture chain is empty; starting from an empty repository");
            GitRepo::init(working_directory)
                .map_err(|error| BootError::config(format!("git init: {error}")))?;
            None
        }
    };

    let seeded = previous.is_some();
    let mut engine = CaptureEngine::open(config, previous)
        .map_err(|error| BootError::config(format!("capture engine: {error}")))?;
    if seeded {
        engine
            .seed_tips_from_repo()
            .map_err(|error| BootError::config(format!("capture engine seed: {error}")))?;
    }
    Ok(CaptureBoot {
        engine,
        sink,
        registrar,
        worktree_id,
        epoch,
    })
}
