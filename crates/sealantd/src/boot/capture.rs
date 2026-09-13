//! Capture-store workspaces (ADR-0015): at boot, fetch the plan through the session channel,
//! materialize the chain head onto local disk, and hand back an engine seeded to continue the
//! chain under this session's lease epoch.

use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

use sealant_capture::gitpack::GitRepo;
use sealant_capture::manifest::BulkState;
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
    /// The sink objects are fetched from and shipped to.
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

/// Fetch the plan over HTTP, materialize the head into `working_directory`, and open the engine.
///
/// # Errors
/// Returns [`BootError::Config`] when the channel refuses the token or the plan cannot be
/// materialized; the workspace is left as far as materialize got.
pub fn materialize(
    source: &CaptureSourceConfig,
    token: &str,
    working_directory: &Path,
) -> Result<CaptureBoot, BootError> {
    let registrar: Arc<dyn Registrar> =
        Arc::new(HttpRegistrar::new(&source.endpoint, token, CHANNEL_TIMEOUT));
    boot_from(registrar, None, source, working_directory)
}

/// [`materialize`] over any registrar. `sink` is the object store to read the head from; `None`
/// is the presigned-URL sink over the registrar (GET URLs from the plan, PUT URLs minted on
/// demand), which is what a real boot uses.
///
/// # Errors
/// As [`materialize`].
pub(crate) fn boot_from(
    registrar: Arc<dyn Registrar>,
    sink: Option<Arc<dyn BlobSink>>,
    source: &CaptureSourceConfig,
    working_directory: &Path,
) -> Result<CaptureBoot, BootError> {
    let plan = registrar
        .plan_get(&PlanGetRequest::booting(source.worktree_id.clone()))
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
    tracing::info!(
        worktree = %worktree_id,
        epoch,
        head = ?plan.head.as_ref().map(|h| h.n),
        bulk_pending = plan
            .head
            .as_ref()
            .is_some_and(|h| h.manifest.sections.bulk.section().is_none()),
        "capture plan fetched"
    );

    let sink: Arc<dyn BlobSink> = match sink {
        Some(sink) => sink,
        None => {
            let minter = RegistrarMinter::new(
                registrar.clone(),
                &worktree_id,
                epoch,
                plan.get_urls.clone(),
            );
            Arc::new(PresignedHttp::new(Box::new(minter), OBJECT_TIMEOUT))
        }
    };

    let mut config = CaptureConfig::new(&worktree_id, epoch, working_directory);
    config.harness_home = source.harness_home.clone();
    config.watch.raise_limit = source.raise_inotify_limit;

    let previous = match &plan.head {
        Some(head) => {
            let mut targets =
                MaterializeTargets::new(working_directory, source.harness_home.clone());
            targets.bulk_dirs = config.bulk_dirs.clone();
            let materializer = Materializer::new(sink.as_ref(), targets);
            let mut manifest = materializer
                .fetch_manifest(&head.manifest_key, &head.capture_id)
                .map_err(|error| BootError::config(format!("capture head manifest: {error}")))?;
            // The stored bytes verify the head; the plan's answer decides the bulk section: a
            // registrar leaves it `"pending"` when the head's was captured for another platform,
            // and the engine continues the chain that way until this platform's bulk is snapped.
            if head.manifest.sections.bulk.section().is_none() {
                manifest.manifest.sections.bulk = BulkState::pending();
            }
            let report = materializer
                .materialize(&manifest.manifest, MaterializeClass::All)
                .map_err(|error| {
                    BootError::config(format!("capture materialize failed: {error}"))
                })?;
            tracing::info!(
                files = report.files,
                bytes = report.bytes,
                files_skipped = report.files_skipped,
                bytes_skipped = report.bytes_skipped,
                removed = report.removed,
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

#[cfg(test)]
mod tests {
    use std::path::Path;
    use std::process::Command as Proc;

    use sealant_capture::engine::default_platform;
    use sealant_capture::{
        CaptureKind, Class, InMemoryRegistrar, LocalDir, SnapRequest, sink::BlobSink,
    };

    use super::*;

    fn git(root: &Path, args: &[&str]) {
        let out = Proc::new("git")
            .current_dir(root)
            .env("GIT_OPTIONAL_LOCKS", "0")
            .args(args)
            .output()
            .expect("git");
        assert!(out.status.success(), "git {args:?}");
    }

    /// A source workspace with a tracked file and a bulk directory, captured (small + bulk)
    /// into `store` and registered as the head of `registrar`.
    fn capture_source(base: &Path, registrar: &Arc<InMemoryRegistrar>) -> Arc<LocalDir> {
        let src = base.join("src");
        std::fs::create_dir_all(src.join("node_modules/pkg")).unwrap();
        git(&src, &["init", "-q", "-b", "main"]);
        git(&src, &["config", "user.email", "t@t"]);
        git(&src, &["config", "user.name", "t"]);
        std::fs::write(src.join(".gitignore"), "node_modules/\n").unwrap();
        std::fs::write(src.join("lib.rs"), "pub fn f() {}\n").unwrap();
        std::fs::write(
            src.join("node_modules/pkg/index.js"),
            "module.exports = 1;\n",
        )
        .unwrap();
        git(&src, &["add", "-A"]);
        git(&src, &["commit", "-q", "-m", "one"]);
        let sink = Arc::new(LocalDir::new(&base.join("store")).unwrap());
        let mut engine = CaptureEngine::open(CaptureConfig::new("wt-boot", 1, &src), None).unwrap();
        for (class, seq) in [(Class::Small, 1), (Class::Bulk, 2)] {
            engine
                .snap(SnapRequest {
                    kind: CaptureKind::Checkpoint,
                    class,
                    seq,
                })
                .unwrap();
        }
        let dyn_registrar: Arc<dyn Registrar> = registrar.clone();
        engine
            .shipper(sink.clone(), dyn_registrar)
            .ship_pending()
            .unwrap();
        sink
    }

    fn source() -> CaptureSourceConfig {
        CaptureSourceConfig {
            endpoint: "http://unused".to_owned(),
            worktree_id: None,
            harness_home: None,
            raise_inotify_limit: false,
        }
    }

    /// The boot's `plan.get` names this build's platform. A head whose bulk section was
    /// captured for it is restored whole; one captured for another platform comes back
    /// `"pending"` and its bulk directories are not materialized (the install runs on the
    /// control plane's side), while the engine continues the chain from that head.
    #[test]
    fn boot_sends_the_platform_and_skips_another_platforms_bulk() {
        let tmp = tempfile::tempdir().unwrap();
        let registrar = Arc::new(InMemoryRegistrar::new("wt-boot", 1, None));
        let sink = capture_source(tmp.path(), &registrar);
        let head = registrar.head().unwrap();
        let bulk = head.manifest.sections.bulk.section().unwrap().clone();
        assert_eq!(bulk.platform, default_platform());

        let same = tmp.path().join("same");
        let dyn_sink: Arc<dyn BlobSink> = sink.clone();
        let boot = boot_from(registrar.clone(), Some(dyn_sink.clone()), &source(), &same).unwrap();
        assert_eq!(boot.worktree_id, "wt-boot");
        assert!(same.join("lib.rs").exists());
        assert!(same.join("node_modules/pkg/index.js").exists());
        assert!(
            boot.engine
                .previous()
                .unwrap()
                .manifest
                .sections
                .bulk
                .section()
                .is_some()
        );

        // Re-stamp the head's bulk section for another platform: the double answers pending.
        registrar.set_bulk_platform("linux-riscv64-musl");
        let other = tmp.path().join("other");
        let boot = boot_from(registrar.clone(), Some(dyn_sink), &source(), &other).unwrap();
        assert!(other.join("lib.rs").exists());
        assert!(!other.join("node_modules").exists(), "bulk left pending");
        assert_eq!(
            boot.engine.previous().unwrap().manifest.sections.bulk,
            BulkState::pending()
        );
    }
}
