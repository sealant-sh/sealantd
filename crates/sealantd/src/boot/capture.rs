//! Capture-store workspaces (ADR-0015): at boot, fetch the plan through the session channel,
//! materialize the chain head onto local disk, and hand back an engine seeded to continue the
//! chain under this session's lease epoch.

use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use sealant_capture::engine::Pickup;
use sealant_capture::gitpack::GitRepo;
use sealant_capture::manifest::{BulkState, DirFormat, Sections};
use sealant_capture::materialize::{DiskState, MaterializedCapture};
use sealant_capture::registrar::{PlanGetRequest, RegistrarMinter};
use sealant_capture::{
    BlobSink, CaptureConfig, CaptureEngine, ChannelTransport, HttpRegistrar, MaterializeClass,
    MaterializeTargets, Materializer, PresignedHttp, Registrar,
};

use crate::boot::config::CaptureSourceConfig;
use crate::boot::error::BootError;
use crate::boot::remotes;
use crate::boot::sources;

/// The secret-environment key carrying the session token.
pub const TOKEN_KEY: &str = "SEALANT_CAPTURE_TOKEN";

/// Per-call timeout for the session channel.
const CHANNEL_TIMEOUT: Duration = Duration::from_secs(60);
/// Per-object timeout for presigned PUT/GET (a 64 MiB pack on a slow link).
const OBJECT_TIMEOUT: Duration = Duration::from_secs(600);

/// The URL minter behind a presigned sink, shared with the daemon so a re-plan can reset it.
pub type SharedMinter = Arc<RegistrarMinter<dyn Registrar>>;

/// A materialized capture-store workspace, ready to run.
pub struct CaptureBoot {
    /// The engine, seeded with the chain head.
    pub engine: CaptureEngine,
    /// The sink objects are fetched from and shipped to.
    pub sink: Arc<dyn BlobSink>,
    /// The session channel.
    pub registrar: Arc<dyn Registrar>,
    /// The URL minter behind a presigned sink, for a re-plan to point at the new plan's URLs;
    /// none when the sink reads the store directly.
    pub minter: Option<SharedMinter>,
    /// Worktree the lease is on.
    pub worktree_id: String,
    /// Lease epoch this session holds.
    pub epoch: u64,
    /// Where content the plan names beside the worktree may land, and where its stamps live: a
    /// re-plan lays down the sources of the worktree it is assigned (a standby executor boots
    /// under a placeholder and only then learns whose session it is).
    pub layout: SourceLayout,
    /// The disk was this executor's own continuation of the chain (a daemon restart): it was
    /// left as it is, and both classes are snapped once the cadence starts, so whatever changed
    /// after the last snap is captured.
    pub resumed: bool,
}

/// Bring a stored head's sections to what this executor continues the chain from, given the
/// bulk section the registrar answered for it (`plan.get`'s head). The answered section is the
/// one restored here when the head holds it and it was captured on `platform`; otherwise the
/// bulk section is `"pending"` (restore nothing, sweep nothing, the next bulk snap captures the
/// disk). Either way every bulk section the head holds for another platform is kept in
/// `other_bulk`: before, a registrar's `"pending"` for another platform's dependency tree
/// replaced it in the engine's copy of the head, and the next capture dropped it from the chain
/// for good, so the platform it was built on could never restore it again.
pub(crate) fn continue_bulk(sections: &mut Sections, answered: &BulkState, platform: &str) {
    let answered = match answered.section() {
        Some(section) if section.platform == platform => answered.clone(),
        Some(section) => {
            tracing::warn!(
                answered = %section.platform,
                platform,
                "the registrar answered another platform's bulk section; not restored here"
            );
            BulkState::pending()
        }
        None => BulkState::pending(),
    };
    *sections = sections.with_bulk_answer(&answered);
    if !sections.other_bulk.is_empty() {
        tracing::info!(
            platforms = ?sections.other_bulk.keys().collect::<Vec<_>>(),
            "bulk sections of other platforms carried on the chain"
        );
    }
}

/// The paths `sources` are resolved against.
#[derive(Debug, Clone)]
pub struct SourceLayout {
    /// `SEALANT_WORKSPACE_ROOT`: every source lands under it.
    pub workspace_root: PathBuf,
    /// The worktree; no source may land inside it.
    pub working_directory: PathBuf,
    /// Capture staging, which holds the content stamps and the extraction scratch space.
    pub staging_dir: PathBuf,
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
    workspace_root: &Path,
) -> Result<CaptureBoot, BootError> {
    // Refused here, before the token leaves the process: plain HTTP beyond loopback without the
    // launcher's explicit exception, a scheme that is not http(s), or an unreadable CA bundle.
    let transport = transport_of(source)?;
    if transport.plaintext_allowed() {
        tracing::warn!(
            "SEALANT_CAPTURE_ALLOW_PLAINTEXT is set: the session channel and object URLs may be \
             dialled over plain HTTP; the network between this executor and them must be private"
        );
    }
    let registrar: Arc<dyn Registrar> = Arc::new(
        HttpRegistrar::new(&source.endpoint, token, CHANNEL_TIMEOUT, &transport)
            .map_err(|refusal| BootError::config(refusal.to_string()))?,
    );
    boot_from(registrar, None, source, working_directory, workspace_root)
}

/// The session's transport policy, from the capture source's environment.
///
/// # Errors
/// [`BootError::Config`] when a CA bundle cannot be read or holds no certificate.
pub(crate) fn transport_of(source: &CaptureSourceConfig) -> Result<ChannelTransport, BootError> {
    let bundle = |pem: &Option<String>, file: &Option<PathBuf>, name: &str| match (pem, file) {
        (Some(pem), _) => Ok(Some(pem.clone())),
        (None, Some(path)) => std::fs::read_to_string(path)
            .map(Some)
            .map_err(|error| BootError::config(format!("{name} {}: {error}", path.display()))),
        (None, None) => Ok(None),
    };
    let mut transport = ChannelTransport::verified().allow_plaintext(source.allow_plaintext);
    if let Some(pem) = bundle(&source.ca_pem, &source.ca_file, "SEALANT_CAPTURE_CA_FILE")? {
        transport = transport
            .with_channel_ca_pem(&pem)
            .map_err(|error| BootError::config(error.to_string()))?;
    }
    if let Some(pem) = bundle(
        &source.object_ca_pem,
        &source.object_ca_file,
        "SEALANT_CAPTURE_OBJECT_CA_FILE",
    )? {
        transport = transport
            .with_object_ca_pem(&pem)
            .map_err(|error| BootError::config(format!("object store: {error}")))?;
    }
    Ok(transport)
}

/// Whether the disk at `working_directory` was never materialized, verified: `Ok` only when the
/// worktree is absent, or a real directory (not a symlink) holding nothing but the daemon's own
/// directory `.sealantd`, itself a real directory holding nothing but an empty regular
/// `boot.lock` ([`crate::boot::lock`], taken before anything else). So: no materialize record
/// (`.sealantd/capture/index/materialized.json`), no staging and no other capture state
/// (`.sealantd/capture/`), no repository, no file of any kind. Capture starts right after a
/// materialize and before any user code (cross-repo decision 8), so on such a disk no user code
/// ran and nothing is work product. `Err` names the first thing found (a recovery then goes on,
/// and exits 75 if it cannot save it). Read-only; the caller holds the disk lock.
///
/// # Errors
/// What makes the disk anything but never materialized, or what could not be read.
pub fn never_materialized(working_directory: &Path) -> Result<(), String> {
    let only = |dir: &Path, allowed: &str| -> Result<Option<PathBuf>, String> {
        let mut found = None;
        let entries = std::fs::read_dir(dir).map_err(|e| format!("{}: {e}", dir.display()))?;
        for entry in entries {
            let entry = entry.map_err(|e| format!("{}: {e}", dir.display()))?;
            if entry.file_name() != allowed {
                return Err(format!("{} holds {:?}", dir.display(), entry.file_name()));
            }
            found = Some(entry.path());
        }
        Ok(found)
    };
    let meta = match std::fs::symlink_metadata(working_directory) {
        Ok(meta) => meta,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(e) => return Err(format!("{}: {e}", working_directory.display())),
    };
    if !meta.file_type().is_dir() {
        return Err(format!(
            "{} is not a directory",
            working_directory.display()
        ));
    }
    let Some(daemon_dir) = only(working_directory, sealant_capture::index::DAEMON_DIR)? else {
        return Ok(());
    };
    if !std::fs::symlink_metadata(&daemon_dir)
        .map_err(|e| format!("{}: {e}", daemon_dir.display()))?
        .file_type()
        .is_dir()
    {
        return Err(format!("{} is not a directory", daemon_dir.display()));
    }
    let Some(lock) = only(&daemon_dir, "boot.lock")? else {
        return Ok(());
    };
    let lock_meta =
        std::fs::symlink_metadata(&lock).map_err(|e| format!("{}: {e}", lock.display()))?;
    if !lock_meta.file_type().is_file() || lock_meta.len() != 0 {
        return Err(format!("{} is not the empty lock file", lock.display()));
    }
    Ok(())
}

/// How long a boot first waits to ask `plan.get` again while another launch holds the lease;
/// it doubles up to [`PLAN_LEASED_WAIT_MAX`].
const PLAN_LEASED_WAIT: Duration = Duration::from_secs(1);

/// The longest wait between two `plan.get`s refused as `worktree-leased`.
const PLAN_LEASED_WAIT_MAX: Duration = Duration::from_secs(30);

/// [`materialize`] over any registrar. `sink` is the object store to read the head from; `None`
/// is the presigned-URL sink over the registrar (GET URLs from the plan, PUT URLs minted on
/// demand), which is what a real boot uses.
///
/// # Errors
/// As [`materialize`].
#[doc(hidden)]
pub fn boot_from(
    registrar: Arc<dyn Registrar>,
    sink: Option<Arc<dyn BlobSink>>,
    source: &CaptureSourceConfig,
    working_directory: &Path,
    workspace_root: &Path,
) -> Result<CaptureBoot, BootError> {
    // The launch this executor is, from the very first request (cross-repo decision 11): as
    // the launcher named it, else as this disk last served (a restart, a recovery boot).
    let claimed = source.launch_id.clone().or_else(|| {
        CaptureEngine::disk_launch(&CaptureConfig::new("", 0, working_directory).staging_dir())
    });
    let request = PlanGetRequest::booting(source.worktree_id.clone()).with_launch(claimed.clone());
    // Another launch holds the worktree (409 `worktree-leased`): no epoch is this executor's,
    // and it adopts none — it waits, touching nothing, and asks again until it is given one.
    let mut wait = PLAN_LEASED_WAIT;
    let plan = loop {
        match registrar.plan_get(&request) {
            Err(sealant_capture::RegistrarError::WorktreeLeased) => {
                tracing::warn!(
                    retry_in_ms = wait.as_millis() as u64,
                    "capture plan.get: another launch holds the worktree's lease; waiting"
                );
                std::thread::sleep(wait);
                wait = (wait * 2).min(PLAN_LEASED_WAIT_MAX);
            }
            other => {
                break other.map_err(|error| {
                    BootError::config(format!("capture plan.get failed: {error}"))
                })?;
            }
        }
    };
    // A plan for another launch is not this executor's: capturing under it would seal (or
    // resume) as a launch it is not.
    if let (Some(named), Some(executor)) = (&source.launch_id, &plan.executor)
        && named != executor
    {
        return Err(BootError::config(format!(
            "SEALANT_CAPTURE_LAUNCH_ID is {named} but the plan answers executor {executor}: the \
             session token is another launch's; refusing to capture under it"
        )));
    }
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
        manifest_format = plan.manifest_format,
        bulk_pending = plan
            .head
            .as_ref()
            .is_some_and(|h| h.manifest.sections.bulk.section().is_none()),
        "capture plan fetched"
    );

    let (sink, minter): (Arc<dyn BlobSink>, Option<SharedMinter>) = match sink {
        Some(sink) => (sink, None),
        None => {
            let minter = Arc::new(RegistrarMinter::new(
                registrar.clone(),
                &worktree_id,
                epoch,
                plan.get_urls.clone(),
            ));
            let sink = PresignedHttp::with_transport(
                Box::new(minter.clone()),
                OBJECT_TIMEOUT,
                // Built again rather than threaded through every `boot_from` caller: two small
                // reads of the same bundles, once per boot.
                &transport_of(source)?,
            );
            (Arc::new(sink), Some(minter))
        }
    };

    let mut config = CaptureConfig::new(&worktree_id, epoch, working_directory);
    config.harness_home = source.harness_home.clone();
    // The executor a completed final flush is sealed under: the launch the session token was
    // issued for, as the plan names it (cross-repo decision 5), and nothing else — not the
    // workspace id this daemon was started as, which names a runtime resource, not a launch.
    config.executor = plan.executor.clone();
    if config.executor.is_none() {
        tracing::warn!(
            "plan.get names no executor: a completed final flush is not sealed on the chain, \
             only reported"
        );
    }
    // Dir packs only for a registrar that reads them; either format materializes here.
    config.dir_format = DirFormat::for_registrar(plan.manifest_format);
    // The git section's trees in their own fields (and the raw tree beside them) only for a
    // registrar that reads them; for one that does not, the trees ride `refs` as before. A
    // store that does not read every feature this build writes cannot hold what a capture
    // holds: captures still ship (crash protection), but no final flush over it is complete or
    // sealed (decision 12; review 2026-09-28, fourth pass, #7).
    config.set_store_features(&plan.manifest_features);
    // And the repository the writers get: a SHA-256 or reftable one — the head's, or the one
    // already on this disk — needs the store to read `object_format` or `ref_format`. Refused
    // here, before anything runs, rather than by the final flush after the writers' work
    // (review 2026-09-28, tenth pass).
    let head_git = plan.head.as_ref().map(|h| &h.manifest.sections.git);
    if let Some(gap) = config.admission_gap(head_git, working_directory) {
        // No writer admission without full fidelity (decision 16; review 2026-09-28, fifth
        // pass, #5): every capture over such a store — the periodic ones a hard crash would be
        // picked up from, not only the final one — restores less than the disk held, so no user
        // code may write here. Refused before the disk is touched: nothing is materialized, no
        // dotfiles, lifecycle step or harness runs. A recovery boot admits no writer at all: it
        // ships what the store can take, and its final flush says incomplete (the executor is
        // kept until a registrar that reads every feature saves it).
        if !source.recovery {
            tracing::error!(
                %gap,
                unread = %config.unread_features.join(", "),
                "the registrar cannot hold what a capture holds; refusing to admit user code"
            );
            return Err(BootError::StoreUnfit(gap));
        }
        tracing::error!(
            %gap,
            unread = %config.unread_features.join(", "),
            "recovery over a registrar that cannot hold what a capture holds: what ships is the \
             most it can take, and no final flush will say complete"
        );
    }
    config.watch.raise_limit = source.raise_inotify_limit;
    let layout = SourceLayout {
        workspace_root: workspace_root.to_path_buf(),
        working_directory: working_directory.to_path_buf(),
        staging_dir: config.staging_dir(),
    };

    // A daemon restarting on its own disk finds it at or past the head: staged captures not
    // shipped yet, and whatever changed after the last snap. Materializing the head over it
    // would take that work back, so the disk is left as it is and the queue resumes.
    let pickup = CaptureEngine::pickup(&config, plan.head.as_ref().map(|h| h.capture_id.as_str()))
        .map_err(|error| BootError::config(format!("capture staging: {error}")))?;
    let mut resumed = matches!(pickup, Pickup::Resume { .. });
    // A recovery boot restores nothing: the disk holds work no registered capture has, and a
    // materialize would take it back. It resumes this disk as it is when the disk is provably
    // this executor's own continuation of the head — its staging continues the head (above), or
    // its materialize of exactly the head's capture completed under this plan's executor at an
    // epoch no later than the plan's (and every change since is on disk, to be snapped) — and
    // refuses to boot otherwise, touching nothing. Equal worktree trees are not that proof:
    // two captures can share one and differ in refs, index, bulk or metadata, and recovering a
    // stale disk against a head that moved on would register its old state as the successor
    // (review 2026-09-28 #22).
    if source.recovery && !resumed {
        let materialized = DiskState::load(&config.staging_dir().join("index")).capture;
        let holds_head = match (&plan.head, &materialized) {
            (Some(head), Some(disk)) => {
                let bound = disk.capture_id == head.capture_id
                    && disk.executor == plan.executor
                    && disk.epoch <= epoch;
                if !bound {
                    tracing::error!(
                        disk_capture = %disk.capture_id,
                        disk_epoch = disk.epoch,
                        disk_executor = ?disk.executor,
                        head_capture = %head.capture_id,
                        plan_epoch = epoch,
                        plan_executor = ?plan.executor,
                        "recovery: the disk's materialize is not this plan's head under this \
                         executor and lease"
                    );
                }
                bound
            }
            (Some(_), None) => false,
            (None, _) => working_directory.join(".git").exists(),
        };
        if !holds_head {
            return Err(BootError::config(format!(
                "recovery: {} is not this executor's continuation of the chain head (no staging \
                 that continues it, and no completed materialize of exactly that capture under \
                 this executor and lease); refusing to materialize over it or to capture it — \
                 the disk is left as it is",
                working_directory.display()
            )));
        }
        tracing::warn!(
            "recovery: no staging continues the head, but the head's materialize completed on \
             this disk under this executor and lease; resuming it as it is"
        );
        resumed = true;
    }
    if source.recovery {
        tracing::warn!(
            "recovery boot: resuming this disk's own staging; no lifecycle step, no harness, no \
             exec or session admitted — the final flush saves what is here"
        );
    }
    if let Pickup::Resume {
        queued,
        epoch_changed,
    } = pickup
    {
        tracing::info!(
            queued,
            epoch_changed,
            "capture resumed on this disk: the head is not materialized over it"
        );
    }
    // Whether the head restored a session's own `.git/config` (a base carries none).
    let mut captured_config = false;
    let previous = match &plan.head {
        Some(head) if resumed => {
            let manifest = Materializer::new(
                sink.as_ref(),
                MaterializeTargets::new(working_directory, source.harness_home.clone()),
            )
            .fetch_manifest(&head.manifest_key, &head.capture_id)
            .map_err(|error| BootError::config(format!("capture head manifest: {error}")))?;
            Some(manifest)
        }
        None if resumed => None,
        Some(head) => {
            let mut targets =
                MaterializeTargets::new(working_directory, source.harness_home.clone());
            targets.bulk_dirs = config.bulk_dirs.clone();
            let materializer = Materializer::new(sink.as_ref(), targets);
            let mut manifest = materializer
                .fetch_manifest(&head.manifest_key, &head.capture_id)
                .map_err(|error| BootError::config(format!("capture head manifest: {error}")))?;
            // The stored bytes verify the head; the plan's answer decides the bulk section
            // restored here, and every other bulk section the head holds is carried on.
            continue_bulk(
                &mut manifest.manifest.sections,
                &head.manifest.sections.bulk,
                &config.platform,
            );
            let report = materializer
                .materialize(&manifest.manifest, MaterializeClass::All)
                .map_err(|error| {
                    BootError::config(format!("capture materialize failed: {error}"))
                })?;
            captured_config = report.git_config;
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
            // What a recovery boot on this disk binds to.
            DiskState::record_capture(
                &config.staging_dir().join("index"),
                MaterializedCapture {
                    capture_id: head.capture_id.clone(),
                    epoch,
                    executor: plan.executor.clone(),
                },
            )
            .map_err(|error| BootError::config(format!("capture materialize record: {error}")))?;
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

    // Content beside the worktree (Mend's folders and reference repositories): outside the
    // worktree, so it is laid down after the head and never enters a capture.
    sources::apply(sink.as_ref(), &plan.sources, &layout)?;

    // The plan's remotes seed a base only: a repository built here from an empty chain, or
    // from a capture that carries no `.git/config` (Mend's capture 0). A capture that carries
    // one is a session's own configuration and is authoritative, a remote the user removed
    // included (review 2026-09-28, fourth pass, #8: a fresh executor added it back). A disk
    // resumed as it is — a restart, a recovery boot — keeps its configuration byte for byte:
    // the user may have changed a remote since the last capture, and only the next capture may
    // save it (review 2026-09-28 #13).
    if !resumed && !captured_config {
        remotes::apply(working_directory, &plan.remotes)?;
    }

    // A resumed disk's repository holds objects no registered capture carries yet: its tips are
    // not the chain's, and the engine keeps the ones it staged under this identity.
    let seeded = previous.is_some() && !resumed;
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
        minter,
        worktree_id,
        epoch,
        layout,
        resumed,
    })
}

#[cfg(test)]
mod tests {
    use std::path::Path;
    use std::process::Command as Proc;

    use sealant_capture::engine::default_platform;
    use sealant_capture::registrar::PlanSource;
    use sealant_capture::sink::BlobSource;
    use sealant_capture::{
        CaptureKind, Class, InMemoryRegistrar, LocalDir, SnapRequest, sink::BlobSink,
    };
    use sha2::{Digest, Sha256};
    use std::os::unix::fs::PermissionsExt;

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
        capture_source_on(base, registrar, &default_platform())
    }

    /// [`capture_source`] on an executor of `platform` (the key its bulk section is stamped
    /// with).
    fn capture_source_on(
        base: &Path,
        registrar: &Arc<InMemoryRegistrar>,
        platform: &str,
    ) -> Arc<LocalDir> {
        capture_source_with(base, registrar, platform, true, &[])
    }

    /// [`capture_source`] as Mend registers a base (capture 0): no `.git/config`, so no
    /// configuration of a session's travels in it.
    fn capture_base(base: &Path, registrar: &Arc<InMemoryRegistrar>) -> Arc<LocalDir> {
        capture_source_with(base, registrar, &default_platform(), false, &[])
    }

    /// `init` are further `git init` options (`--ref-format=reftable`).
    fn capture_source_with(
        base: &Path,
        registrar: &Arc<InMemoryRegistrar>,
        platform: &str,
        with_config: bool,
        init: &[&str],
    ) -> Arc<LocalDir> {
        let src = base.join("src");
        std::fs::create_dir_all(src.join("node_modules/pkg")).unwrap();
        let mut args = vec!["init", "-q", "-b", "main"];
        args.extend_from_slice(init);
        git(&src, &args);
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
        if !with_config {
            std::fs::remove_file(src.join(".git/config")).unwrap();
        }
        let sink = Arc::new(LocalDir::new(&base.join("store")).unwrap());
        let mut config = CaptureConfig::new("wt-boot", 1, &src);
        config.platform = platform.to_owned();
        let mut engine = CaptureEngine::open(config, None).unwrap();
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

    #[test]
    fn a_plain_http_channel_beyond_loopback_refuses_boot_before_dialling() {
        let mut plain = source();
        plain.endpoint = "http://mend-api:3106/channel".to_owned();
        let tmp = tempfile::tempdir().unwrap();
        let refusal = materialize(&plain, "session-token", &tmp.path().join("ws"), tmp.path())
            .expect_err("refused");
        let text = refusal.to_string();
        assert!(text.contains("plain http to mend-api"), "{text}");
        assert!(text.contains("SEALANT_CAPTURE_ALLOW_PLAINTEXT"), "{text}");
        assert!(!text.contains("session-token"), "{text}");
    }

    #[test]
    fn an_unreadable_or_empty_ca_bundle_refuses_boot() {
        let mut missing = source();
        missing.ca_file = Some(PathBuf::from("/nonexistent/channel-ca.pem"));
        assert!(
            transport_of(&missing)
                .unwrap_err()
                .to_string()
                .contains("SEALANT_CAPTURE_CA_FILE")
        );
        let mut empty = source();
        empty.ca_pem = Some("not a certificate".to_owned());
        assert!(transport_of(&empty).is_err());
    }

    fn source() -> CaptureSourceConfig {
        CaptureSourceConfig {
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
        let boot = boot_from(
            registrar.clone(),
            Some(dyn_sink.clone()),
            &source(),
            &same,
            tmp.path(),
        )
        .unwrap();
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
        let boot = boot_from(
            registrar.clone(),
            Some(dyn_sink),
            &source(),
            &other,
            tmp.path(),
        )
        .unwrap();
        assert!(other.join("lib.rs").exists());
        assert!(!other.join("node_modules").exists(), "bulk left pending");
        assert_eq!(
            boot.engine.previous().unwrap().manifest.sections.bulk,
            BulkState::pending()
        );
    }

    /// A recovery boot never materializes over the disk. An executor materialized the head and
    /// wrote work it never snapped, and nothing on its disk says its staging continues the head
    /// (it died before its engine recorded one): an ordinary boot on that disk materializes the
    /// head again and takes the work back; a recovery boot resumes the disk as it is (its
    /// materialize of the head completed), and its engine continues from the head. A disk that
    /// is not this executor's continuation of the head (nothing materialized, nothing staged)
    /// is refused, touched by nothing.
    #[test]
    fn a_recovery_boot_resumes_the_disk_and_never_materializes_over_it() {
        let tmp = tempfile::tempdir().unwrap();
        let registrar = Arc::new(InMemoryRegistrar::new("wt-boot", 1, None));
        let sink = capture_source(tmp.path(), &registrar);
        let dyn_sink: Arc<dyn BlobSink> = sink.clone();
        let head = registrar.head().unwrap();
        let recovery = CaptureSourceConfig {
            recovery: true,
            ..source()
        };
        // The executor's first boot, the work it wrote before any snap, and no record of what
        // its staging continues.
        let first_boot = |disk: &Path| {
            drop(
                boot_from(
                    registrar.clone(),
                    Some(dyn_sink.clone()),
                    &source(),
                    disk,
                    tmp.path(),
                )
                .unwrap(),
            );
            std::fs::write(disk.join("unsaved.rs"), "// written, never snapped\n").unwrap();
            std::fs::write(disk.join("lib.rs"), "pub fn f() { edited() }\n").unwrap();
            let _ = std::fs::remove_file(disk.join(".sealantd/capture/index/last.json"));
        };
        // Everything but the daemon's own directory, which the engine keeps.
        let work = |dir: &Path| -> Vec<(String, Vec<u8>)> {
            tree(dir)
                .into_iter()
                .filter(|(rel, _)| !rel.starts_with(".sealantd/"))
                .collect()
        };

        // An ordinary boot on such a disk materializes the head over it: the new file goes.
        let copy = tmp.path().join("copy");
        first_boot(&copy);
        let rebooted = boot_from(
            registrar.clone(),
            Some(dyn_sink.clone()),
            &source(),
            &copy,
            tmp.path(),
        )
        .unwrap();
        assert!(!rebooted.resumed);
        assert!(
            !copy.join("unsaved.rs").exists(),
            "an ordinary boot sweeps the work the head does not hold: what a recovery boot \
             must never do"
        );
        drop(rebooted);

        // A recovery boot on the same kind of disk resumes it as it is.
        let disk = tmp.path().join("disk");
        first_boot(&disk);
        let before = work(&disk);
        let boot = boot_from(
            registrar.clone(),
            Some(dyn_sink.clone()),
            &recovery,
            &disk,
            tmp.path(),
        )
        .unwrap();
        assert!(boot.resumed, "the disk is resumed, not materialized over");
        assert_eq!(work(&disk), before, "nothing on the disk changed");
        assert_eq!(
            boot.engine.previous().unwrap().capture_id,
            head.capture_id,
            "the engine continues from the head"
        );
        drop(boot);

        // A disk nothing materialized: refused, untouched.
        let foreign = tmp.path().join("foreign");
        std::fs::create_dir_all(&foreign).unwrap();
        std::fs::write(foreign.join("notes.txt"), "someone's work\n").unwrap();
        match boot_from(registrar, Some(dyn_sink), &recovery, &foreign, tmp.path()) {
            Ok(_) => panic!("a recovery boot over a disk that is not the executor's own"),
            Err(refused) => assert!(refused.to_string().contains("recovery"), "{refused}"),
        }
        assert_eq!(
            tree(&foreign),
            vec![("notes.txt".to_owned(), b"someone's work\n".to_vec())]
        );
    }

    /// Every file under `dir` with its bytes, sorted.
    fn tree(dir: &Path) -> Vec<(String, Vec<u8>)> {
        let mut out = Vec::new();
        let mut stack = vec![dir.to_path_buf()];
        while let Some(d) = stack.pop() {
            for entry in std::fs::read_dir(&d).unwrap() {
                let path = entry.unwrap().path();
                if path.is_dir() {
                    stack.push(path);
                } else {
                    let rel = path.strip_prefix(dir).unwrap().display().to_string();
                    out.push((rel, std::fs::read(&path).unwrap()));
                }
            }
        }
        out.sort();
        out
    }

    /// Another platform's dependency tree is never dropped from the chain. The head was captured
    /// on `linux-riscv64-musl`; this executor boots on its own platform, the registrar answers
    /// the bulk section `"pending"`, and nothing is restored here. The executor keeps the riscv
    /// section in `other_bulk`, through a small capture and through its own bulk capture (which
    /// takes `bulk`), so a riscv executor booting on the chain head afterwards is answered that
    /// section and restores it byte for byte. Before, the first capture here dropped it.
    #[test]
    fn another_platforms_bulk_stays_on_the_chain_and_restores_there() {
        let riscv = "linux-riscv64-musl";
        let tmp = tempfile::tempdir().unwrap();
        let registrar = Arc::new(InMemoryRegistrar::new("wt-boot", 1, None));
        let sink = capture_source_on(tmp.path(), &registrar, riscv);
        let src_tree = tree(&tmp.path().join("src/node_modules"));
        let dyn_sink: Arc<dyn BlobSink> = sink.clone();

        // This platform: the riscv tree is not restored, and it is kept.
        let here = tmp.path().join("here");
        let mut boot = boot_from(
            registrar.clone(),
            Some(dyn_sink.clone()),
            &source(),
            &here,
            tmp.path(),
        )
        .unwrap();
        assert!(!here.join("node_modules").exists(), "not restored here");
        let previous = &boot.engine.previous().unwrap().manifest.sections;
        assert_eq!(previous.bulk, BulkState::pending());
        assert_eq!(previous.other_bulk[riscv].platform, riscv);

        // A small capture, then this platform's own dependency tree.
        std::fs::write(here.join("lib.rs"), "pub fn f() { here() }\n").unwrap();
        std::fs::create_dir_all(here.join("node_modules/native")).unwrap();
        std::fs::write(here.join("node_modules/native/x86.node"), "x86 build\n").unwrap();
        for (class, seq) in [(Class::Small, 10), (Class::Bulk, 11)] {
            boot.engine
                .snap(SnapRequest {
                    kind: CaptureKind::Auto,
                    class,
                    seq,
                })
                .unwrap();
        }
        let dyn_registrar: Arc<dyn Registrar> = registrar.clone();
        assert_eq!(
            boot.engine
                .shipper(dyn_sink.clone(), dyn_registrar)
                .ship_pending()
                .unwrap(),
            2
        );
        let head = registrar.head().unwrap();
        let sections = &head.manifest.sections;
        assert_eq!(
            sections.bulk.section().unwrap().platform,
            default_platform()
        );
        assert_eq!(
            sections.other_bulk.keys().collect::<Vec<_>>(),
            [riscv],
            "the riscv tree rides on the chain"
        );

        // A riscv executor on the new head: answered its own tree, restored byte for byte, with
        // the edit made here.
        let plan = registrar
            .plan_get(&PlanGetRequest {
                worktree_id: None,
                epoch: 0,
                platform: Some(riscv.to_owned()),
                manifest_format: Some(sealant_capture::manifest::MAX_SECTION_FORMAT),
                manifest_features: PlanGetRequest::booting(None).manifest_features,
                launch: None,
                upload_answers: None,
            })
            .unwrap();
        let answered = plan.head.unwrap().manifest.sections.bulk;
        assert_eq!(answered.section().unwrap().platform, riscv);
        let there = tmp.path().join("there");
        let mut restored = Materializer::new(sink.as_ref(), MaterializeTargets::new(&there, None))
            .fetch_manifest(&head.manifest_key, &head.capture_id)
            .unwrap();
        continue_bulk(&mut restored.manifest.sections, &answered, riscv);
        Materializer::new(sink.as_ref(), MaterializeTargets::new(&there, None))
            .materialize(&restored.manifest, MaterializeClass::All)
            .unwrap();
        assert_eq!(tree(&there.join("node_modules")), src_tree);
        assert_eq!(
            std::fs::read_to_string(there.join("lib.rs")).unwrap(),
            "pub fn f() { here() }\n"
        );
        // …and the x86 tree is now the one carried for this platform.
        assert_eq!(
            restored.manifest.sections.other_bulk[&default_platform()].platform,
            default_platform()
        );
    }

    /// A gzipped tar at `key` in `sink`, and the `PlanSource` that names it at `path`.
    fn publish_source(
        sink: &LocalDir,
        base: &Path,
        name: &str,
        path: &str,
        body: &str,
        read_only: bool,
    ) -> PlanSource {
        let tree = base.join(format!("publish-{name}"));
        std::fs::create_dir_all(&tree).unwrap();
        std::fs::write(tree.join("NOTES.md"), body).unwrap();
        let archive = base.join(format!("{name}.tar.gz"));
        let out = Proc::new("tar")
            .arg("-czf")
            .arg(&archive)
            .arg("-C")
            .arg(&tree)
            .arg(".")
            .output()
            .expect("tar -czf");
        assert!(out.status.success(), "tar -czf");
        let bytes = std::fs::read(&archive).unwrap();
        let sha256 = format!("{:x}", Sha256::digest(&bytes));
        let key = format!("projects/p/sources/{sha256}");
        sink.put_if_absent(&key, BlobSource::Bytes(&bytes)).unwrap();
        PlanSource {
            name: name.to_owned(),
            path: path.to_owned(),
            key,
            sha256,
            bytes: bytes.len() as u64,
            read_only,
        }
    }

    /// Content the plan names beside the worktree lands outside it, is left alone when the
    /// stamp says the copy is current, and a `read_only` source is not writable. Mend's folders
    /// and reference repositories reach a capture-source workspace this way, which mounts
    /// nothing from the host (Mend PLATFORM-FEEDBACK, 2026-09-17).
    #[test]
    fn plan_sources_land_beside_the_worktree_and_are_stamped_by_content() {
        let tmp = tempfile::tempdir().unwrap();
        let registrar = Arc::new(InMemoryRegistrar::new("wt-boot", 1, None));
        let sink = capture_source(tmp.path(), &registrar);
        let root = tmp.path().join("ws");
        let repo = root.join("repo");

        let docs = publish_source(
            &sink,
            tmp.path(),
            "docs",
            &root.join("home/docs").display().to_string(),
            "first\n",
            true,
        );
        let refs = publish_source(
            &sink,
            tmp.path(),
            "api",
            &root.join("ref/api").display().to_string(),
            "reference\n",
            false,
        );
        registrar.set_sources(vec![docs.clone(), refs.clone()]);

        let dyn_sink: Arc<dyn BlobSink> = sink.clone();
        boot_from(
            registrar.clone(),
            Some(dyn_sink.clone()),
            &source(),
            &repo,
            &root,
        )
        .unwrap();
        assert!(repo.join("lib.rs").exists(), "the worktree materialized");
        let laid_down = root.join("home/docs/NOTES.md");
        assert_eq!(std::fs::read_to_string(&laid_down).unwrap(), "first\n");
        assert_eq!(
            std::fs::read_to_string(root.join("ref/api/NOTES.md")).unwrap(),
            "reference\n"
        );
        // Outside the worktree, so no capture of this session ever lists it.
        assert!(!laid_down.starts_with(&repo));
        // read_only takes the writable bit off; the writable source keeps it.
        assert_eq!(
            std::fs::metadata(&laid_down).unwrap().permissions().mode() & 0o222,
            0
        );
        assert_ne!(
            std::fs::metadata(root.join("ref/api/NOTES.md"))
                .unwrap()
                .permissions()
                .mode()
                & 0o222,
            0
        );

        // The stamp is the archive digest: an unchanged source is not extracted again, which a
        // file written beside it survives to prove.
        std::fs::write(root.join("ref/api/LOCAL.md"), "kept\n").unwrap();
        boot_from(
            registrar.clone(),
            Some(dyn_sink.clone()),
            &source(),
            &repo,
            &root,
        )
        .unwrap();
        assert!(root.join("ref/api/LOCAL.md").exists(), "not re-extracted");

        // New bytes, new digest: the copy is replaced, and what was beside it is gone.
        let docs_v2 = publish_source(
            &sink,
            tmp.path(),
            "docs",
            &root.join("home/docs").display().to_string(),
            "second\n",
            true,
        );
        assert_ne!(docs_v2.sha256, docs.sha256);
        registrar.set_sources(vec![docs_v2, refs.clone()]);
        boot_from(
            registrar.clone(),
            Some(dyn_sink.clone()),
            &source(),
            &repo,
            &root,
        )
        .unwrap();
        assert_eq!(std::fs::read_to_string(&laid_down).unwrap(), "second\n");

        // A path inside the worktree would be captured back into the store as the session's
        // own work: that is a control-plane bug, and it fails the boot.
        let inside = PlanSource {
            path: repo.join("vendor").display().to_string(),
            ..refs
        };
        registrar.set_sources(vec![inside]);
        let error = boot_from(registrar, Some(dyn_sink), &source(), &repo, &root).unwrap_err();
        assert!(
            format!("{error}").contains("outside the worktree"),
            "{error}"
        );
    }

    /// A daemon that restarts on its own disk finds a capture staged and not shipped and an
    /// edit made after it. The boot leaves the disk as it is (materializing the head would take
    /// both back), the engine continues from the staged capture, and the queue ships.
    #[test]
    fn a_restart_on_its_own_disk_is_not_materialized_over() {
        let tmp = tempfile::tempdir().unwrap();
        let registrar = Arc::new(InMemoryRegistrar::new("wt-boot", 1, None));
        let sink = capture_source(tmp.path(), &registrar);
        let dyn_sink: Arc<dyn BlobSink> = sink.clone();
        let ws = tmp.path().join("ws");
        let boot = boot_from(
            registrar.clone(),
            Some(dyn_sink.clone()),
            &source(),
            &ws,
            tmp.path(),
        )
        .unwrap();
        assert!(!boot.resumed, "a fresh disk is materialized");
        assert_eq!(
            boot.engine.config().dir_format,
            DirFormat::Packs,
            "the registrar reads dir packs"
        );
        let mut engine = boot.engine;
        std::fs::write(ws.join("lib.rs"), "pub fn f() { staged() }\n").unwrap();
        let staged = engine
            .snap(SnapRequest {
                kind: CaptureKind::Turn,
                class: Class::Small,
                seq: 3,
            })
            .unwrap();
        drop(engine);
        std::fs::write(
            ws.join("node_modules/pkg/index.js"),
            "after the last snap\n",
        )
        .unwrap();

        let boot = boot_from(
            registrar.clone(),
            Some(dyn_sink),
            &source(),
            &ws,
            tmp.path(),
        )
        .unwrap();
        assert!(boot.resumed);
        assert_eq!(
            std::fs::read_to_string(ws.join("lib.rs")).unwrap(),
            "pub fn f() { staged() }\n"
        );
        assert_eq!(
            std::fs::read_to_string(ws.join("node_modules/pkg/index.js")).unwrap(),
            "after the last snap\n"
        );
        assert_eq!(
            boot.engine.previous().unwrap().capture_id,
            staged.manifest.capture_id
        );
        let dyn_registrar: Arc<dyn Registrar> = registrar.clone();
        let sink: Arc<dyn BlobSink> = sink;
        assert_eq!(
            boot.engine
                .shipper(sink, dyn_registrar)
                .ship_pending()
                .unwrap(),
            1
        );
        assert_eq!(
            registrar.head().unwrap().capture_id,
            staged.manifest.capture_id
        );
    }

    /// A registrar that does not announce `manifest_format` 2 gets one object per directory.
    #[test]
    fn a_registrar_without_dir_packs_gets_dir_objects() {
        let tmp = tempfile::tempdir().unwrap();
        let registrar =
            Arc::new(InMemoryRegistrar::new("wt-boot", 1, None).with_manifest_format(1));
        let sink: Arc<dyn BlobSink> = capture_source(tmp.path(), &registrar);
        let boot = boot_from(
            registrar,
            Some(sink),
            &source(),
            &tmp.path().join("ws"),
            tmp.path(),
        )
        .unwrap();
        assert_eq!(boot.engine.config().dir_format, DirFormat::Objects);
    }

    fn origin_of(dir: &Path) -> String {
        let out = Proc::new("git")
            .current_dir(dir)
            .args(["remote", "get-url", "origin"])
            .output()
            .unwrap();
        String::from_utf8(out.stdout).unwrap().trim().to_owned()
    }

    /// A recovery boot resumes the disk as it is, the user's remotes included (review
    /// 2026-09-28 #13): a session pointed `origin` at its fork and died before the next
    /// capture; the recovery boot must not set it back to the plan's URL before the final
    /// snapshot saves it (it did: `git remote set-url` on every boot).
    #[test]
    fn a_recovery_boot_keeps_the_users_changed_origin() {
        use sealant_capture::registrar::PlanRemote;
        let tmp = tempfile::tempdir().unwrap();
        let registrar = Arc::new(InMemoryRegistrar::new("wt-boot", 1, None));
        let sink = capture_base(tmp.path(), &registrar);
        registrar.set_remotes(vec![PlanRemote {
            name: "origin".to_owned(),
            url: "https://example.invalid/original.git".to_owned(),
        }]);
        let disk = tmp.path().join("disk");
        drop(
            boot_from(
                registrar.clone(),
                Some(sink.clone()),
                &source(),
                &disk,
                tmp.path(),
            )
            .unwrap(),
        );
        assert_eq!(origin_of(&disk), "https://example.invalid/original.git");
        git(
            &disk,
            &[
                "remote",
                "set-url",
                "origin",
                "https://example.invalid/user-fork.git",
            ],
        );
        let recovery = CaptureSourceConfig {
            recovery: true,
            ..source()
        };
        let boot = boot_from(registrar, Some(sink), &recovery, &disk, tmp.path()).unwrap();
        assert!(boot.resumed);
        assert_eq!(origin_of(&disk), "https://example.invalid/user-fork.git");
    }

    /// The user's remotes travel in the capture (`.git/config` is workspace-class bookkeeping),
    /// and neither a restart on the same disk nor a fresh executor materializing that capture
    /// sets them back to the plan's (review 2026-09-28 #13), nor adds back one the user removed
    /// (fourth pass, #8: a fresh executor re-added `upstream`, and this test asserted it did).
    /// The plan's remotes seed only a base: a capture that carries no `.git/config`.
    #[test]
    fn a_captured_remote_change_survives_a_restart_and_a_fresh_materialize() {
        use sealant_capture::registrar::PlanRemote;
        let tmp = tempfile::tempdir().unwrap();
        let registrar = Arc::new(InMemoryRegistrar::new("wt-boot", 1, None));
        let sink = capture_base(tmp.path(), &registrar);
        let dyn_sink: Arc<dyn BlobSink> = sink.clone();
        registrar.set_remotes(vec![
            PlanRemote {
                name: "origin".to_owned(),
                url: "https://example.invalid/original.git".to_owned(),
            },
            PlanRemote {
                name: "upstream".to_owned(),
                url: "https://example.invalid/upstream.git".to_owned(),
            },
        ]);
        let ws = tmp.path().join("ws");
        let boot = boot_from(
            registrar.clone(),
            Some(dyn_sink.clone()),
            &source(),
            &ws,
            tmp.path(),
        )
        .unwrap();
        git(
            &ws,
            &[
                "remote",
                "set-url",
                "origin",
                "https://example.invalid/user-fork.git",
            ],
        );
        git(&ws, &["remote", "remove", "upstream"]);
        let mut engine = boot.engine;
        engine
            .snap(SnapRequest {
                kind: CaptureKind::Turn,
                class: Class::Small,
                seq: 3,
            })
            .unwrap();
        // A restart on its own disk (staged, not shipped): resumed as it is.
        drop(engine);
        let boot = boot_from(
            registrar.clone(),
            Some(dyn_sink.clone()),
            &source(),
            &ws,
            tmp.path(),
        )
        .unwrap();
        assert!(boot.resumed);
        assert_eq!(origin_of(&ws), "https://example.invalid/user-fork.git");
        // A resumed disk is left as it is: the remote the user removed stays removed.
        assert!(
            !Proc::new("git")
                .current_dir(&ws)
                .args(["remote", "get-url", "upstream"])
                .output()
                .unwrap()
                .status
                .success()
        );
        let dyn_registrar: Arc<dyn Registrar> = registrar.clone();
        boot.engine
            .shipper(dyn_sink.clone(), dyn_registrar)
            .ship_pending()
            .unwrap();
        drop(boot);
        // A fresh executor materializes the capture that holds the user's `.git/config`: that
        // configuration is the repository's, byte for byte, the remote the user removed absent.
        let captured_config = std::fs::read(ws.join(".git/config")).unwrap();
        let fresh = tmp.path().join("fresh");
        let boot = boot_from(registrar, Some(dyn_sink), &source(), &fresh, tmp.path()).unwrap();
        assert!(!boot.resumed);
        assert_eq!(origin_of(&fresh), "https://example.invalid/user-fork.git");
        assert!(
            !Proc::new("git")
                .current_dir(&fresh)
                .args(["remote", "get-url", "upstream"])
                .output()
                .unwrap()
                .status
                .success(),
            "a remote the user removed is not added back"
        );
        assert_eq!(
            std::fs::read(fresh.join(".git/config")).unwrap(),
            captured_config
        );
    }

    /// A session capture's `.git/config` is authoritative even when it names no remote at all:
    /// the plan's remotes seed a base (a capture without one, or an empty chain), never a
    /// repository a session configured (review 2026-09-28, fourth pass, #8).
    #[test]
    fn plan_remotes_seed_a_base_and_never_a_captured_configuration() {
        use sealant_capture::registrar::PlanRemote;
        let origin = PlanRemote {
            name: "origin".to_owned(),
            url: "https://example.invalid/original.git".to_owned(),
        };
        let has_origin = |dir: &Path| {
            Proc::new("git")
                .current_dir(dir)
                .args(["remote", "get-url", "origin"])
                .output()
                .unwrap()
                .status
                .success()
        };
        for (name, base) in [("session", false), ("base", true)] {
            let tmp = tempfile::tempdir().unwrap();
            let registrar = Arc::new(InMemoryRegistrar::new("wt-boot", 1, None));
            let sink: Arc<dyn BlobSink> = if base {
                capture_base(tmp.path(), &registrar)
            } else {
                capture_source(tmp.path(), &registrar)
            };
            registrar.set_remotes(vec![origin.clone()]);
            let ws = tmp.path().join("ws");
            let boot = boot_from(registrar, Some(sink), &source(), &ws, tmp.path()).unwrap();
            assert!(!boot.resumed);
            assert_eq!(has_origin(&ws), base, "{name}");
        }
        // An empty chain is a base too.
        let tmp = tempfile::tempdir().unwrap();
        let registrar = Arc::new(InMemoryRegistrar::new("wt-boot", 1, None));
        registrar.set_remotes(vec![origin]);
        let sink: Arc<dyn BlobSink> = Arc::new(LocalDir::new(&tmp.path().join("store")).unwrap());
        let ws = tmp.path().join("ws");
        drop(boot_from(registrar, Some(sink), &source(), &ws, tmp.path()).unwrap());
        assert!(has_origin(&ws), "empty chain");
    }

    /// The seal names the executor `plan.get` answers — the launch the session token was
    /// issued for — and nothing else (cross-repo decision 5): a plan that names none seals
    /// nothing, whatever `SEALANT_WORKSPACE_ID` says. Before, the workspace id stood in, and a
    /// seal could name a runtime resource instead of the launch being stopped.
    #[test]
    fn the_seal_names_only_the_executor_the_plan_answers() {
        let tmp = tempfile::tempdir().unwrap();
        let registrar = Arc::new(InMemoryRegistrar::new("wt-boot", 1, None));
        let sink: Arc<dyn BlobSink> = capture_source(tmp.path(), &registrar);
        // `SEALANT_WORKSPACE_ID` is no longer read for it at all (`CaptureSourceConfig` has no
        // such field); the plan without an executor seals nothing.
        let with_workspace_id = source();
        let boot = boot_from(
            registrar.clone(),
            Some(sink.clone()),
            &with_workspace_id,
            &tmp.path().join("a"),
            tmp.path(),
        )
        .unwrap();
        assert_eq!(boot.engine.config().executor, None);
        drop(boot);
        let named = Arc::new(InMemoryRegistrar::new("wt-boot", 1, None).with_executor("launch-7"));
        let sink: Arc<dyn BlobSink> = capture_source(&tmp.path().join("b"), &named);
        let boot = boot_from(
            named,
            Some(sink),
            &with_workspace_id,
            &tmp.path().join("b/ws"),
            tmp.path(),
        )
        .unwrap();
        assert_eq!(boot.engine.config().executor.as_deref(), Some("launch-7"));
    }

    /// The git section's trees go in their own fields (`git_trees`) for a registrar whose plan
    /// lists that feature. A registrar that does not read every feature this daemon writes
    /// cannot hold what a capture holds — a trees-less one normalizes attribute-converted
    /// bytes and takes a user ref named like its pseudo-ref, in every periodic capture a hard
    /// crash would be picked up from — so no user code is admitted over it (decision 16;
    /// review 2026-09-28, fifth pass, #5): the boot is refused right after `plan.get`, before
    /// the head is materialized, naming what the store leaves out. Before, it booted, ran
    /// user code and captured it lossily until a final flush said `store-fidelity`.
    #[test]
    fn a_store_that_cannot_hold_a_capture_admits_no_user_code() {
        let tmp = tempfile::tempdir().unwrap();
        let reads = Arc::new(InMemoryRegistrar::new("wt-boot", 1, None));
        let sink: Arc<dyn BlobSink> = capture_source(tmp.path(), &reads);
        let boot = boot_from(
            reads,
            Some(sink),
            &source(),
            &tmp.path().join("a"),
            tmp.path(),
        )
        .unwrap();
        assert!(boot.engine.config().git_trees);
        assert!(boot.engine.fidelity_gap().is_none());
        drop(boot);
        for (name, features, unread) in [
            (
                "b",
                &[
                    "worktree_meta",
                    "symrefs",
                    "other_bulk",
                    "raw_names",
                    "final_seal",
                ][..],
                "git_trees",
            ),
            (
                "c",
                &[
                    "worktree_meta",
                    "symrefs",
                    "other_bulk",
                    "final_seal",
                    "git_trees",
                ][..],
                "raw_names",
            ),
        ] {
            let older = Arc::new(
                InMemoryRegistrar::new("wt-boot", 1, None).with_manifest_features(features),
            );
            let sink: Arc<dyn BlobSink> = capture_source(&tmp.path().join(name), &older);
            let disk = tmp.path().join(name).join("ws");
            let Err(refused) = boot_from(older, Some(sink), &source(), &disk, tmp.path()) else {
                panic!("a boot over a store that cannot hold a capture is refused");
            };
            let BootError::StoreUnfit(gap) = &refused else {
                panic!("refused for another reason: {refused}");
            };
            assert!(gap.contains(unread), "{gap}");
            assert!(refused.to_string().contains("nothing ran"), "{refused}");
            // Refused before the materialize: the head's files are not on the disk.
            assert!(!disk.join("lib.rs").exists());
            assert!(!disk.join("node_modules").exists());
        }
    }

    /// A store that reads every feature a capture always holds, but not the one the repository
    /// needs — `ref_format` for a reftable repository, `object_format` for a SHA-256 one —
    /// admits no user code over it either (review 2026-09-28, tenth pass). Before, both were
    /// left out of the admission gate: the boot materialized the head and admitted writers,
    /// and only their final flush said incomplete. Refused whether the chain head names the
    /// format or the repository is already on the disk; a store that reads the feature boots.
    #[test]
    fn a_store_that_cannot_hold_the_repository_admits_no_user_code() {
        for (name, init, feature) in [
            ("reftable", "--ref-format=reftable", "ref_format"),
            ("sha256", "--object-format=sha256", "object_format"),
        ] {
            let tmp = tempfile::tempdir().unwrap();
            let without: Vec<&str> = sealant_capture::registrar::MANIFEST_FEATURES
                .iter()
                .copied()
                .filter(|f| *f != feature)
                .collect();
            // The chain head names the format.
            let older = Arc::new(
                InMemoryRegistrar::new("wt-boot", 1, None).with_manifest_features(&without),
            );
            let sink: Arc<dyn BlobSink> = capture_source_with(
                &tmp.path().join("head"),
                &older,
                &default_platform(),
                true,
                &[init],
            );
            let disk = tmp.path().join("head").join("ws");
            let Err(refused) = boot_from(older, Some(sink), &source(), &disk, tmp.path()) else {
                panic!("{name}: a boot over a store that cannot hold the repository is refused");
            };
            let BootError::StoreUnfit(gap) = &refused else {
                panic!("{name}: refused for another reason: {refused}");
            };
            assert!(gap.contains(feature), "{name}: {gap}");
            assert!(
                !disk.join("lib.rs").exists(),
                "{name}: nothing materialized"
            );
            // The repository is already on the disk (an empty chain).
            let older = Arc::new(
                InMemoryRegistrar::new("wt-boot", 1, None).with_manifest_features(&without),
            );
            let sink: Arc<dyn BlobSink> =
                Arc::new(LocalDir::new(&tmp.path().join("store")).unwrap());
            let disk = tmp.path().join("disk");
            std::fs::create_dir_all(&disk).unwrap();
            git(&disk, &["init", "-q", "-b", "main", init]);
            let Err(BootError::StoreUnfit(gap)) =
                boot_from(older, Some(sink), &source(), &disk, tmp.path())
            else {
                panic!("{name}: a boot over the repository on the disk is refused as unfit");
            };
            assert!(gap.contains(feature), "{name}: {gap}");
            // A store that reads the feature boots.
            let reads = Arc::new(InMemoryRegistrar::new("wt-boot", 1, None));
            let sink: Arc<dyn BlobSink> = capture_source_with(
                &tmp.path().join("fit"),
                &reads,
                &default_platform(),
                true,
                &[init],
            );
            let disk = tmp.path().join("fit").join("ws");
            let boot = boot_from(reads, Some(sink), &source(), &disk, tmp.path()).unwrap();
            assert!(disk.join("lib.rs").exists(), "{name}");
            drop(boot);
        }
    }

    /// A recovery boot admits no writer, so a store that cannot hold what a capture holds does
    /// not refuse it: it resumes the disk and ships what the store can take, and its final
    /// flush never says complete (the executor is kept).
    #[test]
    fn a_recovery_boot_over_a_store_that_cannot_hold_a_capture_resumes() {
        let tmp = tempfile::tempdir().unwrap();
        let older = Arc::new(
            InMemoryRegistrar::new("wt-boot", 1, None).with_manifest_features(&[
                "worktree_meta",
                "symrefs",
                "other_bulk",
                "raw_names",
                "final_seal",
            ]),
        );
        let disk = tmp.path().join("ws");
        std::fs::create_dir_all(&disk).unwrap();
        git(&disk, &["init", "-q", "-b", "main"]);
        let sink: Arc<dyn BlobSink> = Arc::new(LocalDir::new(&tmp.path().join("store")).unwrap());
        let recovery = CaptureSourceConfig {
            recovery: true,
            ..source()
        };
        let boot = boot_from(older, Some(sink), &recovery, &disk, tmp.path()).unwrap();
        assert!(!boot.engine.config().git_trees);
        assert!(
            boot.engine
                .fidelity_gap()
                .is_some_and(|gap| gap.contains("git_trees"))
        );
    }

    /// While another launch holds the worktree, `plan.get` answers 409 `worktree-leased` and
    /// gives no epoch (Mend round 4). The boot adopts none: it waits, touching nothing, asks
    /// again, and boots on the epoch it is finally given. Before, the first refusal failed the
    /// boot as a chain conflict.
    #[test]
    fn a_boot_refused_as_leased_waits_and_adopts_no_epoch() {
        let tmp = tempfile::tempdir().unwrap();
        let registrar = Arc::new(InMemoryRegistrar::new("wt-boot", 1, None));
        let sink: Arc<dyn BlobSink> = capture_source(tmp.path(), &registrar);
        registrar.set_live_epoch(4);
        registrar.refuse_plans_leased(2);
        let ws = tmp.path().join("ws");
        let started = std::time::Instant::now();
        let boot = boot_from(registrar.clone(), Some(sink), &source(), &ws, tmp.path()).unwrap();
        assert!(
            started.elapsed() >= Duration::from_secs(3),
            "it waited 1 s, then 2 s"
        );
        let asked = registrar.plan_requests();
        assert_eq!(asked.len(), 3);
        assert!(asked.iter().all(|r| r.epoch == 0), "no epoch was adopted");
        assert_eq!(boot.epoch, 4, "the epoch it was given");
    }

    /// A disk the daemon before never materialized — absent, empty, or holding only the daemon's
    /// empty lock file — is verified as such (a recovery boot on it exits 76, nothing to save);
    /// anything else is not: a file, a repository, capture staging, a materialize record, a
    /// second file beside the lock, a lock with bytes in it, a worktree that is a symlink.
    #[test]
    fn only_a_disk_with_nothing_on_it_was_never_materialized() {
        let tmp = tempfile::tempdir().unwrap();
        let wt = tmp.path().join("repo");
        assert_eq!(never_materialized(&wt), Ok(()), "absent");
        std::fs::create_dir_all(&wt).unwrap();
        assert_eq!(never_materialized(&wt), Ok(()), "empty");
        let lock = crate::boot::lock::DiskLock::acquire(&wt).unwrap();
        assert_eq!(never_materialized(&wt), Ok(()), "the lock alone");
        drop(lock);
        type Setup = fn(&Path);
        let refused: [(&str, Setup); 8] = [
            ("a file", |wt| {
                std::fs::write(wt.join("draft.md"), "work").unwrap()
            }),
            ("a repository", |wt| {
                std::fs::create_dir_all(wt.join(".git")).unwrap()
            }),
            ("an empty directory", |wt| {
                std::fs::create_dir_all(wt.join("src")).unwrap()
            }),
            ("capture staging", |wt| {
                std::fs::create_dir_all(wt.join(".sealantd/capture")).unwrap();
            }),
            ("a materialize record", |wt| {
                let index = wt.join(".sealantd/capture/index");
                std::fs::create_dir_all(&index).unwrap();
                std::fs::write(index.join("materialized.json"), "{}").unwrap();
            }),
            ("a file beside the lock", |wt| {
                std::fs::write(wt.join(".sealantd/other"), "").unwrap();
            }),
            ("a lock with bytes", |wt| {
                std::fs::write(wt.join(".sealantd/boot.lock"), "x").unwrap();
            }),
            ("a daemon directory that is a file", |wt| {
                std::fs::remove_dir_all(wt.join(".sealantd")).unwrap();
                std::fs::write(wt.join(".sealantd"), "").unwrap();
            }),
        ];
        for (what, setup) in refused {
            let tmp = tempfile::tempdir().unwrap();
            let wt = tmp.path().join("repo");
            drop(crate::boot::lock::DiskLock::acquire(&wt).unwrap());
            setup(&wt);
            assert!(never_materialized(&wt).is_err(), "{what}");
        }
        let target = tmp.path().join("elsewhere");
        std::fs::create_dir_all(&target).unwrap();
        let link = tmp.path().join("link");
        std::os::unix::fs::symlink(&target, &link).unwrap();
        assert!(never_materialized(&link).is_err(), "a symlink");
    }

    /// A registrar that ignores `launch` (an older Mend) but answers the executor its token was
    /// issued for.
    struct IgnoresLaunch(Arc<InMemoryRegistrar>);

    impl Registrar for IgnoresLaunch {
        fn plan_get(
            &self,
            req: &PlanGetRequest,
        ) -> Result<sealant_capture::registrar::PlanGetResponse, sealant_capture::RegistrarError>
        {
            self.0.plan_get(&req.clone().with_launch(None))
        }
        fn upload_urls(
            &self,
            req: &sealant_capture::registrar::UploadUrlsRequest,
        ) -> Result<sealant_capture::registrar::UploadUrlsResponse, sealant_capture::RegistrarError>
        {
            self.0.upload_urls(req)
        }
        fn upload_complete(
            &self,
            req: &sealant_capture::registrar::UploadCompleteRequest,
        ) -> Result<
            sealant_capture::registrar::UploadCompleteResponse,
            sealant_capture::RegistrarError,
        > {
            self.0.upload_complete(req)
        }
        fn capture_register(
            &self,
            req: &sealant_capture::registrar::RegisterRequest,
        ) -> Result<sealant_capture::registrar::RegisterResponse, sealant_capture::RegistrarError>
        {
            self.0.capture_register(req)
        }
        fn lease_heartbeat(
            &self,
            req: &sealant_capture::registrar::HeartbeatRequest,
        ) -> Result<sealant_capture::registrar::HeartbeatResponse, sealant_capture::RegistrarError>
        {
            self.0.lease_heartbeat(req)
        }
        fn change_summary(
            &self,
            req: &sealant_capture::registrar::ChangeSummaryRequest,
        ) -> Result<(), sealant_capture::RegistrarError> {
            self.0.change_summary(req)
        }
    }

    /// The boot's first `plan.get` names the launch this executor is (cross-repo decision 11):
    /// as `SEALANT_CAPTURE_LAUNCH_ID` says, else as its disk last served (a restart). A plan for
    /// another launch refuses the boot — the registrar's gate (409 `launch-mismatch`), or, from
    /// one that does not read `launch`, the answered executor (review 2026-09-28, fourth pass,
    /// #11).
    #[test]
    fn the_first_plan_get_names_the_launch_and_a_plan_for_another_is_refused() {
        let tmp = tempfile::tempdir().unwrap();
        let registrar =
            Arc::new(InMemoryRegistrar::new("wt-boot", 1, None).with_executor("launch-7"));
        let sink: Arc<dyn BlobSink> = capture_source(tmp.path(), &registrar);
        let named = |launch: &str| CaptureSourceConfig {
            launch_id: Some(launch.to_owned()),
            ..source()
        };
        let ws = tmp.path().join("ws");
        let boot = boot_from(
            registrar.clone(),
            Some(sink.clone()),
            &named("launch-7"),
            &ws,
            tmp.path(),
        )
        .unwrap();
        assert_eq!(
            registrar.plan_requests().last().unwrap().launch.as_deref(),
            Some("launch-7")
        );
        let mut engine = boot.engine;
        engine
            .snap(SnapRequest {
                kind: CaptureKind::Turn,
                class: Class::Small,
                seq: 3,
            })
            .unwrap();
        drop(engine);
        // A restart that was not told its launch names the one its disk served.
        let boot = boot_from(
            registrar.clone(),
            Some(sink.clone()),
            &source(),
            &ws,
            tmp.path(),
        )
        .unwrap();
        assert!(boot.resumed);
        assert_eq!(
            registrar.plan_requests().last().unwrap().launch.as_deref(),
            Some("launch-7")
        );
        drop(boot);
        // Another launch's executor with this token: refused by the registrar...
        let other = tmp.path().join("other");
        let refused = boot_from(
            registrar.clone(),
            Some(sink.clone()),
            &named("launch-8"),
            &other,
            tmp.path(),
        )
        .expect_err("another launch");
        assert!(refused.to_string().contains("launch-mismatch"), "{refused}");
        // ...and by sealantd itself when the registrar does not read `launch`.
        let refused = boot_from(
            Arc::new(IgnoresLaunch(registrar)),
            Some(sink),
            &named("launch-8"),
            &other,
            tmp.path(),
        )
        .expect_err("another launch");
        assert!(refused.to_string().contains("launch-7"), "{refused}");
        assert!(!other.join(".git").exists(), "nothing was materialized");
    }

    /// A recovery boot's fallback (no staging continues the head) binds the disk to the exact
    /// capture its completed materialize wrote (review 2026-09-28 #22), not to a worktree tree
    /// that happens to be equal: the disk materialized capture A; the chain moved on to capture
    /// B, whose worktree tree is A's but whose refs are not. Recovering that disk against B
    /// would snap A's refs over B's and register them as B's successor. Refused, untouched;
    /// the same disk against A itself is resumed.
    #[test]
    fn a_recovery_boot_binds_the_disk_to_the_capture_it_materialized() {
        let tmp = tempfile::tempdir().unwrap();
        let registrar = Arc::new(InMemoryRegistrar::new("wt-boot", 1, None));
        let sink = capture_source(tmp.path(), &registrar);
        let dyn_sink: Arc<dyn BlobSink> = sink.clone();
        let a = registrar.head().unwrap();
        let recovery = CaptureSourceConfig {
            recovery: true,
            ..source()
        };
        let disk = tmp.path().join("disk");
        drop(
            boot_from(
                registrar.clone(),
                Some(dyn_sink.clone()),
                &source(),
                &disk,
                tmp.path(),
            )
            .unwrap(),
        );
        std::fs::write(disk.join("unsaved.rs"), "// written, never snapped\n").unwrap();
        let _ = std::fs::remove_file(disk.join(".sealantd/capture/index/last.json"));

        // The chain moves on: a branch only, the worktree tree unchanged.
        let src = tmp.path().join("src");
        git(&src, &["branch", "side"]);
        let mut engine = CaptureEngine::open(
            CaptureConfig::new("wt-boot", 1, &src),
            Some(a.manifest.clone().encode()),
        )
        .unwrap();
        engine
            .snap(SnapRequest {
                kind: CaptureKind::Checkpoint,
                class: Class::Small,
                seq: 5,
            })
            .unwrap();
        let dyn_registrar: Arc<dyn Registrar> = registrar.clone();
        engine
            .shipper(dyn_sink.clone(), dyn_registrar)
            .ship_pending()
            .unwrap();
        let b = registrar.head().unwrap();
        assert_ne!(b.capture_id, a.capture_id);
        let before = tree(&disk);
        match boot_from(
            registrar.clone(),
            Some(dyn_sink.clone()),
            &recovery,
            &disk,
            tmp.path(),
        ) {
            Ok(_) => panic!("recovered a disk materialized from another capture than the head"),
            Err(refused) => assert!(refused.to_string().contains("recovery"), "{refused}"),
        }
        assert_eq!(tree(&disk), before, "refused, touched by nothing");
    }
}
