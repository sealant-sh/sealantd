//! Capture-store workspaces (ADR-0015): at boot, fetch the plan through the session channel,
//! materialize the chain head onto local disk, and hand back an engine seeded to continue the
//! chain under this session's lease epoch.

use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use sealant_capture::engine::Pickup;
use sealant_capture::gitpack::GitRepo;
use sealant_capture::manifest::{BulkState, DirFormat, Sections};
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
    workspace_root: &Path,
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
    // Dir packs only for a registrar that reads them; either format materializes here.
    config.dir_format = DirFormat::for_registrar(plan.manifest_format);
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
    let resumed = matches!(pickup, Pickup::Resume { .. });
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

    // Content beside the worktree (Mend's folders and reference repositories): outside the
    // worktree, so it is laid down after the head and never enters a capture.
    sources::apply(sink.as_ref(), &plan.sources, &layout)?;

    // The repository above was built here, so it has no remotes until the plan names them.
    remotes::apply(working_directory, &plan.remotes)?;

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
}
