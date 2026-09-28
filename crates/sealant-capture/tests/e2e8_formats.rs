//! A base restores in its repository's formats (Docker end to end, round 8, F4b): a restore of
//! a capture whose workspace class carries no `.git/config` (Mend's capture 0, a base authored
//! from the project's repository) keeps the repository the git class made — its object format
//! and ref backend in `.git/config`, and a reftable repository's tables. Before, the workspace
//! class swept `.git/config` (the plan did not name it) and a SHA-256 restore read as SHA-1:
//! `git for-each-ref` failed on 64-hex `packed-refs` once the boot added a remote to a config
//! without `extensions.objectformat`. And whatever config the workspace class writes, the
//! repository reads in the git section's formats after the restore.

use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::Arc;

use sealant_capture::manifest::{BulkState, WorkspaceSection};
use sealant_capture::sink::BlobSource;
use sealant_capture::tree::DirObject;
use sealant_capture::{
    BlobSink, CadenceRunner, CaptureConfig, CaptureEngine, CaptureKind, InMemoryRegistrar,
    LocalDir, MaterializeClass, MaterializeTargets, Materializer,
};

const EXECUTOR: &str = "exec-e2e8";

fn git(root: &Path, args: &[&str]) -> String {
    let out = Command::new("git")
        .current_dir(root)
        .env("GIT_OPTIONAL_LOCKS", "0")
        .args(args)
        .output()
        .expect("git");
    assert!(
        out.status.success(),
        "git {args:?} in {} failed: {}",
        root.display(),
        String::from_utf8_lossy(&out.stderr)
    );
    String::from_utf8(out.stdout).unwrap().trim().to_owned()
}

/// A repository at `root` in `object_format` and `ref_format`, one commit on `main`.
fn init_repo(root: &Path, object_format: &str, ref_format: &str, contents: &[u8]) {
    fs::create_dir_all(root).unwrap();
    git(
        root,
        &[
            "init",
            "-q",
            "-b",
            "main",
            &format!("--object-format={object_format}"),
            &format!("--ref-format={ref_format}"),
        ],
    );
    git(root, &["config", "user.email", "t@t"]);
    git(root, &["config", "user.name", "t"]);
    fs::write(root.join("a"), contents).unwrap();
    fs::write(root.join(".gitignore"), b"ignored/\n").unwrap();
    git(root, &["add", "-A"]);
    git(root, &["commit", "-qm", "base"]);
    assert_eq!(
        git(root, &["rev-parse", "--show-object-format"]),
        object_format
    );
    assert_eq!(git(root, &["rev-parse", "--show-ref-format"]), ref_format);
}

struct Fixture {
    tmp: tempfile::TempDir,
    root: PathBuf,
    store: Arc<LocalDir>,
    registrar: Arc<InMemoryRegistrar>,
}

impl Fixture {
    fn new(object_format: &str, ref_format: &str) -> Self {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path().join("ws");
        init_repo(&root, object_format, ref_format, b"base\n");
        Self {
            store: Arc::new(LocalDir::new(&tmp.path().join("store")).unwrap()),
            registrar: Arc::new(InMemoryRegistrar::new("wt", 1, None).with_executor(EXECUTOR)),
            root,
            tmp,
        }
    }

    /// Another repository at `<tmp>/<name>`, capturing into `other`'s store.
    fn sharing(other: &Self, name: &str, object_format: &str, ref_format: &str) -> Self {
        let tmp = tempfile::tempdir().unwrap();
        let root = other.tmp.path().join(name);
        init_repo(&root, object_format, ref_format, b"base\n");
        Self {
            store: other.store.clone(),
            registrar: Arc::new(InMemoryRegistrar::new("wt", 1, None).with_executor(EXECUTOR)),
            root,
            tmp,
        }
    }

    fn runner(&self) -> CadenceRunner {
        let mut config = CaptureConfig::new("wt", 1, &self.root);
        config.executor = Some(EXECUTOR.to_owned());
        let engine = CaptureEngine::open(config, None).unwrap();
        let shipper = Arc::new(engine.shipper(self.store.clone(), self.registrar.clone()));
        CadenceRunner::new(engine, shipper)
    }
}

// ---------------------------------------------------------------------------------------------
// F4b: a base capture (no `.git/config` in the workspace class) restores in its own formats.
// ---------------------------------------------------------------------------------------------

/// The chain's head as a base: its git section as captured, its workspace class an empty root
/// (Mend's capture 0 carries no `.git/`, no `tree/`, no harness home), no overlay, no bulk
/// section, no seal.
fn as_base(fx: &Fixture) -> sealant_capture::Manifest {
    let mut manifest = fx.registrar.head().unwrap().manifest;
    let empty = DirObject::new(Vec::new()).encode();
    let key = format!("captures/wt/0/trees/{}", empty.sha256);
    fx.store
        .put_if_absent(&key, BlobSource::Bytes(&empty.bytes))
        .unwrap();
    manifest.sections.workspace = WorkspaceSection::objects(key, Vec::new());
    manifest.sections.bulk = BulkState::pending();
    manifest.sections.other_bulk.clear();
    manifest.final_seal = None;
    manifest
}

fn a_base_restores_in_its_formats(object_format: &str, ref_format: &str) {
    let fx = Fixture::new(object_format, ref_format);
    let head = git(&fx.root, &["rev-parse", "HEAD"]);
    fx.runner()
        .flush(CaptureKind::Checkpoint, None)
        .expect("a checkpoint");
    let base = as_base(&fx);
    assert_eq!(base.sections.git.object_format(), object_format);
    assert_eq!(base.sections.git.ref_format(), ref_format);

    let out = fx.tmp.path().join("restored");
    let report = Materializer::new(fx.store.as_ref(), MaterializeTargets::new(&out, None))
        .materialize(&base, MaterializeClass::All)
        .unwrap();
    assert!(!report.git_config, "a base carries no .git/config");
    let case = format!("{object_format}/{ref_format}");
    assert_eq!(
        git(&out, &["rev-parse", "--show-object-format"]),
        object_format,
        "{case}: the restore is not a repository in the capture's object format"
    );
    assert_eq!(
        git(&out, &["rev-parse", "--show-ref-format"]),
        ref_format,
        "{case}: the restore is not a repository in the capture's ref backend"
    );
    // What the boot does next on a base: add the plan's remotes (the config is written again),
    // then seed the engine from the refs.
    git(
        &out,
        &["remote", "add", "origin", "https://example.invalid/r.git"],
    );
    assert_eq!(
        git(&out, &["rev-parse", "--show-object-format"]),
        object_format,
        "{case}: adding a remote made the repository read as another format"
    );
    let refs = git(&out, &["for-each-ref", "--format=%(refname) %(objectname)"]);
    assert_eq!(refs, format!("refs/heads/main {head}"), "{case}");
    assert_eq!(git(&out, &["rev-parse", "HEAD"]), head, "{case}");
    assert_eq!(git(&out, &["symbolic-ref", "HEAD"]), "refs/heads/main");
    assert_eq!(git(&out, &["status", "--porcelain"]), "", "{case}");
    git(&out, &["fsck", "--no-dangling"]);

    // The same base again over the restore (a standby's re-plan onto a base): nothing changes.
    Materializer::new(fx.store.as_ref(), MaterializeTargets::new(&out, None))
        .materialize(&base, MaterializeClass::All)
        .unwrap();
    assert_eq!(
        git(&out, &["rev-parse", "--show-object-format"]),
        object_format
    );
    assert_eq!(git(&out, &["rev-parse", "HEAD"]), head, "{case}");
    assert_eq!(
        git(&out, &["config", "remote.origin.url"]),
        "https://example.invalid/r.git",
        "{case}: the remote the boot added is kept"
    );
}

#[test]
fn a_sha256_base_without_git_config_restores_as_sha256() {
    a_base_restores_in_its_formats("sha256", "files");
}

#[test]
fn a_reftable_base_without_git_config_keeps_its_refs() {
    a_base_restores_in_its_formats("sha1", "reftable");
}

#[test]
fn a_sha256_reftable_base_without_git_config_restores_as_one() {
    a_base_restores_in_its_formats("sha256", "reftable");
}

#[test]
fn a_sha1_base_without_git_config_restores_as_before() {
    a_base_restores_in_its_formats("sha1", "files");
}

/// A workspace class whose `.git/config` does not name the git section's object format (here:
/// a SHA-1 repository's config beside a SHA-256 git section): the formats the git class made
/// the repository in are written back after the class, and the rest of the captured config
/// stays as captured.
#[test]
fn a_captured_config_without_the_capture_s_format_is_given_it_back() {
    let fx = Fixture::new("sha256", "files");
    let head = git(&fx.root, &["rev-parse", "HEAD"]);
    fx.runner()
        .flush(CaptureKind::Checkpoint, None)
        .expect("a checkpoint");
    let other = Fixture::sharing(&fx, "sha1-ws", "sha1", "files");
    git(&other.root, &["config", "sealant.mark", "captured"]);
    other
        .runner()
        .flush(CaptureKind::Checkpoint, None)
        .expect("a checkpoint");
    let mut manifest = fx.registrar.head().unwrap().manifest;
    manifest.sections.workspace = other.registrar.head().unwrap().manifest.sections.workspace;
    manifest.sections.workspace.worktree_meta = None;
    manifest.final_seal = None;

    let out = fx.tmp.path().join("restored");
    let report = Materializer::new(fx.store.as_ref(), MaterializeTargets::new(&out, None))
        .materialize(&manifest, MaterializeClass::All)
        .unwrap();
    assert!(report.git_config);
    assert_eq!(git(&out, &["config", "sealant.mark"]), "captured");
    assert_eq!(
        git(&out, &["rev-parse", "--show-object-format"]),
        "sha256",
        "the captured config took the repository's object format away"
    );
    assert_eq!(git(&out, &["rev-parse", "HEAD"]), head);
    let refs = git(&out, &["for-each-ref", "--format=%(refname) %(objectname)"]);
    assert_eq!(refs, format!("refs/heads/main {head}"));
    // The objects read as the capture's (the index beside them is the other repository's, as
    // this workspace class carried it).
    assert_eq!(git(&out, &["show", "HEAD:a"]), "base");
}
