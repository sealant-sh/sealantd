//! A restore that cannot write says where.
//!
//! Docker end to end, round 3: sealantd booted as a user that is not root answered `capture
//! materialize failed: Permission denied (os error 13)` — no path, so nobody could tell which
//! directory it needed. The error now names the operation and the path.

use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::Path;
use std::process::Command;
use std::sync::Arc;
use std::time::Duration;

use sealant_capture::{
    BlobSink, CaptureConfig, CaptureEngine, CaptureKind, Class, InMemoryRegistrar, LocalDir,
    MaterializeClass, MaterializeTargets, Materializer, Registrar, SnapRequest,
};

fn git(root: &Path, args: &[&str]) {
    let out = Command::new("git")
        .current_dir(root)
        .env("GIT_OPTIONAL_LOCKS", "0")
        .args(args)
        .output()
        .expect("git");
    assert!(out.status.success(), "git {args:?}");
}

#[test]
fn a_restore_that_cannot_write_names_the_path() {
    let tmp = tempfile::tempdir().unwrap();
    let probe = tmp.path().join("probe");
    fs::create_dir(&probe).unwrap();
    fs::set_permissions(&probe, fs::Permissions::from_mode(0o555)).unwrap();
    if fs::create_dir(probe.join("x")).is_ok() {
        eprintln!("skipped: permission bits do not bind this process (root)");
        return;
    }
    let root = tmp.path().join("ws");
    fs::create_dir_all(root.join("src")).unwrap();
    git(&root, &["init", "-q", "-b", "main"]);
    git(&root, &["config", "user.email", "t@t"]);
    git(&root, &["config", "user.name", "t"]);
    fs::write(root.join("src/lib.rs"), "pub fn f() {}\n").unwrap();
    git(&root, &["add", "-A"]);
    git(&root, &["commit", "-q", "-m", "one"]);
    let mut engine = CaptureEngine::open(CaptureConfig::new("wt", 1, &root), None).unwrap();
    engine
        .snap(SnapRequest {
            kind: CaptureKind::Final,
            class: Class::Small,
            seq: 1,
        })
        .unwrap();
    let store: Arc<dyn BlobSink> = Arc::new(LocalDir::new(&tmp.path().join("store")).unwrap());
    let registrar = Arc::new(InMemoryRegistrar::new("wt", 1, None));
    let dyn_registrar: Arc<dyn Registrar> = registrar.clone();
    engine
        .shipper(store.clone(), dyn_registrar)
        .flush(Duration::from_secs(30))
        .unwrap();

    // The worktree's parent is not writable: the directory it must create is named.
    let target = probe.join("repo");
    let error = Materializer::new(store.as_ref(), MaterializeTargets::new(&target, None))
        .materialize(&registrar.head().unwrap().manifest, MaterializeClass::All)
        .unwrap_err()
        .to_string();
    assert!(
        error.contains(&target.display().to_string()),
        "the error names the path: {error}"
    );
    assert!(error.contains("Permission denied"), "{error}");
    fs::set_permissions(&probe, fs::Permissions::from_mode(0o755)).unwrap();
}
