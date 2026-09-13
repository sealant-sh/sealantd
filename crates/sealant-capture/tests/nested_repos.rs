//! Nested repositories (a `.git` under the worktree) never enter the worktree tree and always
//! come back from the chunked class, whether or not they have a commit checked out, whether or
//! not git tracks them as a gitlink, and beside an ignored path. On git 2.52 the checkpoint
//! helper's `git add -A --ignore-errors` is fatal on a commit-less nested repository; the
//! helper names them in `:(exclude)` pathspecs ahead of the add instead of relying on the flag.

use std::fs;
use std::path::Path;
use std::process::Command;
use std::sync::Arc;

use sealant_capture::manifest::WORKTREE_TREE_REF;
use sealant_capture::{
    CaptureConfig, CaptureEngine, CaptureKind, Class, InMemoryRegistrar, LocalDir,
    MaterializeClass, MaterializeTargets, Materializer, SnapRequest,
};

fn git(root: &Path, args: &[&str]) -> String {
    let out = Command::new("git")
        .current_dir(root)
        .env("GIT_OPTIONAL_LOCKS", "0")
        .args(args)
        .output()
        .expect("git");
    assert!(
        out.status.success(),
        "git {args:?}: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    String::from_utf8_lossy(&out.stdout).to_string()
}

fn init(root: &Path) {
    fs::create_dir_all(root).unwrap();
    git(root, &["init", "-q", "-b", "main"]);
    git(root, &["config", "user.email", "t@t"]);
    git(root, &["config", "user.name", "t"]);
}

/// Workspace: an ignored directory (holding its own nested repository), a commit-less nested
/// repository, one with a commit, and one with a commit that git already tracks as a gitlink.
fn workspace(root: &Path) {
    init(root);
    fs::write(root.join(".gitignore"), "ign/\n").unwrap();
    fs::write(root.join("a.txt"), "a\n").unwrap();
    git(root, &["add", "-A"]);
    git(root, &["commit", "-q", "-m", "one"]);
    fs::create_dir_all(root.join("ign")).unwrap();
    fs::write(root.join("ign/secret.txt"), "ignored\n").unwrap();
    init(&root.join("ign/z"));
    fs::write(root.join("ign/z/i.txt"), "ignored nested\n").unwrap();
    init(&root.join("vendor/x"));
    fs::write(root.join("vendor/x/v.txt"), "no commit\n").unwrap();
    init(&root.join("vendor/y"));
    fs::write(root.join("vendor/y/w.txt"), "committed\n").unwrap();
    git(&root.join("vendor/y"), &["add", "-A"]);
    git(&root.join("vendor/y"), &["commit", "-q", "-m", "w"]);
    init(&root.join("vendor/t"));
    fs::write(root.join("vendor/t/t.txt"), "tracked gitlink\n").unwrap();
    git(&root.join("vendor/t"), &["add", "-A"]);
    git(&root.join("vendor/t"), &["commit", "-q", "-m", "t"]);
    git(
        root,
        &["-c", "advice.addEmbeddedRepo=false", "add", "vendor/t"],
    );
    fs::write(root.join("notes.md"), "untracked\n").unwrap();
}

#[test]
fn nested_repositories_round_trip_through_the_chunked_class() {
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path().join("ws");
    workspace(&root);

    let mut engine = CaptureEngine::open(CaptureConfig::new("wt", 1, &root), None).unwrap();
    let staged = engine
        .snap(SnapRequest {
            kind: CaptureKind::Checkpoint,
            class: Class::Small,
            seq: 1,
        })
        .unwrap();
    let wt_tree = &staged.manifest.manifest.sections.git.refs[WORKTREE_TREE_REF];
    let entries = git(&root, &["ls-tree", "-r", wt_tree]);
    assert!(entries.contains("notes.md"), "{entries}");
    assert!(!entries.contains("vendor/x"), "{entries}");
    assert!(!entries.contains("vendor/y"), "{entries}");
    assert!(!entries.contains("ign/"), "{entries}");
    assert!(
        entries.contains("160000 commit") && entries.contains("vendor/t"),
        "the tracked gitlink keeps the index entry: {entries}"
    );
    assert!(
        entries.contains(
            &git(&root.join("vendor/t"), &["rev-parse", "HEAD"])
                .trim()
                .to_owned()
        ),
        "{entries}"
    );
    let sink = Arc::new(LocalDir::new(&tmp.path().join("store")).unwrap());
    let registrar = Arc::new(InMemoryRegistrar::new("wt", 1, None));
    engine
        .shipper(sink.clone(), registrar.clone())
        .ship_pending()
        .unwrap();
    let head = registrar.head().unwrap();
    let restore = tmp.path().join("restore");
    let m = Materializer::new(sink.as_ref(), MaterializeTargets::new(&restore, None));
    let manifest = m
        .fetch_manifest(&head.manifest_key, &head.capture_id)
        .unwrap();
    m.materialize(&manifest.manifest, MaterializeClass::All)
        .unwrap();

    for (p, body) in [
        ("vendor/x/v.txt", "no commit\n"),
        ("vendor/y/w.txt", "committed\n"),
        ("vendor/t/t.txt", "tracked gitlink\n"),
        ("ign/secret.txt", "ignored\n"),
        ("ign/z/i.txt", "ignored nested\n"),
        ("notes.md", "untracked\n"),
    ] {
        assert_eq!(fs::read_to_string(restore.join(p)).unwrap(), body, "{p}");
    }
    assert!(restore.join("vendor/x/.git/HEAD").exists());
    assert_eq!(
        git(&restore.join("vendor/y"), &["rev-parse", "HEAD"]),
        git(&root.join("vendor/y"), &["rev-parse", "HEAD"]),
        "the nested repository's own history came back"
    );
    assert_eq!(
        git(&restore, &["status", "--porcelain", "--ignored"]),
        git(&root, &["status", "--porcelain", "--ignored"])
    );
}
