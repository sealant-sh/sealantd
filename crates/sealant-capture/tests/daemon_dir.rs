//! Staging (`.sealantd/`) sits inside the worktree and must never enter the git section: the
//! engine adds a local git exclude at boot (never the user's `.gitignore`), materialize adds it
//! before anything runs in the restored tree, and the worktree-tree helper excludes it on its own.

use std::fs;
use std::path::Path;
use std::process::Command;
use std::sync::Arc;

use sealant_capture::manifest::{INDEX_TREE_REF, WORKTREE_TREE_REF};
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

fn exclude_lines(root: &Path) -> Vec<String> {
    fs::read_to_string(root.join(".git/info/exclude"))
        .unwrap_or_default()
        .lines()
        .filter(|l| *l == "/.sealantd/")
        .map(str::to_owned)
        .collect()
}

fn assert_tree_clean(root: &Path, refs: &std::collections::BTreeMap<String, String>, name: &str) {
    let tree = &refs[name];
    let listing = git(root, &["ls-tree", "-r", "--name-only", tree]);
    assert!(
        !listing.lines().any(|l| l.starts_with(".sealantd")),
        "{name} carries daemon internals:\n{listing}"
    );
    assert!(listing.contains("src/a.txt"), "{name}:\n{listing}");
}

#[test]
fn staging_never_enters_the_git_section() {
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path().join("ws");
    fs::create_dir_all(root.join("src")).unwrap();
    git(&root, &["init", "-q", "-b", "main"]);
    git(&root, &["config", "user.email", "t@t"]);
    git(&root, &["config", "user.name", "t"]);
    fs::write(root.join(".gitignore"), "target/\n").unwrap();
    fs::write(root.join("src/a.txt"), "a\n").unwrap();
    git(&root, &["add", "-A"]);
    git(&root, &["commit", "-q", "-m", "one"]);

    let engine = CaptureEngine::open(CaptureConfig::new("wt", 1, &root), None).unwrap();
    assert_eq!(exclude_lines(&root).len(), 1, "boot adds the local exclude");
    assert_eq!(
        fs::read_to_string(root.join(".gitignore")).unwrap(),
        "target/\n",
        "the user's .gitignore is untouched"
    );
    drop(engine);
    let mut engine = CaptureEngine::open(CaptureConfig::new("wt", 1, &root), None).unwrap();
    assert_eq!(
        exclude_lines(&root).len(),
        1,
        "a second boot does not repeat the line"
    );
    let staged = engine
        .snap(SnapRequest {
            kind: CaptureKind::Auto,
            class: Class::Small,
            seq: 1,
        })
        .unwrap();
    assert!(staged.stats.files > 0);
    assert!(
        fs::read_dir(root.join(".sealantd/capture/objects"))
            .unwrap()
            .count()
            > 0,
        "staging holds objects inside the worktree"
    );

    // An agent's (or a checkpoint's) `git add -A` on the real index picks up nothing under it.
    git(&root, &["add", "-A"]);
    let status = git(&root, &["status", "--porcelain", "--ignored=no"]);
    assert!(!status.contains(".sealantd"), "{status}");
    let staged = engine
        .snap(SnapRequest {
            kind: CaptureKind::Checkpoint,
            class: Class::Small,
            seq: 2,
        })
        .unwrap();
    let refs = &staged.manifest.manifest.sections.git.refs;
    assert_tree_clean(&root, refs, INDEX_TREE_REF);
    assert_tree_clean(&root, refs, WORKTREE_TREE_REF);

    // Without the local exclude the worktree-tree helper still keeps it out on its own.
    fs::write(root.join(".git/info/exclude"), "").unwrap();
    let staged = engine
        .snap(SnapRequest {
            kind: CaptureKind::Auto,
            class: Class::Small,
            seq: 3,
        })
        .unwrap();
    assert_tree_clean(
        &root,
        &staged.manifest.manifest.sections.git.refs,
        WORKTREE_TREE_REF,
    );

    // A materialized tree carries the exclude before anything runs in it.
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
    assert_eq!(
        exclude_lines(&restore).len(),
        1,
        "materialize adds it even though the captured .git/info/exclude was stripped"
    );
    assert!(restore.join("src/a.txt").exists());
    // Booting on the restored tree keeps the one line.
    let _engine = CaptureEngine::open(CaptureConfig::new("wt", 2, &restore), None).unwrap();
    assert_eq!(exclude_lines(&restore).len(), 1);
}
