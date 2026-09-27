//! What a fresh executor's materialize removes (`removed=15` on every boot of the Docker end to
//! end, 17 on the first): the files `git init` writes from its template that no captured disk
//! holds — `.git/hooks/*.sample`, `.git/description` — and nothing else. Nothing in the
//! worktree or the harness home: the disk is empty before the head is laid down.

use std::collections::BTreeSet;
use std::fs;
use std::path::Path;
use std::process::Command;
use std::sync::Arc;

use sealant_capture::registrar::Registrar;
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
        "git {args:?} failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    String::from_utf8_lossy(&out.stdout).trim().to_owned()
}

/// Every file under `dir`, relative, `.sealantd` left out.
fn files(dir: &Path) -> BTreeSet<String> {
    walkdir::WalkDir::new(dir)
        .into_iter()
        .filter_entry(|e| e.file_name() != ".sealantd")
        .map(Result::unwrap)
        .filter(|e| !e.file_type().is_dir())
        .map(|e| e.path().strip_prefix(dir).unwrap().display().to_string())
        .collect()
}

/// The `.git` files the workspace class lists (objects, refs, `HEAD`, `packed-refs` travel in
/// the git section; `index` is the git class's).
fn listed_git_files(root: &Path) -> BTreeSet<String> {
    files(&root.join(".git"))
        .into_iter()
        .filter(|f| {
            !(f.starts_with("objects/")
                || f.starts_with("refs/")
                || f == "HEAD"
                || f == "packed-refs"
                || f == "index")
        })
        .collect()
}

#[test]
fn a_fresh_executor_removes_only_git_init_template_files() {
    let tmp = tempfile::tempdir().unwrap();
    let base = tmp.path();

    // What `git init` writes here (git's version decides: 14 sample hooks with 2.43).
    let scratch = base.join("scratch");
    fs::create_dir_all(&scratch).unwrap();
    git(&scratch, &["init", "-q"]);
    let template = listed_git_files(&scratch);

    // The executor that captures: its repository was laid down by a materialize, which swept
    // the template (a disk no capture held it on), then the session worked in it.
    let root = base.join("ws");
    let home = base.join("home");
    fs::create_dir_all(root.join("src")).unwrap();
    fs::create_dir_all(home.join(".claude")).unwrap();
    git(&root, &["init", "-q", "-b", "main", "--template="]);
    git(&root, &["config", "user.email", "t@t"]);
    git(&root, &["config", "user.name", "t"]);
    git(
        &root,
        &["remote", "add", "origin", "https://example.invalid/r.git"],
    );
    fs::write(root.join(".gitignore"), "*.log\n").unwrap();
    fs::write(root.join("src/lib.rs"), "pub fn f() {}\n").unwrap();
    git(&root, &["add", "-A"]);
    git(&root, &["commit", "-q", "-m", "one"]);
    fs::create_dir_all(root.join(".git/hooks")).unwrap();
    fs::write(root.join(".git/hooks/pre-commit"), "#!/bin/sh\nexit 0\n").unwrap();
    fs::write(root.join("untracked.txt"), "work in progress\n").unwrap();
    fs::write(root.join("build.log"), "ignored\n").unwrap();
    fs::write(home.join(".claude/settings.json"), "{}\n").unwrap();
    fs::write(home.join(".bash_history"), "ls\n").unwrap();

    let sink = Arc::new(LocalDir::new(&base.join("store")).unwrap());
    let registrar = Arc::new(InMemoryRegistrar::new("wt-fresh", 1, None));
    let mut config = CaptureConfig::new("wt-fresh", 1, &root);
    config.harness_home = Some(home.clone());
    let mut engine = CaptureEngine::open(config, None).unwrap();
    for (class, seq) in [(Class::Small, 1), (Class::Bulk, 2), (Class::Small, 3)] {
        engine
            .snap(SnapRequest {
                kind: CaptureKind::Turn,
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
    let head = registrar.head().unwrap();

    // A fresh executor: nothing on its disk before the materialize.
    let fresh = base.join("fresh");
    let fresh_home = base.join("fresh-home");
    let report = Materializer::new(
        sink.as_ref(),
        MaterializeTargets::new(&fresh, Some(fresh_home.clone())),
    )
    .materialize(&head.manifest, MaterializeClass::All)
    .unwrap();

    let captured = listed_git_files(&root);
    let expected: BTreeSet<&String> = template.difference(&captured).collect();
    assert!(
        expected
            .iter()
            .all(|f| f.starts_with("hooks/") && f.ends_with(".sample") || *f == "description"),
        "git's template here: {expected:?}"
    );
    assert_eq!(
        report.removed,
        expected.len() as u64,
        "only the template files no capture holds: {expected:?}"
    );
    // After the sweep the fresh disk's `.git` bookkeeping is the captured one exactly; the
    // worktree and the harness home hold everything the session left.
    assert_eq!(listed_git_files(&fresh), captured);
    let worktree = |dir: &Path| -> BTreeSet<String> {
        files(dir)
            .into_iter()
            .filter(|f| !f.starts_with(".git/"))
            .collect()
    };
    assert_eq!(worktree(&fresh), worktree(&root));
    assert_eq!(files(&fresh_home), files(&home));
}
