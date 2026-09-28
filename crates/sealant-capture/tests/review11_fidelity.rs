//! What a sealed final flush holds is what the disk held, or the flush is not complete (review
//! 2026-09-28, eleventh pass):
//!
//! - a nested repository with no worktree — a bare repository — is found, and one that borrows
//!   the top-level object store (`objects/info/alternates`) keeps the objects its refs reach;
//!   so does a nested repository whose `objects` is a symlink to the top-level store; one whose
//!   object store lies outside the workspace leaves the final flush incomplete, naming it (#1;
//!   decision 29);
//! - only git's own transaction files are transient in a git directory: a hook project's
//!   `Cargo.lock`, a config include called `personal.lock`, in every class, are captured and
//!   restored byte for byte, and a stale transaction lock a killed git left is not, and does
//!   not keep the final flush from completing (#2; decision 33).

use std::fs;
use std::os::unix::fs::symlink;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use std::sync::Arc;

use sealant_capture::{
    CadenceRunner, CaptureConfig, CaptureEngine, CaptureKind, Class, InMemoryRegistrar, LocalDir,
    MaterializeClass, MaterializeTargets, Materializer, SnapRequest,
};

const EXECUTOR: &str = "exec-r11";

fn git_out(root: &Path, args: &[&str], input: Option<&[u8]>) -> Output {
    use std::io::Write;
    use std::process::Stdio;
    let mut child = Command::new("git")
        .current_dir(root)
        .env("GIT_OPTIONAL_LOCKS", "0")
        .args(args)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("git");
    let mut stdin = child.stdin.take().unwrap();
    if let Some(input) = input {
        stdin.write_all(input).unwrap();
    }
    drop(stdin);
    child.wait_with_output().unwrap()
}

fn git(root: &Path, args: &[&str]) -> String {
    git_in(root, args, None)
}

fn git_in(root: &Path, args: &[&str], input: Option<&[u8]>) -> String {
    let out = git_out(root, args, input);
    assert!(
        out.status.success(),
        "git {args:?} failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    String::from_utf8(out.stdout).unwrap().trim().to_owned()
}

/// A commit no ref, reflog or `HEAD` reaches, holding one file with `contents`.
fn unreachable_commit(root: &Path, contents: &[u8]) -> String {
    let blob = git_in(root, &["hash-object", "-w", "--stdin"], Some(contents));
    let tree = git_in(
        root,
        &["mktree"],
        Some(format!("100644 blob {blob}\tunique.txt\n").as_bytes()),
    );
    git(
        root,
        &["commit-tree", &tree, "-m", "unique unreachable commit"],
    )
}

struct Fixture {
    tmp: tempfile::TempDir,
    root: PathBuf,
    store: Arc<LocalDir>,
    registrar: Arc<InMemoryRegistrar>,
}

impl Fixture {
    /// A repository with one commit on `main`: `a` holding `base\n`; `.gitignore` ignoring
    /// `ignored/` and `node_modules/`.
    fn new() -> Self {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path().join("ws");
        fs::create_dir_all(&root).unwrap();
        git(&root, &["init", "-q", "-b", "main"]);
        git(&root, &["config", "user.email", "t@t"]);
        git(&root, &["config", "user.name", "t"]);
        fs::write(root.join("a"), b"base\n").unwrap();
        fs::write(root.join(".gitignore"), b"ignored/\nnode_modules/\n").unwrap();
        git(&root, &["add", "-A"]);
        git(&root, &["commit", "-qm", "base"]);
        Self {
            store: Arc::new(LocalDir::new(&tmp.path().join("store")).unwrap()),
            registrar: Arc::new(InMemoryRegistrar::new("wt", 1, None).with_executor(EXECUTOR)),
            root,
            tmp,
        }
    }

    fn config(&self) -> CaptureConfig {
        let mut config = CaptureConfig::new("wt", 1, &self.root);
        config.executor = Some(EXECUTOR.to_owned());
        config
    }

    fn runner(&self) -> CadenceRunner {
        let engine = CaptureEngine::open(self.config(), None).unwrap();
        let shipper = Arc::new(engine.shipper(self.store.clone(), self.registrar.clone()));
        CadenceRunner::new(engine, shipper)
    }

    /// A final flush that must say `complete` and seal the chain.
    fn final_flush(&self) {
        let result = self.runner().flush_final(None);
        assert!(result.complete(), "{result:?}");
        let head = self.registrar.head().unwrap();
        assert!(head.manifest.final_seal.is_some(), "the chain is sealed");
        assert!(
            !self.registrar.seals().is_empty(),
            "the registrar recorded it"
        );
    }

    /// A final flush that must not say `complete`; its reason and error text.
    fn incomplete_flush(&self) -> (String, String) {
        let result = self.runner().flush_final(None);
        let incomplete = result
            .incomplete
            .clone()
            .unwrap_or_else(|| panic!("the final flush said complete: {result:?}"));
        assert!(self.registrar.seals().is_empty(), "nothing is sealed");
        (incomplete.reason().to_owned(), incomplete.to_string())
    }

    /// An automatic capture of both classes, shipped and registered.
    fn automatic(&self) {
        let mut engine = CaptureEngine::open(self.config(), None).unwrap();
        for (class, seq) in [(Class::Small, 1), (Class::Bulk, 2)] {
            engine
                .snap(SnapRequest {
                    kind: CaptureKind::Auto,
                    class,
                    seq,
                })
                .unwrap();
        }
        engine
            .shipper(self.store.clone(), self.registrar.clone())
            .ship_pending()
            .unwrap();
    }

    fn restore(&self, name: &str) -> PathBuf {
        let out = self.tmp.path().join(name);
        Materializer::new(self.store.as_ref(), MaterializeTargets::new(&out, None))
            .materialize(
                &self.registrar.head().unwrap().manifest,
                MaterializeClass::All,
            )
            .unwrap();
        out
    }
}

// ---------------------------------------------------------------------------------------------
// #1: nested shared storage — bare repositories, symlinked object stores.
// ---------------------------------------------------------------------------------------------

/// `<at>` as a bare repository whose `objects/info/alternates` names the top-level object
/// store (relative), its `main` at `oid`.
fn bare_borrowing(fx: &Fixture, at: &str, oid: &str) -> PathBuf {
    let child = fx.root.join(at);
    fs::create_dir_all(&child).unwrap();
    git(&child, &["init", "--bare", "-q", "-b", "main"]);
    let depth = at.split('/').count();
    let up = "../".repeat(depth + 1);
    fs::write(
        child.join("objects/info/alternates"),
        format!("{up}.git/objects\n"),
    )
    .unwrap();
    git(&child, &["update-ref", "refs/heads/main", oid]);
    child
}

/// The reviewer's first case: a bare repository in the worktree tree (untracked, not ignored)
/// borrowing the top-level store through a relative alternate. The commit only it reaches was
/// in no pack: the final flush completed and sealed, the restored child's `main` named an
/// object the restored store did not hold, and `git show` there failed.
#[test]
fn a_nested_bare_repository_borrowing_the_top_level_objects_keeps_them() {
    let fx = Fixture::new();
    let oid = unreachable_commit(&fx.root, b"unique work only nested bare repo reaches\n");
    let child = bare_borrowing(&fx, "child.git", &oid);
    assert_eq!(
        git(&child, &["show", "HEAD:unique.txt"]),
        "unique work only nested bare repo reaches"
    );
    fx.final_flush();
    let out = fx.restore("nested-bare");
    assert_eq!(
        fs::read_to_string(out.join("child.git/refs/heads/main"))
            .unwrap()
            .trim(),
        oid
    );
    let object = git_out(&out, &["cat-file", "-e", &oid], None);
    assert!(object.status.success(), "the restored store lacks {oid}");
    let read = git_out(&out.join("child.git"), &["show", "HEAD:unique.txt"], None);
    assert!(
        read.status.success(),
        "the nested bare repository lost its commit {oid}: {}",
        String::from_utf8_lossy(&read.stderr)
    );
    assert_eq!(read.stdout, b"unique work only nested bare repo reaches\n");
}

/// The same bare repository under an ignored directory (the workspace class's `tree/`), and
/// tracked by the top-level repository: each is found by its `HEAD`, and keeps its commit.
#[test]
fn a_bare_repository_ignored_or_tracked_borrowing_the_top_level_objects_keeps_them() {
    let fx = Fixture::new();
    let ignored = unreachable_commit(&fx.root, b"only the ignored bare repo reaches\n");
    let tracked = unreachable_commit(&fx.root, b"only the tracked bare repo reaches\n");
    bare_borrowing(&fx, "ignored/child.git", &ignored);
    bare_borrowing(&fx, "fixtures/child.git", &tracked);
    git(&fx.root, &["add", "-f", "fixtures"]);
    git(&fx.root, &["commit", "-qm", "a bare fixture"]);
    fx.final_flush();
    let out = fx.restore("nested-bare-classes");
    for (at, oid, text) in [
        (
            "ignored/child.git",
            &ignored,
            "only the ignored bare repo reaches\n",
        ),
        (
            "fixtures/child.git",
            &tracked,
            "only the tracked bare repo reaches\n",
        ),
    ] {
        let read = git_out(&out.join(at), &["show", "HEAD:unique.txt"], None);
        assert!(
            read.status.success(),
            "{at} lost {oid}: {}",
            String::from_utf8_lossy(&read.stderr)
        );
        assert_eq!(read.stdout, text.as_bytes(), "{at}");
    }
}

/// The reviewer's second case: a nested repository whose `objects` is a relative symlink to the
/// top-level store. It was taken for storage the chunked classes carry (only the symlink is),
/// and the commit only it reaches was in no pack.
#[test]
fn a_nested_repository_whose_objects_link_to_the_top_level_store_keeps_them() {
    let fx = Fixture::new();
    let oid = unreachable_commit(
        &fx.root,
        b"unique work only symlinked nested object store reaches\n",
    );
    let child = fx.root.join("child");
    fs::create_dir_all(&child).unwrap();
    git(&child, &["init", "-q", "-b", "main"]);
    fs::remove_dir_all(child.join(".git/objects")).unwrap();
    symlink("../../.git/objects", child.join(".git/objects")).unwrap();
    git(&child, &["update-ref", "refs/heads/main", &oid]);
    assert_eq!(
        git(&child, &["show", "HEAD:unique.txt"]),
        "unique work only symlinked nested object store reaches"
    );
    fx.final_flush();
    let out = fx.restore("nested-object-link");
    assert_eq!(
        fs::read_to_string(out.join("child/.git/refs/heads/main"))
            .unwrap()
            .trim(),
        oid
    );
    let read = git_out(&out.join("child"), &["show", "HEAD:unique.txt"], None);
    assert!(
        read.status.success(),
        "the nested repository lost the symlinked store's commit {oid}: {}",
        String::from_utf8_lossy(&read.stderr)
    );
    assert_eq!(
        read.stdout,
        b"unique work only symlinked nested object store reaches\n"
    );
}

/// A bare repository whose `objects` is a symlink to a store outside the workspace, and one
/// under a bulk directory borrowing the top-level store: neither can come back from a capture
/// of the workspace, and the final flush says so, naming it. An automatic capture ships all
/// the same (crash protection).
#[test]
fn a_bare_repository_whose_storage_the_capture_cannot_carry_leaves_the_final_flush_incomplete() {
    type Setup = fn(&Fixture, &Path);
    let cases: [(&str, &str, Setup); 2] = [
        ("objects outside", "child.git", |fx, outside| {
            let lender = outside.join("lender.git");
            git(outside, &["init", "--bare", "-q", "lender.git"]);
            let child = fx.root.join("child.git");
            fs::create_dir_all(&child).unwrap();
            git(&child, &["init", "--bare", "-q", "-b", "main"]);
            fs::remove_dir_all(child.join("objects")).unwrap();
            symlink(lender.join("objects"), child.join("objects")).unwrap();
        }),
        ("bulk bare borrowing", "node_modules/child.git", |fx, _| {
            let oid = unreachable_commit(&fx.root, b"only a bulk bare repo reaches\n");
            bare_borrowing(fx, "node_modules/child.git", &oid);
        }),
    ];
    for (name, at, setup) in cases {
        let fx = Fixture::new();
        let outside = fx.tmp.path().join("outside");
        fs::create_dir_all(&outside).unwrap();
        setup(&fx, &outside);
        let (reason, error) = fx.incomplete_flush();
        println!("{name}: {reason}: {error}");
        assert_eq!(reason, "snapshot-failed", "{name}: {error}");
        assert!(error.contains(at), "{name}: {error}");
        let auto = Fixture::new();
        let outside = auto.tmp.path().join("outside");
        fs::create_dir_all(&outside).unwrap();
        setup(&auto, &outside);
        auto.automatic();
        assert!(auto.registrar.head().is_some(), "{name}");
    }
}

// ---------------------------------------------------------------------------------------------
// #2: only git's own transaction files are transient.
// ---------------------------------------------------------------------------------------------

/// The lockfile of a custom Rust git hook: the user's, not git's. It was left out of every
/// capture as a "transient", and a sealed restore had no hook project lockfile.
#[test]
fn a_hook_projects_cargo_lock_in_the_git_directory_is_captured() {
    let fx = Fixture::new();
    let name = ".git/hooks/Cargo.lock";
    let bytes = b"# This file is automatically @generated by Cargo.\nversion = 4\n\n[[package]]\nname = \"my-custom-hook\"\nversion = \"0.1.0\"\n";
    fs::write(fx.root.join(name), bytes).unwrap();
    fx.final_flush();
    let out = fx.restore("hook-cargo-lock");
    assert_eq!(fs::read(out.join(name)).unwrap(), bytes);
}

/// A config include called `personal.lock`, holding the only copy of a remote: the restored
/// `.git/config` still included it, the file was gone, and `git config --get` failed silently.
#[test]
fn a_config_include_named_lock_in_the_git_directory_is_captured() {
    let fx = Fixture::new();
    let name = ".git/personal.lock";
    let bytes = b"[remote \"user-backup\"]\n\turl = ../only-user-remote\n";
    fs::write(fx.root.join(name), bytes).unwrap();
    git(&fx.root, &["config", "include.path", "personal.lock"]);
    fx.final_flush();
    let out = fx.restore("git-include-lock");
    assert_eq!(fs::read(out.join(name)).unwrap(), bytes);
    assert_eq!(
        git(&out, &["config", "--get", "remote.user-backup.url"]),
        "../only-user-remote"
    );
}

/// The same hook lockfile in nested repositories under an ignored directory (the workspace
/// class) and under a bulk directory (the bulk class), beside ordinary `Cargo.lock` controls.
#[test]
fn hook_lockfiles_of_ignored_and_bulk_nested_repositories_are_captured() {
    let fx = Fixture::new();
    let bytes = b"version = 4\n\n[[package]]\nname = \"my-custom-hook\"\nversion = \"0.1.0\"\n";
    for nested in ["ignored/nested", "node_modules/nested"] {
        let child = fx.root.join(nested);
        fs::create_dir_all(&child).unwrap();
        git(&child, &["init", "-q", "-b", "main"]);
        fs::write(child.join(".git/hooks/Cargo.lock"), bytes).unwrap();
    }
    for name in [
        "Cargo.lock",
        "ignored/Cargo.lock",
        "node_modules/Cargo.lock",
    ] {
        fs::write(fx.root.join(name), bytes).unwrap();
    }
    fx.final_flush();
    let out = fx.restore("nested-hook-cargo-lock");
    for name in [
        "Cargo.lock",
        "ignored/Cargo.lock",
        "node_modules/Cargo.lock",
        "ignored/nested/.git/hooks/Cargo.lock",
        "node_modules/nested/.git/hooks/Cargo.lock",
    ] {
        assert_eq!(fs::read(out.join(name)).unwrap(), bytes, "{name}");
    }
}

/// Stale transaction locks a killed git left — the index's, a ref's, the config's, a nested
/// repository's — are git's, not work product: the final flush completes over them (they
/// would otherwise keep the executor from ever completing), the restore has none of them, and
/// git works there.
#[test]
fn stale_git_transaction_locks_are_left_out_and_do_not_block_the_final_flush() {
    let fx = Fixture::new();
    let child = fx.root.join("ignored/nested");
    fs::create_dir_all(&child).unwrap();
    git(&child, &["init", "-q", "-b", "main"]);
    let locks = [
        ".git/index.lock",
        ".git/HEAD.lock",
        ".git/config.lock",
        ".git/packed-refs.lock",
        ".git/refs/heads/main.lock",
        ".git/logs/refs/heads/main.lock",
        "ignored/nested/.git/index.lock",
    ];
    for lock in locks {
        fs::write(fx.root.join(lock), b"half-written by a killed git\n").unwrap();
    }
    fx.final_flush();
    let out = fx.restore("stale-locks");
    for lock in locks {
        assert!(!out.join(lock).exists(), "{lock} came back");
    }
    // Git works in the restore: the index, a ref and the config can be written.
    git(&out, &["update-index", "--refresh"]);
    git(&out, &["config", "user.name", "after"]);
    git(&out, &["commit", "-q", "--allow-empty", "-m", "after"]);
}
