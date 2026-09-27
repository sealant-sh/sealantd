//! Refs a complete final flush holds come back exactly (review 2026-09-28 #8, #11): a ref name
//! that is not UTF-8 keeps its bytes (two such names never collapse into one, which dropped a
//! branch and the commit only it reached), and a symbolic ref whose target does not exist (a
//! dangling `refs/remotes/origin/HEAD`, which `git for-each-ref` does not list) is restored with
//! its exact target, beside an ordinary one and one that points at another symbolic ref.

use std::ffi::OsStr;
use std::fs;
use std::os::unix::ffi::OsStrExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use std::sync::Arc;

use sealant_capture::{
    CadenceRunner, CaptureConfig, CaptureEngine, InMemoryRegistrar, LocalDir, MaterializeClass,
    MaterializeTargets, Materializer,
};

fn git_raw(root: &Path, args: &[&OsStr]) -> Output {
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
    out
}

fn git(root: &Path, args: &[&str]) -> String {
    let args: Vec<&OsStr> = args.iter().map(OsStr::new).collect();
    let out = git_raw(root, &args);
    String::from_utf8_lossy(&out.stdout).trim().to_owned()
}

/// `git for-each-ref` names and values, as bytes.
fn ref_listing(root: &Path) -> Vec<u8> {
    git_raw(
        root,
        &[
            OsStr::new("for-each-ref"),
            OsStr::new("--format=%(refname) %(objectname)"),
        ],
    )
    .stdout
}

/// The target `name` names itself (`--no-recurse`: a symbolic ref to a symbolic ref is not
/// followed).
fn symbolic_ref(root: &Path, name: &[u8]) -> Vec<u8> {
    git_raw(
        root,
        &[
            OsStr::new("symbolic-ref"),
            OsStr::new("--no-recurse"),
            OsStr::from_bytes(name),
        ],
    )
    .stdout
}

struct Fixture {
    _temp: tempfile::TempDir,
    root: PathBuf,
    out: PathBuf,
    store: Arc<LocalDir>,
    registrar: Arc<InMemoryRegistrar>,
}

impl Fixture {
    fn new() -> Self {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().join("one");
        fs::create_dir_all(&root).unwrap();
        git(&root, &["init", "-q", "-b", "main"]);
        git(&root, &["config", "user.email", "t@t"]);
        git(&root, &["config", "user.name", "t"]);
        fs::write(root.join("a"), b"base").unwrap();
        git(&root, &["add", "-A"]);
        git(&root, &["commit", "-qm", "base"]);
        Self {
            out: temp.path().join("out"),
            store: Arc::new(LocalDir::new(&temp.path().join("store")).unwrap()),
            registrar: Arc::new(InMemoryRegistrar::new("wt", 1, None)),
            root,
            _temp: temp,
        }
    }

    /// A final flush that must say `complete`, then a fresh restore of the head.
    fn final_flush_and_restore(&self) {
        let engine = CaptureEngine::open(CaptureConfig::new("wt", 1, &self.root), None).unwrap();
        let shipper = Arc::new(engine.shipper(self.store.clone(), self.registrar.clone()));
        let runner = CadenceRunner::new(engine, shipper);
        let result = runner.flush_final(None);
        assert!(result.complete(), "{result:?}");
        Materializer::new(
            self.store.as_ref(),
            MaterializeTargets::new(&self.out, None),
        )
        .materialize(
            &self.registrar.head().unwrap().manifest,
            MaterializeClass::All,
        )
        .unwrap();
    }

    /// A commit only `name` reaches (no reflog: `core.logAllRefUpdates=false`).
    fn branch_with_own_commit(&self, name: &[u8], message: &str) -> String {
        let oid = git(
            &self.root,
            &["commit-tree", "HEAD^{tree}", "-p", "HEAD", "-m", message],
        );
        git_raw(
            &self.root,
            &[
                OsStr::new("-c"),
                OsStr::new("core.logAllRefUpdates=false"),
                OsStr::new("update-ref"),
                OsStr::from_bytes(name),
                OsStr::new(&oid),
            ],
        );
        oid
    }
}

/// Two branches whose names differ only in a byte that is not UTF-8 both survive, each with the
/// commit only it reached. Decoded lossily, both were `refs/heads/caf\u{fffd}`: one overwrote
/// the other, its commit was no pack tip, and the restore lacked it.
#[test]
fn two_raw_ref_names_keep_both_branches_and_their_commits() {
    let fx = Fixture::new();
    let one = fx.branch_with_own_commit(b"refs/heads/caf\xe8", "work one");
    let two = fx.branch_with_own_commit(b"refs/heads/caf\xe9", "work two");
    fx.final_flush_and_restore();
    for oid in [&one, &two] {
        let present = Command::new("git")
            .current_dir(&fx.out)
            .args(["cat-file", "-e", oid])
            .status()
            .unwrap()
            .success();
        assert!(present, "commit {oid} was not restored");
    }
    assert_eq!(ref_listing(&fx.out), ref_listing(&fx.root));
    let heads = git_raw(
        &fx.out,
        &[
            OsStr::new("for-each-ref"),
            OsStr::new("--format=%(refname) %(objectname)"),
            OsStr::new("refs/heads/"),
        ],
    )
    .stdout;
    let mut expected = b"refs/heads/caf\xe8 ".to_vec();
    expected.extend_from_slice(one.as_bytes());
    expected.extend_from_slice(b"\nrefs/heads/caf\xe9 ");
    expected.extend_from_slice(two.as_bytes());
    expected.push(b'\n');
    assert!(
        heads.starts_with(&expected),
        "{:?}",
        String::from_utf8_lossy(&heads)
    );
}

/// A ref name that is not UTF-8 is restored byte for byte (it came back as
/// `refs/heads/caf\u{fffd}`), and `HEAD` pointing at one does too.
#[test]
fn a_raw_ref_name_is_restored_byte_for_byte() {
    let fx = Fixture::new();
    let oid = git(&fx.root, &["rev-parse", "HEAD"]);
    fs::write(
        fx.root.join(OsStr::from_bytes(b".git/refs/heads/caf\xe9")),
        format!("{oid}\n"),
    )
    .unwrap();
    git_raw(
        &fx.root,
        &[
            OsStr::new("symbolic-ref"),
            OsStr::new("HEAD"),
            OsStr::from_bytes(b"refs/heads/caf\xe9"),
        ],
    );
    fx.final_flush_and_restore();
    assert_eq!(ref_listing(&fx.out), ref_listing(&fx.root));
    assert_eq!(symbolic_ref(&fx.out, b"HEAD"), b"refs/heads/caf\xe9\n");
}

/// Symbolic refs are restored with their exact targets, whether the target exists or not: a
/// dangling `refs/remotes/origin/HEAD` (which `for-each-ref` leaves out, so it vanished), an
/// ordinary alias, one pointing at another symbolic ref, and one whose name and target are not
/// UTF-8.
#[test]
fn symbolic_refs_keep_their_targets_even_dangling() {
    let fx = Fixture::new();
    git(&fx.root, &["update-ref", "refs/remotes/up/main", "HEAD"]);
    let cases: [(&[u8], &[u8]); 4] = [
        (b"refs/remotes/origin/HEAD", b"refs/remotes/origin/missing"),
        (b"refs/remotes/up/HEAD", b"refs/remotes/up/main"),
        (b"refs/remotes/up/alias", b"refs/remotes/up/HEAD"),
        (b"refs/remotes/raw/caf\xe9", b"refs/remotes/raw/gone\xff"),
    ];
    for (name, target) in cases {
        git_raw(
            &fx.root,
            &[
                OsStr::new("symbolic-ref"),
                OsStr::from_bytes(name),
                OsStr::from_bytes(target),
            ],
        );
    }
    for (name, target) in cases {
        let mut line = target.to_vec();
        line.push(b'\n');
        assert_eq!(symbolic_ref(&fx.root, name), line);
    }
    fx.final_flush_and_restore();
    for (name, target) in cases {
        let mut line = target.to_vec();
        line.push(b'\n');
        assert_eq!(
            symbolic_ref(&fx.out, name),
            line,
            "{}",
            String::from_utf8_lossy(name)
        );
    }
    assert_eq!(ref_listing(&fx.out), ref_listing(&fx.root));
}
