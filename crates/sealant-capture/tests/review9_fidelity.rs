//! What a sealed final flush holds is what the disk held, or the flush is not complete (review
//! 2026-09-28, ninth pass):
//!
//! - a reftable repository's `HEAD`, reflogs and root refs are read through git, so the objects
//!   only they reach are in the packs, and the restore makes a reftable repository again (#1,
//!   decision 24);
//! - a symlink under `.git/refs` that git reads through to a ref file comes back as that symlink,
//!   and one that reaches outside the repository leaves the flush incomplete (#2);
//! - a modification time a capture cannot record exactly leaves the flush incomplete, whatever
//!   the class (#3);
//! - a strict restore never relinks a tracked hardlink group whose names hold different bytes
//!   (#7).

use std::fs;
use std::os::unix::fs::{MetadataExt, symlink};
use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use std::sync::Arc;
use std::time::{Duration, UNIX_EPOCH};

use sealant_capture::gitpack::GitRepo;
use sealant_capture::worktree_meta::{self, MetaScope};
use sealant_capture::{
    CadenceRunner, CaptureConfig, CaptureEngine, InMemoryRegistrar, LocalDir, MaterializeClass,
    MaterializeTargets, Materializer,
};

const EXECUTOR: &str = "exec-r9";

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

/// Every object a reflog entry names (none when there is no reflog).
fn reflog_objects(root: &Path) -> String {
    git_in(
        root,
        &["rev-list", "--no-walk=unsorted", "--reflog", "--stdin"],
        Some(b""),
    )
}

/// Set `path`'s modification time (not following a symlink's link) to `secs` after the epoch.
fn set_mtime_secs(path: &Path, secs: u64) {
    fs::File::options()
        .read(true)
        .open(path)
        .unwrap()
        .set_times(fs::FileTimes::new().set_modified(UNIX_EPOCH + Duration::from_secs(secs)))
        .unwrap();
    assert_eq!(
        fs::metadata(path).unwrap().mtime(),
        i64::try_from(secs).unwrap()
    );
}

/// 10,000,000,000 seconds after the epoch (the year 2286): a time the filesystem holds and
/// signed 64-bit nanoseconds (which end in 2262) do not.
const FUTURE_SECS: u64 = 10_000_000_000;

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

    /// [`Self::new`], its refs moved to the reftable backend.
    fn reftable() -> Self {
        let fx = Self::new();
        git(&fx.root, &["refs", "migrate", "--ref-format=reftable"]);
        assert_eq!(
            git(&fx.root, &["rev-parse", "--show-ref-format"]),
            "reftable"
        );
        fx
    }

    fn config(&self) -> CaptureConfig {
        let mut config = CaptureConfig::new("wt", 1, &self.root);
        config.executor = Some(EXECUTOR.to_owned());
        config
    }

    fn runner(&self, config: CaptureConfig) -> CadenceRunner {
        let engine = CaptureEngine::open(config, None).unwrap();
        let shipper = Arc::new(engine.shipper(self.store.clone(), self.registrar.clone()));
        CadenceRunner::new(engine, shipper)
    }

    /// A final flush that must say `complete` and seal the chain.
    fn final_flush(&self, config: CaptureConfig) {
        let result = self.runner(config).flush_final(None);
        assert!(result.complete(), "{result:?}");
        let head = self.registrar.head().unwrap();
        assert!(head.manifest.final_seal.is_some(), "the chain is sealed");
        assert!(
            !self.registrar.seals().is_empty(),
            "the registrar recorded it"
        );
    }

    /// A final flush that must not say `complete`; its reason and error text.
    fn incomplete_flush(&self, config: CaptureConfig) -> (String, String) {
        let result = self.runner(config).flush_final(None);
        let incomplete = result
            .incomplete
            .clone()
            .unwrap_or_else(|| panic!("the final flush said complete: {result:?}"));
        assert!(self.registrar.seals().is_empty(), "nothing is sealed");
        (incomplete.reason().to_owned(), incomplete.to_string())
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
// #1: reftable.
// ---------------------------------------------------------------------------------------------

/// A commit only the reftable reflog reaches (committed, then reset away; `ORIG_HEAD` gone):
/// its commit and blob are in the packs, and the restored repository shows the file.
#[test]
fn a_reftable_reflog_keeps_its_unique_work() {
    let fx = Fixture::reftable();
    fs::write(
        fx.root.join("unique.txt"),
        b"unique work in a reflog-only commit\n",
    )
    .unwrap();
    git(&fx.root, &["add", "unique.txt"]);
    git(&fx.root, &["commit", "-qm", "unique reflog work"]);
    let oid = git(&fx.root, &["rev-parse", "HEAD"]);
    git(&fx.root, &["reset", "-q", "--hard", "HEAD~1"]);
    git(&fx.root, &["update-ref", "-d", "ORIG_HEAD"]);
    assert!(
        !fx.root.join(".git/logs").exists(),
        "the reflog is in the tables"
    );
    fx.final_flush(fx.config());
    let out = fx.restore("restored");
    assert_eq!(
        git(&out, &["show", &format!("{oid}:unique.txt")]),
        "unique work in a reflog-only commit"
    );
    assert!(
        git(&out, &["rev-list", "--reflog", "--all"]).contains(&oid),
        "the restored reflog names it"
    );
}

/// A detached reftable `HEAD` on a commit nothing else reaches: the commit is in the packs, and
/// the restored `HEAD` is that commit with its tree.
#[test]
fn a_reftable_detached_head_keeps_its_commit() {
    let fx = Fixture::reftable();
    let oid = unreachable_commit(&fx.root, b"unique detached head work\n");
    git(&fx.root, &["checkout", "-q", "--detach", &oid]);
    // Nothing but `HEAD` reaches it: its reflog entries are gone.
    git(&fx.root, &["reflog", "expire", "--expire=now", "--all"]);
    assert!(!reflog_objects(&fx.root).contains(&oid));
    fx.final_flush(fx.config());
    let out = fx.restore("restored");
    assert_eq!(git(&out, &["rev-parse", "HEAD"]), oid);
    assert_eq!(
        git(&out, &["show", "HEAD:unique.txt"]),
        "unique detached head work"
    );
}

/// `ORIG_HEAD` is a ref in a reftable repository, not a file: the commit only it reaches is in
/// the packs.
#[test]
fn a_reftable_orig_head_keeps_its_commit() {
    let fx = Fixture::reftable();
    fs::write(
        fx.root.join("unique.txt"),
        b"unique work only ORIG_HEAD names\n",
    )
    .unwrap();
    git(&fx.root, &["add", "unique.txt"]);
    git(&fx.root, &["commit", "-qm", "unique"]);
    let oid = git(&fx.root, &["rev-parse", "HEAD"]);
    git(&fx.root, &["reset", "-q", "--hard", "HEAD~1"]);
    git(&fx.root, &["reflog", "expire", "--expire=now", "--all"]);
    assert!(!reflog_objects(&fx.root).contains(&oid));
    assert_eq!(git(&fx.root, &["rev-parse", "ORIG_HEAD"]), oid);
    assert!(
        !fx.root.join(".git/ORIG_HEAD").exists(),
        "a ref in the tables"
    );
    fx.final_flush(fx.config());
    let out = fx.restore("restored");
    assert_eq!(git(&out, &["rev-parse", "ORIG_HEAD"]), oid);
    assert_eq!(
        git(&out, &["show", "ORIG_HEAD:unique.txt"]),
        "unique work only ORIG_HEAD names"
    );
}

/// The git section names the reftable backend (`ref_format`) and the real `HEAD`, never the
/// compatibility file's `refs/heads/.invalid`; symbolic refs are read through git, each by its
/// immediate target. A files repository's section names no backend.
#[test]
fn the_git_section_names_the_reftable_backend() {
    let fx = Fixture::reftable();
    git(
        &fx.root,
        &["symbolic-ref", "refs/heads/alias", "refs/heads/main"],
    );
    git(
        &fx.root,
        &["symbolic-ref", "refs/heads/alias2", "refs/heads/alias"],
    );
    fx.final_flush(fx.config());
    let manifest = fx.registrar.head().unwrap().manifest;
    let section = &manifest.sections.git;
    assert_eq!(section.ref_format.as_deref(), Some("reftable"));
    assert_eq!(section.head, "refs/heads/main");
    assert_eq!(
        section.symrefs.get("refs/heads/alias2").map(String::as_str),
        Some("refs/heads/alias")
    );
    let out = fx.restore("restored");
    assert_eq!(git(&out, &["rev-parse", "--show-ref-format"]), "reftable");
    assert_eq!(git(&out, &["symbolic-ref", "HEAD"]), "refs/heads/main");
    assert_eq!(
        git(&out, &["symbolic-ref", "--no-recurse", "refs/heads/alias2"]),
        "refs/heads/alias"
    );
    // The restored git class alone (no workspace class, whose tables would stand in for it)
    // is a reftable repository with the same refs.
    let git_only = fx.tmp.path().join("git-only");
    Materializer::new(fx.store.as_ref(), MaterializeTargets::new(&git_only, None))
        .materialize(&manifest, MaterializeClass::Git)
        .unwrap();
    assert_eq!(
        git(&git_only, &["rev-parse", "--show-ref-format"]),
        "reftable"
    );
    assert_eq!(
        git(
            &git_only,
            &["for-each-ref", "--format=%(refname) %(objectname)"]
        ),
        git(
            &fx.root,
            &["for-each-ref", "--format=%(refname) %(objectname)"]
        )
    );
    assert_eq!(git(&git_only, &["symbolic-ref", "HEAD"]), "refs/heads/main");

    let fx = Fixture::new();
    fx.final_flush(fx.config());
    let manifest = fx.registrar.head().unwrap().manifest;
    assert_eq!(manifest.sections.git.ref_format, None);
    let text = String::from_utf8(manifest.encode().bytes).unwrap();
    assert!(!text.contains("ref_format"), "{text}");
}

/// A store that does not read `ref_format`: a reftable repository's final flush is not complete
/// (the store would restore the refs into another backend); a files one's is.
#[test]
fn a_store_that_does_not_read_the_ref_format_cannot_complete_a_reftable_flush() {
    let reads: Vec<String> = sealant_capture::registrar::MANIFEST_FEATURES
        .iter()
        .filter(|f| **f != "ref_format")
        .map(|f| (*f).to_owned())
        .collect();
    let fx = Fixture::reftable();
    let mut config = fx.config();
    config.set_store_features(&reads);
    assert!(
        config.fidelity_gap().is_none(),
        "a files repository needs nothing more"
    );
    let (reason, error) = fx.incomplete_flush(config);
    assert_eq!(reason, "snapshot-failed", "{error}");
    assert!(error.contains("ref_format"), "{error}");

    let fx = Fixture::new();
    let mut config = fx.config();
    config.set_store_features(&reads);
    fx.final_flush(config);
}

// ---------------------------------------------------------------------------------------------
// #2: ref symlinks.
// ---------------------------------------------------------------------------------------------

/// `.git/refs/heads/alias -> main`: git reads the file it reaches, a direct ref. The restore
/// puts the symlink back, and it still resolves to `main`'s commit (the file it reaches is
/// there).
#[test]
fn a_ref_symlink_alias_keeps_its_link() {
    let fx = Fixture::new();
    symlink("main", fx.root.join(".git/refs/heads/alias")).unwrap();
    fs::create_dir_all(fx.root.join(".git/refs/heads/topic")).unwrap();
    symlink("../alias", fx.root.join(".git/refs/heads/topic/chain")).unwrap();
    let oid = git(&fx.root, &["rev-parse", "refs/heads/alias"]);
    assert_eq!(git(&fx.root, &["rev-parse", "refs/heads/topic/chain"]), oid);
    fx.final_flush(fx.config());
    let out = fx.restore("restored");
    assert_eq!(
        fs::read_link(out.join(".git/refs/heads/alias")).unwrap(),
        PathBuf::from("main")
    );
    assert_eq!(
        fs::read_link(out.join(".git/refs/heads/topic/chain")).unwrap(),
        PathBuf::from("../alias")
    );
    assert_eq!(git(&out, &["rev-parse", "refs/heads/alias"]), oid);
    assert_eq!(git(&out, &["rev-parse", "refs/heads/topic/chain"]), oid);
    // Still the alias it was: a commit on `main` moves it too.
    git(&out, &["config", "user.email", "t@t"]);
    git(&out, &["config", "user.name", "t"]);
    git(&out, &["commit", "-q", "--allow-empty", "-m", "next"]);
    assert_eq!(
        git(&out, &["rev-parse", "refs/heads/alias"]),
        git(&out, &["rev-parse", "refs/heads/main"])
    );
}

/// A ref symlink that reaches a file outside the repository: a restore cannot bring that file
/// back, so a final flush over it is not complete.
#[test]
fn a_ref_symlink_reaching_outside_the_repository_leaves_the_final_flush_incomplete() {
    let fx = Fixture::new();
    let outside = fx.tmp.path().join("elsewhere");
    fs::create_dir_all(&outside).unwrap();
    let oid = git(&fx.root, &["rev-parse", "HEAD"]);
    fs::write(outside.join("ref"), format!("{oid}\n")).unwrap();
    symlink(
        outside.join("ref"),
        fx.root.join(".git/refs/heads/external"),
    )
    .unwrap();
    assert_eq!(git(&fx.root, &["rev-parse", "refs/heads/external"]), oid);
    let (reason, error) = fx.incomplete_flush(fx.config());
    assert_eq!(reason, "snapshot-failed", "{error}");
    assert!(error.contains("refs/heads/external"), "{error}");
}

// ---------------------------------------------------------------------------------------------
// #3: modification times a capture cannot record.
// ---------------------------------------------------------------------------------------------

/// Every class: an untracked file (the workspace class), a tracked one (the worktree
/// metadata), an untracked directory, a bulk file. Each leaves the final flush incomplete as
/// `unreadable`, naming the path.
#[test]
fn a_modification_time_after_2262_leaves_the_final_flush_incomplete() {
    type Setup = fn(&Path) -> (PathBuf, &'static str);
    let cases: [Setup; 4] = [
        |root| {
            let p = root.join("ignored/future.txt");
            fs::create_dir_all(p.parent().unwrap()).unwrap();
            fs::write(&p, b"future dated user work\n").unwrap();
            (p, "ignored/future.txt")
        },
        |root| {
            let p = root.join("a");
            (p, "tree/a")
        },
        |root| {
            let p = root.join("ignored/dir");
            fs::create_dir_all(&p).unwrap();
            fs::write(p.join("x"), b"x\n").unwrap();
            (p, "ignored/dir")
        },
        |root| {
            let p = root.join("node_modules/pkg/index.js");
            fs::create_dir_all(p.parent().unwrap()).unwrap();
            fs::write(&p, b"module.exports = 1;\n").unwrap();
            (p, "node_modules/pkg/index.js")
        },
    ];
    for setup in cases {
        let fx = Fixture::new();
        let (path, named) = setup(&fx.root);
        set_mtime_secs(&path, FUTURE_SECS);
        let (reason, error) = fx.incomplete_flush(fx.config());
        println!("{named}: {reason}: {error}");
        assert_eq!(reason, "unreadable", "{named}: {error}");
        assert!(error.contains(named), "{named}: {error}");
        assert!(error.contains("modification time"), "{error}");
    }
}

/// An automatic snap still carries the file's bytes (only its time cannot be recorded).
#[test]
fn an_automatic_snap_keeps_the_bytes_of_a_future_dated_file() {
    use sealant_capture::{CaptureKind, Class, SnapRequest};
    let fx = Fixture::new();
    let path = fx.root.join("ignored/future.txt");
    fs::create_dir_all(path.parent().unwrap()).unwrap();
    fs::write(&path, b"future dated user work\n").unwrap();
    set_mtime_secs(&path, FUTURE_SECS);
    let mut engine = CaptureEngine::open(fx.config(), None).unwrap();
    engine
        .snap(SnapRequest {
            kind: CaptureKind::Auto,
            class: Class::Small,
            seq: 0,
        })
        .unwrap();
    let shipper = engine.shipper(fx.store.clone(), fx.registrar.clone());
    shipper.ship_pending().unwrap();
    let out = fx.restore("restored");
    assert_eq!(
        fs::read(out.join("ignored/future.txt")).unwrap(),
        b"future dated user work\n"
    );
}

// ---------------------------------------------------------------------------------------------
// #7: a tracked hardlink group whose names hold different bytes.
// ---------------------------------------------------------------------------------------------

/// A document promising `a.txt` and `b.txt` are one inode, over a disk where `b.txt` holds other
/// bytes (a workspace overlay wrote them): a strict apply refuses and writes over neither; a
/// lenient one leaves the two names apart.
#[test]
fn a_tracked_hardlink_group_whose_bytes_differ_is_never_relinked() {
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path().join("ws");
    fs::create_dir_all(&root).unwrap();
    git(&root, &["init", "-q", "-b", "main"]);
    fs::write(root.join("a.txt"), b"base group bytes\n").unwrap();
    fs::hard_link(root.join("a.txt"), root.join("b.txt")).unwrap();
    git(&root, &["add", "-A"]);
    let tree = git(&root, &["write-tree"]);
    let repo = GitRepo::open(&root).unwrap();
    let scope = MetaScope {
        root: root.clone(),
        excludes: vec![".sealantd".to_owned()],
        bulk_dirs: Vec::new(),
        nested: Vec::new(),
        skip_abs: Vec::new(),
    };
    let doc = worktree_meta::capture(&repo, &tree, &scope, None)
        .unwrap()
        .doc;
    assert_eq!(
        doc.hardlinks,
        vec![vec!["a.txt".to_owned(), "b.txt".to_owned()]]
    );
    // The overlay: `b.txt` is its own file with unique bytes.
    fs::remove_file(root.join("b.txt")).unwrap();
    fs::write(root.join("b.txt"), b"new unique overlay work\n").unwrap();
    let resolve = |_: worktree_meta::LinkClass, _: &[u8]| -> Option<PathBuf> { None };
    let refused = worktree_meta::apply_strict(&repo, &doc, &scope, &resolve);
    assert!(
        matches!(
            refused,
            Err(worktree_meta::MetaError::LinkUnfulfilled { .. })
        ),
        "{refused:?}"
    );
    assert_eq!(
        fs::read(root.join("b.txt")).unwrap(),
        b"new unique overlay work\n"
    );
    assert_eq!(fs::read(root.join("a.txt")).unwrap(), b"base group bytes\n");
    worktree_meta::apply(&repo, &doc, &scope, &resolve).unwrap();
    assert_eq!(
        fs::read(root.join("b.txt")).unwrap(),
        b"new unique overlay work\n"
    );
    let (a, b) = (
        fs::metadata(root.join("a.txt")).unwrap(),
        fs::metadata(root.join("b.txt")).unwrap(),
    );
    assert_ne!(a.ino(), b.ino(), "left apart");
}
