//! What a sealed final flush holds comes back as it was (review 2026-09-28, seventh pass):
//!
//! - a symbolic ref git stores as a symlink (`core.preferSymlinkRefs`) stays symbolic, keeps
//!   its name and target bytes — dangling, chained, beside `HEAD` — and comes back as the
//!   symlink it was (#1);
//! - the `.git` directory and the harness home keep their mode and nanosecond mtime (#2);
//! - a strict restore refuses a document that promises one inode two modes or two mtimes,
//!   before it changes anything (#10);
//! - `plan.get` says this executor reads `present` in an `upload.urls` answer (decision 20).

use std::ffi::OsStr;
use std::fs;
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use std::sync::Arc;

use nix::sys::stat::{UtimensatFlags, utimensat};
use nix::sys::time::TimeSpec;
use sealant_capture::gitpack::GitRepo;
use sealant_capture::registrar::PlanGetRequest;
use sealant_capture::worktree_meta::{self, MetaDocument, MetaEntry, MetaKind, MetaScope};
use sealant_capture::{
    CadenceRunner, CaptureConfig, CaptureEngine, InMemoryRegistrar, LocalDir, MaterializeClass,
    MaterializeTargets, Materializer,
};

const EXECUTOR: &str = "exec-r7";

fn git_out(root: &Path, args: &[&OsStr]) -> Output {
    Command::new("git")
        .current_dir(root)
        .env("GIT_OPTIONAL_LOCKS", "0")
        .args(args)
        .output()
        .expect("git")
}

fn git(root: &Path, args: &[&str]) -> Vec<u8> {
    let args: Vec<&OsStr> = args.iter().map(OsStr::new).collect();
    let out = git_out(root, &args);
    assert!(
        out.status.success(),
        "git {args:?} failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    out.stdout
}

/// `git symbolic-ref --no-recurse <name>`: the ref's own target, or `None` when git does not
/// read it as a symbolic ref.
fn symbolic(root: &Path, name: &[u8]) -> Option<Vec<u8>> {
    let out = git_out(
        root,
        &[
            OsStr::new("symbolic-ref"),
            OsStr::new("--no-recurse"),
            OsStr::from_bytes(name),
        ],
    );
    out.status.success().then_some(out.stdout)
}

/// How a ref is stored: `Some((link, mtime))` for a symlink, `None` for anything else.
fn as_symlink(path: &Path) -> Option<(PathBuf, i64)> {
    let meta = fs::symlink_metadata(path).ok()?;
    meta.is_symlink().then(|| {
        (
            fs::read_link(path).unwrap(),
            meta.mtime() * 1_000_000_000 + meta.mtime_nsec(),
        )
    })
}

fn set_mtime(path: &Path, ns: i64) {
    utimensat(
        nix::fcntl::AT_FDCWD,
        path,
        &TimeSpec::UTIME_OMIT,
        &TimeSpec::new(ns / 1_000_000_000, ns % 1_000_000_000),
        UtimensatFlags::NoFollowSymlink,
    )
    .unwrap();
}

struct Fixture {
    tmp: tempfile::TempDir,
    root: PathBuf,
    store: Arc<LocalDir>,
    registrar: Arc<InMemoryRegistrar>,
}

impl Fixture {
    /// A repository with one commit on `main`.
    fn new() -> Self {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path().join("ws");
        fs::create_dir_all(&root).unwrap();
        git(&root, &["init", "-q", "-b", "main"]);
        git(&root, &["config", "user.email", "t@t"]);
        git(&root, &["config", "user.name", "t"]);
        fs::write(root.join("a"), b"base\n").unwrap();
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
    }

    fn restore(&self, name: &str, harness: Option<PathBuf>) -> PathBuf {
        let out = self.tmp.path().join(name);
        Materializer::new(self.store.as_ref(), MaterializeTargets::new(&out, harness))
            .materialize(
                &self.registrar.head().unwrap().manifest,
                MaterializeClass::All,
            )
            .unwrap();
        out
    }
}

/// Refs git stores as symlinks — one to a branch, one to another symlinked ref, one whose name
/// is not UTF-8, `HEAD` itself — beside a symbolic ref stored as text: after a sealed final
/// flush and a full restore each is the symbolic ref it was, with the same target, stored the
/// same way (a symlink with the same link text and mtime, or a `ref:` file).
#[test]
fn symlinked_symbolic_refs_stay_symbolic_and_symlinked() {
    let fx = Fixture::new();
    let root = &fx.root;
    let symlinked = |args: &[&OsStr]| {
        let mut all = vec![
            OsStr::new("-c"),
            OsStr::new("core.preferSymlinkRefs=true"),
            OsStr::new("symbolic-ref"),
        ];
        all.extend_from_slice(args);
        let out = git_out(root, &all);
        assert!(out.status.success(), "{out:?}");
    };
    symlinked(&[
        OsStr::new("refs/heads/alias"),
        OsStr::new("refs/heads/main"),
    ]);
    symlinked(&[
        OsStr::new("refs/heads/alias2"),
        OsStr::new("refs/heads/alias"),
    ]);
    symlinked(&[
        OsStr::from_bytes(b"refs/heads/caf\xe9"),
        OsStr::new("refs/heads/main"),
    ]);
    symlinked(&[OsStr::new("HEAD"), OsStr::new("refs/heads/alias2")]);
    git(
        root,
        &["symbolic-ref", "refs/heads/text", "refs/heads/alias"],
    );
    let names: [&[u8]; 5] = [
        b"HEAD",
        b"refs/heads/alias",
        b"refs/heads/alias2",
        b"refs/heads/caf\xe9",
        b"refs/heads/text",
    ];
    let git_dir = root.join(".git");
    for (i, name) in names.iter().enumerate() {
        set_mtime(
            &git_dir.join(OsStr::from_bytes(name)),
            1_700_000_000_000_000_000 + i as i64 * 1_000_000_007,
        );
    }
    let before: Vec<_> = names
        .iter()
        .map(|n| {
            (
                symbolic(root, n),
                as_symlink(&git_dir.join(OsStr::from_bytes(n))),
            )
        })
        .collect();
    assert!(before[..4].iter().all(|(s, l)| s.is_some() && l.is_some()));
    assert!(before[4].0.is_some() && before[4].1.is_none(), "{before:?}");
    let head = git(root, &["rev-parse", "HEAD"]);

    fx.final_flush(fx.config());
    let out = fx.restore("restored", None);
    let after: Vec<_> = names
        .iter()
        .map(|n| {
            (
                symbolic(&out, n),
                as_symlink(&out.join(".git").join(OsStr::from_bytes(n))),
            )
        })
        .collect();
    println!("source {before:?}\nrestored {after:?}");
    assert_eq!(
        before, after,
        "every symbolic ref as it was, stored as it was"
    );
    assert_eq!(git(&out, &["rev-parse", "HEAD"]), head);
}

/// A symbolic ref stored as a symlink whose target does not exist yet is a ref the repository
/// holds: it comes back, dangling, symbolic, and a symlink.
#[test]
fn a_dangling_symlinked_symbolic_ref_survives() {
    let fx = Fixture::new();
    git(&fx.root, &["config", "core.preferSymlinkRefs", "true"]);
    git(
        &fx.root,
        &[
            "symbolic-ref",
            "refs/heads/future",
            "refs/heads/not-created-yet",
        ],
    );
    let path = |root: &Path| root.join(".git/refs/heads/future");
    let before = (
        symbolic(&fx.root, b"refs/heads/future"),
        as_symlink(&path(&fx.root)),
    );
    assert!(before.0.is_some() && before.1.is_some(), "{before:?}");
    fx.final_flush(fx.config());
    let out = fx.restore("restored", None);
    let after = (
        symbolic(&out, b"refs/heads/future"),
        as_symlink(&path(&out)),
    );
    println!("source {before:?}; restored {after:?}");
    assert_eq!(before, after, "a dangling symlinked symbolic ref vanished");
}

/// A restore over a disk whose `HEAD` is a symlink (a restore of one, or the repository's own)
/// replaces the link; it never writes through it into the branch it names.
#[test]
fn a_restore_over_a_symlinked_head_leaves_the_branch_alone() {
    let fx = Fixture::new();
    git(&fx.root, &["config", "core.preferSymlinkRefs", "true"]);
    git(&fx.root, &["symbolic-ref", "HEAD", "refs/heads/main"]);
    assert!(as_symlink(&fx.root.join(".git/HEAD")).is_some());
    let main = git(&fx.root, &["rev-parse", "refs/heads/main"]);
    fx.final_flush(fx.config());
    let out = fx.restore("restored", None);
    let manifest = fx.registrar.head().unwrap().manifest;
    // Once more over itself: the restored `HEAD` is the symlink.
    Materializer::new(fx.store.as_ref(), MaterializeTargets::new(&out, None))
        .materialize(&manifest, MaterializeClass::All)
        .unwrap();
    let after = (
        symbolic(&out, b"HEAD"),
        symbolic(&out, b"refs/heads/main"),
        as_symlink(&out.join(".git/HEAD")).map(|(link, _)| link),
    );
    println!("restored twice: {after:?}");
    assert_eq!(
        after,
        (
            Some(b"refs/heads/main\n".to_vec()),
            None,
            Some(PathBuf::from("refs/heads/main"))
        ),
        "HEAD and main as they were"
    );
    assert_eq!(git(&out, &["rev-parse", "refs/heads/main"]), main);
}

/// The `.git` directory and the harness home are directories of the workspace class like any
/// other: their mode and nanosecond mtime come back, after everything the restore writes into
/// them.
#[test]
fn the_git_and_harness_roots_keep_their_mode_and_mtime() {
    let fx = Fixture::new();
    let harness = fx.tmp.path().join("harness");
    fs::create_dir(&harness).unwrap();
    fs::write(harness.join("work"), b"work").unwrap();
    let mut config = fx.config();
    config.harness_home = Some(harness.clone());
    // The engine sets up its staging before anything is stamped.
    let runner = fx.runner(config);
    let stamp = 1_700_000_000_123_456_789i64;
    for path in [fx.root.join(".git"), harness.clone()] {
        fs::set_permissions(&path, fs::Permissions::from_mode(0o750)).unwrap();
        set_mtime(&path, stamp);
    }
    let result = runner.flush_final(None);
    assert!(result.complete(), "{result:?}");
    let h_out = fx.tmp.path().join("restored-harness");
    let out = fx.restore("restored", Some(h_out.clone()));
    let mut differences = Vec::new();
    for (name, source, restored) in [
        (".git", fx.root.join(".git"), out.join(".git")),
        ("harness", harness, h_out),
    ] {
        let a = fs::metadata(source).unwrap();
        let b = fs::metadata(restored).unwrap();
        let (a, b) = (
            (a.mode() & 0o7777, a.mtime(), a.mtime_nsec()),
            (b.mode() & 0o7777, b.mtime(), b.mtime_nsec()),
        );
        println!("{name}: source {a:?}; restored {b:?}");
        assert_eq!(a, (0o750, 1_700_000_000, 123_456_789), "{name} held still");
        if a != b {
            differences.push(name);
        }
    }
    assert!(
        differences.is_empty(),
        "root metadata changed for {differences:?}"
    );
}

/// Two names the document says are one inode, promised two modes and two mtimes: a strict
/// restore cannot make both true, so it refuses the document before it links or sets anything.
#[test]
fn a_strict_restore_refuses_one_inode_with_two_metadata_promises() {
    let fx = Fixture::new();
    fs::write(fx.root.join("b"), b"base\n").unwrap();
    fs::set_permissions(fx.root.join("a"), fs::Permissions::from_mode(0o640)).unwrap();
    fs::set_permissions(fx.root.join("b"), fs::Permissions::from_mode(0o640)).unwrap();
    set_mtime(&fx.root.join("a"), 50);
    set_mtime(&fx.root.join("b"), 60);
    let doc = MetaDocument {
        format: 1,
        entries: vec![
            MetaEntry {
                path: "a".into(),
                raw_path: None,
                kind: MetaKind::File,
                mode: Some(0o644),
                mtime: 100,
            },
            MetaEntry {
                path: "b".into(),
                raw_path: None,
                kind: MetaKind::File,
                mode: Some(0o600),
                mtime: 200,
            },
        ],
        hardlinks: vec![vec!["a".into(), "b".into()]],
        ..MetaDocument::default()
    };
    let doc = MetaDocument::decode(&doc.encode()).unwrap();
    let scope = MetaScope {
        root: fx.root.clone(),
        excludes: vec![".sealantd".into()],
        bulk_dirs: vec![],
        nested: vec![],
        skip_abs: vec![],
        shared_group: false,
    };
    let stat = |name: &str| {
        let m = fs::metadata(fx.root.join(name)).unwrap();
        (m.ino(), m.mode() & 0o7777, m.mtime_nsec())
    };
    let before = (stat("a"), stat("b"));
    let applied =
        worktree_meta::apply_strict(&GitRepo::open(&fx.root).unwrap(), &doc, &scope, &|_, _| {
            None
        });
    let after = (stat("a"), stat("b"));
    println!("applied {applied:?}; before {before:?}; after {after:?}");
    assert!(
        applied.is_err(),
        "one inode promised two modes and two mtimes was accepted"
    );
    assert_eq!(before, after, "nothing was changed before the refusal");
}

/// A booting executor tells the registrar it reads `present` in an `upload.urls` answer, so
/// the registrar answers `present` only to an executor that can read it (cross-repo decision
/// 20); an older executor's request says nothing and keeps getting a URL. It also says it sends
/// `x-amz-checksum-sha256` on a PUT whose URL signs it (`sha256`, bytes-bound PUT URLs).
#[test]
fn plan_get_says_this_executor_reads_present() {
    let booting = serde_json::to_value(PlanGetRequest::booting(None)).unwrap();
    assert_eq!(
        booting["upload_answers"],
        serde_json::json!(["present", "sha256"]),
        "{booting}"
    );
}
