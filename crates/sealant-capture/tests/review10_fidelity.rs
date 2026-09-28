//! What a sealed final flush holds is what the disk held, or the flush is not complete (review
//! 2026-09-28, tenth pass; cross-repo decision 29):
//!
//! - every object a reflog names is in the packs, whatever its type — a blob, a tree, an
//!   annotated tag — in either ref backend (#1);
//! - a linked worktree inside the workspace keeps its administrative directory (`index`,
//!   `HEAD`, `ORIG_HEAD`, its reflog), and the objects its `HEAD`, refs, reflogs and every index
//!   stage reach are in the packs (#2);
//! - a nested repository that borrows the top-level object store (`objects/info/alternates`)
//!   keeps the objects its `HEAD`, refs, reflogs and index reach (#2);
//! - a nested repository whose git directory, common directory or alternates live outside the
//!   workspace leaves a final flush incomplete, naming it (#2);
//! - a modification time outside signed 64-bit nanoseconds is recorded exactly (the
//!   `wide_times` manifest feature), by an automatic capture as by a final one, and restored
//!   exactly (review 9 #3, carried).

use std::fs;
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use sealant_capture::{
    CadenceRunner, CaptureConfig, CaptureEngine, CaptureKind, Class, InMemoryRegistrar, LocalDir,
    MaterializeClass, MaterializeTargets, Materializer, SnapRequest,
};

const EXECUTOR: &str = "exec-r10";

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

fn init(root: &Path) {
    fs::create_dir_all(root).unwrap();
    git(root, &["init", "-q", "-b", "main"]);
    git(root, &["config", "user.email", "t@t"]);
    git(root, &["config", "user.name", "t"]);
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
        init(&root);
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

    /// An automatic capture of both classes, shipped and registered.
    fn automatic(&self, config: CaptureConfig) {
        let mut engine = CaptureEngine::open(config, None).unwrap();
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
// #1: reflog-only objects of every type.
// ---------------------------------------------------------------------------------------------

/// A blob, a tree and an annotated tag (of another blob) that only a reflog still names: each
/// ref was moved away from it. `git rev-list --reflog` lists commits only, and a sealed capture
/// restored a repository whose reflog named objects it did not hold (`git cat-file` exits 128,
/// `git fsck --full` reports the reflog invalid).
fn reflog_only_objects(reftable: bool) {
    let fx = Fixture::new();
    if reftable {
        git(&fx.root, &["refs", "migrate", "--ref-format=reftable"]);
    }
    let unique: &[u8] = b"unique user work kept only by a blob reflog\n";
    let blob = git_in(&fx.root, &["hash-object", "-w", "--stdin"], Some(unique));
    let in_tree: &[u8] = b"unique bytes only a tree reflog reaches\n";
    let tree_blob = git_in(&fx.root, &["hash-object", "-w", "--stdin"], Some(in_tree));
    let tree = git_in(
        &fx.root,
        &["mktree"],
        Some(format!("100644 blob {tree_blob}\tkept.txt\n").as_bytes()),
    );
    let tagged: &[u8] = b"unique bytes only a tag reflog reaches\n";
    let tagged_blob = git_in(&fx.root, &["hash-object", "-w", "--stdin"], Some(tagged));
    let tag = git_in(
        &fx.root,
        &["mktag"],
        Some(
            format!("object {tagged_blob}\ntype blob\ntag kept\ntagger t <t@t> 0 +0000\n\nkept\n")
                .as_bytes(),
        ),
    );
    let next = git_in(&fx.root, &["hash-object", "-w", "--stdin"], Some(b"new\n"));
    for (name, old) in [
        ("refs/custom/blob", &blob),
        ("refs/custom/tree", &tree),
        ("refs/custom/tag", &tag),
    ] {
        git(&fx.root, &["update-ref", "--create-reflog", name, old]);
        git(&fx.root, &["update-ref", name, &next]);
    }
    let commits_only = git_in(
        &fx.root,
        &["rev-list", "--no-walk=unsorted", "--reflog", "--stdin"],
        Some(b""),
    );
    assert!(!commits_only.contains(&blob) && !commits_only.contains(&tree));
    fx.final_flush(fx.config());
    let out = fx.restore(if reftable { "reftable" } else { "files" });
    for (oid, bytes) in [
        (&blob, unique),
        (&tree_blob, in_tree),
        (&tagged_blob, tagged),
    ] {
        let read = git_out(&out, &["cat-file", "blob", oid], None);
        assert!(read.status.success(), "{oid}: {read:?}");
        assert_eq!(read.stdout, bytes);
    }
    for oid in [&tree, &tag] {
        assert!(
            git_out(&out, &["cat-file", "-e", oid], None)
                .status
                .success(),
            "{oid}"
        );
    }
    let fsck = git_out(&out, &["fsck", "--full"], None);
    assert!(fsck.status.success(), "{fsck:?}");
}

#[test]
fn reflog_only_objects_of_every_type_are_in_the_packs() {
    reflog_only_objects(false);
}

#[test]
fn reftable_reflog_only_objects_of_every_type_are_in_the_packs() {
    reflog_only_objects(true);
}

// ---------------------------------------------------------------------------------------------
// #2: nested repositories that share git storage.
// ---------------------------------------------------------------------------------------------

/// A linked worktree added inside the workspace (`git worktree add <ws>/child`), its `HEAD`
/// detached on a commit nothing else reaches, a file staged there and then changed on disk.
/// Its administrative directory (`.git/worktrees/child`) was pruned from the workspace class,
/// and the staged blob, reachable from nothing the top-level repository reads, was in no pack.
#[test]
fn a_nested_linked_worktree_keeps_its_admin_and_its_staged_work() {
    let fx = Fixture::new();
    let child = fx.root.join("child");
    git(
        &fx.root,
        &[
            "worktree",
            "add",
            "-qb",
            "child-branch",
            child.to_str().unwrap(),
        ],
    );
    let detached = unreachable_commit(&fx.root, b"unique work only the child's HEAD reaches\n");
    git(&child, &["checkout", "-q", "--detach", &detached]);
    let unique: &[u8] = b"unique work only staged in linked child\n";
    fs::write(child.join("staged.txt"), unique).unwrap();
    git(&child, &["add", "staged.txt"]);
    let blob = git(&child, &["rev-parse", ":staged.txt"]);
    fs::write(child.join("staged.txt"), b"newer unstaged child bytes\n").unwrap();
    let admin = fx.root.join(".git/worktrees/child");
    let index = fs::read(admin.join("index")).unwrap();
    let head = fs::read(admin.join("HEAD")).unwrap();
    fx.final_flush(fx.config());
    let out = fx.restore("restored");
    let restored_admin = out.join(".git/worktrees/child");
    assert_eq!(fs::read(restored_admin.join("index")).unwrap(), index);
    assert_eq!(fs::read(restored_admin.join("HEAD")).unwrap(), head);
    assert!(restored_admin.join("gitdir").exists());
    assert!(restored_admin.join("commondir").exists());
    let read = git_out(&out, &["cat-file", "blob", &blob], None);
    assert!(read.status.success(), "{read:?}");
    assert_eq!(read.stdout, unique);
    assert_eq!(
        git(&out, &["show", &format!("{detached}:unique.txt")]),
        "unique work only the child's HEAD reaches"
    );
}

/// A nested repository whose `objects/info/alternates` names the top-level object store (by a
/// path inside the workspace), its `main` on a commit only the top-level store holds and that
/// no top-level ref reaches. The commit was in no pack: the restored nested repository's ref
/// named a commit that was not there.
#[test]
fn a_nested_repository_borrowing_the_top_level_objects_keeps_them() {
    let fx = Fixture::new();
    let oid = unreachable_commit(&fx.root, b"unique commit only used by nested alternate\n");
    let child = fx.root.join("child");
    init(&child);
    fs::create_dir_all(child.join(".git/objects/info")).unwrap();
    fs::write(
        child.join(".git/objects/info/alternates"),
        b"../../../.git/objects\n",
    )
    .unwrap();
    git(&child, &["update-ref", "refs/heads/main", &oid]);
    assert_eq!(
        git(&child, &["show", "HEAD:unique.txt"]),
        "unique commit only used by nested alternate"
    );
    fx.final_flush(fx.config());
    let out = fx.restore("restored");
    assert_eq!(
        git(&out.join("child"), &["show", "HEAD:unique.txt"]),
        "unique commit only used by nested alternate"
    );
    assert!(
        git_out(&out, &["cat-file", "-e", &oid], None)
            .status
            .success()
    );
}

/// A nested repository whose git storage lives outside the workspace cannot come back from a
/// capture of the workspace: its git directory (`git init --separate-git-dir`), a linked
/// worktree of a repository outside, alternates naming an object store outside. Each leaves
/// the final flush incomplete, naming the nested repository; an automatic capture still ships.
#[test]
fn a_nested_repository_sharing_storage_outside_the_workspace_leaves_the_final_flush_incomplete() {
    type Setup = fn(&Path, &Path);
    let cases: [(&str, Setup); 3] = [
        ("separate git dir", |root, outside| {
            let child = root.join("child");
            fs::create_dir_all(&child).unwrap();
            git(
                &child,
                &[
                    "init",
                    "-q",
                    "-b",
                    "main",
                    "--separate-git-dir",
                    outside.join("child.git").to_str().unwrap(),
                ],
            );
        }),
        (
            "linked worktree of an outside repository",
            |root, outside| {
                let other = outside.join("other");
                init(&other);
                fs::write(other.join("o"), b"o\n").unwrap();
                git(&other, &["add", "o"]);
                git(&other, &["commit", "-qm", "o"]);
                git(
                    &other,
                    &[
                        "worktree",
                        "add",
                        "-qb",
                        "w",
                        root.join("child").to_str().unwrap(),
                    ],
                );
            },
        ),
        ("alternates outside", |root, outside| {
            let lender = outside.join("lender");
            init(&lender);
            let child = root.join("child");
            init(&child);
            fs::create_dir_all(child.join(".git/objects/info")).unwrap();
            fs::write(
                child.join(".git/objects/info/alternates"),
                format!("{}\n", lender.join(".git/objects").display()),
            )
            .unwrap();
        }),
    ];
    for (name, setup) in cases {
        let fx = Fixture::new();
        let outside = fx.tmp.path().join("outside");
        fs::create_dir_all(&outside).unwrap();
        setup(&fx.root, &outside);
        let (reason, error) = fx.incomplete_flush(fx.config());
        println!("{name}: {reason}: {error}");
        assert_eq!(reason, "snapshot-failed", "{name}: {error}");
        assert!(error.contains("child"), "{name}: {error}");
        assert!(error.contains("outside the workspace"), "{name}: {error}");
        // An automatic capture ships all the same (crash protection).
        let auto = Fixture::new();
        let outside = auto.tmp.path().join("outside");
        fs::create_dir_all(&outside).unwrap();
        setup(&auto.root, &outside);
        auto.automatic(auto.config());
        assert!(auto.registrar.head().is_some(), "{name}");
    }
}

// ---------------------------------------------------------------------------------------------
// Review 9 #3, carried: times outside signed 64-bit nanoseconds.
// ---------------------------------------------------------------------------------------------

/// 10,000,000,000 seconds after the epoch (the year 2286) plus 123456789 ns, and as far
/// before it (the year 1653): times a filesystem holds and signed 64-bit nanoseconds (1677 to
/// 2262) do not.
fn out_of_range() -> [(SystemTime, (i64, i64)); 2] {
    let d = Duration::new(10_000_000_000, 123_456_789);
    [
        (UNIX_EPOCH + d, (10_000_000_000, 123_456_789)),
        // 1653: -10000000000 s + 0.123456789 s after the epoch.
        (UNIX_EPOCH - d, (-10_000_000_001, 876_543_211)),
    ]
}

/// Whether the filesystem under `dir` stores `at` exactly. Some (ext4 with 128-byte inodes,
/// as on CI runners) clamp times to 32-bit seconds, so a time before 1901 cannot be set at all.
fn filesystem_holds(dir: &Path, at: SystemTime, expected: (i64, i64)) -> bool {
    let probe = dir.join(".time-probe");
    fs::write(&probe, b"").unwrap();
    set_time(&probe, at);
    let held = times_of(&probe) == expected;
    fs::remove_file(&probe).unwrap();
    held
}

fn set_time(path: &Path, at: SystemTime) {
    fs::File::options()
        .read(true)
        .open(path)
        .unwrap()
        .set_times(fs::FileTimes::new().set_modified(at))
        .unwrap();
}

fn times_of(path: &Path) -> (i64, i64) {
    let meta = fs::symlink_metadata(path).unwrap();
    (meta.mtime(), meta.mtime_nsec())
}

/// Every class: an untracked file (the workspace class), a tracked one (the worktree
/// metadata), an untracked directory, a bulk file; each at a time after 2262 and before 1677.
fn out_of_range_paths(root: &Path) -> Vec<PathBuf> {
    let ignored = root.join("ignored/future.txt");
    fs::create_dir_all(ignored.parent().unwrap()).unwrap();
    fs::write(&ignored, b"future dated user work\n").unwrap();
    let dir = root.join("ignored/dir");
    fs::create_dir_all(&dir).unwrap();
    let bulk = root.join("node_modules/pkg/index.js");
    fs::create_dir_all(bulk.parent().unwrap()).unwrap();
    fs::write(&bulk, b"module.exports = 1;\n").unwrap();
    vec![ignored, root.join("a"), dir, bulk]
}

/// An automatic capture recorded the time saturated (`9223372036.854775807`), and a crash
/// restore wrote that false time. It records the time exactly and the restore writes it back,
/// in every class, after 2262 and before 1677.
#[test]
fn an_automatic_capture_restores_a_time_outside_2262_exactly() {
    for (at, expected) in out_of_range() {
        let fx = Fixture::new();
        if !filesystem_holds(&fx.root, at, expected) {
            eprintln!("skipped {expected:?}: this filesystem cannot store that time");
            continue;
        }
        let paths = out_of_range_paths(&fx.root);
        for p in &paths {
            set_time(p, at);
            assert_eq!(times_of(p), expected);
        }
        fx.automatic(fx.config());
        let out = fx.restore("restored");
        for p in &paths {
            let rel = p.strip_prefix(&fx.root).unwrap();
            assert_eq!(times_of(&out.join(rel)), expected, "{}", rel.display());
        }
    }
}

/// A store that reads `wide_times`: a final flush over such times is complete and restores
/// them exactly.
#[test]
fn a_final_flush_records_a_time_outside_2262_exactly() {
    let (at, expected) = out_of_range()[0];
    let fx = Fixture::new();
    let paths = out_of_range_paths(&fx.root);
    for p in &paths {
        set_time(p, at);
    }
    fx.final_flush(fx.config());
    let out = fx.restore("restored");
    for p in &paths {
        let rel = p.strip_prefix(&fx.root).unwrap();
        assert_eq!(times_of(&out.join(rel)), expected, "{}", rel.display());
    }
}
