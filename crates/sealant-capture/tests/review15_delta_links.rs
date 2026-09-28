//! A delta restore leaves the inodes the capture holds, and no others (review 2026-09-28,
//! fifteenth pass, #2).
//!
//! A delta restore reuses a file whose bytes it already has: the git class writes only the
//! paths whose blobs changed, the chunked classes skip a file their index still matches. Such a
//! file keeps its inode, with every name that inode had. When the capture holds those names
//! apart — a tracked file its own copy replaced, two tracked aliases split later — the restore
//! gives each group of names the capture joins an inode of its own before it links anything,
//! so a later edit through one name reaches only the names the capture joined, and setting one
//! name's mtime moves no other's. A sealed final capture restored whole also checks, once every
//! link is made, that no inode holds names of two groups (`LinkUnfulfilled` otherwise).
//!
//! pnpm's layout is made by hand below (a tracked local package's file hardlinked into
//! `node_modules/.pnpm` and into a store outside the worktree, as `pnpm install
//! --package-import-method=hardlink` makes it); the real installation runs as well when `node`
//! and `pnpm` are on `PATH`.

use std::collections::BTreeMap;
use std::fs;
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::{MetadataExt, symlink};
use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use std::sync::Arc;
use std::time::Duration;

use sealant_capture::{
    CadenceRunner, CaptureConfig, CaptureEngine, CaptureKind, Class, InMemoryRegistrar, LocalDir,
    MaterializeClass, MaterializeReport, MaterializeTargets, Materializer, SnapRequest,
};

const EXECUTOR: &str = "exec-r15";

/// Where pnpm puts the installed copy of the local package `review-local-util`.
const INSTALLED: &str =
    "node_modules/.pnpm/review-local-util@file+packages+util/node_modules/review-local-util";

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
    String::from_utf8(out.stdout).unwrap().trim().to_owned()
}

struct Fixture {
    tmp: tempfile::TempDir,
    root: PathBuf,
    store: Arc<LocalDir>,
    registrar: Arc<InMemoryRegistrar>,
}

impl Fixture {
    /// A repository with one commit on `main`: `a` holding `base\n`; `.gitignore` ignoring
    /// `node_modules/` (the bulk class).
    fn new() -> Self {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path().join("ws");
        fs::create_dir_all(&root).unwrap();
        git(&root, &["init", "-q", "-b", "main"]);
        git(&root, &["config", "user.email", "t@t"]);
        git(&root, &["config", "user.name", "t"]);
        fs::write(root.join("a"), b"base\n").unwrap();
        fs::write(root.join(".gitignore"), b"node_modules/\n").unwrap();
        git(&root, &["add", "-A"]);
        git(&root, &["commit", "-qm", "base"]);
        Self {
            store: Arc::new(LocalDir::new(&tmp.path().join("store")).unwrap()),
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

    /// Snap the disk as it is now and seal it: the registrar's new head.
    fn seal(&self, runner: &CadenceRunner) -> sealant_capture::registrar::HeadInfo {
        runner.snap(CaptureKind::Turn).unwrap();
        let result = runner.flush_final(None);
        assert!(result.complete(), "{result:?}");
        let head = self.registrar.head().unwrap();
        assert!(head.manifest.final_seal.is_some(), "the chain is sealed");
        head
    }

    fn materializer(&self, out: &Path) -> Materializer<'_> {
        Materializer::new(self.store.as_ref(), MaterializeTargets::new(out, None))
    }
}

/// Every path under `root` (`.git` and `.sealantd` left out): mode, mtime and contents (a
/// symlink's target).
fn snapshot(root: &Path) -> BTreeMap<PathBuf, (u32, i64, i64, Vec<u8>)> {
    fn visit(root: &Path, rel: &Path, out: &mut BTreeMap<PathBuf, (u32, i64, i64, Vec<u8>)>) {
        let abs = root.join(rel);
        let m = fs::symlink_metadata(&abs).unwrap();
        let content = if m.is_file() {
            fs::read(&abs).unwrap()
        } else if m.file_type().is_symlink() {
            fs::read_link(&abs).unwrap().as_os_str().as_bytes().to_vec()
        } else {
            Vec::new()
        };
        out.insert(
            rel.to_path_buf(),
            (m.mode(), m.mtime(), m.mtime_nsec(), content),
        );
        if m.is_dir() {
            for e in fs::read_dir(abs).unwrap() {
                let e = e.unwrap();
                if rel.as_os_str().is_empty()
                    && (e.file_name() == ".git" || e.file_name() == ".sealantd")
                {
                    continue;
                }
                visit(root, &rel.join(e.file_name()), out);
            }
        }
    }
    let mut out = BTreeMap::new();
    visit(root, Path::new(""), &mut out);
    out
}

/// Every file under `root` (`.git` and `.sealantd` left out), grouped by inode: the groups of
/// two or more names, sorted.
fn inode_groups(root: &Path) -> Vec<Vec<PathBuf>> {
    let mut map = BTreeMap::<(u64, u64), Vec<PathBuf>>::new();
    for path in snapshot(root).keys() {
        let m = fs::symlink_metadata(root.join(path)).unwrap();
        if m.is_file() {
            map.entry((m.dev(), m.ino()))
                .or_default()
                .push(path.clone());
        }
    }
    let mut groups: Vec<_> = map.into_values().filter(|g| g.len() > 1).collect();
    groups.sort();
    groups
}

fn ino(path: &Path) -> u64 {
    fs::metadata(path).unwrap().ino()
}

fn mtime(path: &Path) -> (i64, i64) {
    let m = fs::symlink_metadata(path).unwrap();
    (m.mtime(), m.mtime_nsec())
}

/// Replace `path` with an independent copy of itself: the same bytes on a new inode, its
/// mtime `later` past the old one.
fn replace_with_copy(path: &Path, later: Duration) {
    let old = fs::metadata(path).unwrap();
    let tmp = path.with_extension("replacement");
    fs::copy(path, &tmp).unwrap();
    fs::File::open(&tmp)
        .unwrap()
        .set_times(fs::FileTimes::new().set_modified(old.modified().unwrap() + later))
        .unwrap();
    fs::rename(&tmp, path).unwrap();
    assert_eq!(fs::metadata(path).unwrap().nlink(), 1);
}

/// The committed local package `packages/util` and a project that depends on it.
fn commit_local_package(fx: &Fixture) {
    fs::create_dir_all(fx.root.join("packages/util")).unwrap();
    fs::write(
        fx.root.join("packages/util/package.json"),
        br#"{"name":"review-local-util","version":"1.0.0","main":"index.js"}"#,
    )
    .unwrap();
    fs::write(
        fx.root.join("packages/util/index.js"),
        b"module.exports='original';\n",
    )
    .unwrap();
    fs::write(
        fx.root.join("package.json"),
        br#"{"name":"review-project","private":true,"version":"1.0.0","dependencies":{"review-local-util":"file:./packages/util"}}"#,
    )
    .unwrap();
    git(&fx.root, &["add", "-A"]);
    git(&fx.root, &["commit", "-qm", "local package"]);
}

/// What `pnpm install --package-import-method=hardlink` makes of the local package, by hand:
/// each of its files hardlinked into its installed copy and into a store outside the worktree,
/// and `node_modules/review-local-util` a symlink to the installed copy.
fn install_by_hand(root: &Path, store: &Path) {
    let installed = root.join(INSTALLED);
    fs::create_dir_all(&installed).unwrap();
    fs::create_dir_all(store).unwrap();
    for file in ["package.json", "index.js"] {
        let tracked = root.join("packages/util").join(file);
        fs::hard_link(&tracked, installed.join(file)).unwrap();
        fs::hard_link(&tracked, store.join(file)).unwrap();
    }
    symlink(
        ".pnpm/review-local-util@file+packages+util/node_modules/review-local-util",
        root.join("node_modules/review-local-util"),
    )
    .unwrap();
}

/// `node` and `pnpm` on `PATH`, for the real installation.
fn pnpm_available() -> bool {
    ["node", "pnpm"].iter().all(|tool| {
        Command::new(tool)
            .arg("--version")
            .output()
            .is_ok_and(|o| o.status.success())
    })
}

fn run_at(root: &Path, home: &Path, program: &str, args: &[&str]) -> Output {
    let output = Command::new(program)
        .current_dir(root)
        .args(args)
        .env("HOME", home)
        .env("npm_config_update_notifier", "false")
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{program} {args:?}: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    output
}

fn install_with_pnpm(root: &Path, home: &Path, store: &Path) {
    run_at(
        root,
        home,
        "pnpm",
        &[
            "install",
            "--store-dir",
            store.to_str().unwrap(),
            "--package-import-method=hardlink",
            "--ignore-scripts",
        ],
    );
}

/// The standby path of `capture.replan`: the base materialized on the standby, the same
/// install run on the source and the standby, the source's installed copy split from its
/// tracked source (its mtime `later` past the old one) and sealed, the standby engine's setup
/// indexed, then the saved head applied over it as a delta. Returns the standby, the source's
/// hardlink groups and the report.
fn standby_replan(
    fx: &Fixture,
    later: Duration,
    install: &dyn Fn(&Path, &Path),
) -> (PathBuf, Vec<Vec<PathBuf>>, MaterializeReport) {
    commit_local_package(fx);
    let runner = fx.runner();
    let base = fx.seal(&runner);
    let standby = fx.tmp.path().join("standby");
    fx.materializer(&standby)
        .materialize(&base.manifest, MaterializeClass::All)
        .unwrap();
    install(&fx.root, &fx.tmp.path().join("source-store"));
    install(&standby, &fx.tmp.path().join("standby-store"));
    let tracked = fx.root.join("packages/util/index.js");
    assert!(
        fs::metadata(&tracked).unwrap().nlink() > 1,
        "the install linked the tracked file into node_modules"
    );
    assert_eq!(
        ino(&standby.join("packages/util/index.js")),
        ino(&standby.join(INSTALLED).join("index.js")),
        "the standby's setup made the same link"
    );
    replace_with_copy(&tracked, later);
    let head = fx.seal(&runner);
    let expected = inode_groups(&fx.root);
    assert!(
        !expected
            .iter()
            .flatten()
            .any(|p| p == Path::new("packages/util/index.js")),
        "the source holds the tracked file apart: {expected:?}"
    );
    let mut config = CaptureConfig::new("standby", 7, &standby);
    config.executor = Some("standby-launch".to_owned());
    let mut engine = CaptureEngine::open(config, Some(base.manifest.encode())).unwrap();
    for (class, seq) in [(Class::Small, 1), (Class::Bulk, 2)] {
        engine
            .snap(SnapRequest {
                kind: CaptureKind::Auto,
                class,
                seq,
            })
            .unwrap();
    }
    let report = engine
        .materialize_delta(fx.store.as_ref(), &head.manifest, MaterializeClass::All)
        .unwrap();
    (standby, expected, report)
}

/// After a standby replan: the standby's inodes, modes, mtimes and bytes are the source's; an
/// edit to the tracked source reaches no installed copy; and the delta reused what it could.
fn assert_replan_is_the_source(
    fx: &Fixture,
    standby: &Path,
    expected: &[Vec<PathBuf>],
    report: &MaterializeReport,
) {
    assert_eq!(
        inode_groups(standby),
        expected,
        "the replan keeps no link the capture does not hold"
    );
    assert_eq!(
        snapshot(standby),
        snapshot(&fx.root),
        "every path as captured"
    );
    assert!(
        report.files_skipped > 0,
        "the delta reused files: {report:?}"
    );
    let installed = standby.join(INSTALLED).join("index.js");
    let before = fs::read(&installed).unwrap();
    fs::write(
        standby.join("packages/util/index.js"),
        b"module.exports='user edit source only';\n",
    )
    .unwrap();
    assert_eq!(
        fs::read(&installed).unwrap(),
        before,
        "an edit to the tracked source leaves the installed copy as it was"
    );
}

/// Two tracked aliases (one inode), materialized, then split on the source with their bytes
/// unchanged and sealed: the delta restore changes no git path, and still gives the two names
/// two inodes (the reviewer's `audit_delta_restore_splits_a_previously_linked_tracked_group`).
#[test]
fn a_delta_restore_splits_a_tracked_group_the_capture_split() {
    let fx = Fixture::new();
    fs::hard_link(fx.root.join("a"), fx.root.join("b")).unwrap();
    git(&fx.root, &["add", "b"]);
    git(&fx.root, &["commit", "-qm", "two tracked aliases"]);
    let runner = fx.runner();
    let first = fx.seal(&runner);
    let out = fx.tmp.path().join("delta-target");
    let m = fx.materializer(&out);
    m.materialize(&first.manifest, MaterializeClass::All)
        .unwrap();
    assert_eq!(ino(&out.join("a")), ino(&out.join("b")));
    replace_with_copy(&fx.root.join("b"), Duration::ZERO);
    assert_ne!(ino(&fx.root.join("a")), ino(&fx.root.join("b")));
    let second = fx.seal(&runner);
    assert_ne!(first.capture_id, second.capture_id);
    let report = m
        .materialize(&second.manifest, MaterializeClass::All)
        .unwrap();
    assert_eq!(report.git_paths_changed, Some(0), "{report:?}");
    assert_ne!(
        ino(&out.join("a")),
        ino(&out.join("b")),
        "a group the new capture split restores as separate inodes"
    );
    assert_eq!(snapshot(&out), snapshot(&fx.root));
    fs::write(out.join("a"), b"edit only a\n").unwrap();
    assert_eq!(fs::read(out.join("b")).unwrap(), b"base\n");
    // A third materialize of the same head over the restored disk writes nothing.
    let again = m
        .materialize(&second.manifest, MaterializeClass::All)
        .unwrap();
    assert_eq!(again.files, 0, "{again:?}");
}

/// A standby's setup (pnpm, by hand) linked the tracked source into its installed copy; the
/// saved head holds them apart, with the replacement's mtime the old one: the replan gives
/// them separate inodes (the reviewer's
/// `audit_pnpm_standby_setup_preserves_an_unwanted_source_bulk_hardlink`).
#[test]
fn a_standby_replan_splits_a_tracked_file_from_its_installed_copy() {
    let fx = Fixture::new();
    let (standby, expected, report) = standby_replan(&fx, Duration::ZERO, &install_by_hand);
    assert_replan_is_the_source(&fx, &standby, &expected, &report);
}

/// The same with the independent copy's mtime a second later: setting the tracked file's mtime
/// moves the installed copy's no longer (the reviewer's
/// `audit_pnpm_standby_extra_link_changes_peer_mtime_immediately`).
#[test]
fn a_standby_replan_keeps_the_installed_copy_mtime() {
    let fx = Fixture::new();
    let (standby, expected, report) = standby_replan(&fx, Duration::from_secs(1), &install_by_hand);
    let peer = Path::new(INSTALLED).join("index.js");
    assert_eq!(
        mtime(&standby.join(&peer)),
        mtime(&fx.root.join(&peer)),
        "the replan keeps the installed copy's captured mtime"
    );
    assert_ne!(
        mtime(&standby.join("packages/util/index.js")),
        mtime(&standby.join(&peer))
    );
    assert_replan_is_the_source(&fx, &standby, &expected, &report);
}

/// Both standby cases with a real `pnpm install`, when `node` and `pnpm` are on `PATH`; passed
/// over (saying so) without them — the hand-made layout above is the same topology.
#[test]
fn a_standby_replan_over_a_real_pnpm_install_keeps_only_captured_links() {
    if !pnpm_available() {
        eprintln!("node and pnpm are not on PATH: the real pnpm installation is passed over");
        return;
    }
    for later in [Duration::ZERO, Duration::from_secs(1)] {
        let fx = Fixture::new();
        let home = fx.tmp.path().join("home");
        fs::create_dir_all(&home).unwrap();
        let install = |root: &Path, store: &Path| install_with_pnpm(root, &home, store);
        let (standby, expected, report) = standby_replan(&fx, later, &install);
        let peer = Path::new(INSTALLED).join("index.js");
        assert_eq!(mtime(&standby.join(&peer)), mtime(&fx.root.join(&peer)));
        assert_eq!(inode_groups(&standby), expected);
        assert!(report.files_skipped > 0, "{report:?}");
        fs::write(
            standby.join("packages/util/index.js"),
            b"module.exports='user edit source only';\n",
        )
        .unwrap();
        let read = "console.log(require('review-local-util'))";
        let out = run_at(&standby, &home, "node", &["-e", read]);
        assert_eq!(out.stdout, b"original\n", "the installed copy is its own");
    }
}

/// A replan whose saved head still holds the standby's link keeps it and rewrites nothing: the
/// split touches only inodes whose names the capture holds apart.
#[test]
fn a_standby_replan_keeps_a_link_the_capture_holds() {
    let fx = Fixture::new();
    commit_local_package(&fx);
    let runner = fx.runner();
    let base = fx.seal(&runner);
    let standby = fx.tmp.path().join("standby");
    fx.materializer(&standby)
        .materialize(&base.manifest, MaterializeClass::All)
        .unwrap();
    install_by_hand(&fx.root, &fx.tmp.path().join("source-store"));
    install_by_hand(&standby, &fx.tmp.path().join("standby-store"));
    let head = fx.seal(&runner);
    let mut config = CaptureConfig::new("standby", 7, &standby);
    config.executor = Some("standby-launch".to_owned());
    let mut engine = CaptureEngine::open(config, Some(base.manifest.encode())).unwrap();
    for (class, seq) in [(Class::Small, 1), (Class::Bulk, 2)] {
        engine
            .snap(SnapRequest {
                kind: CaptureKind::Auto,
                class,
                seq,
            })
            .unwrap();
    }
    let linked = ino(&standby.join("packages/util/index.js"));
    let report = engine
        .materialize_delta(fx.store.as_ref(), &head.manifest, MaterializeClass::All)
        .unwrap();
    assert_eq!(report.files, 0, "nothing rewritten: {report:?}");
    assert_eq!(inode_groups(&standby), inode_groups(&fx.root));
    assert_eq!(snapshot(&standby), snapshot(&fx.root));
    assert_eq!(ino(&standby.join("packages/util/index.js")), linked);
    assert_eq!(
        ino(&standby.join(INSTALLED).join("index.js")),
        linked,
        "the installed copy stays on the tracked file's inode"
    );
}

/// Control: a full cold checkout over a disk that already links two independent tracked files
/// breaks the link (no delta state: every tracked path is written).
#[test]
fn a_cold_restore_splits_links_the_disk_held_before() {
    let fx = Fixture::new();
    fs::write(fx.root.join("b"), b"base\n").unwrap();
    git(&fx.root, &["add", "b"]);
    git(&fx.root, &["commit", "-qm", "independent same-byte files"]);
    let runner = fx.runner();
    let head = fx.seal(&runner);
    let out = fx.tmp.path().join("cold-preexisting");
    fs::create_dir_all(&out).unwrap();
    git(&out, &["init", "-q"]);
    fs::write(out.join("a"), b"base\n").unwrap();
    fs::hard_link(out.join("a"), out.join("b")).unwrap();
    fx.materializer(&out)
        .materialize(&head.manifest, MaterializeClass::All)
        .unwrap();
    assert_ne!(ino(&out.join("a")), ino(&out.join("b")));
}

/// Control: a delta whose tracked blob changed writes the path again, which breaks its old
/// link.
#[test]
fn a_delta_restore_of_changed_tracked_bytes_breaks_the_old_link() {
    let fx = Fixture::new();
    fs::hard_link(fx.root.join("a"), fx.root.join("b")).unwrap();
    git(&fx.root, &["add", "b"]);
    git(&fx.root, &["commit", "-qm", "linked files"]);
    let runner = fx.runner();
    let first = fx.seal(&runner);
    let out = fx.tmp.path().join("delta-changed");
    let m = fx.materializer(&out);
    m.materialize(&first.manifest, MaterializeClass::All)
        .unwrap();
    fs::remove_file(fx.root.join("b")).unwrap();
    fs::write(fx.root.join("b"), b"new independent bytes\n").unwrap();
    let second = fx.seal(&runner);
    m.materialize(&second.manifest, MaterializeClass::All)
        .unwrap();
    assert_eq!(fs::read(out.join("a")).unwrap(), b"base\n");
    assert_eq!(fs::read(out.join("b")).unwrap(), b"new independent bytes\n");
    assert_ne!(ino(&out.join("a")), ino(&out.join("b")));
}
