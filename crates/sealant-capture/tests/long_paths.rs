//! Paths longer than `PATH_MAX`, captured and restored byte for byte.
//!
//! Docker end to end, round 3: an untracked file 4,186 bytes deep (17 directories of 243-byte
//! names) made one `lstat` fail with `ENAMETOOLONG`, which failed the worktree metadata overlay,
//! which failed every snap for the rest of the session — the head stuck, a README edit and a
//! new tree lost, and nothing said so. A path of any length is now captured in the class that
//! owns it (a directory or file git cannot reach goes to the workspace class; an ignored one
//! and a bulk one stay where they were), and restored exactly: bytes, modes, mtimes, a symlink
//! and a hardlink at depth, the empty directory, the names near `NAME_MAX`.
//!
//! The helpers here reach deep paths through `/proc/self/fd/<dir>/<name>`: one directory
//! descriptor at a time, never a path `std::fs` refuses.

use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::os::fd::{AsRawFd, OwnedFd};
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::Arc;
use std::time::Duration;

use nix::fcntl::{OFlag, openat};
use nix::sys::stat::{Mode, UtimensatFlags, utimensat};
use nix::sys::time::TimeSpec;
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
    assert!(
        out.status.success(),
        "git {args:?}: {}",
        String::from_utf8_lossy(&out.stderr)
    );
}

fn proc(fd: &OwnedFd) -> PathBuf {
    PathBuf::from(format!("/proc/self/fd/{}", fd.as_raw_fd()))
}

fn open_dir(path: &Path) -> OwnedFd {
    nix::fcntl::open(
        path,
        OFlag::O_RDONLY | OFlag::O_DIRECTORY | OFlag::O_CLOEXEC,
        Mode::empty(),
    )
    .unwrap()
}

fn child(dir: &OwnedFd, name: &str) -> OwnedFd {
    openat(
        dir,
        name,
        OFlag::O_RDONLY | OFlag::O_DIRECTORY | OFlag::O_NOFOLLOW | OFlag::O_CLOEXEC,
        Mode::empty(),
    )
    .unwrap()
}

fn set_mtime(path: &Path, ns: i64) {
    let mtime = TimeSpec::new(ns / 1_000_000_000, ns % 1_000_000_000);
    utimensat(
        nix::fcntl::AT_FDCWD,
        path,
        &TimeSpec::UTIME_OMIT,
        &mtime,
        UtimensatFlags::NoFollowSymlink,
    )
    .unwrap();
}

const T: i64 = 1_700_000_000_000_000_000;

/// `levels` directories of 243-byte names under `base/top`, created; returns the deepest one
/// opened, and the directory at `mark` (0-based) opened too.
fn chain(base: &Path, top: &str, levels: usize, mark: usize) -> (OwnedFd, OwnedFd) {
    let mut dir = open_dir(base);
    fs::create_dir_all(proc(&dir).join(top)).unwrap();
    dir = child(&dir, top);
    let mut marked = None;
    for i in 0..levels {
        let name = format!("d{i:02}{}", "x".repeat(240));
        fs::create_dir(proc(&dir).join(&name)).unwrap();
        dir = child(&dir, &name);
        if i == mark {
            marked = Some(child(&dir, "."));
        }
    }
    (dir, marked.unwrap())
}

/// One path as compared between two trees.
#[derive(Debug, PartialEq, Eq)]
struct Entry {
    kind: &'static str,
    mode: u32,
    mtime: i64,
    bytes: Vec<u8>,
    link: Option<PathBuf>,
}

/// Every path under `root` (minus `.git` and `.sealantd`), whatever its length, and the
/// hardlink groups among its files.
fn snapshot(root: &Path) -> (BTreeMap<String, Entry>, BTreeSet<Vec<String>>) {
    fn walk(
        dir: &OwnedFd,
        rel: &str,
        out: &mut BTreeMap<String, Entry>,
        inodes: &mut BTreeMap<(u64, u64), Vec<String>>,
    ) {
        let mut names: Vec<String> = fs::read_dir(proc(dir))
            .unwrap()
            .map(|e| e.unwrap().file_name().into_string().unwrap())
            .collect();
        names.sort();
        for name in names {
            if rel.is_empty() && (name == ".git" || name == ".sealantd") {
                continue;
            }
            let path = proc(dir).join(&name);
            let v = if rel.is_empty() {
                name.clone()
            } else {
                format!("{rel}/{name}")
            };
            let meta = fs::symlink_metadata(&path).unwrap();
            let mtime = meta.mtime() * 1_000_000_000 + meta.mtime_nsec();
            let entry = if meta.is_symlink() {
                Entry {
                    kind: "symlink",
                    mode: 0,
                    mtime,
                    bytes: Vec::new(),
                    link: Some(fs::read_link(&path).unwrap()),
                }
            } else if meta.is_dir() {
                walk(&child(dir, &name), &v, out, inodes);
                Entry {
                    kind: "dir",
                    mode: meta.mode() & 0o7777,
                    mtime,
                    bytes: Vec::new(),
                    link: None,
                }
            } else {
                if meta.nlink() > 1 {
                    inodes
                        .entry((meta.dev(), meta.ino()))
                        .or_default()
                        .push(v.clone());
                }
                Entry {
                    kind: "file",
                    mode: meta.mode() & 0o7777,
                    mtime,
                    bytes: fs::read(&path).unwrap(),
                    link: None,
                }
            };
            out.insert(v, entry);
        }
    }
    let mut out = BTreeMap::new();
    let mut inodes = BTreeMap::new();
    let dir = open_dir(root);
    walk(&dir, "", &mut out, &mut inodes);
    let meta = fs::metadata(root).unwrap();
    out.insert(
        String::new(),
        Entry {
            kind: "dir",
            mode: meta.mode() & 0o7777,
            mtime: meta.mtime() * 1_000_000_000 + meta.mtime_nsec(),
            bytes: Vec::new(),
            link: None,
        },
    );
    let groups = inodes.into_values().filter(|g| g.len() > 1).collect();
    (out, groups)
}

fn assert_same(source: &Path, restored: &Path) {
    let (a, ga) = snapshot(source);
    let (b, gb) = snapshot(restored);
    let short = |k: &str| {
        if k.len() > 120 {
            format!("{}…{} ({} bytes)", &k[..40], &k[k.len() - 60..], k.len())
        } else {
            k.to_owned()
        }
    };
    let mut diffs = Vec::new();
    for k in a.keys().chain(b.keys()).collect::<BTreeSet<_>>() {
        match (a.get(k), b.get(k)) {
            (Some(x), Some(y)) if x == y => {}
            (x, y) => diffs.push(format!(
                "{}: source {:?} restored {:?}",
                short(k),
                x.map(|e| (e.kind, e.mode, e.mtime, e.bytes.len(), &e.link)),
                y.map(|e| (e.kind, e.mode, e.mtime, e.bytes.len(), &e.link))
            )),
        }
    }
    if ga != gb {
        diffs.push(format!(
            "hardlink groups differ: source {} restored {}",
            ga.len(),
            gb.len()
        ));
    }
    assert!(diffs.is_empty(), "trees differ:\n{}", diffs.join("\n"));
    assert!(
        a.keys().any(|k| k.len() > 4200),
        "the tree holds paths longer than PATH_MAX"
    );
}

struct Fixture {
    _tmp: tempfile::TempDir,
    base: PathBuf,
    root: PathBuf,
}

/// A repository with work product far below `PATH_MAX`: untracked (a directory git cannot open,
/// and a file in one it can whose own path is too long), ignored, and in a bulk directory.
fn fixture() -> Fixture {
    fixture_with(true)
}

/// [`fixture`]; without `long_file`, only a directory git cannot open (the e2e's tree).
fn fixture_with(long_file: bool) -> Fixture {
    let tmp = tempfile::tempdir().unwrap();
    let base = tmp.path().to_path_buf();
    let root = base.join("ws");
    fs::create_dir_all(&root).unwrap();
    git(&root, &["init", "-q", "-b", "main"]);
    git(&root, &["config", "user.email", "t@t"]);
    git(&root, &["config", "user.name", "t"]);
    fs::write(root.join(".gitignore"), "logs/\nnode_modules/\n").unwrap();
    fs::write(root.join("README.md"), "readme\n").unwrap();
    git(&root, &["add", "-A"]);
    git(&root, &["commit", "-q", "-m", "one"]);

    // Untracked: 18 levels (the deepest directory is 4,400 bytes below the root; the 16th,
    // 3,900 bytes, is one git can still open).
    let (deep, sixteenth) = chain(&root, "deep", 18, 15);
    let d = proc(&deep);
    fs::write(d.join("work.txt"), "deep work product\n").unwrap();
    fs::set_permissions(d.join("work.txt"), fs::Permissions::from_mode(0o640)).unwrap();
    fs::hard_link(d.join("work.txt"), d.join("twin.txt")).unwrap();
    std::os::unix::fs::symlink("work.txt", d.join("link")).unwrap();
    fs::create_dir(d.join("empty")).unwrap();
    let near_name_max = format!("n{}", "y".repeat(250));
    fs::write(d.join(&near_name_max), "a name near NAME_MAX\n").unwrap();
    set_mtime(&d.join("work.txt"), T + 1);
    set_mtime(&d.join("link"), T + 2);
    set_mtime(&d.join("empty"), T + 3);
    // In a directory git can open, a file whose own path is too long for it, and one that
    // is not.
    let s = proc(&sixteenth);
    if long_file {
        fs::write(
            s.join(format!("f{}", "z".repeat(220))),
            "too long for git\n",
        )
        .unwrap();
    }
    fs::write(s.join("short.txt"), "git reaches this one\n").unwrap();

    // Ignored (the workspace class) and bulk, as deep.
    let (logs, _) = chain(&root, "logs", 18, 0);
    fs::write(proc(&logs).join("run.log"), "an ignored deep log\n").unwrap();
    let (modules, _) = chain(&root, "node_modules", 18, 0);
    fs::write(proc(&modules).join("index.js"), "module.exports = 1;\n").unwrap();
    drop((deep, sixteenth, logs, modules));

    Fixture {
        _tmp: tmp,
        base,
        root,
    }
}

fn engine(fx: &Fixture) -> CaptureEngine {
    CaptureEngine::open(CaptureConfig::new("wt", 1, &fx.root), None).unwrap()
}

fn snap(engine: &mut CaptureEngine, kind: CaptureKind, class: Class) {
    engine
        .snap(SnapRequest {
            kind,
            class,
            seq: 1,
        })
        .unwrap_or_else(|e| panic!("{kind:?} {class:?} snap failed: {e}"));
}

/// The e2e's loss, in one test: with a path longer than `PATH_MAX` on disk, an automatic snap
/// still captures the README edit made beside it (it used to fail, and every snap after it),
/// and a final flush's head restores every class byte for byte, the deep paths included.
#[test]
fn paths_longer_than_path_max_are_captured_and_restored_exactly() {
    let fx = fixture();
    let mut engine = engine(&fx);
    fs::write(
        fx.root.join("README.md"),
        "readme, edited beside the deep tree\n",
    )
    .unwrap();
    snap(&mut engine, CaptureKind::Auto, Class::Small);

    snap(&mut engine, CaptureKind::Final, Class::Small);
    snap(&mut engine, CaptureKind::Final, Class::Bulk);
    let store: Arc<dyn BlobSink> = Arc::new(LocalDir::new(&fx.base.join("store")).unwrap());
    let registrar = Arc::new(InMemoryRegistrar::new("wt", 1, None));
    let dyn_registrar: Arc<dyn Registrar> = registrar.clone();
    engine
        .shipper(store.clone(), dyn_registrar)
        .flush(Duration::from_secs(60))
        .unwrap();
    let head = registrar.head().unwrap();
    assert!(head.manifest.sections.bulk.section().is_some());

    let fresh = fx.base.join("fresh");
    Materializer::new(store.as_ref(), MaterializeTargets::new(&fresh, None))
        .materialize(&head.manifest, MaterializeClass::All)
        .unwrap();
    assert_same(&fx.root, &fresh);

    // And again as a delta over the restored disk: nothing to do, still the same.
    Materializer::new(store.as_ref(), MaterializeTargets::new(&fresh, None))
        .materialize(&head.manifest, MaterializeClass::All)
        .unwrap();
    assert_same(&fx.root, &fresh);
}

/// Exactly the e2e's tree: a directory git cannot open (it warns and skips it), nothing else
/// too long. The metadata overlay's walk met it and failed every snap; an automatic snap now
/// captures the README edit beside it and the deep file, and the next one sees a new change.
#[test]
fn a_directory_git_cannot_open_does_not_stop_automatic_snaps() {
    let fx = fixture_with(false);
    let mut engine = engine(&fx);
    fs::write(fx.root.join("README.md"), "first edit\n").unwrap();
    snap(&mut engine, CaptureKind::Auto, Class::Small);
    fs::write(fx.root.join("README.md"), "second edit\n").unwrap();
    fs::create_dir_all(fx.root.join("new-tree/src")).unwrap();
    fs::write(fx.root.join("new-tree/src/a.rs"), "fn a() {}\n").unwrap();
    snap(&mut engine, CaptureKind::Auto, Class::Small);

    let store: Arc<dyn BlobSink> = Arc::new(LocalDir::new(&fx.base.join("store")).unwrap());
    let registrar = Arc::new(InMemoryRegistrar::new("wt", 1, None));
    let dyn_registrar: Arc<dyn Registrar> = registrar.clone();
    engine
        .shipper(store.clone(), dyn_registrar)
        .flush(Duration::from_secs(60))
        .unwrap();
    let fresh = fx.base.join("fresh");
    Materializer::new(store.as_ref(), MaterializeTargets::new(&fresh, None))
        .materialize(&registrar.head().unwrap().manifest, MaterializeClass::All)
        .unwrap();
    assert_eq!(
        fs::read_to_string(fresh.join("README.md")).unwrap(),
        "second edit\n"
    );
    assert_eq!(
        fs::read_to_string(fresh.join("new-tree/src/a.rs")).unwrap(),
        "fn a() {}\n"
    );
    let (restored, _) = snapshot(&fresh);
    let deep_work = restored
        .iter()
        .find(|(k, _)| k.ends_with("/work.txt"))
        .map(|(_, e)| e.bytes.clone());
    assert_eq!(deep_work.as_deref(), Some(&b"deep work product\n"[..]));
}
