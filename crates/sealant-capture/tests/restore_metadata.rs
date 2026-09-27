//! Filesystem-level round trips of what git trees do not carry: write a worktree, capture it,
//! materialize it fresh (and as a delta over a disk that drifted), and compare everything —
//! exact mode bits, mtimes to the nanosecond (files, directories, symlinks, the root), empty
//! directories, hardlink inode groups, symlink targets — and the complete ref set (loose and
//! packed refs, `HEAD`, the stash) against the manifest's.

use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::Arc;

use nix::sys::stat::{UtimensatFlags, utimensat};
use nix::sys::time::TimeSpec;
use sealant_capture::manifest::{WORKTREE_TREE_REF, WorktreeMeta};
use sealant_capture::materialize::MaterializeError;
use sealant_capture::pack::PackReader;
use sealant_capture::registrar::HeadInfo;
use sealant_capture::worktree_meta::MetaDocument;
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

/// Set `path`'s mtime (nanoseconds), never following a symlink.
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

fn chmod(path: &Path, mode: u32) {
    fs::set_permissions(path, fs::Permissions::from_mode(mode)).unwrap();
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

/// Every path under `root` — the root itself as `""`, directories included — minus `.git` and
/// the daemon directory, plus the hardlink groups (paths sharing an inode) among its files.
fn snapshot(root: &Path) -> (BTreeMap<String, Entry>, BTreeSet<Vec<String>>) {
    let mut out = BTreeMap::new();
    let mut inodes: BTreeMap<(u64, u64), Vec<String>> = BTreeMap::new();
    for e in walkdir::WalkDir::new(root)
        .follow_links(false)
        .sort_by_file_name()
        .into_iter()
        .filter_entry(|e| {
            e.depth() != 1 || (e.file_name() != ".git" && e.file_name() != ".sealantd")
        })
    {
        let e = e.unwrap();
        let rel = e
            .path()
            .strip_prefix(root)
            .unwrap()
            .to_string_lossy()
            .to_string();
        let meta = fs::symlink_metadata(e.path()).unwrap();
        let mtime = meta.mtime() * 1_000_000_000 + meta.mtime_nsec();
        let entry = if meta.is_symlink() {
            Entry {
                kind: "symlink",
                mode: 0,
                mtime,
                bytes: Vec::new(),
                link: Some(fs::read_link(e.path()).unwrap()),
            }
        } else if meta.is_dir() {
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
                    .push(rel.clone());
            }
            Entry {
                kind: "file",
                mode: meta.mode() & 0o7777,
                mtime,
                bytes: fs::read(e.path()).unwrap(),
                link: None,
            }
        };
        out.insert(rel, entry);
    }
    let groups = inodes.into_values().filter(|g| g.len() > 1).collect();
    (out, groups)
}

fn assert_same(source: &Path, restored: &Path) {
    let (a, ga) = snapshot(source);
    let (b, gb) = snapshot(restored);
    let mut diffs = Vec::new();
    for k in a.keys().chain(b.keys()).collect::<BTreeSet<_>>() {
        match (a.get(k), b.get(k)) {
            (Some(x), Some(y)) if x == y => {}
            (x, y) => diffs.push(format!("{k:?}: source {x:?} restored {y:?}")),
        }
    }
    if ga != gb {
        diffs.push(format!("hardlink groups: source {ga:?} restored {gb:?}"));
    }
    assert!(
        diffs.is_empty(),
        "{source:?} and {restored:?} differ:\n{}",
        diffs.join("\n")
    );
}

/// Refs as `git for-each-ref` lists them, `HEAD`, and the stash list.
fn refs(root: &Path) -> (String, String, String) {
    (
        git(
            root,
            &[
                "for-each-ref",
                "--format=%(refname) %(objectname) %(*objectname)",
            ],
        ),
        git(root, &["symbolic-ref", "HEAD"]),
        git(root, &["stash", "list", "--format=%gd %H"]),
    )
}

struct Fixture {
    _tmp: tempfile::TempDir,
    base: PathBuf,
    root: PathBuf,
}

const T: i64 = 1_600_000_000_000_000_000;

impl Fixture {
    /// A repository whose worktree carries every kind of metadata a git tree drops, and every
    /// kind of ref.
    fn build() -> Self {
        let tmp = tempfile::tempdir().unwrap();
        let base = tmp.path().to_path_buf();
        let root = base.join("ws");
        fs::create_dir_all(root.join("src")).unwrap();
        git(&root, &["init", "-q", "-b", "main"]);
        git(&root, &["config", "user.email", "t@t"]);
        git(&root, &["config", "user.name", "t"]);
        fs::write(root.join(".gitignore"), "ignored/\n*.log\n").unwrap();
        fs::write(root.join("secret.txt"), "secret\n").unwrap();
        fs::write(root.join("run.sh"), "#!/bin/sh\n").unwrap();
        fs::write(root.join("ro.txt"), "read only\n").unwrap();
        fs::write(root.join("src/lib.rs"), "pub fn f() {}\n").unwrap();
        fs::write(root.join("link.txt"), "linked twice\n").unwrap();
        fs::hard_link(root.join("link.txt"), root.join("src/twin.txt")).unwrap();
        std::os::unix::fs::symlink("secret.txt", root.join("to-secret")).unwrap();
        git(&root, &["add", "-A"]);
        git(&root, &["commit", "-q", "-m", "one"]);
        git(&root, &["tag", "-a", "v1", "-m", "v1"]);
        git(&root, &["branch", "packed-branch"]);
        git(&root, &["pack-refs", "--all"]);
        git(&root, &["branch", "loose-branch"]);
        // A stash entry, then the worktree back as committed.
        fs::write(root.join("secret.txt"), "stashed edit\n").unwrap();
        git(&root, &["stash", "push", "-q", "-m", "wip"]);
        // Untracked, not ignored: a file, a directory with a file, a dangling symlink, empty
        // directories (one holding only another empty one).
        fs::write(root.join("untracked.md"), "notes\n").unwrap();
        fs::create_dir_all(root.join("newdir")).unwrap();
        fs::write(root.join("newdir/new.txt"), "new\n").unwrap();
        std::os::unix::fs::symlink("nowhere", root.join("dangling")).unwrap();
        fs::create_dir_all(root.join("empty/deeper")).unwrap();
        fs::create_dir_all(root.join("hollow/inner")).unwrap();
        // Ignored: a file beside tracked ones, a directory with a symlink.
        fs::write(root.join("app.log"), "log\n").unwrap();
        fs::create_dir_all(root.join("ignored")).unwrap();
        fs::write(root.join("ignored/cache.bin"), "cache\n").unwrap();
        std::os::unix::fs::symlink("cache.bin", root.join("ignored/cache-link")).unwrap();
        let fx = Self {
            _tmp: tmp,
            base,
            root,
        };
        fx.stamp();
        fx
    }

    /// Modes and mtimes no checkout would reproduce. Directories last, deepest first.
    fn stamp(&self) {
        let r = &self.root;
        chmod(&r.join("secret.txt"), 0o600);
        chmod(&r.join("run.sh"), 0o750);
        chmod(&r.join("ro.txt"), 0o444);
        chmod(&r.join("src/lib.rs"), 0o640);
        chmod(&r.join("link.txt"), 0o660);
        chmod(&r.join("untracked.md"), 0o604);
        chmod(&r.join("newdir/new.txt"), 0o400);
        let files = [
            "secret.txt",
            "run.sh",
            "ro.txt",
            "src/lib.rs",
            "link.txt",
            "untracked.md",
            "newdir/new.txt",
            "to-secret",
            "dangling",
            "app.log",
            "ignored/cache.bin",
            "ignored/cache-link",
            ".gitignore",
        ];
        for (i, f) in files.iter().enumerate() {
            set_mtime(&r.join(f), T + i as i64 * 1_000_000_007 + 123_456_789);
        }
        let dirs = [
            ("empty/deeper", 0o755),
            ("empty", 0o700),
            ("hollow/inner", 0o711),
            ("hollow", 0o750),
            ("newdir", 0o711),
            ("src", 0o750),
            ("ignored", 0o700),
        ];
        for (i, (d, mode)) in dirs.iter().enumerate() {
            chmod(&r.join(d), *mode);
            set_mtime(&r.join(d), T - (i as i64 + 1) * 86_400_000_000_007);
        }
    }

    fn stamp_root(&self) {
        chmod(&self.root, 0o750);
        set_mtime(&self.root, T - 999_000_000_001);
    }
}

fn snap(engine: &mut CaptureEngine, kind: CaptureKind, seq: u64) -> bool {
    engine
        .snap(SnapRequest {
            kind,
            class: Class::Small,
            seq,
        })
        .unwrap()
        .unchanged
}

/// Write → capture → fresh materialize → compare everything; drift the restored disk (extra
/// loose and packed refs, `HEAD` elsewhere, modes and mtimes off, a hardlink broken, an extra
/// empty directory) and materialize the same head over it → identical again; change only
/// metadata at the source → a capture, and both a delta and a fresh materialize carry it.
#[test]
fn metadata_and_refs_round_trip_exactly() {
    let fx = Fixture::build();
    let sink = Arc::new(LocalDir::new(&fx.base.join("store")).unwrap());
    let registrar = Arc::new(InMemoryRegistrar::new("wt-meta", 1, None));
    let mut engine = CaptureEngine::open(CaptureConfig::new("wt-meta", 1, &fx.root), None).unwrap();
    // The engine made its staging directory under the root: the root's own stamp goes after.
    fx.stamp_root();
    snap(&mut engine, CaptureKind::Checkpoint, 1);
    let shipper = engine.shipper(sink.clone(), registrar.clone());
    shipper.ship_pending().unwrap();
    let head = registrar.head().unwrap();
    assert!(
        head.manifest.sections.workspace.worktree_meta.is_some(),
        "the capture carries the overlay"
    );
    assert!(
        snap(&mut engine, CaptureKind::Auto, 1),
        "an unchanged working tree stays unchanged: the overlay is deterministic"
    );

    let restored = fx.base.join("restored");
    let m = Materializer::new(sink.as_ref(), MaterializeTargets::new(&restored, None));
    let first = m
        .materialize(&head.manifest, MaterializeClass::All)
        .unwrap();
    assert!(first.worktree_meta > 0, "{first:?}");
    assert_same(&fx.root, &restored);
    assert_eq!(refs(&restored), refs(&fx.root));
    assert!(
        refs(&restored).2.contains("stash@{0}"),
        "the stash came back: {:?}",
        refs(&restored)
    );

    // Drift the restored disk every way a rematerialize must undo.
    git(&restored, &["branch", "extra-loose"]);
    git(&restored, &["branch", "extra-packed"]);
    git(&restored, &["pack-refs", "--all"]);
    git(&restored, &["branch", "extra-loose-2"]);
    git(
        &restored,
        &["symbolic-ref", "HEAD", "refs/heads/extra-loose"],
    );
    git(
        &restored,
        &["update-ref", "refs/remotes/origin/main", "HEAD"],
    );
    chmod(&restored.join("secret.txt"), 0o644);
    set_mtime(&restored.join("src/lib.rs"), T);
    set_mtime(&restored.join("to-secret"), T);
    set_mtime(&restored.join("ignored/cache-link"), T);
    fs::remove_file(restored.join("src/twin.txt")).unwrap();
    fs::write(restored.join("src/twin.txt"), "linked twice\n").unwrap();
    fs::create_dir_all(restored.join("stray-empty")).unwrap();
    fs::remove_dir(restored.join("empty/deeper")).unwrap();
    m.materialize(&head.manifest, MaterializeClass::All)
        .unwrap();
    assert_same(&fx.root, &restored);
    assert_eq!(refs(&restored), refs(&fx.root));

    // Metadata alone changes at the source: that is a change worth a capture.
    chmod(&fx.root.join("src/lib.rs"), 0o600);
    set_mtime(&fx.root.join("ro.txt"), T + 42);
    fs::create_dir_all(fx.root.join("later-empty")).unwrap();
    fs::remove_dir(fx.root.join("hollow/inner")).unwrap();
    fs::remove_dir(fx.root.join("hollow")).unwrap();
    set_mtime(&fx.root.join("src"), T - 5);
    fx.stamp_root();
    assert!(
        !snap(&mut engine, CaptureKind::Auto, 2),
        "a metadata-only change is captured"
    );
    // A hardlink group moves and a branch goes.
    fs::remove_file(fx.root.join("src/twin.txt")).unwrap();
    fs::hard_link(fx.root.join("secret.txt"), fx.root.join("src/twin.txt")).unwrap();
    git(&fx.root, &["branch", "-D", "loose-branch"]);
    set_mtime(&fx.root.join("src"), T - 7);
    fx.stamp_root();
    snap(&mut engine, CaptureKind::Turn, 3);
    shipper.ship_pending().unwrap();
    let head2 = registrar.head().unwrap();
    assert!(head2.n > head.n);
    m.materialize(&head2.manifest, MaterializeClass::All)
        .unwrap();
    assert_same(&fx.root, &restored);
    assert_eq!(refs(&restored), refs(&fx.root));
    let fresh = fx.base.join("fresh");
    Materializer::new(sink.as_ref(), MaterializeTargets::new(&fresh, None))
        .materialize(&head2.manifest, MaterializeClass::All)
        .unwrap();
    assert_same(&fx.root, &fresh);
    assert_eq!(refs(&fresh), refs(&fx.root));

    // The head over itself writes nothing and changes nothing.
    let again = m
        .materialize(&head2.manifest, MaterializeClass::All)
        .unwrap();
    assert_eq!(
        (
            again.files,
            again.bytes,
            again.removed,
            again.symlinks,
            again.hardlinks,
            again.worktree_meta
        ),
        (0, 0, 0, 0, 0, 0),
        "{again:?}"
    );
    assert_same(&fx.root, &restored);
}

/// The ref set after a materialize is exactly the manifest's, whatever the disk held: extra
/// loose and packed refs go, `HEAD` comes back, the stash is the captured one.
#[test]
fn rematerialize_reconciles_the_complete_ref_set() {
    let fx = Fixture::build();
    let sink = Arc::new(LocalDir::new(&fx.base.join("store")).unwrap());
    let registrar = Arc::new(InMemoryRegistrar::new("wt-refs", 1, None));
    let mut engine = CaptureEngine::open(CaptureConfig::new("wt-refs", 1, &fx.root), None).unwrap();
    snap(&mut engine, CaptureKind::Checkpoint, 1);
    engine
        .shipper(sink.clone(), registrar.clone())
        .ship_pending()
        .unwrap();
    let head = registrar.head().unwrap();
    let restored = fx.base.join("restored");
    let m = Materializer::new(sink.as_ref(), MaterializeTargets::new(&restored, None));
    m.materialize(&head.manifest, MaterializeClass::All)
        .unwrap();
    assert_eq!(refs(&restored), refs(&fx.root));

    git(&restored, &["branch", "extra-packed"]);
    git(&restored, &["pack-refs", "--all"]);
    git(&restored, &["branch", "extra-loose"]);
    git(
        &restored,
        &["update-ref", "refs/remotes/origin/main", "HEAD"],
    );
    git(&restored, &["update-ref", "refs/stash", "HEAD"]);
    git(
        &restored,
        &["symbolic-ref", "HEAD", "refs/heads/extra-loose"],
    );
    assert_ne!(refs(&restored), refs(&fx.root));
    m.materialize(&head.manifest, MaterializeClass::All)
        .unwrap();
    assert_eq!(refs(&restored), refs(&fx.root));
    let loose: Vec<String> = walkdir::WalkDir::new(restored.join(".git/refs"))
        .into_iter()
        .flatten()
        .filter(|e| e.file_type().is_file())
        .map(|e| e.path().display().to_string())
        .collect();
    assert!(loose.is_empty(), "every ref is in packed-refs: {loose:?}");
}

/// Capture the fixture once and hand back what the other tests need.
fn captured(fx: &Fixture, id: &str) -> (Arc<LocalDir>, HeadInfo) {
    let sink = Arc::new(LocalDir::new(&fx.base.join("store")).unwrap());
    let registrar = Arc::new(InMemoryRegistrar::new(id, 1, None));
    let mut engine = CaptureEngine::open(CaptureConfig::new(id, 1, &fx.root), None).unwrap();
    snap(&mut engine, CaptureKind::Checkpoint, 1);
    engine
        .shipper(sink.clone(), registrar.clone())
        .ship_pending()
        .unwrap();
    (sink, registrar.head().unwrap())
}

/// A capture without the overlay (every capture before it) restores as it always did: the
/// tree as git checks it out, nothing about modes, mtimes or empty directories, no failure.
#[test]
fn a_capture_without_the_overlay_restores_as_before() {
    let fx = Fixture::build();
    let (sink, head) = captured(&fx, "wt-old");
    let mut old = head.manifest.clone();
    old.sections.workspace.worktree_meta = None;
    let text = String::from_utf8(old.clone().encode().bytes).unwrap();
    assert!(!text.contains("worktree_meta"), "{text}");
    let restored = fx.base.join("restored");
    let report = Materializer::new(sink.as_ref(), MaterializeTargets::new(&restored, None))
        .materialize(&old, MaterializeClass::All)
        .unwrap();
    assert_eq!(report.worktree_meta, 0);
    assert_eq!(
        fs::read_to_string(restored.join("secret.txt")).unwrap(),
        "secret\n"
    );
    let checkout_mode = fs::metadata(restored.join("secret.txt")).unwrap().mode() & 0o7777;
    assert_ne!(checkout_mode, 0o600, "no overlay, git's mode");
    assert!(
        !restored.join("empty").exists(),
        "no overlay, no empty directory"
    );
    assert_eq!(
        refs(&restored),
        refs(&fx.root),
        "refs are reconciled either way"
    );
}

/// An overlay this build does not read, or one whose bytes do not verify, fails the
/// materialize before anything is written.
#[test]
fn an_unreadable_overlay_fails_before_anything_is_written() {
    let fx = Fixture::build();
    let (sink, head) = captured(&fx, "wt-bad");
    let targets = |name: &str| MaterializeTargets::new(&fx.base.join(name), None);

    let mut newer = head.manifest.clone();
    newer
        .sections
        .workspace
        .worktree_meta
        .as_mut()
        .unwrap()
        .format = 2;
    let err = Materializer::new(sink.as_ref(), targets("newer"))
        .materialize(&newer, MaterializeClass::All)
        .unwrap_err();
    assert!(
        matches!(err, MaterializeError::UnsupportedMetaFormat(2)),
        "{err}"
    );
    assert!(!fx.base.join("newer/.git").exists(), "nothing written");

    let mut forged = head.manifest.clone();
    forged
        .sections
        .workspace
        .worktree_meta
        .as_mut()
        .unwrap()
        .sha256 = "0".repeat(64);
    let err = Materializer::new(sink.as_ref(), targets("forged"))
        .materialize(&forged, MaterializeClass::All)
        .unwrap_err();
    assert!(matches!(err, MaterializeError::Corrupt { .. }), "{err}");
    assert!(!fx.base.join("forged/.git").exists(), "nothing written");
}

/// A disk the overlay cannot be applied to fails the materialize loudly instead of reporting a
/// partly restored tree as restored: here the overlay names a file the checked-out tree does
/// not have.
#[test]
fn an_overlay_that_cannot_be_applied_fails_the_materialize() {
    let fx = Fixture::build();
    let (sink, head) = captured(&fx, "wt-mismatch");
    // The tree of the commit (no untracked files) under the overlay of the working tree.
    let mut odd = head.manifest.clone();
    let commit_tree = git(&fx.root, &["rev-parse", "HEAD^{tree}"]);
    odd.sections
        .git
        .refs
        .insert(WORKTREE_TREE_REF.to_owned(), commit_tree);
    let err = Materializer::new(
        sink.as_ref(),
        MaterializeTargets::new(&fx.base.join("odd"), None),
    )
    .materialize(&odd, MaterializeClass::All)
    .unwrap_err();
    let text = err.to_string();
    assert!(
        matches!(err, MaterializeError::WorktreeMeta(_)) && text.contains("No such file"),
        "{text}"
    );
}

/// The overlay covers the working tree and nothing another class carries: not `.git`, the
/// daemon directory, bulk directories, nested repositories or ignored directories.
#[test]
fn the_overlay_leaves_other_classes_alone() {
    let fx = Fixture::build();
    let r = &fx.root;
    fs::create_dir_all(r.join("node_modules/pkg/empty")).unwrap();
    fs::create_dir_all(r.join("pkgs/a/node_modules/x")).unwrap();
    fs::create_dir_all(r.join("vendor/nested")).unwrap();
    git(&r.join("vendor/nested"), &["init", "-q"]);
    fs::create_dir_all(r.join("vendor/nested/inside")).unwrap();
    fs::create_dir_all(r.join("ignored/deep/er")).unwrap();
    let (sink, head) = captured(&fx, "wt-scope");
    let meta = head
        .manifest
        .sections
        .workspace
        .worktree_meta
        .clone()
        .unwrap();
    assert!(
        meta.packs
            .iter()
            .all(|p| head.manifest.sections.workspace.packs.contains(p)),
        "the overlay's packs are the workspace section's"
    );
    let restored = fx.base.join("restored");
    Materializer::new(sink.as_ref(), MaterializeTargets::new(&restored, None))
        .materialize(&head.manifest, MaterializeClass::All)
        .unwrap();
    let doc = read_doc(&restored, &meta);
    let paths: Vec<&str> = doc.entries.iter().map(|e| e.path.as_str()).collect();
    for absent in [
        ".git",
        ".sealantd",
        "node_modules",
        "pkgs/a/node_modules",
        "vendor/nested",
        "vendor/nested/inside",
        "ignored",
        "ignored/deep",
    ] {
        assert!(
            !paths
                .iter()
                .any(|p| *p == absent || p.starts_with(&format!("{absent}/"))),
            "{absent} is not the overlay's: {paths:?}"
        );
    }
    for present in [
        "",
        "src",
        "empty/deeper",
        "pkgs",
        "pkgs/a",
        "vendor",
        "to-secret",
    ] {
        assert!(
            paths.contains(&present),
            "{present} is the overlay's: {paths:?}"
        );
    }
    assert_eq!(
        doc.hardlinks,
        vec![vec!["link.txt".to_owned(), "src/twin.txt".to_owned()]]
    );
}

/// The overlay document of `meta`, read back from the restored disk's pack cache.
fn read_doc(restored: &Path, meta: &WorktreeMeta) -> MetaDocument {
    let cache = restored.join(".sealantd/capture/cache");
    let mut bytes = Vec::new();
    for id in &meta.chunks {
        let found = meta.packs.iter().find_map(|p| {
            let reader = PackReader::open(&cache.join(p.rsplit('/').next().unwrap())).unwrap();
            reader.read(id).unwrap()
        });
        bytes.extend(found.expect("chunk in the overlay's packs"));
    }
    MetaDocument::decode(&bytes).unwrap()
}

/// Tracked files under a bulk-named directory (`build/`, `dist/`) belong to the git class: a
/// bulk section older than the worktree tree neither sweeps a tracked file it never saw nor
/// writes back older bytes over one that changed since.
#[test]
fn a_stale_bulk_section_never_touches_tracked_files() {
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path().join("ws");
    fs::create_dir_all(root.join("build")).unwrap();
    git(&root, &["init", "-q", "-b", "main"]);
    git(&root, &["config", "user.email", "t@t"]);
    git(&root, &["config", "user.name", "t"]);
    fs::write(root.join("build/a.sh"), "old a\n").unwrap();
    fs::write(root.join("build/out.o"), "generated\n").unwrap();
    git(&root, &["add", "build/a.sh"]);
    git(&root, &["commit", "-q", "-m", "a"]);
    let sink = Arc::new(LocalDir::new(&tmp.path().join("store")).unwrap());
    let registrar = Arc::new(InMemoryRegistrar::new("wt-bulk", 1, None));
    let mut engine = CaptureEngine::open(CaptureConfig::new("wt-bulk", 1, &root), None).unwrap();
    snap(&mut engine, CaptureKind::Turn, 1);
    engine
        .snap(SnapRequest {
            kind: CaptureKind::Auto,
            class: Class::Bulk,
            seq: 2,
        })
        .unwrap();
    // After the bulk capture: a tracked file edited, one added.
    fs::write(root.join("build/a.sh"), "new a\n").unwrap();
    fs::write(root.join("build/b.sh"), "b\n").unwrap();
    git(&root, &["add", "-A", "build/a.sh", "build/b.sh"]);
    git(&root, &["commit", "-q", "-m", "b"]);
    snap(&mut engine, CaptureKind::Turn, 3);
    engine
        .shipper(sink.clone(), registrar.clone())
        .ship_pending()
        .unwrap();
    let head = registrar.head().unwrap();
    assert!(head.manifest.sections.bulk.section().is_some());
    for with_overlay in [true, false] {
        let mut manifest = head.manifest.clone();
        if !with_overlay {
            manifest.sections.workspace.worktree_meta = None;
        }
        let restored = tmp.path().join(format!("restored-{with_overlay}"));
        Materializer::new(sink.as_ref(), MaterializeTargets::new(&restored, None))
            .materialize(&manifest, MaterializeClass::All)
            .unwrap();
        assert_eq!(
            fs::read_to_string(restored.join("build/a.sh")).unwrap(),
            "new a\n",
            "overlay {with_overlay}"
        );
        assert_eq!(
            fs::read_to_string(restored.join("build/b.sh")).unwrap(),
            "b\n",
            "overlay {with_overlay}"
        );
        assert_eq!(
            fs::read_to_string(restored.join("build/out.o")).unwrap(),
            "generated\n"
        );
        assert_eq!(git(&restored, &["status", "--porcelain"]), "?? build/out.o");
    }
}
