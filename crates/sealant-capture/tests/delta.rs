//! Delta materialize: the head applied over a materialized base is byte-identical to a fresh
//! materialize of the head, writes only what changed, removes what the plan dropped, and a
//! second application is a no-op. Bytes written versus skipped are printed for the record.

use std::collections::BTreeMap;
use std::fs;
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::Arc;

use sealant_capture::manifest::BulkState;
use sealant_capture::{
    CaptureConfig, CaptureEngine, CaptureKind, Class, InMemoryRegistrar, LocalDir,
    MaterializeClass, MaterializeReport, MaterializeTargets, Materializer, SnapRequest,
};

const BULK_FILES: usize = 400;

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

fn noise(len: usize, seed: u64) -> Vec<u8> {
    let mut x = seed | 1;
    (0..len)
        .map(|_| {
            x ^= x << 13;
            x ^= x >> 7;
            x ^= x << 17;
            ((x >> 24) & 0xff) as u8
        })
        .collect()
}

struct Fixture {
    _tmp: tempfile::TempDir,
    base: PathBuf,
    root: PathBuf,
    home: PathBuf,
}

impl Fixture {
    fn build() -> Self {
        let tmp = tempfile::tempdir().unwrap();
        let base = tmp.path().to_path_buf();
        let root = base.join("ws");
        let home = base.join("home");
        fs::create_dir_all(root.join("src")).unwrap();
        fs::create_dir_all(&home).unwrap();
        git(&root, &["init", "-q", "-b", "main"]);
        git(&root, &["config", "user.email", "t@t"]);
        git(&root, &["config", "user.name", "t"]);
        fs::write(root.join(".gitignore"), ".env*\nnode_modules/\ndist/\n").unwrap();
        fs::write(root.join("a.txt"), "one\n").unwrap();
        fs::write(root.join("src/lib.rs"), "pub fn f() {}\n").unwrap();
        fs::write(root.join("src/main.rs"), "fn main() {}\n").unwrap();
        git(&root, &["add", "-A"]);
        git(&root, &["commit", "-q", "-m", "one"]);
        fs::write(root.join("notes.md"), "untracked\n").unwrap();
        fs::write(root.join(".env"), "SECRET=1\n").unwrap();
        fs::create_dir_all(root.join("dist")).unwrap();
        fs::write(root.join("dist/out.js"), "console.log(1)\n").unwrap();
        let nm = root.join("node_modules");
        for i in 0..BULK_FILES {
            let pkg = nm.join(format!("pkg{}", i % 20)).join("lib");
            fs::create_dir_all(&pkg).unwrap();
            fs::write(pkg.join(format!("m{i}.js")), noise(2_000 + i * 7, i as u64)).unwrap();
        }
        fs::create_dir_all(nm.join(".pnpm/store")).unwrap();
        fs::write(nm.join(".pnpm/store/shared.js"), noise(30_000, 77)).unwrap();
        fs::hard_link(
            nm.join(".pnpm/store/shared.js"),
            nm.join("pkg1/lib/shared.js"),
        )
        .unwrap();
        fs::hard_link(
            nm.join(".pnpm/store/shared.js"),
            nm.join("pkg2/lib/shared.js"),
        )
        .unwrap();
        fs::create_dir_all(nm.join(".bin")).unwrap();
        std::os::unix::fs::symlink("../pkg1/lib/m1.js", nm.join(".bin/m1")).unwrap();
        fs::write(home.join("transcript.jsonl"), noise(200_000, 5)).unwrap();
        fs::write(home.join("state.db"), noise(100_000, 6)).unwrap();
        Self {
            _tmp: tmp,
            base,
            root,
            home,
        }
    }

    fn config(&self) -> CaptureConfig {
        let mut c = CaptureConfig::new("wt-delta", 1, &self.root);
        c.harness_home = Some(self.home.clone());
        c
    }

    /// Change something in every class.
    fn mutate(&self) {
        let root = &self.root;
        // Git class: an edit, a new tracked file, a removed tracked file, an untracked file
        // gone and another one new.
        fs::write(root.join("a.txt"), "one\ntwo\n").unwrap();
        fs::write(root.join("src/new.rs"), "pub fn g() {}\n").unwrap();
        git(root, &["rm", "-q", "src/main.rs"]);
        git(root, &["add", "-A"]);
        git(root, &["commit", "-q", "-m", "two"]);
        fs::remove_file(root.join("notes.md")).unwrap();
        fs::write(root.join("todo.md"), "todo\n").unwrap();
        // Workspace class: an ignored file changed, one added; the transcript grew.
        fs::write(root.join(".env"), "SECRET=2\n").unwrap();
        fs::write(root.join(".env.local"), "LOCAL=1\n").unwrap();
        let mut t = fs::read(self.home.join("transcript.jsonl")).unwrap();
        t.extend(noise(5_000, 9));
        fs::write(self.home.join("transcript.jsonl"), t).unwrap();
        // Bulk class: one file edited, one removed, one added, the symlink retargeted, a hardlink
        // member added and another removed.
        let nm = root.join("node_modules");
        fs::write(nm.join("pkg1/lib/m1.js"), noise(3_000, 1_001)).unwrap();
        fs::remove_file(nm.join("pkg2/lib/m2.js")).unwrap();
        fs::create_dir_all(nm.join("pkg9/lib")).unwrap();
        fs::write(nm.join("pkg9/lib/new.js"), noise(4_000, 1_002)).unwrap();
        fs::remove_file(nm.join(".bin/m1")).unwrap();
        std::os::unix::fs::symlink("../pkg3/lib/m3.js", nm.join(".bin/m1")).unwrap();
        fs::hard_link(
            nm.join(".pnpm/store/shared.js"),
            nm.join("pkg3/lib/shared.js"),
        )
        .unwrap();
        fs::remove_file(nm.join("pkg2/lib/shared.js")).unwrap();
    }
}

/// One file or symlink as compared between two restores.
#[derive(Debug, PartialEq, Eq)]
struct Entry {
    kind: &'static str,
    mode: u32,
    /// Compared only where the class restores mtimes (files of the chunked classes; git does
    /// not, and a symlink's is never restored).
    mtime: Option<i64>,
    bytes: Vec<u8>,
    link: Option<PathBuf>,
}

/// Every file and symlink under `root` (minus the daemon dir) keyed by relative path.
fn walk(root: &Path, mtimes_under: &[&str]) -> BTreeMap<String, Entry> {
    let mut out = BTreeMap::new();
    for e in walkdir::WalkDir::new(root)
        .follow_links(false)
        .min_depth(1)
        .into_iter()
        .filter_entry(|e| e.file_name() != ".sealantd")
        .flatten()
    {
        let rel = e
            .path()
            .strip_prefix(root)
            .unwrap()
            .to_string_lossy()
            .to_string();
        let meta = fs::symlink_metadata(e.path()).unwrap();
        if meta.is_dir() {
            continue;
        }
        let with_mtime = mtimes_under.iter().any(|p| rel.starts_with(p));
        let mtime = with_mtime.then(|| meta.mtime() * 1_000_000_000 + meta.mtime_nsec());
        let entry = if meta.is_symlink() {
            Entry {
                kind: "symlink",
                mode: meta.mode() & 0o7777,
                mtime: None,
                bytes: Vec::new(),
                link: Some(fs::read_link(e.path()).unwrap()),
            }
        } else {
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
    out
}

fn assert_same_tree(a: &Path, b: &Path, mtimes_under: &[&str]) {
    let wa = walk(a, mtimes_under);
    let wb = walk(b, mtimes_under);
    let ka: Vec<&String> = wa.keys().collect();
    let kb: Vec<&String> = wb.keys().collect();
    assert_eq!(ka, kb, "path sets differ between {a:?} and {b:?}");
    for (k, ea) in &wa {
        assert_eq!(ea, &wb[k], "{k} differs");
    }
}

fn ino(p: &Path) -> u64 {
    fs::metadata(p).unwrap().ino()
}

fn print_report(label: &str, r: &MaterializeReport) {
    eprintln!(
        "{label}: files written {} ({} bytes), skipped {} ({} bytes), removed {}, symlinks {}, hardlinks {}, git packs {}, git paths changed {:?}, fsck {:?}",
        r.files,
        r.bytes,
        r.files_skipped,
        r.bytes_skipped,
        r.removed,
        r.symlinks,
        r.hardlinks,
        r.git_packs,
        r.git_paths_changed,
        r.fsck
    );
}

#[test]
fn head_over_base_equals_a_fresh_materialize_and_writes_only_the_delta() {
    let fx = Fixture::build();
    let sink = Arc::new(LocalDir::new(&fx.base.join("store")).unwrap());
    let registrar = Arc::new(InMemoryRegistrar::new("wt-delta", 1, None));
    let mut engine = CaptureEngine::open(fx.config(), None).unwrap();
    let snap = |engine: &mut CaptureEngine, class, seq| {
        engine
            .snap(SnapRequest {
                kind: if class == Class::Small {
                    CaptureKind::Checkpoint
                } else {
                    CaptureKind::Auto
                },
                class,
                seq,
            })
            .unwrap()
    };
    snap(&mut engine, Class::Small, 1);
    snap(&mut engine, Class::Bulk, 2);
    let shipper = engine.shipper(sink.clone(), registrar.clone());
    shipper.ship_pending().unwrap();
    let base_head = registrar.head().unwrap();

    // The base, materialized fresh: everything is written.
    let restore = fx.base.join("restore");
    let home_r = fx.base.join("home-r");
    let m = Materializer::new(
        sink.as_ref(),
        MaterializeTargets::new(&restore, Some(home_r.clone())),
    );
    let r0 = m
        .materialize(&base_head.manifest, MaterializeClass::All)
        .unwrap();
    print_report("base fresh", &r0);
    assert_eq!(r0.files_skipped, 0);
    assert_eq!(r0.removed, 0);
    assert!(r0.files as usize >= BULK_FILES);
    assert_eq!(
        r0.git_paths_changed, None,
        "nothing was known: a full checkout"
    );

    // The head: every class changed.
    fx.mutate();
    snap(&mut engine, Class::Small, 3);
    snap(&mut engine, Class::Bulk, 4);
    shipper.ship_pending().unwrap();
    let head = registrar.head().unwrap();
    assert!(head.n > base_head.n);

    // Delta: the head over the base.
    let r1 = m
        .materialize(&head.manifest, MaterializeClass::All)
        .unwrap();
    print_report("head over base", &r1);
    assert!(
        r1.files_skipped as usize >= BULK_FILES - 5,
        "the unchanged bulk files are skipped: {r1:?}"
    );
    assert!(r1.files <= 12, "only the changed files are written: {r1:?}");
    // The grown transcript is rewritten whole (chunks save the upload, not the write), so the
    // delta is bounded by it, not by the bulk tree.
    assert!(
        r1.bytes < r0.bytes / 4,
        "delta bytes {} vs fresh {}",
        r1.bytes,
        r0.bytes
    );
    assert!(r1.bytes_skipped > r1.bytes * 5);
    // pkg2/lib/m2.js and pkg2/lib/shared.js (bulk sweep); notes.md goes with the tree diff.
    assert!(r1.removed >= 2, "{r1:?}");
    assert_eq!(r1.hardlinks, 1, "one new hardlink member: {r1:?}");
    assert_eq!(r1.symlinks, 1, "the retargeted symlink: {r1:?}");
    // a.txt, src/new.rs, src/main.rs, notes.md, todo.md.
    assert_eq!(r1.git_paths_changed, Some(5), "{r1:?}");
    assert_eq!(r1.git_packs, 1, "the head's commit pack: {r1:?}");
    assert_eq!(r1.fsck, Some(sealant_capture::FsckStatus::Verified));
    assert!(!restore.join("notes.md").exists());
    assert!(!restore.join("src/main.rs").exists());
    assert!(!restore.join("node_modules/pkg2/lib/m2.js").exists());
    assert!(!restore.join("node_modules/pkg2/lib/shared.js").exists());
    assert_eq!(
        fs::read_to_string(restore.join("todo.md")).unwrap(),
        "todo\n"
    );
    assert_eq!(
        fs::read_to_string(restore.join(".env")).unwrap(),
        "SECRET=2\n"
    );

    // Fresh: the head into an empty directory.
    let fresh = fx.base.join("fresh");
    let home_f = fx.base.join("home-f");
    let mf = Materializer::new(
        sink.as_ref(),
        MaterializeTargets::new(&fresh, Some(home_f.clone())),
    );
    let r2 = mf
        .materialize(&head.manifest, MaterializeClass::All)
        .unwrap();
    print_report("head fresh", &r2);
    assert_eq!(r2.files_skipped, 0);
    eprintln!(
        "delta wrote {} of {} bytes a fresh materialize writes ({:.1}%)",
        r1.bytes,
        r2.bytes,
        100.0 * r1.bytes as f64 / r2.bytes as f64
    );

    assert_same_tree(
        &restore,
        &fresh,
        &["node_modules", "dist", ".env", ".git/index", ".git/logs"],
    );
    assert_same_tree(&home_r, &home_f, &[""]);
    assert_eq!(
        git(&restore, &["status", "--porcelain"]),
        git(&fresh, &["status", "--porcelain"])
    );
    assert_eq!(
        git(&restore, &["rev-parse", "HEAD"]),
        git(&fresh, &["rev-parse", "HEAD"])
    );
    for r in [&restore, &fresh] {
        let store = ino(&r.join("node_modules/.pnpm/store/shared.js"));
        assert_eq!(ino(&r.join("node_modules/pkg1/lib/shared.js")), store);
        assert_eq!(ino(&r.join("node_modules/pkg3/lib/shared.js")), store);
        assert_eq!(
            fs::read_link(r.join("node_modules/.bin/m1")).unwrap(),
            Path::new("../pkg3/lib/m3.js")
        );
    }

    // The head over itself: nothing to do.
    let r3 = m
        .materialize(&head.manifest, MaterializeClass::All)
        .unwrap();
    print_report("head over head", &r3);
    assert_eq!(
        (r3.files, r3.bytes, r3.removed, r3.symlinks, r3.hardlinks),
        (0, 0, 0, 0, 0)
    );
    assert_eq!(r3.git_paths_changed, Some(0));
    assert_same_tree(
        &restore,
        &fresh,
        &["node_modules", "dist", ".env", ".git/index", ".git/logs"],
    );

    // A plan whose bulk section is pending (another platform's dependency tree, or none yet)
    // leaves the bulk directories on disk alone.
    let mut pending = head.manifest.clone();
    pending.sections.bulk = BulkState::pending();
    let r4 = m.materialize(&pending, MaterializeClass::All).unwrap();
    assert_eq!(r4.removed, 0);
    assert!(restore.join("node_modules/pkg1/lib/m1.js").exists());
    assert!(restore.join("dist/out.js").exists());
}
