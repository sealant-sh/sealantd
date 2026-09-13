//! End-to-end proofs of ADR-0015's claims on this machine: snap → ship → materialize.

use std::collections::HashSet;
use std::fs;
use std::io::Write;
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use sealant_capture::gitpack::GitRepo;
use sealant_capture::manifest::{FsckStatus, INDEX_TREE_REF, PSEUDO_REF_PREFIX};
use sealant_capture::registrar::Registrar;
use sealant_capture::{
    CaptureConfig, CaptureEngine, CaptureKind, Class, InMemoryRegistrar, LocalDir,
    MaterializeClass, MaterializeTargets, Materializer, SnapRequest,
};

/// `git status --porcelain` without the daemon directory (untracked in the fixture, and the
/// materializer's cache lands there too).
fn status(root: &Path) -> String {
    git(root, &["status", "--porcelain"])
        .lines()
        .filter(|l| !l.ends_with(".sealantd/"))
        .collect::<Vec<_>>()
        .join("\n")
}

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

fn pseudo_random(len: usize, seed: u64) -> Vec<u8> {
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

/// JSONL that compresses like a transcript but still cuts into several chunks.
fn transcript_bytes(len: usize, seed: u64) -> Vec<u8> {
    let mut out = Vec::with_capacity(len + 200);
    let noise = pseudo_random(len / 4 + 64, seed);
    let mut i = 0usize;
    while out.len() < len {
        let word = hex::encode(&noise[(i * 8) % noise.len()..(i * 8) % noise.len() + 8]);
        let line = format!(
            "{{\"type\":\"message\",\"seq\":{i},\"role\":\"assistant\",\"text\":\"token {word} and more words here\"}}\n"
        );
        out.extend_from_slice(line.as_bytes());
        i += 1;
    }
    out.truncate(len);
    out
}

struct Fixture {
    _tmp: tempfile::TempDir,
    base: PathBuf,
    root: PathBuf,
    home: PathBuf,
}

impl Fixture {
    fn build(node_modules_files: usize, transcript_len: usize) -> Self {
        let tmp = tempfile::tempdir().unwrap();
        let base = tmp.path().to_path_buf();
        let root = base.join("ws");
        let home = base.join("home");
        fs::create_dir_all(&root).unwrap();
        fs::create_dir_all(&home).unwrap();
        git(&root, &["init", "-q", "-b", "main"]);
        git(&root, &["config", "user.email", "t@t"]);
        git(&root, &["config", "user.name", "t"]);
        fs::write(root.join(".gitignore"), ".env\nnode_modules/\ndist/\n").unwrap();
        fs::write(root.join("a.txt"), "one\n").unwrap();
        fs::create_dir_all(root.join("src")).unwrap();
        fs::write(root.join("src/lib.rs"), "pub fn f() {}\n").unwrap();
        git(&root, &["add", "-A"]);
        git(&root, &["commit", "-q", "-m", "one"]);
        fs::write(root.join("a.txt"), "one\ntwo\n").unwrap();
        git(&root, &["commit", "-q", "-am", "two"]);
        fs::write(root.join("src/main.rs"), "fn main() {}\n").unwrap();
        git(&root, &["add", "-A"]);
        git(&root, &["commit", "-q", "-m", "three"]);
        // A stash entry.
        fs::write(root.join("src/lib.rs"), "pub fn f() { stashed() }\n").unwrap();
        git(&root, &["stash", "push", "-q", "-m", "wip"]);
        // Uncommitted edit, a staged file, an untracked file, an ignored file.
        fs::write(root.join("a.txt"), "one\ntwo\nthree (dirty)\n").unwrap();
        fs::write(root.join("staged.txt"), "staged\n").unwrap();
        git(&root, &["add", "staged.txt"]);
        fs::write(root.join("notes.md"), "untracked\n").unwrap();
        fs::write(root.join(".env"), "SECRET=1\n").unwrap();
        // Bulk: dist and node_modules with hardlinks and symlinks.
        fs::create_dir_all(root.join("dist")).unwrap();
        fs::write(root.join("dist/out.js"), "console.log(1)\n").unwrap();
        let nm = root.join("node_modules");
        for i in 0..node_modules_files {
            let pkg = nm.join(format!("pkg{}", i % 50)).join("lib");
            fs::create_dir_all(&pkg).unwrap();
            fs::write(
                pkg.join(format!("m{i}.js")),
                format!("module.exports = {i};\n"),
            )
            .unwrap();
        }
        fs::create_dir_all(nm.join(".pnpm/store")).unwrap();
        fs::write(nm.join(".pnpm/store/shared.js"), "shared\n").unwrap();
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
        // A nested repository with a mid-index-pack `.pack` (no `.idx`).
        let nested = root.join("vendor/x");
        fs::create_dir_all(&nested).unwrap();
        git(&nested, &["init", "-q"]);
        fs::write(nested.join("v.txt"), "vendored\n").unwrap();
        fs::create_dir_all(nested.join(".git/objects/pack")).unwrap();
        fs::write(nested.join(".git/objects/pack/pack-abc.pack"), b"PACK").unwrap();
        // Harness home: transcript, SQLite db + wal (+ shm, excluded), credentials (excluded).
        fs::write(
            home.join("transcript.jsonl"),
            transcript_bytes(transcript_len, 5),
        )
        .unwrap();
        fs::write(home.join("state.db"), pseudo_random(100_000, 6)).unwrap();
        fs::write(home.join("state.db-wal"), pseudo_random(20_000, 7)).unwrap();
        fs::write(home.join("state.db-shm"), pseudo_random(32_000, 8)).unwrap();
        fs::create_dir_all(home.join(".claude")).unwrap();
        fs::write(home.join(".claude/.credentials.json"), "{\"token\":\"x\"}").unwrap();
        fs::write(home.join(".claude/settings.json"), "{}").unwrap();
        // A stale lock, always excluded.
        fs::write(root.join(".git/index.lock"), b"").unwrap();
        Self {
            _tmp: tmp,
            base,
            root,
            home,
        }
    }

    fn config(&self, epoch: u64) -> CaptureConfig {
        let mut c = CaptureConfig::new("wt-fixture", epoch, &self.root);
        c.harness_home = Some(self.home.clone());
        c
    }

    fn sink(&self) -> Arc<LocalDir> {
        Arc::new(LocalDir::new(&self.base.join("store")).unwrap())
    }
}

fn diff_r(a: &Path, b: &Path, excludes: &[&str]) -> String {
    let mut cmd = Command::new("diff");
    cmd.arg("-r").arg("-q");
    for e in excludes {
        cmd.arg(format!("--exclude={e}"));
    }
    let out = cmd.arg(a).arg(b).output().expect("diff");
    String::from_utf8_lossy(&out.stdout).to_string()
}

/// (a) round trip: snap → ship → materialize; fsck, status, stash and tree identical.
#[test]
fn round_trip_materializes_an_identical_workspace() {
    let fx = Fixture::build(2000, 9_500_000);
    let sink = fx.sink();
    let registrar = Arc::new(InMemoryRegistrar::new("wt-fixture", 1, None));
    let mut engine = CaptureEngine::open(fx.config(1), None).unwrap();

    let small = engine
        .snap(SnapRequest {
            kind: CaptureKind::Checkpoint,
            class: Class::Small,
            seq: 1,
        })
        .unwrap();
    assert_eq!(
        small.manifest.manifest.sections.git.fsck,
        FsckStatus::Verified
    );
    assert!(small.stats.git_pack_bytes > 0);
    assert!(small.stats.torn == 0);
    let bulk = engine
        .snap(SnapRequest {
            kind: CaptureKind::Auto,
            class: Class::Bulk,
            seq: 2,
        })
        .unwrap();
    assert!(bulk.stats.files >= 2000);

    let shipper = engine.shipper(sink.clone(), registrar.clone());
    assert_eq!(shipper.ship_pending().unwrap(), 2);
    assert!(engine.staging().pending().unwrap().is_empty());
    let head = registrar.head().unwrap();
    assert_eq!(head.n, 1);
    assert_eq!(head.capture_id, bulk.manifest.capture_id);

    // Materialize from the store alone.
    let restore = fx.base.join("restore");
    let home2 = fx.base.join("home2");
    let m = Materializer::new(
        sink.as_ref(),
        MaterializeTargets::new(&restore, Some(home2.clone())),
    );
    let manifest = m
        .fetch_manifest(&head.manifest_key, &head.capture_id)
        .unwrap();
    let report = m
        .materialize(&manifest.manifest, MaterializeClass::All)
        .unwrap();
    assert_eq!(report.fsck, Some(FsckStatus::Verified));
    assert!(report.hardlinks >= 2);

    let restored = GitRepo::open(&restore).unwrap();
    assert_eq!(restored.fsck().unwrap(), FsckStatus::Verified);
    assert_eq!(status(&restore), status(&fx.root));
    assert!(
        small
            .manifest
            .manifest
            .sections
            .git
            .refs
            .contains_key(INDEX_TREE_REF)
    );
    assert_eq!(
        git(&restore, &["stash", "list"]),
        git(&fx.root, &["stash", "list"])
    );
    assert_eq!(
        git(&restore, &["rev-parse", "HEAD"]),
        git(&fx.root, &["rev-parse", "HEAD"])
    );
    assert_eq!(
        git(&restore, &["log", "--oneline", "--all"]),
        git(&fx.root, &["log", "--oneline", "--all"])
    );
    assert_eq!(
        git(&restore, &["diff", "--cached"]),
        git(&fx.root, &["diff", "--cached"])
    );
    assert!(!git(&restore, &["for-each-ref"]).contains(PSEUDO_REF_PREFIX));
    let wt_tree =
        &small.manifest.manifest.sections.git.refs[sealant_capture::manifest::WORKTREE_TREE_REF];
    assert!(!git(&fx.root, &["ls-tree", "--name-only", wt_tree]).contains(".sealantd"));
    assert!(git(&fx.root, &["ls-tree", "--name-only", wt_tree]).contains("notes.md"));

    let tree_diff = diff_r(&fx.root, &restore, &[".git", ".sealantd"]);
    assert!(tree_diff.is_empty(), "tree differs:\n{tree_diff}");
    let home_diff = diff_r(&fx.home, &home2, &[".credentials.json", "state.db-shm"]);
    assert!(home_diff.is_empty(), "harness home differs:\n{home_diff}");

    // (d) the `.pack` without `.idx` was skipped; the nested repo otherwise came back.
    assert!(restore.join("vendor/x/.git/HEAD").exists());
    assert!(
        !restore
            .join("vendor/x/.git/objects/pack/pack-abc.pack")
            .exists()
    );
    // (e) index.lock excluded; credentials and -shm excluded.
    assert!(fx.root.join(".git/index.lock").exists());
    assert!(!restore.join(".git/index.lock").exists());
    assert!(!home2.join(".claude/.credentials.json").exists());
    assert!(!home2.join("state.db-shm").exists());
    // Hardlink groups materialize as links; mtimes are restored.
    let a = fs::metadata(restore.join("node_modules/pkg1/lib/shared.js")).unwrap();
    let b = fs::metadata(restore.join("node_modules/.pnpm/store/shared.js")).unwrap();
    assert_eq!(a.ino(), b.ino());
    let orig = fs::metadata(fx.root.join("node_modules/pkg3/lib/m3.js")).unwrap();
    let back = fs::metadata(restore.join("node_modules/pkg3/lib/m3.js")).unwrap();
    assert_eq!(
        (orig.mtime(), orig.mtime_nsec()),
        (back.mtime(), back.mtime_nsec())
    );
    assert!(
        fs::symlink_metadata(restore.join("node_modules/.bin/m1"))
            .unwrap()
            .is_symlink()
    );

    // (b) incremental: a 6 KB append ships one or two chunks and no git pack.
    let before_packs = engine
        .previous()
        .unwrap()
        .manifest
        .sections
        .git
        .packs
        .clone();
    let mut f = fs::OpenOptions::new()
        .append(true)
        .open(fx.home.join("transcript.jsonl"))
        .unwrap();
    f.write_all(&transcript_bytes(6 * 1024, 99)).unwrap();
    drop(f);
    let inc = engine
        .snap(SnapRequest {
            kind: CaptureKind::Auto,
            class: Class::Small,
            seq: 3,
        })
        .unwrap();
    assert!(
        inc.stats.chunks_new >= 1 && inc.stats.chunks_new <= 2,
        "chunks_new = {}",
        inc.stats.chunks_new
    );
    assert_eq!(inc.stats.cdc_packs, 1);
    assert_eq!(inc.stats.git_pack_bytes, 0);
    assert_eq!(inc.manifest.manifest.sections.git.packs, before_packs);
    assert_eq!(inc.stats.files_read, 1, "only the transcript is re-read");
    assert_eq!(shipper.ship_pending().unwrap(), 1);
    let head = registrar.head().unwrap();
    assert_eq!(head.n, 2);
    let restore2 = fx.base.join("restore2");
    let m2 = Materializer::new(
        sink.as_ref(),
        MaterializeTargets::new(&restore2, Some(fx.base.join("home3"))),
    );
    m2.materialize(&head.manifest, MaterializeClass::Workspace)
        .unwrap();
    assert_eq!(
        fs::read(fx.base.join("home3/transcript.jsonl")).unwrap(),
        fs::read(fx.home.join("transcript.jsonl")).unwrap()
    );
}

/// (c) torn writes: a writer keeps appending and committing while snaps run; every snap
/// materializes and verifies, or is marked unverified; nothing panics.
#[test]
fn torn_writes_never_break_a_capture() {
    let fx = Fixture::build(50, 200_000);
    fs::remove_file(fx.root.join(".git/index.lock")).unwrap();
    let sink = fx.sink();
    let registrar = Arc::new(InMemoryRegistrar::new("wt-fixture", 1, None));
    let mut engine = CaptureEngine::open(fx.config(1), None).unwrap();
    let stop = Arc::new(AtomicBool::new(false));
    let writer = {
        let stop = stop.clone();
        let root = fx.root.clone();
        let home = fx.home.clone();
        std::thread::spawn(move || {
            let mut i = 0u64;
            while !stop.load(Ordering::Relaxed) {
                let mut f = fs::OpenOptions::new()
                    .append(true)
                    .create(true)
                    .open(root.join("log.txt"))
                    .unwrap();
                f.write_all(format!("line {i}\n").repeat(200).as_bytes())
                    .unwrap();
                drop(f);
                let mut t = fs::OpenOptions::new()
                    .append(true)
                    .open(home.join("transcript.jsonl"))
                    .unwrap();
                t.write_all(&transcript_bytes(3000, i)).unwrap();
                drop(t);
                fs::write(home.join("state.db-wal"), pseudo_random(20_000, i)).unwrap();
                let _ = Command::new("git")
                    .current_dir(&root)
                    .args(["add", "log.txt"])
                    .output();
                let _ = Command::new("git")
                    .current_dir(&root)
                    .args(["commit", "-q", "-m", &format!("c{i}")])
                    .output();
                i += 1;
                std::thread::sleep(Duration::from_millis(3));
            }
            i
        })
    };
    let shipper = engine.shipper(sink.clone(), registrar.clone());
    let mut verified = 0;
    for seq in 0..6u64 {
        let staged = engine
            .snap(SnapRequest {
                kind: CaptureKind::Turn,
                class: Class::Small,
                seq,
            })
            .unwrap();
        shipper.ship_pending().unwrap();
        let head = registrar.head().unwrap();
        assert_eq!(head.capture_id, staged.manifest.capture_id);
        let restore = fx.base.join(format!("restore-{seq}"));
        let m = Materializer::new(
            sink.as_ref(),
            MaterializeTargets::new(&restore, Some(fx.base.join(format!("home-{seq}")))),
        );
        let report = m
            .materialize(&head.manifest, MaterializeClass::All)
            .unwrap();
        let fsck = report.fsck.unwrap();
        let marked = staged.manifest.manifest.sections.git.fsck;
        assert!(
            fsck == FsckStatus::Verified || marked == FsckStatus::Unverified,
            "snap {seq}: restore fsck {fsck:?}, manifest fsck {marked:?}"
        );
        if fsck == FsckStatus::Verified {
            verified += 1;
        }
        std::thread::sleep(Duration::from_millis(20));
    }
    stop.store(true, Ordering::Relaxed);
    let commits = writer.join().unwrap();
    assert!(commits > 3, "writer made {commits} commits");
    assert!(verified >= 1);
}

/// (f) CDC packs spill into a second pack past the 64 MiB cap and still materialize.
#[test]
fn packs_spill_past_the_cap() {
    let fx = Fixture::build(10, 1000);
    fs::write(fx.home.join("big.bin"), pseudo_random(70 * 1024 * 1024, 42)).unwrap();
    let sink = fx.sink();
    let registrar = Arc::new(InMemoryRegistrar::new("wt-fixture", 1, None));
    let mut engine = CaptureEngine::open(fx.config(1), None).unwrap();
    let staged = engine
        .snap(SnapRequest {
            kind: CaptureKind::Auto,
            class: Class::Small,
            seq: 1,
        })
        .unwrap();
    assert!(
        staged.stats.cdc_packs >= 2,
        "packs = {}",
        staged.stats.cdc_packs
    );
    let objects = engine.staging().objects_dir();
    for u in &engine.staging().pending().unwrap()[0].uploads {
        let len = fs::metadata(objects.join(&u.file)).unwrap().len();
        assert!(len <= 64 * 1024 * 1024, "{} is {len} bytes", u.file);
    }
    let packs: HashSet<_> = staged
        .manifest
        .manifest
        .sections
        .workspace
        .packs
        .iter()
        .cloned()
        .collect();
    assert!(packs.len() >= 2);
    engine
        .shipper(sink.clone(), registrar.clone())
        .ship_pending()
        .unwrap();
    let head = registrar.head().unwrap();
    let home2 = fx.base.join("home2");
    Materializer::new(
        sink.as_ref(),
        MaterializeTargets::new(&fx.base.join("restore"), Some(home2.clone())),
    )
    .materialize(&head.manifest, MaterializeClass::Workspace)
    .unwrap();
    assert_eq!(
        fs::read(home2.join("big.bin")).unwrap(),
        fs::read(fx.home.join("big.bin")).unwrap()
    );
}

/// Fencing: a bumped epoch stops shipping; a reopened engine under a new epoch re-uploads
/// under its own prefix and continues the chain from the plan's head.
#[test]
fn fence_stops_shipping_and_a_new_epoch_continues_the_chain() {
    let fx = Fixture::build(20, 50_000);
    fs::remove_file(fx.root.join(".git/index.lock")).unwrap();
    let sink = fx.sink();
    let registrar = Arc::new(InMemoryRegistrar::new("wt-fixture", 1, None));
    let mut engine = CaptureEngine::open(fx.config(1), None).unwrap();
    engine
        .snap(SnapRequest {
            kind: CaptureKind::Auto,
            class: Class::Small,
            seq: 1,
        })
        .unwrap();
    let shipper = engine.shipper(sink.clone(), registrar.clone());
    shipper.ship_pending().unwrap();
    registrar.set_live_epoch(2);
    fs::write(fx.root.join("more.txt"), "x").unwrap();
    engine
        .snap(SnapRequest {
            kind: CaptureKind::Auto,
            class: Class::Small,
            seq: 2,
        })
        .unwrap();
    assert!(matches!(
        shipper.ship_pending(),
        Err(sealant_capture::ship::ShipError::Fenced(_))
    ));
    assert!(shipper.is_fenced());
    assert_eq!(engine.staging().pending().unwrap().len(), 1);

    // The replacement executor: epoch 2, seeded from the plan head.
    let plan = registrar
        .plan_get(&sealant_capture::registrar::PlanGetRequest {
            worktree_id: None,
            epoch: 2,
        })
        .unwrap();
    assert_eq!(plan.worktree_id, "wt-fixture");
    let head = plan.head.unwrap();
    let mut cfg = fx.config(2);
    cfg.staging_dir = Some(fx.base.join("staging2"));
    let mut engine2 = CaptureEngine::open(cfg, Some(head.manifest.clone().encode())).unwrap();
    let staged = engine2
        .snap(SnapRequest {
            kind: CaptureKind::Auto,
            class: Class::Small,
            seq: 3,
        })
        .unwrap();
    assert_eq!(staged.manifest.manifest.epoch, 2);
    assert_eq!(
        staged.manifest.manifest.parent.as_deref(),
        Some(head.capture_id.as_str())
    );
    assert!(
        staged
            .manifest
            .manifest
            .sections
            .workspace
            .packs
            .iter()
            .all(|k| k.starts_with("captures/wt-fixture/2/"))
    );
    assert!(
        staged
            .manifest
            .manifest
            .sections
            .git
            .packs
            .iter()
            .any(|k| k.starts_with("captures/wt-fixture/1/"))
    );
    engine2
        .shipper(sink.clone(), registrar.clone())
        .ship_pending()
        .unwrap();
    assert_eq!(registrar.head().unwrap().n, 1);
    let restore = fx.base.join("restore");
    let m = Materializer::new(sink.as_ref(), MaterializeTargets::new(&restore, None));
    let report = m
        .materialize(&registrar.head().unwrap().manifest, MaterializeClass::Git)
        .unwrap();
    assert_eq!(report.fsck, Some(FsckStatus::Verified));
    assert_eq!(fs::read_to_string(restore.join("more.txt")).unwrap(), "x");
}
