//! A hard kill before ext4 wrote back the newest loose objects leaves them as empty files
//! (Milestone 1, Gate 3: `docker kill` of a host-vm workspace seconds after an edit, a `git
//! commit` or a capture). The edited files were synced and are on the disk; the objects git had
//! made of them are not. Git takes an empty object as present, so a recovery's final flush
//! failed in `pack-objects` ("object file … is empty"), was `snapshot-failed`, and the saved
//! edit was never recovered. A final flush over such a repository now completes and restores
//! every file of the worktree byte for byte.

use std::fs::{self, File};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::Arc;

use sealant_capture::{
    CadenceRunner, CaptureConfig, CaptureEngine, CaptureKind, InMemoryRegistrar, LocalDir,
    MaterializeClass, MaterializeTargets, Materializer, Registrar,
};
use sealant_process::CommandGateExt;

fn git(root: &Path, args: &[&str]) -> String {
    let out = Command::new("git")
        .current_dir(root)
        .env("GIT_OPTIONAL_LOCKS", "0")
        .args(args)
        .stdin(Stdio::null())
        .output_gated()
        .expect("git");
    assert!(
        out.status.success(),
        "git {args:?} failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    String::from_utf8(out.stdout).unwrap().trim().to_owned()
}

/// Replace the loose object `id` with an empty file, as a hard kill before writeback leaves it.
fn tear(root: &Path, id: &str) {
    let path = root.join(".git/objects").join(&id[..2]).join(&id[2..]);
    fs::remove_file(&path).unwrap_or_else(|e| panic!("{id} is not loose: {e}"));
    File::create(&path).unwrap();
}

/// The empty loose objects under `root`'s object store.
fn empty_objects(root: &Path) -> Vec<PathBuf> {
    walkdir::WalkDir::new(root.join(".git/objects"))
        .into_iter()
        .map(Result::unwrap)
        .filter(|e| e.file_type().is_file() && e.metadata().unwrap().len() == 0)
        .map(|e| e.path().to_path_buf())
        .collect()
}

/// Every file under `dir` with its bytes, sorted; `.sealantd` and `.git` left out.
fn files(dir: &Path) -> Vec<(String, Vec<u8>)> {
    let mut out: Vec<(String, Vec<u8>)> = walkdir::WalkDir::new(dir)
        .into_iter()
        .filter_entry(|e| e.file_name() != ".sealantd" && e.file_name() != ".git")
        .map(Result::unwrap)
        .filter(|e| e.file_type().is_file())
        .map(|e| {
            (
                e.path().strip_prefix(dir).unwrap().display().to_string(),
                fs::read(e.path()).unwrap(),
            )
        })
        .collect();
    out.sort();
    out
}

struct Fixture {
    _tmp: tempfile::TempDir,
    base: PathBuf,
    root: PathBuf,
    store: Arc<LocalDir>,
    registrar: Arc<InMemoryRegistrar>,
}

impl Fixture {
    fn new() -> Self {
        let tmp = tempfile::tempdir().unwrap();
        let base = tmp.path().to_path_buf();
        let root = base.join("ws");
        fs::create_dir_all(root.join("src")).unwrap();
        git(&root, &["init", "-q", "-b", "main"]);
        git(&root, &["config", "user.email", "t@t"]);
        git(&root, &["config", "user.name", "t"]);
        fs::write(root.join("src/edit.txt"), "first\n").unwrap();
        fs::write(root.join("src/keep.txt"), "kept\n").unwrap();
        git(&root, &["add", "-A"]);
        git(&root, &["commit", "-q", "-m", "one"]);
        Self {
            store: Arc::new(LocalDir::new(&base.join("store")).unwrap()),
            registrar: Arc::new(InMemoryRegistrar::new("wt", 1, None)),
            _tmp: tmp,
            base,
            root,
        }
    }

    /// A runner over the staging the disk holds, resuming from the registered head when there
    /// is one: what a recovery boot opens.
    fn runner(&self) -> CadenceRunner {
        self.runner_at(&self.root)
    }

    /// [`Self::runner`] over the workspace at `root`: a restored disk picked up.
    fn runner_at(&self, root: &Path) -> CadenceRunner {
        let previous = self.registrar.head().map(|h| h.manifest.encode());
        let engine = CaptureEngine::open(CaptureConfig::new("wt", 1, root), previous).unwrap();
        let registrar: Arc<dyn Registrar> = self.registrar.clone();
        let shipper = Arc::new(engine.shipper(self.store.clone(), registrar));
        CadenceRunner::new(engine, shipper)
    }

    /// The registered head, restored into a fresh directory.
    fn restore(&self, name: &str) -> PathBuf {
        let into = self.base.join(name);
        Materializer::new(self.store.as_ref(), MaterializeTargets::new(&into, None))
            .materialize(
                &self.registrar.head().unwrap().manifest,
                MaterializeClass::All,
            )
            .unwrap();
        into
    }

    /// The index made newer than every file, so its entries are clean by stat (not racily
    /// clean) and `git add` trusts the blobs they name: a kill seconds after the index was
    /// written, as on a real disk.
    fn index_after_the_files(&self) {
        let index = self.root.join(".git/index");
        let later = std::time::SystemTime::now() + std::time::Duration::from_secs(5);
        File::options()
            .write(true)
            .open(&index)
            .unwrap()
            .set_modified(later)
            .unwrap();
    }
}

/// A fresh boot opens a workspace where an empty loose object sits right before its first
/// capture: the blob of the edit an earlier snap's `git add` wrote, torn by the kill. The final
/// flush removes it, writes it again from the file and completes.
#[test]
fn a_final_flush_over_an_empty_loose_object_completes() {
    let fx = Fixture::new();
    fs::write(fx.root.join("src/edit.txt"), "saved, then killed\n").unwrap();
    let blob = git(&fx.root, &["hash-object", "-w", "src/edit.txt"]);
    tear(&fx.root, &blob);
    assert_eq!(empty_objects(&fx.root).len(), 1);

    let runner = fx.runner();
    let flushed = runner.flush_final(None);
    assert!(flushed.complete(), "{flushed:?}");
    assert!(empty_objects(&fx.root).is_empty());
    let restored = fx.restore("restored");
    assert_eq!(files(&restored), files(&fx.root));
    assert_eq!(
        fs::read(restored.join("src/edit.txt")).unwrap(),
        b"saved, then killed\n"
    );
}

/// The Gate 3 hard kill, end to end. A workspace captured as it ran (automatic captures
/// registered); then an edit, a capture's `git add` of it, a `git commit`, more edits and a
/// new file, and a kill before writeback: every object the commit and the capture wrote is
/// empty, the branch and the index name the lost ones, the files are on disk. A new engine
/// over the same staging, as the recovery boot opens it, makes a complete final flush, and the
/// head restores every file byte for byte.
#[test]
fn a_recovery_final_flush_after_a_hard_kill_restores_every_file() {
    let fx = Fixture::new();
    let running = fx.runner();
    running.flush(CaptureKind::Checkpoint, None).unwrap();
    running.stop();
    drop(running);
    let captured = fx.registrar.chain().len();
    assert!(captured > 0, "the running workspace was captured");

    // The work after the last capture.
    fs::write(fx.root.join("src/edit.txt"), "committed, then killed\n").unwrap();
    let capture_blob = git(&fx.root, &["hash-object", "-w", "src/edit.txt"]);
    git(&fx.root, &["add", "src/edit.txt"]);
    git(&fx.root, &["commit", "-q", "-m", "two"]);
    let committed = git(
        &fx.root,
        &["rev-list", "--objects", "--no-object-names", "HEAD^..HEAD"],
    );
    fs::write(
        fx.root.join("src/keep.txt"),
        "kept, edited after the commit\n",
    )
    .unwrap();
    fs::write(fx.root.join("src/new.bin"), b"untracked \x00\x01 bytes\n").unwrap();
    fx.index_after_the_files();
    // The kill: none of it written back.
    let mut torn: Vec<&str> = committed.lines().collect();
    if !torn.contains(&capture_blob.as_str()) {
        torn.push(&capture_blob);
    }
    for id in &torn {
        tear(&fx.root, id);
    }
    assert!(
        empty_objects(&fx.root).len() >= 3,
        "commit, tree and blob torn"
    );

    let recovery = fx.runner();
    let flushed = recovery.flush_final(None);
    assert!(flushed.complete(), "{flushed:?}");
    assert!(
        fx.registrar.chain().len() > captured,
        "the recovery registered"
    );
    assert!(empty_objects(&fx.root).is_empty());

    let restored = fx.restore("restored");
    assert_eq!(files(&restored), files(&fx.root));
    for (path, bytes) in [
        ("src/edit.txt", &b"committed, then killed\n"[..]),
        ("src/keep.txt", b"kept, edited after the commit\n"),
        ("src/new.bin", b"untracked \x00\x01 bytes\n"),
    ] {
        assert_eq!(fs::read(restored.join(path)).unwrap(), bytes, "{path}");
    }
}

/// R1 and R2 reviews of #242: a commit the kill left whole whose blob it tore, the file edited
/// again since. The index (its cache tree, and its entry for the file) still names the lost
/// blob. A capture that named the commit's tree as its index tree made every restore fail
/// (`git read-tree …: failed to unpack tree object`); one that carried the index's bytes gave
/// the restored disk an index naming the lost blob, and its next capture, knowing of no crash,
/// failed (`pack-objects: bad object`). The index is now carried rebuilt from the files, the
/// final flush completes, the head restores the latest edit byte for byte, and the restored
/// workspace captures new work that a second restore brings back.
#[test]
fn a_lost_index_tree_is_not_named_and_the_head_restores() {
    let fx = Fixture::new();
    let running = fx.runner();
    running.flush(CaptureKind::Checkpoint, None).unwrap();
    running.stop();
    drop(running);

    fs::write(fx.root.join("src/edit.txt"), "committed\n").unwrap();
    git(&fx.root, &["add", "src/edit.txt"]);
    git(&fx.root, &["commit", "-q", "-m", "two"]);
    let committed = git(&fx.root, &["rev-parse", "HEAD:src/edit.txt"]);
    let lost_tree = git(&fx.root, &["rev-parse", "HEAD^{tree}"]);
    fs::write(
        fx.root.join("src/edit.txt"),
        "edited again after the commit\n",
    )
    .unwrap();
    fx.index_after_the_files();
    tear(&fx.root, &committed);

    let recovery = fx.runner();
    let flushed = recovery.flush_final(None);
    assert!(flushed.complete(), "{flushed:?}");
    recovery.stop();
    drop(recovery);
    let git_section = fx.registrar.head().unwrap().manifest.sections.git;
    assert_ne!(
        git_section.index_tree.as_deref(),
        Some(lost_tree.as_str()),
        "the lost index tree is not named"
    );
    let restored = fx.restore("restored");
    assert_eq!(files(&restored), files(&fx.root));
    assert_eq!(
        fs::read(restored.join("src/edit.txt")).unwrap(),
        b"edited again after the commit\n"
    );
    // The restored index names only what the store holds.
    let staged = git(&restored, &["ls-files", "-s", "src/edit.txt"]);
    let blob = staged.split_whitespace().nth(1).unwrap().to_owned();
    assert_ne!(blob, committed, "{staged}");
    assert_eq!(git(&restored, &["cat-file", "-t", &blob]), "blob");

    // The restored disk, picked up: new work is captured and comes back.
    fs::write(
        restored.join("src/second.txt"),
        "written after the restore\n",
    )
    .unwrap();
    let picked_up = fx.runner_at(&restored);
    picked_up.flush(CaptureKind::Checkpoint, None).unwrap();
    picked_up.stop();
    let again = fx.restore("restored-again");
    assert_eq!(files(&again), files(&restored));
    assert_eq!(
        fs::read(again.join("src/edit.txt")).unwrap(),
        b"edited again after the commit\n"
    );
    assert_eq!(
        fs::read(again.join("src/second.txt")).unwrap(),
        b"written after the restore\n"
    );
}

/// R1 review of #242 (Astra #2): a tip a torn pack left out is no negative of a later one. A
/// side branch's commit is lost; the capture names no ref to it. Its objects come back
/// (fetched again, written again), and the next capture, in a process of its own, packs the
/// commit and names the branch again. Named while it was lost, it would have been a negative
/// of that pack and stayed out of every pack while the capture named it.
#[test]
fn a_lost_tip_that_comes_back_is_packed_not_taken_for_a_negative() {
    let fx = Fixture::new();
    let running = fx.runner();
    running.flush(CaptureKind::Checkpoint, None).unwrap();
    running.stop();
    drop(running);

    git(&fx.root, &["checkout", "-q", "-b", "side"]);
    fs::write(fx.root.join("src/edit.txt"), "committed, lost, back\n").unwrap();
    git(&fx.root, &["commit", "-q", "-am", "two"]);
    let lost = git(&fx.root, &["rev-parse", "HEAD"]);
    let ids = git(
        &fx.root,
        &["rev-list", "--objects", "--no-object-names", "HEAD^..HEAD"],
    );
    git(&fx.root, &["checkout", "-q", "main"]);
    let saved: Vec<(PathBuf, Vec<u8>)> = ids
        .lines()
        .map(|id| {
            let path = fx.root.join(".git/objects").join(&id[..2]).join(&id[2..]);
            let bytes = fs::read(&path).unwrap();
            (path, bytes)
        })
        .collect();
    for id in ids.lines() {
        tear(&fx.root, id);
    }

    let torn = fx.runner();
    torn.flush(CaptureKind::Checkpoint, None).unwrap();
    torn.stop();
    drop(torn);
    let head = fx.registrar.head().unwrap().manifest.sections.git;
    assert!(
        !head.refs.contains_key("refs/heads/side") && head.refs.values().all(|v| *v != lost),
        "no ref names the lost commit: {:?}",
        head.refs
    );

    // The objects come back.
    for (path, bytes) in &saved {
        let _ = fs::remove_file(path);
        fs::write(path, bytes).unwrap();
    }
    let later = fx.runner();
    later.flush(CaptureKind::Checkpoint, None).unwrap();
    later.stop();
    let head = fx.registrar.head().unwrap().manifest.sections.git;
    assert_eq!(
        head.refs.get("refs/heads/side"),
        Some(&lost),
        "{:?}",
        head.refs
    );
    let restored = fx.restore("restored");
    assert_eq!(
        git(&restored, &["cat-file", "-t", &lost]),
        "commit",
        "the commit came back with the capture"
    );
    assert_eq!(
        git(&restored, &["show", &format!("{lost}:src/edit.txt")]),
        "committed, lost, back"
    );
}
