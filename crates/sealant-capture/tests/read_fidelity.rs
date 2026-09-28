//! What a capture reads is what is on disk: every file under a class root is carried whatever it
//! is called (only git's own transient files inside a git directory are not), local git-lfs
//! objects included; a file that cannot be read is never a deletion; a same-size overwrite
//! that restores the mtime is still seen; names and symlink text that are not UTF-8 come back
//! byte for byte. Each test snaps a real repository, ships to a local store, materializes a
//! fresh directory from the registered head and compares bytes.
//!
//! Observed before the fix (adversarial review findings 9, 10, 12 and the lossy-name risk):
//! an ignored `Cargo.lock` and a local-only `.git/lfs` object missing after a successful final
//! flush; a previously captured file made unreadable missing from the next restore; a
//! same-size edit with its mtime put back reported `unchanged`; two non-UTF-8 names merged
//! into one.

use std::ffi::OsStr;
use std::fs::{self, File, FileTimes};
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::Arc;
use std::time::{Duration, SystemTime};

use sealant_capture::{
    BlobSink, CaptureConfig, CaptureEngine, CaptureKind, Class, InMemoryRegistrar, LocalDir,
    MaterializeClass, MaterializeTargets, Materializer, Registrar, SnapRequest,
};

fn git(root: &Path, args: &[&str]) -> String {
    let out = Command::new("git")
        .current_dir(root)
        .args(args)
        .output()
        .expect("git");
    assert!(
        out.status.success(),
        "git {args:?}: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    String::from_utf8_lossy(&out.stdout).trim().to_owned()
}

struct Fixture {
    _tmp: tempfile::TempDir,
    base: PathBuf,
    source: PathBuf,
    sink: Arc<LocalDir>,
    registrar: Arc<InMemoryRegistrar>,
}

impl Fixture {
    /// A repository ignoring `ignored/`, `*.log` and `*.bin`, with one commit.
    fn new() -> Self {
        let tmp = tempfile::tempdir().unwrap();
        let base = tmp.path().to_path_buf();
        let source = base.join("source");
        fs::create_dir_all(source.join("ignored")).unwrap();
        git(&source, &["init", "-q", "-b", "main"]);
        git(&source, &["config", "user.email", "t@t"]);
        git(&source, &["config", "user.name", "t"]);
        fs::write(
            source.join(".gitignore"),
            "ignored/\n*.log\n*.bin\nnode_modules/\n",
        )
        .unwrap();
        fs::write(source.join("tracked"), b"tracked\n").unwrap();
        git(&source, &["add", "-A"]);
        git(&source, &["commit", "-q", "-m", "base"]);
        let sink = Arc::new(LocalDir::new(&base.join("store")).unwrap());
        let registrar = Arc::new(InMemoryRegistrar::new("wt", 1, None));
        Self {
            _tmp: tmp,
            base,
            source,
            sink,
            registrar,
        }
    }

    fn engine(&self, racy_window: Duration) -> CaptureEngine {
        let mut config = CaptureConfig::new("wt", 1, &self.source);
        config.racy_window = racy_window;
        CaptureEngine::open(config, None).unwrap()
    }

    fn snap(
        &self,
        engine: &mut CaptureEngine,
        kind: CaptureKind,
        class: Class,
        seq: u64,
    ) -> Result<sealant_capture::StagedCapture, sealant_capture::EngineError> {
        engine.snap(SnapRequest { kind, class, seq })
    }

    fn ship(&self, engine: &CaptureEngine) {
        let sink: Arc<dyn BlobSink> = self.sink.clone();
        let registrar: Arc<dyn Registrar> = self.registrar.clone();
        engine.shipper(sink, registrar).ship_pending().unwrap();
    }

    /// Materialize the registered head into a fresh directory.
    fn restore(&self, name: &str) -> PathBuf {
        let head = self.registrar.head().unwrap();
        let out = self.base.join(name);
        Materializer::new(self.sink.as_ref(), MaterializeTargets::new(&out, None))
            .materialize(&head.manifest, MaterializeClass::All)
            .unwrap();
        out
    }
}

/// Whether permission bits bind this process (they do not for root).
fn permissions_bind(dir: &Path) -> bool {
    let probe = dir.join("probe");
    fs::write(&probe, b"p").unwrap();
    fs::set_permissions(&probe, fs::Permissions::from_mode(0o000)).unwrap();
    let binds = File::open(&probe).is_err();
    fs::set_permissions(&probe, fs::Permissions::from_mode(0o600)).unwrap();
    fs::remove_file(&probe).unwrap();
    binds
}

fn set_mtime(path: &Path, mtime: SystemTime) {
    File::options()
        .write(true)
        .open(path)
        .unwrap()
        .set_times(FileTimes::new().set_modified(mtime))
        .unwrap();
}

/// Finding 9: a user's `*.lock`, `*.pid`, `-shm` and `.pack` files, and a git-lfs object that
/// exists only in this repository, are restored byte for byte by a final capture.
#[test]
fn user_lock_pid_shm_files_and_local_lfs_objects_are_restored() {
    let fx = Fixture::new();
    let s = &fx.source;
    let user_files: &[(&str, &[u8])] = &[
        ("ignored/Cargo.lock", b"legitimate ignored lock bytes\n"),
        ("ignored/tmp/server.pid", b"4242\n"),
        ("ignored/state.db-shm", b"shm bytes"),
        ("ignored/export.pack", b"a user's pack, no idx"),
        ("app.log", b"log line\n"),
        (
            ".git/lfs/objects/9f/86/9f86d081884c7d659a2feaa0c55ad015",
            b"local-only lfs bytes\n",
        ),
        ("node_modules/pkg/yarn.lock", b"bulk lock\n"),
    ];
    for (rel, bytes) in user_files {
        let path = s.join(rel);
        fs::create_dir_all(path.parent().unwrap()).unwrap();
        fs::write(path, bytes).unwrap();
    }
    let mut engine = fx.engine(Duration::ZERO);
    fx.snap(&mut engine, CaptureKind::Final, Class::Small, 1)
        .unwrap();
    fx.snap(&mut engine, CaptureKind::Final, Class::Bulk, 2)
        .unwrap();
    fx.ship(&engine);
    let out = fx.restore("restored");
    for (rel, bytes) in user_files {
        assert_eq!(
            fs::read(out.join(rel)).ok().as_deref(),
            Some(*bytes),
            "{rel} restored"
        );
    }
}

/// Finding 10: a file the capture has read before and can no longer read is carried (an
/// automatic capture restores its last read bytes) and fails a final capture, which names it.
/// A directory git cannot open fails a final capture too; its ignored files are carried.
#[test]
fn unreadable_work_is_carried_and_fails_a_final_capture() {
    let fx = Fixture::new();
    if !permissions_bind(&fx.base) {
        eprintln!("skipped: permission bits do not bind this process");
        return;
    }
    let s = &fx.source;
    fs::write(s.join("ignored/unreadable"), b"KEEP").unwrap();
    fs::create_dir_all(s.join("sec")).unwrap();
    fs::write(
        s.join("sec/a.log"),
        b"ignored inside a dir git will not open\n",
    )
    .unwrap();
    let mut engine = fx.engine(Duration::ZERO);
    fx.snap(&mut engine, CaptureKind::Turn, Class::Small, 1)
        .unwrap();
    fx.ship(&engine);

    let unreadable = s.join("ignored/unreadable");
    set_mtime(&unreadable, SystemTime::now() + Duration::from_secs(1));
    fs::set_permissions(&unreadable, fs::Permissions::from_mode(0o000)).unwrap();
    fs::set_permissions(s.join("sec"), fs::Permissions::from_mode(0o000)).unwrap();

    let fin = fx.snap(&mut engine, CaptureKind::Final, Class::Small, 2);
    let turn = fx.snap(&mut engine, CaptureKind::Turn, Class::Small, 3);
    fs::set_permissions(s.join("sec"), fs::Permissions::from_mode(0o755)).unwrap();
    fs::set_permissions(&unreadable, fs::Permissions::from_mode(0o600)).unwrap();

    let err = fin.expect_err("a final capture that cannot read work fails");
    let text = err.to_string();
    assert!(
        text.contains("tree/ignored/unreadable") && text.contains("tree/sec"),
        "{text}"
    );
    turn.expect("an automatic capture carries what it cannot read");
    fx.ship(&engine);
    let out = fx.restore("restored");
    let restored = out.join("ignored/unreadable");
    let meta = fs::symlink_metadata(&restored).expect("carried, never deleted");
    assert_eq!(
        meta.permissions().mode() & 0o7777,
        0o000,
        "with its mode now"
    );
    fs::set_permissions(&restored, fs::Permissions::from_mode(0o600)).unwrap();
    assert_eq!(
        fs::read(&restored).unwrap(),
        b"KEEP",
        "and its last read bytes"
    );
    // The worktree metadata overlay restores the directory's mode as it was when captured.
    let sec = out.join("sec");
    assert_eq!(
        fs::symlink_metadata(&sec).unwrap().permissions().mode() & 0o7777,
        0o000,
        "the directory with its mode now"
    );
    fs::set_permissions(&sec, fs::Permissions::from_mode(0o755)).unwrap();
    assert_eq!(
        fs::read(out.join("sec/a.log")).ok().as_deref(),
        Some(&b"ignored inside a dir git will not open\n"[..])
    );
}

/// Finding 12: overwrite `AAAA` with `BBBB` on the same inode and put the mtime back; the next
/// capture holds `BBBB` (the ctime moved), with no racy window to help.
#[test]
fn a_same_size_edit_with_the_mtime_restored_is_captured() {
    let fx = Fixture::new();
    let state = fx.source.join("ignored/state");
    fs::write(&state, b"AAAA").unwrap();
    let mut engine = fx.engine(Duration::ZERO);
    fx.snap(&mut engine, CaptureKind::Turn, Class::Small, 1)
        .unwrap();
    let mtime = fs::metadata(&state).unwrap().modified().unwrap();
    std::thread::sleep(Duration::from_millis(20));
    fs::write(&state, b"BBBB").unwrap();
    set_mtime(&state, mtime);
    let second = fx
        .snap(&mut engine, CaptureKind::Auto, Class::Small, 2)
        .unwrap();
    assert!(!second.unchanged, "the edit is a change");
    fx.ship(&engine);
    let out = fx.restore("restored");
    assert_eq!(fs::read(out.join("ignored/state")).unwrap(), b"BBBB");
}

/// Names and symlink text that are not UTF-8 are restored byte for byte, and two names a lossy
/// conversion would merge stay two files.
#[test]
fn names_and_symlink_text_that_are_not_utf8_round_trip() {
    let fx = Fixture::new();
    let s = &fx.source;
    let a = s.join(OsStr::from_bytes(b"ignored/caf\xe9"));
    let b = s.join(OsStr::from_bytes(b"ignored/caf\xe8"));
    let top = s.join(OsStr::from_bytes(b"na\xefve.bin"));
    fs::write(&a, b"one").unwrap();
    fs::write(&b, b"two").unwrap();
    fs::write(&top, b"top").unwrap();
    std::os::unix::fs::symlink(OsStr::from_bytes(b"caf\xe9"), s.join("ignored/link")).unwrap();
    let mut engine = fx.engine(Duration::ZERO);
    fx.snap(&mut engine, CaptureKind::Final, Class::Small, 1)
        .unwrap();
    fx.ship(&engine);
    let out = fx.restore("restored");
    assert_eq!(
        fs::read(out.join(OsStr::from_bytes(b"ignored/caf\xe9"))).unwrap(),
        b"one"
    );
    assert_eq!(
        fs::read(out.join(OsStr::from_bytes(b"ignored/caf\xe8"))).unwrap(),
        b"two"
    );
    assert_eq!(
        fs::read(out.join(OsStr::from_bytes(b"na\xefve.bin"))).unwrap(),
        b"top"
    );
    assert_eq!(
        fs::read_link(out.join("ignored/link"))
            .unwrap()
            .as_os_str()
            .as_bytes(),
        b"caf\xe9"
    );
}

/// A worktree with an untracked, non-ignored directory (`un/`) and a tracked one (`tr/`, its
/// file edited and never staged), captured once.
fn worktree_with_dirs(fx: &Fixture) -> CaptureEngine {
    let s = &fx.source;
    fs::create_dir_all(s.join("un/deep")).unwrap();
    fs::write(s.join("un/u"), b"untracked work\n").unwrap();
    fs::write(s.join("un/deep/d"), b"deeper\n").unwrap();
    fs::create_dir_all(s.join("tr")).unwrap();
    fs::write(s.join("tr/a"), b"committed\n").unwrap();
    git(s, &["add", "tr/a"]);
    git(s, &["commit", "-q", "-m", "tr"]);
    fs::write(s.join("tr/a"), b"edited, never staged\n").unwrap();
    let mut engine = fx.engine(Duration::ZERO);
    fx.snap(&mut engine, CaptureKind::Turn, Class::Small, 1)
        .unwrap();
    fx.ship(&engine);
    engine
}

fn set_mode(paths: &[PathBuf], mode: u32) {
    for p in paths {
        fs::set_permissions(p, fs::Permissions::from_mode(mode)).unwrap();
    }
}

/// `git add -A` skips a directory it cannot open with a warning: an untracked one dropped out
/// of the worktree tree, a tracked one fell back to the index's blob instead of the edit the
/// last capture held. An automatic capture now gives both the previous capture's entries and
/// counts them in its stats; neither is a deletion.
#[test]
fn an_unreadable_worktree_directory_is_carried_from_the_previous_capture() {
    let fx = Fixture::new();
    if !permissions_bind(&fx.base) {
        eprintln!("skipped: permission bits do not bind this process");
        return;
    }
    let mut engine = worktree_with_dirs(&fx);
    let s = &fx.source;
    let locked = [s.join("un"), s.join("tr")];
    // What the metadata overlay read of `tr/a` at the first capture; the next one cannot read
    // it and keeps that entry.
    let captured_mtime = fs::metadata(s.join("tr/a")).unwrap().modified().unwrap();
    set_mode(&locked, 0o000);
    fs::write(s.join("other"), b"a change elsewhere\n").unwrap();
    let turn = fx.snap(&mut engine, CaptureKind::Turn, Class::Small, 2);
    set_mode(&locked, 0o755);
    let turn = turn.expect("an automatic capture carries what it cannot read");
    assert_eq!(turn.stats.unreadable, 2, "{:?}", turn.stats);
    assert_eq!(turn.stats.carried, 2, "{:?}", turn.stats);
    assert_eq!(turn.stats.unreadable_paths, vec!["tree/tr", "tree/un"]);
    fx.ship(&engine);
    let out = fx.restore("restored");
    // The worktree metadata overlay restores both directories with the mode they had.
    let restored = [out.join("un"), out.join("tr")];
    for dir in &restored {
        let mode = fs::symlink_metadata(dir).unwrap().permissions().mode() & 0o7777;
        assert_eq!(mode, 0o000, "{} with its mode now", dir.display());
    }
    set_mode(&restored, 0o755);
    assert_eq!(
        fs::metadata(out.join("tr/a")).unwrap().modified().unwrap(),
        captured_mtime,
        "the overlay's entry for a path it cannot read is carried, not dropped"
    );
    assert_eq!(fs::read(out.join("un/u")).unwrap(), b"untracked work\n");
    assert_eq!(fs::read(out.join("un/deep/d")).unwrap(), b"deeper\n");
    assert_eq!(
        fs::read(out.join("tr/a")).unwrap(),
        b"edited, never staged\n",
        "the last captured edit, not the index's blob"
    );
    assert_eq!(
        fs::read(out.join("other")).unwrap(),
        b"a change elsewhere\n"
    );
}

/// A final capture that cannot read a worktree directory fails naming it, stages nothing, and
/// leaves the chain whole: the next capture's git pack still holds every object it needs (the
/// failed snap's tips once became the next pack's negatives, so a restore of the next capture
/// could not read its own blobs).
#[test]
fn a_final_capture_fails_on_an_unreadable_worktree_directory_and_the_chain_stays_whole() {
    let fx = Fixture::new();
    if !permissions_bind(&fx.base) {
        eprintln!("skipped: permission bits do not bind this process");
        return;
    }
    let mut engine = worktree_with_dirs(&fx);
    let s = &fx.source;
    let locked = [s.join("un"), s.join("tr")];
    set_mode(&locked, 0o000);
    fs::write(s.join("other"), b"a change elsewhere\n").unwrap();
    let fin = fx.snap(&mut engine, CaptureKind::Final, Class::Small, 2);
    set_mode(&locked, 0o755);
    let text = fin
        .expect_err("a final capture that cannot read work fails")
        .to_string();
    assert!(
        text.contains("tree/un") && text.contains("tree/tr"),
        "{text}"
    );
    fx.snap(&mut engine, CaptureKind::Turn, Class::Small, 3)
        .unwrap();
    fx.ship(&engine);
    let out = fx.restore("restored");
    assert_eq!(
        fs::read(out.join("other")).unwrap(),
        b"a change elsewhere\n"
    );
    assert_eq!(fs::read(out.join("un/u")).unwrap(), b"untracked work\n");
}
