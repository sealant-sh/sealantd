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
