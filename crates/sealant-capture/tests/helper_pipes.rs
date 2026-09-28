//! Every git the capture feeds on stdin is fed while its answers are read.
//!
//! Docker end to end, round 8 (F1): `GitRepo::run_with_stdin` wrote all of its input before it
//! read a byte of the answer. `git cat-file --batch-check` answers each name as it reads it, so
//! once the answers filled the stdout pipe git stopped reading, the question filled the stdin
//! pipe, and both sides waited on each other for good. In a container whose root is over
//! `fs.pipe-user-pages-soft` a pipe is 8 KiB, and 1,349 cached raw-tree blobs (55 KB of names)
//! were enough: no capture after the first, for 17 minutes, with a status that said nothing.
//! With 64 KiB pipes it takes a few thousand names. These tests ask far more than any pipe
//! holds, so they deadlock on every host before the fix; each runs on its own thread with a
//! bound, so a deadlock fails the test instead of hanging the suite.

use std::fs;
use std::path::Path;
use std::process::Command;
use std::sync::mpsc;
use std::time::Duration;

use sealant_capture::gitpack::GitRepo;
use sealant_capture::{CaptureConfig, CaptureEngine, CaptureKind, Class, SnapRequest};

/// Far longer than any of these takes when git is read while it is fed.
const BOUND: Duration = Duration::from_secs(120);

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

/// Run `work` on its own thread; its result, or a failure naming `what` once [`BOUND`] passed.
fn bounded<T: Send + 'static>(what: &str, work: impl FnOnce() -> T + Send + 'static) -> T {
    let (tx, rx) = mpsc::channel();
    std::thread::spawn(move || {
        let _ = tx.send(work());
    });
    rx.recv_timeout(BOUND)
        .unwrap_or_else(|_| panic!("{what}: no answer within {BOUND:?} (a pipe deadlock)"))
}

fn repo(root: &Path) {
    fs::create_dir_all(root).unwrap();
    git(root, &["init", "-q", "-b", "main"]);
    git(root, &["config", "user.email", "t@t"]);
    git(root, &["config", "user.name", "t"]);
}

/// `existing` asks `cat-file --batch-check` about every name at once: 40,000 names are 1.6 MB
/// of question and 2 MB of answer, more than any pipe on any host holds.
#[test]
fn a_batch_check_larger_than_any_pipe_is_answered() {
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path().join("ws");
    repo(&root);
    fs::write(root.join("a.txt"), "a\n").unwrap();
    git(&root, &["add", "-A"]);
    git(&root, &["commit", "-q", "-m", "one"]);
    let head = String::from_utf8(
        Command::new("git")
            .current_dir(&root)
            .args(["rev-parse", "HEAD"])
            .output()
            .unwrap()
            .stdout,
    )
    .unwrap()
    .trim()
    .to_owned();
    let mut names: Vec<String> = (0..40_000u32).map(|i| format!("{i:040x}")).collect();
    names.push(head.clone());
    let repo = GitRepo::open(&root).unwrap();
    let present = bounded("existing() over 40,001 names", move || {
        repo.existing(&names)
    });
    assert_eq!(
        present.unwrap(),
        vec![head],
        "only the one real object is present"
    );
}

/// The snap that stopped in the end to end run: the second small snap asks which of the
/// cached raw-tree blobs the object store still holds (one name per tracked file). Six
/// thousand tracked files are enough on a host with 64 KiB pipes.
#[test]
fn a_snap_over_thousands_of_cached_raw_blobs_finishes() {
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path().join("ws");
    repo(&root);
    for d in 0..60 {
        let dir = root.join(format!("src/d{d:02}"));
        fs::create_dir_all(&dir).unwrap();
        for f in 0..100 {
            fs::write(dir.join(format!("f{f:03}.rs")), format!("// {d} {f}\n")).unwrap();
        }
    }
    git(&root, &["add", "-A"]);
    git(&root, &["commit", "-q", "-m", "six thousand files"]);
    // Older than the raw blob cache's racy window, so the first snap remembers every blob and
    // the second asks the object store about each of them.
    std::thread::sleep(Duration::from_millis(2_100));
    let config = CaptureConfig::new("wt", 1, &root);
    let edited = root.join("src/d00/f000.rs");
    let staged = bounded("two small snaps over 6,000 tracked files", move || {
        let mut engine = CaptureEngine::open(config, None).unwrap();
        let snap = |engine: &mut CaptureEngine, seq| {
            engine.snap(SnapRequest {
                kind: CaptureKind::Auto,
                class: Class::Small,
                seq,
            })
        };
        let first = snap(&mut engine, 1).map(|s| s.unchanged);
        fs::write(&edited, "// edited\n").unwrap();
        let second = snap(&mut engine, 2).map(|s| s.unchanged);
        (first, second)
    });
    let (first, second) = staged;
    assert!(!first.unwrap(), "the first snap stages the tree");
    assert!(!second.unwrap(), "the second snap stages the edit");
}
