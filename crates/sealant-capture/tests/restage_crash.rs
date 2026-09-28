//! A small capture staged ahead of a queued bulk capture moves two queue entries: the bulk
//! capture is written again at `n + 1` with the small capture as its parent, and the small
//! capture takes the bulk capture's old slot. A process that died between those two renames
//! left a bulk capture naming a parent no entry held: it could never register, and nothing
//! staged after it could either (review risk "small-ahead-of-bulk restaging is not
//! crash-atomic"). The restage is now one journaled step. These tests kill it after each of its
//! steps — the journal written, the journal committed, each queue file, the sweep — reopen the
//! engine as a restarted daemon would, and ship: every capture registers, and the head restores
//! the edit and the dependency tree byte for byte.

use std::fs;
use std::path::Path;
use std::process::Command;
use std::sync::Arc;
use std::time::Duration;

use sealant_capture::{
    BlobSink, CaptureConfig, CaptureEngine, CaptureKind, Class, InMemoryRegistrar, LocalDir,
    MaterializeClass, MaterializeTargets, Materializer, Registrar, SnapRequest,
};

/// Steps a restage takes: journal written, committed, the bulk capture's queue file, the small
/// capture's queue file, the sweep. A crash "after" the last one leaves only the journal.
const STEPS: u64 = 5;

fn git(root: &Path, args: &[&str]) {
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
}

fn workspace(root: &Path) {
    fs::create_dir_all(root.join("src")).unwrap();
    git(root, &["init", "-q", "-b", "main"]);
    git(root, &["config", "user.email", "t@t"]);
    git(root, &["config", "user.name", "t"]);
    fs::write(root.join(".gitignore"), "node_modules/\n").unwrap();
    fs::write(root.join("src/lib.rs"), "pub fn f() {}\n").unwrap();
    git(root, &["add", "-A"]);
    git(root, &["commit", "-q", "-m", "one"]);
    for p in 0..10 {
        let dir = root.join(format!("node_modules/pkg{p}"));
        fs::create_dir_all(&dir).unwrap();
        fs::write(dir.join("index.js"), format!("module.exports = {p};\n")).unwrap();
    }
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

fn snap(engine: &mut CaptureEngine, kind: CaptureKind, class: Class, seq: u64) {
    engine.snap(SnapRequest { kind, class, seq }).expect("snap");
}

/// A queue of a small capture and a bulk capture above it (neither shipped), an edit, and a
/// small snap of `kind` that is staged ahead of the bulk capture — killed after `crash_after`
/// of the restage's steps (0: not killed). Returns the tempdir, the store and the registrar.
fn restage_killed(
    kind: CaptureKind,
    crash_after: u64,
) -> (
    tempfile::TempDir,
    CaptureConfig,
    Arc<LocalDir>,
    Arc<InMemoryRegistrar>,
) {
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path().join("ws");
    workspace(&root);
    let config = CaptureConfig::new("wt", 1, &root);
    let mut engine = CaptureEngine::open(config.clone(), None).unwrap();
    snap(&mut engine, CaptureKind::Auto, Class::Small, 1);
    snap(&mut engine, CaptureKind::Auto, Class::Bulk, 2);
    fs::write(root.join("src/lib.rs"), "pub fn f() { edited() }\n").unwrap();
    engine.staging().crash_restage_after(crash_after);
    let staged = engine.snap(SnapRequest {
        kind,
        class: Class::Small,
        seq: 3,
    });
    assert_eq!(
        staged.is_err(),
        crash_after > 0,
        "killed after step {crash_after}: {staged:?}"
    );
    // The process dies here: nothing of the engine survives but the disk.
    drop(engine);
    (
        tmp,
        config,
        Arc::new(LocalDir::new(&tmp_store(&root)).unwrap()),
        Arc::new(InMemoryRegistrar::new("wt", 1, None)),
    )
}

fn tmp_store(root: &Path) -> std::path::PathBuf {
    root.parent().unwrap().join("store")
}

/// Ship everything, snap once more (a restarted daemon snaps both classes), ship again, and
/// restore the head into a fresh directory: it is the disk.
fn ship_and_restore(
    engine: &mut CaptureEngine,
    store: &Arc<LocalDir>,
    registrar: &Arc<InMemoryRegistrar>,
    label: &str,
) {
    let sink: Arc<dyn BlobSink> = store.clone();
    let dyn_registrar: Arc<dyn Registrar> = registrar.clone();
    let shipper = engine.shipper(sink, dyn_registrar);
    shipper
        .flush_final(Some(Duration::from_secs(30)))
        .unwrap_or_else(|e| panic!("{label}: the restaged queue ships: {e}"));
    snap(engine, CaptureKind::Turn, Class::Small, 10);
    snap(engine, CaptureKind::Auto, Class::Bulk, 11);
    shipper
        .flush_final(Some(Duration::from_secs(30)))
        .unwrap_or_else(|e| panic!("{label}: the next captures ship: {e}"));
    let chain = registrar.chain();
    for pair in chain.windows(2) {
        assert_eq!(
            pair[1].manifest.parent.as_deref(),
            Some(pair[0].capture_id.as_str()),
            "{label}: the chain is linear"
        );
    }
    let root = &engine.config().root;
    let fresh = root.parent().unwrap().join("fresh");
    Materializer::new(store.as_ref(), MaterializeTargets::new(&fresh, None))
        .materialize(&registrar.head().unwrap().manifest, MaterializeClass::All)
        .unwrap();
    assert_eq!(
        fs::read_to_string(fresh.join("src/lib.rs")).unwrap(),
        "pub fn f() { edited() }\n",
        "{label}"
    );
    assert_eq!(files(&fresh), files(root), "{label}");
}

/// Killed after every step, both shapes of the restage (an `auto` snap coalesces with the small
/// capture below the bulk one; a `turn` snap takes the bulk capture's slot), then a restarted
/// daemon: the queue is whole and everything registers.
#[test]
fn a_restage_killed_after_any_step_recovers_on_restart() {
    for kind in [CaptureKind::Auto, CaptureKind::Turn] {
        for step in 0..=STEPS {
            let label = format!("{kind:?}, killed after step {step}");
            let (_tmp, config, store, registrar) = restage_killed(kind, step);
            let mut engine = CaptureEngine::open(config, None)
                .unwrap_or_else(|e| panic!("{label}: reopen: {e}"));
            assert!(
                !engine.staging().restage_pending(),
                "{label}: the journal is finished at open"
            );
            ship_and_restore(&mut engine, &store, &registrar, &label);
        }
    }
}

/// Killed after the journal was committed, in a process that keeps running (an I/O error
/// rather than a crash): the shipper ships nothing of the half-way queue, and the next snap
/// finishes the restage before it takes a chain position.
#[test]
fn a_restage_interrupted_in_process_is_finished_by_the_next_snap() {
    for step in 2..=STEPS {
        let label = format!("in process, interrupted after step {step}");
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path().join("ws");
        workspace(&root);
        let store = Arc::new(LocalDir::new(&tmp_store(&root)).unwrap());
        let registrar = Arc::new(InMemoryRegistrar::new("wt", 1, None));
        let mut engine = CaptureEngine::open(CaptureConfig::new("wt", 1, &root), None).unwrap();
        snap(&mut engine, CaptureKind::Auto, Class::Small, 1);
        snap(&mut engine, CaptureKind::Auto, Class::Bulk, 2);
        fs::write(root.join("src/lib.rs"), "pub fn f() { edited() }\n").unwrap();
        engine.staging().crash_restage_after(step);
        assert!(
            engine
                .snap(SnapRequest {
                    kind: CaptureKind::Turn,
                    class: Class::Small,
                    seq: 3,
                })
                .is_err(),
            "{label}"
        );
        assert!(engine.staging().restage_pending(), "{label}");
        let sink: Arc<dyn BlobSink> = store.clone();
        let dyn_registrar: Arc<dyn Registrar> = registrar.clone();
        assert_eq!(
            engine.shipper(sink, dyn_registrar).ship_pending().unwrap(),
            0,
            "{label}: nothing ships from a half-way queue"
        );
        engine.staging().crash_restage_after(0);
        snap(&mut engine, CaptureKind::Turn, Class::Small, 4);
        assert!(!engine.staging().restage_pending(), "{label}");
        ship_and_restore(&mut engine, &store, &registrar, &label);
    }
}
