//! What a capture holds is the disk's bytes, and a write through any name of a file is captured
//! within the cadence (review 2026-09-28, sixth pass):
//!
//! - no filter driver of the user's runs in a capture's git, whatever bytes its name holds (#1);
//! - the raw tree holds every file's bytes as they are on disk, whether or not an attribute
//!   file is among the index entries (an ignored `.gitattributes` still converts) (#7);
//! - a write through another name of a hardlinked file — a bulk-class name of a tracked file, a
//!   name outside the workspace — dirties every class holding a name, and a watched class is
//!   read whole on its reconcile interval whatever the watcher saw (#2);
//! - a final flush seals only after a census that finds no process alive (#1).

use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::{Duration, Instant};

use sealant_capture::{
    CadenceRunner, CaptureConfig, CaptureEngine, CaptureKind, Class, InMemoryRegistrar, Incomplete,
    LocalDir, MaterializeClass, MaterializeTargets, Materializer, SnapRequest, WatchMode,
};

const EXECUTOR: &str = "exec-r6";

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

struct Fixture {
    tmp: tempfile::TempDir,
    root: PathBuf,
    store: Arc<LocalDir>,
    registrar: Arc<InMemoryRegistrar>,
}

impl Fixture {
    /// A repository with one commit: `a` holding `base\n`, and `.gitignore` holding `ignore`.
    fn new(ignore: &str) -> Self {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path().join("ws");
        fs::create_dir_all(&root).unwrap();
        git(&root, &["init", "-q", "-b", "main"]);
        git(&root, &["config", "user.email", "t@t"]);
        git(&root, &["config", "user.name", "t"]);
        fs::write(root.join("a"), b"base\n").unwrap();
        fs::write(root.join(".gitignore"), ignore).unwrap();
        git(&root, &["add", "-A"]);
        git(&root, &["commit", "-qm", "base"]);
        Self {
            store: Arc::new(LocalDir::new(&tmp.path().join("store")).unwrap()),
            registrar: Arc::new(InMemoryRegistrar::new("wt", 1, None).with_executor(EXECUTOR)),
            root,
            tmp,
        }
    }

    fn config(&self) -> CaptureConfig {
        let mut config = CaptureConfig::new("wt", 1, &self.root);
        config.executor = Some(EXECUTOR.to_owned());
        config
    }

    fn runner(&self, config: CaptureConfig) -> CadenceRunner {
        let engine = CaptureEngine::open(config, None).unwrap();
        let shipper = Arc::new(engine.shipper(self.store.clone(), self.registrar.clone()));
        CadenceRunner::new(engine, shipper)
    }

    /// A final flush that must say `complete` and seal the chain.
    fn final_flush(&self) {
        let result = self.runner(self.config()).flush_final(None);
        assert!(result.complete(), "{result:?}");
        let head = self.registrar.head().unwrap();
        assert!(head.manifest.final_seal.is_some(), "the chain is sealed");
    }

    fn restore(&self, name: &str) -> PathBuf {
        let out = self.tmp.path().join(name);
        Materializer::new(self.store.as_ref(), MaterializeTargets::new(&out, None))
            .materialize(
                &self.registrar.head().unwrap().manifest,
                MaterializeClass::All,
            )
            .unwrap();
        out
    }

    /// Wait up to `limit` for the chain head to restore `name` as the disk holds it.
    fn head_restores(&self, name: &str, limit: Duration) -> bool {
        let start = Instant::now();
        let mut attempt = 0;
        loop {
            attempt += 1;
            let restored = self.restore(&format!("restore-{attempt}"));
            if fs::read(restored.join(name)).ok() == fs::read(self.root.join(name)).ok() {
                return true;
            }
            if start.elapsed() >= limit {
                return false;
            }
            std::thread::sleep(Duration::from_millis(100));
        }
    }
}

#[test]
fn an_ignored_gitattributes_leaves_the_raw_bytes_captured() {
    let fx = Fixture::new(".gitattributes\n");
    fs::write(fx.root.join(".gitattributes"), b"*.txt text\n").unwrap();
    fs::write(fx.root.join("work.txt"), b"unique work\r\nsecond line\r\n").unwrap();
    fx.final_flush();
    let restored = fx.restore("restored");
    assert_eq!(
        fs::read(restored.join("work.txt")).unwrap(),
        b"unique work\r\nsecond line\r\n",
        "a sealed final capture restores the bytes the disk held"
    );
}

#[test]
fn a_filter_driver_named_in_raw_bytes_never_runs() {
    use std::io::Write;
    let fx = Fixture::new("");
    let mark = fx.tmp.path().join("raw-filter-ran");
    let mut config = fs::OpenOptions::new()
        .append(true)
        .open(fx.root.join(".git/config"))
        .unwrap();
    config.write_all(b"\n[filter \"raw\xff\"]\n").unwrap();
    config
        .write_all(
            format!(
                "\tclean = touch {}; cat\n\trequired = true\n",
                mark.display()
            )
            .as_bytes(),
        )
        .unwrap();
    drop(config);
    fs::write(fx.root.join(".gitattributes"), b"*.txt filter=raw\xff\n").unwrap();
    fs::write(fx.root.join("work.txt"), b"work\n").unwrap();
    fx.final_flush();
    assert!(!mark.exists(), "a capture ran the user's filter driver");
    let restored = fx.restore("restored");
    assert_eq!(fs::read(restored.join("work.txt")).unwrap(), b"work\n");
}

/// A cadence whose clocks fire fast — the alias poll runs on the 100 ms maximum interval — and
/// whose reconcile intervals are out of reach: only the alias poll can find a write no watch
/// sees.
fn fast(config: &mut CaptureConfig) {
    config.cadence.quiet = Duration::from_millis(40);
    config.cadence.max_interval = Duration::from_millis(100);
    config.cadence.bulk_quiet = Duration::from_millis(40);
    config.cadence.bulk_max_interval = Duration::from_millis(100);
    config.cadence.reconcile = Duration::from_secs(600);
    config.cadence.bulk_reconcile = Duration::from_secs(600);
}

/// How long a write the alias poll should find may take to reach the chain's head. Locally
/// well under a second; generous because arm64 CI runners stall for seconds at a time (two
/// tests of this file missed a 2 s window in the same run). A class the poll never dirties is
/// not snapped again until its reconcile interval, minutes away ([`fast`]), and still fails.
const ALIAS_WINDOW: Duration = Duration::from_secs(20);

#[test]
fn a_write_through_a_bulk_name_of_a_tracked_file_is_captured_within_the_cadence() {
    let fx = Fixture::new("node_modules/\n");
    fs::create_dir_all(fx.root.join("node_modules")).unwrap();
    fs::hard_link(fx.root.join("a"), fx.root.join("node_modules/a")).unwrap();
    let mut config = fx.config();
    fast(&mut config);
    let mut engine = CaptureEngine::open(config, None).unwrap();
    engine
        .snap(SnapRequest {
            kind: CaptureKind::Auto,
            class: Class::Bulk,
            seq: 1,
        })
        .unwrap();
    engine
        .snap(SnapRequest {
            kind: CaptureKind::Auto,
            class: Class::Small,
            seq: 2,
        })
        .unwrap();
    let shipper = Arc::new(engine.shipper(fx.store.clone(), fx.registrar.clone()));
    shipper.ship_pending().unwrap();
    let runner = CadenceRunner::new(engine, shipper);
    runner.start(None);
    std::thread::sleep(Duration::from_millis(300));

    fs::write(
        fx.root.join("node_modules/a"),
        b"work changed through bulk alias\n",
    )
    .unwrap();
    assert_eq!(
        fs::read(fx.root.join("a")).unwrap(),
        b"work changed through bulk alias\n"
    );
    let captured = fx.head_restores("a", ALIAS_WINDOW);
    let snapshot = runner.snapshot();
    runner.stop();
    assert!(
        captured,
        "the tracked name kept the old bytes for {ALIAS_WINDOW:?}: {snapshot:?}"
    );
    assert_eq!(snapshot.small_mode, WatchMode::Watched, "{snapshot:?}");
}

#[test]
fn a_write_through_a_name_outside_the_workspace_is_captured_within_the_cadence() {
    let fx = Fixture::new("");
    let alias = fx.tmp.path().join("outside-alias");
    fs::hard_link(fx.root.join("a"), &alias).unwrap();
    let mut config = fx.config();
    fast(&mut config);
    let mut engine = CaptureEngine::open(config, None).unwrap();
    engine
        .snap(SnapRequest {
            kind: CaptureKind::Auto,
            class: Class::Small,
            seq: 1,
        })
        .unwrap();
    let shipper = Arc::new(engine.shipper(fx.store.clone(), fx.registrar.clone()));
    shipper.ship_pending().unwrap();
    let runner = CadenceRunner::new(engine, shipper);
    runner.start(None);
    // Past the racy window of the file's last change: the poll trusts the stat it read.
    std::thread::sleep(Duration::from_millis(2_200));

    fs::write(&alias, b"work changed through external alias\n").unwrap();
    let captured = fx.head_restores("a", ALIAS_WINDOW);
    let snapshot = runner.snapshot();
    runner.stop();
    assert!(
        captured,
        "a write through a name outside the workspace went uncaptured for {ALIAS_WINDOW:?}: \
         {snapshot:?}"
    );
    assert!(snapshot.aliases_moved > 0, "{snapshot:?}");
    assert_eq!(snapshot.small_mode, WatchMode::Watched, "{snapshot:?}");
}

#[test]
fn a_watched_class_is_read_whole_on_its_reconcile_interval() {
    let fx = Fixture::new("");
    let alias = fx.tmp.path().join("outside-alias");
    fs::hard_link(fx.root.join("a"), &alias).unwrap();
    let mut config = fx.config();
    // The alias poll is on the maximum interval: out of reach here, so only the reconcile
    // interval can find the write.
    config.cadence.quiet = Duration::from_millis(40);
    config.cadence.max_interval = Duration::from_secs(600);
    config.cadence.bulk_max_interval = Duration::from_secs(600);
    config.cadence.reconcile = Duration::from_millis(300);
    let runner = fx.runner(config);
    runner.snap(CaptureKind::Auto).unwrap();
    runner.ship(Duration::from_secs(10)).unwrap();
    runner.start(None);
    std::thread::sleep(Duration::from_millis(100));

    fs::write(&alias, b"work no watch saw\n").unwrap();
    // Generous for the same stalls as [`ALIAS_WINDOW`]; the alias poll is ten minutes away.
    let captured = fx.head_restores("a", Duration::from_secs(20));
    let snapshot = runner.snapshot();
    runner.stop();
    assert!(captured, "{snapshot:?}");
    assert!(snapshot.reconcile_fired > 0, "{snapshot:?}");
    assert_eq!(snapshot.aliases_moved, 0, "{snapshot:?}");
}

#[test]
fn a_final_flush_seals_only_after_a_census_that_finds_no_process() {
    let fx = Fixture::new("");
    fs::write(fx.root.join("a"), b"edited\n").unwrap();
    let runner = fx.runner(fx.config());
    let calls = Arc::new(AtomicUsize::new(0));
    let seen = Arc::clone(&calls);
    // The first census finds (and stops) a process; the next finds none.
    runner.set_census(Some(Arc::new(move || {
        if seen.fetch_add(1, Ordering::SeqCst) == 0 {
            Err("1 process(es) alive after the writers stopped, killed: 4242".to_owned())
        } else {
            Ok(())
        }
    })));
    let result = runner.flush_final(None);
    assert!(result.complete(), "{result:?}");
    assert_eq!(
        calls.load(Ordering::SeqCst),
        2,
        "a second round took a second census"
    );
    assert!(fx.registrar.head().unwrap().manifest.final_seal.is_some());
}

#[test]
fn a_census_that_keeps_finding_processes_leaves_the_flush_incomplete_and_unsealed() {
    let fx = Fixture::new("");
    fs::write(fx.root.join("a"), b"edited\n").unwrap();
    let runner = fx.runner(fx.config());
    runner.set_census(Some(Arc::new(|| {
        Err("1 process(es) alive after the writers stopped; 1 outlived SIGKILL".to_owned())
    })));
    let result = runner.flush_final(None);
    assert!(!result.complete(), "{result:?}");
    assert!(
        matches!(result.incomplete, Some(Incomplete::ProcessesRemain(_))),
        "{result:?}"
    );
    assert_eq!(
        result.incomplete.as_ref().map(Incomplete::reason),
        Some("processes-remain")
    );
    assert!(
        fx.registrar.head().unwrap().manifest.final_seal.is_none(),
        "nothing is sealed"
    );
}
