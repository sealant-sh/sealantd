//! A final flush that reports complete leaves nothing for a later one to capture.
//!
//! Docker end to end, round 3: after the first final flush answered `complete: true`, the next
//! one (Core's drain, the daemon's SIGTERM handler) registered another final capture of 8 KB or
//! 19 KB, `files_read=0`. Two causes, one test each:
//!
//! - The final small snap was staged ahead of a scheduled bulk capture still uploading, and the
//!   final bulk snap found that capture current: the chain ended in a capture of kind `auto`.
//!   The next final flush staged a final capture with the same sections (its manifest only),
//!   and until then Mend's reading of the head ("the executor's own final flush registered
//!   last") said the work was lost.
//! - The final small snap's worktree metadata overlay names the bulk class's names of a tracked
//!   file's inode (a pnpm `file:` package hardlinked into `node_modules`) as the bulk index had
//!   them, and the bulk class had never been snapped: the final capture lacked the links, a
//!   restore of it left the two names on separate inodes, and the next flush's small snap
//!   captured them.

use std::fs;
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use sealant_capture::manifest::{BulkState, DirFormat};
use sealant_capture::sink::{BlobSource, PutOutcome, SinkError};
use sealant_capture::{
    BlobSink, CadenceRunner, CaptureConfig, CaptureEngine, CaptureKind, Class, FinalSeal,
    InMemoryRegistrar, LocalDir, MaterializeClass, MaterializeTargets, Materializer, Registrar,
    SnapRequest,
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

/// A sink that spends `delay` on every PUT.
struct Slow {
    inner: Arc<LocalDir>,
    delay: Duration,
    puts: AtomicU64,
}

impl BlobSink for Slow {
    fn put_if_absent(&self, key: &str, source: BlobSource<'_>) -> Result<PutOutcome, SinkError> {
        self.puts.fetch_add(1, Ordering::SeqCst);
        std::thread::sleep(self.delay);
        self.inner.put_if_absent(key, source)
    }

    fn get(&self, key: &str) -> Result<Vec<u8>, SinkError> {
        self.inner.get(key)
    }

    fn exists(&self, key: &str) -> Result<bool, SinkError> {
        self.inner.exists(key)
    }
}

struct Fixture {
    _tmp: tempfile::TempDir,
    base: PathBuf,
    root: PathBuf,
    store: Arc<LocalDir>,
    registrar: Arc<InMemoryRegistrar>,
}

fn fixture(packages: usize) -> Fixture {
    let tmp = tempfile::tempdir().unwrap();
    let base = tmp.path().to_path_buf();
    let root = base.join("ws");
    fs::create_dir_all(root.join("src")).unwrap();
    git(&root, &["init", "-q", "-b", "main"]);
    git(&root, &["config", "user.email", "t@t"]);
    git(&root, &["config", "user.name", "t"]);
    fs::write(root.join(".gitignore"), "node_modules/\n").unwrap();
    fs::write(root.join("src/lib.rs"), "pub fn f() {}\n").unwrap();
    git(&root, &["add", "-A"]);
    git(&root, &["commit", "-q", "-m", "one"]);
    for p in 0..packages {
        let dir = root.join(format!("node_modules/pkg{p}/lib"));
        fs::create_dir_all(&dir).unwrap();
        for f in 0..3 {
            fs::write(
                dir.join(format!("m{f}.js")),
                format!("module.exports = [{p}, {f}];\n").repeat(5),
            )
            .unwrap();
        }
    }
    Fixture {
        store: Arc::new(LocalDir::new(&base.join("store")).unwrap()),
        registrar: Arc::new(InMemoryRegistrar::new("wt", 1, None)),
        _tmp: tmp,
        base,
        root,
    }
}

fn runner(config: CaptureConfig, sink: Arc<dyn BlobSink>, fx: &Fixture) -> CadenceRunner {
    let engine = CaptureEngine::open(config, None).unwrap();
    let registrar: Arc<dyn Registrar> = fx.registrar.clone();
    let shipper = Arc::new(engine.shipper(sink, registrar));
    CadenceRunner::new(engine, shipper)
}

/// The first cause: the final small snap staged ahead of a scheduled bulk capture still
/// uploading. The flush seals the chain with a final capture, and the next flush stages nothing.
#[test]
fn a_final_flush_ahead_of_an_uploading_bulk_capture_ends_the_chain_in_a_final_capture() {
    let fx = fixture(40);
    let slow = Arc::new(Slow {
        inner: fx.store.clone(),
        delay: Duration::from_millis(20),
        puts: AtomicU64::new(0),
    });
    let mut config = CaptureConfig::new("wt", 1, &fx.root);
    config.dir_format = DirFormat::Objects;
    config.uploads_in_flight = 1;
    let runner = runner(config, slow, &fx);
    runner.start(None);
    runner.flush(CaptureKind::Suspend, None).unwrap();
    // A scheduled bulk capture, uploading one object at a time.
    let staged = runner
        .with_engine_mut(|engine| {
            engine.snap(SnapRequest {
                kind: CaptureKind::Auto,
                class: Class::Bulk,
                seq: 7,
            })
        })
        .unwrap();
    assert!(!staged.unchanged);
    fs::write(fx.root.join("src/lib.rs"), "pub fn f() { g() }\n").unwrap();

    let flushed = runner.flush_final(None);
    assert!(flushed.complete(), "{flushed:?}");
    let chain = fx.registrar.chain();
    let head = chain.last().unwrap();
    assert_eq!(
        head.manifest.kind,
        CaptureKind::Final,
        "the chain ends in a final capture: {:?}",
        chain
            .iter()
            .map(|h| (h.n, h.manifest.kind))
            .collect::<Vec<_>>()
    );
    assert!(matches!(head.manifest.sections.bulk, BulkState::Ready(_)));

    // The same final flush again, as the drain and the SIGTERM handler ask it: nothing new.
    let registered = chain.len();
    for _ in 0..3 {
        assert!(runner.flush_final(None).complete());
    }
    assert_eq!(
        fx.registrar.chain().len(),
        registered,
        "no capture after the flush that reported complete"
    );
    runner.stop();
}

/// The second cause: a tracked file hardlinked into `node_modules`, the bulk class never
/// snapped before the final flush. The final capture records the link (a restore puts both
/// names on one inode), and the next flush stages nothing.
#[test]
fn a_final_flush_records_the_bulk_names_of_a_tracked_inode_it_just_captured() {
    let fx = fixture(3);
    fs::create_dir_all(fx.root.join("packages/util")).unwrap();
    fs::write(
        fx.root.join("packages/util/index.js"),
        "export const u = 1;\n",
    )
    .unwrap();
    git(&fx.root, &["add", "-A"]);
    git(&fx.root, &["commit", "-q", "-m", "util"]);
    // What pnpm does for a `file:` dependency: the package's files, hardlinked.
    fs::create_dir_all(fx.root.join("node_modules/util")).unwrap();
    fs::hard_link(
        fx.root.join("packages/util/index.js"),
        fx.root.join("node_modules/util/index.js"),
    )
    .unwrap();
    let runner = runner(CaptureConfig::new("wt", 1, &fx.root), fx.store.clone(), &fx);
    runner.start(None);
    let flushed = runner.flush_final(None);
    assert!(flushed.complete(), "{flushed:?}");
    let head = fx.registrar.head().unwrap();
    assert_eq!(head.manifest.kind, CaptureKind::Final);

    let fresh = fx.base.join("fresh");
    Materializer::new(fx.store.as_ref(), MaterializeTargets::new(&fresh, None))
        .materialize(&head.manifest, MaterializeClass::All)
        .unwrap();
    let tracked = fs::metadata(fresh.join("packages/util/index.js")).unwrap();
    let linked = fs::metadata(fresh.join("node_modules/util/index.js")).unwrap();
    assert_eq!(
        (tracked.dev(), tracked.ino()),
        (linked.dev(), linked.ino()),
        "the final capture holds the link between the tracked file and its bulk name"
    );

    let registered = fx.registrar.chain().len();
    assert!(runner.flush_final(None).complete());
    assert_eq!(
        fx.registrar.chain().len(),
        registered,
        "no capture after the flush that reported complete"
    );
    runner.stop();
}

/// A runner whose engine seals under `executor`, over a registrar whose token is scoped to
/// `scoped`.
fn sealing_runner(
    fx: &Fixture,
    executor: &str,
    scoped: &str,
) -> (CadenceRunner, Arc<InMemoryRegistrar>) {
    let registrar = Arc::new(InMemoryRegistrar::new("wt", 1, None).with_executor(scoped));
    let mut config = CaptureConfig::new("wt", 1, &fx.root);
    config.executor = Some(executor.to_owned());
    let engine = CaptureEngine::open(config, None).unwrap();
    let dyn_registrar: Arc<dyn Registrar> = registrar.clone();
    let shipper = Arc::new(engine.shipper(fx.store.clone(), dyn_registrar));
    (CadenceRunner::new(engine, shipper), registrar)
}

fn seal(executor: &str) -> FinalSeal {
    FinalSeal {
        complete: true,
        epoch: 1,
        executor: executor.to_owned(),
    }
}

/// Cross-repo decision 1: a completed final flush is a store-side fact. Once everything is
/// registered, the flush registers one more capture — the newest one's sections, `kind: final`
/// — carrying `final_seal` (complete, its epoch, its executor), and reports complete only once
/// that register is acknowledged. Asked again, it stages nothing. A capture staged after it (a
/// turn boundary) unseals the chain; the next final flush seals it again.
#[test]
fn a_complete_final_flush_seals_the_chain_and_a_later_capture_unseals_it() {
    let fx = fixture(2);
    let (runner, registrar) = sealing_runner(&fx, "exec-1", "exec-1");
    runner.start(None);
    let flushed = runner.flush_final(None);
    assert!(flushed.complete(), "{flushed:?}");
    let chain = registrar.chain();
    let head = chain.last().unwrap();
    assert_eq!(head.manifest.kind, CaptureKind::Final);
    assert_eq!(head.manifest.final_seal, Some(seal("exec-1")));
    assert_eq!(
        head.manifest.sections,
        chain[chain.len() - 2].manifest.sections,
        "the sealing capture holds the newest capture's sections"
    );
    assert!(
        chain[..chain.len() - 1]
            .iter()
            .all(|h| h.manifest.final_seal.is_none())
    );
    assert_eq!(registrar.seals(), vec![(head.n, seal("exec-1"))]);
    assert!(runner.final_sealed());

    // The drain and the SIGTERM handler ask again: nothing new, the same seal.
    let registered = chain.len();
    for _ in 0..2 {
        assert!(runner.flush_final(None).complete());
    }
    assert_eq!(registrar.chain().len(), registered);
    assert_eq!(registrar.seals().len(), 1);

    // A turn boundary after it: the chain ends on a capture without a seal.
    fs::write(fx.root.join("src/lib.rs"), "pub fn f() { h() }\n").unwrap();
    runner.flush(CaptureKind::Auto, None).unwrap();
    let head = registrar.head().unwrap();
    assert_eq!(head.manifest.kind, CaptureKind::Auto);
    assert_eq!(head.manifest.final_seal, None, "a later capture unseals");
    assert!(!runner.final_sealed());

    // The next final flush seals again.
    assert!(runner.flush_final(None).complete());
    let head = registrar.head().unwrap();
    assert_eq!(head.manifest.final_seal, Some(seal("exec-1")));
    assert_eq!(registrar.seals().len(), 2);
    assert_eq!(registrar.seals()[1].0, head.n);

    // The sealed head restores like any other.
    let out = fx.base.join("restored");
    Materializer::new(fx.store.as_ref(), MaterializeTargets::new(&out, None))
        .materialize(&head.manifest, MaterializeClass::All)
        .unwrap();
    assert_eq!(
        fs::read_to_string(out.join("src/lib.rs")).unwrap(),
        "pub fn f() { h() }\n"
    );
    runner.stop();
}

/// A final flush whose caller cannot vouch that every writer stopped seals nothing, and an
/// engine with no executor seals nothing: the chain ends as it did before seals.
#[test]
fn nothing_is_sealed_unless_the_writers_stopped_and_the_executor_is_known() {
    let fx = fixture(1);
    let (runner, registrar) = sealing_runner(&fx, "exec-1", "exec-1");
    runner.start(None);
    assert!(runner.flush_final_sealing(None, false).complete());
    assert!(
        registrar
            .chain()
            .iter()
            .all(|h| h.manifest.final_seal.is_none())
    );
    assert!(registrar.seals().is_empty());
    assert!(!runner.final_sealed());
    runner.stop();

    let fx = fixture(1);
    let runner = runner_with(&fx);
    runner.start(None);
    assert!(runner.flush_final(None).complete());
    assert!(
        fx.registrar
            .chain()
            .iter()
            .all(|h| h.manifest.final_seal.is_none())
    );
    assert!(
        runner.final_sealed(),
        "nothing to seal under: sealed as far as it can be"
    );
    runner.stop();
}

/// The registrar records a seal only for the executor its token is scoped to (Mend's rule):
/// one naming another executor registers as a capture and seals nothing.
#[test]
fn a_seal_naming_another_executor_is_registered_but_not_recorded() {
    let fx = fixture(1);
    let (runner, registrar) = sealing_runner(&fx, "exec-other", "exec-1");
    runner.start(None);
    assert!(runner.flush_final(None).complete());
    assert_eq!(
        registrar.head().unwrap().manifest.final_seal,
        Some(seal("exec-other"))
    );
    assert!(registrar.seals().is_empty());
    runner.stop();
}

fn runner_with(fx: &Fixture) -> CadenceRunner {
    runner(CaptureConfig::new("wt", 1, &fx.root), fx.store.clone(), fx)
}
