//! Dir packs (section format 2): a capture's dir objects travel in a few packs instead of one
//! object per directory, and a restore reads them from a few GETs. Measured on alpha
//! (2026-09-27): a pnpm `node_modules` of ≈ 800 MB was 20,878 objects, ≈ 20,860 of them dir
//! objects, uploaded one PUT at a time in 24 minutes; a resume would have fetched them one GET
//! at a time.
//!
//! Also here: what stores already hold keeps working. A head written one object per directory
//! (format 1) materializes, a capture staged on top of it carries its bulk section as it is (one
//! manifest, two formats), and a section format this build does not know is refused.

use std::collections::BTreeMap;
use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::time::Duration;

use sealant_capture::engine::MAX_DIR_PACKS;
use sealant_capture::manifest::{
    BulkState, DirFormat, FORMAT_DIR_OBJECTS, FORMAT_DIR_PACKS, Manifest,
};
use sealant_capture::materialize::MaterializeError;
use sealant_capture::registrar::{PlanGetRequest, tree_keys};
use sealant_capture::sink::{BlobSource, PutOutcome, SinkError};
use sealant_capture::{
    BlobSink, CaptureConfig, CaptureEngine, CaptureKind, Class, InMemoryRegistrar, LocalDir,
    MaterializeClass, MaterializeTargets, Materializer, Registrar, SnapRequest, StagedCapture,
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
        "git {args:?} failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );
}

/// A repository with an ignored `.env` and a pnpm-shaped `node_modules/`: per package
/// `.pnpm/<pkg>@1.0.0/node_modules/<pkg>/{lib,lib/util,dist}` with a few files, and a symlink
/// `node_modules/<pkg>` to it.
fn workspace(root: &Path, packages: usize) {
    fs::create_dir_all(root.join("src")).unwrap();
    git(root, &["init", "-q", "-b", "main"]);
    git(root, &["config", "user.email", "t@t"]);
    git(root, &["config", "user.name", "t"]);
    fs::write(root.join(".gitignore"), ".env\nnode_modules/\n").unwrap();
    fs::write(root.join("src/lib.rs"), "pub fn f() {}\n").unwrap();
    git(root, &["add", "-A"]);
    git(root, &["commit", "-q", "-m", "one"]);
    fs::write(root.join(".env"), "SECRET=1\n").unwrap();
    let nm = root.join("node_modules");
    for p in 0..packages {
        let name = format!("pkg{p}");
        let pkg = package_dir(root, p);
        fs::create_dir_all(pkg.join("lib/util")).unwrap();
        fs::create_dir_all(pkg.join("dist")).unwrap();
        fs::write(
            pkg.join("package.json"),
            format!("{{\"name\":\"{name}\"}}\n"),
        )
        .unwrap();
        fs::write(pkg.join("lib/index.js"), format!("module.exports = {p};\n")).unwrap();
        fs::write(pkg.join("lib/util/u.js"), format!("exports.u = {p};\n")).unwrap();
        fs::write(
            pkg.join("dist/d.cjs"),
            format!("exports.d = {p};\n").repeat(3),
        )
        .unwrap();
        fs::set_permissions(pkg.join("dist"), fs::Permissions::from_mode(0o750)).unwrap();
        std::os::unix::fs::symlink(
            format!(".pnpm/{name}@1.0.0/node_modules/{name}"),
            nm.join(&name),
        )
        .unwrap();
    }
}

fn package_dir(root: &Path, p: usize) -> PathBuf {
    let name = format!("pkg{p}");
    root.join("node_modules/.pnpm")
        .join(format!("{name}@1.0.0"))
        .join("node_modules")
        .join(name)
}

/// Every path under `dir`: kind, mode and content (or link text).
fn listing(dir: &Path) -> BTreeMap<String, (String, u32, Vec<u8>)> {
    let mut out = BTreeMap::new();
    for entry in walkdir::WalkDir::new(dir).min_depth(1) {
        let entry = entry.unwrap();
        let rel = entry
            .path()
            .strip_prefix(dir)
            .unwrap()
            .to_string_lossy()
            .into_owned();
        let meta = fs::symlink_metadata(entry.path()).unwrap();
        let mode = meta.permissions().mode() & 0o7777;
        let value = if meta.file_type().is_symlink() {
            (
                "link".to_owned(),
                0,
                fs::read_link(entry.path())
                    .unwrap()
                    .to_string_lossy()
                    .into_owned()
                    .into_bytes(),
            )
        } else if meta.is_dir() {
            ("dir".to_owned(), mode, Vec::new())
        } else {
            ("file".to_owned(), mode, fs::read(entry.path()).unwrap())
        };
        out.insert(rel, value);
    }
    out
}

/// Counts requests on the way to a directory store, and the most PUTs in flight at once.
struct Counting {
    inner: LocalDir,
    delay: Duration,
    puts: AtomicU64,
    gets: AtomicU64,
    in_flight: AtomicUsize,
    max_in_flight: AtomicUsize,
}

impl Counting {
    fn new(dir: &Path, delay: Duration) -> Arc<Self> {
        Arc::new(Self {
            inner: LocalDir::new(dir).unwrap(),
            delay,
            puts: AtomicU64::new(0),
            gets: AtomicU64::new(0),
            in_flight: AtomicUsize::new(0),
            max_in_flight: AtomicUsize::new(0),
        })
    }

    fn take(&self) -> (u64, u64) {
        (
            self.puts.swap(0, Ordering::SeqCst),
            self.gets.swap(0, Ordering::SeqCst),
        )
    }
}

impl BlobSink for Counting {
    fn put_if_absent(&self, key: &str, source: BlobSource<'_>) -> Result<PutOutcome, SinkError> {
        self.puts.fetch_add(1, Ordering::SeqCst);
        let now = self.in_flight.fetch_add(1, Ordering::SeqCst) + 1;
        self.max_in_flight.fetch_max(now, Ordering::SeqCst);
        std::thread::sleep(self.delay);
        let result = self.inner.put_if_absent(key, source);
        self.in_flight.fetch_sub(1, Ordering::SeqCst);
        result
    }

    fn get(&self, key: &str) -> Result<Vec<u8>, SinkError> {
        self.gets.fetch_add(1, Ordering::SeqCst);
        self.inner.get(key)
    }

    fn exists(&self, key: &str) -> Result<bool, SinkError> {
        self.inner.exists(key)
    }
}

struct Session {
    _tmp: tempfile::TempDir,
    base: PathBuf,
    root: PathBuf,
    sink: Arc<Counting>,
    registrar: Arc<InMemoryRegistrar>,
}

fn session(packages: usize, delay: Duration) -> Session {
    let tmp = tempfile::tempdir().unwrap();
    let base = tmp.path().to_path_buf();
    let root = base.join("ws");
    workspace(&root, packages);
    Session {
        sink: Counting::new(&base.join("store"), delay),
        registrar: Arc::new(InMemoryRegistrar::new("wt", 1, None)),
        _tmp: tmp,
        base,
        root,
    }
}

impl Session {
    fn engine(
        &self,
        format: DirFormat,
        previous: Option<sealant_capture::EncodedManifest>,
    ) -> CaptureEngine {
        let mut config = CaptureConfig::new("wt", 1, &self.root);
        config.cpu_fraction = 1.0;
        config.dir_format = format;
        CaptureEngine::open(config, previous).unwrap()
    }

    fn ship(&self, engine: &CaptureEngine) {
        let sink: Arc<dyn BlobSink> = self.sink.clone();
        let registrar: Arc<dyn Registrar> = self.registrar.clone();
        engine.shipper(sink, registrar).ship_pending().unwrap();
        assert!(engine.staging().pending().unwrap().is_empty());
    }

    fn head(&self) -> Manifest {
        self.registrar.head().unwrap().manifest
    }

    fn materialize(&self, into: &str) -> (PathBuf, sealant_capture::MaterializeReport) {
        let restore = self.base.join(into);
        let report = Materializer::new(self.sink.as_ref(), MaterializeTargets::new(&restore, None))
            .materialize(&self.head(), MaterializeClass::All)
            .unwrap();
        (restore, report)
    }
}

fn snap(engine: &mut CaptureEngine, class: Class, seq: u64) -> StagedCapture {
    engine
        .snap(SnapRequest {
            kind: CaptureKind::Auto,
            class,
            seq,
        })
        .unwrap()
}

/// Hundreds of directories go up as a few objects; one edit adds one small dir pack holding the
/// changed directories' path to the root; a restore is a few GETs, none per directory, and
/// gives back the tree as it was (modes, symlinks, the edit).
#[test]
fn a_node_modules_capture_and_its_restore_are_a_few_objects() {
    let s = session(150, Duration::ZERO);
    let mut engine = s.engine(DirFormat::Packs, None);
    snap(&mut engine, Class::Small, 1);
    s.ship(&engine);
    s.sink.take();

    let bulk = snap(&mut engine, Class::Bulk, 2);
    // node_modules, .pnpm, per package five directories.
    let dirs = 2 + 150 * 5;
    assert!(bulk.stats.dirs_new as usize > dirs, "{:?}", bulk.stats);
    assert_eq!(bulk.stats.dir_packs, 1, "{:?}", bulk.stats);
    let section = bulk
        .manifest
        .manifest
        .sections
        .bulk
        .section()
        .unwrap()
        .clone();
    assert_eq!(section.format, FORMAT_DIR_PACKS);
    assert_eq!(section.dir_packs.len(), 1);
    assert_eq!(
        section.root.len(),
        64,
        "the root is a digest: {}",
        section.root
    );
    s.ship(&engine);
    let (puts, _) = s.sink.take();
    eprintln!(
        "first bulk capture: {} dir objects, {puts} PUTs",
        bulk.stats.dirs_new
    );
    // A content pack, a dir pack, the manifest.
    assert!(
        puts <= 4,
        "{puts} PUTs for {} dir objects",
        bulk.stats.dirs_new
    );

    // One edit deep in the tree: the dir objects on its path to the root, in one new pack.
    let edited = package_dir(&s.root, 75).join("lib/util/u.js");
    fs::write(&edited, "exports.u = 'edited';\n").unwrap();
    let inc = snap(&mut engine, Class::Bulk, 3);
    assert_eq!(inc.stats.dir_packs, 1, "{:?}", inc.stats);
    // util, lib, pkg75, node_modules, pkg75@1.0.0, .pnpm, node_modules, the root.
    assert_eq!(inc.stats.dirs_new, 8, "{:?}", inc.stats);
    let section = inc
        .manifest
        .manifest
        .sections
        .bulk
        .section()
        .unwrap()
        .clone();
    assert_eq!(section.dir_packs.len(), 2, "the first pack and the path");
    s.ship(&engine);
    let (puts, _) = s.sink.take();
    assert_eq!(puts, 3, "a content pack, a dir pack, the manifest");

    let (restore, report) = s.materialize("restore");
    let (_, gets) = s.sink.take();
    eprintln!("restore: {gets} GETs, {report:?}");
    assert_eq!(report.dir_objects_fetched, 0);
    let packs = section.packs.len() + section.dir_packs.len();
    assert!(
        gets as usize <= packs + 12,
        "{gets} GETs for {packs} bulk packs (plus git and workspace)"
    );
    assert_eq!(
        listing(&restore.join("node_modules")),
        listing(&s.root.join("node_modules"))
    );
    assert_eq!(
        fs::read_to_string(restore.join(edited.strip_prefix(&s.root).unwrap())).unwrap(),
        "exports.u = 'edited';\n"
    );
    assert_eq!(
        fs::read_to_string(restore.join(".env")).unwrap(),
        "SECRET=1\n"
    );

    // A second restore over the first: every pack is in the cache, nothing is fetched.
    let (_, report) = s.materialize("restore");
    let (_, gets) = s.sink.take();
    assert_eq!(report.packs_fetched, 0, "{report:?}");
    assert_eq!(report.files, 0, "{report:?}");
    assert!(
        gets <= 3,
        "{gets} GETs (git packs only, and they are installed)"
    );
}

/// A section lists at most [`MAX_DIR_PACKS`] dir packs: every capture that changes the class
/// adds one, and past the bound the tree is packed whole. Every head restores.
#[test]
fn a_section_never_lists_more_than_the_bound() {
    let s = session(40, Duration::ZERO);
    let mut engine = s.engine(DirFormat::Packs, None);
    snap(&mut engine, Class::Small, 1);
    snap(&mut engine, Class::Bulk, 2);
    s.ship(&engine);
    let mut most = 0;
    let mut compacted = false;
    for round in 0..(MAX_DIR_PACKS + 4) {
        let p = round % 40;
        fs::write(
            package_dir(&s.root, p).join("lib/index.js"),
            format!("module.exports = 'round {round}';\n"),
        )
        .unwrap();
        let staged = snap(&mut engine, Class::Bulk, 3 + round as u64);
        let listed = staged
            .manifest
            .manifest
            .sections
            .bulk
            .section()
            .unwrap()
            .dir_packs
            .len();
        assert!(listed <= MAX_DIR_PACKS, "round {round}: {listed} dir packs");
        compacted |= listed < most;
        most = most.max(listed);
        s.ship(&engine);
    }
    assert_eq!(most, MAX_DIR_PACKS);
    assert!(
        compacted,
        "the tree was packed whole once the bound was reached"
    );
    let (restore, _) = s.materialize("restore");
    assert_eq!(
        listing(&restore.join("node_modules")),
        listing(&s.root.join("node_modules"))
    );
}

/// A store written one object per directory (every capture before dir packs, and every capture
/// for a registrar that does not read them) restores, and an executor that writes dir packs
/// continues its chain: the first small capture carries the head's format-1 bulk section as it
/// is beside its own format-2 workspace section, and both restore from that one manifest; the
/// next bulk capture moves the bulk section to format 2 as well.
#[test]
fn an_old_format_head_restores_and_a_new_capture_continues_it() {
    let s = session(30, Duration::ZERO);
    let mut old = s.engine(DirFormat::Objects, None);
    snap(&mut old, Class::Small, 1);
    snap(&mut old, Class::Bulk, 2);
    s.ship(&old);
    let head = s.registrar.head().unwrap();
    for section in [
        head.manifest.sections.workspace.tree(),
        head.manifest.sections.bulk.section().unwrap().tree(),
    ] {
        assert_eq!(section.format, FORMAT_DIR_OBJECTS);
        assert!(section.root.contains("/trees/"), "{}", section.root);
        assert!(section.dir_packs.is_empty());
    }
    s.sink.take();
    let (restore, report) = s.materialize("restore-old");
    assert!(report.dir_objects_fetched > 30 * 5, "{report:?}");
    assert_eq!(
        listing(&restore.join("node_modules")),
        listing(&s.root.join("node_modules"))
    );
    drop(old);

    // A new executor picks the chain up from the old head (a boot: materialize, then open).
    let encoded = Materializer::new(s.sink.as_ref(), MaterializeTargets::new(&restore, None))
        .fetch_manifest(&head.manifest_key, &head.capture_id)
        .unwrap();
    let ws = s.root.clone();
    fs::remove_dir_all(&ws).unwrap();
    fs::rename(&restore, &ws).unwrap();
    let mut new = s.engine(DirFormat::Packs, Some(encoded));
    new.seed_tips_from_repo().unwrap();
    fs::write(ws.join(".env"), "SECRET=2\n").unwrap();
    let small = snap(&mut new, Class::Small, 3);
    let sections = &small.manifest.manifest.sections;
    assert_eq!(sections.workspace.format, FORMAT_DIR_PACKS);
    assert_eq!(
        sections.bulk, head.manifest.sections.bulk,
        "the old bulk section rides along as it is"
    );
    s.ship(&new);
    let (mixed, report) = s.materialize("restore-mixed");
    assert!(report.dir_objects_fetched > 30 * 5, "{report:?}");
    assert_eq!(
        fs::read_to_string(mixed.join(".env")).unwrap(),
        "SECRET=2\n"
    );
    assert_eq!(
        listing(&mixed.join("node_modules")),
        listing(&ws.join("node_modules"))
    );

    fs::write(package_dir(&ws, 3).join("lib/index.js"), "edited\n").unwrap();
    let bulk = snap(&mut new, Class::Bulk, 4);
    let section = bulk.manifest.manifest.sections.bulk.section().unwrap();
    assert_eq!(section.format, FORMAT_DIR_PACKS);
    assert_eq!(section.dir_packs.len(), 1, "every dir object packed anew");
    s.ship(&new);
    // Applied over the mixed restore: only the edit is written, no dir object is fetched alone.
    let (again, report) = s.materialize("restore-mixed");
    assert_eq!(report.dir_objects_fetched, 0, "{report:?}");
    assert_eq!(report.files, 1, "{report:?}");
    assert_eq!(
        listing(&again.join("node_modules")),
        listing(&ws.join("node_modules"))
    );
}

/// A registrar that does not announce `manifest_format` 2 gets format 1, and one that does gets
/// dir packs: an executor never writes a capture its registrar cannot restore.
#[test]
fn the_registrar_decides_the_format() {
    let plan = |registrar: &InMemoryRegistrar| {
        registrar
            .plan_get(&PlanGetRequest::booting(None))
            .unwrap()
            .manifest_format
    };
    assert_eq!(
        DirFormat::for_registrar(plan(&InMemoryRegistrar::new("wt", 1, None))),
        DirFormat::Packs
    );
    let old = InMemoryRegistrar::new("wt", 1, None).with_manifest_format(FORMAT_DIR_OBJECTS);
    assert_eq!(DirFormat::for_registrar(plan(&old)), DirFormat::Objects);
    // An answer without the field (a registrar older than dir packs).
    let answer: sealant_capture::registrar::PlanGetResponse =
        serde_json::from_str(r#"{"worktree_id":"wt","epoch":1,"head":null}"#).unwrap();
    assert_eq!(answer.manifest_format, FORMAT_DIR_OBJECTS);

    // A capture staged for each: format 1 names keys, format 2 digests and dir packs.
    let s = session(3, Duration::ZERO);
    let mut engine = s.engine(DirFormat::Objects, None);
    let staged = snap(&mut engine, Class::Small, 1);
    let ws = &staged.manifest.manifest.sections.workspace;
    assert_eq!(tree_keys(ws.tree()), vec![ws.root.clone()]);
    engine.set_dir_format(DirFormat::Packs);
    fs::write(s.root.join(".env"), "SECRET=3\n").unwrap();
    let staged = snap(&mut engine, Class::Small, 2);
    let ws = &staged.manifest.manifest.sections.workspace;
    assert_eq!(ws.format, FORMAT_DIR_PACKS);
    assert_eq!(tree_keys(ws.tree()), ws.dir_packs);
    s.ship(&engine);
    let (restore, _) = s.materialize("restore");
    assert_eq!(
        fs::read_to_string(restore.join(".env")).unwrap(),
        "SECRET=3\n"
    );
}

/// A section in a format this build does not read is refused before anything is written.
#[test]
fn a_newer_section_format_is_refused() {
    let s = session(2, Duration::ZERO);
    let mut engine = s.engine(DirFormat::Packs, None);
    snap(&mut engine, Class::Small, 1);
    snap(&mut engine, Class::Bulk, 2);
    s.ship(&engine);
    let mut manifest = s.head();
    if let BulkState::Ready(bulk) = &mut manifest.sections.bulk {
        bulk.format = 3;
    }
    let restore = s.base.join("restore");
    let error = Materializer::new(s.sink.as_ref(), MaterializeTargets::new(&restore, None))
        .materialize(&manifest, MaterializeClass::All)
        .unwrap_err();
    assert!(
        matches!(
            error,
            MaterializeError::UnsupportedFormat {
                section: "bulk",
                format: 3
            }
        ),
        "{error}"
    );
    assert!(!restore.join("src").exists(), "nothing was written");
}

/// Uploads run several at a time — never more than the configured number — and a capture of
/// many objects still ships whole.
#[test]
fn uploads_run_in_parallel_up_to_the_bound() {
    let s = session(40, Duration::from_millis(20));
    let mut engine = s.engine(DirFormat::Objects, None);
    snap(&mut engine, Class::Small, 1);
    snap(&mut engine, Class::Bulk, 2);
    let objects = engine
        .staging()
        .pending()
        .unwrap()
        .iter()
        .map(|e| e.uploads.len())
        .sum::<usize>();
    assert!(objects > 100, "{objects}");
    let start = std::time::Instant::now();
    s.ship(&engine);
    let took = start.elapsed();
    let most = s.sink.max_in_flight.load(Ordering::SeqCst);
    eprintln!("{objects} objects in {took:?}, at most {most} in flight");
    assert_eq!(most, sealant_capture::ship::DEFAULT_UPLOADS_IN_FLIGHT);
    assert!(
        took < Duration::from_millis(20) * objects as u32 / 3,
        "{took:?} for {objects} objects"
    );
    let (restore, _) = s.materialize("restore");
    assert_eq!(
        listing(&restore.join("node_modules")),
        listing(&s.root.join("node_modules"))
    );

    // One at a time when asked.
    let s = session(5, Duration::from_millis(5));
    let mut config = CaptureConfig::new("wt", 1, &s.root);
    config.dir_format = DirFormat::Objects;
    config.uploads_in_flight = 1;
    let mut engine = CaptureEngine::open(config, None).unwrap();
    snap(&mut engine, Class::Small, 1);
    snap(&mut engine, Class::Bulk, 2);
    s.ship(&engine);
    assert_eq!(s.sink.max_in_flight.load(Ordering::SeqCst), 1);
}
