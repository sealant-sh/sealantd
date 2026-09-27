//! A restored executor's next capture is incremental. Docker end to end (2026-09-27, the Mend
//! repository with a 140k-file `node_modules`): after every resume the first bulk capture read
//! all 119,414 files and uploaded 1.4 GB again, for one new 300 MB file — the new epoch forgot
//! where the restored chunks are (chunk locations from an earlier epoch were dropped), so no
//! materialized file's index entry could be reused. The engine now learns them from the packs
//! the registered head names that the materializer left in its cache.

use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::Arc;

use sealant_capture::manifest::BulkState;
use sealant_capture::{
    BlobSink, CaptureConfig, CaptureEngine, CaptureKind, Class, InMemoryRegistrar, LocalDir,
    MaterializeClass, MaterializeTargets, Materializer, Registrar, SnapRequest,
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

fn noise(seed: u64, len: usize) -> Vec<u8> {
    let mut x = seed.wrapping_mul(6364136223846793005).wrapping_add(1);
    (0..len)
        .map(|_| {
            x = x
                .wrapping_mul(6364136223846793005)
                .wrapping_add(1442695040888963407);
            (x >> 33) as u8
        })
        .collect()
}

fn files(dir: &Path) -> Vec<(String, Vec<u8>)> {
    let mut out: Vec<(String, Vec<u8>)> = walkdir::WalkDir::new(dir)
        .into_iter()
        .filter_map(Result::ok)
        .filter(|e| e.file_type().is_file())
        .map(|e| {
            (
                e.path()
                    .strip_prefix(dir)
                    .unwrap()
                    .to_string_lossy()
                    .into_owned(),
                fs::read(e.path()).unwrap(),
            )
        })
        .collect();
    out.sort();
    out
}

fn snap(engine: &mut CaptureEngine, class: Class, seq: u64) -> sealant_capture::StagedCapture {
    engine
        .snap(SnapRequest {
            kind: CaptureKind::Auto,
            class,
            seq,
        })
        .unwrap()
}

/// Executor 1 captures a repository with a dependency tree; executor 2 (a new epoch, a fresh
/// disk) restores the head and captures again: nothing is read or packed again, and one new file
/// costs one file's read and its bytes.
#[test]
fn a_restored_executor_reads_and_uploads_only_what_changed() {
    let tmp = tempfile::tempdir().unwrap();
    let base = tmp.path();
    let store = Arc::new(LocalDir::new(&base.join("store")).unwrap());
    let sink: Arc<dyn BlobSink> = store.clone();
    let registrar = Arc::new(InMemoryRegistrar::new("wt", 1, None));
    let registrar_dyn: Arc<dyn Registrar> = registrar.clone();

    let one = base.join("one");
    fs::create_dir_all(one.join("src")).unwrap();
    git(&one, &["init", "-q", "-b", "main"]);
    git(&one, &["config", "user.email", "t@t"]);
    git(&one, &["config", "user.name", "t"]);
    fs::write(one.join(".gitignore"), "node_modules/\n").unwrap();
    fs::write(one.join("src/lib.rs"), "pub fn f() {}\n").unwrap();
    git(&one, &["add", "-A"]);
    git(&one, &["commit", "-q", "-m", "one"]);
    for p in 0..30 {
        let dir = one.join(format!("node_modules/pkg{p}"));
        fs::create_dir_all(&dir).unwrap();
        for f in 0..10 {
            fs::write(dir.join(format!("m{f}.js")), noise(p * 100 + f, 3_000)).unwrap();
        }
    }
    let mut first = CaptureEngine::open(CaptureConfig::new("wt", 1, &one), None).unwrap();
    snap(&mut first, Class::Small, 1);
    snap(&mut first, Class::Bulk, 2);
    first
        .shipper(sink.clone(), registrar_dyn.clone())
        .ship_pending()
        .unwrap();
    let head = registrar.head().unwrap();
    assert!(matches!(head.manifest.sections.bulk, BulkState::Ready(_)));

    // Executor 2: epoch 2, a fresh disk, the head materialized the way boot does it.
    registrar.set_live_epoch(2);
    let two: PathBuf = base.join("two");
    let config = CaptureConfig::new("wt", 2, &two);
    let mut targets = MaterializeTargets::new(&two, None);
    targets.bulk_dirs = config.bulk_dirs.clone();
    let materializer = Materializer::new(store.as_ref(), targets);
    let manifest = materializer
        .fetch_manifest(&head.manifest_key, &head.capture_id)
        .unwrap();
    materializer
        .materialize(&manifest.manifest, MaterializeClass::All)
        .unwrap();
    assert_eq!(
        files(&two.join("node_modules")),
        files(&one.join("node_modules"))
    );
    let mut second = CaptureEngine::open(config, Some(manifest)).unwrap();

    let again = snap(&mut second, Class::Bulk, 3);
    assert_eq!(
        again.stats.files_read, 0,
        "nothing restored is read again: {:?}",
        again.stats
    );
    assert_eq!(again.stats.cdc_packs, 0, "nothing is packed again");

    fs::write(two.join("node_modules/pkg0/new.js"), noise(999_999, 50_000)).unwrap();
    let grown = snap(&mut second, Class::Bulk, 4);
    assert_eq!(grown.stats.files_read, 1, "{:?}", grown.stats);
    assert!(
        grown.stats.cdc_pack_bytes < 100_000,
        "one file's bytes, not the tree's: {:?}",
        grown.stats
    );
    let BulkState::Ready(bulk) = &grown.manifest.manifest.sections.bulk else {
        panic!("bulk captured");
    };
    assert!(
        bulk.packs.iter().any(|k| k.starts_with("captures/wt/1/")),
        "the restored chunks stay where the chain put them"
    );
    second
        .shipper(sink.clone(), registrar_dyn)
        .ship_pending()
        .unwrap();

    let out = base.join("restored");
    Materializer::new(store.as_ref(), MaterializeTargets::new(&out, None))
        .materialize(&registrar.head().unwrap().manifest, MaterializeClass::All)
        .unwrap();
    assert_eq!(
        files(&out.join("node_modules")),
        files(&two.join("node_modules"))
    );
}
