//! A recovery boot's final flush seals the hardlinks a tracked file shares with the bulk class.
//!
//! Docker end to end, round 8 (F5): after a `docker kill` and Core's recovery boot, 88 groups of
//! tracked files pnpm had hardlinked into `node_modules` came back as separate files (contents,
//! modes and times intact; only the shared inode lost). A normal Stop kept them. The executor
//! was killed after a bulk snap and before the small snap that would have recorded the links;
//! the recovery boot's final small snap looked the bulk names up in the bulk index the dead
//! daemon wrote, and a restarted container's overlay has another device number (`st_dev`
//! changes with every mount; the inode numbers stay). Every bulk name read as "not that inode
//! any more", was left out without a word (not even deferred), the final bulk snap found the
//! bulk class unchanged, and the chain was sealed with no link.
//!
//! The test takes the same steps on one disk: the executor's small and bulk snaps, the kill
//! before the small snap after them, the remount (every device number the dead daemon recorded
//! is not the disk's any more), and the recovery boot's final flush. It must seal the links, or
//! not seal at all.

use std::fs;
use std::os::unix::fs::MetadataExt;
use std::path::Path;
use std::process::Command;
use std::sync::Arc;

use sealant_capture::{
    CadenceRunner, CaptureConfig, CaptureEngine, CaptureKind, Class, InMemoryRegistrar, LocalDir,
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
        "git {args:?}: {}",
        String::from_utf8_lossy(&out.stderr)
    );
}

/// Every `dev` the dead daemon recorded under `dir` (its class indexes, its caches), moved to
/// another device: what a restarted container's overlay mount reads for the same inodes.
fn remount(dir: &Path) -> usize {
    fn bump(value: &mut serde_json::Value) -> usize {
        match value {
            serde_json::Value::Object(map) => {
                let mut n = 0;
                for (key, v) in map.iter_mut() {
                    if key == "dev"
                        && let Some(dev) = v.as_u64()
                    {
                        *v = serde_json::Value::from(dev + 1);
                        n += 1;
                    } else {
                        n += bump(v);
                    }
                }
                n
            }
            serde_json::Value::Array(items) => items.iter_mut().map(bump).sum(),
            _ => 0,
        }
    }
    let mut moved = 0;
    for entry in walkdir::WalkDir::new(dir).into_iter().flatten() {
        let path = entry.path();
        if !entry.file_type().is_file() || path.extension().is_none_or(|e| e != "json") {
            continue;
        }
        let Ok(mut value) = serde_json::from_slice::<serde_json::Value>(&fs::read(path).unwrap())
        else {
            continue;
        };
        let n = bump(&mut value);
        if n > 0 {
            fs::write(path, serde_json::to_vec(&value).unwrap()).unwrap();
            moved += n;
        }
    }
    moved
}

fn config(root: &Path) -> CaptureConfig {
    let mut config = CaptureConfig::new("wt", 1, root);
    config.executor = Some("exec-1".to_owned());
    config
}

/// The executor's small and bulk snaps, the kill before the small snap after them, `between`
/// (what happened to the disk while no daemon ran), and the recovery boot's final flush: it
/// seals the links, or does not seal.
fn kill_then_recover(between: impl FnOnce(&Path)) {
    let tmp = tempfile::tempdir().unwrap();
    let base = tmp.path();
    let root = base.join("ws");
    fs::create_dir_all(root.join("packages/util")).unwrap();
    git(&root, &["init", "-q", "-b", "main"]);
    git(&root, &["config", "user.email", "t@t"]);
    git(&root, &["config", "user.name", "t"]);
    fs::write(root.join(".gitignore"), "node_modules/\n").unwrap();
    for f in ["index.js", "lib.js", "package.json"] {
        fs::write(root.join("packages/util").join(f), format!("// {f}\n")).unwrap();
    }
    git(&root, &["add", "-A"]);
    git(&root, &["commit", "-q", "-m", "util"]);
    // What pnpm does for a `file:` dependency: the package's tracked files, hardlinked.
    fs::create_dir_all(root.join("node_modules/util")).unwrap();
    for f in ["index.js", "lib.js", "package.json"] {
        fs::hard_link(
            root.join("packages/util").join(f),
            root.join("node_modules/util").join(f),
        )
        .unwrap();
    }
    fs::create_dir_all(root.join("node_modules/other")).unwrap();
    fs::write(
        root.join("node_modules/other/m.js"),
        "module.exports = 1;\n",
    )
    .unwrap();

    let store = Arc::new(LocalDir::new(&base.join("store")).unwrap());
    let registrar = Arc::new(InMemoryRegistrar::new("wt", 1, None).with_executor("exec-1"));

    // The executor before the kill: a small snap, then a bulk snap. The small snap after it
    // (the one that records the tracked files' bulk names) never runs.
    {
        let mut engine = CaptureEngine::open(config(&root), None).unwrap();
        for (class, seq) in [(Class::Small, 1), (Class::Bulk, 2)] {
            engine
                .snap(SnapRequest {
                    kind: CaptureKind::Auto,
                    class,
                    seq,
                })
                .unwrap();
        }
        // Killed: nothing shipped, the queue and the indexes stay on the disk.
    }
    between(&config(&root).staging_dir());

    // The recovery boot over the same disk: no writer, a final flush.
    let engine = CaptureEngine::open(config(&root), None).unwrap();
    let dyn_registrar: Arc<dyn Registrar> = registrar.clone();
    let shipper = Arc::new(engine.shipper(store.clone(), dyn_registrar));
    let runner = CadenceRunner::new(engine, shipper);
    runner.start(None);
    let flushed = runner.flush_final(None);
    runner.stop();
    let sealed = !registrar.seals().is_empty();
    assert_eq!(
        flushed.complete(),
        sealed,
        "a seal stands exactly when the flush is complete: {flushed:?}"
    );

    let head = registrar.head().expect("the recovery registered the chain");
    let fresh = base.join("fresh");
    Materializer::new(store.as_ref(), MaterializeTargets::new(&fresh, None))
        .materialize(&head.manifest, MaterializeClass::All)
        .unwrap();
    let apart: Vec<&str> = ["index.js", "lib.js", "package.json"]
        .into_iter()
        .filter(|f| {
            let tracked = fs::metadata(fresh.join("packages/util").join(f)).unwrap();
            let bulk = fs::metadata(fresh.join("node_modules/util").join(f)).unwrap();
            (tracked.dev(), tracked.ino()) != (bulk.dev(), bulk.ino())
        })
        .collect();
    assert!(
        !sealed || apart.is_empty(),
        "sealed without the links: {apart:?} came back as separate files"
    );
    assert!(
        flushed.complete(),
        "the disk holds the links: the recovery seals them ({flushed:?})"
    );
}

/// Docker end to end, round 8 (F5): the container restarted, its overlay under another device
/// number.
#[test]
fn a_recovery_after_a_remount_seals_the_tracked_files_bulk_links() {
    kill_then_recover(|staging| {
        let moved = remount(staging);
        assert!(moved > 0, "the dead daemon recorded device numbers");
    });
}

/// The bulk index the dead daemon wrote is gone (or unreadable, which loads as empty): the
/// recovery's first small snap knows no bulk name at all, and the final bulk snap finds the
/// class as its last capture holds it.
#[test]
fn a_recovery_without_the_bulk_index_seals_the_tracked_files_bulk_links() {
    kill_then_recover(|staging| {
        let index = staging.join("index/bulk.json");
        assert!(index.exists(), "{}", index.display());
        fs::remove_file(index).unwrap();
    });
}
