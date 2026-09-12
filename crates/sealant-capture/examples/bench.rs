//! Measure snap / ship / materialize on a real workspace.
//!
//! `cargo run --release --example bench -- <root> --out <dir> [--home <harness home>] [--bulk]`
//!
//! Staging, the store and the restore all go under `--out`; the workspace itself is only read
//! (git writes tree objects for the closure into its object store, nothing else).

use std::path::PathBuf;
use std::sync::Arc;
use std::time::Instant;

use sealant_capture::gitpack::GitRepo;
use sealant_capture::{
    CaptureConfig, CaptureEngine, CaptureKind, Class, InMemoryRegistrar, LocalDir,
    MaterializeClass, MaterializeTargets, Materializer, SnapRequest,
};

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let root = PathBuf::from(args.first().expect("root"));
    let mut out = None;
    let mut home = None;
    let mut bulk = false;
    let mut i = 1;
    while i < args.len() {
        match args[i].as_str() {
            "--out" => {
                out = Some(PathBuf::from(&args[i + 1]));
                i += 2;
            }
            "--home" => {
                home = Some(PathBuf::from(&args[i + 1]));
                i += 2;
            }
            "--bulk" => {
                bulk = true;
                i += 1;
            }
            other => panic!("unknown arg {other}"),
        }
    }
    let out = out.expect("--out <dir>");
    let mut config = CaptureConfig::new("bench", 1, &root);
    config.staging_dir = Some(out.join("staging"));
    config.harness_home = home;
    let sink = Arc::new(LocalDir::new(&out.join("store")).unwrap());
    let registrar = Arc::new(InMemoryRegistrar::new("bench", 1, None));
    let mut engine = CaptureEngine::open(config, None).unwrap();

    let t = Instant::now();
    let small = engine
        .snap(SnapRequest {
            kind: CaptureKind::Checkpoint,
            class: Class::Small,
            seq: 1,
        })
        .unwrap();
    println!(
        "small snap: {:?} {}",
        t.elapsed(),
        serde_json::to_string(&small.stats).unwrap()
    );
    if bulk {
        let t = Instant::now();
        let b = engine
            .snap(SnapRequest {
                kind: CaptureKind::Auto,
                class: Class::Bulk,
                seq: 2,
            })
            .unwrap();
        println!(
            "bulk snap: {:?} {}",
            t.elapsed(),
            serde_json::to_string(&b.stats).unwrap()
        );
    }
    let t = Instant::now();
    let shipper = engine
        .shipper(sink.clone(), registrar.clone())
        .with_cpu_fraction(1.0);
    let n = shipper.ship_pending().unwrap();
    println!(
        "ship: {:?} captures={n} {:?}",
        t.elapsed(),
        shipper.status.snapshot()
    );
    let t = Instant::now();
    let second = engine
        .snap(SnapRequest {
            kind: CaptureKind::Auto,
            class: Class::Small,
            seq: 3,
        })
        .unwrap();
    println!(
        "second small snap (no change): {:?} {}",
        t.elapsed(),
        serde_json::to_string(&second.stats).unwrap()
    );
    shipper.ship_pending().unwrap();

    let head = registrar.head().unwrap();
    let restore = out.join("restore");
    let m = Materializer::new(
        sink.as_ref(),
        MaterializeTargets::new(&restore, Some(out.join("restore-home"))),
    );
    let t = Instant::now();
    let class = if bulk {
        MaterializeClass::All
    } else {
        MaterializeClass::Git
    };
    let report = m.materialize(&head.manifest, class).unwrap();
    println!("materialize ({class:?}): {:?} {report:?}", t.elapsed());
    if !bulk {
        let t = Instant::now();
        let report = m
            .materialize(&head.manifest, MaterializeClass::Workspace)
            .unwrap();
        println!("materialize (workspace): {:?} {report:?}", t.elapsed());
    }
    let t = Instant::now();
    let fsck = GitRepo::open(&restore).unwrap().fsck().unwrap();
    println!("restore fsck: {fsck:?} in {:?}", t.elapsed());
    let orig = GitRepo::open(&root).unwrap().status_porcelain().unwrap();
    let back = GitRepo::open(&restore).unwrap().status_porcelain().unwrap();
    println!("status identical: {}", orig == back);
    if orig != back {
        println!("--- original\n{orig}\n--- restore\n{back}");
    }
}
