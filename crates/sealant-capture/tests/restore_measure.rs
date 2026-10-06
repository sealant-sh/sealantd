//! Restore time and bytes on a real worktree: capture it once into a local store (both classes,
//! the harness home with it), then materialize the head into a fresh directory several times and
//! print each run. Per-person harness homes (Mend's ADR 0016) budget restore time and bytes at +5%
//! or +1 s; this is the measurement each of its sealantd changes states.
//!
//! ```text
//! RESTORE_MEASURE_SOURCE=/path/to/worktree RESTORE_MEASURE_HOME=/path/to/harness-home \
//! RESTORE_MEASURE_STORE=/tmp/m/store RESTORE_MEASURE_OUT=/tmp/m/out RESTORE_MEASURE_RUNS=5 \
//! cargo test -p sealant-capture --release --test restore_measure -- --ignored --nocapture
//! ```
//!
//! The store is made on the first run and reused after (its head is in `head.json` beside it), so
//! two builds measure the same capture. This file names only API that predates the per-person
//! stack, so it compiles against `main` for the "before" numbers; a variant that needs newer API
//! (`restore_measure_owners.rs`) includes it and calls [`measure`].

use std::fs;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Instant;

use sealant_capture::{
    CaptureConfig, CaptureEngine, CaptureKind, Class, InMemoryRegistrar, LocalDir,
    MaterializeClass, MaterializeTargets, Materializer, SnapRequest,
};

fn env_path(name: &str) -> Option<PathBuf> {
    std::env::var_os(name)
        .filter(|v| !v.is_empty())
        .map(PathBuf::from)
}

/// Capture `source` (and `home`) into `store`, once; answers the head's manifest key and id.
fn head(source: &Path, home: Option<&Path>, store: &Path) -> (String, String) {
    let recorded = store.join("head.json");
    if let Ok(bytes) = fs::read(&recorded) {
        let v: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        return (
            v["manifest_key"].as_str().unwrap().to_owned(),
            v["capture_id"].as_str().unwrap().to_owned(),
        );
    }
    let sink = Arc::new(LocalDir::new(store).unwrap());
    let registrar = Arc::new(InMemoryRegistrar::new("wt-measure", 1, None));
    let mut config = CaptureConfig::new("wt-measure", 1, source);
    config.harness_home = home.map(Path::to_path_buf);
    config.racy_window = std::time::Duration::ZERO;
    let mut engine = CaptureEngine::open(config, None).unwrap();
    let started = Instant::now();
    for (seq, class) in [(1, Class::Small), (2, Class::Bulk)] {
        engine
            .snap(SnapRequest {
                kind: CaptureKind::Auto,
                class,
                seq,
            })
            .unwrap();
    }
    engine
        .shipper(sink, registrar.clone())
        .ship_pending()
        .unwrap();
    let head = registrar.head().unwrap();
    eprintln!(
        "captured {} into {} in {:.1} s",
        source.display(),
        store.display(),
        started.elapsed().as_secs_f64()
    );
    fs::write(
        &recorded,
        serde_json::json!({ "manifest_key": head.manifest_key, "capture_id": head.capture_id })
            .to_string(),
    )
    .unwrap();
    (head.manifest_key, head.capture_id)
}

#[test]
#[ignore = "a measurement over a real worktree: set RESTORE_MEASURE_* and run with --ignored"]
fn restore_a_real_worktree() {
    measure(|_root, _targets| {});
}

/// Restore the store's head `RESTORE_MEASURE_RUNS` times into fresh directories, timing each from
/// `prepare` (called first, with the run's worktree root and targets: what a variant does before a
/// restore, an executor's preparation included) to the end of the materialize. Prints one
/// `restore-run <seconds> <files> <bytes>` line per run (a runner interleaving two builds run by
/// run reads these) and the median, p90, min and max. Shared, through `#[path]`, by the variants
/// that need API this file must not name to keep compiling against older commits.
#[allow(dead_code)]
pub fn measure(prepare: impl Fn(&Path, &mut MaterializeTargets)) {
    let (Some(source), Some(store), Some(out)) = (
        env_path("RESTORE_MEASURE_SOURCE"),
        env_path("RESTORE_MEASURE_STORE"),
        env_path("RESTORE_MEASURE_OUT"),
    ) else {
        panic!("set RESTORE_MEASURE_SOURCE, RESTORE_MEASURE_STORE and RESTORE_MEASURE_OUT");
    };
    let home = env_path("RESTORE_MEASURE_HOME");
    let runs: usize = std::env::var("RESTORE_MEASURE_RUNS")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(5);
    fs::create_dir_all(&store).unwrap();
    let (manifest_key, capture_id) = head(&source, home.as_deref(), &store);
    let sink = LocalDir::new(&store).unwrap();
    let mut walls = Vec::new();
    for run in 0..runs {
        let root = out.join(format!("run-{run}/repo"));
        let home = out.join(format!("run-{run}/harness-home"));
        if let Some(parent) = root.parent() {
            fs::remove_dir_all(parent).ok();
            fs::create_dir_all(parent).unwrap();
        }
        let mut targets = MaterializeTargets::new(&root, Some(home));
        let started = Instant::now();
        prepare(&root, &mut targets);
        let materializer = Materializer::new(&sink, targets);
        let manifest = materializer
            .fetch_manifest(&manifest_key, &capture_id)
            .unwrap();
        let report = materializer
            .materialize(&manifest.manifest, MaterializeClass::All)
            .unwrap();
        let wall = started.elapsed();
        walls.push(wall.as_secs_f64());
        eprintln!(
            "restore-run {:.3} {} {}",
            wall.as_secs_f64(),
            report.files,
            report.bytes
        );
        fs::remove_dir_all(root.parent().unwrap()).ok();
    }
    walls.sort_by(f64::total_cmp);
    let at = |q: f64| walls[((walls.len() - 1) as f64 * q).round() as usize];
    eprintln!(
        "restore: median {:.2} s, p90 {:.2} s, min {:.2} s, max {:.2} s over {runs} runs",
        at(0.5),
        at(0.9),
        walls[0],
        walls[walls.len() - 1]
    );
}
