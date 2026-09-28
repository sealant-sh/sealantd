//! A capture boot and the daemon's final flush over it, for the tests that each need a binary
//! of their own (a final flush sweeps every descendant of the process it runs in).

use std::path::{Path, PathBuf};
use std::process::Command as Proc;
use std::sync::Arc;

use sealant_capture::{
    BlobSink, CaptureConfig, CaptureEngine, InMemoryRegistrar, LocalDir, MaterializeClass,
    MaterializeTargets, Materializer, Registrar,
};
use sealant_runtime_core::{RuntimeConfig, new_runtime_id};
use sealantd::boot::capture::{CaptureBoot, SourceLayout};
use sealantd::capture::CaptureRuntime;
use sealantd::{Runtime, ShutdownSignal};

pub(crate) fn git(root: &Path, args: &[&str]) {
    let out = Proc::new("git")
        .current_dir(root)
        .env("GIT_OPTIONAL_LOCKS", "0")
        .args(args)
        .output()
        .expect("git");
    assert!(out.status.success(), "git {args:?}");
}

pub(crate) const EXECUTOR: &str = "exec-r5";

/// A capture boot over `wrap(store)`, its engine sealing under [`EXECUTOR`].
pub(crate) fn boot(
    base: &Path,
    wrap: impl FnOnce(Arc<dyn BlobSink>) -> Arc<dyn BlobSink>,
) -> (CaptureBoot, Arc<InMemoryRegistrar>) {
    let root = base.join("ws");
    std::fs::create_dir_all(root.join("src")).unwrap();
    git(&root, &["init", "-q", "-b", "main"]);
    git(&root, &["config", "user.email", "t@t"]);
    git(&root, &["config", "user.name", "t"]);
    std::fs::write(root.join("src/lib.rs"), "pub fn f() {}\n").unwrap();
    git(&root, &["add", "-A"]);
    git(&root, &["commit", "-q", "-m", "one"]);
    let registrar = Arc::new(InMemoryRegistrar::new("wt-r5", 1, None).with_executor(EXECUTOR));
    let sink = wrap(Arc::new(LocalDir::new(&base.join("store")).unwrap()));
    let mut config = CaptureConfig::new("wt-r5", 1, &root);
    config.executor = Some(EXECUTOR.to_owned());
    let engine = CaptureEngine::open(config, None).unwrap();
    let dyn_registrar: Arc<dyn Registrar> = registrar.clone();
    (
        CaptureBoot {
            engine,
            sink,
            registrar: dyn_registrar,
            minter: None,
            worktree_id: "wt-r5".to_owned(),
            epoch: 1,
            layout: SourceLayout {
                workspace_root: base.to_path_buf(),
                working_directory: root.clone(),
                staging_dir: root.join(".sealantd/capture"),
            },
            resumed: false,
        },
        registrar,
    )
}

/// The daemon's final flush over `boot`, the capture running as it does after the harness
/// started (the watcher included).
pub(crate) async fn final_flush(
    ws: &Path,
    boot: CaptureBoot,
) -> sealant_protocol::CaptureStatusReport {
    let mut config = RuntimeConfig::new(new_runtime_id());
    config.workspace_root = ws.to_path_buf();
    let runtime = Runtime::new(config, Arc::new(ShutdownSignal::new(5_000)));
    runtime.mark_healthy();
    let capture = CaptureRuntime::new(boot);
    assert!(runtime.install_capture(capture.clone()));
    capture.start_without_harness(runtime.clone());
    runtime.final_flush(None, Some(50)).await.unwrap()
}

/// A fresh restore of the chain head.
pub(crate) fn restore(base: &Path, registrar: &InMemoryRegistrar, name: &str) -> PathBuf {
    let head = registrar.head().unwrap();
    let store = LocalDir::new(&base.join("store")).unwrap();
    let fresh = base.join(name);
    Materializer::new(&store, MaterializeTargets::new(&fresh, None))
        .materialize(&head.manifest, MaterializeClass::All)
        .unwrap();
    fresh
}
