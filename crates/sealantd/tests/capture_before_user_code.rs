//! Capture runs before any user code (cross-repo decision 8, review 2026-09-28 #9): a boot
//! starts the capture engine as soon as the workspace is materialized, before dotfiles,
//! lifecycle setup and startup steps and the harness, and every exit after that point runs the
//! engine's final flush. Before, the engine started only once the harness was running: a setup
//! step wrote for as long as it liked with no capture timer, and a failing one ended the boot
//! with no final flush at all — what it wrote was on the disk only.
//!
//! One test in its own binary on purpose: the boot becomes this process's orphan reaper and
//! its final flush sweeps every descendant, as the daemon's does.

use std::collections::HashMap;
use std::path::Path;
use std::process::Command as Proc;
use std::sync::Arc;

use sealant_capture::{
    BlobSink, CaptureConfig, CaptureEngine, InMemoryRegistrar, LocalDir, MaterializeClass,
    MaterializeTargets, Materializer, Registrar,
};
use sealantd::boot::capture::{CaptureBoot, SourceLayout};
use sealantd::boot::config::{BootConfig, EnvSource};

struct Env(HashMap<String, String>);

impl EnvSource for Env {
    fn get(&self, key: &str) -> Option<String> {
        self.0.get(key).cloned()
    }
    fn entries(&self) -> Vec<(String, String)> {
        self.0.iter().map(|(k, v)| (k.clone(), v.clone())).collect()
    }
}

fn git(root: &Path, args: &[&str]) {
    let out = Proc::new("git")
        .current_dir(root)
        .env("GIT_OPTIONAL_LOCKS", "0")
        .args(args)
        .output()
        .expect("git");
    assert!(out.status.success(), "git {args:?}");
}

#[test]
fn a_failing_setup_step_is_captured_and_final_flushed() {
    let tmp = tempfile::tempdir().unwrap();
    let base = tmp.path();
    let ws = base.join("ws");
    std::fs::create_dir_all(&ws).unwrap();
    git(&ws, &["init", "-q", "-b", "main"]);
    git(&ws, &["config", "user.email", "t@t"]);
    git(&ws, &["config", "user.name", "t"]);
    std::fs::write(ws.join("lib.rs"), "pub fn f() {}\n").unwrap();
    git(&ws, &["add", "-A"]);
    git(&ws, &["commit", "-q", "-m", "one"]);

    let registrar = Arc::new(InMemoryRegistrar::new("wt-early", 1, None).with_executor("launch-1"));
    let store = Arc::new(LocalDir::new(&base.join("store")).unwrap());
    let sink: Arc<dyn BlobSink> = store.clone();
    let mut capture_config = CaptureConfig::new("wt-early", 1, &ws);
    capture_config.executor = Some("launch-1".to_owned());
    let engine = CaptureEngine::open(capture_config, None).unwrap();
    let dyn_registrar: Arc<dyn Registrar> = registrar.clone();
    let boot = CaptureBoot {
        engine,
        sink,
        registrar: dyn_registrar,
        minter: None,
        worktree_id: "wt-early".to_owned(),
        epoch: 1,
        layout: SourceLayout {
            workspace_root: base.to_path_buf(),
            working_directory: ws.clone(),
            staging_dir: ws.join(".sealantd/capture"),
        },
        resumed: false,
    };

    let path = std::env::var("PATH").unwrap_or_default();
    let env = Env([
        ("SEALANT_WORKSPACE_SOURCE", "capture"),
        ("SEALANT_CAPTURE_ENDPOINT", "http://127.0.0.1:9/unused"),
        ("SEALANT_WORKSPACE_ROOT", &base.display().to_string()),
        ("SEALANT_WORKING_DIRECTORY", &ws.display().to_string()),
        (
            "SEALANT_CONTROL_SOCKET",
            &base.join("run/control.sock").display().to_string(),
        ),
        (
            "SEALANT_SESSION_JOURNAL_DIR",
            &base.join("journals").display().to_string(),
        ),
        ("SEALANT_OS_FAMILY", "fedora"),
        ("SEALANT_SHUTDOWN_GRACE_MS", "2000"),
        ("SEALANT_HARNESS_LAUNCH_COMMAND", "exit 0"),
        (
            "SEALANT_LIFECYCLE_SETUP_JSON",
            r#"[{"run":"echo work the setup step wrote > setup.txt; exit 3","shell":"sh"}]"#,
        ),
        ("PATH", &path),
    ]
    .into_iter()
    .map(|(k, v)| (k.to_owned(), v.to_owned()))
    .collect());
    let config = BootConfig::load(&env).expect("boot config");
    std::fs::create_dir_all(base.join("run")).unwrap();

    let code = sealantd::boot::run_supervised(config, Vec::new(), Some(boot));

    // The boot fails with the step's own code: its final flush completed, so not 75.
    assert_eq!(
        format!("{code:?}"),
        format!("{:?}", std::process::ExitCode::from(3)),
        "the failing step's exit code"
    );
    let head = registrar.head().expect(
        "the setup step's work is registered: a capture ran before it and a final flush after",
    );
    assert!(
        head.manifest.final_seal.is_some(),
        "the exit ran the final flush: {:?}",
        head.manifest
    );
    let out = base.join("restored");
    Materializer::new(store.as_ref(), MaterializeTargets::new(&out, None))
        .materialize(&head.manifest, MaterializeClass::All)
        .unwrap();
    assert_eq!(
        std::fs::read_to_string(out.join("setup.txt")).unwrap(),
        "work the setup step wrote\n"
    );
}
