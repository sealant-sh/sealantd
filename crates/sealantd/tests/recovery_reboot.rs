//! A recovery reboot on a still-running machine (review 2026-09-28 #7; what Core's MicroVM
//! agent runs after `sealantd boot` exited 75 and the VM is still up): `sealantd boot
//! --recovery`, with the first boot's environment and secret environment file, on the same
//! disk. The first daemon materialized the head, staged a capture and died before shipping it,
//! and the user wrote more after that snap. The recovery boot resumes the disk as it is — its
//! stale control socket replaced, no dotfiles, lifecycle step or harness run, nothing admitted
//! — and its final flush, on the stop, registers everything, sealed. A second boot on the same
//! disk while it runs (the real binary, `--recovery`) is refused with 75 and touches nothing.
//!
//! One test in its own binary on purpose: the boot becomes this process's orphan reaper, its
//! final flush sweeps every descendant, and the stop is this process's own `SIGTERM`.

use std::collections::HashMap;
use std::path::Path;
use std::process::Command as Proc;
use std::sync::Arc;
use std::time::{Duration, Instant};

use sealant_capture::{
    BlobSink, CaptureConfig, CaptureEngine, CaptureKind, Class, InMemoryRegistrar, LocalDir,
    MaterializeClass, MaterializeTargets, Materializer, Registrar, SnapRequest,
};
use sealantd::boot::capture::boot_from;
use sealantd::boot::config::{BootConfig, CaptureSourceConfig, EnvSource};
use sealantd::boot::lock::DiskLock;

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

fn source(recovery: bool) -> CaptureSourceConfig {
    CaptureSourceConfig {
        endpoint: "http://127.0.0.1:9/unused".to_owned(),
        worktree_id: None,
        harness_home: None,
        raise_inotify_limit: false,
        allow_plaintext: false,
        ca_pem: None,
        ca_file: None,
        object_ca_pem: None,
        object_ca_file: None,
        recovery,
        launch_id: None,
    }
}

/// Every file under `dir` but the daemon's own directory, with its bytes, sorted.
fn work(dir: &Path) -> Vec<(String, Vec<u8>)> {
    let mut out = Vec::new();
    let mut stack = vec![dir.to_path_buf()];
    while let Some(d) = stack.pop() {
        for entry in std::fs::read_dir(&d).unwrap() {
            let path = entry.unwrap().path();
            let rel = path.strip_prefix(dir).unwrap().display().to_string();
            if rel == ".sealantd" || rel == ".git" {
                continue;
            }
            if path.is_dir() {
                stack.push(path);
            } else {
                out.push((rel, std::fs::read(&path).unwrap()));
            }
        }
    }
    out.sort();
    out
}

#[test]
fn a_recovery_reboot_on_its_own_disk_saves_it_and_a_second_is_refused() {
    let tmp = tempfile::tempdir().unwrap();
    let base = tmp.path();

    // The chain head: a repository captured by another executor.
    let src = base.join("src");
    std::fs::create_dir_all(&src).unwrap();
    git(&src, &["init", "-q", "-b", "main"]);
    git(&src, &["config", "user.email", "t@t"]);
    git(&src, &["config", "user.name", "t"]);
    std::fs::write(src.join("lib.rs"), "pub fn f() {}\n").unwrap();
    git(&src, &["add", "-A"]);
    git(&src, &["commit", "-q", "-m", "one"]);
    let registrar = Arc::new(InMemoryRegistrar::new("wt-rec", 1, None).with_executor("launch-1"));
    let dyn_registrar: Arc<dyn Registrar> = registrar.clone();
    let store = Arc::new(LocalDir::new(&base.join("store")).unwrap());
    let sink: Arc<dyn BlobSink> = store.clone();
    let mut engine = CaptureEngine::open(CaptureConfig::new("wt-rec", 1, &src), None).unwrap();
    engine
        .snap(SnapRequest {
            kind: CaptureKind::Checkpoint,
            class: Class::Small,
            seq: 1,
        })
        .unwrap();
    engine
        .shipper(sink.clone(), dyn_registrar.clone())
        .ship_pending()
        .unwrap();
    drop(engine);

    // The first daemon: materialized, staged a capture it never shipped, and died; the user
    // wrote more after that snap.
    let workspace_root = base.join("workspace");
    let disk = workspace_root.join("repo");
    let first = boot_from(
        dyn_registrar.clone(),
        Some(sink.clone()),
        &source(false),
        &disk,
        &workspace_root,
    )
    .unwrap();
    std::fs::write(disk.join("staged.txt"), "staged, never shipped\n").unwrap();
    let mut engine = first.engine;
    engine
        .snap(SnapRequest {
            kind: CaptureKind::Turn,
            class: Class::Small,
            seq: 2,
        })
        .unwrap();
    drop(engine);
    std::fs::write(disk.join("unsaved.txt"), "after the last snap\n").unwrap();
    // Its control socket is left behind.
    let socket = base.join("run/control.sock");
    std::fs::create_dir_all(socket.parent().unwrap()).unwrap();
    drop(std::os::unix::net::UnixListener::bind(&socket).unwrap());
    assert!(socket.exists());

    let path = std::env::var("PATH").unwrap_or_default();
    let env_pairs: Vec<(String, String)> = [
        ("SEALANT_WORKSPACE_SOURCE", "capture"),
        ("SEALANT_CAPTURE_ENDPOINT", "http://127.0.0.1:9/unused"),
        (
            "SEALANT_WORKSPACE_ROOT",
            &workspace_root.display().to_string(),
        ),
        ("SEALANT_WORKING_DIRECTORY", &disk.display().to_string()),
        ("SEALANT_CONTROL_SOCKET", &socket.display().to_string()),
        (
            "SEALANT_SESSION_JOURNAL_DIR",
            &base.join("journals").display().to_string(),
        ),
        ("SEALANT_OS_FAMILY", "fedora"),
        ("SEALANT_SHUTDOWN_GRACE_MS", "2000"),
        (
            "SEALANT_HARNESS_LAUNCH_COMMAND",
            "echo harness > harness-ran.txt",
        ),
        (
            "SEALANT_LIFECYCLE_SETUP_JSON",
            r#"[{"run":"echo setup > setup-ran.txt","shell":"sh"}]"#,
        ),
        ("PATH", &path),
    ]
    .into_iter()
    .map(|(k, v)| (k.to_owned(), v.to_owned()))
    .collect();
    let before = work(&disk);

    // The recovery reboot, as `run_boot` does it: the disk lock, the boot on the disk as it is,
    // then the supervisor.
    let lock = DiskLock::acquire(&disk).expect("the first daemon is gone");
    let boot = boot_from(
        dyn_registrar.clone(),
        Some(sink.clone()),
        &source(true),
        &disk,
        &workspace_root,
    )
    .unwrap();
    assert!(boot.resumed, "resumed as it is, never materialized over");
    assert_eq!(work(&disk), before);
    let config = BootConfig::load(&Env(env_pairs.iter().cloned().collect()))
        .expect("boot config")
        .into_recovery()
        .expect("a capture store");
    // As a recovery in Docker or Kubernetes runs: sealantd PID 1 of the container, its sweep
    // taking every process there (narrowed here to none: a mark no process holds). A daemon
    // that is not PID 1 and has no helper list from an agent cannot see the dead daemon's
    // orphans, and its recovery never completes (`recovery_sweep.rs`).
    let daemon = std::thread::spawn(move || {
        let code = sealantd::boot::run_supervised_with(config, Vec::new(), Some(boot), |rt| {
            rt.set_sweep_scope_for_test(sealantd::sweep::Scope::Namespace);
            rt.set_sweep_mark(Some(format!("recovery-reboot-{}", std::process::id())));
        });
        drop(lock);
        code
    });

    // Up: the stale socket was replaced by a live one.
    let deadline = Instant::now() + Duration::from_secs(20);
    while std::os::unix::net::UnixStream::connect(&socket).is_err() {
        assert!(
            Instant::now() < deadline,
            "the recovery daemon never listened"
        );
        std::thread::sleep(Duration::from_millis(50));
    }

    // A second boot on the same disk, the real binary, `--recovery`: refused, 75, untouched.
    let second = Proc::new(env!("CARGO_BIN_EXE_sealantd"))
        .args(["boot", "--recovery"])
        .env_clear()
        .envs(env_pairs.iter().map(|(k, v)| (k.as_str(), v.as_str())))
        .output()
        .expect("sealantd boot --recovery");
    let stderr = String::from_utf8_lossy(&second.stderr);
    assert_eq!(second.status.code(), Some(75), "{stderr}");
    assert!(stderr.contains("another sealantd"), "{stderr}");
    assert_eq!(work(&disk), before, "the refused boot touched nothing");

    // The stop: the final flush saves the disk and the daemon exits 0.
    std::thread::sleep(Duration::from_millis(300));
    nix::sys::signal::kill(nix::unistd::Pid::this(), nix::sys::signal::Signal::SIGTERM)
        .expect("SIGTERM");
    let code = daemon.join().expect("the daemon thread");
    assert_eq!(
        format!("{code:?}"),
        format!("{:?}", std::process::ExitCode::SUCCESS),
        "complete"
    );

    assert!(
        !disk.join("setup-ran.txt").exists(),
        "no lifecycle step ran"
    );
    assert!(!disk.join("harness-ran.txt").exists(), "no harness ran");
    let head = registrar.head().expect("registered");
    assert_eq!(
        head.manifest
            .final_seal
            .as_ref()
            .map(|s| s.executor.as_str()),
        Some("launch-1"),
        "sealed under the plan's executor"
    );
    let out = base.join("restored");
    Materializer::new(store.as_ref(), MaterializeTargets::new(&out, None))
        .materialize(&head.manifest, MaterializeClass::All)
        .unwrap();
    assert_eq!(
        std::fs::read_to_string(out.join("staged.txt")).unwrap(),
        "staged, never shipped\n"
    );
    assert_eq!(
        std::fs::read_to_string(out.join("unsaved.txt")).unwrap(),
        "after the last snap\n"
    );
}
