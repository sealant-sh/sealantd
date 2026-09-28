//! Docker end to end, round 5 (session HS): the store went down, Core stopped the executor, and
//! the `SIGTERM` final flush retried the uploads with no deadline — the container ran until
//! Core's 3600 s stop timeout killed it, so the exit-75 path ("keep my disk, recover it") was
//! never reached, and every retry minted fresh upload URLs until the registrar's call quota ran
//! out. With `SEALANT_SHUTDOWN_FINAL_DEADLINE_MS` the shutdown's final flush gives up at that
//! deadline, counted from the `SIGTERM`: the daemon exits 75 with its staging directory as it
//! was — nothing lost, the platform keeps the disk and recovers it — and while it tried, the
//! store's refusals were asked again after a backoff, not in a tight loop.
//!
//! One test in its own binary on purpose: the boot becomes this process's orphan reaper, its
//! final flush sweeps every descendant, and the stop is this process's own `SIGTERM`.

use std::collections::HashMap;
use std::path::Path;
use std::process::Command as Proc;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

use sealant_capture::sink::{BlobSource, PutOutcome, SinkError};
use sealant_capture::{
    BlobSink, CaptureConfig, CaptureEngine, InMemoryRegistrar, LocalDir, Registrar,
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

/// A store that is down: every PUT answers 503 (retryable), and is counted.
struct Down {
    inner: Arc<dyn BlobSink>,
    puts: AtomicU64,
}

impl BlobSink for Down {
    fn put_if_absent(&self, key: &str, _source: BlobSource<'_>) -> Result<PutOutcome, SinkError> {
        self.puts.fetch_add(1, Ordering::SeqCst);
        Err(SinkError::Http {
            method: "PUT",
            key: key.to_owned(),
            status: 503,
        })
    }

    fn get(&self, key: &str) -> Result<Vec<u8>, SinkError> {
        self.inner.get(key)
    }

    fn exists(&self, key: &str) -> Result<bool, SinkError> {
        self.inner.exists(key)
    }
}

#[test]
fn a_shutdown_whose_store_is_down_exits_75_at_its_deadline_with_staging_kept() {
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

    let registrar =
        Arc::new(InMemoryRegistrar::new("wt-deadline", 1, None).with_executor("launch-1"));
    let down = Arc::new(Down {
        inner: Arc::new(LocalDir::new(&base.join("store")).unwrap()),
        puts: AtomicU64::new(0),
    });
    let sink: Arc<dyn BlobSink> = down.clone();
    let mut capture_config = CaptureConfig::new("wt-deadline", 1, &ws);
    capture_config.executor = Some("launch-1".to_owned());
    let engine = CaptureEngine::open(capture_config, None).unwrap();
    let dyn_registrar: Arc<dyn Registrar> = registrar.clone();
    let boot = CaptureBoot {
        engine,
        sink,
        registrar: dyn_registrar,
        minter: None,
        worktree_id: "wt-deadline".to_owned(),
        epoch: 1,
        layout: SourceLayout {
            workspace_root: base.to_path_buf(),
            working_directory: ws.clone(),
            staging_dir: ws.join(".sealantd/capture"),
        },
        resumed: false,
    };

    let socket = base.join("run/control.sock");
    let path = std::env::var("PATH").unwrap_or_default();
    let env = Env([
        ("SEALANT_WORKSPACE_SOURCE", "capture"),
        ("SEALANT_CAPTURE_ENDPOINT", "http://127.0.0.1:9/unused"),
        ("SEALANT_WORKSPACE_ROOT", &base.display().to_string()),
        ("SEALANT_WORKING_DIRECTORY", &ws.display().to_string()),
        ("SEALANT_CONTROL_SOCKET", &socket.display().to_string()),
        (
            "SEALANT_SESSION_JOURNAL_DIR",
            &base.join("journals").display().to_string(),
        ),
        ("SEALANT_OS_FAMILY", "fedora"),
        ("SEALANT_LOGIN_SHELL_PATH", "/bin/sh"),
        ("SEALANT_SHUTDOWN_GRACE_MS", "1000"),
        ("SEALANT_SHUTDOWN_FINAL_DEADLINE_MS", "3000"),
        ("SEALANT_HARNESS_LAUNCH_COMMAND", "exec sleep 3600"),
        ("PATH", &path),
    ]
    .into_iter()
    .map(|(k, v)| (k.to_owned(), v.to_owned()))
    .collect());
    let config = BootConfig::load(&env).expect("boot config");
    std::fs::create_dir_all(base.join("run")).unwrap();

    let (done, exited) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        let code = sealantd::boot::run_supervised(config, Vec::new(), Some(boot));
        let _ = done.send((code, Instant::now()));
    });
    let up = Instant::now() + Duration::from_secs(20);
    while std::os::unix::net::UnixStream::connect(&socket).is_err() {
        assert!(Instant::now() < up, "the daemon never listened");
        std::thread::sleep(Duration::from_millis(50));
    }
    // Work the harness wrote, which the store cannot take.
    std::fs::write(ws.join("work.txt"), "written before the stop\n").unwrap();
    std::thread::sleep(Duration::from_millis(300));

    let sigterm = Instant::now();
    nix::sys::signal::kill(nix::unistd::Pid::this(), nix::sys::signal::Signal::SIGTERM)
        .expect("SIGTERM");
    let (code, at) = exited
        .recv_timeout(Duration::from_secs(30))
        .expect("the daemon exits at its shutdown deadline, not at the platform's kill");
    let took = at.duration_since(sigterm);
    assert_eq!(
        format!("{code:?}"),
        format!("{:?}", std::process::ExitCode::from(75)),
        "not saved: 75"
    );
    assert!(
        took >= Duration::from_millis(2_500) && took < Duration::from_secs(10),
        "exits at the 3 s deadline: {took:?}"
    );

    // Nothing registered, nothing dropped: every capture is still staged on this disk.
    assert!(registrar.seals().is_empty());
    let queued = std::fs::read_dir(ws.join(".sealantd/capture/queue"))
        .map(|d| d.count())
        .unwrap_or(0);
    assert!(queued > 0, "the staging queue is kept");

    // The store's refusals were asked again after a backoff: over ~3 s of retries the
    // shipper sent a bounded number of PUTs, not a tight loop.
    let puts = down.puts.load(Ordering::SeqCst);
    eprintln!("exit {code:?} {took:?} after SIGTERM; {queued} captures staged; {puts} PUTs");
    assert!(puts > 0, "it tried");
    assert!(
        puts < 200,
        "retried with backoff, not in a tight loop: {puts} PUTs"
    );
}
