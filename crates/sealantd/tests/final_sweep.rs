//! A final capture flush stops every writer in the workspace, not only the managed process
//! groups: a writer that `setsid`'d and double-forked out of its group (re-parented to
//! sealantd, the child subreaper) kept writing after the last snap, and what it wrote from its
//! `SIGTERM` handler — or at all, after the snap — was on the disk only. Nor does joining
//! sealantd's own process group spare a writer: only the helpers sealantd spawned itself are
//! left running (review 2026-09-28 #18).
//!
//! One test in its own binary on purpose: the sweep takes every descendant of the process it
//! runs in, as the daemon's does, and other tests' processes would be its descendants too.

use std::path::{Path, PathBuf};
use std::process::Command as Proc;
use std::sync::Arc;
use std::time::{Duration, Instant};

use sealant_capture::{
    BlobSink, CaptureConfig, CaptureEngine, InMemoryRegistrar, LocalDir, MaterializeClass,
    MaterializeTargets, Materializer, Registrar,
};
use sealant_protocol::{EnvVar, ExecArgs};
use sealant_runtime_core::{RuntimeConfig, new_runtime_id};
use sealantd::boot::capture::{CaptureBoot, SourceLayout};
use sealantd::capture::CaptureRuntime;
use sealantd::{Runtime, ShutdownSignal};

fn git(root: &Path, args: &[&str]) {
    let out = Proc::new("git")
        .current_dir(root)
        .env("GIT_OPTIONAL_LOCKS", "0")
        .args(args)
        .output()
        .expect("git");
    assert!(out.status.success(), "git {args:?}");
}

fn boot(base: &Path) -> (CaptureBoot, Arc<InMemoryRegistrar>) {
    let root = base.join("ws");
    std::fs::create_dir_all(root.join("src")).unwrap();
    git(&root, &["init", "-q", "-b", "main"]);
    git(&root, &["config", "user.email", "t@t"]);
    git(&root, &["config", "user.name", "t"]);
    std::fs::write(root.join("src/lib.rs"), "pub fn f() {}\n").unwrap();
    git(&root, &["add", "-A"]);
    git(&root, &["commit", "-q", "-m", "one"]);
    let registrar = Arc::new(InMemoryRegistrar::new("wt-sweep", 1, None));
    let sink: Arc<dyn BlobSink> = Arc::new(LocalDir::new(&base.join("store")).unwrap());
    let engine = CaptureEngine::open(CaptureConfig::new("wt-sweep", 1, &root), None).unwrap();
    let dyn_registrar: Arc<dyn Registrar> = registrar.clone();
    (
        CaptureBoot {
            engine,
            sink,
            registrar: dyn_registrar,
            minter: None,
            worktree_id: "wt-sweep".to_owned(),
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

fn sh(script: &str, cwd: &Path) -> ExecArgs {
    let pgid = nix::unistd::getpgid(None).expect("this process's group");
    ExecArgs {
        user: None,
        execution_id: None,
        session_id: None,
        executable: "/bin/sh".to_owned(),
        args: vec!["-c".to_owned(), script.to_owned()],
        cwd: Some(cwd.display().to_string()),
        // `setsid` and `sleep` from this process's PATH (the child's base environment has none).
        env: vec![
            EnvVar {
                key: "PATH".to_owned(),
                value: std::env::var("PATH").unwrap_or_default(),
            },
            EnvVar {
                key: "SWEEP_PGID".to_owned(),
                value: pgid.to_string(),
            },
        ],
        stdin: false,
        attach: false,
        timeout_millis: None,
        background: false,
        capture: None,
        graceful_signal: None,
    }
}

/// The escaped writer: its own session (`setsid`), its parent gone (the subshell exits), so it
/// is re-parented to this process. It writes `escaped.txt` every 20 ms and its last word from
/// its `SIGTERM` handler. Its original group only sleeps.
/// A second one joins sealantd's own process group (`$SWEEP_PGID`), where sealantd's helpers
/// run, and writes `joined.txt` the same way.
const ESCAPE: &str = r#"( setsid sh -c 'echo $$ > escaped.pid; trap "echo escaped last words > escaped-term.txt; exit 0" TERM; i=0; while true; do i=$((i+1)); echo $i > escaped.txt; sleep 0.02; done' & ); ( perl -e '$g = shift; setpgrp(0, $g) or die "setpgrp: $!"; exec @ARGV' "$SWEEP_PGID" sh -c 'echo $$ > joined.pid; trap "echo joined last words > joined-term.txt; exit 0" TERM; i=0; while true; do i=$((i+1)); echo $i > joined.txt; sleep 0.02; done' & ); exec sleep 3600"#;

/// Kills the escaped writers when the test ends, whatever happened.
struct Reap(Vec<PathBuf>);

impl Drop for Reap {
    fn drop(&mut self) {
        for file in &self.0 {
            if let Ok(pid) = std::fs::read_to_string(file) {
                let _ = Proc::new("kill").args(["-9", pid.trim()]).status();
            }
        }
    }
}

fn alive(pid: &str) -> bool {
    std::fs::read_to_string(format!("/proc/{pid}/stat")).is_ok_and(|stat| {
        !matches!(
            stat.rsplit(')')
                .next()
                .and_then(|r| r.trim().chars().next()),
            Some('Z' | 'X')
        )
    })
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_final_flush_stops_a_writer_that_left_its_process_group() {
    let tmp = tempfile::tempdir().unwrap();
    let (boot, registrar) = boot(tmp.path());
    let ws = tmp.path().join("ws");
    let _reap = Reap(vec![ws.join("escaped.pid"), ws.join("joined.pid")]);
    let mut config = RuntimeConfig::new(new_runtime_id());
    config.workspace_root = ws.clone();
    let runtime = Runtime::new(config, Arc::new(ShutdownSignal::new(5_000)));
    runtime.mark_healthy();
    let capture = CaptureRuntime::new(boot);
    assert!(runtime.install_capture(capture.clone()));
    let harness = runtime.spawn_managed(sh(ESCAPE, &ws)).expect("spawn");
    capture.start(runtime.clone(), harness.process_id);
    let start = Instant::now();
    while !["escaped.txt", "escaped.pid", "joined.txt", "joined.pid"]
        .iter()
        .all(|f| ws.join(f).exists())
    {
        assert!(
            start.elapsed() < Duration::from_secs(10),
            "the escaped writer runs"
        );
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    let pid = std::fs::read_to_string(ws.join("escaped.pid")).unwrap();
    let pid = pid.trim().to_owned();
    let stat = std::fs::read_to_string(format!("/proc/{pid}/stat")).unwrap();
    let ppid: u32 = stat
        .rsplit(')')
        .next()
        .unwrap()
        .split_whitespace()
        .nth(1)
        .unwrap()
        .parse()
        .unwrap();
    assert_eq!(
        ppid,
        std::process::id(),
        "re-parented to the subreaper: {stat}"
    );

    let joined = std::fs::read_to_string(ws.join("joined.pid")).unwrap();
    let joined = joined.trim().to_owned();
    let stat = std::fs::read_to_string(format!("/proc/{joined}/stat")).unwrap();
    let pgid: i32 = stat
        .rsplit(')')
        .next()
        .unwrap()
        .split_whitespace()
        .nth(2)
        .unwrap()
        .parse()
        .unwrap();
    assert_eq!(
        pgid,
        nix::unistd::getpgid(None).unwrap().as_raw(),
        "the second writer is in this process's group: {stat}"
    );

    // What `capture.flush {kind: final}` and the daemon's own way out run.
    let report = runtime
        .final_flush(None, Some(5_000))
        .await
        .expect("a capture engine");
    assert!(
        !alive(&pid),
        "the escaped writer is stopped before the last snap"
    );
    assert!(
        !alive(&joined),
        "the writer in sealantd's process group is stopped: sealantd did not spawn it"
    );
    assert!(report.complete, "{report:?}");

    // The head is the disk as the escaped writer left it: its SIGTERM handler's file, and the
    // counter's last value — nothing written after the snap.
    tokio::time::sleep(Duration::from_millis(200)).await;
    let store = LocalDir::new(&tmp.path().join("store")).unwrap();
    let fresh = tmp.path().join("fresh");
    Materializer::new(&store, MaterializeTargets::new(&fresh, None))
        .materialize(&registrar.head().unwrap().manifest, MaterializeClass::All)
        .unwrap();
    assert_eq!(
        std::fs::read_to_string(fresh.join("escaped-term.txt"))
            .ok()
            .as_deref(),
        Some("escaped last words\n"),
        "what the escaped writer wrote on SIGTERM is in the head"
    );
    assert_eq!(
        std::fs::read_to_string(fresh.join("escaped.txt")).unwrap(),
        std::fs::read_to_string(ws.join("escaped.txt")).unwrap(),
        "nothing was written after the last snap"
    );
    assert_eq!(
        std::fs::read_to_string(fresh.join("joined-term.txt"))
            .ok()
            .as_deref(),
        Some("joined last words\n"),
    );
    assert_eq!(
        std::fs::read_to_string(fresh.join("joined.txt")).unwrap(),
        std::fs::read_to_string(ws.join("joined.txt")).unwrap(),
        "nothing was written after the last snap by the writer in sealantd's group"
    );
}
