//! A recovery boot's final flush covers every writer on the machine, not only its own
//! descendants (review 2026-09-28, fourth pass, #4). On a MicroVM the recovered daemon is not
//! PID 1: Core's agent is, and it adopted every orphan the dead daemon left — a writer that
//! escaped it included. That writer is the recovered daemon's sibling, so a sweep of its
//! descendants never saw it, and the final flush answered `complete` while it kept writing.
//!
//! Now such a daemon either sweeps the machine, sparing exactly the helpers the agent names in
//! `SEALANT_SWEEP_EXEMPT_FILE` (pid and start time), or — named none — cannot say it stopped
//! every writer: `sweep-unavailable`, never `complete`.
//!
//! One test in its own binary on purpose: the writers are started before this process becomes
//! a child subreaper (a `Runtime` makes it one), so they are re-parented away from it — as the
//! old daemon's orphans are re-parented to the agent — and the sweep is narrowed to the
//! processes this test marked.

use std::path::{Path, PathBuf};
use std::process::Command as Proc;
use std::sync::Arc;
use std::time::{Duration, Instant};

use sealant_capture::{
    BlobSink, CaptureConfig, CaptureEngine, InMemoryRegistrar, LocalDir, Registrar,
};
use sealant_runtime_core::{RuntimeConfig, new_runtime_id};
use sealantd::boot::capture::{CaptureBoot, SourceLayout};
use sealantd::capture::CaptureRuntime;
use sealantd::sweep::Scope;
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

fn boot(base: &Path) -> CaptureBoot {
    let root = base.join("ws");
    std::fs::create_dir_all(root.join("src")).unwrap();
    git(&root, &["init", "-q", "-b", "main"]);
    git(&root, &["config", "user.email", "t@t"]);
    git(&root, &["config", "user.name", "t"]);
    std::fs::write(root.join("src/lib.rs"), "pub fn f() {}\n").unwrap();
    git(&root, &["add", "-A"]);
    git(&root, &["commit", "-q", "-m", "one"]);
    let registrar: Arc<dyn Registrar> = Arc::new(InMemoryRegistrar::new("wt-rsweep", 1, None));
    let sink: Arc<dyn BlobSink> = Arc::new(LocalDir::new(&base.join("store")).unwrap());
    let engine = CaptureEngine::open(CaptureConfig::new("wt-rsweep", 1, &root), None).unwrap();
    CaptureBoot {
        engine,
        sink,
        registrar,
        minter: None,
        worktree_id: "wt-rsweep".to_owned(),
        epoch: 1,
        layout: SourceLayout {
            workspace_root: base.to_path_buf(),
            working_directory: root.clone(),
            staging_dir: root.join(".sealantd/capture"),
        },
        resumed: false,
    }
}

/// A marked process in a session of its own whose parent exits at once: re-parented to
/// whatever reaps orphans above this process, never this process's descendant. It writes its
/// pid to `<name>.pid`, sleeps `nap` seconds — through the final flush, as the review's writer
/// did — then writes `<target>` every 20 ms.
fn orphan(dir: &Path, name: &str, mark: &str, nap: u32, target: &Path) -> String {
    let script = format!(
        "( setsid sh -c 'echo $$ > {name}.pid; sleep {nap}; i=0; while true; do i=$((i+1)); echo $i > {}; sleep 0.02; done' & )",
        target.display()
    );
    let ws = dir;
    let status = Proc::new("sh")
        .args(["-c", &script])
        .current_dir(ws)
        .env("SEALANTD_SWEEP_MARK", mark)
        .status()
        .unwrap();
    assert!(status.success());
    let start = Instant::now();
    loop {
        if let Ok(pid) = std::fs::read_to_string(ws.join(format!("{name}.pid")))
            && !pid.trim().is_empty()
        {
            return pid.trim().to_owned();
        }
        assert!(start.elapsed() < Duration::from_secs(10), "{name} starts");
        std::thread::sleep(Duration::from_millis(20));
    }
}

/// A marked process like [`orphan`]'s that starts no process of its own: the agent's helper.
/// (One whose loop started a `sleep` every 20 ms had children the list does not spare — it names
/// the helper alone — and a final flush that met one alive at its seal was, rightly, never
/// complete.)
fn idle_orphan(dir: &Path, name: &str, mark: &str) -> String {
    let script = format!("( setsid sh -c 'echo $$ > {name}.pid; exec sleep 600' & )");
    let status = Proc::new("sh")
        .args(["-c", &script])
        .current_dir(dir)
        .env("SEALANTD_SWEEP_MARK", mark)
        .status()
        .unwrap();
    assert!(status.success());
    let start = Instant::now();
    loop {
        if let Ok(pid) = std::fs::read_to_string(dir.join(format!("{name}.pid")))
            && !pid.trim().is_empty()
        {
            return pid.trim().to_owned();
        }
        assert!(start.elapsed() < Duration::from_secs(10), "{name} starts");
        std::thread::sleep(Duration::from_millis(20));
    }
}

fn stat_fields(pid: &str) -> Option<Vec<String>> {
    let stat = std::fs::read_to_string(format!("/proc/{pid}/stat")).ok()?;
    Some(
        stat.rsplit(')')
            .next()?
            .split_whitespace()
            .map(str::to_owned)
            .collect(),
    )
}

fn alive(pid: &str) -> bool {
    stat_fields(pid).is_some_and(|f| !matches!(f[0].as_str(), "Z" | "X"))
}

/// Whether `pid` descends from this process.
fn descends_from_me(pid: &str) -> bool {
    let me = std::process::id().to_string();
    let mut at = pid.to_owned();
    for _ in 0..64 {
        let Some(fields) = stat_fields(&at) else {
            return false;
        };
        let ppid = fields[1].clone();
        if ppid == me {
            return true;
        }
        if ppid == "0" || ppid == "1" {
            return false;
        }
        at = ppid;
    }
    false
}

/// Kills the orphans when the test ends, whatever happened.
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

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_recovery_final_flush_covers_writers_the_agent_adopted() {
    let tmp = tempfile::tempdir().unwrap();
    let capture_boot = boot(tmp.path());
    let ws = tmp.path().join("ws");
    let mark = format!("recovery-sweep-{}", std::process::id());
    let pids = tmp.path().join("pids");
    std::fs::create_dir_all(&pids).unwrap();
    let _reap = Reap(vec![pids.join("writer.pid"), pids.join("helper.pid")]);
    // Before any `Runtime`: this process is no subreaper yet, so both are re-parented away. The
    // writer sleeps through the flushes and would then write the worktree; the helper (the
    // agent's) idles.
    let writer = orphan(&pids, "writer", &mark, 60, &ws.join("late-write.txt"));
    let helper = idle_orphan(&pids, "helper", &mark);
    assert!(
        !descends_from_me(&writer),
        "the writer is a sibling, not a descendant"
    );
    assert!(!descends_from_me(&helper));

    let mut config = RuntimeConfig::new(new_runtime_id());
    config.workspace_root = ws.clone();
    let runtime = Runtime::new(config, Arc::new(ShutdownSignal::new(5_000)));
    runtime.mark_healthy();
    // A recovery boot of a daemon that is not PID 1 (a MicroVM's agent is), a child subreaper,
    // the sweep narrowed to this test's processes.
    runtime.close_admission();
    runtime.set_sweep_scope_for_test(Scope::Descendants);
    runtime.set_subreaper_for_test(true);
    runtime.set_sweep_mark(Some(mark.clone()));
    let capture = CaptureRuntime::new(capture_boot);
    assert!(runtime.install_capture(capture.clone()));
    // As a recovery boot starts it: no harness.
    capture.start_without_harness(runtime.clone());

    // No exempt list from the agent: the orphan writer is out of reach, and the flush says so
    // (before, it answered complete while the writer lived on, to write after the snap).
    let report = runtime
        .final_flush(None, Some(2_000))
        .await
        .expect("a capture engine");
    assert!(alive(&writer), "the sweep never saw the sibling writer");
    assert!(
        !report.complete,
        "a recovery sweep of descendants only must not complete: {report:?}"
    );
    assert_eq!(
        report.incomplete_reason.as_deref(),
        Some("sweep-unavailable"),
        "{report:?}"
    );

    // A list the agent named but that cannot be read: nothing is known of its helpers, the
    // sweep takes only what it can vouch for, and the flush is not complete.
    let exempt = tmp.path().join("sweep-exempt.json");
    runtime.set_sweep_exempt_file(Some(exempt.clone()));
    let report = runtime
        .final_flush(None, Some(2_000))
        .await
        .expect("a capture engine");
    assert_eq!(
        report.incomplete_reason.as_deref(),
        Some("sweep-unavailable"),
        "{report:?}"
    );
    assert!(alive(&writer) && alive(&helper));

    // The agent names its own helper, as Core's writes it (pid, `/proc/<pid>/stat` field 22 as
    // a string, role, descendants): the machine is swept, the writer stopped, the helper
    // spared, and the flush is complete.
    let start_time = &stat_fields(&helper).unwrap()[19];
    std::fs::write(
        &exempt,
        format!(
            r#"{{"version":1,"exempt":[{{"pid":{helper},"startTime":"{start_time}","role":"dockerd","descendants":false}}]}}"#
        ),
    )
    .unwrap();
    let report = runtime
        .final_flush(None, Some(2_000))
        .await
        .expect("a capture engine");
    assert!(!alive(&writer), "the adopted writer is stopped");
    assert!(alive(&helper), "the helper the agent named is spared");
    assert!(report.complete, "{report:?}");

    // An entry whose start time is not the live process's is a reused pid, not the helper: it
    // spares nothing, and the machine sweep would take the process.
    std::fs::write(
        &exempt,
        format!(r#"{{"version":1,"exempt":[{{"pid":{helper},"startTime":"1","role":"dockerd","descendants":false}}]}}"#),
    )
    .unwrap();
    let stale = sealantd::sweep::read_exempt(&exempt).unwrap();
    assert_eq!(stale, sealantd::sweep::Exempt::default());
    let sweeper = sealantd::sweep::Sweeper {
        me: i32::try_from(std::process::id()).unwrap(),
        my_pgid: nix::unistd::getpgid(None).unwrap().as_raw(),
        scope: Scope::Machine,
    };
    let marked = |pid: i32| sealantd::sweep::has_env_entry(pid, "SEALANTD_SWEEP_MARK", &mark);
    let picked = sweeper.select_sparing(
        &sealantd::sweep::read_proc(Path::new("/proc")),
        &marked,
        &std::collections::HashSet::new(),
        &stale,
    );
    // (The helper, marked too, and listed under a start time that is not its own.)
    assert!(
        picked.contains(&helper.parse::<i32>().unwrap()),
        "{picked:?}"
    );
    assert!(
        !picked.contains(&writer.parse::<i32>().unwrap()),
        "{picked:?}"
    );
}
