//! Linux-only: the spawn↔reap gate must keep the orphan reaper from stealing Tokio-owned
//! children's exit statuses. Lives in its own test binary because it spawns the process-global
//! reaper (same isolation rule as `orphan_reaping.rs`).
#![cfg(target_os = "linux")]

use std::sync::Arc;
use std::time::Duration;

use sealant_process::ProcessRegistry;
use sealant_process::platform;

/// Regression: the reaper must never steal a Tokio-owned child's exit status, even when the
/// child exits faster than its ownership registration would land without the spawn↔reap gate.
/// Pre-gate, this flaked with `ProcessExited { exit_code: None }` (the CI failure mode of
/// `binary_stdio_roundtrips_binary_unsafe_output_and_shuts_down`).
#[tokio::test]
async fn reaper_never_steals_fast_exiting_owned_children() {
    use sealant_process::ProcessRuntime;
    use sealant_protocol::{EventPayload, ExecArgs};
    use sealant_runtime_core::{
        Clock, IdGenerator, Redactor, RuntimeConfig, RuntimeStatus, new_runtime_id,
    };
    use sealant_telemetry::EventBus;

    assert!(platform::set_child_subreaper());
    let rt_id = new_runtime_id();
    let clock = Arc::new(Clock::new());
    let idgen = Arc::new(IdGenerator::new(&rt_id));
    let bus = Arc::new(EventBus::new(
        rt_id.clone(),
        clock.clone(),
        idgen.clone(),
        4096,
    ));
    let mut config = RuntimeConfig::new(rt_id);
    config.workspace_root = std::env::temp_dir();
    let runtime = ProcessRuntime {
        registry: Arc::new(ProcessRegistry::new()),
        bus,
        idgen,
        status: Arc::new(RuntimeStatus::new()),
        clock,
        config: Arc::new(config),
        extra_env: Arc::new(std::sync::Mutex::new(Vec::new())),
        redactor: Arc::new(Redactor::default()),
    };
    platform::spawn_orphan_reaper(runtime.registry.clone());

    for round in 0..50 {
        let mut rx = runtime.bus.subscribe();
        runtime
            .exec(
                ExecArgs {
                    execution_id: None,
                    session_id: None,
                    executable: "/bin/true".to_owned(),
                    args: vec![],
                    cwd: None,
                    env: vec![],
                    stdin: false,
                    attach: false,
                    timeout_millis: None,
                    background: false,
                    capture: None,
                    graceful_signal: None,
                },
                None,
            )
            .expect("exec /bin/true");
        let exited = tokio::time::timeout(Duration::from_secs(5), async {
            loop {
                let envelope = rx.recv().await.expect("event");
                if let EventPayload::ProcessExited(exited) = envelope.payload {
                    return exited;
                }
            }
        })
        .await
        .expect("process exit observed");
        assert_eq!(
            exited.exit_code,
            Some(0),
            "round {round}: the reaper stole a Tokio-owned child's exit status"
        );
    }
}
