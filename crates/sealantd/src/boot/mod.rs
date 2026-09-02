//! `sealantd boot`: the PID-1 workspace supervisor.
//!
//! `boot` is the container's PID 1. It reproduces every step the legacy bash entrypoint performed —
//! workspace prep, glibc loader shim, git clone with scoped credentials, runtime dotfiles, lifecycle
//! steps — then runs the control server *in-process* and supervises the harness as a managed child.
//! Because it is the subreaper, double-forked orphans reparent here and are reaped continuously;
//! because the harness runs through the daemon's `exec`, its stdout/stderr are captured on the event
//! bus. `boot` waits for the harness, propagates signals, and exits with the harness's status.
//!
//! Interactive SSH access is no longer served by an in-container `sshd`: the gateway tunnels to the
//! daemon over the control socket and drives sessions/forwards through the control protocol. Only the
//! SSH *client* survives (git-over-SSH clone, see [`git`]).

pub mod config;
mod dotfiles;
mod error;
mod git;
mod mount;

use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::sync::Arc;

use sealant_protocol::{
    CapturePolicy, EnvVar, EventPayload, ExecArgs, ExecutionId, NetworkMode, ProcessId,
    RuntimeState,
};
use sealant_runtime_core::{RuntimeConfig, new_runtime_id};
use tokio::sync::watch;

use crate::runtime::Runtime;
use crate::shutdown::ShutdownSignal;

pub use config::BootConfig;
pub use error::BootError;

use config::{ForegroundConfig, LifecycleStep, OsFamily, Shell, WorkspaceSource};

/// The directory under the workspace root holding boot-time clone credentials and dotfiles state.
const SSH_RUNTIME_SUBDIR: &str = ".ssh-runtime";

/// Child-environment keys `boot` computes itself; no launcher-provided entry may set them.
const BOOT_OWNED_KEYS: &[&str] = &["HOME", "USER", "LOGNAME", "PATH"];

/// Entry point for the `boot` subcommand. Performs synchronous prep, then enters Tokio to run the
/// control server and supervise the harness. Returns the process exit code.
#[must_use]
pub fn run_boot(log_level: &str) -> ExitCode {
    init_tracing(log_level);

    let config = match BootConfig::from_env() {
        Ok(config) => config,
        Err(error) => {
            tracing::error!(%error, "boot configuration is invalid");
            eprintln!("sealantd boot: {error}");
            return ExitCode::FAILURE;
        }
    };

    if let Err(error) = prepare(&config) {
        tracing::error!(%error, "boot preparation failed");
        eprintln!("sealantd boot: {error}");
        return ExitCode::FAILURE;
    }

    // The launcher-provided secret environment is read exactly once, here, and handed straight to
    // the runtime config: it never rides `BootConfig` (which is `Debug`) and never touches this
    // process's own environment.
    let secret_env = match &config.secret_env_file {
        None => Vec::new(),
        Some(path) => match config::load_secret_env(path) {
            Ok(entries) => entries,
            Err(error) => {
                tracing::error!(%error, "secret environment file is invalid");
                eprintln!("sealantd boot: {error}");
                return ExitCode::FAILURE;
            }
        },
    };

    run_supervised(config, secret_env)
}

fn init_tracing(log_level: &str) {
    let filter = tracing_subscriber::EnvFilter::try_new(log_level)
        .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info"));
    let _ = tracing_subscriber::fmt()
        .with_writer(std::io::stderr)
        .with_env_filter(filter)
        .try_init();
}

/// Synchronous boot preparation (steps 2–7): all side effects that must complete, in order, before
/// the async runtime and the harness start.
fn prepare(config: &BootConfig) -> Result<(), BootError> {
    // Step 2: become subreaper BEFORE any fork so double-forked orphans reparent here.
    if cfg!(target_os = "linux") {
        if !sealant_process::platform::set_child_subreaper() {
            tracing::warn!("PR_SET_CHILD_SUBREAPER failed; orphan reaping may be incomplete");
        }
    } else {
        tracing::warn!("not Linux; child-subreaper is a no-op (boot is intended for containers)");
    }
    let _ = sealant_process::platform::set_no_new_privs();

    // Step 3: workspace prep.
    prepare_workspace(config)?;

    // Step 4: glibc loader shim (Nix base only).
    if config.os_family == OsFamily::Nix {
        glibc_loader_shim();
    }

    // Steps 5–7: provision the working directory per source mode.
    match &config.source {
        // Clone with scoped credentials, then wipe them.
        WorkspaceSource::Clone(repo) => {
            let runtime_dir = ssh_runtime_dir(config);
            let clone_auth = git::materialize_clone_auth(&config.clone_auth, &runtime_dir)?;
            let clone_result =
                git::clone_repo_if_absent(repo, &config.workspace.working_directory, &clone_auth);
            clone_auth.wipe();
            clone_result?;
        }
        // Caller-owned mount: no clone, no credentials; verify the mount actually exists and is
        // writable so writes land on the host path rather than the container layer.
        WorkspaceSource::Mount(mount_config) => {
            mount::verify_mounted_source(&config.workspace.working_directory, mount_config)?;
        }
        // Standby (ADR-0014): the working directory appears at bind time; the ROOT must be here.
        WorkspaceSource::Standby(_) => {}
    }
    // Every bindable root — the standby root and any extra bindable mount — must be a real,
    // writable mount, for the same reason a mounted source must: a bind onto a container-local
    // directory would strand every write in the writable layer.
    for bindable in &config.bindable_mounts {
        mount::verify_mount_root(
            &bindable.root_mount_path,
            bindable.host_root_path.as_deref().unwrap_or("<unknown>"),
        )?;
    }

    Ok(())
}

/// The SSH-runtime / credential directory under the workspace root.
fn ssh_runtime_dir(config: &BootConfig) -> PathBuf {
    config.workspace.workspace_root.join(SSH_RUNTIME_SUBDIR)
}

/// Step 3: create the standard directories and chdir into the workspace root. The harness child's
/// identity/PATH are injected via `child_env` (see [`harness_child_env`]), not the process env.
fn prepare_workspace(config: &BootConfig) -> Result<(), BootError> {
    let mut dirs: Vec<PathBuf> = vec![
        config.workspace.workspace_root.clone(),
        ssh_runtime_dir(config),
        PathBuf::from("/root"),
        PathBuf::from("/tmp"),
        PathBuf::from("/run/sealant"),
        config.control.session_journal_dir.clone(),
    ];
    if let Some(parent) = config.control.socket.parent() {
        dirs.push(parent.to_path_buf());
    }
    // A standby working directory is a symlink the bind creates; pre-creating a real directory
    // there would only be removed again (or refused, once something wrote into it).
    if !matches!(config.source, WorkspaceSource::Standby(_)) {
        dirs.push(config.workspace.working_directory.clone());
    }
    for dir in &dirs {
        std::fs::create_dir_all(dir).map_err(|e| BootError::io_path("mkdir -p", dir, e))?;
    }

    // We deliberately do NOT mutate this process's environment (it is `unsafe` in edition 2024 and
    // this crate forbids unsafe). The harness child's identity (HOME/USER/LOGNAME) and the
    // `/usr/local/bin` PATH prepend are injected explicitly via `child_env` in `harness_child_env`,
    // which is the only consumer that needs them. The clone helper commands inherit boot's own env
    // (PATH already includes the system dirs).
    std::env::set_current_dir(&config.workspace.workspace_root)
        .map_err(|e| BootError::io_path("chdir", &config.workspace.workspace_root, e))?;
    Ok(())
}

/// Step 4: on Nix bases the dynamic loader may not be at the canonical path; symlink it from the
/// nix store so binaries expecting `/lib64/ld-linux-x86-64.so.2` work. Best-effort.
fn glibc_loader_shim() {
    let canonical = Path::new("/lib64/ld-linux-x86-64.so.2");
    if canonical.exists() {
        return;
    }
    let Some(loader) = find_nix_loader() else {
        tracing::warn!("nix base: no glibc loader found under /nix/store; skipping shim");
        return;
    };
    if let Some(parent) = canonical.parent() {
        let _ = std::fs::create_dir_all(parent);
    }
    match std::os::unix::fs::symlink(&loader, canonical) {
        Ok(()) => tracing::info!(loader = %loader.display(), "linked glibc loader shim"),
        Err(error) => tracing::warn!(%error, "failed to link glibc loader shim"),
    }
}

/// Glob `/nix/store/*-glibc-*/lib/ld-linux-x86-64.so.2` and return the first hit.
fn find_nix_loader() -> Option<PathBuf> {
    let store = Path::new("/nix/store");
    let entries = std::fs::read_dir(store).ok()?;
    for entry in entries.flatten() {
        let name = entry.file_name();
        let Some(name) = name.to_str() else { continue };
        if !name.contains("-glibc-") {
            continue;
        }
        let candidate = entry.path().join("lib/ld-linux-x86-64.so.2");
        if candidate.exists() {
            return Some(candidate);
        }
    }
    None
}

/// Build the `RuntimeConfig` from the boot config (the `into_runtime_config` of the spec).
fn into_runtime_config(config: &BootConfig, secret_env: &[(String, String)]) -> RuntimeConfig {
    let mut runtime_config = RuntimeConfig::new(new_runtime_id());
    runtime_config.socket_path = config.control.socket.clone();
    runtime_config.workspace_root = config.workspace.working_directory.clone();
    runtime_config.spool_dir = config.control.spool_dir.clone();
    runtime_config.session_journal_dir = Some(config.control.session_journal_dir.clone());
    runtime_config.watch_filesystem = config.control.watch_filesystem;
    runtime_config.network_mode = if config.control.network_proxy {
        NetworkMode::Proxy
    } else {
        NetworkMode::Off
    };
    runtime_config.workspace_id = config.control.workspace_id.clone();
    runtime_config.default_execution_id = config.control.execution_id.clone().map(ExecutionId::new);
    runtime_config.default_shell = config.shells.login.display().to_string();
    runtime_config.bindable_mounts = config.bindable_mounts.clone();
    runtime_config.log_level = "info".to_owned();
    // The harness child's base environment: the passthrough env, the launcher's secret env, and
    // the prep-set identity vars. Every secret value seeds the I/O redactor whatever its name.
    runtime_config.child_env = harness_child_env(config, secret_env);
    runtime_config.redact_literals = secret_env.iter().map(|(_, value)| value.clone()).collect();
    runtime_config
}

/// Compute the harness child's base environment, in precedence order (later wins): the non-secret
/// passthrough, then the launcher-provided secret environment (explicitly addressed to the
/// workspace, so it bypasses the secret-name scrub and overrides same-named passthrough entries),
/// then the identity vars `boot` set on itself in prep (HOME/USER/LOGNAME/PATH), which nothing may
/// override.
fn harness_child_env(config: &BootConfig, secret_env: &[(String, String)]) -> Vec<EnvVar> {
    let mut map: std::collections::BTreeMap<String, String> =
        config.passthrough_env.iter().cloned().collect();
    for (key, value) in secret_env {
        // The identity/PATH keys are computed below from the passthrough alone; a launcher entry
        // under one of those names is dropped (the platform's own validation rejects them first).
        if BOOT_OWNED_KEYS.contains(&key.as_str()) {
            tracing::warn!(key, "secret env entry ignored: the key is owned by boot");
            continue;
        }
        map.insert(key.clone(), value.clone());
    }
    map.insert("HOME".to_owned(), "/root".to_owned());
    map.insert("USER".to_owned(), "root".to_owned());
    map.insert("LOGNAME".to_owned(), "root".to_owned());
    // Prepend /usr/local/bin (where local tools live) to the child PATH.
    let base_path = map
        .get("PATH")
        .cloned()
        .or_else(|| std::env::var("PATH").ok())
        .unwrap_or_default();
    let path = if base_path.split(':').any(|p| p == "/usr/local/bin") {
        base_path
    } else if base_path.is_empty() {
        "/usr/local/bin".to_owned()
    } else {
        format!("/usr/local/bin:{base_path}")
    };
    map.insert("PATH".to_owned(), path);
    map.into_iter()
        .map(|(key, value)| EnvVar { key, value })
        .collect()
}

/// Steps 9–18: build the runtime, enter Tokio, run the control server and supervise the harness.
fn run_supervised(config: BootConfig, secret_env: Vec<(String, String)>) -> ExitCode {
    let runtime_config = into_runtime_config(&config, &secret_env);
    // Nothing downstream needs the values in this form; the runtime config owns them now.
    drop(secret_env);
    if let Err(error) = runtime_config.validate() {
        tracing::error!(%error, "derived runtime configuration is invalid");
        eprintln!("sealantd boot: invalid runtime configuration: {error}");
        return ExitCode::FAILURE;
    }
    let shutdown = Arc::new(ShutdownSignal::new(runtime_config.shutdown_grace_ms));
    let runtime = Runtime::new(runtime_config, shutdown);

    let tokio_runtime = match tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
    {
        Ok(rt) => rt,
        Err(error) => {
            tracing::error!(%error, "failed to start async runtime");
            return ExitCode::FAILURE;
        }
    };

    tokio_runtime.block_on(boot_serve(runtime, config))
}

/// The async supervisor body (steps 11–18).
async fn boot_serve(runtime: Arc<Runtime>, config: BootConfig) -> ExitCode {
    let (serve_tx, serve_rx) = watch::channel(false);

    // Step 11: same background machinery app.rs::serve starts.
    crate::app::spawn_signal_listener(runtime.shutdown().clone());
    crate::app::spawn_heartbeat(runtime.clone());
    sealant_process::platform::spawn_orphan_reaper(runtime.process_registry());
    runtime.start_telemetry();
    runtime.start_filesystem();
    let network_mode = runtime.start_network().await;
    if network_mode != NetworkMode::Off {
        tracing::info!(?network_mode, "network observation active");
    }
    runtime.mark_healthy();

    // Step 11b: bind the working directory (and any other bindable mount) the orchestrator asked
    // for, plus whatever this container's record holds, BEFORE anything can look for the repo
    // (ADR-0014). A bind the platform promised and cannot deliver is a broken workspace.
    if let Err(error) = runtime.binds().apply_initial(&config.initial_binds) {
        tracing::error!(%error, "initial mount bind failed");
        eprintln!("sealantd boot: {error}");
        return shutdown_before_control(&runtime, ExitCode::FAILURE).await;
    }

    // Step 12: runtime dotfiles, synchronously, BEFORE the control socket binds. The launching
    // adapter and the gateway treat the socket as the readiness signal, and everything they inject
    // after readiness (credential files into $HOME) must never race a dotfiles apply that writes
    // the same tree.
    if let Some(dotfiles) = &config.dotfiles
        && let Err(error) = dotfiles::apply(dotfiles, &ssh_runtime_dir(&config))
    {
        tracing::error!(%error, "dotfiles apply failed");
        eprintln!("sealantd boot: {error}");
        return shutdown_before_control(&runtime, ExitCode::FAILURE).await;
    }
    // Caller-provided archives apply after the repo so local selections override its files.
    if let Some(dir) = &config.dotfiles_archives
        && let Err(error) = dotfiles::apply_archives(dir)
    {
        tracing::error!(%error, "dotfiles archive apply failed");
        eprintln!("sealantd boot: {error}");
        return shutdown_before_control(&runtime, ExitCode::FAILURE).await;
    }

    // Step 13: control server in-process on the same runtime/bus/registry. The optional WSS
    // frontend (ADR-0013) binds first so TLS/address problems fail boot loudly.
    let wss_listener = match &config.control.wss {
        None => None,
        Some(wss) => match sealant_control::WssListener::bind(wss).await {
            Ok(listener) => Some(listener),
            Err(error) => {
                tracing::error!(%error, "wss frontend failed to start");
                eprintln!("sealantd boot: wss frontend failed to start: {error}");
                return shutdown_before_control(&runtime, ExitCode::FAILURE).await;
            }
        },
    };
    let control_runtime = runtime.clone();
    let unix = crate::control_frontends::UnixFrontend {
        path: control_runtime.socket_path(),
        allowed_peer_uids: control_runtime.allowed_peer_uids(),
    };
    let mut control_handle = crate::control_frontends::spawn_control_frontends(
        control_runtime,
        unix,
        wss_listener,
        serve_rx,
    );

    // Print the harness banner (E8) now that prep is done.
    tracing::info!(banner = %config.banner, "{}", config.banner);

    // Step 14: lifecycle setup then startup, each awaited to completion (set -e parity).
    let steps: Vec<&LifecycleStep> = config
        .lifecycle
        .setup
        .iter()
        .chain(config.lifecycle.startup.iter())
        .collect();
    for step in steps {
        if let Err(code) = run_lifecycle_step(&runtime, &config, step).await {
            tracing::error!(run = %step.run, "lifecycle step failed; aborting boot");
            return shutdown_with(&runtime, &serve_tx, control_handle, code).await;
        }
    }

    // Step 15: launch the harness through exec so its telemetry is captured. Subscribe to the bus
    // BEFORE launching so a fast exit cannot be missed (the broadcast bus does not replay).
    let mut harness_events = runtime.event_subscriber();
    let harness_process_id = match launch_harness(&runtime, &config) {
        Ok(id) => id,
        Err(error) => {
            tracing::error!(%error, "failed to launch harness");
            eprintln!("sealantd boot: {error}");
            return shutdown_with(&runtime, &serve_tx, control_handle, ExitCode::FAILURE).await;
        }
    };

    // Step 16: supervise — wait for the harness exit OR a shutdown signal.
    let exit_code = tokio::select! {
        status = await_exit_on(&mut harness_events, &harness_process_id) => {
            tracing::info!("harness exited; shutting down");
            exit_code_from_status(status)
        }
        () = runtime.shutdown().wait() => {
            tracing::info!("shutdown requested; terminating harness");
            ExitCode::SUCCESS
        }
        join = &mut control_handle => {
            if let Err(error) = join {
                tracing::warn!(%error, "control server task ended unexpectedly");
            }
            ExitCode::FAILURE
        }
    };

    // Steps 17–18.
    shutdown_with(&runtime, &serve_tx, control_handle, exit_code).await
}

/// Run one lifecycle step as a managed process and await its exit. `Err(code)` on non-zero exit.
async fn run_lifecycle_step(
    runtime: &Arc<Runtime>,
    config: &BootConfig,
    step: &LifecycleStep,
) -> Result<(), ExitCode> {
    let (executable, flag) = shell_invocation(config, step.shell);
    let cwd = step
        .working_directory
        .clone()
        .unwrap_or_else(|| config.workspace.working_directory.clone());
    let args = ExecArgs {
        execution_id: runtime.default_execution_id(),
        session_id: None,
        executable,
        args: vec![flag.to_owned(), step.run.clone()],
        cwd: Some(cwd.display().to_string()),
        env: vec![],
        stdin: false,
        attach: false,
        timeout_millis: None,
        background: false,
        capture: Some(CapturePolicy::default()),
        graceful_signal: None,
    };
    // Subscribe before spawning so a fast-exiting step's `process.exited` is not missed.
    let mut events = runtime.event_subscriber();
    let accepted = match runtime.spawn_managed(args) {
        Ok(accepted) => accepted,
        Err(error) => {
            tracing::error!(%error, run = %step.run, "lifecycle step failed to spawn");
            return Err(ExitCode::FAILURE);
        }
    };
    match await_exit_on(&mut events, &accepted.process_id).await {
        ExitStatus::Code(0) => Ok(()),
        ExitStatus::Code(code) => Err(exit_code_from(code)),
        ExitStatus::Signal(_) | ExitStatus::Lost => Err(ExitCode::FAILURE),
    }
}

/// Launch the harness/foreground command through `exec`, returning its managed process id.
fn launch_harness(runtime: &Arc<Runtime>, config: &BootConfig) -> Result<ProcessId, BootError> {
    let (executable, args, cwd) = match &config.foreground {
        ForegroundConfig::Override { command } => (
            config.shells.bash.display().to_string(),
            vec!["-lc".to_owned(), command.clone()],
            config.workspace.working_directory.clone(),
        ),
        ForegroundConfig::Command {
            run,
            shell,
            working_directory,
        } => {
            let (exe, flag) = shell_invocation(config, *shell);
            (
                exe,
                vec![flag.to_owned(), run.clone()],
                working_directory
                    .clone()
                    .unwrap_or_else(|| config.workspace.working_directory.clone()),
            )
        }
        ForegroundConfig::Harness { launch_command } => (
            config.shells.login.display().to_string(),
            vec!["-lc".to_owned(), launch_command.clone()],
            config.workspace.working_directory.clone(),
        ),
    };

    let exec_args = ExecArgs {
        execution_id: runtime.default_execution_id(),
        session_id: None,
        executable,
        args,
        cwd: Some(cwd.display().to_string()),
        env: vec![],
        stdin: false,
        attach: false,
        timeout_millis: None,
        background: false,
        capture: Some(CapturePolicy::default()),
        graceful_signal: None,
    };
    let accepted = runtime
        .spawn_managed(exec_args)
        .map_err(|e| BootError::command("harness", e.to_string()))?;
    tracing::info!(pid = accepted.pid, "harness started");
    Ok(accepted.process_id)
}

/// Resolve `(executable, flag)` for a shell selection.
fn shell_invocation(config: &BootConfig, shell: Shell) -> (String, &'static str) {
    match shell {
        Shell::Sh => ("/bin/sh".to_owned(), "-c"),
        Shell::LoginBash => (config.shells.bash.display().to_string(), "-lc"),
    }
}

/// Exit status of a supervised process.
enum ExitStatus {
    Code(i32),
    Signal(i32),
    Lost,
}

/// Await a managed process's `process.exited` event on an already-open subscription and classify
/// it. The subscription MUST be created before the process is spawned, otherwise a fast exit can be
/// missed (the broadcast bus does not replay).
async fn await_exit_on(
    events: &mut tokio::sync::broadcast::Receiver<sealant_protocol::EventEnvelope>,
    process_id: &ProcessId,
) -> ExitStatus {
    loop {
        match events.recv().await {
            Ok(envelope) => {
                if envelope.process_id.as_ref() == Some(process_id)
                    && let EventPayload::ProcessExited(exited) = &envelope.payload
                {
                    if let Some(code) = exited.exit_code {
                        return ExitStatus::Code(code);
                    }
                    if let Some(signal) = exited.signal {
                        return ExitStatus::Signal(signal);
                    }
                    return ExitStatus::Lost;
                }
            }
            Err(tokio::sync::broadcast::error::RecvError::Lagged(_)) => continue,
            Err(tokio::sync::broadcast::error::RecvError::Closed) => return ExitStatus::Lost,
        }
    }
}

/// Translate an exit status into a process exit code (step 18).
fn exit_code_from_status(status: ExitStatus) -> ExitCode {
    match status {
        ExitStatus::Code(code) => exit_code_from(code),
        // Conventional 128 + signal for signal-terminated processes.
        ExitStatus::Signal(signal) => {
            ExitCode::from(128u8.wrapping_add(u8::try_from(signal).unwrap_or(0)))
        }
        ExitStatus::Lost => ExitCode::FAILURE,
    }
}

fn exit_code_from(code: i32) -> ExitCode {
    ExitCode::from(u8::try_from(code & 0xff).unwrap_or(1))
}

/// Steps 17–18: begin graceful shutdown (terminates the harness group), stop the control task, and
/// finish shutdown, then return `code`.
async fn shutdown_with(
    runtime: &Arc<Runtime>,
    serve_tx: &watch::Sender<bool>,
    control_handle: tokio::task::JoinHandle<std::io::Result<()>>,
    code: ExitCode,
) -> ExitCode {
    if !matches!(
        runtime.state(),
        RuntimeState::ShuttingDown | RuntimeState::Stopped
    ) {
        runtime.shutdown().request_graceful(None);
    }
    runtime.begin_shutdown().await;
    let _ = serve_tx.send(true);
    if !control_handle.is_finished()
        && let Err(error) = control_handle.await
    {
        tracing::warn!(%error, "control server task join error");
    }
    runtime.finish_shutdown();
    tracing::info!("sealantd boot stopped");
    code
}

/// Shutdown path for failures that happen before the control server is spawned (there is no
/// socket to close and no task to join).
async fn shutdown_before_control(runtime: &Arc<Runtime>, code: ExitCode) -> ExitCode {
    if !matches!(
        runtime.state(),
        RuntimeState::ShuttingDown | RuntimeState::Stopped
    ) {
        runtime.shutdown().request_graceful(None);
    }
    runtime.begin_shutdown().await;
    runtime.finish_shutdown();
    tracing::info!("sealantd boot stopped");
    code
}

#[cfg(test)]
mod tests {
    use super::*;
    use config::MapEnv;

    fn boot_config(pairs: &[(&str, &str)]) -> BootConfig {
        let mut all = vec![
            ("SEALANT_WORKSPACE_REPO_URL", "git@github.com:o/r.git"),
            ("SEALANT_OS_FAMILY", "fedora"),
            ("SEALANT_HARNESS_LAUNCH_COMMAND", "x"),
        ];
        all.extend_from_slice(pairs);
        BootConfig::load(&MapEnv::from_pairs(&all)).expect("valid boot config")
    }

    fn lookup<'a>(env: &'a [EnvVar], key: &str) -> Option<&'a str> {
        env.iter().find(|v| v.key == key).map(|v| v.value.as_str())
    }

    #[test]
    fn secret_env_overrides_passthrough_but_never_identity_vars() {
        let config = boot_config(&[
            ("PORT", "3000"),
            ("APP_MODE", "review"),
            ("PATH", "/usr/bin"),
        ]);
        let secret_env = vec![
            ("PORT".to_owned(), "4000".to_owned()),
            ("DATABASE_URL".to_owned(), "postgres://u:p@h/db".to_owned()),
            // A launcher cannot smuggle identity/PATH through the secret file: prep's values win.
            ("HOME".to_owned(), "/elsewhere".to_owned()),
            ("PATH".to_owned(), "/evil".to_owned()),
        ];
        let env = harness_child_env(&config, &secret_env);
        assert_eq!(lookup(&env, "PORT"), Some("4000"));
        assert_eq!(lookup(&env, "APP_MODE"), Some("review"));
        assert_eq!(lookup(&env, "DATABASE_URL"), Some("postgres://u:p@h/db"));
        assert_eq!(lookup(&env, "HOME"), Some("/root"));
        assert_eq!(lookup(&env, "USER"), Some("root"));
        assert!(lookup(&env, "PATH").is_some_and(|p| p.starts_with("/usr/local/bin:")));
        assert!(lookup(&env, "PATH").is_some_and(|p| !p.contains("/evil")));
    }

    #[test]
    fn secret_env_bypasses_the_secret_name_scrub_and_seeds_the_redactor() {
        // The daemon's own env scrub drops secret-looking names from the PASSTHROUGH…
        let config = boot_config(&[("MY_TOKEN", "from-container-env")]);
        assert!(!config.passthrough_env.iter().any(|(k, _)| k == "MY_TOKEN"));
        // …but the launcher-provided secret env is addressed to the workspace and lands verbatim,
        // with every value (whatever its name) registered for I/O redaction.
        let secret_env = vec![
            ("MY_TOKEN".to_owned(), "from-secret-file-value".to_owned()),
            (
                "DATABASE_URL".to_owned(),
                "postgres://plain-name".to_owned(),
            ),
        ];
        let runtime_config = into_runtime_config(&config, &secret_env);
        assert_eq!(
            lookup(&runtime_config.child_env, "MY_TOKEN"),
            Some("from-secret-file-value")
        );
        assert_eq!(
            runtime_config.redact_literals,
            vec![
                "from-secret-file-value".to_owned(),
                "postgres://plain-name".to_owned()
            ]
        );
    }

    #[test]
    fn empty_secret_env_changes_nothing() {
        let config = boot_config(&[("APP_MODE", "review")]);
        let with = harness_child_env(&config, &[]);
        assert_eq!(lookup(&with, "APP_MODE"), Some("review"));
        assert!(into_runtime_config(&config, &[]).redact_literals.is_empty());
    }
}
