//! CLI parsing, runtime wiring, and lifecycle orchestration.

use std::path::PathBuf;
use std::process::ExitCode;
use std::sync::Arc;

use clap::{Args, Parser, Subcommand};
use sealant_control::{serve_stdio, serve_unix};
use sealant_protocol::{NetworkMode, RuntimeState};
use sealant_runtime_core::{RuntimeConfig, new_runtime_id};
use tokio::sync::watch;

use crate::runtime::Runtime;
use crate::shutdown::ShutdownSignal;

/// Sealant workspace runtime daemon.
#[derive(Debug, Parser)]
#[command(name = "sealantd", version, about = "Sealant workspace runtime daemon")]
struct Cli {
    /// Optional subcommand. With none, runs the control server (the bare SDK-spawn invocation).
    #[command(subcommand)]
    command: Option<Command>,
    /// Flags for the bare control-server invocation.
    #[command(flatten)]
    serve: ServeArgs,
}

/// `sealantd` subcommands.
#[derive(Debug, Subcommand)]
enum Command {
    /// PID-1 workspace supervisor: prepare the workspace, clone, ssh, dotfiles, and lifecycle, then
    /// run the control server in-process and supervise the harness. Configured entirely via the
    /// `SEALANT_*` environment contract.
    Boot(BootArgs),
}

/// Arguments to `sealantd boot`. Everything else comes from `SEALANT_*` env.
#[derive(Debug, Args)]
struct BootArgs {
    /// Tracing log filter (e.g. `info`, `debug`).
    #[arg(long, default_value = "info")]
    log_level: String,
}

/// Flags for the bare (no-subcommand) control-server invocation. Preserved verbatim so the SDK
/// spawn `sealantd --socket … --workspace …` keeps working unchanged.
#[derive(Debug, Args)]
struct ServeArgs {
    /// Unix control socket path.
    #[arg(long)]
    socket: Option<PathBuf>,
    /// Serve a single connection over stdio instead of a Unix socket.
    #[arg(long)]
    stdio: bool,
    /// Workspace / repository root.
    #[arg(long)]
    workspace: Option<PathBuf>,
    /// Durable telemetry spool directory (enables crash-safe at-least-once delivery).
    #[arg(long)]
    spool_dir: Option<PathBuf>,
    /// Observe the workspace filesystem (baseline snapshot + live watch + final diff).
    #[arg(long)]
    watch_filesystem: bool,
    /// Route child egress through an explicit local proxy and observe HTTP/CONNECT metadata.
    #[arg(long)]
    network_proxy: bool,
    /// Bound workspace id.
    #[arg(long)]
    workspace_id: Option<String>,
    /// Default execution (run) id.
    #[arg(long)]
    execution_id: Option<String>,
    /// Default shell for interactive sessions.
    #[arg(long)]
    shell: Option<String>,
    /// Validate configuration, print a sanitized summary, and exit.
    #[arg(long)]
    check_config: bool,
    /// Print capabilities as JSON and exit.
    #[arg(long)]
    print_capabilities: bool,
    /// Tracing log filter (e.g. `info`, `debug`).
    #[arg(long, default_value = "info")]
    log_level: String,
}

fn build_config(cli: &ServeArgs) -> RuntimeConfig {
    let mut config = RuntimeConfig::new(new_runtime_id());
    if let Some(socket) = &cli.socket {
        config.socket_path = socket.clone();
    }
    if let Some(workspace) = &cli.workspace {
        config.workspace_root = workspace.clone();
    }
    if let Some(spool_dir) = &cli.spool_dir {
        config.spool_dir = Some(spool_dir.clone());
    }
    if cli.watch_filesystem {
        config.watch_filesystem = true;
    }
    if cli.network_proxy {
        config.network_mode = NetworkMode::Proxy;
    }
    if let Some(workspace_id) = &cli.workspace_id {
        config.workspace_id = Some(workspace_id.clone());
    }
    if let Some(execution_id) = &cli.execution_id {
        config.default_execution_id = Some(execution_id.clone().into());
    }
    if let Some(shell) = &cli.shell {
        config.default_shell = shell.clone();
    }
    config.log_level = cli.log_level.clone();
    config
}

/// Parse arguments and dispatch. With no subcommand, runs the control server (the bare SDK-spawn
/// invocation); with `boot`, runs the PID-1 supervisor. Returns the process exit code.
pub fn run() -> ExitCode {
    let cli = Cli::parse();
    match cli.command {
        Some(Command::Boot(args)) => crate::boot::run_boot(&args.log_level),
        None => run_serve(cli.serve),
    }
}

/// The bare control-server path: build the runtime from flags and serve. Unchanged behavior.
fn run_serve(cli: ServeArgs) -> ExitCode {
    // Diagnostics go to stderr; stdout is reserved for the protocol in stdio mode.
    let filter = tracing_subscriber::EnvFilter::try_new(&cli.log_level)
        .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info"));
    let _ = tracing_subscriber::fmt()
        .with_writer(std::io::stderr)
        .with_env_filter(filter)
        .try_init();

    let config = build_config(&cli);

    if let Err(error) = config.validate() {
        tracing::error!(%error, "invalid configuration");
        eprintln!("sealantd: invalid configuration: {error}");
        return ExitCode::FAILURE;
    }

    if cli.check_config {
        println!(
            "{}",
            serde_json::to_string_pretty(&config.sanitized_summary()).unwrap_or_default()
        );
        return ExitCode::SUCCESS;
    }

    let shutdown = Arc::new(ShutdownSignal::new(config.shutdown_grace_ms));
    let runtime = Runtime::new(config, shutdown);

    if cli.print_capabilities {
        println!(
            "{}",
            serde_json::to_string_pretty(&runtime.capabilities()).unwrap_or_default()
        );
        return ExitCode::SUCCESS;
    }

    let tokio_runtime = match tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
    {
        Ok(runtime) => runtime,
        Err(error) => {
            tracing::error!(%error, "failed to start async runtime");
            return ExitCode::FAILURE;
        }
    };

    tokio_runtime.block_on(serve(cli, runtime))
}

pub(crate) fn spawn_signal_listener(shutdown: Arc<ShutdownSignal>) {
    tokio::spawn(async move {
        use tokio::signal::unix::{SignalKind, signal};
        let mut terminate = match signal(SignalKind::terminate()) {
            Ok(s) => s,
            Err(error) => {
                tracing::warn!(%error, "cannot install SIGTERM handler");
                return;
            }
        };
        let mut interrupt = match signal(SignalKind::interrupt()) {
            Ok(s) => s,
            Err(error) => {
                tracing::warn!(%error, "cannot install SIGINT handler");
                return;
            }
        };
        tokio::select! {
            _ = terminate.recv() => tracing::info!("received SIGTERM"),
            _ = interrupt.recv() => tracing::info!("received SIGINT"),
        }
        shutdown.request_graceful(None);
    });
}

pub(crate) fn spawn_heartbeat(runtime: Arc<Runtime>) {
    let interval = runtime.heartbeat_interval();
    tokio::spawn(async move {
        let mut ticker = tokio::time::interval(interval);
        ticker.tick().await; // consume the immediate first tick
        loop {
            ticker.tick().await;
            match runtime.state() {
                RuntimeState::ShuttingDown | RuntimeState::Stopped => break,
                _ => runtime.publish_heartbeat(),
            }
        }
    });
}

async fn serve(cli: ServeArgs, runtime: Arc<Runtime>) -> ExitCode {
    let (serve_tx, serve_rx) = watch::channel(false);

    spawn_signal_listener(runtime.shutdown().clone());
    spawn_heartbeat(runtime.clone());
    // Reap descendants that reparent to us as subreaper / PID 1 (no-op off Linux).
    sealant_process::platform::spawn_orphan_reaper(runtime.process_registry());
    // Start durable telemetry delivery: replay the spool, then deliver live events.
    runtime.start_telemetry();
    // Begin filesystem observation if enabled (no-op otherwise).
    runtime.start_filesystem();
    // Start network observation if requested (injects proxy routing into the child env).
    let network_mode = runtime.start_network().await;
    if network_mode != NetworkMode::Off {
        tracing::info!(?network_mode, "network observation active");
    }

    // Startup validation is complete; announce healthy before accepting work.
    runtime.mark_healthy();

    let serve_runtime = runtime.clone();
    let mut serve_handle = if cli.stdio {
        tokio::spawn(async move {
            serve_stdio(serve_runtime, serve_rx).await;
            Ok::<(), std::io::Error>(())
        })
    } else {
        let path = serve_runtime.socket_path();
        let allowed = serve_runtime.allowed_peer_uids();
        tokio::spawn(async move { serve_unix(serve_runtime, &path, allowed, serve_rx).await })
    };

    let serve_finished = tokio::select! {
        () = runtime.shutdown().wait() => false,
        _ = &mut serve_handle => true,
    };

    if serve_finished {
        runtime.shutdown().request_graceful(None);
    } else {
        tracing::info!("shutdown requested");
    }

    runtime.begin_shutdown().await;
    let _ = serve_tx.send(true);
    if !serve_finished && let Err(error) = serve_handle.await {
        tracing::warn!(%error, "serve task join error");
    }
    runtime.finish_shutdown();
    tracing::info!("sealantd stopped");
    ExitCode::SUCCESS
}
