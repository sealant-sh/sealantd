//! CLI parsing, runtime wiring, and lifecycle orchestration.

use std::path::PathBuf;
use std::process::ExitCode;
use std::sync::Arc;

use clap::Parser;
use sealant_control::{serve_stdio, serve_unix};
use sealant_protocol::RuntimeState;
use sealant_runtime_core::{RuntimeConfig, new_runtime_id};
use tokio::sync::watch;

use crate::runtime::Runtime;
use crate::shutdown::ShutdownSignal;

/// Sealant sandbox runtime daemon.
#[derive(Debug, Parser)]
#[command(name = "sealantd", version, about = "Sealant sandbox runtime daemon")]
struct Cli {
    /// Unix control socket path.
    #[arg(long)]
    socket: Option<PathBuf>,
    /// Serve a single connection over stdio instead of a Unix socket.
    #[arg(long)]
    stdio: bool,
    /// Workspace / repository root.
    #[arg(long)]
    workspace: Option<PathBuf>,
    /// Bound sandbox id.
    #[arg(long)]
    sandbox_id: Option<String>,
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

fn build_config(cli: &Cli) -> RuntimeConfig {
    let mut config = RuntimeConfig::new(new_runtime_id());
    if let Some(socket) = &cli.socket {
        config.socket_path = socket.clone();
    }
    if let Some(workspace) = &cli.workspace {
        config.workspace_root = workspace.clone();
    }
    if let Some(sandbox_id) = &cli.sandbox_id {
        config.sandbox_id = Some(sandbox_id.clone());
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

/// Parse arguments, build the runtime, and run to completion. Returns the process exit code.
pub fn run() -> ExitCode {
    let cli = Cli::parse();

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

fn spawn_signal_listener(shutdown: Arc<ShutdownSignal>) {
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

fn spawn_heartbeat(runtime: Arc<Runtime>) {
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

async fn serve(cli: Cli, runtime: Arc<Runtime>) -> ExitCode {
    let (serve_tx, serve_rx) = watch::channel(false);

    spawn_signal_listener(runtime.shutdown().clone());
    spawn_heartbeat(runtime.clone());
    // Reap descendants that reparent to us as subreaper / PID 1 (no-op off Linux).
    sealant_process::platform::spawn_orphan_reaper(runtime.process_registry());

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
        tokio::spawn(async move { serve_unix(serve_runtime, &path, serve_rx).await })
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
