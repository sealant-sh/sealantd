//! `sealant-vmd` binary entry point.
#![cfg_attr(not(test), deny(clippy::unwrap_used, clippy::expect_used))]
#![forbid(unsafe_code)]

use std::net::SocketAddr;
use std::path::PathBuf;
use std::process::ExitCode;

use clap::Parser;
use sealant_vmd::{selftest, server};

#[derive(Debug, Parser)]
#[command(name = "sealant-vmd", version)]
struct Args {
    /// Run host self-tests, print a JSON report to stdout, and exit.
    #[arg(long)]
    self_test: bool,
    /// Loopback address to bind (must be loopback; e.g. `127.0.0.1:49152`).
    #[arg(long, default_value = "127.0.0.1:0")]
    listen: SocketAddr,
    /// File containing the 256-bit per-install bearer token (mode 0600).
    #[arg(long)]
    token_file: Option<PathBuf>,
    /// Per-installation VM disk root (`~/Library/Application Support/Mend/vm/<installId>`).
    #[arg(long)]
    vm_root: PathBuf,
    /// Path to the pinned arm64 Linux 6.12 `Image`.
    #[arg(long)]
    kernel: PathBuf,
    /// Path to the signed `sealant-vz-worker` executable.
    #[arg(long)]
    worker: PathBuf,
}

#[tokio::main]
async fn main() -> ExitCode {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .init();

    let args = Args::parse();
    if args.self_test {
        let report = selftest::run(&args.kernel, &args.worker, &args.vm_root);
        match serde_json::to_string(&report) {
            Ok(json) => println!("{json}"),
            Err(e) => {
                tracing::error!("cannot serialize self-test report: {e}");
                return ExitCode::FAILURE;
            }
        }
        return if report.ok {
            ExitCode::SUCCESS
        } else {
            ExitCode::FAILURE
        };
    }

    let Some(token_file) = args.token_file else {
        tracing::error!("--token-file is required unless --self-test is passed");
        return ExitCode::FAILURE;
    };
    let bearer_token = match std::fs::read_to_string(&token_file) {
        Ok(t) => t.trim().to_owned(),
        Err(e) => {
            tracing::error!(path = %token_file.display(), "cannot read bearer token: {e}");
            return ExitCode::FAILURE;
        }
    };
    if bearer_token.len() < 32 {
        tracing::error!("bearer token must be at least 32 characters");
        return ExitCode::FAILURE;
    }

    let config = server::Config {
        listen_addr: args.listen,
        bearer_token,
        vm_root: args.vm_root,
        kernel_path: args.kernel,
        worker_path: args.worker,
    };

    let (listener, state) = match server::bind(config).await {
        Ok(bound) => bound,
        Err(e) => {
            tracing::error!("cannot bind sealant-vmd: {e}");
            return ExitCode::FAILURE;
        }
    };
    let bound_addr = listener.local_addr().ok();
    tracing::info!(?bound_addr, "sealant-vmd listening");

    let (shutdown_tx, shutdown_rx) = tokio::sync::watch::channel(false);
    tokio::spawn(async move {
        let mut sigterm =
            match tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate()) {
                Ok(s) => s,
                Err(_) => return,
            };
        tokio::select! {
            _ = tokio::signal::ctrl_c() => {}
            _ = sigterm.recv() => {}
        }
        tracing::info!("sealant-vmd shutting down (running sealant-vz-worker VMs stay alive)");
        let _ = shutdown_tx.send(true);
    });

    match server::serve(listener, state, shutdown_rx).await {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            tracing::error!("sealant-vmd error: {e}");
            ExitCode::FAILURE
        }
    }
}
