//! sealantctl: a thin debug/integration client for sealantd.
//!
//! Connects to a control socket, issues one command, and prints each server message as a JSON line
//! to stdout (diagnostics go to stderr).
#![cfg_attr(not(test), deny(clippy::unwrap_used, clippy::expect_used))]
#![forbid(unsafe_code)]

use std::path::PathBuf;
use std::process::ExitCode;

use clap::{Parser, Subcommand};
use sealant_control::{read_frame, write_frame};
use sealant_protocol::{
    ClientMessage, Command, ControlRequest, DEFAULT_MAX_FRAME_BYTES, EventPayload, ExecArgs,
    RequestId, ServerMessage,
};
use tokio::net::UnixStream;

/// Debug client for sealantd.
#[derive(Debug, Parser)]
#[command(name = "sealantctl", version, about = "Debug client for sealantd")]
struct Cli {
    /// Control socket path.
    #[arg(long, default_value = "/run/sealantd.sock")]
    socket: PathBuf,
    #[command(subcommand)]
    command: Cmd,
}

#[derive(Debug, Subcommand)]
enum Cmd {
    /// Report runtime health.
    Health,
    /// Report capabilities.
    Capabilities,
    /// Report runtime metrics.
    Metrics,
    /// List managed processes.
    Processes,
    /// Execute a command (use `--wait` to stream until it exits).
    ///
    /// For arguments beginning with `-`, use a `--` separator: `exec --wait /bin/ls -- -la`.
    Exec {
        /// Executable to run.
        executable: String,
        /// Arguments to the executable.
        args: Vec<String>,
        /// Stream telemetry until the process exits.
        #[arg(long)]
        wait: bool,
    },
    /// Request graceful shutdown.
    Shutdown {
        /// Grace period in milliseconds.
        #[arg(long)]
        grace: Option<u64>,
    },
}

#[tokio::main(flavor = "current_thread")]
async fn main() -> ExitCode {
    let cli = Cli::parse();

    let stream = match UnixStream::connect(&cli.socket).await {
        Ok(stream) => stream,
        Err(error) => {
            eprintln!(
                "sealantctl: cannot connect to {}: {error}",
                cli.socket.display()
            );
            return ExitCode::FAILURE;
        }
    };
    let (mut reader, mut writer) = stream.into_split();

    let (command, wait_exit) = match cli.command {
        Cmd::Health => (Command::RuntimeHealth, false),
        Cmd::Capabilities => (Command::RuntimeGetCapabilities, false),
        Cmd::Metrics => (Command::GetRuntimeMetrics, false),
        Cmd::Processes => (Command::ListProcesses { execution_id: None }, false),
        Cmd::Shutdown { grace } => (
            Command::RuntimeGracefulShutdown {
                grace_millis: grace,
            },
            false,
        ),
        Cmd::Exec {
            executable,
            args,
            wait,
        } => (
            Command::Exec(ExecArgs {
                execution_id: None,
                session_id: None,
                executable,
                args,
                cwd: None,
                env: vec![],
                stdin: false,
                timeout_millis: None,
                background: false,
                capture: None,
                graceful_signal: None,
            }),
            wait,
        ),
    };

    let request = ControlRequest::new(RequestId::new("ctl_1"), command);
    let body = serde_json::to_vec(&ClientMessage::Request(request)).unwrap_or_default();
    if let Err(error) = write_frame(&mut writer, &body, DEFAULT_MAX_FRAME_BYTES).await {
        eprintln!("sealantctl: write failed: {error}");
        return ExitCode::FAILURE;
    }

    let mut exit = ExitCode::SUCCESS;
    loop {
        match read_frame(&mut reader, DEFAULT_MAX_FRAME_BYTES).await {
            Ok(Some(frame)) => match serde_json::from_slice::<ServerMessage>(&frame) {
                Ok(ServerMessage::Response(response)) => {
                    println!("{}", serde_json::to_string(&response).unwrap_or_default());
                    if !response.is_ok() {
                        exit = ExitCode::FAILURE;
                    }
                    if !wait_exit {
                        break;
                    }
                }
                Ok(ServerMessage::Event(event)) => {
                    println!("{}", serde_json::to_string(&event).unwrap_or_default());
                    if wait_exit && matches!(event.payload, EventPayload::ProcessExited(_)) {
                        break;
                    }
                }
                Err(error) => eprintln!("sealantctl: decode error: {error}"),
            },
            Ok(None) => break,
            Err(error) => {
                eprintln!("sealantctl: read error: {error}");
                exit = ExitCode::FAILURE;
                break;
            }
        }
    }
    exit
}
