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
    CaptureFlushKind, CaptureKind, ClientMessage, Command, ControlRequest, DEFAULT_MAX_FRAME_BYTES,
    EventPayload, ExecArgs, RequestId, ServerMessage,
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
    /// Session capture store (ADR-0015).
    Capture {
        #[command(subcommand)]
        action: CaptureCmd,
    },
    /// Worktree lease.
    Lease {
        #[command(subcommand)]
        action: LeaseCmd,
    },
}

#[derive(Debug, Subcommand)]
enum CaptureCmd {
    /// Take a small-class capture now and stage it for shipping.
    Now {
        /// Why: auto | turn | checkpoint | suspend | final.
        #[arg(long, default_value = "checkpoint")]
        kind: String,
    },
    /// A forced capture, then ship and register it (the suspend and terminate hooks). Without
    /// `--final`: returns once everything ahead of a bulk upload is registered. With it: the
    /// executor is ending — the daemon admits no new process, terminates every managed one
    /// (SIGTERM, SIGKILL after `--grace`) and waits for them, snaps the small and the bulk
    /// class, and ships until nothing is pending (or `--deadline`, or a fence). Prints the
    /// report: `complete` (true only when all of that happened), `incompleteReason`,
    /// `pending`, `pendingBulk`, `pendingBytes`, `refused`.
    Flush {
        /// The executor is ending: stop its processes, then snap and ship everything,
        /// dependency trees included.
        #[arg(long = "final")]
        final_: bool,
        /// How long the flush may take: `500ms`, `90s`, `15m`, `2h` (a bare number is
        /// seconds). Never clamped by the daemon. Without it a final flush runs until done and
        /// a suspend flush is bounded by the daemon's shutdown grace.
        #[arg(long, value_parser = parse_duration_ms)]
        deadline: Option<u64>,
        /// Final only: how long managed processes get after SIGTERM before SIGKILL (same
        /// units). Without it, the daemon's shutdown grace.
        #[arg(long, value_parser = parse_duration_ms, requires = "final_")]
        grace: Option<u64>,
    },
    /// Report the capture engine's state.
    Status,
    /// Fetch the plan again and bring the workspace to it (a standby taking its worktree).
    Replan,
}

#[derive(Debug, Subcommand)]
enum LeaseCmd {
    /// Report the lease epoch this executor holds.
    Epoch,
}

/// `500ms`, `90s`, `15m`, `2h`, or a bare number of seconds, as milliseconds.
fn parse_duration_ms(text: &str) -> Result<u64, String> {
    let text = text.trim();
    let split = text
        .find(|c: char| !c.is_ascii_digit())
        .unwrap_or(text.len());
    let (digits, unit) = text.split_at(split);
    let n: u64 = digits
        .parse()
        .map_err(|_| format!("{text:?} is not a duration (500ms, 90s, 15m, 2h)"))?;
    let per = match unit {
        "ms" => 1,
        "" | "s" => 1_000,
        "m" => 60_000,
        "h" => 3_600_000,
        other => return Err(format!("unknown unit {other:?} (ms, s, m, h)")),
    };
    n.checked_mul(per)
        .ok_or_else(|| format!("{text:?} is too long"))
}

fn parse_kind(kind: &str) -> Option<CaptureKind> {
    match kind {
        "auto" => Some(CaptureKind::Auto),
        "turn" => Some(CaptureKind::Turn),
        "checkpoint" => Some(CaptureKind::Checkpoint),
        "suspend" => Some(CaptureKind::Suspend),
        "final" => Some(CaptureKind::Final),
        _ => None,
    }
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
        Cmd::Capture { action } => match action {
            CaptureCmd::Now { kind } => match parse_kind(&kind) {
                Some(kind) => (Command::CaptureNow { kind }, false),
                None => {
                    eprintln!(
                        "sealantctl: unknown capture kind {kind:?} (auto|turn|checkpoint|suspend|final)"
                    );
                    return ExitCode::FAILURE;
                }
            },
            CaptureCmd::Flush {
                final_,
                deadline,
                grace,
            } => (
                Command::CaptureFlush {
                    kind: if final_ {
                        CaptureFlushKind::Final
                    } else {
                        CaptureFlushKind::Suspend
                    },
                    deadline_ms: deadline,
                    grace_ms: grace,
                },
                false,
            ),
            CaptureCmd::Status => (Command::CaptureStatus, false),
            CaptureCmd::Replan => (Command::CaptureReplan, false),
        },
        Cmd::Lease { action } => match action {
            LeaseCmd::Epoch => (Command::LeaseEpoch, false),
        },
        Cmd::Exec {
            executable,
            args,
            wait,
        } => (
            Command::Exec(ExecArgs {
                user: None,
                execution_id: None,
                session_id: None,
                executable,
                args,
                cwd: None,
                env: vec![],
                stdin: false,
                attach: false,
                timeout_millis: None,
                background: false,
                capture: None,
                graceful_signal: None,
            }),
            wait,
        ),
    };

    let request = ControlRequest::new(RequestId::new("ctl_1"), command);
    let body = sealant_protocol::encode_client(&ClientMessage::Request(request));
    if let Err(error) = write_frame(&mut writer, &body, DEFAULT_MAX_FRAME_BYTES).await {
        eprintln!("sealantctl: write failed: {error}");
        return ExitCode::FAILURE;
    }

    let mut exit = ExitCode::SUCCESS;
    loop {
        match read_frame(&mut reader, DEFAULT_MAX_FRAME_BYTES).await {
            Ok(Some(frame)) => match sealant_protocol::decode_server(&frame) {
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
                Ok(ServerMessage::Stream(frame)) => {
                    // The CLI is a request/response + telemetry tool; raw byte conduits are driven
                    // by the gateway, not sealantctl. Surface a debug line and keep reading.
                    println!("{}", serde_json::to_string(&frame).unwrap_or_default());
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

#[cfg(test)]
mod tests {

    use super::*;

    #[test]
    fn durations_parse_to_milliseconds() {
        assert_eq!(parse_duration_ms("500ms"), Ok(500));
        assert_eq!(parse_duration_ms("90s"), Ok(90_000));
        assert_eq!(parse_duration_ms("90"), Ok(90_000));
        assert_eq!(parse_duration_ms("15m"), Ok(900_000));
        assert_eq!(parse_duration_ms("2h"), Ok(7_200_000));
        assert!(parse_duration_ms("").is_err());
        assert!(parse_duration_ms("10d").is_err());
        assert!(parse_duration_ms("s").is_err());
    }

    #[test]
    fn capture_flush_takes_final_and_a_deadline() {
        let flush = |args: &[&str]| {
            let cli = Cli::try_parse_from(args).expect("parse");
            match cli.command {
                Cmd::Capture {
                    action:
                        CaptureCmd::Flush {
                            final_,
                            deadline,
                            grace,
                        },
                } => (final_, deadline, grace),
                other => panic!("{other:?}"),
            }
        };
        assert_eq!(
            flush(&["sealantctl", "capture", "flush"]),
            (false, None, None)
        );
        assert_eq!(
            flush(&["sealantctl", "capture", "flush", "--final"]),
            (true, None, None)
        );
        assert_eq!(
            flush(&[
                "sealantctl",
                "capture",
                "flush",
                "--final",
                "--grace",
                "30s"
            ]),
            (true, None, Some(30_000))
        );
        assert!(
            Cli::try_parse_from(["sealantctl", "capture", "flush", "--grace", "30s"]).is_err(),
            "a grace belongs to a final flush"
        );
        assert_eq!(
            flush(&[
                "sealantctl",
                "capture",
                "flush",
                "--final",
                "--deadline",
                "15m"
            ]),
            (true, Some(900_000), None)
        );
    }
}
