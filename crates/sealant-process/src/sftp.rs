//! SFTP-equivalent light bridge (gateway consolidation §1.C).
//!
//! SFTP is a request/response binary protocol over one bidirectional byte stream — exactly what the
//! reliable [`ChannelId`] conduit provides. Rather than implement file semantics, we spawn the
//! standalone in-container `sftp-server` binary and bridge its stdio to the channel: inbound
//! [`StreamPayload::Data`] → child stdin, child stdout → outbound [`StreamFrame::Data`]. The daemon
//! stays a dumb byte conduit; payload never touches the telemetry bus.
//!
//! Provisioning note (cross-repo): the binary must be the standalone `sftp-server`
//! (`/usr/lib/openssh/sftp-server` on Debian/Ubuntu, `/usr/libexec/openssh/sftp-server` on Fedora),
//! NOT sshd's `internal-sftp`. §4 (sshd removal) must preserve that binary.

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::sync::{Arc, Mutex};

use sealant_protocol::{
    ChannelId, ControlError, ControlErrorCode, ServerMessage, StreamEnd, StreamFrame, StreamPayload,
};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::process::Command;
use tokio::sync::mpsc;

use crate::registry::ProcessRegistry;

/// Read-buffer size for the stdout→gateway pump.
const READ_BUF: usize = 64 * 1024;

/// Standard locations of the standalone `sftp-server` binary across distros.
const SFTP_SERVER_PATHS: &[&str] = &[
    "/usr/lib/openssh/sftp-server",     // Debian / Ubuntu (openssh-client)
    "/usr/libexec/openssh/sftp-server", // Fedora / RHEL
    "/usr/lib/ssh/sftp-server",         // Arch
    "/usr/libexec/sftp-server",         // misc
];

/// Resolve the `sftp-server` binary path, honoring the `SEALANT_SFTP_SERVER_PATH` override.
#[must_use]
pub fn resolve_sftp_server() -> Option<PathBuf> {
    if let Ok(path) = std::env::var("SEALANT_SFTP_SERVER_PATH")
        && !path.is_empty()
        && Path::new(&path).exists()
    {
        return Some(PathBuf::from(path));
    }
    SFTP_SERVER_PATHS
        .iter()
        .map(PathBuf::from)
        .find(|p| p.exists())
}

#[derive(Debug)]
struct SftpEntry {
    stdout_to_gateway: tokio::task::JoinHandle<()>,
    stdin_from_gateway: tokio::task::JoinHandle<()>,
    waiter: tokio::task::JoinHandle<()>,
    /// OS pid of the bridged `sftp-server`, held in the registry's owned-pid set while live.
    pid: i32,
}

impl SftpEntry {
    fn abort(&self) {
        self.stdout_to_gateway.abort();
        self.stdin_from_gateway.abort();
        self.waiter.abort();
    }
}

/// Registry of live SFTP bridges, keyed by channel id. Connection-scoped teardown drops the inbound
/// sinks; [`SftpRuntime::close`] aborts a single bridge (and `kill_on_drop` reaps the child).
#[derive(Debug)]
pub struct SftpRuntime {
    inner: Mutex<HashMap<ChannelId, SftpEntry>>,
    /// The shared process registry — sftp children register as owned pids so the orphan reaper
    /// never steals their exit status from the waiter.
    registry: Arc<ProcessRegistry>,
}

impl SftpRuntime {
    /// An empty SFTP runtime registering its children as owned pids in `registry`.
    #[must_use]
    pub fn new(registry: Arc<ProcessRegistry>) -> Self {
        Self {
            inner: Mutex::new(HashMap::new()),
            registry,
        }
    }

    /// Whether an `sftp-server` binary is available in this container.
    #[must_use]
    pub fn available() -> bool {
        resolve_sftp_server().is_some()
    }

    /// Open an SFTP bridge bound to `channel_id`, spawning `sftp-server` in `cwd`.
    ///
    /// Returns the inbound sink (gateway → child stdin) the caller registers in the connection's
    /// channel registry.
    ///
    /// # Errors
    /// Returns [`ControlErrorCode::FeatureUnavailable`] if no `sftp-server` binary exists, or
    /// [`ControlErrorCode::ProcessStartFailed`] if it cannot be spawned.
    pub fn open(
        &self,
        channel_id: ChannelId,
        cwd: &Path,
        out_tx: mpsc::Sender<ServerMessage>,
    ) -> Result<mpsc::Sender<StreamPayload>, ControlError> {
        let binary = resolve_sftp_server().ok_or_else(|| {
            ControlError::new(
                ControlErrorCode::FeatureUnavailable,
                "no sftp-server binary found (expected /usr/lib/openssh/sftp-server or similar)"
                    .to_owned(),
            )
        })?;

        let mut command = Command::new(&binary);
        command.current_dir(cwd);
        command.stdin(Stdio::piped());
        command.stdout(Stdio::piped());
        command.stderr(Stdio::null());
        command.kill_on_drop(true);
        // Spawn under the reap gate so the orphan reaper can never peek this child before its
        // pid is recorded as owned (see `ProcessRegistry::owned_pids`).
        let mut owned = self.registry.owned_pids();
        let mut child = command.spawn().map_err(|e| {
            ControlError::process_start_failed(format!("{}: {e}", binary.display()))
        })?;
        let pid = child.id().map_or(-1, |p| p as i32);
        owned.insert(pid);
        drop(owned);

        let (mut stdin, mut stdout) = match (child.stdin.take(), child.stdout.take()) {
            (Some(stdin), Some(stdout)) => (stdin, stdout),
            _ => {
                // The kill_on_drop child never got a waiter; give its pid back to the reaper.
                self.registry.release_pid(pid);
                return Err(ControlError::process_start_failed(
                    "sftp stdio missing".to_owned(),
                ));
            }
        };

        // gateway → child stdin (bounded so a slow child backpressures the gateway).
        let (inbound_tx, mut inbound_rx) = mpsc::channel::<StreamPayload>(64);
        let stdin_from_gateway = tokio::spawn(async move {
            while let Some(payload) = inbound_rx.recv().await {
                match payload {
                    StreamPayload::Data { data } => {
                        if stdin.write_all(data.as_slice()).await.is_err() {
                            break;
                        }
                    }
                    StreamPayload::WindowUpdate { .. } => {}
                    StreamPayload::End(_) => break,
                }
            }
            let _ = stdin.shutdown().await;
        });

        // child stdout → gateway (awaited send = backpressure).
        let s2g_channel = channel_id.clone();
        let s2g_out = out_tx.clone();
        let stdout_to_gateway = tokio::spawn(async move {
            let mut buf = vec![0u8; READ_BUF];
            let mut seq: u64 = 0;
            loop {
                match stdout.read(&mut buf).await {
                    Ok(0) | Err(_) => break,
                    Ok(n) => {
                        let frame = StreamFrame::data(s2g_channel.clone(), seq, &buf[..n]);
                        seq = seq.wrapping_add(1);
                        if s2g_out.send(ServerMessage::Stream(frame)).await.is_err() {
                            break;
                        }
                    }
                }
            }
        });

        // Reap the child and emit a final End{exit_code} on the channel.
        let waiter_channel = channel_id.clone();
        let waiter_out = out_tx;
        let waiter_registry = self.registry.clone();
        let waiter = tokio::spawn(async move {
            let status = child.wait().await;
            waiter_registry.release_pid(pid);
            let exit_code = status.ok().and_then(|s| s.code());
            let end = StreamFrame::end(
                waiter_channel,
                u64::MAX,
                StreamEnd {
                    exit_code,
                    signal: None,
                    error: None,
                },
            );
            let _ = waiter_out.send(ServerMessage::Stream(end)).await;
        });

        self.inner.lock().unwrap_or_else(|e| e.into_inner()).insert(
            channel_id,
            SftpEntry {
                stdout_to_gateway,
                stdin_from_gateway,
                waiter,
                pid,
            },
        );
        Ok(inbound_tx)
    }

    /// Close an SFTP bridge eagerly. Idempotent.
    pub fn close(&self, channel_id: &ChannelId) {
        if let Some(entry) = self
            .inner
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .remove(channel_id)
        {
            entry.abort();
            // The aborted waiter can no longer release the pid; do it here (idempotent). The
            // kill_on_drop child is reaped by Tokio's background queue, not by us.
            self.registry.release_pid(entry.pid);
        }
    }

    /// Number of live bridges.
    #[must_use]
    pub fn len(&self) -> usize {
        self.inner.lock().unwrap_or_else(|e| e.into_inner()).len()
    }

    /// Whether there are no live bridges.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn availability_matches_resolution() {
        assert_eq!(SftpRuntime::available(), resolve_sftp_server().is_some());
    }

    #[tokio::test]
    async fn open_without_binary_reports_unavailable() {
        // When no sftp-server binary is present (typical for macOS dev / minimal CI), open must
        // fail closed with FeatureUnavailable. If a real sftp-server is present, the bridge spawns
        // and the End frame is exercised by integration tests instead.
        if SftpRuntime::available() {
            let (out_tx, mut rx) = mpsc::channel::<ServerMessage>(8);
            let rt = SftpRuntime::new(Arc::new(ProcessRegistry::new()));
            let channel = ChannelId::new("chan_sftp");
            let inbound = rt
                .open(channel.clone(), Path::new("/tmp"), out_tx)
                .expect("sftp-server present: open should succeed");
            // Closing inbound (End) makes sftp-server exit; we should observe an End frame.
            inbound
                .send(StreamPayload::End(StreamEnd::default()))
                .await
                .expect("send end");
            // Drain until an End arrives (sftp-server may emit nothing on a bare EOF).
            let _ = tokio::time::timeout(std::time::Duration::from_secs(2), async {
                while let Some(msg) = rx.recv().await {
                    if matches!(
                        msg,
                        ServerMessage::Stream(StreamFrame {
                            payload: StreamPayload::End(_),
                            ..
                        })
                    ) {
                        break;
                    }
                }
            })
            .await;
            rt.close(&channel);
            return;
        }
        let (out_tx, _rx) = mpsc::channel::<ServerMessage>(8);
        let rt = SftpRuntime::new(Arc::new(ProcessRegistry::new()));
        let err = rt
            .open(ChannelId::new("chan_sftp"), Path::new("/tmp"), out_tx)
            .expect_err("should be unavailable");
        assert_eq!(err.code, ControlErrorCode::FeatureUnavailable);
    }

    /// Drive a raw SFTP `SSH_FXP_INIT` handshake over the channel and assert the server replies with
    /// a `SSH_FXP_VERSION` packet. Proves the byte conduit faithfully bridges the binary protocol.
    /// Skipped when no `sftp-server` binary is present (e.g. macOS dev host / minimal CI).
    #[tokio::test]
    async fn sftp_init_handshake_returns_version() {
        if !SftpRuntime::available() {
            return;
        }
        let (out_tx, mut rx) = mpsc::channel::<ServerMessage>(64);
        let rt = SftpRuntime::new(Arc::new(ProcessRegistry::new()));
        let channel = ChannelId::new("chan_sftp_init");
        let inbound = rt
            .open(channel.clone(), Path::new("/tmp"), out_tx)
            .expect("open sftp bridge");

        // SSH_FXP_INIT: u32 length=5, u8 type=1 (INIT), u32 version=3.
        let mut init = Vec::new();
        init.extend_from_slice(&5u32.to_be_bytes());
        init.push(1); // SSH_FXP_INIT
        init.extend_from_slice(&3u32.to_be_bytes());
        inbound
            .send(StreamPayload::data(sealant_protocol::Base64Bytes::new(
                init,
            )))
            .await
            .expect("send init");

        // Collect outbound bytes until we have a full packet; assert type byte == 2 (FXP_VERSION).
        let mut acc: Vec<u8> = Vec::new();
        let got_version = tokio::time::timeout(std::time::Duration::from_secs(5), async {
            loop {
                match rx.recv().await {
                    Some(ServerMessage::Stream(StreamFrame {
                        payload: StreamPayload::Data { data },
                        ..
                    })) => {
                        acc.extend_from_slice(data.as_slice());
                        if acc.len() >= 5 {
                            let len = u32::from_be_bytes([acc[0], acc[1], acc[2], acc[3]]) as usize;
                            if acc.len() >= 4 + len {
                                return acc[4] == 2; // SSH_FXP_VERSION
                            }
                        }
                    }
                    Some(_) => {}
                    None => return false,
                }
            }
        })
        .await
        .unwrap_or(false);
        assert!(got_version, "expected SSH_FXP_VERSION; got {acc:?}");
        rt.close(&channel);
    }
}
