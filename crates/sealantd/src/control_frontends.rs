//! Runs every configured control frontend for one daemon: the Unix socket (always, unless stdio
//! mode) and the optional secure WebSocket listener (ADR-0013). Shared by the bare `serve` path
//! and `boot` so both compose transports identically.

use std::path::PathBuf;
use std::sync::Arc;

use sealant_control::{ControlService, WssListener};
use tokio::sync::watch;
use tokio::task::JoinHandle;

/// Unix socket parameters, captured before spawning.
#[derive(Debug)]
pub(crate) struct UnixFrontend {
    pub(crate) path: PathBuf,
    pub(crate) allowed_peer_uids: Vec<u32>,
}

/// Spawn the frontends. Returns a handle that resolves when the Unix socket serve returns (its
/// result is the handle's result) — the WSS serve only ever returns on shutdown, after binding
/// succeeded up front in [`WssListener::bind`].
///
/// With `vsock_port` (a microVM guest, `sealantd --vm`), the control protocol is also served on
/// that `AF_VSOCK` port to the host only (`sealant_control::serve_vsock`). A vsock listener that
/// cannot bind ends the frontends with its error: the host could not reach this daemon at all.
pub(crate) fn spawn_control_frontends<S: ControlService>(
    service: Arc<S>,
    unix: UnixFrontend,
    wss: Option<WssListener>,
    vsock_port: Option<u32>,
    shutdown: watch::Receiver<bool>,
) -> JoinHandle<std::io::Result<()>> {
    tokio::spawn(async move {
        let wss_task = wss.map(|listener| {
            let service = service.clone();
            let shutdown = shutdown.clone();
            tokio::spawn(async move { listener.serve(service, shutdown).await })
        });
        let vsock_task = vsock_port.map(|port| {
            let service = service.clone();
            let shutdown = shutdown.clone();
            tokio::spawn(async move { serve_vsock(service, port, shutdown).await })
        });
        let unix_serve =
            sealant_control::serve_unix(service, &unix.path, unix.allowed_peer_uids, shutdown);
        let result = match vsock_task {
            None => unix_serve.await,
            Some(mut vsock) => {
                tokio::pin!(unix_serve);
                tokio::select! {
                    result = &mut unix_serve => {
                        let _ = vsock.await;
                        result
                    }
                    joined = &mut vsock => match joined {
                        // A vsock frontend that ended with an error (it could not bind) ends the
                        // daemon's control plane; one that ended on the shutdown waits for the
                        // Unix socket's own drain.
                        Ok(Err(error)) => Err(error),
                        _ => unix_serve.await,
                    },
                }
            }
        };
        if let Some(task) = wss_task {
            let _ = task.await;
        }
        result
    })
}

#[cfg(target_os = "linux")]
async fn serve_vsock<S: ControlService>(
    service: Arc<S>,
    port: u32,
    shutdown: watch::Receiver<bool>,
) -> std::io::Result<()> {
    sealant_control::serve_vsock(service, port, shutdown).await
}

#[cfg(not(target_os = "linux"))]
async fn serve_vsock<S: ControlService>(
    _service: Arc<S>,
    _port: u32,
    _shutdown: watch::Receiver<bool>,
) -> std::io::Result<()> {
    Err(std::io::Error::new(
        std::io::ErrorKind::Unsupported,
        "vsock is Linux only",
    ))
}
