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
pub(crate) fn spawn_control_frontends<S: ControlService>(
    service: Arc<S>,
    unix: UnixFrontend,
    wss: Option<WssListener>,
    shutdown: watch::Receiver<bool>,
) -> JoinHandle<std::io::Result<()>> {
    tokio::spawn(async move {
        let wss_task = wss.map(|listener| {
            let service = service.clone();
            let shutdown = shutdown.clone();
            tokio::spawn(async move { listener.serve(service, shutdown).await })
        });
        let result =
            sealant_control::serve_unix(service, &unix.path, unix.allowed_peer_uids, shutdown)
                .await;
        if let Some(task) = wss_task {
            let _ = task.await;
        }
        result
    })
}
