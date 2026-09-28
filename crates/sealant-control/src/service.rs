//! The seam between the transport and the runtime.

use std::future::Future;
use std::sync::Arc;

use sealant_protocol::{
    ChannelId, ControlRequest, ControlResponse, EventEnvelope, ServerMessage, StreamPayload,
};
use tokio::sync::{Mutex, broadcast, mpsc, watch};

/// The per-connection registry of open byte conduits.
///
/// Maps each [`ChannelId`] opened on this connection to the sink that pumps inbound
/// [`StreamPayload`] frames (gateway → far end). Owned by `handle_connection` and shared into
/// [`ConnHandle`] so streaming commands can register their inbound sink at open time and so that
/// dropping the connection tears down every channel (connection-scoped lifetime).
pub type ChannelRegistry =
    Arc<Mutex<std::collections::HashMap<ChannelId, mpsc::Sender<StreamPayload>>>>;

/// An eager teardown action for one channel: aborts both pumps AND removes the channel's
/// runtime map entry (e.g. `ForwardRuntime::close` / `SftpRuntime::close` / `SessionRuntime::detach`).
///
/// This is the load-bearing half of connection-scoped teardown. Dropping the [`ChannelRegistry`]
/// closes the inbound (gateway → far end) sink, which only ends the inbound pump. The *outbound*
/// pump (far end → gateway) blocks on `read()` from the upstream and, for an idle/never-writing
/// upstream, never calls `out_tx.send`, so it never observes the closed outbound queue — it would
/// hang forever, leaking the task, the socket FD, and the un-reaped runtime map entry. Invoking the
/// closer at teardown aborts that read pump and reaps the map entry unconditionally.
pub type ChannelCloser = Box<dyn FnOnce() + Send>;

/// The per-connection registry of eager channel closers, keyed by [`ChannelId`]. Owned by
/// `handle_connection` and shared into [`ConnHandle`]. Drained and invoked on connection teardown.
pub type CloserRegistry = Arc<Mutex<std::collections::HashMap<ChannelId, ChannelCloser>>>;

/// A per-connection handle the service uses to open and drive reliable byte channels.
///
/// `out_tx` is the *same* backpressured outbound queue used for responses and events
/// (`OUTBOUND_CAPACITY`): awaiting `out_tx.send(...)` is the flow-control mechanism. `channels` is
/// the connection's [`ChannelRegistry`] (inbound sinks); `closers` is the connection's
/// [`CloserRegistry`] (eager teardown actions); `shutdown` lets long-lived pump tasks observe
/// shutdown.
#[derive(Clone)]
pub struct ConnHandle {
    /// The connection's backpressured outbound queue (responses, events, and stream frames).
    pub out_tx: mpsc::Sender<ServerMessage>,
    /// The connection's channel registry (inbound sinks keyed by [`ChannelId`]).
    pub channels: ChannelRegistry,
    /// The connection's closer registry (eager teardown actions keyed by [`ChannelId`]).
    pub closers: CloserRegistry,
    /// Observes daemon shutdown so per-channel pump tasks can exit promptly.
    pub shutdown: watch::Receiver<bool>,
}

impl std::fmt::Debug for ConnHandle {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ConnHandle").finish_non_exhaustive()
    }
}

impl ConnHandle {
    /// Register a freshly opened channel's inbound sink so reader-routed `Stream` frames reach it.
    pub async fn register_channel(
        &self,
        channel_id: ChannelId,
        inbound: mpsc::Sender<StreamPayload>,
    ) {
        self.channels.lock().await.insert(channel_id, inbound);
    }

    /// Register a channel's eager teardown action. Invoked on connection drop (and once on explicit
    /// close) to abort both pumps and reap the channel's runtime map entry — closing the idle-pump
    /// leak. Registering a closer for a channel that already has one replaces (and runs) the old one
    /// is *not* done here; the caller is expected to register once at open time.
    pub async fn register_closer(&self, channel_id: ChannelId, closer: ChannelCloser) {
        self.closers.lock().await.insert(channel_id, closer);
    }

    /// Remove a channel's closer without running it (the caller is closing it explicitly and will
    /// invoke the runtime close itself). Returns the closer if one was registered.
    pub async fn take_closer(&self, channel_id: &ChannelId) -> Option<ChannelCloser> {
        self.closers.lock().await.remove(channel_id)
    }

    /// Deregister (and drop the sink for) a channel; its pump task observes the closed sender.
    /// Also drops any registered closer (the caller is performing the runtime close explicitly).
    pub async fn deregister_channel(&self, channel_id: &ChannelId) {
        self.channels.lock().await.remove(channel_id);
        self.closers.lock().await.remove(channel_id);
    }
}

/// A handler the control server dispatches to. Implemented by the runtime composition root.
///
/// `handle_on_connection` returns exactly one response per request (the acknowledgement contract,
/// plan §8.6) but additionally receives this connection's [`ConnHandle`] so streaming commands
/// (`attachSession`/`openForward`/`openSftp`) can register a [`ChannelId`] and pump bytes over the
/// backpressured writer. Long-running telemetry still surfaces via [`Self::subscribe_events`].
pub trait ControlService: Send + Sync + 'static {
    /// Handle one control request with access to this connection's backpressured writer and channel
    /// registry, and produce its single response.
    fn handle_on_connection(
        &self,
        request: ControlRequest,
        conn: &ConnHandle,
    ) -> impl Future<Output = ControlResponse> + Send;

    /// Subscribe to the runtime's telemetry event stream. Each connection gets its own receiver.
    fn subscribe_events(&self) -> broadcast::Receiver<EventEnvelope>;

    /// The configured maximum control-frame size.
    fn max_frame_bytes(&self) -> u32;
}
