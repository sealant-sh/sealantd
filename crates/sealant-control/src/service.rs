//! The seam between the transport and the runtime.

use std::future::Future;

use sealant_protocol::{ControlRequest, ControlResponse, EventEnvelope};
use tokio::sync::broadcast;

/// A handler the control server dispatches to. Implemented by the runtime composition root.
///
/// `handle` returns exactly one response per request (the acknowledgement contract, plan §8.6).
/// Long-running work surfaces later as telemetry events delivered via [`Self::subscribe_events`].
pub trait ControlService: Send + Sync + 'static {
    /// Handle one control request and produce its single response.
    fn handle(&self, request: ControlRequest) -> impl Future<Output = ControlResponse> + Send;

    /// Subscribe to the runtime's telemetry event stream. Each connection gets its own receiver.
    fn subscribe_events(&self) -> broadcast::Receiver<EventEnvelope>;

    /// The configured maximum control-frame size.
    fn max_frame_bytes(&self) -> u32;
}
