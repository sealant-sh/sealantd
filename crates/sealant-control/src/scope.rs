//! What a control frontend lets its peers ask for.
//!
//! A normal daemon answers every command. A daemon booted to recover a crashed workspace
//! (`sealantd --vm` with `sealantd.mode=recover`, or `sealantd boot --recovery`) exists only to
//! ship what is on its disk: the platform asks it for its status and for the final flush, and
//! nothing else. [`ControlScope::Recovery`] holds it to that at the transport, before the request
//! reaches the runtime, so no command added later can slip past by forgetting to check the
//! runtime's admission state.

use sealant_protocol::{CaptureFlushKind, Command, ControlError, ControlErrorCode, ControlRequest};
use tokio::sync::broadcast;

use crate::service::{ConnHandle, ControlService};

/// Which commands a frontend dispatches.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum ControlScope {
    /// Every command.
    #[default]
    Full,
    /// Status and the final flush only: health, capabilities, metrics, the process list,
    /// `capture.status`, `lease.epoch`, `capture.flush` of kind `final`, and
    /// `runtime.gracefulShutdown` (the stop that follows the flush). Admission stays closed:
    /// no exec, session, PTY, forward, SFTP bridge, bind, re-plan, dotfiles apply or kill.
    Recovery,
}

impl ControlScope {
    /// Whether this scope dispatches `command`.
    #[must_use]
    pub fn permits(self, command: &Command) -> bool {
        match self {
            Self::Full => true,
            Self::Recovery => matches!(
                command,
                Command::RuntimeHealth
                    | Command::RuntimeGetCapabilities
                    | Command::GetRuntimeMetrics
                    | Command::ListProcesses { .. }
                    | Command::CaptureStatus
                    | Command::LeaseEpoch
                    | Command::RuntimeGracefulShutdown { .. }
                    | Command::CaptureFlush {
                        kind: CaptureFlushKind::Final,
                        ..
                    }
            ),
        }
    }
}

/// A [`ControlService`] that refuses what its [`ControlScope`] does not permit, with
/// `policy-denied`, and hands everything else to `inner` unchanged.
#[derive(Debug)]
pub struct ScopedService<S> {
    inner: std::sync::Arc<S>,
    scope: ControlScope,
}

impl<S> ScopedService<S> {
    /// Wrap `inner` in `scope`.
    pub fn new(inner: std::sync::Arc<S>, scope: ControlScope) -> Self {
        Self { inner, scope }
    }

    /// The scope this service enforces.
    #[must_use]
    pub fn scope(&self) -> ControlScope {
        self.scope
    }
}

impl<S: ControlService> ControlService for ScopedService<S> {
    async fn handle_on_connection(
        &self,
        request: ControlRequest,
        conn: &ConnHandle,
    ) -> sealant_protocol::ControlResponse {
        if !self.scope.permits(&request.command) {
            return sealant_protocol::ControlResponse::error(
                request.request_id,
                ControlError::new(
                    ControlErrorCode::PolicyDenied,
                    "this daemon is a recovery boot: it answers status and the final capture \
                     flush only, and admits nothing"
                        .to_owned(),
                ),
            );
        }
        self.inner.handle_on_connection(request, conn).await
    }

    fn subscribe_events(&self) -> broadcast::Receiver<sealant_protocol::EventEnvelope> {
        self.inner.subscribe_events()
    }

    fn max_frame_bytes(&self) -> u32 {
        self.inner.max_frame_bytes()
    }
}
