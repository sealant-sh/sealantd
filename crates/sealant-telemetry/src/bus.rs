//! The event bus and correlation builder.

use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use sealant_protocol::{
    CaptureMethod, Confidence, EventEnvelope, EventId, EventPayload, ExecutionId, ProcessId,
    RequestId, RuntimeId, SCHEMA_VERSION, Sequence, SessionId,
};
use sealant_runtime_core::{Clock, IdGenerator};
use tokio::sync::broadcast;

/// Correlation ids attached to an event. Cheaply cloned; absent ids are omitted on the wire.
#[derive(Debug, Clone, Default)]
pub struct Correlation {
    /// Execution association.
    pub execution_id: Option<ExecutionId>,
    /// Session association.
    pub session_id: Option<SessionId>,
    /// Process association.
    pub process_id: Option<ProcessId>,
    /// Originating control request.
    pub request_id: Option<RequestId>,
}

impl Correlation {
    /// An empty correlation.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Set the execution association.
    #[must_use]
    pub fn execution(mut self, id: Option<ExecutionId>) -> Self {
        self.execution_id = id;
        self
    }

    /// Set the session association.
    #[must_use]
    pub fn session(mut self, id: Option<SessionId>) -> Self {
        self.session_id = id;
        self
    }

    /// Set the process association.
    #[must_use]
    pub fn process(mut self, id: ProcessId) -> Self {
        self.process_id = Some(id);
        self
    }

    /// Set the originating request.
    #[must_use]
    pub fn request(mut self, id: Option<RequestId>) -> Self {
        self.request_id = id;
        self
    }
}

/// The runtime-wide event bus.
#[derive(Debug)]
pub struct EventBus {
    runtime_id: RuntimeId,
    clock: Arc<Clock>,
    idgen: Arc<IdGenerator>,
    sequence: AtomicU64,
    emitted: AtomicU64,
    sender: broadcast::Sender<EventEnvelope>,
}

impl EventBus {
    /// Create a bus with a bounded broadcast buffer of `capacity` events.
    #[must_use]
    pub fn new(
        runtime_id: RuntimeId,
        clock: Arc<Clock>,
        idgen: Arc<IdGenerator>,
        capacity: usize,
    ) -> Self {
        let (sender, _initial_rx) = broadcast::channel(capacity.max(1));
        Self {
            runtime_id,
            clock,
            idgen,
            sequence: AtomicU64::new(0),
            emitted: AtomicU64::new(0),
            sender,
        }
    }

    /// Publish a payload. This is the single deterministic point where `sequence`, `eventId`, and
    /// timestamps are assigned. Returns the minted event id.
    pub fn publish(
        &self,
        correlation: &Correlation,
        capture_method: CaptureMethod,
        confidence: Confidence,
        payload: EventPayload,
    ) -> EventId {
        let sequence = Sequence(self.sequence.fetch_add(1, Ordering::Relaxed));
        let event_id = self.idgen.event_id();
        let envelope = EventEnvelope {
            schema_version: SCHEMA_VERSION,
            event_id: event_id.clone(),
            runtime_id: self.runtime_id.clone(),
            execution_id: correlation.execution_id.clone(),
            session_id: correlation.session_id.clone(),
            process_id: correlation.process_id.clone(),
            request_id: correlation.request_id.clone(),
            sequence,
            observed_at: self.clock.wall_now(),
            monotonic_timestamp: self.clock.mono_now(),
            capture_method,
            confidence,
            payload,
        };
        self.emitted.fetch_add(1, Ordering::Relaxed);
        // A send error only means there are currently no subscribers; the event is still counted.
        let _ = self.sender.send(envelope);
        event_id
    }

    /// Subscribe to the event stream. Each subscriber gets an independent receiver.
    #[must_use]
    pub fn subscribe(&self) -> broadcast::Receiver<EventEnvelope> {
        self.sender.subscribe()
    }

    /// Total events published since startup.
    #[must_use]
    pub fn emitted(&self) -> u64 {
        self.emitted.load(Ordering::Relaxed)
    }

    /// Number of currently-attached subscribers.
    #[must_use]
    pub fn subscriber_count(&self) -> usize {
        self.sender.receiver_count()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use sealant_protocol::{RuntimeHeartbeat, RuntimeState};
    use sealant_runtime_core::new_runtime_id;

    fn bus() -> EventBus {
        let rt = new_runtime_id();
        let clock = Arc::new(Clock::new());
        let idgen = Arc::new(IdGenerator::new(&rt));
        EventBus::new(rt, clock, idgen, 64)
    }

    #[tokio::test]
    async fn publishes_with_monotonic_sequence() {
        let bus = bus();
        let mut rx = bus.subscribe();
        let payload = || {
            EventPayload::RuntimeHeartbeat(RuntimeHeartbeat {
                state: RuntimeState::Healthy,
            })
        };
        bus.publish(
            &Correlation::new(),
            CaptureMethod::Internal,
            Confidence::Observed,
            payload(),
        );
        bus.publish(
            &Correlation::new(),
            CaptureMethod::Internal,
            Confidence::Observed,
            payload(),
        );

        let a = rx.recv().await.expect("first");
        let b = rx.recv().await.expect("second");
        assert_eq!(a.sequence, Sequence(0));
        assert_eq!(b.sequence, Sequence(1));
        assert_ne!(a.event_id, b.event_id);
        assert_eq!(bus.emitted(), 2);
    }

    #[tokio::test]
    async fn carries_correlation() {
        let bus = bus();
        let mut rx = bus.subscribe();
        let corr = Correlation::new()
            .execution(Some(ExecutionId::new("run-1")))
            .process(ProcessId::new("proc_1"));
        bus.publish(
            &corr,
            CaptureMethod::Pipe,
            Confidence::Observed,
            EventPayload::RuntimeHeartbeat(RuntimeHeartbeat {
                state: RuntimeState::Healthy,
            }),
        );
        let env = rx.recv().await.expect("event");
        assert_eq!(env.execution_id, Some(ExecutionId::new("run-1")));
        assert_eq!(env.process_id, Some(ProcessId::new("proc_1")));
        assert_eq!(env.session_id, None);
    }
}
