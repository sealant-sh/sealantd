//! The event bus and correlation builder.
//!
//! The bus assigns the final `sequence`, `eventId`, and timestamps at a single deterministic point
//! (plan §15) and fans events out over a bounded broadcast channel.
//!
//! Two delivery modes:
//! - **Direct** (default, used by unit tests): `publish` broadcasts immediately.
//! - **Durable**: `publish` hands the event to a bounded queue; a delivery task spools each event
//!   (write-ahead durability), broadcasts it, and periodically flushes + acks the spool. On startup
//!   the task replays un-acked spooled events. Under queue pressure, low/normal events are dropped
//!   with explicit `telemetry.dropped` accounting while critical events are delivered inline so they
//!   are never silently lost (optimistic broadcast-ack model).

use std::sync::Arc;
use std::sync::Mutex;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use sealant_eventlog::Spool;
use sealant_protocol::{
    CaptureMethod, Confidence, EventEnvelope, EventId, EventPayload, EventPriority, ExecutionId,
    ProcessId, RequestId, RuntimeId, SCHEMA_VERSION, Sequence, SessionId, TelemetryDropped,
};
use sealant_runtime_core::{Clock, IdGenerator};
use tokio::sync::{broadcast, mpsc};

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

#[derive(Debug, Default)]
struct DropCounters {
    low: AtomicU64,
    normal: AtomicU64,
    critical: AtomicU64,
    spilled_critical: AtomicU64,
}

impl DropCounters {
    fn total(&self) -> u64 {
        self.low.load(Ordering::Relaxed)
            + self.normal.load(Ordering::Relaxed)
            + self.critical.load(Ordering::Relaxed)
    }
}

#[derive(Debug)]
struct Durable {
    submit_tx: mpsc::Sender<EventEnvelope>,
    rx_holder: Mutex<Option<mpsc::Receiver<EventEnvelope>>>,
    spool: Arc<Mutex<Spool>>,
    high_water: AtomicU64,
    flush_interval: Duration,
    queue_capacity: u64,
}

#[derive(Debug)]
enum Delivery {
    Direct,
    Durable(Durable),
}

/// The runtime-wide event bus.
#[derive(Debug)]
pub struct EventBus {
    runtime_id: RuntimeId,
    clock: Arc<Clock>,
    idgen: Arc<IdGenerator>,
    sequence: AtomicU64,
    emitted: AtomicU64,
    drops: DropCounters,
    delivery: Delivery,
    sender: broadcast::Sender<EventEnvelope>,
}

impl EventBus {
    /// Create a direct-broadcast bus (no durability). `publish` broadcasts immediately.
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
            drops: DropCounters::default(),
            delivery: Delivery::Direct,
            sender,
        }
    }

    /// Create a durable, spool-backed bus. Call [`EventBus::start_delivery`] once a Tokio runtime is
    /// available to spawn the delivery task and replay any un-acked spooled events.
    #[must_use]
    pub fn durable(
        runtime_id: RuntimeId,
        clock: Arc<Clock>,
        idgen: Arc<IdGenerator>,
        capacity: usize,
        spool: Spool,
        flush_interval: Duration,
    ) -> Self {
        let capacity = capacity.max(1);
        let (sender, _initial_rx) = broadcast::channel(capacity);
        let (submit_tx, submit_rx) = mpsc::channel(capacity);
        Self {
            runtime_id,
            clock,
            idgen,
            sequence: AtomicU64::new(0),
            emitted: AtomicU64::new(0),
            drops: DropCounters::default(),
            delivery: Delivery::Durable(Durable {
                submit_tx,
                rx_holder: Mutex::new(Some(submit_rx)),
                spool: Arc::new(Mutex::new(spool)),
                high_water: AtomicU64::new(0),
                flush_interval,
                queue_capacity: capacity as u64,
            }),
            sender,
        }
    }

    /// Spawn the durable delivery task (no-op for a direct bus or if already started).
    pub fn start_delivery(self: &Arc<Self>) {
        let Delivery::Durable(durable) = &self.delivery else {
            return;
        };
        let Some(rx) = durable
            .rx_holder
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .take()
        else {
            return;
        };
        let bus = self.clone();
        tokio::spawn(async move { bus.run_delivery(rx).await });
    }

    async fn run_delivery(self: Arc<Self>, mut rx: mpsc::Receiver<EventEnvelope>) {
        let Delivery::Durable(durable) = &self.delivery else {
            return;
        };
        self.replay_spool(durable);
        let mut flush = tokio::time::interval(durable.flush_interval);
        let mut last_drops = 0u64;
        loop {
            tokio::select! {
                maybe = rx.recv() => match maybe {
                    Some(env) => self.deliver_durable(durable, env),
                    None => break,
                },
                _ = flush.tick() => {
                    {
                        let mut spool = durable.spool.lock().unwrap_or_else(|e| e.into_inner());
                        let _ = spool.flush();
                        let _ = spool.ack(durable.high_water.load(Ordering::Relaxed));
                    }
                    let total = self.drops.total();
                    if total > last_drops {
                        self.emit_drop_report(total - last_drops);
                        last_drops = total;
                    }
                }
            }
        }
    }

    fn replay_spool(&self, durable: &Durable) {
        let mut spool = durable.spool.lock().unwrap_or_else(|e| e.into_inner());
        let result = spool.replay(|record| {
            if let Ok(env) = serde_json::from_slice::<EventEnvelope>(&record.payload) {
                durable
                    .high_water
                    .fetch_max(env.sequence.get(), Ordering::Relaxed);
                let _ = self.sender.send(env);
            }
        });
        match result {
            Ok(stats) if stats.records > 0 => {
                tracing::info!(
                    replayed = stats.records,
                    corrupt = stats.corrupt_segments,
                    truncated_tail = stats.truncated_tail,
                    "replayed spooled events on startup"
                );
            }
            Ok(_) => {}
            Err(error) => tracing::warn!(%error, "spool replay failed"),
        }
        let _ = spool.ack(durable.high_water.load(Ordering::Relaxed));
    }

    fn deliver_durable(&self, durable: &Durable, env: EventEnvelope) {
        let seq = env.sequence.get();
        let ts = env.observed_at.get();
        let bytes = serde_json::to_vec(&env).unwrap_or_default();
        {
            let mut spool = durable.spool.lock().unwrap_or_else(|e| e.into_inner());
            if let Err(error) = spool.append(seq, ts, &bytes) {
                tracing::warn!(%error, seq, "spool append failed");
            }
        }
        let _ = self.sender.send(env);
        durable.high_water.fetch_max(seq, Ordering::Relaxed);
    }

    fn emit_drop_report(&self, count: u64) {
        let envelope = self.build_envelope(
            &Correlation::new(),
            CaptureMethod::Internal,
            Confidence::Observed,
            EventPayload::TelemetryDropped(TelemetryDropped {
                reason: "queue-full".to_owned(),
                count,
                priority: EventPriority::Normal,
            }),
        );
        let _ = self.sender.send(envelope);
    }

    fn build_envelope(
        &self,
        correlation: &Correlation,
        capture_method: CaptureMethod,
        confidence: Confidence,
        payload: EventPayload,
    ) -> EventEnvelope {
        let sequence = Sequence(self.sequence.fetch_add(1, Ordering::Relaxed));
        EventEnvelope {
            schema_version: SCHEMA_VERSION,
            event_id: self.idgen.event_id(),
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
        let envelope = self.build_envelope(correlation, capture_method, confidence, payload);
        let event_id = envelope.event_id.clone();
        self.emitted.fetch_add(1, Ordering::Relaxed);
        match &self.delivery {
            Delivery::Direct => {
                let _ = self.sender.send(envelope);
            }
            Delivery::Durable(durable) => match durable.submit_tx.try_send(envelope) {
                Ok(()) => {}
                Err(mpsc::error::TrySendError::Full(env)) => match env.priority() {
                    EventPriority::Critical => {
                        // Never drop a critical event: spool + broadcast it inline.
                        self.deliver_durable(durable, env);
                        self.drops.spilled_critical.fetch_add(1, Ordering::Relaxed);
                    }
                    EventPriority::Normal => {
                        self.drops.normal.fetch_add(1, Ordering::Relaxed);
                    }
                    EventPriority::Low => {
                        self.drops.low.fetch_add(1, Ordering::Relaxed);
                    }
                },
                Err(mpsc::error::TrySendError::Closed(_)) => {}
            },
        }
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

    /// Total events dropped under backpressure.
    #[must_use]
    pub fn dropped(&self) -> u64 {
        self.drops.total()
    }

    /// Number of currently-attached subscribers.
    #[must_use]
    pub fn subscriber_count(&self) -> usize {
        self.sender.receiver_count()
    }

    /// Current durable-queue depth (0 for a direct bus).
    #[must_use]
    pub fn queue_depth(&self) -> u64 {
        match &self.delivery {
            Delivery::Direct => 0,
            Delivery::Durable(d) => d
                .queue_capacity
                .saturating_sub(d.submit_tx.capacity() as u64),
        }
    }

    /// Durable-queue capacity (broadcast capacity for a direct bus).
    #[must_use]
    pub fn queue_capacity(&self) -> u64 {
        match &self.delivery {
            Delivery::Direct => 0,
            Delivery::Durable(d) => d.queue_capacity,
        }
    }

    /// Bytes currently held in the durable spool (0 for a direct bus).
    #[must_use]
    pub fn spool_bytes(&self) -> u64 {
        match &self.delivery {
            Delivery::Direct => 0,
            Delivery::Durable(d) => d
                .spool
                .lock()
                .map(|s| s.total_bytes())
                .unwrap_or_else(|e| e.into_inner().total_bytes()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use sealant_eventlog::{FsyncPolicy, SpoolConfig};
    use sealant_protocol::{RuntimeHeartbeat, RuntimeState};
    use sealant_runtime_core::new_runtime_id;
    use std::path::PathBuf;

    fn heartbeat() -> EventPayload {
        EventPayload::RuntimeHeartbeat(RuntimeHeartbeat {
            state: RuntimeState::Healthy,
        })
    }

    fn open_spool(dir: PathBuf) -> Spool {
        Spool::open(SpoolConfig {
            dir,
            segment_bytes: 1 << 20,
            disk_limit_bytes: 1 << 30,
            max_payload_bytes: 1 << 20,
            fsync: FsyncPolicy::Never,
        })
        .expect("spool")
    }

    fn direct_bus() -> EventBus {
        let rt = new_runtime_id();
        let clock = Arc::new(Clock::new());
        let idgen = Arc::new(IdGenerator::new(&rt));
        EventBus::new(rt, clock, idgen, 64)
    }

    #[tokio::test]
    async fn direct_publishes_with_monotonic_sequence() {
        let bus = direct_bus();
        let mut rx = bus.subscribe();
        bus.publish(
            &Correlation::new(),
            CaptureMethod::Internal,
            Confidence::Observed,
            heartbeat(),
        );
        bus.publish(
            &Correlation::new(),
            CaptureMethod::Internal,
            Confidence::Observed,
            heartbeat(),
        );
        let a = rx.recv().await.expect("first");
        let b = rx.recv().await.expect("second");
        assert_eq!(a.sequence, Sequence(0));
        assert_eq!(b.sequence, Sequence(1));
        assert_eq!(bus.emitted(), 2);
    }

    #[tokio::test]
    async fn durable_spools_and_delivers() {
        let dir = tempfile::tempdir().expect("tmp");
        let rt = new_runtime_id();
        let clock = Arc::new(Clock::new());
        let idgen = Arc::new(IdGenerator::new(&rt));
        let bus = Arc::new(EventBus::durable(
            rt,
            clock,
            idgen,
            64,
            open_spool(dir.path().into()),
            Duration::from_millis(50),
        ));
        let mut rx = bus.subscribe();
        bus.start_delivery();

        bus.publish(
            &Correlation::new(),
            CaptureMethod::Internal,
            Confidence::Observed,
            heartbeat(),
        );
        let env = tokio::time::timeout(Duration::from_secs(2), rx.recv())
            .await
            .expect("no timeout")
            .expect("event");
        assert_eq!(env.sequence, Sequence(0));
        assert_eq!(bus.emitted(), 1);
    }

    #[tokio::test]
    async fn durable_replays_spooled_records_on_start() {
        let dir = tempfile::tempdir().expect("tmp");
        // Pre-seed the spool with one un-acked event (as if it survived a crash before delivery).
        let rt = new_runtime_id();
        let clock = Arc::new(Clock::new());
        let idgen = Arc::new(IdGenerator::new(&rt));
        let seed = EventBus::new(rt.clone(), clock.clone(), idgen.clone(), 8);
        // Build an envelope via the seed bus and write its bytes into the spool directly.
        let envelope = seed.build_envelope(
            &Correlation::new(),
            CaptureMethod::Internal,
            Confidence::Observed,
            heartbeat(),
        );
        {
            let mut spool = open_spool(dir.path().into());
            let bytes = serde_json::to_vec(&envelope).expect("ser");
            spool
                .append(envelope.sequence.get(), 0, &bytes)
                .expect("append");
            spool.flush().expect("flush");
        }

        // A fresh durable bus over the same dir should replay it on start.
        let bus = Arc::new(EventBus::durable(
            rt,
            clock,
            idgen,
            64,
            open_spool(dir.path().into()),
            Duration::from_millis(50),
        ));
        let mut rx = bus.subscribe();
        bus.start_delivery();

        let replayed = tokio::time::timeout(Duration::from_secs(2), rx.recv())
            .await
            .expect("no timeout")
            .expect("event");
        assert_eq!(replayed.sequence, envelope.sequence);
    }

    #[tokio::test]
    async fn durable_drops_low_priority_under_pressure_without_panicking() {
        let dir = tempfile::tempdir().expect("tmp");
        let rt = new_runtime_id();
        let clock = Arc::new(Clock::new());
        let idgen = Arc::new(IdGenerator::new(&rt));
        // Capacity 1 and no delivery task started -> the queue fills immediately.
        let bus = EventBus::durable(
            rt,
            clock,
            idgen,
            1,
            open_spool(dir.path().into()),
            Duration::from_millis(50),
        );
        // Heartbeats are Low priority; flooding without a consumer must drop, not block or panic.
        for _ in 0..50 {
            bus.publish(
                &Correlation::new(),
                CaptureMethod::Internal,
                Confidence::Observed,
                heartbeat(),
            );
        }
        assert!(
            bus.dropped() > 0,
            "low-priority events should be dropped under pressure"
        );
    }
}
