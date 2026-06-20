//! Telemetry event bus.
//!
//! Producers publish typed payloads with correlation; the bus assigns the final `sequence`,
//! `eventId`, and timestamps at a single deterministic point (plan §15) and fans the resulting
//! [`sealant_protocol::EventEnvelope`] out to all subscribers over a bounded broadcast channel.
//!
//! The durable spool, batching, retry, and priority-aware backpressure land in a later phase; for
//! now the broadcast channel is the delivery sink to connected control clients.
#![cfg_attr(not(test), deny(clippy::unwrap_used, clippy::expect_used))]
#![forbid(unsafe_code)]

pub mod bus;

pub use bus::{Correlation, EventBus};
