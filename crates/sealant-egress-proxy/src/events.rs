//! Structured egress telemetry, streamed as NDJSON from `GET /v1/events`.
//!
//! Events name hosts, methods, statuses and brokered secret IDs. They never carry a secret value,
//! a header value or a query string.

use std::collections::VecDeque;
use std::sync::Mutex;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

use serde::Serialize;
use tokio::sync::broadcast;

const BACKLOG: usize = 1024;

#[derive(Clone, Debug, Default, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Event {
    pub seq: u64,
    pub ts_ms: u64,
    pub kind: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ingress: Option<&'static str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub host: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub port: Option<u16>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ip: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub method: Option<String>,
    /// The request path without its query string.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub path: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub status: Option<u16>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub secret_ids: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub qtype: Option<u16>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub closed: Option<usize>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub policy_hash: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub revocation_watermark: Option<u64>,
}

impl Event {
    pub(crate) fn new(kind: &'static str) -> Self {
        Self {
            kind,
            ..Self::default()
        }
    }
}

/// A line of NDJSON with its sequence number.
#[derive(Clone, Debug)]
pub(crate) struct Line {
    pub(crate) seq: u64,
    pub(crate) text: std::sync::Arc<str>,
}

pub(crate) struct EventHub {
    seq: AtomicU64,
    backlog: Mutex<VecDeque<Line>>,
    live: broadcast::Sender<Line>,
}

impl EventHub {
    pub(crate) fn new() -> Self {
        let (live, _) = broadcast::channel(BACKLOG);
        Self {
            seq: AtomicU64::new(0),
            backlog: Mutex::new(VecDeque::with_capacity(BACKLOG)),
            live,
        }
    }

    pub(crate) fn emit(&self, mut event: Event) {
        event.seq = self.seq.fetch_add(1, Ordering::Relaxed) + 1;
        event.ts_ms = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| u64::try_from(d.as_millis()).unwrap_or(u64::MAX))
            .unwrap_or(0);
        let Ok(json) = serde_json::to_string(&event) else {
            return;
        };
        tracing::info!(target: "sealant_egress_proxy::events", "{json}");
        let line = Line {
            seq: event.seq,
            text: json.into(),
        };
        if let Ok(mut backlog) = self.backlog.lock() {
            if backlog.len() == BACKLOG {
                backlog.pop_front();
            }
            backlog.push_back(line.clone());
        }
        let _ = self.live.send(line);
    }

    /// The live receiver and the backlog, taken in that order so no event falls between them.
    pub(crate) fn subscribe(&self) -> (broadcast::Receiver<Line>, Vec<Line>) {
        let live = self.live.subscribe();
        let backlog = self
            .backlog
            .lock()
            .map(|b| b.iter().cloned().collect())
            .unwrap_or_default();
        (live, backlog)
    }
}
