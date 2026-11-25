//! A boot's trace: one root span from the process's start to the end of its boot, a child of the
//! launcher's span, with a child span per stage.
//!
//! Some stages end before the trace can begin (a microVM guest lays out its disks before the
//! boot config that names its parent arrives), so a stage is recorded with the times it ran
//! ([`BootTrace::stage`]). The others are measured from the boot's start ([`BootTrace::reached`]),
//! or are ordinary spans made children of the boot ([`BootTrace::adopt`]). Every stage span
//! carries `sealant.boot.stage`.

use std::borrow::Cow;
use std::sync::Mutex;
use std::sync::PoisonError;
use std::time::SystemTime;

use opentelemetry::trace::{
    Span as _, SpanKind, Status, TraceContextExt as _, Tracer as _, TracerProvider as _,
};
use opentelemetry::{Context, KeyValue};
use opentelemetry_sdk::trace::SdkTracer;
use tracing_opentelemetry::OpenTelemetrySpanExt as _;

/// The attribute every stage span carries.
pub const STAGE: &str = "sealant.boot.stage";

/// One boot's trace. Ends when [`BootTrace::end`] is called, or when it is dropped.
#[derive(Debug)]
pub struct BootTrace {
    name: &'static str,
    started: SystemTime,
    tracer: SdkTracer,
    /// The root span, until it ends.
    cx: Context,
    ended: Mutex<bool>,
}

impl BootTrace {
    /// Begin `name` (`sealantd.vm.boot`), as started at `started`, as a child of the launcher's
    /// `traceparent` when it names a span. None before [`crate::install`].
    #[must_use]
    pub fn begin(
        name: &'static str,
        started: SystemTime,
        traceparent: Option<(&str, &str)>,
    ) -> Option<Self> {
        let state = crate::STATE.get()?;
        let tracer = state.provider.tracer(state.service);
        let parent = traceparent
            .and_then(|(parent, state)| crate::remote_context(parent, state))
            .unwrap_or_default();
        let span = tracer
            .span_builder(name)
            .with_kind(SpanKind::Internal)
            .with_start_time(started)
            .start_with_context(&tracer, &parent);
        let cx = parent.with_span(span);
        *crate::BOOTING
            .write()
            .unwrap_or_else(PoisonError::into_inner) = Some(cx.span().span_context().clone());
        Some(Self {
            name,
            started,
            tracer,
            cx,
            ended: Mutex::new(false),
        })
    }

    fn stage_span(&self, stage: &'static str, start: SystemTime) -> opentelemetry_sdk::trace::Span {
        self.tracer
            .span_builder(Cow::Owned(format!("{}.{stage}", self.name)))
            .with_kind(SpanKind::Internal)
            .with_start_time(start)
            .with_attributes([KeyValue::new(STAGE, stage)])
            .start_with_context(&self.tracer, &self.cx)
    }

    /// A stage that ran from `start` to `end`, before the trace could begin or off its thread.
    pub fn stage(&self, stage: &'static str, start: SystemTime, end: SystemTime) {
        self.stage_span(stage, start).end_with_timestamp(end);
    }

    /// The boot reached `stage` now: a span from the boot's start to now.
    pub fn reached(&self, stage: &'static str) {
        self.stage_span(stage, self.started).end();
    }

    /// Make `span` (not yet entered) a stage of this boot.
    pub fn adopt(&self, span: &tracing::Span) {
        let _ = span.set_parent(self.cx.clone());
    }

    /// The boot's span as a W3C `(traceparent, tracestate)`, for a process it starts; None when
    /// the boot is not recorded.
    #[must_use]
    pub fn traceparent(&self) -> Option<(String, String)> {
        crate::traceparent_of(&self.cx)
    }

    /// End the boot: `ok` false marks it failed. Only the first call counts.
    pub fn end(&self, ok: bool) {
        let mut ended = self.ended.lock().unwrap_or_else(PoisonError::into_inner);
        if *ended {
            return;
        }
        *ended = true;
        *crate::BOOTING
            .write()
            .unwrap_or_else(PoisonError::into_inner) = None;
        let span = self.cx.span();
        if !ok {
            span.set_status(Status::error("boot failed"));
        }
        span.end();
    }
}

impl Drop for BootTrace {
    fn drop(&mut self) {
        self.end(true);
    }
}
