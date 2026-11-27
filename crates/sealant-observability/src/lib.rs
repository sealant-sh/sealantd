//! Logs, traces and errors for sealantd, its VM runner and the egress proxy.
//!
//! [`install`] sets the process's tracing subscriber, as early as `main` likes: it starts no
//! thread and makes no network call. Logs go to stderr under the caller's filter, as before.
//! Spans from sealant crates feed an OpenTelemetry pipeline, and `error!` events from them feed
//! Sentry, each under its own filter, so `--log-level off` silences stderr and nothing else.
//! [`start`] then turns export on for a [`Config`]: it starts the OTLP batch exporter's thread
//! and Sentry's transport thread, so a process calls it only once it may have threads (a guest
//! after it has set its environment, the runner after it has dropped privileges). Until then
//! spans are held, a bounded number; a [`Config`] that names no DSN or collector drops them and
//! builds nothing. [`shutdown`] sends what is queued, within about two seconds.
//!
//! Only spans reach the OTLP exporter, never log events, and a span carries the fields its code
//! names: ids and enums, never arguments, environment or output. Sentry events are scrubbed
//! ([`scrub`]) and linked to the trace of the span they happened in.
#![cfg_attr(not(test), deny(clippy::unwrap_used, clippy::expect_used))]
#![forbid(unsafe_code)]

mod boot;
mod config;
mod conventions;
mod http;
mod pipeline;
pub mod scrub;

use std::collections::HashMap;
use std::sync::{Arc, Mutex, OnceLock, PoisonError};
use std::time::Duration;

use opentelemetry::propagation::TextMapPropagator as _;
use opentelemetry::trace::{TraceContextExt as _, TracerProvider as _};
use opentelemetry::{Context, KeyValue};
use opentelemetry_otlp::{WithExportConfig as _, WithHttpConfig as _};
use opentelemetry_sdk::Resource;
use opentelemetry_sdk::propagation::TraceContextPropagator;
use opentelemetry_sdk::trace::{BatchConfigBuilder, BatchSpanProcessor, SdkTracerProvider};
use tracing_opentelemetry::OpenTelemetrySpanExt as _;
use tracing_subscriber::filter::{EnvFilter, filter_fn};
use tracing_subscriber::layer::SubscriberExt as _;
use tracing_subscriber::util::SubscriberInitExt as _;
use tracing_subscriber::{Layer as _, Registry};

pub use boot::{BootTrace, STAGE};
pub use config::{
    Config, DEV_RELEASE, OTEL_EXPORTER_OTLP_ENDPOINT, OTEL_EXPORTER_OTLP_HEADERS, SENTRY_DSN,
    SENTRY_ENVIRONMENT, SENTRY_RELEASE, SENTRY_TRACES_SAMPLE_RATE, VARIABLES,
};
pub use conventions::{CONTAINER_BOOT, GUEST_BOOT, VM_LAUNCH};

/// How long [`shutdown`] gives queued spans, then queued Sentry events.
const FLUSH_SPANS: Duration = Duration::from_millis(1500);
const FLUSH_EVENTS: Duration = Duration::from_millis(500);
/// The W3C limits: a traceparent is 55 bytes; a tracestate at most 32 members of 256.
const MAX_TRACEPARENT: usize = 64;
const MAX_TRACESTATE: usize = 512;

struct State {
    service: &'static str,
    started: std::sync::atomic::AtomicBool,
    shared: Arc<pipeline::Shared>,
    provider: SdkTracerProvider,
    sentry: Mutex<Option<sentry::ClientInitGuard>>,
}

static STATE: OnceLock<State> = OnceLock::new();

/// Whether a callsite is ours: the OTLP and Sentry layers see sealant crates only, so a
/// dependency's spans and errors (and the exporter's own HTTP client) never reach them.
fn ours(metadata: &tracing::Metadata<'_>) -> bool {
    metadata.target().starts_with("sealant")
}

/// Set this process's subscriber: `log_filter` decides what reaches stderr, as it always has;
/// spans and errors are held for export until [`start`]. Returns false, and installs nothing,
/// when the process already has a subscriber (an embedding caller's wins).
pub fn install(service: &'static str, log_filter: EnvFilter) -> bool {
    let shared = pipeline::Shared::new();
    let provider = SdkTracerProvider::builder()
        .with_span_processor(pipeline::Deferred(shared.clone()))
        .with_sampler(pipeline::Sampler(shared.clone()))
        .with_resource(Resource::builder_empty().with_service_name(service).build())
        .build();
    let tracer = provider.tracer(service);
    let spans = tracing_opentelemetry::layer()
        .with_tracer(tracer)
        .with_location(false)
        .with_threads(false)
        .with_level(false)
        .with_target(false)
        .with_tracked_inactivity(false)
        .with_filter(filter_fn(|m| m.is_span() && ours(m)));
    let errors = sentry::integrations::tracing::ErrorLayer::new().with_filter(filter_fn(|m| {
        m.is_event() && *m.level() == tracing::Level::ERROR && ours(m)
    }));
    // Diagnostics go to stderr: stdout is the protocol in stdio mode.
    let logs = tracing_subscriber::fmt::layer()
        .with_writer(std::io::stderr)
        .with_filter(log_filter);
    let installed = Registry::default()
        .with(logs)
        .with(spans)
        .with(errors)
        .try_init()
        .is_ok();
    if installed {
        let _ = STATE.set(State {
            service,
            started: std::sync::atomic::AtomicBool::new(false),
            shared,
            provider,
            sentry: Mutex::new(None),
        });
    }
    installed
}

/// Turn export on as `config` says, starting the exporter's and Sentry's threads; or, when it
/// names nothing to export to, drop the held spans and record no more. Call it from a thread
/// that may start threads. Only the first call counts; a no-op without [`install`].
pub fn start(config: &Config) {
    let Some(state) = STATE.get() else { return };
    if state
        .started
        .swap(true, std::sync::atomic::Ordering::SeqCst)
    {
        return;
    }
    // Every span and event names a release: the configured one, or a development build's.
    let release = config.release.as_deref().unwrap_or(DEV_RELEASE);
    match &config.traces {
        Some(target) => match exporter(target) {
            Ok(exporter) => {
                let batch = BatchSpanProcessor::builder(exporter)
                    .with_batch_config(
                        BatchConfigBuilder::default()
                            .with_max_queue_size(2048)
                            .with_scheduled_delay(Duration::from_secs(2))
                            .build(),
                    )
                    .build();
                let extra = vec![
                    KeyValue::new("deployment.environment.name", config.environment.clone()),
                    KeyValue::new("service.version", release.to_owned()),
                ];
                let common = conventions::release(&config.environment, release);
                state.shared.run(batch, extra, common, config.sample_rate);
            }
            Err(error) => {
                tracing::warn!(%error, "the trace exporter could not be built: no traces are sent");
                state.shared.off();
            }
        },
        None => state.shared.off(),
    }
    if let Some(dsn) = &config.sentry {
        let mut options = sentry::ClientOptions::default();
        options.dsn = Some(dsn.clone());
        // Always set: left unset, the SDK would take the image's `SENTRY_RELEASE`.
        options.release = Some(release.to_owned().into());
        options.environment = Some(config.environment.clone().into());
        options.send_default_pii = false;
        options.max_breadcrumbs = 0;
        options.server_name = None;
        options.auto_session_tracking = false;
        options.shutdown_timeout = FLUSH_EVENTS;
        // Errors only: traces go through OpenTelemetry (the default strategy samples none).
        options.before_send = Some(Arc::new(|event| {
            Some(link_trace(scrub::scrub_event(event)))
        }));
        options.before_breadcrumb = Some(Arc::new(|_| None));
        let guard = sentry::init(options);
        *state.sentry.lock().unwrap_or_else(PoisonError::into_inner) = Some(guard);
    }
    tracing::debug!(
        service = state.service,
        traces = config.sends_traces(),
        errors = config.sends_errors(),
        "telemetry started"
    );
}

fn exporter(
    target: &config::TracesTarget,
) -> Result<opentelemetry_otlp::SpanExporter, opentelemetry_otlp::ExporterBuildError> {
    opentelemetry_otlp::SpanExporter::builder()
        .with_http()
        .with_http_client(http::UreqClient::new(&target.headers))
        .with_endpoint(target.url.clone())
        .with_headers(target.headers.iter().cloned().collect::<HashMap<_, _>>())
        .with_timeout(Duration::from_secs(5))
        .with_retry_policy(opentelemetry_otlp::RetryPolicy::disabled())
        .build()
}

/// Set `key` on every span this process exports from now on: an ID that holds for the process's
/// life, such as `sealant.runtime_id`. A no-op without [`install`].
pub fn tag(key: &'static str, value: impl Into<String>) {
    if let Some(state) = STATE.get() {
        state.shared.tag(KeyValue::new(key, value.into()));
    }
}

/// Send what is queued (spans, then Sentry events) and stop, in about two seconds at most.
pub fn shutdown() {
    let Some(state) = STATE.get() else { return };
    let _ = state.provider.shutdown_with_timeout(FLUSH_SPANS);
    if let Some(guard) = state
        .sentry
        .lock()
        .unwrap_or_else(PoisonError::into_inner)
        .take()
    {
        guard.flush(Some(FLUSH_EVENTS));
        drop(guard);
    }
}

/// The open boot's span ([`BootTrace`]): an error outside any span while the process boots
/// belongs to the boot's trace.
static BOOTING: std::sync::RwLock<Option<opentelemetry::trace::SpanContext>> =
    std::sync::RwLock::new(None);

/// Link an event to the trace it happened in: its span's, or the boot's while one is open.
fn link_trace(mut event: sentry::protocol::Event<'static>) -> sentry::protocol::Event<'static> {
    let context = tracing::Span::current().context();
    let current = context.span().span_context().clone();
    let span = if current.is_valid() {
        Some(current)
    } else {
        BOOTING
            .read()
            .unwrap_or_else(PoisonError::into_inner)
            .clone()
    };
    // A span the sampler dropped has a valid context but no trace in Sentry to link to.
    if let Some(span) = span.filter(|span| span.is_valid() && span.is_sampled()) {
        event.contexts.insert(
            "trace".to_owned(),
            sentry::protocol::Context::Trace(Box::new(sentry::protocol::TraceContext {
                trace_id: span.trace_id().to_bytes().into(),
                span_id: span.span_id().to_bytes().into(),
                ..Default::default()
            })),
        );
    }
    event
}

/// The OpenTelemetry context a W3C `traceparent` (and `tracestate`) names, or None when it is
/// not one. Over-long values are refused, not parsed.
#[must_use]
pub fn remote_context(traceparent: &str, tracestate: &str) -> Option<Context> {
    if traceparent.len() > MAX_TRACEPARENT {
        return None;
    }
    let mut carrier = HashMap::from([("traceparent".to_owned(), traceparent.to_owned())]);
    if !tracestate.is_empty() && tracestate.len() <= MAX_TRACESTATE {
        carrier.insert("tracestate".to_owned(), tracestate.to_owned());
    }
    let context = TraceContextPropagator::new().extract(&carrier);
    context.span().span_context().is_valid().then_some(context)
}

/// Make `span` a child of the caller's trace, when `traceparent` names one. Call before the span
/// is first entered; a malformed context leaves it a trace of its own.
pub fn set_remote_parent(span: &tracing::Span, traceparent: &str, tracestate: &str) {
    if let Some(context) = remote_context(traceparent, tracestate) {
        let _ = span.set_parent(context);
    }
}

/// The current span as a W3C `(traceparent, tracestate)`, to hand to another process; None
/// outside a recorded span.
#[must_use]
pub fn current_traceparent() -> Option<(String, String)> {
    traceparent_of(&tracing::Span::current().context())
}

fn traceparent_of(context: &Context) -> Option<(String, String)> {
    if !context.span().span_context().is_valid() {
        return None;
    }
    let mut carrier = HashMap::new();
    TraceContextPropagator::new().inject_context(context, &mut carrier);
    let traceparent = carrier.remove("traceparent")?;
    Some((
        traceparent,
        carrier.remove("tracestate").unwrap_or_default(),
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_traceparent_parses_and_garbage_does_not() {
        let cx = remote_context(
            "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01",
            "congo=t61rcWkgMzE",
        )
        .expect("valid");
        let span = cx.span();
        let span = span.span_context();
        assert_eq!(
            span.trace_id().to_string(),
            "4bf92f3577b34da6a3ce929d0e0e4736"
        );
        assert!(span.is_sampled() && span.is_remote());
        assert_eq!(span.trace_state().header(), "congo=t61rcWkgMzE");

        for bad in [
            "",
            "garbage",
            "00-00000000000000000000000000000000-00f067aa0ba902b7-01",
            "00-4bf92f3577b34da6a3ce929d0e0e4736-0000000000000000-01",
            &"0".repeat(200),
        ] {
            assert!(remote_context(bad, "").is_none(), "{bad}");
        }
        // An over-long tracestate is dropped, the parent kept.
        let cx = remote_context(
            "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01",
            &"a=b,".repeat(200),
        )
        .expect("valid");
        assert_eq!(cx.span().span_context().trace_state().header(), "");
    }
}
