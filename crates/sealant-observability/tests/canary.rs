//! Nothing secret leaves through the exporters (SLNT-1351).
//!
//! Real transports against a local stand-in for Sentry: the OTLP exporter and Sentry's ureq
//! transport send to a loopback collector, and every byte they hand it is searched for a canary.
//! The canary sits where the daemon's code could leak it: in a known secret quoted by an `error!`
//! message and its fields, in a URL's credentials and query, in a panic message, and in a log line
//! inside a traced span (log lines never become span events). The traced request and the error
//! must still arrive, linked to the caller's trace, so the test cannot pass by sending nothing.

#[allow(dead_code)]
#[path = "support/collector.rs"]
mod collector;

use std::sync::Arc;
use std::time::{Duration, Instant};

use collector::{Collector, assert_sentry_shows, contains, exported_spans};
use sealant_runtime_core::redact::Redactor;

/// A launch secret the daemon knows: masked wherever it is quoted.
const SECRET: &str = "canary-launch-secret-7f3a91";
/// In a URL's user info and in its query: removed whatever they hold.
const URL_PASSWORD: &str = "canary-url-password-1d2c";
const URL_QUERY: &str = "canary-url-query-55e0";
/// In a log line inside a span: logs never reach the OTLP exporter.
const LOGGED: &str = "canary-logged-output-90ab";

const TRACE_ID: &str = "4bf92f3577b34da6a3ce929d0e0e4736";
const TRACEPARENT: &str = "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01";

fn hex(bytes: &str) -> Vec<u8> {
    (0..bytes.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&bytes[i..i + 2], 16).expect("hex"))
        .collect()
}

#[test]
fn a_canary_never_reaches_the_exporters_and_the_trace_still_does() {
    let collector = Collector::start();
    assert!(sealant_observability::install(
        "sealantd",
        tracing_subscriber::EnvFilter::new("off")
    ));
    sealant_observability::scrub::set_redactor(Arc::new(Redactor::new(vec![SECRET.to_owned()])));
    let dsn = collector.dsn();
    sealant_observability::start(&sealant_observability::Config::from_lookup(|key| {
        (key == sealant_observability::SENTRY_DSN).then(|| dsn.clone())
    }));

    let span = tracing::info_span!(
        target: "sealant_control::server",
        "sealantd.control",
        otel.name = "sealantd.control.exec",
        otel.kind = "server",
        sentry.description = "start process",
        sealantd.method = "exec",
        sealantd.request_id = "r1",
    );
    sealant_observability::set_remote_parent(&span, TRACEPARENT, "");
    span.in_scope(|| {
        tracing::info_span!(target: "sealant_process::runtime", "sealantd.process.spawn").in_scope(
            || {
                tracing::info!(target: "sealant_process::runtime", "printed {LOGGED}");
            },
        );
        tracing::error!(
            target: "sealant_control::server",
            url = %format!("https://git:{URL_PASSWORD}@example.com/repo.git?token={URL_QUERY}"),
            "control request exec failed: {SECRET} was refused"
        );
    });
    // Ended, so it is exported.
    drop(span);
    // A panic, caught: the hook reports it before the unwind.
    let panicked = std::thread::spawn(|| panic!("panicked holding {SECRET}")).join();
    assert!(panicked.is_err());

    sealant_observability::shutdown();
    // The Sentry transport sends from its own thread; the flush waited for it, but give the
    // collector's reader a moment to finish storing.
    let deadline = Instant::now() + Duration::from_secs(5);
    let received = loop {
        let received = collector.received();
        let spans = received.iter().any(|r| r.path.contains("/otlp/v1/traces"));
        let events = received
            .iter()
            .filter(|r| r.path.contains("/envelope/"))
            .count();
        if (spans && events >= 2) || Instant::now() > deadline {
            break received;
        }
        std::thread::sleep(Duration::from_millis(50));
    };

    let traces: Vec<_> = received
        .iter()
        .filter(|r| r.path == "/api/10/integration/otlp/v1/traces")
        .collect();
    assert!(!traces.is_empty(), "no OTLP export: {received:?}");
    let otlp: Vec<u8> = traces.iter().flat_map(|r| r.body.clone()).collect();
    assert!(contains(&otlp, b"sealantd.control.exec"));
    assert!(contains(&otlp, b"sealantd.process.spawn"));
    assert!(
        contains(&otlp, &hex(TRACE_ID)),
        "the span is not in the caller's trace"
    );
    // Sentry shows each span as what it is, the spawn under the request.
    let spans = exported_spans(&received);
    assert_sentry_shows(&spans);
    let request = spans
        .iter()
        .find(|s| s.name == "sealantd.control.exec")
        .expect("the request's span");
    assert_eq!(request.attribute("sentry.op"), Some("sealantd.control"));
    assert_eq!(
        request.attribute("sentry.description"),
        Some("start process")
    );
    assert_eq!(
        request.attribute("sentry.release"),
        Some(sealant_observability::DEV_RELEASE)
    );
    assert_eq!(request.attribute("sentry.environment"), Some("development"));
    assert!(!request.failed, "the request was answered");
    assert_eq!(request.trace_id, hex(TRACE_ID));
    let spawn = spans
        .iter()
        .find(|s| s.name == "sealantd.process.spawn")
        .expect("the spawn's span");
    assert_eq!(spawn.attribute("sentry.op"), Some("sealantd.process"));
    assert_eq!(spawn.parent_span_id, request.span_id);
    for export in &traces {
        assert_eq!(
            export.header("x-sentry-auth"),
            Some("sentry sentry_key=5e5c0de5e5c0de5e5c0de5e5c0de5e5c")
        );
    }

    let envelopes: Vec<_> = received
        .iter()
        .filter(|r| r.path == "/api/10/envelope/")
        .collect();
    let sentry: Vec<u8> = envelopes.iter().flat_map(|r| r.body.clone()).collect();
    let sentry_text = String::from_utf8_lossy(&sentry);
    assert!(
        sentry_text.contains("control request exec failed"),
        "the error did not reach Sentry: {sentry_text}"
    );
    assert!(sentry_text.contains("panicked holding"), "{sentry_text}");
    assert!(
        sentry_text.contains(TRACE_ID),
        "the error is not linked to the caller's trace: {sentry_text}"
    );
    assert!(sentry_text.contains("***REDACTED***"), "{sentry_text}");

    for canary in [SECRET, URL_PASSWORD, URL_QUERY, LOGGED] {
        for request in &received {
            assert!(
                !contains(&request.body, canary.as_bytes()),
                "{canary} reached {}: {}",
                request.path,
                String::from_utf8_lossy(&request.body)
            );
            for (name, value) in &request.headers {
                assert!(!value.contains(canary), "{canary} in header {name}");
            }
        }
    }
}
