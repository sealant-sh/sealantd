//! A batch the collector refuses at first is sent again, not lost (SLNT-1409): on a check VM, a
//! workspace's new connections to Sentry stalled for tens of seconds at a time, and every batch
//! exported during a stall was dropped, so most of a session's daemon spans never arrived.
//!
//! Its own process (one test per file): the subscriber and the exporter are process-global.

#[allow(dead_code)]
#[path = "support/collector.rs"]
mod collector;

use std::time::{Duration, Instant};

use collector::{Collector, exported_spans};

#[test]
fn a_refused_export_is_retried_until_it_lands() {
    let collector = Collector::refusing(2);
    assert!(sealant_observability::install(
        "sealantd",
        tracing_subscriber::EnvFilter::new("off")
    ));
    let dsn = collector.dsn();
    sealant_observability::start(&sealant_observability::Config::from_lookup(|key| {
        (key == sealant_observability::SENTRY_DSN).then(|| dsn.clone())
    }));

    tracing::info_span!(
        target: "sealant_control::server",
        "sealantd.control",
        otel.name = "sealantd.control.write_stdin",
        otel.kind = "server",
        sentry.description = "write to stdin",
    )
    .in_scope(|| {});

    // The batch goes out after its 2 s delay, is refused twice, and lands on the third try.
    let deadline = Instant::now() + Duration::from_secs(20);
    let spans = loop {
        let spans = exported_spans(&collector.received());
        if !spans.is_empty() || Instant::now() > deadline {
            break spans;
        }
        std::thread::sleep(Duration::from_millis(50));
    };
    sealant_observability::shutdown();
    assert_eq!(
        collector.refused(),
        2,
        "the collector refused the first two exports"
    );
    let names: Vec<&str> = spans.iter().map(|s| s.name.as_str()).collect();
    assert_eq!(
        names,
        ["sealantd.control.write_stdin"],
        "the span still arrived"
    );
}
