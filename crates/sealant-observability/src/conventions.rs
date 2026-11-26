//! What Sentry shows for each span.
//!
//! Sentry's OTLP ingest gives a span an operation only from a `sentry.op` attribute or a few
//! semantic ones (`http.request.method`, `db.system.name`, `rpc.service`, `messaging.system`),
//! and a description only from `sentry.description`. Without them every span reads `default`
//! with a blank description, and its release is unset unless it carries `sentry.release`. So
//! every span leaving the process passes through [`finish`], which adds the op and description
//! from the span's name and attributes, then the release, environment and [`crate::tag`]s. A
//! span that sets its own `sentry.op` or `sentry.description` keeps it.
//!
//! The operation's first segment is Sentry's span category where one fits (`rpc`, `http`,
//! `subprocess`, `file`); the daemon's own work (a boot, a microVM launch) gets a `sealantd.*`
//! op. Descriptions are fixed phrases or enums, never an argument, path or ID.

use std::borrow::Cow;

use opentelemetry::{KeyValue, Value};
use opentelemetry_sdk::trace::SpanData;

/// The attribute Sentry reads a span's operation from.
const OP: &str = "sentry.op";
/// The attribute Sentry reads a span's description from.
const DESCRIPTION: &str = "sentry.description";
const RELEASE: &str = "sentry.release";
const ENVIRONMENT: &str = "sentry.environment";

/// The attributes that put every span under the process's release and environment.
pub(crate) fn release(environment: &str, release: Option<&str>) -> Vec<KeyValue> {
    let mut common = vec![KeyValue::new(ENVIRONMENT, environment.to_owned())];
    if let Some(release) = release {
        common.push(KeyValue::new(RELEASE, release.to_owned()));
    }
    common
}

/// Give `span` what Sentry needs to show it: an op and a description, then `common` (the
/// release, environment and [`crate::tag`]s) where the span has no value of its own.
pub(crate) fn finish(span: &mut SpanData, common: &[KeyValue]) {
    stamp(&span.name, &mut span.attributes, common);
}

fn stamp(name: &str, attributes: &mut Vec<KeyValue>, common: &[KeyValue]) {
    let (op, description) = describe(name, attributes);
    if attribute(attributes, OP).is_none_or(str::is_empty) {
        attributes.retain(|attribute| attribute.key.as_str() != OP);
        attributes.push(KeyValue::new(OP, op));
    }
    if attribute(attributes, DESCRIPTION).is_none_or(str::is_empty) {
        attributes.retain(|attribute| attribute.key.as_str() != DESCRIPTION);
        attributes.push(KeyValue::new(DESCRIPTION, description));
    }
    for extra in common {
        if !attributes.iter().any(|a| a.key == extra.key) {
            attributes.push(extra.clone());
        }
    }
}

fn attribute<'a>(attributes: &'a [KeyValue], key: &str) -> Option<&'a str> {
    attributes
        .iter()
        .find(|attribute| attribute.key.as_str() == key)
        .and_then(|attribute| match &attribute.value {
            Value::String(value) => Some(value.as_str()),
            _ => None,
        })
}

fn flag(attributes: &[KeyValue], key: &str) -> bool {
    attributes
        .iter()
        .any(|attribute| attribute.key.as_str() == key && attribute.value == Value::Bool(true))
}

/// The op and description for a span named `name`.
pub(crate) fn describe(name: &str, attributes: &[KeyValue]) -> (Cow<'static, str>, String) {
    let text = |key| attribute(attributes, key);
    if let Some(method) = name.strip_prefix("sealantd.control.") {
        let description = text("rpc.method")
            .map_or_else(|| format!("sealantd.control/{method}"), ToOwned::to_owned);
        return ("rpc.server".into(), description);
    }
    if name.starts_with("sealantd.proxy.admin.") {
        let description = match (text("http.request.method"), text("http.route")) {
            (Some(method), Some(route)) => format!("{method} {route}"),
            _ => name
                .trim_start_matches("sealantd.proxy.admin.")
                .replace('.', " "),
        };
        return ("http.server".into(), description);
    }
    let fixed = |op: &'static str, description: &str| (op.into(), description.to_owned());
    match name {
        "sealantd.boot" => return fixed("sealantd.boot", "boot workspace in a container"),
        "sealantd.vm.boot" => return fixed("sealantd.boot", "boot workspace in a microVM"),
        "sealantd.vm.launch" => return fixed("sealantd.vm", "launch microVM"),
        "sealantd.process.spawn" => return fixed("subprocess.spawn", "spawn process"),
        "sealantd.process.identity" => return fixed("subprocess.identity", "resolve process user"),
        "sealantd.session.spawn" => {
            let description = match text("sealantd.session_mode") {
                Some("Pty") => "spawn PTY session",
                Some("Pipe") => "spawn pipe session",
                _ => "spawn session",
            };
            return fixed("subprocess.spawn", description);
        }
        "sealantd.session.journal" => return fixed("file.create", "create session journal"),
        "sealantd.session.subscribe" => {
            let description = if flag(attributes, "sealantd.replay") {
                "replay and attach session output"
            } else {
                "attach session output"
            };
            return fixed("subprocess.attach", description);
        }
        _ => {}
    }
    if let Some(stage) = text(crate::STAGE) {
        let op = if name.starts_with("sealantd.vm.launch.") {
            "sealantd.vm.stage"
        } else {
            "sealantd.boot.stage"
        };
        return (op.into(), stage_description(name, stage));
    }
    // A span this table does not know yet still reads as what it is: its name's area as the op
    // (`sealantd.foo.bar` is a `sealantd.foo`), its name as the description.
    let op = name
        .rsplit_once('.')
        .map_or(name, |(area, _)| area)
        .to_owned();
    (op.into(), name.to_owned())
}

/// Control methods a launcher or gateway calls to watch the daemon or to stop it: readiness polls,
/// capability probes, metrics and capture status, the lease check and the stop. Each is a span in
/// a caller's trace. Without one it starts none, or Sentry's trace list fills with them.
const HOUSEKEEPING: &[&str] = &[
    "runtime.health",
    "runtime.getCapabilities",
    "runtime.gracefulShutdown",
    "getRuntimeMetrics",
    "capture.status",
    "lease.epoch",
];

/// Whether a span named `name` may begin a trace of its own when nothing it ran under (a
/// caller's trace, a boot) is recorded. A boot may, and so may a request someone made of the
/// daemon or the egress proxy, except housekeeping ([`HOUSEKEEPING`] and the proxy's heartbeat).
/// Anything else with no parent (a spawn, a capture, work no caller started) sends nothing.
pub(crate) fn starts_trace(name: &str) -> bool {
    if let Some(method) = name.strip_prefix("sealantd.control.") {
        return !HOUSEKEEPING.contains(&method);
    }
    if let Some(route) = name.strip_prefix("sealantd.proxy.admin.") {
        return route != "heartbeat";
    }
    matches!(
        name,
        "sealantd.boot" | "sealantd.vm.boot" | "sealantd.vm.launch"
    )
}

/// What a boot stage did, in words.
fn stage_description(name: &str, stage: &str) -> String {
    let launch = name.starts_with("sealantd.vm.launch.");
    match (launch, stage) {
        (true, "setup") => "set up network and jail",
        (true, "boot_config") => "load boot config",
        (true, "vmm_started") => "start VMM",
        (false, "disk_layout") => "lay out disks",
        (false, "boot_config") => "receive boot config",
        (false, "clone") => "clone repository",
        (false, "mount") => "check mounted workspace",
        (false, "restore") => "restore capture",
        (false, "healthy") => "runtime healthy",
        (false, "control_ready") => "control server ready",
        (false, "harness_started") => "start harness",
        (_, other) => return other.replace('_', " "),
    }
    .to_owned()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn kv(key: &'static str, value: &'static str) -> KeyValue {
        KeyValue::new(key, value)
    }

    #[test]
    fn every_daemon_span_gets_an_op_and_a_description() {
        let cases: &[(&str, &[KeyValue], &str, &str)] = &[
            (
                "sealantd.control.exec",
                &[kv("rpc.method", "sealantd.control/exec")],
                "rpc.server",
                "sealantd.control/exec",
            ),
            (
                "sealantd.control.runtime.health",
                &[],
                "rpc.server",
                "sealantd.control/runtime.health",
            ),
            (
                "sealantd.proxy.admin.policy",
                &[
                    kv("http.request.method", "PUT"),
                    kv("http.route", "/v1/policy"),
                ],
                "http.server",
                "PUT /v1/policy",
            ),
            (
                "sealantd.boot",
                &[],
                "sealantd.boot",
                "boot workspace in a container",
            ),
            ("sealantd.vm.launch", &[], "sealantd.vm", "launch microVM"),
            (
                "sealantd.boot.clone",
                &[kv(crate::STAGE, "clone")],
                "sealantd.boot.stage",
                "clone repository",
            ),
            (
                "sealantd.vm.boot.boot_config",
                &[kv(crate::STAGE, "boot_config")],
                "sealantd.boot.stage",
                "receive boot config",
            ),
            (
                "sealantd.vm.launch.boot_config",
                &[kv(crate::STAGE, "boot_config")],
                "sealantd.vm.stage",
                "load boot config",
            ),
            (
                "sealantd.boot.some_new_stage",
                &[kv(crate::STAGE, "some_new_stage")],
                "sealantd.boot.stage",
                "some new stage",
            ),
            (
                "sealantd.process.spawn",
                &[],
                "subprocess.spawn",
                "spawn process",
            ),
            (
                "sealantd.session.spawn",
                &[kv("sealantd.session_mode", "Pty")],
                "subprocess.spawn",
                "spawn PTY session",
            ),
            (
                "sealantd.session.journal",
                &[],
                "file.create",
                "create session journal",
            ),
            (
                "sealantd.session.subscribe",
                &[KeyValue::new("sealantd.replay", true)],
                "subprocess.attach",
                "replay and attach session output",
            ),
            (
                "sealantd.capture.seal",
                &[],
                "sealantd.capture",
                "sealantd.capture.seal",
            ),
        ];
        for (name, attributes, op, description) in cases {
            let (got_op, got_description) = describe(name, attributes);
            assert_eq!(
                (got_op.as_ref(), got_description.as_str()),
                (*op, *description)
            );
        }
    }

    #[test]
    fn only_a_boot_or_a_request_someone_made_begins_a_trace() {
        for name in [
            "sealantd.boot",
            "sealantd.vm.boot",
            "sealantd.vm.launch",
            "sealantd.control.exec",
            "sealantd.control.openSession",
            "sealantd.control.runtime.kill",
            "sealantd.proxy.admin.policy",
        ] {
            assert!(starts_trace(name), "{name}");
        }
        for name in [
            "sealantd.control.runtime.health",
            "sealantd.control.runtime.getCapabilities",
            "sealantd.control.runtime.gracefulShutdown",
            "sealantd.control.getRuntimeMetrics",
            "sealantd.control.capture.status",
            "sealantd.control.lease.epoch",
            "sealantd.proxy.admin.heartbeat",
            "sealantd.process.spawn",
            "sealantd.session.spawn",
            "sealantd.boot.harness_started",
            "sealantd.capture.seal",
            "sealantd.control",
        ] {
            assert!(!starts_trace(name), "{name}");
        }
    }

    #[test]
    fn a_span_keeps_its_own_op_and_description_and_gets_the_release() {
        let common = release("production", Some("sealantd@1.2.3"));
        let mut own = vec![kv(OP, "queue.process"), kv(DESCRIPTION, "drain spool")];
        stamp("sealantd.spool.drain", &mut own, &common);
        assert_eq!(attribute(&own, OP), Some("queue.process"));
        assert_eq!(attribute(&own, DESCRIPTION), Some("drain spool"));
        assert_eq!(attribute(&own, RELEASE), Some("sealantd@1.2.3"));
        assert_eq!(attribute(&own, ENVIRONMENT), Some("production"));

        // An empty description is replaced, not kept beside a second one.
        let mut blank = vec![kv(DESCRIPTION, "")];
        stamp("sealantd.process.spawn", &mut blank, &[]);
        assert_eq!(attribute(&blank, OP), Some("subprocess.spawn"));
        assert_eq!(attribute(&blank, DESCRIPTION), Some("spawn process"));
        assert_eq!(
            blank
                .iter()
                .filter(|a| a.key.as_str() == DESCRIPTION)
                .count(),
            1
        );
        assert_eq!(attribute(&blank, RELEASE), None);
    }
}
