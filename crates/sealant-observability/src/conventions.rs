//! What Sentry shows for each span, and what each span is called.
//!
//! Sentry's OTLP ingest gives a span an operation only from a `sentry.op` attribute or a few
//! semantic ones (`http.request.method`, `db.system.name`, `rpc.service`, `messaging.system`),
//! and a description only from `sentry.description`. Without them every span reads `default`
//! with a blank description, and its release is unset unless it carries `sentry.release`. So
//! every span leaving the process passes through [`finish`], which adds the op and description
//! from the span's name and attributes, then the release, environment and [`crate::tag`]s. A
//! span that sets its own `sentry.op` or `sentry.description` keeps it (a control request names
//! its method's description itself: `sealant_protocol::Method`).
//!
//! The naming contract, shared with sealant and Mend: a span is `sealantd.<area>.<operation>` in
//! lower snake case, its op is `sealantd.<area>`, and its description is a short lower-case phrase
//! of its own ("write to stdin", "clone repository"). The egress proxy's admin API is the one
//! exception: an HTTP server span is named `<METHOD> <route>`, with the op `http.server`.
//! Descriptions are fixed phrases or enums, never an argument, path or ID.

use std::borrow::Cow;

use opentelemetry::{KeyValue, Value};
use opentelemetry_sdk::trace::SpanData;

/// The attribute Sentry reads a span's operation from.
const OP: &str = "sentry.op";
/// The attribute Sentry reads a span's description from.
const DESCRIPTION: &str = "sentry.description";
const RELEASE: &str = "sentry.release";
const ENVIRONMENT: &str = "sentry.environment";

/// A container workspace's boot: `sealantd boot`, from the process's start to its harness.
pub const CONTAINER_BOOT: &str = "sealantd.workspace.boot";
/// A microVM guest's boot, inside the VM.
pub const GUEST_BOOT: &str = "sealantd.vm.boot";
/// The VM runner's launch of a microVM, on the host.
pub const VM_LAUNCH: &str = "sealantd.vm.launch";

/// The span of each boot stage: `(stage, span name, description)`. A stage key is what the boot
/// code reports (`sealant.boot.stage`); a launch's stages are the runner's, the rest a boot's.
const BOOT_STAGES: &[(&str, &str, &str)] = &[
    (
        "disk_layout",
        "sealantd.boot.lay_out_disks",
        "lay out disks",
    ),
    (
        "boot_config",
        "sealantd.boot.receive_config",
        "receive boot config",
    ),
    (
        "clone",
        "sealantd.boot.clone_repository",
        "clone repository",
    ),
    (
        "mount",
        "sealantd.boot.check_mount",
        "check mounted workspace",
    ),
    (
        "restore",
        "sealantd.boot.restore_capture",
        "restore capture",
    ),
    ("healthy", "sealantd.boot.start_runtime", "start runtime"),
    (
        "control_ready",
        "sealantd.boot.start_control_server",
        "start control server",
    ),
    (
        "harness_started",
        "sealantd.boot.start_harness",
        "start harness",
    ),
];
const LAUNCH_STAGES: &[(&str, &str, &str)] = &[
    (
        "setup",
        "sealantd.vm.set_up_jail",
        "set up network and jail",
    ),
    ("boot_config", "sealantd.vm.load_config", "load boot config"),
    ("vmm_started", "sealantd.vm.start_vmm", "start VMM"),
];

/// Every other span's description, by name.
const DESCRIPTIONS: &[(&str, &str)] = &[
    (CONTAINER_BOOT, "boot workspace in a container"),
    (GUEST_BOOT, "boot workspace in a microVM"),
    (VM_LAUNCH, "launch microVM"),
    ("sealantd.process.spawn", "spawn child process"),
    ("sealantd.process.resolve_user", "resolve process user"),
    ("sealantd.session.create_journal", "create session journal"),
    ("PUT /v1/policy", "replace egress policy"),
    ("POST /v1/revoke", "revoke egress grants"),
    ("POST /v1/heartbeat", "renew policy lease"),
];

fn stages(root: &str) -> &'static [(&'static str, &'static str, &'static str)] {
    if root == VM_LAUNCH {
        LAUNCH_STAGES
    } else {
        BOOT_STAGES
    }
}

/// The span name of `stage` under the boot or launch `root`: `sealantd.boot.clone_repository`.
/// A stage the table does not know yet is `sealantd.boot.<stage>`.
pub(crate) fn stage_name(root: &str, stage: &str) -> Cow<'static, str> {
    stages(root)
        .iter()
        .find(|(key, _, _)| *key == stage)
        .map_or_else(
            || {
                let area = if root == VM_LAUNCH { "vm" } else { "boot" };
                Cow::Owned(format!("sealantd.{area}.{stage}"))
            },
            |(_, name, _)| Cow::Borrowed(*name),
        )
}

/// The attributes that put every span under the process's release and environment.
pub(crate) fn release(environment: &str, release: &str) -> Vec<KeyValue> {
    vec![
        KeyValue::new(ENVIRONMENT, environment.to_owned()),
        KeyValue::new(RELEASE, release.to_owned()),
    ]
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

/// Every name with a fixed description, and that description.
fn named() -> impl Iterator<Item = (&'static str, &'static str)> {
    DESCRIPTIONS.iter().copied().chain(
        BOOT_STAGES
            .iter()
            .chain(LAUNCH_STAGES)
            .map(|&(_, name, description)| (name, description)),
    )
}

/// The op and description for a span named `name`.
pub(crate) fn describe(name: &str, attributes: &[KeyValue]) -> (Cow<'static, str>, String) {
    let text = |key| attribute(attributes, key);
    let fixed = named()
        .find(|(known, _)| *known == name)
        .map(|(_, description)| description.to_owned());
    if text("http.request.method").is_some() && text("http.route").is_some() {
        return (
            "http.server".into(),
            fixed.unwrap_or_else(|| name.to_owned()),
        );
    }
    let description = fixed.unwrap_or_else(|| {
        let phrase = match name {
            "sealantd.session.spawn" => match text("sealantd.session_mode") {
                Some("Pty") => "spawn PTY session",
                Some("Pipe") => "spawn pipe session",
                _ => "spawn session",
            },
            "sealantd.session.stream_output" if flag(attributes, "sealantd.replay") => {
                "replay and stream session output"
            }
            "sealantd.session.stream_output" => "stream session output",
            // A stage the table does not know yet reads as its stage.
            _ if text(crate::STAGE).is_some() => {
                return text(crate::STAGE).unwrap_or_default().replace('_', " ");
            }
            // Any other span this table does not know yet still reads as what it did: its
            // operation, then its area (`sealantd.capture.seal` is "seal capture").
            _ => return fallback_description(name),
        };
        phrase.to_owned()
    });
    (area(name).to_owned().into(), description)
}

/// `sealantd.<area>`: the name without its operation.
fn area(name: &str) -> &str {
    name.rsplit_once('.').map_or(name, |(area, _)| area)
}

fn fallback_description(name: &str) -> String {
    let (area, operation) = name.rsplit_once('.').unwrap_or(("", name));
    let noun = area.rsplit_once('.').map_or(area, |(_, noun)| noun);
    let words = operation.replace('_', " ");
    if noun.is_empty() || noun == "sealantd" {
        words
    } else {
        format!("{words} {noun}")
    }
}

/// Control methods a launcher or gateway calls to watch the daemon or to stop it: readiness polls,
/// capability probes, metrics and capture status, the lease check and the stop. Each is a span in
/// a caller's trace. Without one it starts none, or Sentry's trace list fills with them.
const HOUSEKEEPING: &[&str] = &[
    "runtime_health",
    "runtime_get_capabilities",
    "runtime_graceful_shutdown",
    "get_runtime_metrics",
    "capture_status",
    "lease_epoch",
];

/// Whether a span named `name` may begin a trace of its own when nothing it ran under (a
/// caller's trace, a boot) is recorded. A boot may, and so may a request someone made of the
/// daemon or the egress proxy, except housekeeping ([`HOUSEKEEPING`] and the proxy's heartbeat).
/// Anything else with no parent (a spawn, a capture, work no caller started) sends nothing.
pub(crate) fn starts_trace(name: &str) -> bool {
    if let Some(operation) = name.strip_prefix("sealantd.control.") {
        return !HOUSEKEEPING.contains(&operation);
    }
    matches!(
        name,
        CONTAINER_BOOT | GUEST_BOOT | VM_LAUNCH | "PUT /v1/policy" | "POST /v1/revoke"
    )
}

#[cfg(test)]
mod tests {
    use std::collections::HashSet;

    use super::*;

    fn kv(key: &'static str, value: &'static str) -> KeyValue {
        KeyValue::new(key, value)
    }

    #[test]
    fn every_daemon_span_gets_an_op_and_a_description() {
        let cases: &[(&str, &[KeyValue], &str, &str)] = &[
            (
                "sealantd.control.write_stdin",
                &[kv("rpc.method", "writeStdin")],
                "sealantd.control",
                "write stdin control",
            ),
            (
                "PUT /v1/policy",
                &[
                    kv("http.request.method", "PUT"),
                    kv("http.route", "/v1/policy"),
                ],
                "http.server",
                "replace egress policy",
            ),
            (
                CONTAINER_BOOT,
                &[],
                "sealantd.workspace",
                "boot workspace in a container",
            ),
            (
                GUEST_BOOT,
                &[],
                "sealantd.vm",
                "boot workspace in a microVM",
            ),
            (VM_LAUNCH, &[], "sealantd.vm", "launch microVM"),
            (
                "sealantd.boot.clone_repository",
                &[kv(crate::STAGE, "clone")],
                "sealantd.boot",
                "clone repository",
            ),
            (
                "sealantd.boot.receive_config",
                &[kv(crate::STAGE, "boot_config")],
                "sealantd.boot",
                "receive boot config",
            ),
            (
                "sealantd.vm.load_config",
                &[kv(crate::STAGE, "boot_config")],
                "sealantd.vm",
                "load boot config",
            ),
            (
                "sealantd.boot.some_new_stage",
                &[kv(crate::STAGE, "some_new_stage")],
                "sealantd.boot",
                "some new stage",
            ),
            (
                "sealantd.process.spawn",
                &[],
                "sealantd.process",
                "spawn child process",
            ),
            (
                "sealantd.session.spawn",
                &[kv("sealantd.session_mode", "Pty")],
                "sealantd.session",
                "spawn PTY session",
            ),
            (
                "sealantd.session.create_journal",
                &[],
                "sealantd.session",
                "create session journal",
            ),
            (
                "sealantd.session.stream_output",
                &[KeyValue::new("sealantd.replay", true)],
                "sealantd.session",
                "replay and stream session output",
            ),
            (
                "sealantd.capture.seal",
                &[],
                "sealantd.capture",
                "seal capture",
            ),
        ];
        for (name, attributes, op, description) in cases {
            let (got_op, got_description) = describe(name, attributes);
            assert_eq!(
                (got_op.as_ref(), got_description.as_str()),
                (*op, *description),
                "{name}"
            );
        }
    }

    /// The contract: `sealantd.<area>.<operation>` in lower snake case, each with a description of
    /// its own, two to five words.
    #[test]
    fn every_known_name_follows_the_contract() {
        let mut names = HashSet::new();
        let mut descriptions = HashSet::new();
        for (name, description) in named() {
            assert!(names.insert(name), "{name} twice");
            assert!(descriptions.insert(description), "{description} twice");
            assert!(
                (2..=5).contains(&description.split(' ').count()),
                "{description}"
            );
            assert!(
                description.starts_with(|c: char| c.is_ascii_lowercase()),
                "{description}"
            );
            if name.contains(' ') {
                continue; // an HTTP route
            }
            let parts: Vec<&str> = name.split('.').collect();
            assert_eq!(parts.len(), 3, "{name}");
            assert_eq!(parts[0], "sealantd", "{name}");
            for part in parts {
                assert!(
                    part.chars().all(|c| c.is_ascii_lowercase() || c == '_'),
                    "{name}"
                );
            }
        }
    }

    #[test]
    fn a_stage_is_named_for_what_it_does() {
        assert_eq!(
            stage_name(CONTAINER_BOOT, "clone"),
            "sealantd.boot.clone_repository"
        );
        assert_eq!(
            stage_name(GUEST_BOOT, "boot_config"),
            "sealantd.boot.receive_config"
        );
        assert_eq!(
            stage_name(VM_LAUNCH, "boot_config"),
            "sealantd.vm.load_config"
        );
        assert_eq!(
            stage_name(VM_LAUNCH, "vmm_started"),
            "sealantd.vm.start_vmm"
        );
        assert_eq!(stage_name(CONTAINER_BOOT, "later"), "sealantd.boot.later");
    }

    #[test]
    fn only_a_boot_or_a_request_someone_made_begins_a_trace() {
        for name in [
            CONTAINER_BOOT,
            GUEST_BOOT,
            VM_LAUNCH,
            "sealantd.control.exec",
            "sealantd.control.open_session",
            "sealantd.control.runtime_kill",
            "PUT /v1/policy",
        ] {
            assert!(starts_trace(name), "{name}");
        }
        for name in [
            "sealantd.control.runtime_health",
            "sealantd.control.runtime_get_capabilities",
            "sealantd.control.runtime_graceful_shutdown",
            "sealantd.control.get_runtime_metrics",
            "sealantd.control.capture_status",
            "sealantd.control.lease_epoch",
            "POST /v1/heartbeat",
            "sealantd.process.spawn",
            "sealantd.session.spawn",
            "sealantd.boot.start_harness",
            "sealantd.capture.seal",
            "sealantd.control",
        ] {
            assert!(!starts_trace(name), "{name}");
        }
    }

    #[test]
    fn a_span_keeps_its_own_op_and_description_and_gets_the_release() {
        let common = release("production", "sealantd@1.2.3");
        let mut own = vec![kv(OP, "queue.process"), kv(DESCRIPTION, "drain spool")];
        stamp("sealantd.spool.drain", &mut own, &common);
        assert_eq!(attribute(&own, OP), Some("queue.process"));
        assert_eq!(attribute(&own, DESCRIPTION), Some("drain spool"));
        assert_eq!(attribute(&own, RELEASE), Some("sealantd@1.2.3"));
        assert_eq!(attribute(&own, ENVIRONMENT), Some("production"));

        // A control request's own description stays, under the control op.
        let mut control = vec![kv(DESCRIPTION, "write to stdin")];
        stamp("sealantd.control.write_stdin", &mut control, &common);
        assert_eq!(attribute(&control, OP), Some("sealantd.control"));
        assert_eq!(attribute(&control, DESCRIPTION), Some("write to stdin"));

        // An empty description is replaced, not kept beside a second one.
        let mut blank = vec![kv(DESCRIPTION, "")];
        stamp("sealantd.process.spawn", &mut blank, &[]);
        assert_eq!(attribute(&blank, OP), Some("sealantd.process"));
        assert_eq!(attribute(&blank, DESCRIPTION), Some("spawn child process"));
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
