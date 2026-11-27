//! The daemon's logs, traces and errors ([`sealant_observability`]).
//!
//! The daemon runs inside a workspace, whose image may set `SENTRY_DSN` for its own code, so it
//! reads its telemetry settings under [`PREFIX`]: `SEALANT_SENTRY_DSN` and the rest. Boot
//! consumes them, so they never reach the harness. None set: nothing is exported.

use std::sync::OnceLock;
use std::time::SystemTime;

use sealant_observability::{BootTrace, Config};

/// The prefix of every telemetry variable the daemon reads.
pub const PREFIX: &str = "SEALANT_";

/// The release a build reports when `SEALANT_SENTRY_RELEASE` is unset: `SENTRY_RELEASE` at build
/// time (`sealantd@<version>`), or none.
pub const RELEASE: Option<&str> = option_env!("SENTRY_RELEASE");

/// Set the subscriber: `log_level` filters stderr only. Starts no thread.
pub(crate) fn install(log_level: &str) {
    let filter = tracing_subscriber::EnvFilter::try_new(log_level)
        .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info"));
    sealant_observability::install("sealantd", filter);
}

/// Start exporting as this process's environment says (only the first call counts). Starts
/// threads. What is queued is sent when the guard drops, within about two seconds.
#[must_use = "dropping the guard sends what is queued and stops export"]
pub(crate) fn start() -> Guard {
    sealant_observability::start(&Config::from_prefixed_env(PREFIX).with_default_release(RELEASE));
    Guard(())
}

/// Sends what is queued when dropped: hold it for the life of the process's work. A boot still
/// open then did not finish, and ends failed.
#[derive(Debug)]
pub(crate) struct Guard(());

impl Drop for Guard {
    fn drop(&mut self) {
        end_boot(false);
        sealant_observability::shutdown();
    }
}

/// The launcher's trace context for a container boot: its span is the boot's parent.
pub const TRACEPARENT: &str = "SEALANT_TRACEPARENT";
/// The tracestate beside [`TRACEPARENT`].
pub const TRACESTATE: &str = "SEALANT_TRACESTATE";

static BOOT: OnceLock<BootTrace> = OnceLock::new();

/// Begin this process's boot trace, `name` (`sealantd.workspace.boot`, `sealantd.vm.boot`), as started at
/// `started`, under the launcher's `traceparent`. Only the first call counts.
pub(crate) fn begin_boot(
    name: &'static str,
    started: SystemTime,
    traceparent: Option<(&str, &str)>,
) {
    if BOOT.get().is_none()
        && let Some(trace) = BootTrace::begin(name, started, traceparent)
    {
        let _ = BOOT.set(trace);
    }
}

/// A boot stage that ran from `start` to `end`.
pub(crate) fn boot_stage(stage: &'static str, start: SystemTime, end: SystemTime) {
    if let Some(boot) = BOOT.get() {
        boot.stage(stage, start, end);
    }
}

/// The boot reached `stage`.
pub(crate) fn boot_reached(stage: &'static str) {
    if let Some(boot) = BOOT.get() {
        boot.reached(stage);
    }
}

/// Run `f` under the boot's span while the boot is open: the spans it makes with no parent of
/// their own (a lifecycle step's or the harness's spawn) are the boot's.
pub(crate) fn in_boot<R>(f: impl FnOnce() -> R) -> R {
    match BOOT.get() {
        Some(boot) => boot.in_scope(f),
        None => f(),
    }
}

/// End the boot: it finished (`ok`) or it never will.
pub(crate) fn end_boot(ok: bool) {
    if let Some(boot) = BOOT.get() {
        boot.end(ok);
    }
}
