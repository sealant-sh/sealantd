//! The daemon's logs, traces and errors ([`sealant_observability`]).
//!
//! The daemon runs inside a workspace, whose image may set `SENTRY_DSN` for its own code, so it
//! reads its telemetry settings under [`PREFIX`]: `SEALANT_SENTRY_DSN` and the rest. Boot
//! consumes them, so they never reach the harness. None set: nothing is exported.

use sealant_observability::Config;

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

/// Sends what is queued when dropped: hold it for the life of the process's work.
#[derive(Debug)]
pub(crate) struct Guard(());

impl Drop for Guard {
    fn drop(&mut self) {
        sealant_observability::shutdown();
    }
}
