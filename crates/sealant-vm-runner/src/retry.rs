//! Accept loops outlive transient errors: a full descriptor table (`EMFILE`, `ENFILE`) or an
//! aborted connection must not stop a forwarder or a vsock bridge for the rest of the VM's life.

use std::time::Duration;

/// How long an accept loop waits after an error before accepting again.
pub(crate) const ACCEPT_BACKOFF: Duration = Duration::from_millis(50);

/// Logs `error` from `what`'s accept and waits [`ACCEPT_BACKOFF`].
pub(crate) async fn after_accept_error(what: &str, error: &std::io::Error) {
    tracing::warn!("{what}: accept failed, retrying: {error}");
    tokio::time::sleep(ACCEPT_BACKOFF).await;
}
