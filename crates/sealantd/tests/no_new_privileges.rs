//! No-new-privileges (plan §18): every daemon sets it on itself, and so on everything it starts,
//! except a per-person executor's (a boot under an owner map, Mend's ADR 0016), where every person
//! has `sudo`. `runtime.getCapabilities` reports which.
//!
//! No-new-privileges is per thread and cannot be unset, so each case runs its runtime on a thread
//! of its own: nothing here leaks into another test.

use std::sync::Arc;

use sealant_runtime_core::{RuntimeConfig, new_runtime_id};
use sealantd::Runtime;
use sealantd::shutdown::ShutdownSignal;

/// On a fresh thread: whether it had no-new-privileges before, after `Runtime::new` with
/// `no_new_privileges`, and what the runtime reports.
fn posture(no_new_privileges: bool) -> (Option<bool>, Option<bool>, Option<bool>) {
    std::thread::spawn(move || {
        let before = sealant_process::platform::no_new_privs();
        let tokio = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        tokio.block_on(async move {
            let mut config = RuntimeConfig::new(new_runtime_id());
            config.workspace_root = std::env::temp_dir();
            config.no_new_privileges = no_new_privileges;
            let runtime = Runtime::new(config, Arc::new(ShutdownSignal::new(1000)));
            let after = sealant_process::platform::no_new_privs();
            (before, after, runtime.capabilities().no_new_privileges)
        })
    })
    .join()
    .unwrap()
}

/// Without an owner map (the default), the daemon sets no-new-privileges, as it always has.
#[test]
fn a_daemon_sets_no_new_privileges_by_default() {
    assert!(RuntimeConfig::new(new_runtime_id()).no_new_privileges);
    let (_, after, reported) = posture(true);
    assert_eq!(after, Some(true), "no-new-privileges is not set");
    assert_eq!(reported, Some(true), "the runtime does not report it");
}

/// A per-person executor's daemon leaves it unset (where the environment did not set it first:
/// it cannot be unset), and reports that. With `SEALANTD_REQUIRE_NNP_FREE=1` (CI's hosted
/// runners impose none) an environment that imposes it fails the test instead of passing it
/// with nothing proven.
#[test]
fn a_per_person_daemon_leaves_no_new_privileges_unset() {
    let (before, after, reported) = posture(false);
    if before != Some(false) {
        assert!(
            std::env::var("SEALANTD_REQUIRE_NNP_FREE").as_deref() != Ok("1"),
            "SEALANTD_REQUIRE_NNP_FREE=1 but this environment imposes no-new-privileges"
        );
        eprintln!("this environment sets no-new-privileges itself: nothing to leave unset");
        assert_eq!((after, reported), (before, before));
        return;
    }
    assert_eq!(after, Some(false), "no-new-privileges was set");
    assert_eq!(reported, Some(false), "the runtime reports it set");
}
