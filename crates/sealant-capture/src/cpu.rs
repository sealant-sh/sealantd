//! CPU-time accounting shared by the shipper's duty cycle and the sinks' helper threads.

use std::time::Duration;

use nix::sys::resource::{UsageWho, getrusage};

/// CPU time (user + system) of the calling thread.
pub(crate) fn thread_cpu() -> Duration {
    match getrusage(UsageWho::RUSAGE_THREAD) {
        Ok(u) => {
            let ut = u.user_time();
            let st = u.system_time();
            let micros = (i128::from(ut.tv_sec()) * 1_000_000 + i128::from(ut.tv_usec()))
                + (i128::from(st.tv_sec()) * 1_000_000 + i128::from(st.tv_usec()));
            Duration::from_micros(u64::try_from(micros.max(0)).unwrap_or(0))
        }
        Err(_) => Duration::ZERO,
    }
}
