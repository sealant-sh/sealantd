//! Guest wall-clock synchronization (`runtime.syncClock`).
//!
//! Under Apple `Virtualization.framework`, Linux's `RTC_HCTOSYS` sets `CLOCK_REALTIME` once at
//! boot and host sleep pauses the guest without automatically stepping guest wall time on wake.
//! `sealant-vm-runner` calls `runtime.syncClock` on wake (and periodically as a fallback); this
//! module validates the timestamp, ignores jitter within [`STEP_THRESHOLD_NS`], and steps
//! `CLOCK_REALTIME` directly when running with `CAP_SYS_TIME`.

use std::time::{SystemTime, UNIX_EPOCH};

use sealant_protocol::{ClockSynced, ControlError, ControlErrorCode};

/// Drift below or equal to 500 ms is ignored so routine ticks do not disturb running timers.
pub(crate) const STEP_THRESHOLD_NS: u128 = 500_000_000;
/// 2020-01-01T00:00:00Z in nanoseconds: refuses zero/garbage timestamps.
const MIN_VALID_UNIX_NS: u64 = 1_577_836_800_000_000_000;
/// 2100-01-01T00:00:00Z in nanoseconds: refuses overflow/garbage timestamps.
const MAX_VALID_UNIX_NS: u64 = 4_102_444_800_000_000_000;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct ClockSyncPlan {
    pub(crate) should_step: bool,
    pub(crate) drift_ms: i64,
    pub(crate) secs: i64,
    pub(crate) nsecs: i64,
}

/// Validates `target_ns` against `[2020, 2100]` UTC and decides whether to step `CLOCK_REALTIME`.
pub(crate) fn plan_clock_sync(target_ns: u64, now_ns: u128) -> Result<ClockSyncPlan, ControlError> {
    if !(MIN_VALID_UNIX_NS..=MAX_VALID_UNIX_NS).contains(&target_ns) {
        return Err(ControlError::invalid_argument(format!(
            "unix_epoch_ns {target_ns} is outside the accepted UTC range (2020..=2100)"
        )));
    }
    let delta_ns = i128::from(target_ns) - (now_ns as i128);
    let abs_delta = delta_ns.unsigned_abs();
    let drift_ms = i64::try_from(delta_ns / 1_000_000).unwrap_or(if delta_ns.is_negative() {
        i64::MIN
    } else {
        i64::MAX
    });
    let secs = i64::try_from(target_ns / 1_000_000_000)
        .map_err(|_| ControlError::invalid_argument("unix_epoch_ns overflows seconds"))?;
    let nsecs = i64::try_from(target_ns % 1_000_000_000)
        .map_err(|_| ControlError::invalid_argument("unix_epoch_ns overflows nanoseconds"))?;
    Ok(ClockSyncPlan {
        should_step: abs_delta > STEP_THRESHOLD_NS,
        drift_ms,
        secs,
        nsecs,
    })
}

/// Synchronizes `CLOCK_REALTIME` to `unix_epoch_ns` when drift exceeds [`STEP_THRESHOLD_NS`].
pub(crate) fn sync_clock(unix_epoch_ns: u64) -> Result<ClockSynced, ControlError> {
    let now_ns = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|e| ControlError::internal(format!("system clock precedes Unix epoch: {e}")))?
        .as_nanos();
    let plan = plan_clock_sync(unix_epoch_ns, now_ns)?;
    if !plan.should_step {
        return Ok(ClockSynced {
            stepped: false,
            drift_ms: plan.drift_ms,
        });
    }
    step_realtime_clock(plan.secs, plan.nsecs)?;
    tracing::info!(drift_ms = plan.drift_ms, "guest wall clock stepped");
    Ok(ClockSynced {
        stepped: true,
        drift_ms: plan.drift_ms,
    })
}

#[cfg(target_os = "linux")]
fn step_realtime_clock(secs: i64, nsecs: i64) -> Result<(), ControlError> {
    use nix::errno::Errno;
    use nix::sys::time::TimeSpec;
    use nix::time::{ClockId, clock_settime};

    clock_settime(ClockId::CLOCK_REALTIME, TimeSpec::new(secs, nsecs)).map_err(|err| match err {
        Errno::EPERM => ControlError::new(
            ControlErrorCode::PermissionDenied,
            "stepping CLOCK_REALTIME requires CAP_SYS_TIME",
        ),
        other => ControlError::internal(format!("clock_settime failed: {other}")),
    })
}

#[cfg(not(target_os = "linux"))]
fn step_realtime_clock(_secs: i64, _nsecs: i64) -> Result<(), ControlError> {
    Err(ControlError::feature_unavailable(
        "runtime.syncClock is only supported on Linux",
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    const BASE_NS: u64 = 1_795_800_000_000_000_000;

    #[test]
    fn rejects_zero_and_out_of_range_timestamps() {
        assert_eq!(
            plan_clock_sync(0, u128::from(BASE_NS)).unwrap_err().code(),
            ControlErrorCode::InvalidArgument
        );
        assert_eq!(
            plan_clock_sync(MIN_VALID_UNIX_NS - 1, u128::from(BASE_NS))
                .unwrap_err()
                .code(),
            ControlErrorCode::InvalidArgument
        );
        assert_eq!(
            plan_clock_sync(MAX_VALID_UNIX_NS + 1, u128::from(BASE_NS))
                .unwrap_err()
                .code(),
            ControlErrorCode::InvalidArgument
        );
    }

    #[test]
    fn skips_stepping_within_500ms_threshold() {
        let plan = plan_clock_sync(BASE_NS + 500_000_000, u128::from(BASE_NS)).unwrap();
        assert!(!plan.should_step);
        assert_eq!(plan.drift_ms, 500);

        let neg = plan_clock_sync(BASE_NS - 250_000_000, u128::from(BASE_NS)).unwrap();
        assert!(!neg.should_step);
        assert_eq!(neg.drift_ms, -250);
    }

    #[test]
    fn steps_when_drift_exceeds_500ms() {
        // Simulates a 30-minute MacBook sleep (1,800,000 ms behind host UTC).
        let target = BASE_NS + 1_800_000_000_000 + 123_456_789;
        let plan = plan_clock_sync(target, u128::from(BASE_NS)).unwrap();
        assert!(plan.should_step);
        assert_eq!(plan.drift_ms, 1_800_123);
        assert_eq!(plan.secs, 1_795_801_800);
        assert_eq!(plan.nsecs, 123_456_789);
    }

    #[test]
    fn sync_clock_with_current_time_is_noop() {
        let now_ns = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos() as u64;
        let res = sync_clock(now_ns).unwrap();
        assert!(!res.stepped);
        assert!(res.drift_ms.abs() < 500);
    }
}
