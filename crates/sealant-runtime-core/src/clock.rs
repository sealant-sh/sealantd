//! Wall-clock and monotonic time sources.

use std::time::{Instant, SystemTime, UNIX_EPOCH};

use sealant_protocol::{MonotonicNanos, WallClockMicros};

/// A clock providing wall-clock timestamps (for `observedAt`) and a monotonic reference
/// (for duration-safe local ordering). The monotonic epoch is fixed at construction.
#[derive(Debug, Clone)]
pub struct Clock {
    mono_epoch: Instant,
}

impl Clock {
    /// Create a clock whose monotonic epoch is now.
    #[must_use]
    pub fn new() -> Self {
        Self {
            mono_epoch: Instant::now(),
        }
    }

    /// The current wall-clock time as microseconds since the Unix epoch.
    ///
    /// If the system clock is set before the Unix epoch the value is negative.
    #[must_use]
    pub fn wall_now(&self) -> WallClockMicros {
        let micros = match SystemTime::now().duration_since(UNIX_EPOCH) {
            Ok(forward) => forward.as_micros() as i64,
            Err(backward) => -(backward.duration().as_micros() as i64),
        };
        WallClockMicros(micros)
    }

    /// The current monotonic reading in nanoseconds since this clock's epoch.
    #[must_use]
    pub fn mono_now(&self) -> MonotonicNanos {
        MonotonicNanos(self.mono_epoch.elapsed().as_nanos() as u64)
    }

    /// Milliseconds elapsed since this clock's epoch (daemon uptime).
    #[must_use]
    pub fn uptime_millis(&self) -> u64 {
        self.mono_epoch.elapsed().as_millis() as u64
    }
}

impl Default for Clock {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn monotonic_is_non_decreasing() {
        let clock = Clock::new();
        let a = clock.mono_now();
        let b = clock.mono_now();
        assert!(b.get() >= a.get());
    }

    #[test]
    fn wall_clock_is_after_2020() {
        // 2020-01-01 in microseconds since the epoch.
        let y2020 = 1_577_836_800_000_000;
        assert!(Clock::new().wall_now().get() > y2020);
    }
}
