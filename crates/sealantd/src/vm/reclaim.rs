//! Giving memory and disk back to the host while the guest is idle (architecture §4.3).
//!
//! A build leaves gigabytes of clean page cache behind, and deleting its output leaves the data
//! disk's blocks allocated in the host's sparse `data.img`. Once nothing in the foreground has
//! run for a while (no terminal open, the CPU quiet), the guest drops clean page cache — the
//! freed pages go back to the host through the balloon's free page reporting — and trims the
//! data disk, punching holes in `data.img`. Once per idle stretch, and never more often than
//! [`Policy::min_interval`], so a guest that idles and wakes in a loop does not thrash its cache.
//! Every failure is logged and tolerated; a trim the device cannot do is not tried again.

use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, Instant};

use tokio::sync::watch;

/// When to reclaim.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct Policy {
    /// How long the guest must be idle first.
    pub idle_window: Duration,
    /// The least time between two reclaims.
    pub min_interval: Duration,
    /// The CPU busy fraction over one tick above which the guest counts as active.
    pub busy_cpu: f64,
    /// How often activity is sampled.
    pub tick: Duration,
}

impl Default for Policy {
    fn default() -> Self {
        Self {
            idle_window: Duration::from_secs(60),
            min_interval: Duration::from_secs(10 * 60),
            busy_cpu: 0.10,
            tick: Duration::from_secs(10),
        }
    }
}

/// The decision half: fed one activity sample per tick, says when to reclaim.
#[derive(Debug)]
pub struct Reclaimer {
    policy: Policy,
    idle_since: Option<Instant>,
    last_reclaim: Option<Instant>,
    /// Whether this idle stretch may still reclaim (re-armed by activity).
    armed: bool,
    trim_disabled: bool,
    trim_failures: u32,
}

/// Consecutive transient trim failures after which trimming stops for good.
const TRIM_GIVE_UP: u32 = 3;

/// What one reclaim did.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Outcome {
    /// The page cache was dropped.
    pub dropped_caches: bool,
    /// Bytes the trim reported, when it ran and succeeded.
    pub trimmed: Option<u64>,
    /// The trim was skipped because it is disabled.
    pub trim_skipped: bool,
}

/// What a reclaim does to the system: the real one in the daemon, a recording double in tests.
pub trait Actions {
    /// Drop clean page cache.
    ///
    /// # Errors
    /// The kernel refused.
    fn drop_caches(&mut self) -> std::io::Result<()>;
    /// Trim the data disk; the bytes trimmed.
    ///
    /// # Errors
    /// The device or filesystem cannot, or the call failed.
    fn trim(&mut self) -> std::io::Result<u64>;
}

impl Reclaimer {
    /// A reclaimer that may reclaim in its first idle stretch.
    #[must_use]
    pub fn new(policy: Policy) -> Self {
        Self {
            policy,
            idle_since: None,
            last_reclaim: None,
            armed: true,
            trim_disabled: false,
            trim_failures: 0,
        }
    }

    /// Feed one sample taken at `now`; whether to reclaim now.
    pub fn tick(&mut self, now: Instant, active: bool) -> bool {
        if active {
            self.idle_since = None;
            self.armed = true;
            return false;
        }
        let since = *self.idle_since.get_or_insert(now);
        if !self.armed || now.duration_since(since) < self.policy.idle_window {
            return false;
        }
        if self
            .last_reclaim
            .is_some_and(|last| now.duration_since(last) < self.policy.min_interval)
        {
            return false;
        }
        self.armed = false;
        self.last_reclaim = Some(now);
        true
    }

    /// Reclaim with `actions`, tolerating every failure.
    pub fn reclaim(&mut self, actions: &mut impl Actions) -> Outcome {
        let mut outcome = Outcome::default();
        match actions.drop_caches() {
            Ok(()) => outcome.dropped_caches = true,
            Err(error) => tracing::warn!(%error, "idle reclaim: dropping the page cache failed"),
        }
        if self.trim_disabled {
            outcome.trim_skipped = true;
            return outcome;
        }
        match actions.trim() {
            Ok(bytes) => {
                self.trim_failures = 0;
                outcome.trimmed = Some(bytes);
            }
            Err(error) if permanent(&error) => {
                tracing::warn!(%error, "idle reclaim: the data disk cannot be trimmed; not trying again");
                self.trim_disabled = true;
            }
            Err(error) => {
                self.trim_failures += 1;
                tracing::warn!(%error, failures = self.trim_failures, "idle reclaim: trim failed");
                if self.trim_failures >= TRIM_GIVE_UP {
                    self.trim_disabled = true;
                }
            }
        }
        outcome
    }
}

/// A trim error that will not go away: no discard support, not a filesystem that trims, or no
/// privilege.
fn permanent(error: &std::io::Error) -> bool {
    const ENOTTY: i32 = 25;
    const EOPNOTSUPP: i32 = 95;
    const EPERM: i32 = 1;
    error.kind() == std::io::ErrorKind::Unsupported
        || matches!(error.raw_os_error(), Some(ENOTTY | EOPNOTSUPP | EPERM))
}

/// `(busy, total)` jiffies from `/proc/stat`'s aggregate `cpu` line; busy is everything but
/// idle and iowait.
#[must_use]
pub fn cpu_times(stat: &str) -> Option<(u64, u64)> {
    let line = stat.lines().find(|line| line.starts_with("cpu "))?;
    let fields: Vec<u64> = line
        .split_ascii_whitespace()
        .skip(1)
        .map(str::parse)
        .collect::<Result<_, _>>()
        .ok()?;
    if fields.len() < 4 {
        return None;
    }
    let total: u64 = fields.iter().take(8).sum();
    let idle = fields[3] + fields.get(4).copied().unwrap_or(0);
    Some((total.saturating_sub(idle), total))
}

/// The busy fraction between two [`cpu_times`] samples.
#[must_use]
pub fn busy_fraction(before: (u64, u64), after: (u64, u64)) -> f64 {
    let total = after.1.saturating_sub(before.1);
    if total == 0 {
        return 0.0;
    }
    after.0.saturating_sub(before.0) as f64 / total as f64
}

/// The guest's real reclaim: cgroup `memory.reclaim` where the daemon's cgroup has it, else
/// `drop_caches`; `FITRIM` on the data disk.
#[derive(Debug)]
pub struct SystemActions {
    /// The data disk's mount point.
    pub data_mount: PathBuf,
}

impl Actions for SystemActions {
    fn drop_caches(&mut self) -> std::io::Result<()> {
        // `memory.reclaim` exists on non-root cgroups only; PID 1 sits in the root, where
        // `drop_caches` is the way. Clean pages only: dirty ones are written back first by the
        // kernel's own flusher, never dropped.
        let reclaim = Path::new("/sys/fs/cgroup/memory.reclaim");
        if reclaim.exists() && std::fs::write(reclaim, "1G").is_ok() {
            return Ok(());
        }
        std::fs::write("/proc/sys/vm/drop_caches", "1\n")
    }

    fn trim(&mut self) -> std::io::Result<u64> {
        sealant_process::trim::fitrim(&self.data_mount)
    }
}

/// Run the reclaimer until `shutdown`: activity is "a PTY session is open, or the CPU was more
/// than [`Policy::busy_cpu`] busy over the last tick".
pub async fn run(
    runtime: Arc<crate::runtime::Runtime>,
    policy: Policy,
    actions: SystemActions,
    mut shutdown: watch::Receiver<bool>,
) {
    let mut reclaimer = Reclaimer::new(policy);
    let mut actions = Some(actions);
    let mut last_cpu = read_cpu();
    let mut ticker = tokio::time::interval(policy.tick);
    ticker.tick().await;
    loop {
        tokio::select! {
            changed = shutdown.changed() => {
                if changed.is_err() || *shutdown.borrow() {
                    return;
                }
            }
            _ = ticker.tick() => {}
        }
        let cpu = read_cpu();
        let busy = match (last_cpu, cpu) {
            (Some(before), Some(after)) => busy_fraction(before, after),
            _ => 0.0,
        };
        last_cpu = cpu;
        let active = runtime.active_sessions() > 0 || busy > policy.busy_cpu;
        if !reclaimer.tick(Instant::now(), active) {
            continue;
        }
        let Some(mut taken) = actions.take() else {
            continue;
        };
        // A trim walks the filesystem's free space: off the async workers.
        let (back, outcome, reclaimer_back) = match tokio::task::spawn_blocking(move || {
            let outcome = reclaimer.reclaim(&mut taken);
            (taken, outcome, reclaimer)
        })
        .await
        {
            Ok(done) => done,
            Err(error) => {
                tracing::warn!(%error, "idle reclaim task failed; reclaim stops");
                return;
            }
        };
        actions = Some(back);
        reclaimer = reclaimer_back;
        tracing::info!(?outcome, "idle reclaim");
    }
}

fn read_cpu() -> Option<(u64, u64)> {
    std::fs::read_to_string("/proc/stat")
        .ok()
        .and_then(|stat| cpu_times(&stat))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn policy() -> Policy {
        Policy {
            idle_window: Duration::from_secs(60),
            min_interval: Duration::from_secs(600),
            ..Policy::default()
        }
    }

    #[test]
    fn it_reclaims_once_the_guest_has_idled_for_the_window() {
        let start = Instant::now();
        let at = |secs| start + Duration::from_secs(secs);
        let mut reclaimer = Reclaimer::new(policy());
        assert!(!reclaimer.tick(at(0), false));
        assert!(!reclaimer.tick(at(59), false));
        assert!(reclaimer.tick(at(60), false));
        // Once per idle stretch, however long it lasts.
        assert!(!reclaimer.tick(at(70), false));
        assert!(!reclaimer.tick(at(5_000), false));
    }

    #[test]
    fn activity_restarts_the_window() {
        let start = Instant::now();
        let at = |secs| start + Duration::from_secs(secs);
        let mut reclaimer = Reclaimer::new(policy());
        assert!(!reclaimer.tick(at(0), false));
        assert!(!reclaimer.tick(at(50), true));
        assert!(!reclaimer.tick(at(60), false));
        assert!(!reclaimer.tick(at(119), false));
        assert!(reclaimer.tick(at(120), false));
    }

    #[test]
    fn idle_and_wake_in_a_loop_never_reclaims_more_often_than_the_interval() {
        let start = Instant::now();
        let mut reclaimer = Reclaimer::new(policy());
        let mut reclaims = Vec::new();
        // Busy for 10 s, idle for 70 s, for an hour: every idle stretch passes the window.
        let mut secs = 0;
        while secs < 3_600 {
            let active = secs % 80 < 10;
            if reclaimer.tick(start + Duration::from_secs(secs), active) {
                reclaims.push(secs);
            }
            secs += 5;
        }
        assert!(reclaims.len() >= 2, "{reclaims:?}");
        for pair in reclaims.windows(2) {
            assert!(pair[1] - pair[0] >= 600, "{reclaims:?}");
        }
    }

    #[derive(Default)]
    struct Recorder {
        drops: usize,
        trims: usize,
        drop_error: bool,
        trim_errors: Vec<std::io::Error>,
    }

    impl Actions for Recorder {
        fn drop_caches(&mut self) -> std::io::Result<()> {
            self.drops += 1;
            if self.drop_error {
                Err(std::io::Error::from(std::io::ErrorKind::PermissionDenied))
            } else {
                Ok(())
            }
        }
        fn trim(&mut self) -> std::io::Result<u64> {
            self.trims += 1;
            if self.trim_errors.is_empty() {
                Ok(4096)
            } else {
                Err(self.trim_errors.remove(0))
            }
        }
    }

    #[test]
    fn a_failed_cache_drop_still_trims() {
        let mut reclaimer = Reclaimer::new(policy());
        let mut actions = Recorder {
            drop_error: true,
            ..Recorder::default()
        };
        let outcome = reclaimer.reclaim(&mut actions);
        assert!(!outcome.dropped_caches);
        assert_eq!(outcome.trimmed, Some(4096));
    }

    #[test]
    fn a_device_without_discard_is_not_trimmed_again() {
        let mut reclaimer = Reclaimer::new(policy());
        let mut actions = Recorder {
            trim_errors: vec![std::io::Error::from_raw_os_error(95)],
            ..Recorder::default()
        };
        assert_eq!(reclaimer.reclaim(&mut actions).trimmed, None);
        let next = reclaimer.reclaim(&mut actions);
        assert!(next.trim_skipped && next.dropped_caches);
        assert_eq!(actions.trims, 1);
        assert_eq!(actions.drops, 2);
    }

    #[test]
    fn transient_trim_failures_are_retried_then_given_up() {
        let mut reclaimer = Reclaimer::new(policy());
        let eio = || std::io::Error::from_raw_os_error(5);
        let mut actions = Recorder {
            trim_errors: vec![eio(), eio()],
            ..Recorder::default()
        };
        reclaimer.reclaim(&mut actions);
        reclaimer.reclaim(&mut actions);
        assert_eq!(reclaimer.reclaim(&mut actions).trimmed, Some(4096));

        actions.trim_errors = vec![eio(), eio(), eio()];
        for _ in 0..3 {
            reclaimer.reclaim(&mut actions);
        }
        assert!(reclaimer.reclaim(&mut actions).trim_skipped);
        assert_eq!(actions.trims, 6);
    }

    #[test]
    fn cpu_busy_is_everything_but_idle_and_iowait() {
        let before = cpu_times("cpu  100 0 100 700 100 0 0 0 0 0\ncpu0 1 2 3 4\n").expect("cpu");
        assert_eq!(before, (200, 1000));
        let after = cpu_times("cpu  150 0 150 1500 200 0 0 0 0 0\n").expect("cpu");
        assert!((busy_fraction(before, after) - 0.1).abs() < 1e-9);
        assert_eq!(busy_fraction(after, after), 0.0);
        assert_eq!(cpu_times("intr 1 2 3\n"), None);
    }
}
