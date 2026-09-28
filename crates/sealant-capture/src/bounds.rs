//! How long a capture step is expected to take at most, and how long a git it runs may run.
//!
//! Docker end to end, round 8 (F1): a snap waited on a `git` for 17 minutes and nothing said so.
//! Every git the capture runs is now bounded ([`sealant_process::Bound`]): past
//! [`Bounds::git_overdue`] it is named in `capture.status` (`overdue`) and logged, past
//! [`Bounds::git_limit`] it is killed, and the snap that ran it fails (and is taken again at the
//! next cadence tick or final round; a killed git leaves nothing the next snap depends on: its
//! objects are written through temporary files, its index is the snap's own scratch copy). A
//! snap is a step of its own, reported past [`Bounds::snap_overdue`] and never killed.
//!
//! The defaults are far above what any git of the capture takes on a large repository; the
//! daemon reads overrides from `SEALANT_CAPTURE_GIT_OVERDUE_SECS`,
//! `SEALANT_CAPTURE_GIT_LIMIT_SECS` and `SEALANT_CAPTURE_SNAP_OVERDUE_SECS`.

use std::sync::{PoisonError, RwLock};
use std::time::Duration;

/// See the module docs.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Bounds {
    /// A git running this long is reported (`capture.status` `overdue`) and logged.
    pub git_overdue: Duration,
    /// A git running this long is killed; the snap that ran it fails.
    pub git_limit: Duration,
    /// A snap running this long is reported and logged.
    pub snap_overdue: Duration,
}

impl Default for Bounds {
    fn default() -> Self {
        Self {
            git_overdue: Duration::from_secs(120),
            git_limit: Duration::from_secs(900),
            snap_overdue: Duration::from_secs(600),
        }
    }
}

impl Bounds {
    /// The defaults, overridden by the environment's `SEALANT_CAPTURE_*_SECS` (a value that is
    /// not a whole number of seconds above 0 is ignored). The limit is never below the
    /// overdue bound.
    #[must_use]
    pub fn from_env() -> Self {
        let secs = |name: &str| {
            std::env::var(name)
                .ok()
                .and_then(|v| v.trim().parse::<u64>().ok())
                .filter(|s| *s > 0)
                .map(Duration::from_secs)
        };
        let mut bounds = Self::default();
        if let Some(d) = secs("SEALANT_CAPTURE_GIT_OVERDUE_SECS") {
            bounds.git_overdue = d;
        }
        if let Some(d) = secs("SEALANT_CAPTURE_GIT_LIMIT_SECS") {
            bounds.git_limit = d;
        }
        if let Some(d) = secs("SEALANT_CAPTURE_SNAP_OVERDUE_SECS") {
            bounds.snap_overdue = d;
        }
        bounds.git_limit = bounds.git_limit.max(bounds.git_overdue);
        bounds
    }
}

static BOUNDS: RwLock<Option<Bounds>> = RwLock::new(None);

/// The bounds in force: set by [`set`], else read once from the environment.
#[must_use]
pub fn current() -> Bounds {
    if let Some(bounds) = *BOUNDS.read().unwrap_or_else(PoisonError::into_inner) {
        return bounds;
    }
    let mut slot = BOUNDS.write().unwrap_or_else(PoisonError::into_inner);
    *slot.get_or_insert_with(Bounds::from_env)
}

/// Replace the bounds for this process (tests; an embedder with its own configuration).
pub fn set(bounds: Bounds) {
    *BOUNDS.write().unwrap_or_else(PoisonError::into_inner) = Some(bounds);
}
