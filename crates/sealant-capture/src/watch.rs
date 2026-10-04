//! Change detection for the cadence (ADR-0015 *Cadence and budgets*): the `sealant-fs` pruned
//! per-directory inotify watcher run over the capture roots under the capture ignore policy.
//! Every event marks a class dirty; nothing is hashed here. A write or create also names its path
//! in the engine's [`Invalidations`], so the next build of that class reads the file again
//! whatever its stat says. The watcher runs under a watch
//! budget: directories are counted before registration, `fs.inotify.max_user_watches` is raised
//! only when the policy says so, and a class whose watches do not fit polls instead (the stat
//! walk the engine does anyway). `IN_Q_OVERFLOW` (`need_rescan`) reports an [`ChangeSignal::Overflow`]
//! and the runner drops to polling. Bulk directories that appear after the start get watches
//! then, within the budget; a directory too long to name is watched through its descriptor.

use std::collections::{HashMap, HashSet};
use std::fs;
use std::mem;
use std::os::fd::{AsRawFd, OwnedFd};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Condvar, Mutex, mpsc};
use std::time::{Duration, Instant};

use notify::event::{CreateKind, ModifyKind, RenameMode};
use notify::{EventKind, RecommendedWatcher, RecursiveMode, Watcher};

use crate::aliases::Aliases;
use crate::engine::Class;
use crate::gitpack::GitRepo;
use crate::index::{
    DAEMON_DIR, Suspects, has_component_in, is_git_transient, is_harness_excluded_path, rel_key,
};
use crate::longpath;

/// The `fs.inotify.max_user_watches` sysctl.
pub const MAX_USER_WATCHES: &str = "/proc/sys/fs/inotify/max_user_watches";

/// What the executor image raises the sysctl to where it is writable (ADR-0015).
pub const RAISED_MAX_USER_WATCHES: u64 = 524_288;

/// Watch policy.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WatchPolicy {
    /// Watch at all; `false` polls both classes at their maximum intervals.
    pub enabled: bool,
    /// Watches this executor may register. `None` reads the sysctl and takes half of it (the
    /// daemon's telemetry watcher shares the user's quota).
    pub budget: Option<usize>,
    /// Try to raise the sysctl when the budget does not fit; never fails, only logs.
    pub raise_limit: bool,
}

impl Default for WatchPolicy {
    fn default() -> Self {
        Self {
            enabled: true,
            budget: None,
            raise_limit: false,
        }
    }
}

/// How a class learns about changes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Mode {
    /// The watcher marks it dirty; snaps fire on the quiet / max-interval clocks.
    Watched,
    /// No watches: snapped at the maximum interval, unconditionally.
    Polled,
}

/// A signal from the watcher thread.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ChangeSignal {
    /// Something under a class root changed.
    Changed(Class),
    /// The kernel queue overflowed (`IN_Q_OVERFLOW`); events were lost.
    Overflow,
    /// A directory of the class could not be watched (the watch limit, the budget, a
    /// permission): changes under it would go unseen, so the class polls until the watcher
    /// watches it after all ([`ChangeSignal::Rewatched`]).
    Unwatched(Class),
    /// Every directory of the class that could not be watched is watched now (or gone): the
    /// class is watched again. What changed under them meanwhile went unseen, so the class is
    /// dirty.
    Rewatched(Class),
}

/// Paths the watcher saw written or created, per class, since that class's last build took them
/// ([`crate::index::TreeBuilder::suspects`]). The stat key already catches every write that
/// moves a file's ctime; these catch the ones that land in the same timestamp tick as a read.
#[derive(Debug, Default)]
pub struct Invalidations {
    small: std::sync::Mutex<Suspects>,
    bulk: std::sync::Mutex<Suspects>,
}

impl Invalidations {
    fn slot(&self, class: Class) -> std::sync::MutexGuard<'_, Suspects> {
        match class {
            Class::Small => &self.small,
            Class::Bulk => &self.bulk,
        }
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    /// Note a write to `path`, a path of `class`.
    pub fn note(&self, class: Class, path: &Path) {
        self.slot(class).insert(path.to_path_buf());
    }

    /// Take every path noted for `class`.
    #[must_use]
    pub fn take(&self, class: Class) -> Suspects {
        mem::take(&mut *self.slot(class))
    }

    /// Put back paths a build took but did not read (the build failed).
    pub fn restore(&self, class: Class, paths: Suspects) {
        self.slot(class).extend(paths);
    }
}

/// The paths a workspace is watched by.
#[derive(Debug, Clone)]
pub struct WatchSpec {
    /// Worktree root.
    pub root: PathBuf,
    /// Harness home, when captured.
    pub harness_home: Option<PathBuf>,
    /// Staging directory (never watched).
    pub staging_dir: PathBuf,
    /// Directory names that are bulk wherever they appear.
    pub bulk_dirs: Vec<String>,
    /// Whether the bulk class is captured (and so watched) at all.
    pub capture_bulk: bool,
    /// Policy.
    pub policy: WatchPolicy,
    /// Where written paths are noted for the engine; `None` notes nothing.
    pub invalidations: Option<Arc<Invalidations>>,
    /// The multi-link files the classes hold ([`crate::aliases`]): an event on one name dirties
    /// every class holding another, and notes each for its class. `None`: names only their own.
    pub aliases: Option<Arc<Aliases>>,
}

/// The result of starting the watcher: which class is watched and the handle keeping it alive.
#[derive(Debug)]
pub struct WatchStart {
    /// Small-class mode.
    pub small: Mode,
    /// Bulk-class mode.
    pub bulk: Mode,
    /// Watches registered.
    pub watches: usize,
    /// The live watcher, `None` when both classes poll.
    pub handle: Option<WatchHandle>,
}

/// Keeps the backend watcher and its worker thread alive; dropping it stops both.
pub struct WatchHandle {
    watcher: Arc<Mutex<Option<RecommendedWatcher>>>,
    fence: Arc<Fence>,
}

/// The directory under the staging directory a [`WatchHandle::settle`] fence is written in.
const FENCE_DIR: &str = "watch-fence";

/// A barrier through the watcher's event stream ([`WatchHandle::settle`]): a file created in a
/// directory of its own, watched by the same watcher as the roots. The kernel queues every
/// event of one watcher in the order it happened, and the worker handles them in that order,
/// so once the worker has handled the fence's event it has delivered every change made before
/// the fence was written.
#[derive(Debug)]
struct Fence {
    dir: PathBuf,
    next: AtomicU64,
    seen: Mutex<u64>,
    cv: Condvar,
}

impl Fence {
    /// The fence number `path` names, when it is a fence file.
    fn number(&self, path: &Path) -> Option<u64> {
        if path.parent() != Some(self.dir.as_path()) {
            return None;
        }
        path.file_name()?.to_str()?.strip_prefix("f-")?.parse().ok()
    }

    fn passed(&self, n: u64) {
        let mut seen = self.seen.lock().unwrap_or_else(|e| e.into_inner());
        if n > *seen {
            *seen = n;
        }
        drop(seen);
        self.cv.notify_all();
    }
}

impl WatchHandle {
    /// Wait until the watcher has delivered every change made before this call (to the signal
    /// hook, synchronously): a fence file is written in a directory the watcher watches, and
    /// this returns once the worker has handled its event. Whatever the watcher saw happen
    /// before now has been counted then. `false` when the fence could not be written, or its
    /// event did not come back within `timeout`: nothing can be said of what is still in the
    /// queue.
    #[must_use]
    pub fn settle(&self, timeout: Duration) -> bool {
        let fence = &self.fence;
        // The directory is watched again (a no-op while it is): the staging directory may have
        // been cleared since the start.
        if fs::create_dir_all(&fence.dir).is_err() {
            return false;
        }
        {
            let mut guard = self.watcher.lock().unwrap_or_else(|e| e.into_inner());
            let Some(watcher) = guard.as_mut() else {
                return false;
            };
            if watcher
                .watch(&fence.dir, RecursiveMode::NonRecursive)
                .is_err()
            {
                return false;
            }
        }
        let n = fence.next.fetch_add(1, Ordering::SeqCst) + 1;
        let file = fence.dir.join(format!("f-{n}"));
        if fs::write(&file, b"").is_err() {
            return false;
        }
        let _ = fs::remove_file(&file);
        let until = Instant::now() + timeout;
        let mut seen = fence.seen.lock().unwrap_or_else(|e| e.into_inner());
        while *seen < n {
            let left = until.saturating_duration_since(Instant::now());
            if left.is_zero() {
                return false;
            }
            seen = fence
                .cv
                .wait_timeout(seen, left)
                .unwrap_or_else(|e| e.into_inner())
                .0;
        }
        true
    }
}

impl std::fmt::Debug for WatchHandle {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("WatchHandle").finish_non_exhaustive()
    }
}

impl Drop for WatchHandle {
    fn drop(&mut self) {
        // Dropping the backend stops event production and drops the callback's channel sender,
        // which ends the worker loop.
        let _ = self
            .watcher
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .take();
    }
}

/// Read the sysctl.
#[must_use]
pub fn max_user_watches() -> Option<u64> {
    fs::read_to_string(MAX_USER_WATCHES)
        .ok()
        .and_then(|s| s.trim().parse().ok())
}

/// Try to raise the sysctl to `at_least`; `Ok(true)` when it now holds, `Ok(false)` when it
/// already did, `Err` when it cannot be written (a read-only `/proc/sys`, no capability).
pub fn raise_max_user_watches(at_least: u64) -> std::io::Result<bool> {
    if max_user_watches().is_some_and(|cur| cur >= at_least) {
        return Ok(false);
    }
    let target = at_least.max(RAISED_MAX_USER_WATCHES);
    fs::write(MAX_USER_WATCHES, format!("{target}\n"))?;
    Ok(max_user_watches().is_some_and(|cur| cur >= at_least))
}

/// The classifier: where an absolute path falls under the capture policy.
struct Policy {
    root: PathBuf,
    git_dirs: Vec<PathBuf>,
    harness_home: Option<PathBuf>,
    staging_dir: PathBuf,
    daemon_dir: PathBuf,
    bulk_dirs: Vec<String>,
    capture_bulk: bool,
    invalidations: Option<Arc<Invalidations>>,
    aliases: Option<Arc<Aliases>>,
}

impl Policy {
    fn new(spec: &WatchSpec) -> Self {
        let git_dirs = GitRepo::open(&spec.root)
            .map(|r| {
                let mut v = vec![r.git_dir.clone()];
                if r.common_dir != r.git_dir {
                    v.push(r.common_dir.clone());
                }
                v
            })
            .unwrap_or_default();
        Self {
            root: spec.root.clone(),
            git_dirs,
            harness_home: spec.harness_home.clone(),
            staging_dir: spec.staging_dir.clone(),
            daemon_dir: spec.root.join(DAEMON_DIR),
            bulk_dirs: spec.bulk_dirs.clone(),
            capture_bulk: spec.capture_bulk,
            invalidations: spec.invalidations.clone(),
            aliases: spec.aliases.clone(),
        }
    }

    /// Git's transient bookkeeping ([`is_git_transient`]), in a git dir of the repository or
    /// in any `.git` under the roots.
    fn is_git_transient(&self, abs: &Path) -> bool {
        let rel = self
            .git_dirs
            .iter()
            .find_map(|g| abs.strip_prefix(g).ok())
            .map(|rel| format!(".git/{}", rel.to_string_lossy()))
            .unwrap_or_else(|| abs.to_string_lossy().into_owned());
        is_git_transient(&rel)
    }

    fn is_daemon(&self, abs: &Path) -> bool {
        abs.starts_with(&self.staging_dir) || abs.starts_with(&self.daemon_dir)
    }

    /// The class an event on `abs` dirties, or `None` when the policy excludes the path.
    fn classify(&self, abs: &Path) -> Option<Class> {
        if self.is_daemon(abs) {
            return None;
        }
        if self.is_git_transient(abs) {
            return None;
        }
        if let Some(home) = &self.harness_home
            && abs.starts_with(home)
        {
            if abs
                .strip_prefix(home)
                .is_ok_and(|rel| is_harness_excluded_path(&rel_key(rel)))
            {
                return None;
            }
            return Some(Class::Small);
        }
        if let Ok(rel) = abs.strip_prefix(&self.root) {
            if has_component_in(rel, &self.bulk_dirs) {
                return self.capture_bulk.then_some(Class::Bulk);
            }
            return Some(Class::Small);
        }
        if self.git_dirs.iter().any(|g| abs.starts_with(g)) {
            return Some(Class::Small);
        }
        None
    }

    /// Whether to descend into `dir` when registering small-class watches. Bulk directories, the
    /// daemon's directories, the harness home (its own root) and the parts of `.git` the engine
    /// never lists (`objects`, `worktrees`; refs, `HEAD`, the index and the logs are what move
    /// when history does) are pruned. So is `lfs`, which the engine does list: its sharded
    /// object directories would spend the watch budget, and git-lfs writes a local object while
    /// `git add` writes the index (a watched change), so the snap that change triggers walks
    /// `lfs` and finds it; every forced snap walks it too.
    fn prune_small(&self, dir: &Path, name: &str) -> bool {
        if self.bulk_dirs.iter().any(|b| b == name) || name == DAEMON_DIR || self.is_daemon(dir) {
            return true;
        }
        if self.harness_home.as_deref() == Some(dir) {
            return true;
        }
        self.git_dirs.iter().any(|g| {
            dir.strip_prefix(g).is_ok_and(|rel| {
                matches!(
                    rel.to_str(),
                    Some("objects" | "worktrees" | "lfs" | "modules")
                )
            })
        })
    }

    /// Whether to descend into `dir` when registering bulk-class watches: nested repositories'
    /// `.git` and the daemon's directories are skipped.
    fn prune_bulk(&self, dir: &Path, name: &str) -> bool {
        name == ".git" || name == DAEMON_DIR || self.is_daemon(dir)
    }

    /// Small-class roots: the worktree, the git dir(s) when outside it, the harness home.
    fn small_roots(&self) -> Vec<PathBuf> {
        let mut roots = vec![self.root.clone()];
        for g in &self.git_dirs {
            // A git dir inside the worktree that is a symlink (`.git` moved aside and linked
            // back) is not walked from the worktree: watched as a root of its own, through the
            // link, as the capture reads it (review 2026-09-28, eighth pass, #1).
            let linked = longpath::symlink_metadata(g).is_ok_and(|m| m.is_symlink());
            if (!g.starts_with(&self.root) || linked) && g.is_dir() {
                roots.push(g.clone());
            }
        }
        if let Some(h) = &self.harness_home
            && h.is_dir()
        {
            roots.push(h.clone());
        }
        roots
    }

    /// Bulk-class roots: every bulk directory under the worktree (outside `.git` and the daemon
    /// directories); nothing below a bulk directory is walked.
    fn bulk_roots(&self) -> Vec<PathBuf> {
        if !self.capture_bulk {
            return Vec::new();
        }
        let mut roots = Vec::new();
        longpath::walk(&self.root, &mut |visit| {
            let longpath::Visit::Entry { path, kind, .. } = visit else {
                return false;
            };
            if kind != longpath::Kind::Dir {
                return false;
            }
            let name = path
                .file_name()
                .map(|n| n.to_string_lossy())
                .unwrap_or_default();
            if self.prune_bulk(path, &name) {
                false
            } else if self.bulk_dirs.iter().any(|b| b.as_str() == name) {
                roots.push(path.to_path_buf());
                false
            } else {
                true
            }
        });
        roots
    }
}

/// Every directory under (and including) `dir` that `prune` does not cut off, whatever its
/// path's length (the `sealant-fs` walk stops where `walkdir` does, at
/// `PATH_MAX`, and a directory it never lists is one nobody knows is unwatched).
fn pruned_dirs(dir: &Path, prune: &dyn Fn(&Path, &str) -> bool) -> Vec<PathBuf> {
    if !longpath::metadata(dir).is_ok_and(|m| m.is_dir()) {
        return Vec::new();
    }
    let mut dirs = vec![dir.to_path_buf()];
    longpath::walk(dir, &mut |visit| {
        let longpath::Visit::Entry { path, kind, .. } = visit else {
            return false;
        };
        if kind != longpath::Kind::Dir {
            return false;
        }
        let name = path
            .file_name()
            .map(|n| n.to_string_lossy())
            .unwrap_or_default();
        if prune(path, &name) {
            return false;
        }
        dirs.push(path.to_path_buf());
        true
    });
    dirs
}

/// Where the backend names the directory a watch was registered through, when its own path is
/// too long to name ([`Registry::watch`]).
const PROC_FD: &str = "/proc/self/fd";

/// The directories watched, by their paths. `inotify_add_watch` takes a path, and one of
/// `PATH_MAX` bytes or more cannot be named; such a directory is opened a run of components at a
/// time ([`longpath::open_dir_path`]) and watched as `/proc/self/fd/<fd>`, which the kernel
/// resolves to the directory itself. The backend reports its events under that name, and
/// [`Registry::real`] turns them back into the directory's path. The descriptor is kept while
/// the watch is, so its number is not reused.
#[derive(Debug, Default)]
struct Registry {
    watched: HashSet<PathBuf>,
    /// `/proc/self/fd/<fd>` → the directory's path, and the descriptor.
    by_fd: HashMap<PathBuf, (PathBuf, OwnedFd)>,
}

impl Registry {
    fn len(&self) -> usize {
        self.watched.len()
    }

    /// Watch the directory `dir`, non-recursively: by its path when that fits in one call,
    /// else through the opened directory.
    fn watch(&mut self, watcher: &mut RecommendedWatcher, dir: &Path) -> notify::Result<()> {
        if longpath::fits(dir) {
            watcher.watch(dir, RecursiveMode::NonRecursive)?;
        } else {
            let fd = longpath::open_dir_path(dir)
                .map_err(|e| notify::Error::io(e).add_path(dir.to_path_buf()))?;
            let name = PathBuf::from(format!("{PROC_FD}/{}", fd.as_raw_fd()));
            watcher.watch(&name, RecursiveMode::NonRecursive)?;
            self.by_fd.insert(name, (dir.to_path_buf(), fd));
        }
        self.watched.insert(dir.to_path_buf());
        Ok(())
    }

    /// `path` as an event names it, as a path under the roots: a path under a directory
    /// watched through its descriptor is that directory's path joined with the rest. `None`
    /// for a descriptor this registry does not hold.
    fn real(&self, path: &Path) -> Option<PathBuf> {
        let Ok(rest) = path.strip_prefix(PROC_FD) else {
            return Some(path.to_path_buf());
        };
        let mut parts = rest.components();
        let fd = parts.next()?;
        let (dir, _) = self.by_fd.get(&Path::new(PROC_FD).join(fd))?;
        let below = parts.as_path();
        Some(if below.as_os_str().is_empty() {
            dir.clone()
        } else {
            dir.join(below)
        })
    }

    /// `dir` is gone: forget it, and release its descriptor (and the backend's watch on it).
    fn remove(&mut self, watcher: Option<&mut RecommendedWatcher>, dir: &Path) {
        if !self.watched.remove(dir) {
            return;
        }
        let names: Vec<PathBuf> = self
            .by_fd
            .iter()
            .filter(|(_, (d, _))| d == dir)
            .map(|(name, _)| name.clone())
            .collect();
        if let Some(watcher) = watcher {
            for name in &names {
                let _ = watcher.unwatch(name);
            }
        }
        for name in names {
            self.by_fd.remove(&name);
        }
    }
}

/// Register a non-recursive watch on every directory [`pruned_dirs`] yields under `dir` that is
/// not already watched: `(registered, failed)`, `failed` naming each directory that could not
/// be watched — logged, never skipped silently: the caller has the class poll until they are.
///
/// A directory that is gone by the time its watch is added (or is no longer a directory) is
/// not a failure: a dependency install renames and removes directories as it goes (`pnpm`
/// unpacks into `<name>_tmp_<pid>_<n>` and renames it into place), and a listing names them
/// a moment before. Its parent's watch saw it go, and whatever took its place is listed next
/// (or raised its own event). Before, one such directory — `No path was found` from
/// `inotify_add_watch` — had the bulk class poll for the executor's life (Docker end to end,
/// round 5: after `pnpm install`, ~750 MB went uncaptured for minutes, and every final flush
/// walked the dependency tree again). A directory that is still there and still fails is tried
/// once more before it counts.
///
/// Listed again until a listing finds nothing new: a directory made after the listing and
/// before its parent's watch existed raised no event (a dependency tree being installed while
/// its top directory is watched); once every listed directory is watched, anything made in one
/// of them raises an event.
fn watch_pruned(
    watcher: &mut RecommendedWatcher,
    registry: &mut Registry,
    dir: &Path,
    prune: &dyn Fn(&Path, &str) -> bool,
) -> (usize, Vec<PathBuf>) {
    watch_listed(watcher, registry, dir, prune, &mut |d, p| pruned_dirs(d, p))
}

/// Whether `dir` is gone — removed, renamed away, or no longer a directory — as opposed to
/// there and refusing (a permission): a watch that failed on it was not a failure to watch.
fn gone(dir: &Path) -> bool {
    match longpath::metadata(dir) {
        Ok(meta) => !meta.is_dir(),
        Err(error) => matches!(
            error.kind(),
            std::io::ErrorKind::NotFound | std::io::ErrorKind::NotADirectory
        ),
    }
}

/// Whether to leave a directory out of a listing (and not descend into it).
type Prune<'a> = &'a dyn Fn(&Path, &str) -> bool;

/// [`watch_pruned`] over what `list` lists (a test lists, then moves a directory away).
fn watch_listed(
    watcher: &mut RecommendedWatcher,
    registry: &mut Registry,
    dir: &Path,
    prune: Prune<'_>,
    list: &mut dyn FnMut(&Path, Prune<'_>) -> Vec<PathBuf>,
) -> (usize, Vec<PathBuf>) {
    let mut added = 0;
    let mut failed: Vec<PathBuf> = Vec::new();
    loop {
        let mut new = 0;
        for d in list(dir, prune) {
            if registry.watched.contains(&d) || failed.contains(&d) {
                continue;
            }
            let mut result = registry.watch(watcher, &d);
            if result.is_err() && !gone(&d) {
                result = registry.watch(watcher, &d);
            }
            match result {
                Ok(()) => new += 1,
                Err(error) if gone(&d) => {
                    tracing::debug!(dir = %d.display(), %error, "capture: a directory went before its watch was added");
                }
                Err(error) => {
                    tracing::warn!(dir = %d.display(), %error, "capture: could not watch a directory; its class polls until it can");
                    failed.push(d);
                }
            }
        }
        added += new;
        if new == 0 {
            return (added, failed);
        }
    }
}

fn count_dirs(roots: &[PathBuf], prune: &dyn Fn(&Path, &str) -> bool) -> usize {
    roots.iter().map(|r| pruned_dirs(r, prune).len()).sum()
}

/// The watch budget in effect for `policy`.
fn budget_of(policy: &WatchPolicy) -> usize {
    policy.budget.unwrap_or_else(|| {
        max_user_watches().map_or(8192, |m| usize::try_from(m / 2).unwrap_or(usize::MAX))
    })
}

/// Start watching the roots in `spec`, delivering signals to `on_signal` from a worker thread.
/// Never fails over the budget: a class that does not fit polls. Returns an error only when the
/// backend watcher cannot be created (the runner then polls both classes).
///
/// # Errors
/// The `notify` backend could not be created.
pub fn start(
    spec: &WatchSpec,
    on_signal: Arc<dyn Fn(ChangeSignal) + Send + Sync>,
) -> notify::Result<WatchStart> {
    let polled = WatchStart {
        small: Mode::Polled,
        bulk: Mode::Polled,
        watches: 0,
        handle: None,
    };
    if !spec.policy.enabled {
        tracing::info!("capture watcher disabled by policy; polling at the maximum intervals");
        return Ok(polled);
    }
    let policy = Arc::new(Policy::new(spec));
    let small_roots = policy.small_roots();
    let bulk_roots = policy.bulk_roots();
    let p = Arc::clone(&policy);
    let small_prune = move |d: &Path, n: &str| p.prune_small(d, n);
    let p = Arc::clone(&policy);
    let bulk_prune = move |d: &Path, n: &str| p.prune_bulk(d, n);

    let small_dirs = count_dirs(&small_roots, &small_prune);
    let bulk_dirs = count_dirs(&bulk_roots, &bulk_prune);
    let mut budget = budget_of(&spec.policy);
    let needed = small_dirs + bulk_dirs;
    if needed > budget && spec.policy.raise_limit && spec.policy.budget.is_none() {
        match raise_max_user_watches(u64::try_from(needed * 2).unwrap_or(u64::MAX)) {
            Ok(true) => {
                budget = budget_of(&spec.policy);
                tracing::info!(budget, needed, "raised fs.inotify.max_user_watches");
            }
            Ok(false) => {}
            Err(error) => {
                tracing::warn!(%error, needed, budget, "could not raise fs.inotify.max_user_watches")
            }
        }
    }
    let small = if small_dirs <= budget {
        Mode::Watched
    } else {
        Mode::Polled
    };
    // The bulk class is watched with no bulk directory yet, too: the small class's watches see
    // one appear (a session's first `pnpm install` runs after this), and the watcher adds its
    // watches then, within the budget ([`handle_event`]). Before, it polled for the executor's
    // life, and every final flush walked the dependency tree again.
    let bulk = if spec.capture_bulk && small_dirs + bulk_dirs <= budget {
        Mode::Watched
    } else {
        Mode::Polled
    };
    if small == Mode::Polled {
        tracing::warn!(
            small_dirs,
            budget,
            "capture watch budget not met; the small class polls at the maximum interval"
        );
        return Ok(polled);
    }
    if bulk == Mode::Polled && !bulk_roots.is_empty() {
        tracing::info!(
            small_dirs,
            bulk_dirs,
            budget,
            "bulk directories exceed the watch budget; the bulk class polls at its maximum interval"
        );
    }

    let watcher_slot: Arc<Mutex<Option<RecommendedWatcher>>> = Arc::new(Mutex::new(None));
    let (tx, rx) = mpsc::channel::<notify::Event>();
    let mut watcher =
        notify::recommended_watcher(move |res: notify::Result<notify::Event>| match res {
            Ok(event) => {
                let _ = tx.send(event);
            }
            Err(error) => tracing::warn!(%error, "capture watcher error"),
        })?;
    let mut registry = Registry::default();
    let mut unwatched = Unwatched::default();
    for r in &small_roots {
        registry.watch(&mut watcher, r)?;
        let failed = watch_pruned(&mut watcher, &mut registry, r, &small_prune).1;
        unwatched.add(Class::Small, failed);
    }
    let mut small = small;
    if unwatched.has(Class::Small) {
        tracing::warn!(
            unwatched = unwatched.count(Class::Small),
            "capture: directories of the small class could not be watched; it polls at its \
             maximum interval until they are (the rest stays watched)"
        );
        small = Mode::Polled;
    }
    let mut bulk = bulk;
    if bulk == Mode::Watched {
        for r in &bulk_roots {
            let failed = watch_pruned(&mut watcher, &mut registry, r, &bulk_prune).1;
            unwatched.add(Class::Bulk, failed);
        }
        if unwatched.has(Class::Bulk) {
            tracing::warn!(
                unwatched = unwatched.count(Class::Bulk),
                "capture: bulk directories could not be watched; the bulk class polls at its \
                 maximum interval until they are (the rest stays watched)"
            );
            bulk = Mode::Polled;
        }
    }
    let watches = registry.len();
    tracing::info!(
        watches,
        through_descriptors = registry.by_fd.len(),
        bulk_roots = bulk_roots.len(),
        small = ?small,
        bulk = ?bulk,
        "capture watches registered"
    );
    *watcher_slot.lock().unwrap_or_else(|e| e.into_inner()) = Some(watcher);

    let fence = Arc::new(Fence {
        dir: spec.staging_dir.join(FENCE_DIR),
        next: AtomicU64::new(0),
        seen: Mutex::new(0),
        cv: Condvar::new(),
    });
    let worker_fence = Arc::clone(&fence);
    let worker_slot = Arc::clone(&watcher_slot);
    let watch_bulk = spec.capture_bulk && (bulk == Mode::Watched || unwatched.has(Class::Bulk));
    let mut state = WatchState {
        registry,
        watch_bulk,
        budget,
        unwatched,
        retry: Retry::new(),
    };
    std::thread::Builder::new()
        .name("capture-watch".to_owned())
        .spawn(move || {
            loop {
                match rx.recv_timeout(state.retry.tick()) {
                    // A fence ([`WatchHandle::settle`]): every event before it was handled.
                    Ok(event)
                        if matches!(event.kind, EventKind::Create(_))
                            && event.paths.iter().any(|p| worker_fence.number(p).is_some()) =>
                    {
                        for n in event.paths.iter().filter_map(|p| worker_fence.number(p)) {
                            worker_fence.passed(n);
                        }
                    }
                    Ok(event) => handle_event(&policy, &worker_slot, &mut state, &on_signal, event),
                    Err(mpsc::RecvTimeoutError::Timeout) => {}
                    Err(mpsc::RecvTimeoutError::Disconnected) => break,
                }
                retry_unwatched(&policy, &worker_slot, &mut state, &on_signal);
            }
        })
        .map_err(|e| notify::Error::io(e).add_path(spec.root.clone()))?;

    Ok(WatchStart {
        small,
        bulk,
        watches,
        handle: Some(WatchHandle {
            watcher: watcher_slot,
            fence,
        }),
    })
}

/// The watcher thread's state.
struct WatchState {
    registry: Registry,
    /// Bulk directories get watches as they appear (`false` only when the bulk class is not
    /// watched at all: not captured, or past the budget at the start). A directory that could
    /// not be watched no longer turns this off: it is retried ([`Unwatched`]), and the rest of
    /// the class stays watched.
    watch_bulk: bool,
    /// Watches this executor may register.
    budget: usize,
    /// Directories that could not be watched, per class, retried on [`Retry`]'s schedule.
    unwatched: Unwatched,
    retry: Retry,
}

/// Directories that could not be watched — the top of each subtree whose changes go unseen —
/// and their class. The class polls while it has any; once every one of them is watched (or
/// gone), the class is watched again ([`ChangeSignal::Rewatched`]).
#[derive(Debug, Default)]
struct Unwatched {
    dirs: std::collections::BTreeMap<PathBuf, Class>,
}

impl Unwatched {
    /// Note `dirs` of `class`, keeping only the top of each subtree.
    fn add(&mut self, class: Class, dirs: Vec<PathBuf>) {
        for dir in dirs {
            if self.dirs.keys().any(|d| dir.starts_with(d)) {
                continue;
            }
            self.dirs.retain(|d, _| !d.starts_with(&dir));
            self.dirs.insert(dir, class);
        }
    }

    fn has(&self, class: Class) -> bool {
        self.dirs.values().any(|c| *c == class)
    }

    fn count(&self, class: Class) -> usize {
        self.dirs.values().filter(|c| **c == class).count()
    }
}

/// When the watcher tries the directories it could not watch again: 2 s after the first
/// failure, doubling while they keep failing, 60 s at most.
#[derive(Debug)]
struct Retry {
    wait: std::time::Duration,
    at: Option<std::time::Instant>,
}

impl Retry {
    const FIRST: std::time::Duration = std::time::Duration::from_secs(2);
    const MAX: std::time::Duration = std::time::Duration::from_secs(60);

    fn new() -> Self {
        Self {
            wait: Self::FIRST,
            at: None,
        }
    }

    /// How long the watcher thread waits for an event before it looks at the retry.
    fn tick(&self) -> std::time::Duration {
        self.at.map_or(Self::MAX, |at| {
            at.saturating_duration_since(std::time::Instant::now())
                .max(std::time::Duration::from_millis(10))
        })
    }
}

/// Try again the directories that could not be watched, when the retry is due: each one still
/// there is watched with everything below it (within the budget), each one gone is dropped.
/// A class left with none is watched again ([`ChangeSignal::Rewatched`]). Scheduled from the
/// first failure; backs off while they keep failing.
fn retry_unwatched(
    policy: &Policy,
    watcher_slot: &Mutex<Option<RecommendedWatcher>>,
    state: &mut WatchState,
    on_signal: &Arc<dyn Fn(ChangeSignal) + Send + Sync>,
) {
    if state.unwatched.dirs.is_empty() {
        state.retry = Retry::new();
        return;
    }
    let now = std::time::Instant::now();
    match state.retry.at {
        None => {
            state.retry.at = Some(now + state.retry.wait);
            return;
        }
        Some(at) if now < at => return,
        Some(_) => {}
    }
    let mut guard = watcher_slot.lock().unwrap_or_else(|e| e.into_inner());
    let Some(watcher) = guard.as_mut() else {
        return;
    };
    let before = [
        state.unwatched.has(Class::Small),
        state.unwatched.has(Class::Bulk),
    ];
    let pending = mem::take(&mut state.unwatched.dirs);
    for (dir, class) in pending {
        if gone(&dir) {
            continue;
        }
        let prune = |d: &Path, n: &str| match class {
            Class::Small => policy.prune_small(d, n),
            Class::Bulk => policy.prune_bulk(d, n),
        };
        let needed = pruned_dirs(&dir, &prune)
            .iter()
            .filter(|d| !state.registry.watched.contains(*d))
            .count();
        if class == Class::Bulk && state.registry.len() + needed > state.budget {
            state.unwatched.add(class, vec![dir]);
            continue;
        }
        let failed = watch_pruned(watcher, &mut state.registry, &dir, &prune).1;
        state.unwatched.add(class, failed);
    }
    drop(guard);
    for (i, class) in [Class::Small, Class::Bulk].into_iter().enumerate() {
        if before[i] && !state.unwatched.has(class) {
            tracing::info!(
                ?class,
                "capture: every directory of the class is watched again"
            );
            on_signal(ChangeSignal::Rewatched(class));
        }
    }
    if state.unwatched.dirs.is_empty() {
        state.retry = Retry::new();
    } else {
        state.retry.wait = (state.retry.wait * 2).min(Retry::MAX);
        state.retry.at = Some(std::time::Instant::now() + state.retry.wait);
    }
}

fn handle_event(
    policy: &Policy,
    watcher_slot: &Mutex<Option<RecommendedWatcher>>,
    state: &mut WatchState,
    on_signal: &Arc<dyn Fn(ChangeSignal) + Send + Sync>,
    event: notify::Event,
) {
    if event.need_rescan() {
        on_signal(ChangeSignal::Overflow);
        return;
    }
    // Only content and structure changes dirty a class: the engine's own reads (IN_ACCESS,
    // IN_OPEN, IN_CLOSE_NOWRITE) must not re-dirty what it just snapped.
    if !matches!(
        event.kind,
        EventKind::Create(_) | EventKind::Modify(_) | EventKind::Remove(_)
    ) {
        return;
    }
    let mut classes: [bool; 2] = [false, false];
    let written = matches!(event.kind, EventKind::Create(_) | EventKind::Modify(_));
    for path in &event.paths {
        // A directory watched through its descriptor names its events under that.
        let Some(path) = state.registry.real(path) else {
            continue;
        };
        let path = path.as_path();
        let Some(class) = policy.classify(path) else {
            continue;
        };
        classes[usize::from(class == Class::Bulk)] = true;
        if written && let Some(inv) = &policy.invalidations {
            inv.note(class, path);
        }
        // Another name of the same inode is written too, whichever class holds it (review
        // 2026-09-28, sixth pass, #2: a write through a bulk name of a tracked file left the
        // small class clean for good).
        if let Some(aliases) = &policy.aliases {
            for (other, name) in aliases.others(path) {
                classes[usize::from(other == Class::Bulk)] = true;
                if let Some(inv) = &policy.invalidations {
                    inv.note(other, &name);
                }
            }
        }
        // A directory created or renamed in needs watches like the initial set (files created
        // inside it before its watch existed are caught by the snap's stat walk).
        let is_new_dir = match &event.kind {
            EventKind::Create(CreateKind::Folder) => true,
            EventKind::Create(_)
            | EventKind::Modify(ModifyKind::Name(RenameMode::To | RenameMode::Both)) => {
                longpath::metadata(path).is_ok_and(|m| m.is_dir())
            }
            _ => false,
        };
        if is_new_dir && (class == Class::Small || state.watch_bulk) {
            let mut guard = watcher_slot.lock().unwrap_or_else(|e| e.into_inner());
            if let Some(watcher) = guard.as_mut() {
                let name = path
                    .file_name()
                    .map(|n| n.to_string_lossy())
                    .unwrap_or_default();
                let bulk_root = policy.bulk_dirs.iter().any(|b| b.as_str() == name);
                if class == Class::Bulk || bulk_root {
                    if state.watch_bulk {
                        watch_new_bulk(policy, watcher, state, path, on_signal);
                    }
                } else if !policy.prune_small(path, &name) {
                    let failed = watch_pruned(watcher, &mut state.registry, path, &|d, n| {
                        policy.prune_small(d, n)
                    })
                    .1;
                    if !failed.is_empty() {
                        state.unwatched.add(Class::Small, failed);
                        on_signal(ChangeSignal::Unwatched(Class::Small));
                    }
                }
            }
        }
        if matches!(event.kind, EventKind::Remove(_)) {
            let mut guard = watcher_slot.lock().unwrap_or_else(|e| e.into_inner());
            state.registry.remove(guard.as_mut(), path);
        }
    }
    if classes[0] {
        on_signal(ChangeSignal::Changed(Class::Small));
    }
    if classes[1] {
        on_signal(ChangeSignal::Changed(Class::Bulk));
    }
}

/// A bulk directory appeared (a dependency tree installed after the watcher started, or a
/// directory created inside one): watch it and everything below it, within the budget. What
/// does not fit, or cannot be watched, has the bulk class poll until the watcher watches it
/// after all ([`retry_unwatched`]); the rest of the class stays watched, and directories that
/// appear later get watches as before (the small class keeps what the budget leaves it).
fn watch_new_bulk(
    policy: &Policy,
    watcher: &mut RecommendedWatcher,
    state: &mut WatchState,
    dir: &Path,
    on_signal: &Arc<dyn Fn(ChangeSignal) + Send + Sync>,
) {
    let prune = |d: &Path, n: &str| policy.prune_bulk(d, n);
    let needed = pruned_dirs(dir, &prune)
        .iter()
        .filter(|d| !state.registry.watched.contains(*d))
        .count();
    if state.registry.len() + needed > state.budget {
        tracing::info!(
            dir = %dir.display(),
            needed,
            watches = state.registry.len(),
            budget = state.budget,
            "bulk directories exceed the watch budget; the bulk class polls at its maximum \
             interval until they fit"
        );
        state.unwatched.add(Class::Bulk, vec![dir.to_path_buf()]);
        on_signal(ChangeSignal::Unwatched(Class::Bulk));
        return;
    }
    let failed = watch_pruned(watcher, &mut state.registry, dir, &prune).1;
    if !failed.is_empty() {
        state.unwatched.add(Class::Bulk, failed);
        on_signal(ChangeSignal::Unwatched(Class::Bulk));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn spec(root: &Path, home: Option<PathBuf>) -> WatchSpec {
        WatchSpec {
            root: root.to_path_buf(),
            harness_home: home,
            staging_dir: root.join(DAEMON_DIR).join("capture"),
            bulk_dirs: crate::index::DEFAULT_BULK_DIRS
                .iter()
                .map(|s| (*s).to_owned())
                .collect(),
            capture_bulk: true,
            policy: WatchPolicy::default(),
            invalidations: None,
            aliases: None,
        }
    }

    #[test]
    fn classifies_under_the_capture_policy() {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path().join("ws");
        let home = tmp.path().join("home");
        fs::create_dir_all(&root).unwrap();
        assert!(
            std::process::Command::new("git")
                .args(["init", "-q"])
                .current_dir(&root)
                .status()
                .unwrap()
                .success()
        );
        fs::create_dir_all(root.join("node_modules/a")).unwrap();
        fs::create_dir_all(home.join(".claude")).unwrap();
        let policy = Policy::new(&spec(&root, Some(home.clone())));
        assert_eq!(policy.classify(&root.join("src/a.rs")), Some(Class::Small));
        assert_eq!(
            policy.classify(&root.join(".git/refs/heads/main")),
            Some(Class::Small)
        );
        assert_eq!(policy.classify(&root.join(".git/index.lock")), None);
        assert_eq!(
            policy.classify(&root.join("vendor/x/.git/HEAD.lock")),
            None,
            "a nested repository's lock files are git's too"
        );
        assert_eq!(
            policy.classify(&root.join("Cargo.lock")),
            Some(Class::Small),
            "a user's lock file is work product"
        );
        assert_eq!(
            policy.classify(&root.join("tmp/server.pid")),
            Some(Class::Small)
        );
        assert_eq!(
            policy.classify(&root.join("node_modules/a/x.js")),
            Some(Class::Bulk)
        );
        assert_eq!(
            policy.classify(&root.join(".sealantd/capture/objects/x")),
            None
        );
        assert_eq!(
            policy.classify(&home.join("transcript.jsonl")),
            Some(Class::Small)
        );
        assert_eq!(
            policy.classify(&home.join(".claude/.credentials.json")),
            None
        );
        assert_eq!(
            policy.classify(&home.join(".codex/.credentials.json")),
            None
        );
        assert_eq!(
            policy.classify(&home.join(".claude/backups/.claude.json.backup.1")),
            None
        );
        assert_eq!(
            policy.classify(&home.join(".codex/config.toml")),
            Some(Class::Small)
        );
        assert_eq!(policy.classify(Path::new("/elsewhere/x")), None);
        assert_eq!(
            policy.bulk_roots(),
            vec![root.join("node_modules")],
            "bulk roots are the bulk directories under the worktree"
        );
        assert!(policy.prune_small(&root.join("node_modules"), "node_modules"));
        assert!(!policy.prune_small(&root.join(".git/refs"), "refs"));
        assert!(policy.prune_small(&root.join(".git/objects"), "objects"));
    }

    /// Every signal until `pred` holds or 5 s pass: whether it held.
    fn wait_for(rx: &mpsc::Receiver<ChangeSignal>, pred: impl Fn(ChangeSignal) -> bool) -> bool {
        while let Ok(s) = rx.recv_timeout(std::time::Duration::from_secs(5)) {
            if pred(s) {
                return true;
            }
        }
        false
    }

    /// Drain what is queued now.
    fn drain(rx: &mpsc::Receiver<ChangeSignal>) -> Vec<ChangeSignal> {
        let mut seen = Vec::new();
        while let Ok(s) = rx.recv_timeout(std::time::Duration::from_millis(300)) {
            seen.push(s);
        }
        seen
    }

    fn deep(top: &Path) -> PathBuf {
        let mut p = top.to_path_buf();
        for i in 0..18 {
            p = p.join(format!("d{i:02}{}", "x".repeat(240)));
            longpath::create_dir(&p).unwrap();
        }
        p
    }

    /// A directory deeper than `PATH_MAX` cannot be named to `inotify_add_watch`: it was
    /// never listed (changes under it unseen while its class read `Watched`), then it made its
    /// class poll — the small class too, whose every flush then walked the tree again. It is
    /// watched through its opened descriptor now, at start and when one appears later, and
    /// its events name its own path.
    #[test]
    fn a_directory_too_long_to_name_is_watched_through_its_descriptor() {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path().join("ws");
        fs::create_dir_all(root.join("src")).unwrap();
        fs::create_dir_all(root.join("node_modules/pkg")).unwrap();
        let deep_bulk = deep(&root.join("node_modules/pkg"));
        let deep_small = deep(&root.join("src"));
        let inv = Arc::new(Invalidations::default());
        let mut s = spec(&root, None);
        s.invalidations = Some(Arc::clone(&inv));
        let (tx, rx) = mpsc::channel();
        let started = start(
            &s,
            Arc::new(move |s| {
                let _ = tx.send(s);
            }),
        )
        .unwrap();
        assert_eq!(started.small, Mode::Watched);
        assert_eq!(started.bulk, Mode::Watched);

        let file = deep_small.join("work.rs");
        let mut f = longpath::create(&file).unwrap();
        std::io::Write::write_all(&mut f, b"work\n").unwrap();
        drop(f);
        assert!(wait_for(&rx, |s| s == ChangeSignal::Changed(Class::Small)));
        assert!(
            inv.take(Class::Small).contains(&file),
            "the write is noted under its own path"
        );
        let mut f = longpath::create(&deep_bulk.join("i.js")).unwrap();
        std::io::Write::write_all(&mut f, b"x").unwrap();
        drop(f);
        assert!(wait_for(&rx, |s| s == ChangeSignal::Changed(Class::Bulk)));

        // One moved in after the watcher started: watched too, nothing reported unwatched.
        let staged = tmp.path().join("staged");
        fs::create_dir_all(&staged).unwrap();
        let below = deep(&staged);
        fs::rename(&staged, root.join("src/moved-in")).unwrap();
        let seen = drain(&rx);
        assert!(
            !seen.contains(&ChangeSignal::Unwatched(Class::Small)),
            "{seen:?}"
        );
        let moved = root
            .join("src/moved-in")
            .join(below.strip_prefix(&staged).unwrap());
        let later = moved.join("later.rs");
        let mut f = longpath::create(&later).unwrap();
        std::io::Write::write_all(&mut f, b"later\n").unwrap();
        drop(f);
        assert!(wait_for(&rx, |s| s == ChangeSignal::Changed(Class::Small)));
        assert!(inv.take(Class::Small).contains(&later));
        drop(started);
    }

    /// Docker end to end, round 4: a session's first `pnpm install` runs after sealantd boots,
    /// so at boot there was no bulk directory, the bulk class polled for the executor's life,
    /// and every final flush walked the dependency tree again (a Stop took 15 s, not 6–7 s).
    /// The bulk class is watched with no bulk directory yet, and one made later gets watches.
    #[test]
    fn bulk_directories_made_after_start_are_watched() {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path().join("ws");
        fs::create_dir_all(root.join("src")).unwrap();
        let (tx, rx) = mpsc::channel();
        let started = start(
            &spec(&root, None),
            Arc::new(move |s| {
                let _ = tx.send(s);
            }),
        )
        .unwrap();
        assert_eq!(started.small, Mode::Watched);
        assert_eq!(
            started.bulk,
            Mode::Watched,
            "no bulk directory yet: one appearing is seen"
        );

        fs::create_dir_all(root.join("node_modules/.pnpm/pkg@1/node_modules/pkg")).unwrap();
        assert!(wait_for(&rx, |s| s == ChangeSignal::Changed(Class::Bulk)));
        let seen = drain(&rx);
        assert!(
            !seen.contains(&ChangeSignal::Unwatched(Class::Bulk)),
            "{seen:?}"
        );
        // A file written deep inside, in a directory made with the rest: seen.
        fs::write(
            root.join("node_modules/.pnpm/pkg@1/node_modules/pkg/index.js"),
            "x",
        )
        .unwrap();
        assert!(wait_for(&rx, |s| s == ChangeSignal::Changed(Class::Bulk)));
        drop(started);
    }

    /// A dependency tree that appears later and does not fit the watch budget has the bulk
    /// class poll (correctness first); the small class keeps its watches.
    #[test]
    fn bulk_directories_past_the_budget_make_the_bulk_class_poll() {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path().join("ws");
        fs::create_dir_all(root.join("src")).unwrap();
        let mut s = spec(&root, None);
        s.policy.budget = Some(8);
        let (tx, rx) = mpsc::channel();
        let started = start(
            &s,
            Arc::new(move |s| {
                let _ = tx.send(s);
            }),
        )
        .unwrap();
        assert_eq!(
            (started.small, started.bulk),
            (Mode::Watched, Mode::Watched)
        );
        let staged = tmp.path().join("staged");
        for i in 0..20 {
            fs::create_dir_all(staged.join(format!("pkg{i}"))).unwrap();
        }
        fs::rename(&staged, root.join("node_modules")).unwrap();
        assert!(wait_for(&rx, |s| s == ChangeSignal::Unwatched(Class::Bulk)));
        fs::write(root.join("src/a.rs"), "x").unwrap();
        assert!(wait_for(&rx, |s| s == ChangeSignal::Changed(Class::Small)));
        drop(started);
    }

    #[test]
    fn budget_zero_polls_everything() {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path().join("ws");
        fs::create_dir_all(root.join("src")).unwrap();
        let mut s = spec(&root, None);
        s.policy.budget = Some(0);
        let started = start(&s, Arc::new(|_| {})).unwrap();
        assert_eq!(started.small, Mode::Polled);
        assert!(started.handle.is_none());
    }

    #[test]
    fn events_reach_the_signal_hook() {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path().join("ws");
        fs::create_dir_all(root.join("src")).unwrap();
        fs::create_dir_all(root.join("node_modules/pkg")).unwrap();
        let (tx, rx) = mpsc::channel();
        let started = start(
            &spec(&root, None),
            Arc::new(move |s| {
                let _ = tx.send(s);
            }),
        )
        .unwrap();
        assert_eq!(started.small, Mode::Watched);
        assert_eq!(started.bulk, Mode::Watched);
        fs::write(root.join("src/a.rs"), "x").unwrap();
        let s = rx.recv_timeout(std::time::Duration::from_secs(5)).unwrap();
        assert_eq!(s, ChangeSignal::Changed(Class::Small));
        fs::write(root.join("node_modules/pkg/i.js"), "x").unwrap();
        let mut got_bulk = false;
        while let Ok(s) = rx.recv_timeout(std::time::Duration::from_secs(5)) {
            if s == ChangeSignal::Changed(Class::Bulk) {
                got_bulk = true;
                break;
            }
        }
        assert!(got_bulk);
        // A directory created later is adopted.
        fs::create_dir_all(root.join("src/deep")).unwrap();
        while rx
            .recv_timeout(std::time::Duration::from_millis(500))
            .is_ok()
        {}
        fs::write(root.join("src/deep/b.rs"), "x").unwrap();
        let s = rx.recv_timeout(std::time::Duration::from_secs(5)).unwrap();
        assert_eq!(s, ChangeSignal::Changed(Class::Small));
        drop(started);
    }

    /// A write names its path in the engine's invalidations, per class, so the next build of
    /// that class reads it whatever its stat says; reads never do.
    #[test]
    fn writes_are_noted_as_invalidations() {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path().join("ws");
        fs::create_dir_all(root.join("src")).unwrap();
        fs::write(root.join("src/a.rs"), "x").unwrap();
        let inv = Arc::new(Invalidations::default());
        let mut s = spec(&root, None);
        s.invalidations = Some(Arc::clone(&inv));
        let (tx, rx) = mpsc::channel();
        let started = start(
            &s,
            Arc::new(move |s| {
                let _ = tx.send(s);
            }),
        )
        .unwrap();
        let _ = fs::read(root.join("src/a.rs")).unwrap();
        fs::write(root.join("src/a.rs"), "y").unwrap();
        let s = rx.recv_timeout(std::time::Duration::from_secs(5)).unwrap();
        assert_eq!(s, ChangeSignal::Changed(Class::Small));
        let noted = inv.take(Class::Small);
        assert!(noted.contains(&root.join("src/a.rs")), "{noted:?}");
        assert!(inv.take(Class::Bulk).is_empty());
        drop(started);
    }

    /// What `pnpm install` does, as fast as it can: each package is unpacked into
    /// `<name>_tmp_<pid>_<n>` under `.pnpm/<name>@<v>/node_modules`, a few directories deep,
    /// then renamed into place, and linked from the top `node_modules`.
    fn pnpm_install(root: &Path, packages: usize) {
        let modules = root.join("node_modules");
        for i in 0..packages {
            let store = modules.join(format!(".pnpm/p{i}@1.0.0/node_modules"));
            let tmp = store.join(format!("p{i}_tmp_4242_{i}"));
            for sub in [
                "dist/cjs/internal",
                "dist/esm/internal",
                "dist/dts",
                "src/internal",
            ] {
                fs::create_dir_all(tmp.join(sub)).unwrap();
                fs::write(tmp.join(sub).join("index.js"), format!("// {i}\n")).unwrap();
            }
            fs::write(tmp.join("package.json"), "{}").unwrap();
            fs::rename(&tmp, store.join(format!("p{i}"))).unwrap();
            std::os::unix::fs::symlink(
                format!(".pnpm/p{i}@1.0.0/node_modules/p{i}"),
                modules.join(format!("p{i}")),
            )
            .unwrap();
        }
    }

    /// Docker end to end, round 5: after `pnpm install` the bulk class polled for good in two
    /// fresh sessions out of two: a package's `_tmp_` directory, listed while its parent's
    /// watch was added, was renamed into place before its own watch was
    /// (`could not watch a directory; its class polls … error=No path was found`), and one
    /// such failure turned watching off for the executor's life (~750 MB uncaptured for
    /// minutes; every final flush walked the tree again). A directory gone before its watch is
    /// not a failure; the install leaves the class watched, and the renamed packages raise
    /// events.
    #[test]
    fn a_pnpm_install_leaves_the_bulk_class_watched() {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path().join("ws");
        fs::create_dir_all(root.join("src")).unwrap();
        fs::create_dir_all(root.join("node_modules/.pnpm")).unwrap();
        let (tx, rx) = mpsc::channel();
        let started = start(
            &spec(&root, None),
            Arc::new(move |s| {
                let _ = tx.send(s);
            }),
        )
        .unwrap();
        assert_eq!(
            (started.small, started.bulk),
            (Mode::Watched, Mode::Watched)
        );
        pnpm_install(&root, 300);
        let seen = drain(&rx);
        assert!(
            !seen.iter().any(|s| matches!(s, ChangeSignal::Unwatched(_))),
            "an install's renames leave every class watched: {:?}",
            seen.iter()
                .filter(|s| matches!(s, ChangeSignal::Unwatched(_)))
                .collect::<Vec<_>>()
        );
        // The packages are watched where they landed.
        fs::write(
            root.join("node_modules/.pnpm/p299@1.0.0/node_modules/p299/dist/cjs/internal/late.js"),
            "x",
        )
        .unwrap();
        assert!(wait_for(&rx, |s| s == ChangeSignal::Changed(Class::Bulk)));
        drop(started);
    }

    /// The same race, forced: a directory listed and renamed away before its watch is added is
    /// skipped, not counted as unwatchable, and where it landed is listed and watched next.
    #[test]
    fn a_directory_renamed_away_before_its_watch_is_not_a_failure() {
        let tmp = tempfile::tempdir().unwrap();
        let store = tmp.path().join("node_modules/.pnpm/p@1/node_modules");
        let tmp_dir = store.join("p_tmp_1_1");
        fs::create_dir_all(tmp_dir.join("dist/cjs")).unwrap();
        let mut watcher =
            notify::recommended_watcher(|_: notify::Result<notify::Event>| {}).unwrap();
        let mut registry = Registry::default();
        let mut renamed = false;
        let (added, failed) = watch_listed(
            &mut watcher,
            &mut registry,
            &store,
            &|_, _| false,
            &mut |dir, prune| {
                let listed = pruned_dirs(dir, prune);
                if !renamed {
                    fs::rename(&tmp_dir, store.join("p")).unwrap();
                    renamed = true;
                }
                listed
            },
        );
        assert!(failed.is_empty(), "{failed:?}");
        assert!(added >= 4, "{added}");
        for d in ["", "p", "p/dist", "p/dist/cjs"] {
            assert!(registry.watched.contains(&store.join(d)), "{d} watched");
        }
        assert!(!registry.watched.contains(&tmp_dir));
    }

    /// A directory that cannot be watched for a reason that lasts (here: the directory is not
    /// readable, so nothing below it can be listed or watched) has its class poll, but only
    /// until the watcher watches it: once it can, the class is watched again, the rest of the
    /// class having stayed watched throughout.
    #[test]
    fn an_unwatchable_directory_is_watched_again_once_it_can_be() {
        use std::os::unix::fs::PermissionsExt;
        if nix::unistd::geteuid().is_root() {
            // Root reads and watches anything: nothing here fails.
            return;
        }
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path().join("ws");
        fs::create_dir_all(root.join("src")).unwrap();
        fs::create_dir_all(root.join("node_modules/.pnpm")).unwrap();
        let (tx, rx) = mpsc::channel();
        let started = start(
            &spec(&root, None),
            Arc::new(move |s| {
                let _ = tx.send(s);
            }),
        )
        .unwrap();
        // A package directory nobody may search, moved in: its subdirectory cannot be watched.
        let outside = tmp.path().join("locked");
        fs::create_dir_all(outside.join("inner")).unwrap();
        fs::set_permissions(&outside, fs::Permissions::from_mode(0o600)).unwrap();
        let locked = root.join("node_modules/.pnpm/locked@1");
        fs::rename(&outside, &locked).unwrap();
        fs::create_dir_all(root.join("node_modules/.pnpm/other@1")).unwrap();
        assert!(
            wait_for(&rx, |s| s == ChangeSignal::Unwatched(Class::Bulk)),
            "the class polls while a directory cannot be watched"
        );
        // The rest of the class is still watched.
        fs::write(root.join("node_modules/.pnpm/other@1/x.js"), "x").unwrap();
        assert!(wait_for(&rx, |s| s == ChangeSignal::Changed(Class::Bulk)));
        // Once it can be watched, it is, and the class is watched again.
        fs::set_permissions(&locked, fs::Permissions::from_mode(0o755)).unwrap();
        let back = std::time::Instant::now();
        let mut rewatched = false;
        while back.elapsed() < std::time::Duration::from_secs(15) {
            if let Ok(s) = rx.recv_timeout(std::time::Duration::from_millis(200))
                && s == ChangeSignal::Rewatched(Class::Bulk)
            {
                rewatched = true;
                break;
            }
        }
        assert!(rewatched, "the watcher tried again and watches it");
        fs::write(locked.join("inner/y.js"), "y").unwrap();
        assert!(wait_for(&rx, |s| s == ChangeSignal::Changed(Class::Bulk)));
        drop(started);
    }
}
