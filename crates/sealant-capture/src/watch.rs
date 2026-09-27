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
use std::sync::{Arc, Mutex, mpsc};

use notify::event::{CreateKind, ModifyKind, RenameMode};
use notify::{EventKind, RecommendedWatcher, RecursiveMode, Watcher};

use crate::engine::Class;
use crate::gitpack::GitRepo;
use crate::index::{CREDENTIAL_FILES, DAEMON_DIR, Suspects, has_component_in, is_git_transient};
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
    /// A directory of the class could not be watched (a path too long for `inotify_add_watch`,
    /// the watch limit): changes under it would go unseen, so the class polls.
    Unwatched(Class),
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
    credentials: Vec<PathBuf>,
    staging_dir: PathBuf,
    daemon_dir: PathBuf,
    bulk_dirs: Vec<String>,
    capture_bulk: bool,
    invalidations: Option<Arc<Invalidations>>,
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
        let credentials = spec
            .harness_home
            .as_ref()
            .map(|h| CREDENTIAL_FILES.iter().map(|c| h.join(c)).collect())
            .unwrap_or_default();
        Self {
            root: spec.root.clone(),
            git_dirs,
            harness_home: spec.harness_home.clone(),
            credentials,
            staging_dir: spec.staging_dir.clone(),
            daemon_dir: spec.root.join(DAEMON_DIR),
            bulk_dirs: spec.bulk_dirs.clone(),
            capture_bulk: spec.capture_bulk,
            invalidations: spec.invalidations.clone(),
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
            if self.credentials.iter().any(|c| c == abs) {
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
            if !g.starts_with(&self.root) && g.is_dir() {
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
/// not already watched: `(registered, failed)`. A failure is logged and counted, never skipped
/// silently: the caller has the class poll.
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
) -> (usize, usize) {
    let (mut added, mut failed) = (0, 0);
    loop {
        let mut new = 0;
        for d in pruned_dirs(dir, prune) {
            if registry.watched.contains(&d) {
                continue;
            }
            match registry.watch(watcher, &d) {
                Ok(()) => new += 1,
                Err(error) => {
                    tracing::warn!(dir = %d.display(), %error, "capture: could not watch a directory; its class polls");
                    failed += 1;
                }
            }
        }
        added += new;
        if new == 0 || failed > 0 {
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
    let mut small_failed = 0;
    for r in &small_roots {
        registry.watch(&mut watcher, r)?;
        small_failed += watch_pruned(&mut watcher, &mut registry, r, &small_prune).1;
    }
    if small_failed > 0 {
        tracing::warn!(
            unwatched = small_failed,
            "capture: directories of the small class could not be watched; polling at the \
             maximum intervals"
        );
        return Ok(polled);
    }
    let mut bulk = bulk;
    if bulk == Mode::Watched {
        let mut bulk_failed = 0;
        for r in &bulk_roots {
            bulk_failed += watch_pruned(&mut watcher, &mut registry, r, &bulk_prune).1;
        }
        if bulk_failed > 0 {
            tracing::warn!(
                unwatched = bulk_failed,
                "capture: bulk directories could not be watched; the bulk class polls at its \
                 maximum interval"
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

    let worker_slot = Arc::clone(&watcher_slot);
    let mut state = WatchState {
        registry,
        watch_bulk: bulk == Mode::Watched,
        budget,
    };
    std::thread::Builder::new()
        .name("capture-watch".to_owned())
        .spawn(move || {
            while let Ok(event) = rx.recv() {
                handle_event(&policy, &worker_slot, &mut state, &on_signal, event);
            }
        })
        .map_err(|e| notify::Error::io(e).add_path(spec.root.clone()))?;

    Ok(WatchStart {
        small,
        bulk,
        watches,
        handle: Some(WatchHandle {
            watcher: watcher_slot,
        }),
    })
}

/// The watcher thread's state.
struct WatchState {
    registry: Registry,
    /// Bulk directories get watches as they appear; `false` once the bulk class polls.
    watch_bulk: bool,
    /// Watches this executor may register.
    budget: usize,
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
                } else if !policy.prune_small(path, &name)
                    && watch_pruned(watcher, &mut state.registry, path, &|d, n| {
                        policy.prune_small(d, n)
                    })
                    .1 > 0
                {
                    on_signal(ChangeSignal::Unwatched(Class::Small));
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
/// does not fit, or cannot be watched, has the bulk class poll from then on (the small class
/// keeps what the budget leaves it).
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
             interval"
        );
        state.watch_bulk = false;
        on_signal(ChangeSignal::Unwatched(Class::Bulk));
        return;
    }
    if watch_pruned(watcher, &mut state.registry, dir, &prune).1 > 0 {
        state.watch_bulk = false;
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
}
