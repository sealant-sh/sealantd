//! Change detection for the cadence (ADR-0015 *Cadence and budgets*): the `sealant-fs` pruned
//! per-directory inotify watcher run over the capture roots under the capture ignore policy.
//! Every event marks a class dirty; nothing is hashed here. The watcher runs under a watch
//! budget: directories are counted before registration, `fs.inotify.max_user_watches` is raised
//! only when the policy says so, and a class whose watches do not fit polls instead (the stat
//! walk the engine does anyway). `IN_Q_OVERFLOW` (`need_rescan`) reports an [`ChangeSignal::Overflow`]
//! and the runner drops to polling.

use std::collections::HashSet;
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, mpsc};

use notify::event::{CreateKind, ModifyKind, RenameMode};
use notify::{EventKind, RecommendedWatcher, RecursiveMode, Watcher};
use sealant_fs::watcher::{pruned_dirs, watch_pruned};

use crate::engine::Class;
use crate::gitpack::GitRepo;
use crate::index::{CREDENTIAL_FILES, DAEMON_DIR, has_component_in, is_excluded_name};

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
        }
    }

    fn is_daemon(&self, abs: &Path) -> bool {
        abs.starts_with(&self.staging_dir) || abs.starts_with(&self.daemon_dir)
    }

    /// The class an event on `abs` dirties, or `None` when the policy excludes the path.
    fn classify(&self, abs: &Path) -> Option<Class> {
        if self.is_daemon(abs) {
            return None;
        }
        let name = abs.file_name().map(|n| n.to_string_lossy());
        let parent_name = abs
            .parent()
            .and_then(Path::file_name)
            .map(|n| n.to_string_lossy());
        if let Some(name) = &name
            && is_excluded_name(name, parent_name.as_deref())
        {
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
    /// never lists (`objects`, `worktrees`, `lfs`: refs, `HEAD`, the index and the logs are what
    /// move when history does) are pruned.
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
        let mut it = walkdir::WalkDir::new(&self.root)
            .follow_links(false)
            .min_depth(1)
            .sort_by_file_name()
            .into_iter();
        while let Some(next) = it.next() {
            let Ok(e) = next else { continue };
            if !e.file_type().is_dir() {
                continue;
            }
            let name = e.file_name().to_string_lossy();
            if self.prune_bulk(e.path(), &name) {
                it.skip_current_dir();
            } else if self.bulk_dirs.iter().any(|b| b.as_str() == name) {
                roots.push(e.path().to_path_buf());
                it.skip_current_dir();
            }
        }
        roots
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
    let bulk = if !bulk_roots.is_empty() && small_dirs + bulk_dirs <= budget {
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
    let mut watched: HashSet<PathBuf> = HashSet::new();
    for r in &small_roots {
        watcher.watch(r, RecursiveMode::NonRecursive)?;
        watched.insert(r.clone());
        watch_pruned(&mut watcher, &mut watched, r, &small_prune);
    }
    if bulk == Mode::Watched {
        for r in &bulk_roots {
            watch_pruned(&mut watcher, &mut watched, r, &bulk_prune);
        }
    }
    let watches = watched.len();
    tracing::info!(
        watches,
        small = ?small,
        bulk = ?bulk,
        "capture watches registered"
    );
    *watcher_slot.lock().unwrap_or_else(|e| e.into_inner()) = Some(watcher);

    let worker_slot = Arc::clone(&watcher_slot);
    let watch_bulk = bulk == Mode::Watched;
    std::thread::Builder::new()
        .name("capture-watch".to_owned())
        .spawn(move || {
            let mut watched = watched;
            while let Ok(event) = rx.recv() {
                handle_event(
                    &policy,
                    &worker_slot,
                    &mut watched,
                    watch_bulk,
                    &on_signal,
                    event,
                );
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

fn handle_event(
    policy: &Policy,
    watcher_slot: &Mutex<Option<RecommendedWatcher>>,
    watched: &mut HashSet<PathBuf>,
    watch_bulk: bool,
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
    for path in &event.paths {
        let Some(class) = policy.classify(path) else {
            continue;
        };
        classes[usize::from(class == Class::Bulk)] = true;
        // A directory created or renamed in needs watches like the initial set (files created
        // inside it before its watch existed are caught by the snap's stat walk).
        let is_new_dir = match &event.kind {
            EventKind::Create(CreateKind::Folder) => true,
            EventKind::Create(_)
            | EventKind::Modify(ModifyKind::Name(RenameMode::To | RenameMode::Both)) => {
                path.is_dir()
            }
            _ => false,
        };
        if is_new_dir && (class == Class::Small || watch_bulk) {
            let mut guard = watcher_slot.lock().unwrap_or_else(|e| e.into_inner());
            if let Some(watcher) = guard.as_mut() {
                let name = path
                    .file_name()
                    .map(|n| n.to_string_lossy())
                    .unwrap_or_default();
                let bulk_root = policy.bulk_dirs.iter().any(|b| b.as_str() == name);
                if class == Class::Bulk || bulk_root {
                    if watch_bulk {
                        watch_pruned(watcher, watched, path, &|d, n| policy.prune_bulk(d, n));
                    }
                } else if !policy.prune_small(path, &name) {
                    watch_pruned(watcher, watched, path, &|d, n| policy.prune_small(d, n));
                }
            }
        }
        if matches!(event.kind, EventKind::Remove(_)) {
            watched.remove(path);
        }
    }
    if classes[0] {
        on_signal(ChangeSignal::Changed(Class::Small));
    }
    if classes[1] {
        on_signal(ChangeSignal::Changed(Class::Bulk));
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
}
