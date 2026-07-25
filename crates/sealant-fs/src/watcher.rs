//! The live `notify` watcher: maps backend events to normalized `file.changed` telemetry, coalesces
//! editor temp-file noise, skips ignored trees, and on overflow emits `file.watchOverflow` + rescans.
//!
//! Watch registration is **pruned by the ignore list** (ADR-0008): instead of one recursive watch —
//! which would register a descriptor for every directory including `.git`/`node_modules`/`target`
//! and blow through `fs.inotify.max_user_watches` on real repositories — each non-ignored directory
//! gets its own non-recursive watch, and directories created later are registered as their create
//! events arrive. All event processing (including content hashing) runs on a dedicated worker
//! thread, never on the notify backend thread: the inotify event loop stays unblocked (less
//! overflow pressure), and registering new watches from the worker cannot deadlock the backend.

use std::collections::HashSet;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, mpsc};

use notify::event::{CreateKind, ModifyKind, RenameMode};
use notify::{EventKind, RecommendedWatcher, RecursiveMode, Watcher};
use sealant_protocol::{
    CaptureMethod, Confidence, EventPayload, FileChange, FileChangeKind, FileWatchOverflow,
};
use sealant_telemetry::{Correlation, EventBus};

use crate::diff::diff;
use crate::snapshot::{Snapshot, SnapshotConfig, entry_for, is_temp_path, snapshot};

pub(crate) struct WatchContext {
    pub root: PathBuf,
    pub snapshot_config: SnapshotConfig,
    pub bus: Arc<EventBus>,
    pub execution: crate::runtime::SharedExecution,
}

/// Keeps the backend watcher and its worker thread alive; dropping it stops both.
pub(crate) struct WatcherHandle {
    watcher: Arc<Mutex<Option<RecommendedWatcher>>>,
}

impl Drop for WatcherHandle {
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

fn publish(ctx: &WatchContext, payload: EventPayload) {
    let execution = ctx
        .execution
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .clone();
    ctx.bus.publish(
        &Correlation::new().execution(execution),
        CaptureMethod::Inotify,
        Confidence::Observed,
        payload,
    );
}

/// Relative path under `root`, or `None` if it escapes the root or is an editor temp file.
fn rel_of(root: &Path, path: &Path) -> Option<String> {
    let rel = path.strip_prefix(root).ok()?.to_string_lossy().to_string();
    if rel.is_empty() || is_temp_path(&rel) {
        None
    } else {
        Some(rel)
    }
}

fn is_in_ignored(rel: &str, config: &SnapshotConfig) -> bool {
    rel.split('/')
        .any(|component| config.ignores.iter().any(|i| i == component))
}

fn change(
    kind: FileChangeKind,
    path: String,
    entry: Option<sealant_protocol::FileEntry>,
) -> FileChange {
    FileChange {
        kind,
        path,
        rename_from: None,
        entry,
        certain: true,
    }
}

/// Per-watcher worker state: the live snapshot (for overflow reconciliation) and the set of
/// directories with a registered watch.
struct WorkerState {
    current: Snapshot,
    watched: HashSet<PathBuf>,
}

/// Walk `dir` with ignore pruning, returning every non-ignored directory (including `dir` itself).
fn watchable_dirs(dir: &Path, config: &SnapshotConfig) -> Vec<PathBuf> {
    let ignores = &config.ignores;
    walkdir::WalkDir::new(dir)
        .follow_links(false)
        .into_iter()
        .filter_entry(|e| {
            let name = e.file_name().to_string_lossy();
            !(e.depth() > 0 && e.file_type().is_dir() && ignores.iter().any(|i| i.as_str() == name))
        })
        .flatten()
        .filter(|e| e.file_type().is_dir())
        .map(walkdir::DirEntry::into_path)
        .collect()
}

/// Register non-recursive watches for every non-ignored directory under (and including) `dir`.
/// Returns the number of new registrations; failures are logged and skipped (a single unwatchable
/// directory should not take down observation of the rest of the tree).
fn watch_tree(
    watcher_slot: &Mutex<Option<RecommendedWatcher>>,
    watched: &mut HashSet<PathBuf>,
    dir: &Path,
    config: &SnapshotConfig,
) -> usize {
    let mut added = 0;
    let mut guard = watcher_slot.lock().unwrap_or_else(|e| e.into_inner());
    let Some(watcher) = guard.as_mut() else {
        return 0;
    };
    for d in watchable_dirs(dir, config) {
        if watched.contains(&d) {
            continue;
        }
        match watcher.watch(&d, RecursiveMode::NonRecursive) {
            Ok(()) => {
                watched.insert(d);
                added += 1;
            }
            Err(error) => tracing::warn!(dir = %d.display(), %error, "could not watch directory"),
        }
    }
    added
}

/// After a directory create is observed, register watches under it and report its contents: files
/// created inside a brand-new directory before its watch existed would otherwise be missed. Any
/// duplicate `file.changed` this produces is harmless advisory noise; the final snapshot diff
/// stays authoritative.
fn adopt_new_dir(
    ctx: &WatchContext,
    watcher_slot: &Mutex<Option<RecommendedWatcher>>,
    state: &mut WorkerState,
    dir: &Path,
) {
    if watch_tree(watcher_slot, &mut state.watched, dir, &ctx.snapshot_config) == 0 {
        return;
    }
    let max_hash = ctx.snapshot_config.max_hash_bytes;
    for entry in walkdir::WalkDir::new(dir)
        .min_depth(1)
        .follow_links(false)
        .into_iter()
        .filter_entry(|e| {
            let name = e.file_name().to_string_lossy();
            !(e.file_type().is_dir()
                && ctx
                    .snapshot_config
                    .ignores
                    .iter()
                    .any(|i| i.as_str() == name))
        })
        .flatten()
    {
        let path = entry.path();
        let Some(rel) = rel_of(&ctx.root, path) else {
            continue;
        };
        if is_in_ignored(&rel, &ctx.snapshot_config) {
            continue;
        }
        publish(
            ctx,
            EventPayload::FileChange(change(
                FileChangeKind::Added,
                rel,
                entry_for(&ctx.root, path, max_hash),
            )),
        );
    }
}

fn handle_event(
    ctx: &WatchContext,
    watcher_slot: &Mutex<Option<RecommendedWatcher>>,
    state: &mut WorkerState,
    event: notify::Event,
) {
    // Overflow / lost events: report it, reconcile via a fresh snapshot diff, and re-register
    // watches for any directories whose create events were lost.
    if event.need_rescan() {
        publish(
            ctx,
            EventPayload::FileWatchOverflow(FileWatchOverflow {
                root: ctx.root.display().to_string(),
            }),
        );
        let fresh = snapshot(&ctx.root, &ctx.snapshot_config);
        for c in diff(&state.current, &fresh) {
            publish(ctx, EventPayload::FileChange(c));
        }
        state.current = fresh;
        watch_tree(
            watcher_slot,
            &mut state.watched,
            &ctx.root,
            &ctx.snapshot_config,
        );
        return;
    }

    let max_hash = ctx.snapshot_config.max_hash_bytes;

    // A correlated rename (both endpoints known) is reported as a certain rename.
    if let EventKind::Modify(ModifyKind::Name(RenameMode::Both)) = &event.kind
        && event.paths.len() >= 2
        && let (Some(from), Some(to)) = (
            rel_of(&ctx.root, &event.paths[0]),
            rel_of(&ctx.root, &event.paths[1]),
        )
    {
        if !is_in_ignored(&to, &ctx.snapshot_config) {
            publish(
                ctx,
                EventPayload::FileChange(FileChange {
                    kind: FileChangeKind::Renamed,
                    path: to,
                    rename_from: Some(from),
                    entry: entry_for(&ctx.root, &event.paths[1], max_hash),
                    certain: true,
                }),
            );
            // A directory renamed into the tree needs watches just like a created one.
            if event.paths[1].is_dir() {
                adopt_new_dir(ctx, watcher_slot, state, &event.paths[1]);
            }
        }
        return;
    }

    for path in &event.paths {
        let Some(rel) = rel_of(&ctx.root, path) else {
            continue;
        };
        if is_in_ignored(&rel, &ctx.snapshot_config) {
            continue;
        }
        let mapped = match &event.kind {
            EventKind::Create(_) | EventKind::Modify(ModifyKind::Name(RenameMode::To)) => {
                Some(change(
                    FileChangeKind::Added,
                    rel,
                    entry_for(&ctx.root, path, max_hash),
                ))
            }
            EventKind::Modify(ModifyKind::Metadata(_)) => Some(change(
                FileChangeKind::MetadataChanged,
                rel,
                entry_for(&ctx.root, path, max_hash),
            )),
            EventKind::Modify(ModifyKind::Data(_) | ModifyKind::Any | ModifyKind::Other) => {
                Some(change(
                    FileChangeKind::Modified,
                    rel,
                    entry_for(&ctx.root, path, max_hash),
                ))
            }
            EventKind::Remove(_) | EventKind::Modify(ModifyKind::Name(_)) => {
                Some(change(FileChangeKind::Deleted, rel, None))
            }
            _ => None, // Access, Other, Any
        };
        if let Some(c) = mapped {
            publish(ctx, EventPayload::FileChange(c));
        }
        match &event.kind {
            // New directory: register watches beneath it (the kernel removes watches for
            // deleted directories on its own; we just forget them).
            EventKind::Create(CreateKind::Folder) => {
                adopt_new_dir(ctx, watcher_slot, state, path);
            }
            EventKind::Create(_) | EventKind::Modify(ModifyKind::Name(RenameMode::To))
                if path.is_dir() =>
            {
                adopt_new_dir(ctx, watcher_slot, state, path);
            }
            EventKind::Remove(_) => {
                state.watched.remove(path);
            }
            _ => {}
        }
    }
}

/// Build and start the pruned per-directory watcher. The returned handle must be kept alive to
/// keep watching.
///
/// # Errors
/// Returns a [`notify::Error`] if the backend watcher cannot be created or the root itself cannot
/// be watched.
pub(crate) fn build_watcher(
    ctx: WatchContext,
    baseline: Snapshot,
) -> notify::Result<WatcherHandle> {
    let root = ctx.root.clone();
    let ctx = Arc::new(ctx);
    let watcher_slot: Arc<Mutex<Option<RecommendedWatcher>>> = Arc::new(Mutex::new(None));
    let (tx, rx) = mpsc::channel::<notify::Event>();

    let mut watcher =
        notify::recommended_watcher(move |res: notify::Result<notify::Event>| match res {
            Ok(event) => {
                let _ = tx.send(event);
            }
            Err(error) => tracing::warn!(%error, "filesystem watcher error"),
        })?;

    // Register the initial pruned watch set. The root itself must be watchable; individual
    // subdirectory failures degrade coverage but do not abort.
    watcher.watch(&root, RecursiveMode::NonRecursive)?;
    let mut watched = HashSet::from([root.clone()]);
    for dir in watchable_dirs(&root, &ctx.snapshot_config) {
        if watched.contains(&dir) {
            continue;
        }
        match watcher.watch(&dir, RecursiveMode::NonRecursive) {
            Ok(()) => {
                watched.insert(dir);
            }
            Err(error) => {
                tracing::warn!(dir = %dir.display(), %error, "could not watch directory");
            }
        }
    }
    tracing::debug!(watches = watched.len(), root = %root.display(), "filesystem watches registered");
    *watcher_slot.lock().unwrap_or_else(|e| e.into_inner()) = Some(watcher);

    // The worker owns all event processing (mapping, hashing, publishing, watch registration).
    // It exits when the channel closes, i.e. when the backend (and its callback sender) drops.
    let worker_slot = watcher_slot.clone();
    std::thread::Builder::new()
        .name("sealant-fs-watch".to_owned())
        .spawn(move || {
            let mut state = WorkerState {
                current: baseline,
                watched,
            };
            while let Ok(event) = rx.recv() {
                handle_event(&ctx, &worker_slot, &mut state, event);
            }
        })
        .map_err(|e| notify::Error::io(e).add_path(root))?;

    Ok(WatcherHandle {
        watcher: watcher_slot,
    })
}
