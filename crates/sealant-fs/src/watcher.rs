//! The live `notify` watcher: maps backend events to normalized `file.changed` telemetry, coalesces
//! editor temp-file noise, skips ignored trees, and on overflow emits `file.watchOverflow` + rescans.

use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

use notify::event::{ModifyKind, RenameMode};
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
    pub correlation: Correlation,
}

fn publish(ctx: &WatchContext, payload: EventPayload) {
    ctx.bus.publish(
        &ctx.correlation,
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

fn handle_event(ctx: &WatchContext, current: &Mutex<Snapshot>, event: notify::Event) {
    // Overflow / lost events: report it and reconcile via a fresh snapshot diff.
    if event.need_rescan() {
        publish(
            ctx,
            EventPayload::FileWatchOverflow(FileWatchOverflow {
                root: ctx.root.display().to_string(),
            }),
        );
        let fresh = snapshot(&ctx.root, &ctx.snapshot_config);
        let mut guard = current.lock().unwrap_or_else(|e| e.into_inner());
        for c in diff(&guard, &fresh) {
            publish(ctx, EventPayload::FileChange(c));
        }
        *guard = fresh;
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
    }
}

/// Build and start a recursive watcher. The returned handle must be kept alive to keep watching.
///
/// # Errors
/// Returns a [`notify::Error`] if the backend watcher cannot be created or the root cannot be watched.
pub(crate) fn build_watcher(
    ctx: WatchContext,
    baseline: Snapshot,
) -> notify::Result<RecommendedWatcher> {
    let root = ctx.root.clone();
    let ctx = Arc::new(ctx);
    let current = Arc::new(Mutex::new(baseline));
    let mut watcher =
        notify::recommended_watcher(move |res: notify::Result<notify::Event>| match res {
            Ok(event) => handle_event(&ctx, &current, event),
            Err(error) => tracing::warn!(%error, "filesystem watcher error"),
        })?;
    watcher.watch(&root, RecursiveMode::Recursive)?;
    Ok(watcher)
}
